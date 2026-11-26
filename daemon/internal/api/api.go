// Package api is the daemon's Unix-socket protocol.
//
// One request per connection: a single line of JSON, answered by a single
// line of JSON. The socket is root-owned with mode 0600, and the server
// also checks the peer is uid 0, so only the WHM page (root) and the
// AdminBin adapter (root, acting for a cPanel user) can connect.
//
// The caller's identity is set by those two clients, never by the browser.
// User verbs take the account name only from Caller.User; any "user" key in
// Args is ignored.
package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/jeemplugins/cpanel--security/daemon/internal/audit"
	"github.com/jeemplugins/cpanel--security/daemon/internal/detector"
	"github.com/jeemplugins/cpanel--security/daemon/internal/pathguard"
	"github.com/jeemplugins/cpanel--security/daemon/internal/quarantine"
)

const maxRequest = 64 * 1024

type Caller struct {
	Role     string `json:"role"` // "admin" or "user"
	User     string `json:"user,omitempty"`
	RemoteIP string `json:"remote_ip,omitempty"`
}

type Request struct {
	Verb   string            `json:"verb"`
	Caller Caller            `json:"caller"`
	Args   map[string]string `json:"args,omitempty"`
}

type Response struct {
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

// The only verbs a cPanel user can reach (through the AdminBin adapter).
var userVerbs = map[string]bool{
	"list_findings":  true,
	"quarantine":     true,
	"restore":        true,
	"allowlist_file": true,
}

var adminVerbs = map[string]bool{
	"status":          true,
	"list_bans":       true,
	"block_ip":        true,
	"unblock_ip":      true,
	"recent_failures": true,
	"list_quarantine": true,
	"audit_log":       true,
}

type Server struct {
	Detector   *detector.Detector
	Quarantine *quarantine.Store
	FileAllow  *FileAllowlist
	Audit      *audit.Log
	// Lookup returns the system account for a cPanel username.
	Lookup func(user string) (quarantine.Account, error)
	Now    func() time.Time
	// BansChanged is called after a ban is added or removed so it can be saved.
	BansChanged func()
	Version     string
	Started     time.Time
	// AllowAnyPeer disables the uid-0 peer check (tests only).
	AllowAnyPeer bool
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Handle authorises and runs one request. Every request is audited.
func (s *Server) Handle(req Request) (resp Response) {
	actor := "admin"
	if req.Caller.Role == "user" {
		actor = "user:" + req.Caller.User
	}
	defer func() {
		if s.Audit == nil || req.Verb == "audit_log" || req.Verb == "status" {
			return
		}
		s.Audit.Write(audit.Entry{
			Actor: actor, RemoteIP: req.Caller.RemoteIP, Verb: req.Verb,
			Args: auditArgs(req.Args), OK: resp.OK, Error: resp.Error,
		})
	}()

	switch req.Caller.Role {
	case "admin":
		if !adminVerbs[req.Verb] {
			return fail("unknown verb")
		}
		return s.admin(req)
	case "user":
		if !userVerbs[req.Verb] {
			return fail("unknown verb")
		}
		acct, err := s.Lookup(req.Caller.User)
		if err != nil {
			return fail("unknown account")
		}
		return s.user(req, acct)
	default:
		return fail("missing caller")
	}
}

func (s *Server) admin(req Request) Response {
	a := req.Args
	now := s.now()
	switch req.Verb {
	case "status":
		return ok(map[string]any{
			"version":     s.Version,
			"started":     s.Started,
			"active_bans": len(s.Detector.Bans(now)),
		})
	case "list_bans":
		return ok(s.Detector.Bans(now))
	case "block_ip":
		ip := net.ParseIP(a["ip"])
		if ip == nil {
			return fail("invalid IP address")
		}
		// Never let an admin lock themselves out of WHM.
		if self := net.ParseIP(req.Caller.RemoteIP); self != nil && self.Equal(ip) {
			return fail("refusing to block your own IP address")
		}
		mins, _ := strconv.Atoi(a["minutes"])
		if mins < 0 || mins > 60*24*365 {
			return fail("minutes out of range")
		}
		reason := a["reason"]
		if len(reason) > 200 {
			reason = reason[:200]
		}
		if reason == "" {
			reason = "blocked by admin"
		}
		ban, err := s.Detector.BlockManual(ip, time.Duration(mins)*time.Minute, reason, now)
		if err != nil {
			return fail(err.Error())
		}
		s.bansChanged()
		return ok(ban)
	case "unblock_ip":
		ip := net.ParseIP(a["ip"])
		if ip == nil {
			return fail("invalid IP address")
		}
		if err := s.Detector.Unblock(ip, time.Now()); err != nil {
			return fail(err.Error())
		}
		s.bansChanged()
		return ok(nil)
	case "recent_failures":
		return ok(s.Detector.Recent(limit(a["limit"], 100, 500)))
	case "list_quarantine":
		items, err := s.Quarantine.List("")
		if err != nil {
			return fail("cannot read quarantine")
		}
		return ok(items)
	case "audit_log":
		entries, err := s.Audit.Tail(limit(a["limit"], 100, 1000))
		if err != nil {
			return fail("cannot read audit log")
		}
		return ok(entries)
	}
	return fail("unknown verb")
}

func (s *Server) user(req Request, acct quarantine.Account) Response {
	a := req.Args
	switch req.Verb {
	case "list_findings":
		// Until the malware scanner lands, findings are this account's
		// quarantined files and allowlisted paths.
		items, err := s.Quarantine.List(acct.User)
		if err != nil {
			return fail("cannot read quarantine")
		}
		return ok(map[string]any{
			"quarantined": items,
			"allowlisted": s.FileAllow.List(acct.User),
		})
	case "quarantine":
		it, err := s.Quarantine.Quarantine(acct, a["path"], "quarantined by account owner", s.now())
		if err != nil {
			return fail(userErr(err))
		}
		return ok(it)
	case "restore":
		it, err := s.Quarantine.Restore(acct, a["id"])
		if err != nil {
			return fail(userErr(err))
		}
		return ok(it)
	case "allowlist_file":
		comps, err := pathguard.Split(acct.Home, a["path"])
		if err != nil {
			return fail(userErr(err))
		}
		fd, err := pathguard.OpenParent(acct.Home, comps)
		if err != nil {
			return fail(userErr(err))
		}
		syscall.Close(fd)
		if err := s.FileAllow.Add(acct.User, comps); err != nil {
			return fail("cannot save allowlist")
		}
		return ok(nil)
	}
	return fail("unknown verb")
}

// userErr maps internal errors to messages that are safe to show a
// tenant: they never include absolute paths from outside their home.
func userErr(err error) string {
	for _, known := range []error{
		pathguard.ErrBadPath, pathguard.ErrOutsideHome, pathguard.ErrSymlink,
		pathguard.ErrNotRegular, pathguard.ErrNotOwner, quarantine.ErrNotFound,
	} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	if errors.Is(err, syscall.ENOENT) {
		return "file not found"
	}
	return "operation failed"
}

func (s *Server) bansChanged() {
	if s.BansChanged != nil {
		s.BansChanged()
	}
}

func ok(data any) Response     { return Response{OK: true, Data: data} }
func fail(msg string) Response { return Response{Error: msg} }

func limit(s string, def, max int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func auditArgs(a map[string]string) map[string]string {
	if len(a) == 0 {
		return nil
	}
	out := make(map[string]string, len(a))
	for k, v := range a {
		if len(v) > 300 {
			v = v[:300] + "..."
		}
		out[k] = v
	}
	return out
}

// Serve accepts connections until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln *net.UnixListener) error {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serveConn(conn)
	}
}

func (s *Server) serveConn(conn *net.UnixConn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if !s.AllowAnyPeer {
		uid, err := peerUID(conn)
		if err != nil || uid != 0 {
			log.Printf("rejected connection from uid %d (%v)", uid, err)
			return
		}
	}

	line, err := bufio.NewReader(io.LimitReader(conn, maxRequest)).ReadBytes('\n')
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		writeResp(conn, fail("bad request"))
		return
	}
	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeResp(conn, fail("bad request"))
		return
	}
	writeResp(conn, s.Handle(req))
}

func writeResp(w io.Writer, r Response) {
	b, err := json.Marshal(r)
	if err != nil {
		b = []byte(`{"ok":false,"error":"internal error"}`)
	}
	w.Write(append(b, '\n'))
}

func peerUID(conn *net.UnixConn) (uint32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	return cred.Uid, nil
}

// Listen creates the socket with mode 0600, replacing a stale one.
func Listen(path string) (*net.UnixListener, error) {
	syscall.Unlink(path)
	old := syscall.Umask(0o177)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", path, err)
	}
	ln.SetUnlinkOnClose(true)
	return ln, nil
}
