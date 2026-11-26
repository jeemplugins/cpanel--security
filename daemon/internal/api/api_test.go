package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeemplugins/cpanel--security/daemon/internal/audit"
	"github.com/jeemplugins/cpanel--security/daemon/internal/detector"
	"github.com/jeemplugins/cpanel--security/daemon/internal/firewall"
	"github.com/jeemplugins/cpanel--security/daemon/internal/quarantine"
)

var t0 = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

type fixture struct {
	srv   *Server
	fw    *firewall.Memory
	homes map[string]string
	dir   string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	dir := t.TempDir()
	homes := map[string]string{
		"alice": filepath.Join(dir, "home", "alice"),
		"bob":   filepath.Join(dir, "home", "bob"),
	}
	for _, h := range homes {
		os.MkdirAll(filepath.Join(h, "public_html"), 0o755)
	}
	os.WriteFile(filepath.Join(homes["alice"], "public_html", "bad.php"), []byte("x"), 0o644)
	os.WriteFile(filepath.Join(homes["bob"], "public_html", "bad.php"), []byte("y"), 0o644)
	qdir := filepath.Join(dir, "q")
	os.Mkdir(qdir, 0o700)

	al, _ := detector.ParseAllowlist([]string{"127.0.0.1"})
	fw := firewall.NewMemory()
	det, _ := detector.New(detector.Config{Threshold: 3, Window: time.Minute, BanFor: time.Hour, Allowlist: al}, fw)
	alog, err := audit.Open(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { alog.Close() })
	fa, _ := LoadFileAllowlist(filepath.Join(dir, "allow.json"))

	srv := &Server{
		Detector:   det,
		Quarantine: &quarantine.Store{Dir: qdir},
		FileAllow:  fa,
		Audit:      alog,
		Now:        func() time.Time { return t0 },
		Lookup: func(u string) (quarantine.Account, error) {
			h, ok := homes[u]
			if !ok {
				return quarantine.Account{}, errors.New("no such user")
			}
			return quarantine.Account{User: u, Home: h, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())}, nil
		},
		AllowAnyPeer: true,
	}
	return fixture{srv: srv, fw: fw, homes: homes, dir: dir}
}

func user(name, verb string, args map[string]string) Request {
	return Request{Verb: verb, Caller: Caller{Role: "user", User: name}, Args: args}
}

func admin(verb string, args map[string]string) Request {
	return Request{Verb: verb, Caller: Caller{Role: "admin", RemoteIP: "192.0.2.10"}, Args: args}
}

func TestUserCannotCallAdminVerbs(t *testing.T) {
	f := newFixture(t)
	for _, v := range []string{"block_ip", "unblock_ip", "list_bans", "list_quarantine", "audit_log", "status", "shell"} {
		if r := f.srv.Handle(user("alice", v, map[string]string{"ip": "1.2.3.4"})); r.OK || r.Error != "unknown verb" {
			t.Errorf("user verb %q: %+v", v, r)
		}
	}
	if len(f.fw.Blocked) != 0 {
		t.Fatal("user managed to block an IP")
	}
}

func TestMissingOrUnknownCaller(t *testing.T) {
	f := newFixture(t)
	if r := f.srv.Handle(Request{Verb: "list_bans"}); r.OK {
		t.Fatal("request with no caller accepted")
	}
	if r := f.srv.Handle(user("mallory", "list_findings", nil)); r.OK {
		t.Fatal("unknown account accepted")
	}
}

// The account comes from Caller.User (set by AdminBin from cPanel), never
// from request arguments.
func TestUserArgIgnored(t *testing.T) {
	f := newFixture(t)
	r := f.srv.Handle(user("alice", "quarantine", map[string]string{"path": "public_html/bad.php", "user": "bob"}))
	if !r.OK {
		t.Fatal(r.Error)
	}
	if _, err := os.Stat(filepath.Join(f.homes["bob"], "public_html", "bad.php")); err != nil {
		t.Fatal("bob's file was quarantined")
	}
	if _, err := os.Stat(filepath.Join(f.homes["alice"], "public_html", "bad.php")); !os.IsNotExist(err) {
		t.Fatal("alice's file was not quarantined")
	}
}

func TestUserCannotReachOtherAccountByPath(t *testing.T) {
	f := newFixture(t)
	for _, p := range []string{"../bob/public_html/bad.php", filepath.Join(f.homes["bob"], "public_html", "bad.php")} {
		r := f.srv.Handle(user("alice", "quarantine", map[string]string{"path": p}))
		if r.OK {
			t.Fatalf("%q accepted", p)
		}
	}
	r := f.srv.Handle(user("alice", "allowlist_file", map[string]string{"path": "../bob/x"}))
	if r.OK {
		t.Fatal("allowlist outside home accepted")
	}
}

func TestUserFlowAndIsolation(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("restore needs root: the quarantined copy is mode 0000")
	}
	f := newFixture(t)
	r := f.srv.Handle(user("alice", "quarantine", map[string]string{"path": "public_html/bad.php"}))
	if !r.OK {
		t.Fatal(r.Error)
	}
	id := r.Data.(*quarantine.Item).ID

	if r := f.srv.Handle(user("alice", "allowlist_file", map[string]string{"path": "public_html/ok.php"})); !r.OK {
		t.Fatal(r.Error)
	}

	// bob sees nothing of alice's and can't restore her item.
	r = f.srv.Handle(user("bob", "list_findings", nil))
	data := r.Data.(map[string]any)
	if len(data["quarantined"].([]quarantine.Item)) != 0 || len(data["allowlisted"].([]string)) != 0 {
		t.Fatalf("bob sees: %+v", data)
	}
	if r := f.srv.Handle(user("bob", "restore", map[string]string{"id": id})); r.OK {
		t.Fatal("bob restored alice's file")
	}

	r = f.srv.Handle(user("alice", "list_findings", nil))
	data = r.Data.(map[string]any)
	if len(data["quarantined"].([]quarantine.Item)) != 1 || data["allowlisted"].([]string)[0] != "public_html/ok.php" {
		t.Fatalf("alice sees: %+v", data)
	}
	if r := f.srv.Handle(user("alice", "restore", map[string]string{"id": id})); !r.OK {
		t.Fatal(r.Error)
	}
}

func TestAdminBlockUnblockAndAudit(t *testing.T) {
	f := newFixture(t)
	if r := f.srv.Handle(admin("block_ip", map[string]string{"ip": "203.0.113.7", "minutes": "30"})); !r.OK {
		t.Fatal(r.Error)
	}
	if f.fw.Blocked["203.0.113.7"] != 30*time.Minute {
		t.Fatalf("fw = %v", f.fw.Blocked)
	}
	for _, bad := range []map[string]string{{"ip": "nope"}, {"ip": "127.0.0.1"}, {"ip": "1.2.3.4", "minutes": "-1"}, {"ip": "192.0.2.10"}} {
		if r := f.srv.Handle(admin("block_ip", bad)); r.OK {
			t.Errorf("accepted %v", bad)
		}
	}
	if r := f.srv.Handle(admin("unblock_ip", map[string]string{"ip": "203.0.113.7"})); !r.OK {
		t.Fatal(r.Error)
	}

	r := f.srv.Handle(admin("audit_log", map[string]string{"limit": "10"}))
	entries := r.Data.([]audit.Entry)
	if len(entries) < 2 || entries[0].Verb != "unblock_ip" || entries[0].RemoteIP != "192.0.2.10" || entries[0].Actor != "admin" {
		t.Fatalf("audit = %+v", entries)
	}
}

func TestSocketRoundTripAndMode(t *testing.T) {
	f := newFixture(t)
	sock := filepath.Join(f.dir, "s.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(sock); st.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, want 0600", st.Mode().Perm())
	}
	f.srv.AllowAnyPeer = false // we run as root in CI containers; skip otherwise
	if os.Getuid() != 0 {
		f.srv.AllowAnyPeer = true
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go f.srv.Serve(ctx, ln)

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	json.NewEncoder(conn).Encode(admin("status", nil))
	var resp Response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.OK {
		t.Fatalf("resp = %+v", resp)
	}
}
