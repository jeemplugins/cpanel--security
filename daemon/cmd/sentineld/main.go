// sentineld is the root daemon for the Sentinel cPanel security plugin.
// It watches the cPanel login log, bans brute-force IPs with nftables, and
// serves the WHM page and the cPanel AdminBin adapter over a Unix socket.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"

	"github.com/jeemplugins/cpanel--security/daemon/internal/api"
	"github.com/jeemplugins/cpanel--security/daemon/internal/audit"
	"github.com/jeemplugins/cpanel--security/daemon/internal/config"
	"github.com/jeemplugins/cpanel--security/daemon/internal/detector"
	"github.com/jeemplugins/cpanel--security/daemon/internal/firewall"
	"github.com/jeemplugins/cpanel--security/daemon/internal/loginlog"
	"github.com/jeemplugins/cpanel--security/daemon/internal/quarantine"
	"github.com/jeemplugins/cpanel--security/daemon/internal/tail"
)

var version = "0.1.0-dev"

func main() {
	cfgPath := flag.String("config", "/etc/sentinel/config.json", "config file")
	dryRun := flag.Bool("dry-run", false, "log bans instead of changing the firewall")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}
	log.SetFlags(0) // journald adds timestamps
	if err := run(*cfgPath, *dryRun); err != nil {
		log.Fatal(err)
	}
}

func run(cfgPath string, dryRun bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	qdir := filepath.Join(cfg.StateDir, "quarantine")
	for _, d := range []string{cfg.StateDir, qdir, filepath.Dir(cfg.AuditLog), filepath.Dir(cfg.Socket)} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}

	var fw firewall.Firewall = firewall.NewNFT()
	if dryRun {
		fw = firewall.NewMemory()
	}
	if err := fw.Setup(); err != nil {
		return fmt.Errorf("firewall setup: %w", err)
	}

	allow, err := detector.ParseAllowlist(cfg.BruteForce.Allowlist)
	if err != nil {
		return err
	}
	det, err := detector.New(detector.Config{
		Threshold: cfg.BruteForce.Threshold,
		Window:    cfg.Window(),
		BanFor:    cfg.BanFor(),
		Allowlist: allow,
	}, fw)
	if err != nil {
		return err
	}

	bansFile := filepath.Join(cfg.StateDir, "bans.json")
	if saved, err := loadBans(bansFile); err != nil {
		log.Printf("ignoring saved bans: %v", err)
	} else if err := det.Restore(saved, time.Now()); err != nil {
		return fmt.Errorf("restore bans: %w", err)
	}
	unblockedFile := filepath.Join(cfg.StateDir, "unblocked.json")
	if b, err := os.ReadFile(unblockedFile); err == nil {
		var c map[string]time.Time
		if err := json.Unmarshal(b, &c); err != nil {
			log.Printf("ignoring saved unblocks: %v", err)
		} else {
			det.RestoreCleared(c, time.Now())
		}
	}
	saveBans := func() {
		now := time.Now()
		if err := writeJSON(bansFile, det.Bans(now)); err != nil {
			log.Printf("save bans: %v", err)
		}
		if err := writeJSON(unblockedFile, det.Cleared(now)); err != nil {
			log.Printf("save unblocks: %v", err)
		}
	}

	alog, err := audit.Open(cfg.AuditLog)
	if err != nil {
		return err
	}
	defer alog.Close()

	fa, err := api.LoadFileAllowlist(filepath.Join(cfg.StateDir, "file_allowlist.json"))
	if err != nil {
		return err
	}

	srv := &api.Server{
		Detector:    det,
		Quarantine:  &quarantine.Store{Dir: qdir},
		FileAllow:   fa,
		Audit:       alog,
		Lookup:      lookupAccount,
		BansChanged: saveBans,
		Version:     version,
		Started:     time.Now().UTC(),
	}

	ln, err := api.Listen(cfg.Socket)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	if cfg.BruteForce.Enabled {
		f := &tail.Follower{Path: cfg.LoginLog, Interval: time.Second, Backlog: 1 << 20}
		go f.Run(ctx, func(line string) {
			ev, ok := loginlog.Parse(line)
			if !ok {
				return
			}
			ban, err := det.Observe(ev, time.Now())
			if err != nil {
				log.Printf("block %s: %v", ev.IP, err)
				return
			}
			if ban != nil {
				log.Printf("blocked %s until %s: %s", ban.IP, ban.Expires.Format(time.RFC3339), ban.Reason)
				alog.Write(audit.Entry{Actor: "sentinel", Verb: "auto_block", Args: map[string]string{"ip": ban.IP, "reason": ban.Reason}, OK: true})
				saveBans()
			}
		})
	}

	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				det.Prune(time.Now())
			}
		}
	}()

	log.Printf("sentineld %s listening on %s (dry-run=%v)", version, cfg.Socket, dryRun)
	err = srv.Serve(ctx, ln)
	saveBans()
	return err
}

// cPanel usernames: lowercase letters and digits, starting with a letter.
var usernameRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}$`)

// lookupAccount resolves a cPanel account from the system databases.
func lookupAccount(name string) (quarantine.Account, error) {
	if !usernameRE.MatchString(name) {
		return quarantine.Account{}, errors.New("invalid username")
	}
	if _, err := os.Stat(filepath.Join("/var/cpanel/users", name)); err != nil {
		return quarantine.Account{}, errors.New("not a cPanel account")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return quarantine.Account{}, err
	}
	uid, err1 := strconv.ParseUint(u.Uid, 10, 32)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 32)
	if err1 != nil || err2 != nil || uid == 0 {
		return quarantine.Account{}, errors.New("refusing system account")
	}
	return quarantine.Account{User: name, Home: u.HomeDir, UID: uint32(uid), GID: uint32(gid)}, nil
}

func loadBans(path string) ([]detector.Ban, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var bans []detector.Ban
	return bans, json.Unmarshal(b, &bans)
}

func writeJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
