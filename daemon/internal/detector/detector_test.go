package detector

import (
	"net"
	"testing"
	"time"

	"github.com/jeemplugins/cpanel--security/daemon/internal/firewall"
	"github.com/jeemplugins/cpanel--security/daemon/internal/loginlog"
)

var t0 = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

func newDet(t *testing.T, allow ...string) (*Detector, *firewall.Memory) {
	t.Helper()
	al, err := ParseAllowlist(allow)
	if err != nil {
		t.Fatal(err)
	}
	fw := firewall.NewMemory()
	d, err := New(Config{Threshold: 3, Window: 10 * time.Minute, BanFor: time.Hour, Allowlist: al}, fw)
	if err != nil {
		t.Fatal(err)
	}
	return d, fw
}

func ev(ip string, at time.Time) loginlog.Event {
	return loginlog.Event{IP: net.ParseIP(ip), User: "root", Service: "whostmgrd", Time: at}
}

// Brute-force simulation: an IP is blocked at the threshold and the ban
// expires after BanFor.
func TestBlocksAtThresholdAndExpires(t *testing.T) {
	d, fw := newDet(t)
	ip := "203.0.113.9"

	for i := 0; i < 2; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		if ban, err := d.Observe(ev(ip, at), at); err != nil || ban != nil {
			t.Fatalf("attempt %d: ban=%v err=%v", i+1, ban, err)
		}
	}
	at := t0.Add(2 * time.Minute)
	ban, err := d.Observe(ev(ip, at), at)
	if err != nil || ban == nil {
		t.Fatalf("expected ban on 3rd failure, got %v %v", ban, err)
	}
	if !fw.Has(ip) || fw.Blocked[ip] != time.Hour {
		t.Fatalf("firewall not updated: %v", fw.Blocked)
	}
	if !ban.Expires.Equal(at.Add(time.Hour)) {
		t.Fatalf("expires = %v", ban.Expires)
	}

	// Further failures while banned don't re-block.
	if b, _ := d.Observe(ev(ip, at.Add(time.Second)), at.Add(time.Second)); b != nil {
		t.Fatal("re-banned while already banned")
	}

	if got := d.Bans(at.Add(59 * time.Minute)); len(got) != 1 {
		t.Fatalf("ban gone too early: %v", got)
	}
	if got := d.Bans(at.Add(time.Hour)); len(got) != 0 {
		t.Fatalf("ban not expired: %v", got)
	}
}

func TestFailuresOutsideWindowDontCount(t *testing.T) {
	d, fw := newDet(t)
	ip := "198.51.100.4"
	for i := 0; i < 5; i++ {
		at := t0.Add(time.Duration(i) * 6 * time.Minute) // 6 min apart, window 10 min
		if ban, _ := d.Observe(ev(ip, at), at); ban != nil {
			t.Fatalf("banned on slow attempts at %d", i)
		}
	}
	if fw.Has(ip) {
		t.Fatal("slow attempts should not be blocked")
	}
}

func TestOldLogLinesIgnored(t *testing.T) {
	d, _ := newDet(t)
	for i := 0; i < 5; i++ {
		if ban, _ := d.Observe(ev("192.0.2.1", t0.Add(-time.Hour)), t0); ban != nil {
			t.Fatal("banned on stale log lines")
		}
	}
}

func TestAllowlistNeverBlocked(t *testing.T) {
	d, fw := newDet(t, "127.0.0.1", "10.0.0.0/8", "::1")
	for _, ip := range []string{"127.0.0.1", "10.1.2.3", "::1"} {
		for i := 0; i < 5; i++ {
			d.Observe(ev(ip, t0), t0)
		}
		if fw.Has(ip) {
			t.Errorf("%s was blocked despite allowlist", ip)
		}
	}
	if _, err := d.BlockManual(net.ParseIP("10.9.9.9"), time.Hour, "x", t0); err == nil {
		t.Error("manual block of allowlisted IP accepted")
	}
}

func TestManualBlockAndUnblock(t *testing.T) {
	d, fw := newDet(t)
	ip := net.ParseIP("203.0.113.50")
	if _, err := d.BlockManual(ip, 0, "admin", t0); err != nil {
		t.Fatal(err)
	}
	if fw.Blocked["203.0.113.50"] != time.Hour {
		t.Fatal("default ban duration not applied")
	}
	if err := d.Unblock(ip, t0); err != nil {
		t.Fatal(err)
	}
	if fw.Has("203.0.113.50") || len(d.Bans(t0)) != 0 {
		t.Fatal("unblock did not clear ban")
	}
	if err := d.Unblock(ip, t0); err == nil {
		t.Fatal("unblocking a non-blocked IP should error")
	}
}

func TestRestoreSkipsExpired(t *testing.T) {
	d, fw := newDet(t)
	err := d.Restore([]Ban{
		{IP: "203.0.113.1", Expires: t0.Add(30 * time.Minute)},
		{IP: "203.0.113.2", Expires: t0.Add(-time.Minute)},
		{IP: "not-an-ip", Expires: t0.Add(time.Hour)},
	}, t0)
	if err != nil {
		t.Fatal(err)
	}
	if !fw.Has("203.0.113.1") || fw.Has("203.0.113.2") || len(fw.Blocked) != 1 {
		t.Fatalf("restore result: %v", fw.Blocked)
	}
	if fw.Blocked["203.0.113.1"] != 30*time.Minute {
		t.Fatalf("restored with wrong remaining time: %v", fw.Blocked["203.0.113.1"])
	}
}

func TestRecentIsBoundedAndNewestFirst(t *testing.T) {
	fw := firewall.NewMemory()
	d, _ := New(Config{Threshold: 100, Window: time.Hour, BanFor: time.Hour, RecentMax: 3}, fw)
	for i := 0; i < 5; i++ {
		at := t0.Add(time.Duration(i) * time.Second)
		d.Observe(ev("192.0.2."+string(rune('1'+i)), at), at)
	}
	r := d.Recent(0)
	if len(r) != 3 || r[0].IP != "192.0.2.5" || r[2].IP != "192.0.2.3" {
		t.Fatalf("recent = %+v", r)
	}
}

func TestParseAllowlistRejectsJunk(t *testing.T) {
	if _, err := ParseAllowlist([]string{"nope"}); err == nil {
		t.Fatal("junk accepted")
	}
}

// Re-reading the log after a restart must not re-ban an IP the admin
// unblocked: the old failures were already forgiven.
func TestUnblockSurvivesLogReplay(t *testing.T) {
	d, fw := newDet(t)
	ip := "203.0.113.77"
	var fails []loginlog.Event
	for i := 0; i < 3; i++ {
		fails = append(fails, ev(ip, t0.Add(time.Duration(i)*time.Second)))
	}
	for _, e := range fails {
		d.Observe(e, e.Time)
	}
	if !fw.Has(ip) {
		t.Fatal("not banned")
	}
	unblockAt := t0.Add(time.Minute)
	if err := d.Unblock(net.ParseIP(ip), unblockAt); err != nil {
		t.Fatal(err)
	}

	// "Restart": a fresh detector gets the saved state, then the log replays.
	restartAt := unblockAt.Add(time.Minute)
	saved := d.Cleared(restartAt)
	d2, fw2 := newDet(t)
	d2.RestoreCleared(saved, restartAt)
	for _, e := range fails {
		if ban, _ := d2.Observe(e, restartAt); ban != nil {
			t.Fatal("replayed failures re-banned an unblocked IP")
		}
	}
	if fw2.Has(ip) {
		t.Fatal("firewall re-blocked after replay")
	}

	// New failures after the unblock still count.
	for i := 1; i <= 3; i++ {
		at := restartAt.Add(time.Duration(i) * time.Second)
		d2.Observe(ev(ip, at), at)
	}
	if !fw2.Has(ip) {
		t.Fatal("fresh attack after unblock was not banned")
	}

	// Unblock times older than the window are dropped.
	if got := d2.Cleared(unblockAt.Add(11 * time.Minute)); len(got) != 0 {
		t.Fatalf("stale unblock kept: %v", got)
	}
}
