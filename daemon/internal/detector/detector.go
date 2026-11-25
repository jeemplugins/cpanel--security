// Package detector turns failed-login events into temporary IP bans.
//
// An IP is banned when it reaches Threshold failures inside Window. The
// ban lasts BanFor; the firewall expires it on its own, and the detector
// forgets it at the same time.
package detector

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/jeemplugins/cpanel--security/daemon/internal/firewall"
	"github.com/jeemplugins/cpanel--security/daemon/internal/loginlog"
)

type Config struct {
	Threshold int
	Window    time.Duration
	BanFor    time.Duration
	Allowlist []*net.IPNet
	// RecentMax bounds the in-memory list of recent failures shown in WHM.
	RecentMax int
}

// Ban is an active block.
type Ban struct {
	IP       string    `json:"ip"`
	Since    time.Time `json:"since"`
	Expires  time.Time `json:"expires"`
	Reason   string    `json:"reason"`
	Failures int       `json:"failures"`
	Manual   bool      `json:"manual"`
}

// Failure is a recent failed login kept for display.
type Failure struct {
	IP      string    `json:"ip"`
	User    string    `json:"user"`
	Service string    `json:"service"`
	Time    time.Time `json:"time"`
	Banned  bool      `json:"banned"`
}

type Detector struct {
	cfg Config
	fw  firewall.Firewall

	mu       sync.Mutex
	failures map[string][]time.Time
	bans     map[string]*Ban
	recent   []Failure
	// cleared holds when an admin last lifted each IP's ban. Failures
	// logged at or before that time never count again, so re-reading the
	// log after a restart doesn't undo an unblock.
	cleared map[string]time.Time
}

func New(cfg Config, fw firewall.Firewall) (*Detector, error) {
	if cfg.Threshold < 1 || cfg.Window <= 0 || cfg.BanFor < time.Second {
		return nil, fmt.Errorf("invalid detector config: threshold=%d window=%v ban=%v", cfg.Threshold, cfg.Window, cfg.BanFor)
	}
	if cfg.RecentMax <= 0 {
		cfg.RecentMax = 500
	}
	return &Detector{
		cfg:      cfg,
		fw:       fw,
		failures: map[string][]time.Time{},
		bans:     map[string]*Ban{},
		cleared:  map[string]time.Time{},
	}, nil
}

// Allowed reports whether ip is on the allowlist and must never be banned.
func (d *Detector) Allowed(ip net.IP) bool {
	for _, n := range d.cfg.Allowlist {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Observe records a failed login. It returns the new ban when this event
// pushed the IP over the threshold.
func (d *Detector) Observe(ev loginlog.Event, now time.Time) (*Ban, error) {
	key := ev.IP.String()

	d.mu.Lock()
	defer d.mu.Unlock()

	d.expireLocked(now)
	_, already := d.bans[key]
	d.recent = append(d.recent, Failure{IP: key, User: ev.User, Service: ev.Service, Time: ev.Time, Banned: already})
	if over := len(d.recent) - d.cfg.RecentMax; over > 0 {
		d.recent = append([]Failure(nil), d.recent[over:]...)
	}

	// Old log lines (for example on first start) count only if they are
	// still inside the window.
	if ev.Time.Before(now.Add(-d.cfg.Window)) || already || d.Allowed(ev.IP) {
		return nil, nil
	}
	if c, ok := d.cleared[key]; ok && !ev.Time.After(c) {
		return nil, nil
	}

	cutoff := now.Add(-d.cfg.Window)
	times := d.failures[key][:0]
	for _, t := range d.failures[key] {
		if !t.Before(cutoff) {
			times = append(times, t)
		}
	}
	times = append(times, ev.Time)
	d.failures[key] = times

	if len(times) < d.cfg.Threshold {
		return nil, nil
	}

	ban := &Ban{
		IP:       key,
		Since:    now,
		Expires:  now.Add(d.cfg.BanFor),
		Reason:   fmt.Sprintf("%d failed logins in %v (last: %s)", len(times), d.cfg.Window, ev.Service),
		Failures: len(times),
	}
	if err := d.fw.Block(ev.IP, d.cfg.BanFor); err != nil {
		return nil, err
	}
	d.bans[key] = ban
	delete(d.failures, key)
	b := *ban
	return &b, nil
}

// BlockManual bans an IP on an admin's request.
func (d *Detector) BlockManual(ip net.IP, dur time.Duration, reason string, now time.Time) (*Ban, error) {
	if ip == nil {
		return nil, fmt.Errorf("invalid IP")
	}
	if d.Allowed(ip) {
		return nil, fmt.Errorf("%s is on the allowlist", ip)
	}
	if dur < time.Second {
		dur = d.cfg.BanFor
	}
	if err := d.fw.Block(ip, dur); err != nil {
		return nil, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	ban := &Ban{IP: ip.String(), Since: now, Expires: now.Add(dur), Reason: reason, Manual: true}
	d.bans[ban.IP] = ban
	b := *ban
	return &b, nil
}

// Unblock lifts a ban early. Failures logged up to now are forgiven.
func (d *Detector) Unblock(ip net.IP, now time.Time) error {
	if ip == nil {
		return fmt.Errorf("invalid IP")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.bans[ip.String()]; !ok {
		return fmt.Errorf("%s is not blocked", ip)
	}
	if err := d.fw.Unblock(ip); err != nil {
		return err
	}
	delete(d.bans, ip.String())
	delete(d.failures, ip.String())
	d.cleared[ip.String()] = now
	return nil
}

// Cleared returns the unblock times that still matter: those inside the
// window, since older failures are ignored anyway.
func (d *Detector) Cleared(now time.Time) map[string]time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.pruneClearedLocked(now)
	out := make(map[string]time.Time, len(d.cleared))
	for k, v := range d.cleared {
		out[k] = v
	}
	return out
}

// RestoreCleared loads unblock times saved before a restart. Call it
// before the log is replayed.
func (d *Detector) RestoreCleared(c map[string]time.Time, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, v := range c {
		if ip := net.ParseIP(k); ip != nil {
			d.cleared[ip.String()] = v
		}
	}
	d.pruneClearedLocked(now)
}

func (d *Detector) pruneClearedLocked(now time.Time) {
	cutoff := now.Add(-d.cfg.Window)
	for k, t := range d.cleared {
		if t.Before(cutoff) {
			delete(d.cleared, k)
		}
	}
}

// Bans returns active bans, soonest-expiring last.
func (d *Detector) Bans(now time.Time) []Ban {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expireLocked(now)
	out := make([]Ban, 0, len(d.bans))
	for _, b := range d.bans {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Since.After(out[j].Since) })
	return out
}

// Recent returns recent failures, newest first.
func (d *Detector) Recent(limit int) []Failure {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := len(d.recent)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Failure, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, d.recent[i])
	}
	return out
}

// Restore re-applies saved bans after a restart; expired ones are dropped.
func (d *Detector) Restore(bans []Ban, now time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, b := range bans {
		left := b.Expires.Sub(now)
		ip := net.ParseIP(b.IP)
		if ip == nil || left < time.Second {
			continue
		}
		if err := d.fw.Block(ip, left); err != nil {
			return err
		}
		bb := b
		d.bans[b.IP] = &bb
	}
	return nil
}

// Prune drops failure history that has fallen out of the window, so
// memory stays bounded under a wide, slow scan.
func (d *Detector) Prune(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.expireLocked(now)
	cutoff := now.Add(-d.cfg.Window)
	for k, times := range d.failures {
		if len(times) == 0 || times[len(times)-1].Before(cutoff) {
			delete(d.failures, k)
		}
	}
	d.pruneClearedLocked(now)
}

func (d *Detector) expireLocked(now time.Time) {
	for k, b := range d.bans {
		if !now.Before(b.Expires) {
			delete(d.bans, k)
		}
	}
}

// ParseAllowlist turns IPs and CIDRs into networks.
func ParseAllowlist(entries []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, e := range entries {
		if ip := net.ParseIP(e); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, fmt.Errorf("allowlist entry %q is not an IP or CIDR", e)
		}
		out = append(out, n)
	}
	return out, nil
}
