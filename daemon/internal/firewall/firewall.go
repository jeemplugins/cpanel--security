// Package firewall applies IP bans. The production backend is nftables,
// using sets with per-element timeouts so the kernel expires bans even
// if the daemon is down.
package firewall

import (
	"bytes"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"sync"
	"time"
)

// Firewall blocks and unblocks single IP addresses.
type Firewall interface {
	// Setup creates the table, sets and drop rules. Safe to call repeatedly.
	Setup() error
	Block(ip net.IP, d time.Duration) error
	Unblock(ip net.IP) error
}

// Runner runs a binary with an argument array and optional stdin. It never
// goes through a shell.
type Runner func(stdin []byte, name string, args ...string) error

// ExecRunner is the real Runner.
func ExecRunner(stdin []byte, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, bytes.TrimSpace(out))
	}
	return nil
}

const (
	Table = "sentinel"
	Set4  = "blocklist4"
	Set6  = "blocklist6"
)

// Ruleset is fixed text with no user input. Deleting and recreating the
// table makes Setup idempotent; existing bans are re-applied by the daemon
// from its state file after Setup.
const Ruleset = `table inet sentinel
delete table inet sentinel
table inet sentinel {
	set blocklist4 {
		type ipv4_addr
		flags timeout
	}
	set blocklist6 {
		type ipv6_addr
		flags timeout
	}
	chain input {
		type filter hook input priority -5; policy accept;
		ip saddr @blocklist4 drop
		ip6 saddr @blocklist6 drop
	}
}
`

// NFT is the nftables backend.
type NFT struct {
	Bin string // path to nft, default "nft"
	Run Runner
}

func NewNFT() *NFT { return &NFT{Bin: "nft", Run: ExecRunner} }

func (n *NFT) Setup() error {
	return n.Run([]byte(Ruleset), n.Bin, "-f", "-")
}

func (n *NFT) Block(ip net.IP, d time.Duration) error {
	set, addr, err := setFor(ip)
	if err != nil {
		return err
	}
	secs := int64(d / time.Second)
	if secs < 1 {
		return fmt.Errorf("ban duration too short: %v", d)
	}
	// Each token is a separate argv entry; addr is net.IP.String() output,
	// so it can only contain hex digits, dots and colons.
	return n.Run(nil, n.Bin, "add", "element", "inet", Table, set,
		"{", addr, "timeout", strconv.FormatInt(secs, 10)+"s", "}")
}

func (n *NFT) Unblock(ip net.IP) error {
	set, addr, err := setFor(ip)
	if err != nil {
		return err
	}
	return n.Run(nil, n.Bin, "delete", "element", "inet", Table, set, "{", addr, "}")
}

func setFor(ip net.IP) (set, addr string, err error) {
	if ip == nil {
		return "", "", fmt.Errorf("invalid IP")
	}
	if v4 := ip.To4(); v4 != nil {
		return Set4, v4.String(), nil
	}
	if len(ip) == net.IPv6len {
		return Set6, ip.String(), nil
	}
	return "", "", fmt.Errorf("invalid IP")
}

// Memory is an in-memory Firewall for tests and --dry-run.
type Memory struct {
	mu      sync.Mutex
	Blocked map[string]time.Duration
}

func NewMemory() *Memory { return &Memory{Blocked: map[string]time.Duration{}} }

func (m *Memory) Setup() error { return nil }

func (m *Memory) Block(ip net.IP, d time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Blocked[ip.String()] = d
	return nil
}

func (m *Memory) Unblock(ip net.IP) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.Blocked, ip.String())
	return nil
}

func (m *Memory) Has(ip string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.Blocked[ip]
	return ok
}
