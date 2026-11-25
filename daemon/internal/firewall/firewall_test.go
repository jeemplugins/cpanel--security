package firewall

import (
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

type call struct {
	stdin string
	argv  []string
}

func recorder(calls *[]call) Runner {
	return func(stdin []byte, name string, args ...string) error {
		*calls = append(*calls, call{string(stdin), append([]string{name}, args...)})
		return nil
	}
}

func TestNFTBlockArgs(t *testing.T) {
	var calls []call
	n := &NFT{Bin: "nft", Run: recorder(&calls)}

	if err := n.Block(net.ParseIP("203.0.113.9"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := n.Block(net.ParseIP("2001:db8::1"), 90*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := n.Unblock(net.ParseIP("203.0.113.9")); err != nil {
		t.Fatal(err)
	}

	want := [][]string{
		{"nft", "add", "element", "inet", "sentinel", "blocklist4", "{", "203.0.113.9", "timeout", "3600s", "}"},
		{"nft", "add", "element", "inet", "sentinel", "blocklist6", "{", "2001:db8::1", "timeout", "90s", "}"},
		{"nft", "delete", "element", "inet", "sentinel", "blocklist4", "{", "203.0.113.9", "}"},
	}
	for i, w := range want {
		if !reflect.DeepEqual(calls[i].argv, w) {
			t.Errorf("call %d = %v, want %v", i, calls[i].argv, w)
		}
	}
}

func TestNFTMappedIPv4UsesV4Set(t *testing.T) {
	var calls []call
	n := &NFT{Bin: "nft", Run: recorder(&calls)}
	if err := n.Block(net.ParseIP("::ffff:198.51.100.4"), time.Minute); err != nil {
		t.Fatal(err)
	}
	if calls[0].argv[5] != "blocklist4" || calls[0].argv[7] != "198.51.100.4" {
		t.Fatalf("argv = %v", calls[0].argv)
	}
}

func TestNFTRejects(t *testing.T) {
	n := &NFT{Bin: "nft", Run: func([]byte, string, ...string) error { t.Fatal("should not run"); return nil }}
	if err := n.Block(nil, time.Hour); err == nil {
		t.Error("nil IP accepted")
	}
	if err := n.Block(net.ParseIP("1.2.3.4"), 0); err == nil {
		t.Error("zero duration accepted")
	}
}

func TestNFTSetupFeedsFixedRuleset(t *testing.T) {
	var calls []call
	n := &NFT{Bin: "nft", Run: recorder(&calls)}
	if err := n.Setup(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls[0].argv, []string{"nft", "-f", "-"}) || !strings.Contains(calls[0].stdin, "flags timeout") {
		t.Fatalf("setup call = %+v", calls[0])
	}
}
