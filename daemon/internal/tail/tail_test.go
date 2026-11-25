package tail

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestFollowAppendPartialAndRotate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "log")
	os.WriteFile(p, []byte("old1\nold2\n"), 0o600)

	var mu sync.Mutex
	var got []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go (&Follower{Path: p, Interval: 10 * time.Millisecond, Backlog: 5}).Run(ctx, func(l string) {
		mu.Lock()
		got = append(got, l)
		mu.Unlock()
	})

	wait := func(n int) []string {
		t.Helper()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			if len(got) >= n {
				out := append([]string(nil), got...)
				mu.Unlock()
				return out
			}
			mu.Unlock()
			time.Sleep(5 * time.Millisecond)
		}
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("timed out waiting for %d lines, got %v", n, got)
		return nil
	}

	// Backlog of 5 bytes covers only "old2\n" (partial "1\n" before it is dropped).
	if g := wait(1); g[0] != "old2" {
		t.Fatalf("backlog: %v", g)
	}

	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("new1\npar")
	f.Sync()
	time.Sleep(50 * time.Millisecond)
	f.WriteString("tial\n")
	f.Close()
	if g := wait(3); g[1] != "new1" || g[2] != "partial" {
		t.Fatalf("append: %v", g)
	}

	// Rotation: file replaced with a new inode.
	os.Rename(p, p+".1")
	os.WriteFile(p, []byte("rotated\n"), 0o600)
	if g := wait(4); g[3] != "rotated" {
		t.Fatalf("rotate: %v", g)
	}
}
