package loginlog

import (
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	ev, ok := Parse(`203.0.113.9 - root [11/25/2026:10:00:01 -0000] "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN whostmgrd: user password incorrect`)
	if !ok {
		t.Fatal("expected a match")
	}
	if ev.IP.String() != "203.0.113.9" || ev.User != "root" || ev.Service != "whostmgrd" || ev.Reason != "user password incorrect" {
		t.Fatalf("bad fields: %+v", ev)
	}
	if want := time.Date(2026, 11, 25, 10, 0, 1, 0, time.UTC); !ev.Time.Equal(want) {
		t.Fatalf("time = %v, want %v", ev.Time, want)
	}
}

func TestParseTimezoneAndIPv6(t *testing.T) {
	ev, ok := Parse(`2001:db8::1 - u [11/25/2026:11:00:00 +0100] "POST / HTTP/1.1" FAILED LOGIN cpaneld: x`)
	if !ok {
		t.Fatal("expected a match")
	}
	if ev.IP.String() != "2001:db8::1" {
		t.Fatalf("ip = %v", ev.IP)
	}
	if want := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC); !ev.Time.Equal(want) {
		t.Fatalf("time = %v, want %v", ev.Time, want)
	}
}

func TestParseRejects(t *testing.T) {
	for _, line := range []string{
		"",
		"garbage",
		`1.2.3.4 - a [11/25/2026:10:15:00 -0000] "GET / HTTP/1.1" DEFERRED LOGIN cpaneld: token missing`,
		`1.2.3.4 - a [13/45/2026:10:15:00 -0000] "GET / HTTP/1.1" FAILED LOGIN cpaneld: x`,
		`1.2.3.4 - a [02/31/2026:10:15:00 -0000] "GET / HTTP/1.1" FAILED LOGIN cpaneld: x`,
		`999.2.3.4 - a [11/25/2026:10:15:00 -0000] "GET / HTTP/1.1" FAILED LOGIN cpaneld: x`,
	} {
		if _, ok := Parse(line); ok {
			t.Errorf("should not parse: %q", line)
		}
	}
}
