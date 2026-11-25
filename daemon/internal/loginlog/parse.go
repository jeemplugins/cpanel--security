// Package loginlog parses failed-login lines from cPanel's login log
// (/usr/local/cpanel/logs/login_log).
package loginlog

import (
	"net"
	"regexp"
	"strconv"
	"time"
)

// Event is one failed login.
type Event struct {
	IP      net.IP
	User    string
	Time    time.Time
	Service string // cpaneld, whostmgrd, webmaild, ...
	Reason  string
}

// Example:
// 203.0.113.9 - root [11/25/2026:10:01:02 -0000] "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN whostmgrd: user password incorrect
var lineRE = regexp.MustCompile(
	`^([0-9A-Fa-f:.]+)\s+-\s+(\S+)\s+` +
		`\[(\d{2})/(\d{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})\]\s+` +
		`"[^"]*"\s+FAILED\s+LOGIN\s+([A-Za-z0-9_-]+):\s*(.*?)\s*$`)

// Parse returns the event on a FAILED LOGIN line, and ok=false for any
// other line (successful logins, deferred logins, garbage).
func Parse(line string) (Event, bool) {
	m := lineRE.FindStringSubmatch(line)
	if m == nil {
		return Event{}, false
	}
	ip := net.ParseIP(m[1])
	if ip == nil {
		return Event{}, false
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	mon, day, year := n(m[3]), n(m[4]), n(m[5])
	hh, mm, ss := n(m[6]), n(m[7]), n(m[8])
	if mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60 {
		return Event{}, false
	}
	offset := (n(m[10])*3600 + n(m[11])*60)
	if m[9] == "-" {
		offset = -offset
	}
	t := time.Date(year, time.Month(mon), day, hh, mm, ss, 0, time.FixedZone("", offset))
	if t.Day() != day { // e.g. 02/31 normalised into March
		return Event{}, false
	}
	return Event{IP: ip, User: m[2], Time: t.UTC(), Service: m[12], Reason: m[13]}, true
}
