// Package loginlog parses failed-login lines from cPanel's login log
// (/usr/local/cpanel/logs/login_log).
package loginlog

import (
	"net"
	"regexp"
	"strconv"
	"strings"
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

// cPanel 11.x+ (seen on cPanel 138, AlmaLinux 9):
// [2026-11-25 19:40:16 +0000] info [whostmgrd] 138.68.0.230 - root "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN whostmgrd: user password incorrect
var currentRE = regexp.MustCompile(
	`^\[(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})\]\s+\S+\s+\[[^\]]*\]\s+` +
		`([0-9A-Fa-f:.]+)\s+-\s+(\S+)\s+` +
		`"[^"]*"\s+FAILED\s+LOGIN\s+([A-Za-z0-9_-]+):\s*(.*?)\s*$`)

// Older format:
// 203.0.113.9 - root [11/25/2026:10:01:02 -0000] "POST /login/?login_only=1 HTTP/1.1" FAILED LOGIN whostmgrd: user password incorrect
var legacyRE = regexp.MustCompile(
	`^([0-9A-Fa-f:.]+)\s+-\s+(\S+)\s+` +
		`\[(\d{2})/(\d{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-])(\d{2})(\d{2})\]\s+` +
		`"[^"]*"\s+FAILED\s+LOGIN\s+([A-Za-z0-9_-]+):\s*(.*?)\s*$`)

type fields struct {
	ip, user, service, reason  string
	year, mon, day, hh, mm, ss string
	sign, tzh, tzm             string
}

// Parse returns the event on a FAILED LOGIN line, and ok=false for any
// other line (successful logins, deferred logins, garbage).
func Parse(line string) (Event, bool) {
	var f fields
	if m := currentRE.FindStringSubmatch(line); m != nil {
		f = fields{year: m[1], mon: m[2], day: m[3], hh: m[4], mm: m[5], ss: m[6],
			sign: m[7], tzh: m[8], tzm: m[9], ip: m[10], user: m[11], service: m[12], reason: m[13]}
	} else if m := legacyRE.FindStringSubmatch(line); m != nil {
		f = fields{ip: m[1], user: m[2], mon: m[3], day: m[4], year: m[5], hh: m[6], mm: m[7], ss: m[8],
			sign: m[9], tzh: m[10], tzm: m[11], service: m[12], reason: m[13]}
	} else {
		return Event{}, false
	}
	return build(f)
}

// LooksLikeFailure reports whether a line mentions a failed login. When it
// is true but Parse fails, the line is in a format this parser doesn't
// know, and failures from it would be missed.
func LooksLikeFailure(line string) bool {
	return strings.Contains(line, "FAILED LOGIN")
}

func build(f fields) (Event, bool) {
	ip := net.ParseIP(f.ip)
	if ip == nil {
		return Event{}, false
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	mon, day, year := n(f.mon), n(f.day), n(f.year)
	hh, mm, ss := n(f.hh), n(f.mm), n(f.ss)
	if mon < 1 || mon > 12 || day < 1 || day > 31 || hh > 23 || mm > 59 || ss > 60 {
		return Event{}, false
	}
	offset := n(f.tzh)*3600 + n(f.tzm)*60
	if f.sign == "-" {
		offset = -offset
	}
	t := time.Date(year, time.Month(mon), day, hh, mm, ss, 0, time.FixedZone("", offset))
	if t.Day() != day { // e.g. 02/31 normalised into March
		return Event{}, false
	}
	return Event{IP: ip, User: f.user, Time: t.UTC(), Service: f.service, Reason: f.reason}, true
}
