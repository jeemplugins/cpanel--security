// Package audit writes an append-only JSON-lines log of every action.
package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"
)

type Entry struct {
	Time     time.Time         `json:"time"`
	Actor    string            `json:"actor"` // "admin" or "user:<name>"
	RemoteIP string            `json:"remote_ip,omitempty"`
	Verb     string            `json:"verb"`
	Args     map[string]string `json:"args,omitempty"`
	OK       bool              `json:"ok"`
	Error    string            `json:"error,omitempty"`
}

type Log struct {
	path string
	mu   sync.Mutex
	f    *os.File
}

func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{path: path, f: f}, nil
}

func (l *Log) Write(e Entry) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.f.Write(append(b, '\n'))
	return err
}

// Tail returns up to n most recent entries, newest first.
func (l *Log) Tail(n int) ([]Entry, error) {
	f, err := os.Open(l.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read at most the last 2 MB to keep this cheap on a large log.
	const maxRead = 2 << 20
	if st, err := f.Stat(); err == nil && st.Size() > maxRead {
		f.Seek(st.Size()-maxRead, 0)
	}
	var ring []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue // partial first line or corruption
		}
		ring = append(ring, e)
		if len(ring) > n {
			ring = ring[1:]
		}
	}
	out := make([]Entry, len(ring))
	for i := range ring {
		out[i] = ring[len(ring)-1-i]
	}
	return out, sc.Err()
}

func (l *Log) Close() error { return l.f.Close() }
