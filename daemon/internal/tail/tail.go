// Package tail follows a log file by polling, surviving rotation and
// truncation.
package tail

import (
	"bufio"
	"context"
	"io"
	"os"
	"syscall"
	"time"
)

type Follower struct {
	Path     string
	Interval time.Duration
	// Backlog is how much of the existing file to read on first open, so
	// recent attacks are seen right after a restart.
	Backlog int64
}

// Run calls fn for each complete line until ctx is cancelled.
func (t *Follower) Run(ctx context.Context, fn func(string)) {
	var (
		f      *os.File
		r      *bufio.Reader
		ino    uint64
		offset int64
		first  = true
	)
	interval := t.Interval
	if interval <= 0 {
		interval = time.Second
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	for {
		st, err := os.Stat(t.Path)
		if err == nil {
			newIno := st.Sys().(*syscall.Stat_t).Ino
			if f == nil || newIno != ino || st.Size() < offset {
				if f != nil {
					f.Close()
				}
				f, err = os.Open(t.Path)
				if err == nil {
					ino, offset = newIno, 0
					if first && st.Size() > t.Backlog {
						// Start one byte early: if that byte is a newline the
						// backlog begins on a line boundary and no line is lost.
						offset = st.Size() - t.Backlog - 1
						f.Seek(offset, io.SeekStart)
						r = bufio.NewReader(f)
						if line, err := r.ReadString('\n'); err == nil {
							offset += int64(len(line)) // drop partial line
						} else {
							offset = st.Size() // no newline in backlog: start at end
							f.Seek(offset, io.SeekStart)
							r.Reset(f)
						}
					} else {
						r = bufio.NewReader(f)
					}
					first = false
				} else {
					f = nil
				}
			}
		}
		if f != nil {
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					// Incomplete line: rewind so it's re-read once finished.
					if len(line) > 0 {
						f.Seek(offset, io.SeekStart)
						r.Reset(f)
					}
					break
				}
				offset += int64(len(line))
				fn(line[:len(line)-1])
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
