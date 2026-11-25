package api

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
)

// FileAllowlist records files an account owner has marked as safe, so the
// scanner skips them. Paths are stored relative to the account's home.
type FileAllowlist struct {
	Path string

	mu sync.Mutex
	m  map[string][]string
}

func LoadFileAllowlist(path string) (*FileAllowlist, error) {
	fa := &FileAllowlist{Path: path, m: map[string][]string{}}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return fa, nil
	}
	if err != nil {
		return nil, err
	}
	return fa, json.Unmarshal(b, &fa.m)
}

const maxAllowlistPerUser = 1000

func (fa *FileAllowlist) Add(user string, comps []string) error {
	p := strings.Join(comps, "/")
	fa.mu.Lock()
	defer fa.mu.Unlock()
	for _, existing := range fa.m[user] {
		if existing == p {
			return nil
		}
	}
	if len(fa.m[user]) >= maxAllowlistPerUser {
		return errors.New("allowlist full")
	}
	fa.m[user] = append(fa.m[user], p)
	sort.Strings(fa.m[user])
	b, err := json.Marshal(fa.m)
	if err != nil {
		return err
	}
	tmp := fa.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, fa.Path)
}

func (fa *FileAllowlist) List(user string) []string {
	fa.mu.Lock()
	defer fa.mu.Unlock()
	return append([]string{}, fa.m[user]...)
}
