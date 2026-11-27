// Package quarantine moves a user's file into a root-only store and puts
// it back on request. All file access inside the user's home goes through
// pathguard, so a tenant cannot point the root daemon at another account's
// files or at system files with symlinks or "..".
package quarantine

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jeemplugins/cpanel--security/daemon/internal/pathguard"
)

// Account is the identity the daemon acts for. It always comes from the
// system account database, never from the request.
type Account struct {
	User string
	Home string
	UID  uint32
	GID  uint32
	// Created identifies this particular account (cPanel's STARTDATE), so
	// an account created later with the same username is a different owner.
	Created string
}

// Key identifies the owner of per-account data. A deleted account's data
// never matches a new account that reuses the username.
func (a Account) Key() string {
	return fmt.Sprintf("%s:%d:%s", a.User, a.UID, a.Created)
}

// Item describes one quarantined file.
type Item struct {
	ID          string    `json:"id"`
	User        string    `json:"user"`
	Owner       string    `json:"owner,omitempty"` // Account.Key() of the owner
	Path        string    `json:"path"`            // relative to the account's home
	Mode        uint32    `json:"mode"`
	Size        int64     `json:"size"`
	SHA256      string    `json:"sha256"`
	Reason      string    `json:"reason"`
	Quarantined time.Time `json:"quarantined"`
}

type Store struct {
	Dir string // e.g. /var/lib/sentinel/quarantine, mode 0700 root
}

var idRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

var ErrNotFound = errors.New("quarantine item not found")

// Quarantine moves path (relative to acct.Home, or absolute inside it)
// into the store. The stored copy is root-owned with mode 0000.
func (s *Store) Quarantine(acct Account, path, reason string, now time.Time) (*Item, error) {
	comps, err := pathguard.Split(acct.Home, path)
	if err != nil {
		return nil, err
	}
	dirfd, err := pathguard.OpenParent(acct.Home, comps)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dirfd)

	name := comps[len(comps)-1]
	fd, st, err := pathguard.OpenFile(dirfd, name, acct.UID)
	if err != nil {
		return nil, err
	}
	src := os.NewFile(uintptr(fd), name)
	defer src.Close()

	id, err := newID()
	if err != nil {
		return nil, err
	}
	dataPath := filepath.Join(s.Dir, id)
	dst, err := os.OpenFile(dataPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(dst, h), src)
	if err == nil {
		err = dst.Sync()
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(dataPath, 0)
	}
	if err != nil {
		os.Remove(dataPath)
		return nil, fmt.Errorf("copy to quarantine: %w", err)
	}

	item := &Item{
		ID:          id,
		User:        acct.User,
		Owner:       acct.Key(),
		Path:        strings.Join(comps, "/"),
		Mode:        st.Mode & 0o7777 &^ (syscall.S_ISUID | syscall.S_ISGID),
		Size:        size,
		SHA256:      hex.EncodeToString(h.Sum(nil)),
		Reason:      reason,
		Quarantined: now.UTC(),
	}
	if err := s.writeMeta(item); err != nil {
		os.Remove(dataPath)
		return nil, err
	}

	// Remove the original relative to the same directory handle we
	// checked, so a swapped path can't make us delete something else.
	if err := syscall.Unlinkat(dirfd, name); err != nil {
		os.Remove(dataPath)
		os.Remove(s.metaPath(id))
		return nil, fmt.Errorf("remove original: %w", err)
	}
	return item, nil
}

// Restore puts an item back where it came from, owned by the account.
// It refuses if a file now exists at that path.
func (s *Store) Restore(acct Account, id string) (*Item, error) {
	item, err := s.Get(id)
	if err != nil {
		return nil, err
	}
	if item.Owner != acct.Key() {
		return nil, ErrNotFound // don't reveal other accounts' items
	}
	comps, err := pathguard.Split(acct.Home, item.Path)
	if err != nil {
		return nil, err
	}
	dirfd, err := pathguard.OpenParent(acct.Home, comps)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dirfd)

	src, err := os.Open(filepath.Join(s.Dir, id))
	if err != nil {
		return nil, err
	}
	defer src.Close()

	name := comps[len(comps)-1]
	// O_EXCL|O_NOFOLLOW: never overwrite, never write through a symlink.
	fd, err := syscall.Openat(dirfd, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return nil, fmt.Errorf("a file already exists at %s", item.Path)
		}
		return nil, err
	}
	dst := os.NewFile(uintptr(fd), name)
	_, err = io.Copy(dst, src)
	if err == nil {
		err = dst.Chown(int(acct.UID), int(acct.GID))
	}
	if err == nil {
		err = dst.Chmod(os.FileMode(item.Mode & 0o777))
	}
	if cerr := dst.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		syscall.Unlinkat(dirfd, name)
		return nil, fmt.Errorf("restore: %w", err)
	}

	os.Remove(filepath.Join(s.Dir, id))
	os.Remove(s.metaPath(id))
	return item, nil
}

// Get loads one item's metadata.
func (s *Store) Get(id string) (*Item, error) {
	if !idRE.MatchString(id) {
		return nil, ErrNotFound
	}
	b, err := os.ReadFile(s.metaPath(id))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var it Item
	if err := json.Unmarshal(b, &it); err != nil {
		return nil, err
	}
	return &it, nil
}

// List returns every item, for the server admin.
func (s *Store) List() ([]Item, error) {
	return s.list(func(*Item) bool { return true })
}

// ListFor returns the items that belong to this account. Items left by a
// deleted account with the same username are not included.
func (s *Store) ListFor(acct Account) ([]Item, error) {
	key := acct.Key()
	return s.list(func(it *Item) bool { return it.Owner == key })
}

func (s *Store) list(keep func(*Item) bool) ([]Item, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		return nil, err
	}
	out := []Item{}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok {
			continue
		}
		it, err := s.Get(id)
		if err != nil {
			continue
		}
		if keep(it) {
			out = append(out, *it)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Quarantined.After(out[j].Quarantined) })
	return out, nil
}

func (s *Store) metaPath(id string) string { return filepath.Join(s.Dir, id+".json") }

func (s *Store) writeMeta(it *Item) error {
	b, err := json.Marshal(it)
	if err != nil {
		return err
	}
	return os.WriteFile(s.metaPath(it.ID), b, 0o600)
}

func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
