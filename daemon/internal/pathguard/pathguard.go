// Package pathguard turns a path supplied by a cPanel user into a file
// handle that is guaranteed to sit inside that user's home directory.
//
// It does not resolve a path and then use the string later (which a tenant
// could race by swapping a directory for a symlink). Instead it walks the
// path one component at a time from an open handle on the home directory,
// opening each directory with O_NOFOLLOW. The caller then acts on the
// final file relative to the returned directory handle.
package pathguard

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"syscall"
)

var (
	ErrOutsideHome = errors.New("path is outside the account's home directory")
	ErrBadPath     = errors.New("invalid path")
	ErrSymlink     = errors.New("path goes through a symlink")
	ErrNotRegular  = errors.New("not a regular file")
	ErrNotOwner    = errors.New("file is not owned by the account")
)

const maxPathLen = 4096

// Split validates p and returns its components relative to home.
// p may be relative to home or absolute (and then must start with home).
// Any "." or ".." component is rejected rather than cleaned away.
func Split(home, p string) ([]string, error) {
	if p == "" || len(p) > maxPathLen || strings.ContainsRune(p, 0) {
		return nil, ErrBadPath
	}
	home = filepath.Clean(home)
	if !filepath.IsAbs(home) || home == "/" {
		return nil, fmt.Errorf("bad home directory %q", home)
	}
	rel := p
	if filepath.IsAbs(p) {
		prefix := home + "/"
		if !strings.HasPrefix(p, prefix) {
			return nil, ErrOutsideHome
		}
		rel = p[len(prefix):]
	}
	var comps []string
	for _, c := range strings.Split(rel, "/") {
		switch c {
		case "":
			continue // tolerate "a//b" and a trailing slash
		case ".", "..":
			return nil, ErrBadPath
		}
		comps = append(comps, c)
	}
	if len(comps) == 0 {
		return nil, ErrBadPath
	}
	return comps, nil
}

// OpenParent opens the directory that holds the last component, walking
// from home without following any symlink. The caller must close the fd.
func OpenParent(home string, comps []string) (int, error) {
	fd, err := syscall.Open(filepath.Clean(home), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open home: %w", err)
	}
	for _, c := range comps[:len(comps)-1] {
		nfd, err := syscall.Openat(fd, c, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		syscall.Close(fd)
		if err != nil {
			if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) {
				return -1, ErrSymlink
			}
			return -1, fmt.Errorf("open %q: %w", c, err)
		}
		fd = nfd
	}
	return fd, nil
}

// OpenFile opens the final component read-only without following a
// symlink, and checks it is a regular file owned by uid. It returns the
// file's fd and stat. The caller must close the fd.
func OpenFile(dirfd int, name string, uid uint32) (int, syscall.Stat_t, error) {
	var st syscall.Stat_t
	fd, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return -1, st, ErrSymlink
		}
		return -1, st, err
	}
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return -1, st, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		syscall.Close(fd)
		return -1, st, ErrNotRegular
	}
	if st.Uid != uid {
		syscall.Close(fd)
		return -1, st, ErrNotOwner
	}
	return fd, st, nil
}
