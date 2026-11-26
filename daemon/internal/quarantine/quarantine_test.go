package quarantine

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeemplugins/cpanel--security/daemon/internal/pathguard"
)

var now = time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)

type env struct {
	home  string
	other string // another account's home
	acct  Account
	store *Store
}

func setup(t *testing.T) env {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	other := filepath.Join(root, "home", "bob")
	qdir := filepath.Join(root, "quarantine")
	for _, d := range []string{filepath.Join(home, "public_html", "wp"), other, qdir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(home, "public_html", "shell.php"), "<?php evil(); ?>", 0o644)
	write(t, filepath.Join(other, "secret.txt"), "bob's secret", 0o600)
	return env{
		home:  home,
		other: other,
		acct:  Account{User: "alice", Home: home, UID: uint32(os.Getuid()), GID: uint32(os.Getgid())},
		store: &Store{Dir: qdir},
	}
}

func write(t *testing.T, p, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

func TestQuarantineAndRestoreRoundTrip(t *testing.T) {
	skipUnlessRoot(t)
	e := setup(t)
	orig := filepath.Join(e.home, "public_html", "shell.php")

	it, err := e.store.Quarantine(e.acct, "public_html/shell.php", "web shell", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(orig); !os.IsNotExist(err) {
		t.Fatal("original still present")
	}
	st, err := os.Stat(filepath.Join(e.store.Dir, it.ID))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0 {
		t.Fatalf("quarantined copy mode = %v, want 0000", st.Mode().Perm())
	}
	if it.Path != "public_html/shell.php" || it.Size != 16 || it.Mode != 0o644 {
		t.Fatalf("item = %+v", it)
	}

	list, _ := e.store.List("alice")
	if len(list) != 1 || list[0].ID != it.ID {
		t.Fatalf("list = %+v", list)
	}

	if _, err := e.store.Restore(e.acct, it.ID); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(orig)
	if err != nil || string(b) != "<?php evil(); ?>" {
		t.Fatalf("restored content = %q, %v", b, err)
	}
	if st, _ := os.Stat(orig); st.Mode().Perm() != 0o644 {
		t.Fatalf("restored mode = %v", st.Mode().Perm())
	}
	if list, _ := e.store.List(""); len(list) != 0 {
		t.Fatal("item left in store after restore")
	}
}

func TestAbsolutePathInsideHomeAccepted(t *testing.T) {
	e := setup(t)
	if _, err := e.store.Quarantine(e.acct, filepath.Join(e.home, "public_html", "shell.php"), "", now); err != nil {
		t.Fatal(err)
	}
}

// Path-escape tests required by the spec: symlinks, "..", absolute paths.
func TestPathEscapesRejected(t *testing.T) {
	e := setup(t)

	// Final component is a symlink to another account's file.
	if err := os.Symlink(filepath.Join(e.other, "secret.txt"), filepath.Join(e.home, "link.txt")); err != nil {
		t.Fatal(err)
	}
	// A directory component is a symlink to another account's home.
	if err := os.Symlink(e.other, filepath.Join(e.home, "public_html", "bobdir")); err != nil {
		t.Fatal(err)
	}

	cases := map[string]error{
		"link.txt":                           pathguard.ErrSymlink,
		"public_html/bobdir/secret.txt":      pathguard.ErrSymlink,
		"../bob/secret.txt":                  pathguard.ErrBadPath,
		"public_html/../../bob/secret.txt":   pathguard.ErrBadPath,
		"./public_html/shell.php":            pathguard.ErrBadPath,
		filepath.Join(e.other, "secret.txt"): pathguard.ErrOutsideHome,
		"/etc/passwd":                        pathguard.ErrOutsideHome,
		e.home + "2/x":                       pathguard.ErrOutsideHome, // /home/alice2 is not inside /home/alice
		"":                                   pathguard.ErrBadPath,
		"a\x00b":                             pathguard.ErrBadPath,
		"public_html":                        pathguard.ErrNotRegular,
	}
	for p, want := range cases {
		_, err := e.store.Quarantine(e.acct, p, "", now)
		if !errors.Is(err, want) {
			t.Errorf("%q: err = %v, want %v", p, err, want)
		}
	}

	// Nothing outside alice's home was touched.
	if b, err := os.ReadFile(filepath.Join(e.other, "secret.txt")); err != nil || string(b) != "bob's secret" {
		t.Fatal("bob's file was touched")
	}
	if list, _ := e.store.List(""); len(list) != 0 {
		t.Fatalf("something was quarantined: %+v", list)
	}
}

func TestFileOwnedBySomeoneElseRejected(t *testing.T) {
	e := setup(t)
	acct := e.acct
	acct.UID++ // the file is owned by the test user, not this account
	_, err := e.store.Quarantine(acct, "public_html/shell.php", "", now)
	if !errors.Is(err, pathguard.ErrNotOwner) {
		t.Fatalf("err = %v, want ErrNotOwner", err)
	}
}

func TestRestoreRules(t *testing.T) {
	skipUnlessRoot(t)
	e := setup(t)
	it, err := e.store.Quarantine(e.acct, "public_html/shell.php", "", now)
	if err != nil {
		t.Fatal(err)
	}

	// Another account can't restore (or even see) alice's item.
	bob := Account{User: "bob", Home: e.other, UID: e.acct.UID, GID: e.acct.GID}
	if _, err := e.store.Restore(bob, it.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bob restore err = %v", err)
	}

	// Never overwrite: a new file at the same path blocks restore.
	write(t, filepath.Join(e.home, "public_html", "shell.php"), "new", 0o644)
	if _, err := e.store.Restore(e.acct, it.ID); err == nil {
		t.Fatal("restore overwrote an existing file")
	}
	os.Remove(filepath.Join(e.home, "public_html", "shell.php"))

	// Restore must not write through a symlink planted at the path.
	target := filepath.Join(e.other, "planted.txt")
	if err := os.Symlink(target, filepath.Join(e.home, "public_html", "shell.php")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Restore(e.acct, it.ID); err == nil {
		t.Fatal("restore followed a symlink")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatal("restore wrote outside the home directory")
	}
	os.Remove(filepath.Join(e.home, "public_html", "shell.php"))

	// Directory swapped for a symlink after quarantine.
	os.RemoveAll(filepath.Join(e.home, "public_html"))
	if err := os.Symlink(e.other, filepath.Join(e.home, "public_html")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.Restore(e.acct, it.ID); !errors.Is(err, pathguard.ErrSymlink) {
		t.Fatalf("restore through symlinked dir: err = %v", err)
	}

	// Malformed IDs never touch the filesystem.
	for _, id := range []string{"", "../../etc/passwd", "ABC"} {
		if _, err := e.store.Restore(e.acct, id); !errors.Is(err, ErrNotFound) {
			t.Errorf("id %q: err = %v", id, err)
		}
	}
}

// Quarantined copies are mode 0000, so only root (as the daemon runs) can
// read them back. Restore tests need root; CI runs them with sudo.
func skipUnlessRoot(t *testing.T) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("restore needs root: the quarantined copy is mode 0000")
	}
}
