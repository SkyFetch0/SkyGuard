package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// hostile builds a "container root" next to a secret "host" file and plants
// the tricks a hostile container could use.
func hostile(t *testing.T) (root, secret string) {
	t.Helper()
	base := t.TempDir()
	secret = filepath.Join(base, "host-secret")
	if err := os.WriteFile(secret, []byte("HOST-ONLY"), 0o600); err != nil {
		t.Fatal(err)
	}
	root = filepath.Join(base, "rootfs")
	for _, d := range []string{"etc", "var/lib/dpkg", "lib/apk/db", "usr/lib", "app", "dev"} {
		_ = os.MkdirAll(filepath.Join(root, d), 0o755)
	}
	_ = os.WriteFile(filepath.Join(root, "usr/lib/os-release"), []byte("ID=debian\nVERSION_ID=\"12\"\n"), 0o644)
	_ = os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc/os-release")) // the ordinary, relative kind
	_ = os.Symlink(secret, filepath.Join(root, "var/lib/dpkg/status"))             // absolute, to the host file
	_ = os.Symlink("../../../../../../../../.."+secret, filepath.Join(root, "app/package.json"))
	_ = os.Symlink("/proc/self/root"+secret, filepath.Join(root, "app/magic"))
	if err := unix.Mkfifo(filepath.Join(root, "lib/apk/db/installed"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root, secret
}

func TestRootFSStaysInside(t *testing.T) {
	root, secret := hostile(t)
	fs, err := OpenRoot(root, "test")
	if err != nil {
		t.Skip("openat2 not available:", err)
	}
	defer fs.Close()

	b, err := fs.ReadFile("/etc/os-release", 1<<20)
	if err != nil || !strings.Contains(string(b), "debian") {
		t.Fatalf("a relative symlink inside the root: %q %v", b, err)
	}
	// Every way out lands inside the root, where the path does not exist.
	for _, p := range []string{"/var/lib/dpkg/status", "/app/package.json", "/../../../.." + secret, secret} {
		b, err := fs.ReadFile(p, 1<<20)
		if strings.Contains(string(b), "HOST-ONLY") {
			t.Fatalf("%s read the host file", p)
		}
		if err == nil {
			t.Errorf("%s: expected an error, got %q", p, b)
		}
	}
	if _, err := fs.ReadFile("/app/magic", 1<<20); err == nil {
		t.Error("a magic link was followed")
	}
	// A FIFO is refused without blocking.
	done := make(chan error, 1)
	go func() { _, err := fs.ReadFile("/lib/apk/db/installed", 1<<20); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("FIFO: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("reading a FIFO blocked")
	}
	if _, err := fs.ReadFile("/etc", 1<<20); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a directory: %v", err)
	}
	if _, err := fs.ReadFile("/usr/lib/os-release", 4); !errors.Is(err, ErrTooLarge) {
		t.Errorf("size limit: %v", err)
	}
	if names, err := fs.ReadDir("/usr/lib", 10); err != nil || len(names) != 1 || names[0] != "os-release" {
		t.Errorf("ReadDir %v %v", names, err)
	}
	if _, err := fs.ReadDir("/var/lib/dpkg/status", 10); err == nil {
		t.Error("ReadDir followed a link out")
	}
}

func TestRootFSNeverOpensDevices(t *testing.T) {
	root, _ := hostile(t)
	// /dev/null's numbers: opening it is harmless, but the point is that
	// a device under a well-known name is refused before any open for reading.
	if err := unix.Mknod(filepath.Join(root, "dev/planted"), unix.S_IFCHR|0o644, int(unix.Mkdev(1, 3))); err != nil {
		t.Skip("cannot make a device node here:", err)
	}
	_ = os.Remove(filepath.Join(root, "etc/os-release"))
	_ = os.Symlink("/dev/planted", filepath.Join(root, "etc/os-release"))
	fs, err := OpenRoot(root, "test")
	if err != nil {
		t.Skip(err)
	}
	defer fs.Close()
	if _, err := fs.ReadFile("/etc/os-release", 1<<20); !errors.Is(err, ErrNotRegular) {
		t.Errorf("a device node: %v", err)
	}
	if _, err := fs.OpenFile("/dev/planted", 1<<20); !errors.Is(err, ErrNotRegular) {
		t.Errorf("OpenFile on a device node: %v", err)
	}
}
