// Package inventory finds the software that runs on this server, in its
// Docker containers and its Incus instances, with versions, and compares
// them with known vulnerabilities (OSV.dev, when the operator switches it on).
//
// What it reads belongs to whoever controls each container, so it is
// treated as hostile:
//
//   - Nothing from a container is ever run: no "docker exec", no binary of
//     theirs started on the host. Versions come from reading files only:
//     package databases, os-release, package.json and lockfiles, version
//     headers, the build info Go writes into its binaries.
//   - Paths are resolved by the kernel inside the container's root
//     (openat2 with RESOLVE_IN_ROOT), so a planted link such as
//     /var/lib/dpkg/status -> /etc/shadow, absolute or with "..", stays in
//     the container and can never name a host file. Magic links
//     (/proc/<pid>/root and friends) are refused.
//   - A file is first opened with O_PATH, which never calls a device driver,
//     and read only if it turns out to be a regular file: a device node
//     planted under a well-known name (opening some devices has side
//     effects) or a FIFO (which would block the reader) is never opened for
//     reading.
//   - Every read has a size limit, every scan a time limit, and every string
//     a length limit; what is found is shown as text, never interpreted.
//
// When the kernel lacks openat2 (before 5.6) files are read through the
// container engine's API instead, which resolves paths inside the container
// itself; nothing falls back to plain path resolution.
package inventory

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// FS is a read-only view of one target's files.
type FS interface {
	// ReadFile reads a regular file of at most max bytes.
	ReadFile(path string, max int64) ([]byte, error)
	// ReadDir lists up to max names in a directory.
	ReadDir(path string, max int) ([]string, error)
	// OpenFile opens a regular file of at most max bytes for random access.
	OpenFile(path string, max int64) (File, error)
	// Via says how the files are read, for people.
	Via() string
	Close() error
}

// File is an opened regular file.
type File interface {
	io.ReaderAt
	io.Closer
	Size() int64
}

var (
	// ErrNotRegular is returned for anything but a regular file.
	ErrNotRegular = errors.New("not a regular file")
	// ErrTooLarge is returned for a file over the size limit.
	ErrTooLarge = errors.New("file too large")
	// ErrUnsupported is returned by an FS that cannot do something.
	ErrUnsupported = errors.New("not supported here")
)

// RootFS reads files below a root directory with every path resolved by
// the kernel inside that root.
type RootFS struct {
	fd   int
	via  string
	path string
}

// OpenRoot opens dir (/ for the host, /proc/<pid>/root for a container) as
// the root every later path is resolved in. It fails when the kernel cannot
// resolve paths inside a root (openat2, Linux 5.6), so a caller falls back
// to a safe alternative rather than plain resolution.
func OpenRoot(dir, via string) (*RootFS, error) {
	fd, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", dir, err)
	}
	r := &RootFS{fd: fd, via: via, path: dir}
	// probe openat2 once
	probe, err := r.openat2(".", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		unix.Close(fd)
		if errors.Is(err, unix.ENOSYS) {
			return nil, errors.New("this kernel cannot resolve paths inside a container (openat2 needs Linux 5.6)")
		}
		return nil, err
	}
	unix.Close(probe)
	return r, nil
}

// FD is the root directory's descriptor, for checks after opening it.
func (r *RootFS) FD() int { return r.fd }

func (r *RootFS) openat2(path string, flags int) (int, error) {
	p := strings.TrimLeft(path, "/")
	if p == "" {
		p = "."
	}
	flags |= unix.O_CLOEXEC
	if flags&unix.O_PATH == 0 {
		flags |= unix.O_NOCTTY // openat2 refuses it next to O_PATH
	}
	how := unix.OpenHow{
		Flags:   uint64(flags),
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	}
	for {
		fd, err := unix.Openat2(r.fd, p, &how)
		if err == unix.EINTR || err == unix.EAGAIN {
			continue // EAGAIN: a rename raced the lookup; try again
		}
		return fd, err
	}
}

// openRegular opens path for reading only once it is known to be a
// regular file: the O_PATH descriptor never reaches a device driver, and
// reopening it through /proc/self/fd opens that same inode, so nothing can
// be swapped in between.
func (r *RootFS) openRegular(path string, max int64) (*os.File, int64, error) {
	pfd, err := r.openat2(path, unix.O_PATH)
	if err != nil {
		return nil, 0, err
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return nil, 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, 0, ErrNotRegular
	}
	if st.Size > max {
		return nil, 0, ErrTooLarge
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", pfd), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, 0, err
	}
	// the same inode, still a regular file
	var st2 unix.Stat_t
	if err := unix.Fstat(fd, &st2); err != nil || st2.Ino != st.Ino || st2.Dev != st.Dev || st2.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, 0, ErrNotRegular
	}
	return os.NewFile(uintptr(fd), path), st2.Size, nil
}

// ReadFile implements FS.
func (r *RootFS) ReadFile(path string, max int64) ([]byte, error) {
	f, _, err := r.openRegular(path, max)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge // it grew while being read
	}
	return b, nil
}

// ReadDir implements FS.
func (r *RootFS) ReadDir(path string, max int) ([]string, error) {
	fd, err := r.openat2(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NONBLOCK)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	names, err := f.Readdirnames(max)
	if err != nil && !errors.Is(err, io.EOF) {
		return names, err
	}
	return names, nil
}

type osFile struct {
	*os.File
	size int64
}

func (f osFile) Size() int64 { return f.size }

// OpenFile implements FS.
func (r *RootFS) OpenFile(path string, max int64) (File, error) {
	f, size, err := r.openRegular(path, max)
	if err != nil {
		return nil, err
	}
	return osFile{f, size}, nil
}

// Via implements FS.
func (r *RootFS) Via() string { return r.via }

// Close implements FS.
func (r *RootFS) Close() error { return unix.Close(r.fd) }

// IsNotExist reports whether err means the path is not there (or not a
// directory on the way), which detectors treat as "not installed".
func IsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) || errors.Is(err, syscall.ENOTDIR)
}
