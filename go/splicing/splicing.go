// Package splicing implements surgical extent restoration via targeted
// pwrite64 operations on the underlying file descriptors. When an anomaly
// is confirmed, the daemon replays the captured pre-image extent directly
// into the backing file at its original offset, avoiding full-file rewrites.
package splicing

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"chronosd/ringbuf"
)

// Splicer restores affected file regions by replaying inverse ring-buffer
// descriptors directly into the backing file descriptors.
type Splicer struct{}

// NewSplicer creates a Splicer.
func NewSplicer() *Splicer { return &Splicer{} }

// Splice restores the pre-image extent described by d by issuing a pwrite64
// of the captured pre-image bytes at the original file offset. It resolves
// the file path from /proc/<pid>/fd/<fd> and opens it for writing.
func (s *Splicer) Splice(d *ringbuf.ExtentDesc) error {
	if d.Size == 0 {
		return errors.New("splicing: zero-size extent")
	}
	if d.PID == 0 {
		return errors.New("splicing: missing pid")
	}

	path, err := resolvePath(d.PID, d.FD)
	if err != nil {
		return fmt.Errorf("splicing: resolve path pid=%d fd=%d: %w", d.PID, d.FD, err)
	}

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("splicing: open %s: %w", path, err)
	}
	defer f.Close()

	// pwrite64(fd, data, size, offset)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_PWRITE64,
		uintptr(f.Fd()),
		uintptr(unsafe.Pointer(&d.Data[0])),
		uintptr(d.Size),
		uintptr(d.Offset),
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("splicing: pwrite64 %s offset=%d size=%d: %w",
			path, d.Offset, d.Size, errno)
	}
	return nil
}

// resolvePath resolves /proc/<pid>/fd/<fd> to the underlying file path.
func resolvePath(pid uint32, fd uint32) (string, error) {
	link := filepath.Join("/proc", fmt.Sprintf("%d", pid), "fd", fmt.Sprintf("%d", fd))
	path, err := os.Readlink(link)
	if err != nil {
		return "", fmt.Errorf("readlink %s: %w", link, err)
	}
	// Readlink may return a path like "/tmp/file" or "deleted:/tmp/file".
	path = cleanupDeleted(path)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("splicing: resolved path not absolute: %s", path)
	}
	return path, nil
}

// cleanupDeleted strips the "deleted:" prefix Linux adds to unlinked but
// still-open file descriptors.
func cleanupDeleted(path string) string {
	for len(path) > 0 && path[0] == '\x00' {
		path = path[1:]
	}
	return path
}

// SpliceByPath restores the extent directly into a file path (bypassing
// /proc fd resolution). Useful for tests and for descriptors where the fd
// is not accessible.
func (s *Splicer) SpliceByPath(path string, d *ringbuf.ExtentDesc) error {
	if d.Size == 0 {
		return errors.New("splicing: zero-size extent")
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("splicing: open %s: %w", path, err)
	}
	defer f.Close()

	_, _, errno := syscall.Syscall6(
		syscall.SYS_PWRITE64,
		uintptr(f.Fd()),
		uintptr(unsafe.Pointer(&d.Data[0])),
		uintptr(d.Size),
		uintptr(d.Offset),
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("splicing: pwrite64 %s offset=%d size=%d: %w",
			path, d.Offset, d.Size, errno)
	}
	return nil
}
