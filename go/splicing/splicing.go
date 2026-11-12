// Package splicing implements surgical extent restoration via targeted pwrite
// operations on the underlying file descriptors.

package splicing

import (
	"chronosd/ringbuf"
	"os"
	"syscall"
	"unsafe"
)

type Splicer struct{}

func NewSplicer() *Splicer { return &Splicer{} }

func (s *Splicer) Splice(d *ringbuf.ExtentDesc) error {
	f, err := os.OpenFile(d.path(), os.O_WRONLY, 0)
	if err != nil {
		return err
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
		return errno
	}
	return nil
}

func (d *ringbuf.ExtentDesc) path() string {
	return ""
}
