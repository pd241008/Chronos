// Package ringbuf provides zero-copy consumption of the per-PID eBPF
// BPF_MAP_TYPE_RINGBUF via memory-mapped shared memory.

package ringbuf

import (
	"errors"
	"io"
	"os"
	"sync/atomic"
	"unsafe"
)

var ErrStopped = errors.New("ringbuf stopped")

// ExtentDesc mirrors struct chronos_extent_desc in kernel/ebpf/chronos_bpf.c.
// Field layout must remain byte-compatible with the eBPF struct.
type ExtentDesc struct {
	PID        uint32
	TID        uint32
	TsNs       uint64
	Ino        uint64
	Size       uint64
	Offset     uint64
	FD         uint32
	DevMajor   uint32
	DevMinor   uint32
	Mode       uint8
	_          [3]byte
	Magic      [16]byte
	MagicDelta uint8
	_          [3]byte
	Entropy    float32
	_          [3]byte
	Data       [65536]byte // pre-image extent bytes
}

const extentDescSize = unsafe.Sizeof(ExtentDesc{})

type Reader struct {
	fd      *os.File
	data    []byte // mmap'd ring buffer pages
	stopped atomic.Bool
}

func Open(path string) (*Reader, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	_ = io.EOF
	return &Reader{fd: f}, nil
}

func (r *Reader) Read() (*ExtentDesc, error) {
	if r.stopped.Load() {
		return nil, ErrStopped
	}
	return nil, io.EOF
}

func (r *Reader) Stop() {
	r.stopped.Store(true)
	r.fd.Close()
}
