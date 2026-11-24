// Package ringbuf provides zero-copy consumption of the per-PID eBPF
// BPF_MAP_TYPE_RINGBUF via memory-mapped shared memory.
//
// It implements the libbpf ring-buffer record protocol so the Go userspace
// daemon can consume pre-image extent descriptors diverted by the eBPF
// kernel layer without syscalls per record:
//
//   [0:4]   consumer_pos  (u32 LE, updated by this reader)
//   [4:8]   producer_pos  (u32 LE, updated by the kernel/eBPF)
//   [8:]    data records, each:
//            u32 len   (total record length incl. this header, 8-aligned)
//            u32 type  (0 = normal record)
//            u8  data[len-8]
package ringbuf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var ErrStopped = errors.New("ringbuf stopped")

// pageSize is the mmap page granularity used to separate metadata from data.
const pageSize = 4096

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

// ExtentDescSize returns the serialized size of an ExtentDesc.
func ExtentDescSize() uintptr { return extentDescSize }

// PageSize returns the mmap page granularity used by the ring buffer.
func PageSize() uint32 { return pageSize }

// MarshalExtentDesc serializes an ExtentDesc into the byte layout expected by
// decodeExtentDesc (little-endian). It returns the number of bytes written.
func MarshalExtentDesc(d *ExtentDesc, buf []byte) (int, error) {
	if len(buf) < int(extentDescSize) {
		return 0, errors.New("buffer too small for ExtentDesc")
	}
	binary.LittleEndian.PutUint32(buf[0:4], d.PID)
	binary.LittleEndian.PutUint32(buf[4:8], d.TID)
	binary.LittleEndian.PutUint64(buf[8:16], d.TsNs)
	binary.LittleEndian.PutUint64(buf[16:24], d.Ino)
	binary.LittleEndian.PutUint64(buf[24:32], d.Size)
	binary.LittleEndian.PutUint64(buf[32:40], d.Offset)
	binary.LittleEndian.PutUint32(buf[40:44], d.FD)
	binary.LittleEndian.PutUint32(buf[44:48], d.DevMajor)
	binary.LittleEndian.PutUint32(buf[48:52], d.DevMinor)
	buf[52] = d.Mode
	copy(buf[56:72], d.Magic[:])
	buf[72] = d.MagicDelta
	binary.LittleEndian.PutUint32(buf[76:80], *(*uint32)(unsafe.Pointer(&d.Entropy)))
	copy(buf[84:], d.Data[:])
	return int(extentDescSize), nil
}

// Reader consumes descriptors from a pinned eBPF ring buffer via mmap.
type Reader struct {
	fd       *os.File
	data     []byte // mmap'd ring buffer (metadata + records)
	size     uint32 // total ring buffer size in bytes (power of 2)
	mask     uint32 // size - 1
	consumer atomic.Uint32 // last consumed position (within data area)
	stopped  atomic.Bool
}

// Open memory-maps the pinned ring-buffer file and prepares a Reader.
// The file must follow the libbpf ring-buffer protocol (consumer/producer
// counters at the start, records follow).
func Open(path string) (*Reader, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0) // O_RDWR to update consumer pos
	if err != nil {
		return nil, fmt.Errorf("open ringbuf: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat ringbuf: %w", err)
	}
	size := uint32(info.Size())
	if size < 2*pageSize+8 {
		f.Close()
		return nil, fmt.Errorf("ringbuf too small: %d bytes", size)
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(size),
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("mmap ringbuf: %w", err)
	}

	r := &Reader{
		fd:   f,
		data: data,
		size: size,
		mask: size - 1,
	}
	// consumer position starts at 0 (fresh reader).
	r.consumer.Store(0)
	return r, nil
}

// Read returns the next extent descriptor from the ring buffer.
// It blocks briefly (polling) when no record is available, and returns
// ErrStopped once Stop() has been called.
func (r *Reader) Read() (*ExtentDesc, error) {
	const pollInterval = 100 * time.Millisecond
	for {
		if r.stopped.Load() {
			return nil, ErrStopped
		}
		desc, ok, err := r.readOne()
		if err != nil {
			return nil, err
		}
		if ok {
			return desc, nil
		}
		time.Sleep(pollInterval)
	}
}

// readOne attempts to consume a single record without blocking.
func (r *Reader) readOne() (*ExtentDesc, bool, error) {
	consumer := r.consumer.Load()
	producer := binary.LittleEndian.Uint32(r.data[4:8])

	if consumer == producer {
		return nil, false, nil // no data available
	}

	// Records live after the metadata (consumer + producer counters).
	dataOff := uint32(2 * pageSize)
	dataSize := r.size - dataOff

	// Compute the absolute offset within the ring buffer for this record.
	recOff := consumer % dataSize

	recLen := binary.LittleEndian.Uint32(r.data[dataOff+recOff : dataOff+recOff+4])
	recType := binary.LittleEndian.Uint32(r.data[dataOff+recOff+4 : dataOff+recOff+8])

	if recLen < 8 || recLen > dataSize {
		return nil, false, fmt.Errorf("corrupt record length: %d", recLen)
	}

	// Copy the record payload (handling wrap-around) into a linear buffer.
	payload := make([]byte, int(recLen-8))
	for i := uint32(0); i < recLen-8; i++ {
		absInData := (recOff + 8 + i) % dataSize
		payload[i] = r.data[dataOff+absInData]
	}

	_ = recType // record type; 0 = normal extent descriptor

	// Advance the consumer counter past this record (8-byte aligned).
	newConsumer := consumer + ((recLen + 7) & ^uint32(7))
	r.consumer.Store(newConsumer)
	// Publish the updated consumer position back into the shared mapping.
	binary.LittleEndian.PutUint32(r.data[0:4], newConsumer)

	if uint32(recLen-8) < uint32(extentDescSize) {
		return nil, false, fmt.Errorf("record too small for ExtentDesc: %d", recLen-8)
	}

	desc, err := decodeExtentDesc(payload[:extentDescSize])
	if err != nil {
		return nil, false, err
	}
	return desc, true, nil
}

// Stop halts the reader and releases the mmap.
func (r *Reader) Stop() error {
	r.stopped.Store(true)
	if err := syscall.Munmap(r.data); err != nil {
		return fmt.Errorf("munmap ringbuf: %w", err)
	}
	return r.fd.Close()
}

// Close halts the reader and releases the mmap (alias for Stop).
func (r *Reader) Close() error { return r.Stop() }

func decodeExtentDesc(b []byte) (*ExtentDesc, error) {
	if len(b) < int(extentDescSize) {
		return nil, fmt.Errorf("extent desc truncated: %d < %d", len(b), extentDescSize)
	}
	d := &ExtentDesc{}
	d.PID = binary.LittleEndian.Uint32(b[0:4])
	d.TID = binary.LittleEndian.Uint32(b[4:8])
	d.TsNs = binary.LittleEndian.Uint64(b[8:16])
	d.Ino = binary.LittleEndian.Uint64(b[16:24])
	d.Size = binary.LittleEndian.Uint64(b[24:32])
	d.Offset = binary.LittleEndian.Uint64(b[32:40])
	d.FD = binary.LittleEndian.Uint32(b[40:44])
	d.DevMajor = binary.LittleEndian.Uint32(b[44:48])
	d.DevMinor = binary.LittleEndian.Uint32(b[48:52])
	d.Mode = b[52]
	copy(d.Magic[:], b[56:72])
	d.MagicDelta = b[72]
	d.Entropy = float32FromBytes(binary.LittleEndian.Uint32(b[76:80]))
	copy(d.Data[:], b[84:84+int(extentDescSize)-84])
	return d, nil
}

// float32FromBytes reconstructs a float32 from its little-endian uint32 bits.
func float32FromBytes(b uint32) float32 {
	return *(*float32)(unsafe.Pointer(&b))
}

// Record formats a single ringbuf record into the shared mapping for testing
// or external producers. It returns the number of bytes consumed.
func Record(buf []byte, typ uint32, payload []byte) (int, error) {
	if len(buf) < 8 {
		return 0, errors.New("ringbuf: buffer too small for record header")
	}
	total := 8 + len(payload)
	total = (total + 7) & ^7 // 8-byte align
	binary.LittleEndian.PutUint32(buf[0:4], uint32(total))
	binary.LittleEndian.PutUint32(buf[4:8], typ)
	copy(buf[8:], payload)
	return total, nil
}
