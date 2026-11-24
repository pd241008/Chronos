package ringbuf

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"unsafe"
)

// buildExtentDesc creates a test ExtentDesc and serializes it into the
// byte layout expected by decodeExtentDesc.
func buildExtentDesc(pid uint32, size uint64, offset uint64, data []byte) ExtentDesc {
	d := ExtentDesc{
		PID:        pid,
		TID:        pid + 1,
		TsNs:       1234567890,
		Ino:        42,
		Size:       size,
		Offset:     offset,
		FD:         7,
		DevMajor:   8,
		DevMinor:   9,
		Mode:       1,
		MagicDelta: 3,
		Entropy:    7.5,
	}
	copy(d.Magic[:], []byte{0x7f, 'E', 'L', 'F'})
	copy(d.Data[:], data)
	return d
}

// serializeExtentDesc writes an ExtentDesc into buf using the same layout as
// decodeExtentDesc expects (little-endian).
func serializeExtentDesc(d ExtentDesc, buf []byte) int {
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
	return int(extentDescSize)
}

func TestExtentDescRoundTrip(t *testing.T) {
	data := []byte("pre-image-bytes-for-testing")
	orig := buildExtentDesc(1001, uint64(len(data)), 4096, data)

	buf := make([]byte, extentDescSize)
	n := serializeExtentDesc(orig, buf)
	if n != int(extentDescSize) {
		t.Fatalf("serializeExtentDesc returned %d, want %d", n, extentDescSize)
	}

	got, err := decodeExtentDesc(buf[:n])
	if err != nil {
		t.Fatalf("decodeExtentDesc: %v", err)
	}

	if got.PID != orig.PID {
		t.Errorf("PID = %d, want %d", got.PID, orig.PID)
	}
	if got.Size != orig.Size {
		t.Errorf("Size = %d, want %d", got.Size, orig.Size)
	}
	if got.Offset != orig.Offset {
		t.Errorf("Offset = %d, want %d", got.Offset, orig.Offset)
	}
	if got.Mode != orig.Mode {
		t.Errorf("Mode = %d, want %d", got.Mode, orig.Mode)
	}
	if got.MagicDelta != orig.MagicDelta {
		t.Errorf("MagicDelta = %d, want %d", got.MagicDelta, orig.MagicDelta)
	}
	if got.Magic[0] != 0x7f || got.Magic[1] != 'E' || got.Magic[2] != 'L' || got.Magic[3] != 'F' {
		t.Errorf("Magic prefix = %q, want \\x7fELF", got.Magic[:4])
	}
	if string(got.Data[:len(data)]) != string(data) {
		t.Errorf("Data mismatch: got %q, want %q", got.Data[:len(data)], data)
	}
}

func TestRecordAndRead(t *testing.T) {
	data := []byte("synthetic-pre-image-extent")
	desc := buildExtentDesc(777, uint64(len(data)), 0x1000, data)

	buf := make([]byte, extentDescSize)
	serializeExtentDesc(desc, buf)

	// Build a ringbuf file: [consumer(4)][producer(4)][data records...]
	// Data area must be large enough for the full ExtentDesc record.
	dataArea := 2 * int(extentDescSize) + 8192
	totalSize := 2*pageSize + dataArea
	ring := make([]byte, totalSize)
	// producer starts at 0
	binary.LittleEndian.PutUint32(ring[4:8], 0)

	recOff := 2 * pageSize
	total, err := Record(ring[recOff:], 0, buf)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	// update producer
	binary.LittleEndian.PutUint32(ring[4:8], uint32(recOff+total))

	// Write to a temp file
	dir := t.TempDir()
	path := filepath.Join(dir, "ringbuf")
	if err := os.WriteFile(path, ring, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Stop()

	got, err := r.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.PID != desc.PID {
		t.Errorf("PID = %d, want %d", got.PID, desc.PID)
	}
	if got.Size != desc.Size {
		t.Errorf("Size = %d, want %d", got.Size, desc.Size)
	}
	if string(got.Data[:len(data)]) != string(data) {
		t.Errorf("Data mismatch: got %q, want %q", got.Data[:len(data)], data)
	}
}

func TestReadEmptyReturnsNoBlock(t *testing.T) {
	// Empty ring buffer (producer == consumer).
	ring := make([]byte, 2*pageSize+8192)
	dir := t.TempDir()
	path := filepath.Join(dir, "empty_rb")
	if err := os.WriteFile(path, ring, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Stop()

	// readOne directly: no data available.
	_, ok, err := r.readOne()
	if err != nil {
		t.Fatalf("readOne on empty: %v", err)
	}
	if ok {
		t.Error("readOne on empty returned ok=true, want false")
	}
}

func TestStopped(t *testing.T) {
	ring := make([]byte, 2*pageSize+8192)
	dir := t.TempDir()
	path := filepath.Join(dir, "stopped_rb")
	if err := os.WriteFile(path, ring, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	r.Stop()

	_, err = r.Read()
	if err != ErrStopped {
		t.Errorf("Read after Stop = %v, want ErrStopped", err)
	}
}
