package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"chronosd/blake3"
	"chronosd/ringbuf"
	"chronosd/splicing"
	"chronosd/telemetry"
)

// writeDescriptorIntoRingbuf builds a ringbuf file (metadata + one record)
// containing the given extent descriptor and returns its path.
func writeDescriptorIntoRingbuf(t *testing.T, dir string, d *ringbuf.ExtentDesc) string {
	buf := make([]byte, ringbuf.ExtentDescSize())
	n, err := ringbuf.MarshalExtentDesc(d, buf)
	if err != nil {
		t.Fatalf("MarshalExtentDesc: %v", err)
	}
	buf = buf[:n]

	// Data area must be large enough for the full ExtentDesc record.
	dataArea := 2*int(ringbuf.ExtentDescSize()) + 8192
	totalSize := 2*int(ringbuf.PageSize()) + dataArea
	ring := make([]byte, totalSize)
	recOff := 2 * ringbuf.PageSize()
	total, err := ringbuf.Record(ring[recOff:], 0, buf)
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	binary.LittleEndian.PutUint32(ring[4:8], recOff+uint32(total))

	path := filepath.Join(dir, "e2e_ringbuf")
	if err := os.WriteFile(path, ring, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestE2EDaemonConsumption reads a descriptor from a synthetic ring buffer
// and runs it through the daemon's processDescriptor, verifying restoration.
func TestE2EDaemonConsumption(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "target.bin")

	original := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(targetPath, original, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	f, err := os.OpenFile(targetPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()

	corrupt := append([]byte(nil), original...)
	for i := 0; i < 8; i++ {
		corrupt[8+i] = 0xFF
	}
	if _, err := f.WriteAt(corrupt, 0); err != nil {
		t.Fatalf("WriteAt corrupt: %v", err)
	}

	pid := uint32(os.Getpid())
	d := &ringbuf.ExtentDesc{
		PID:    pid,
		TID:    pid,
		FD:     uint32(f.Fd()),
		Size:   8,
		Offset: 8,
		Mode:   1,
		TsNs:   uint64(time.Now().UnixNano()),
	}
	copy(d.Data[:], original[8:16])

	rbPath := writeDescriptorIntoRingbuf(t, dir, d)

	rb, err := ringbuf.Open(rbPath)
	if err != nil {
		t.Fatalf("ringbuf.Open: %v", err)
	}
	defer rb.Close()

	// Read the descriptor from the ring buffer (zero-copy shared memory).
	desc, err := rb.Read()
	if err != nil {
		t.Fatalf("ringbuf.Read: %v", err)
	}
	if desc.Size != 8 {
		t.Errorf("desc.Size = %d, want 8", desc.Size)
	}

	merkle := blake3.NewMerkle()
	splicer := splicing.NewSplicer()
	tel := telemetry.New("")

	processDescriptor(desc, merkle, splicer, tel)

	restored, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(restored) != string(original) {
		t.Errorf("restored = %q, want %q", restored, original)
	}
}
