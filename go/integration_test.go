package main

import (
	"os"
	"path/filepath"
	"testing"

	"chronosd/blake3"
	"chronosd/ringbuf"
	"chronosd/splicing"
	"chronosd/telemetry"
)

// TestProcessDescriptorRestoresExtent exercises the full pipeline:
// verify (always true for intact data) -> surgical splice -> bit-exact
// restoration. It opens a file in the test process and references its fd so
// the splicing layer's /proc/<pid>/fd/<fd> resolution works.
func TestProcessDescriptorRestoresExtent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.bin")

	original := []byte("ABCDEFGH01234567ABCDEFGH01234567")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Keep the fd open in this process so /proc/self/fd/<fd> resolves.
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	defer f.Close()

	// Corrupt bytes at offset 8, length 8.
	corrupt := append([]byte(nil), original...)
	for i := 0; i < 8; i++ {
		corrupt[8+i] = 0xFF
	}
	if _, err := f.WriteAt(corrupt, 0); err != nil {
		t.Fatalf("WriteAt corrupt: %v", err)
	}

	// Build the extent descriptor referencing this process's fd.
	pid := uint32(os.Getpid())
	d := &ringbuf.ExtentDesc{
		PID:    pid,
		TID:    pid,
		FD:     uint32(f.Fd()),
		Size:   8,
		Offset: 8,
		Mode:   1,
	}
	copy(d.Data[:], original[8:16])

	merkle := blake3.NewMerkle()
	splicer := splicing.NewSplicer()
	tel := telemetry.New("") // disabled logging

	processDescriptor(d, merkle, splicer, tel)

	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(restored) != string(original) {
		t.Errorf("restored = %q, want %q", restored, original)
	}
}
