package splicing

import (
	"os"
	"path/filepath"
	"testing"

	"chronosd/ringbuf"
)

// TestSpliceByPathRestoresExtent writes known content, overwrites a region,
// then restores it via SpliceByPath and verifies bit-exact restoration.
func TestSpliceByPathRestoresExtent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "target.bin")

	original := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(path, original, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Corrupt bytes at offset 8, length 8.
	corrupt := append([]byte(nil), original...)
	for i := 0; i < 8; i++ {
		corrupt[8+i] = 0xFF
	}
	if err := os.WriteFile(path, corrupt, 0644); err != nil {
		t.Fatalf("WriteFile corrupt: %v", err)
	}

	// Build a descriptor capturing the pre-image extent at offset 8, size 8.
	d := &ringbuf.ExtentDesc{
		PID:    999,
		Size:   8,
		Offset: 8,
		Mode:   1,
	}
	copy(d.Data[:], original[8:16])

	s := NewSplicer()
	if err := s.SpliceByPath(path, d); err != nil {
		t.Fatalf("SpliceByPath: %v", err)
	}

	restored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(restored) != string(original) {
		t.Errorf("restored = %q, want %q", restored, original)
	}
}

// TestSpliceByPathZeroSize returns an error.
func TestSpliceByPathZeroSize(t *testing.T) {
	s := NewSplicer()
	d := &ringbuf.ExtentDesc{Size: 0}
	err := s.SpliceByPath("/tmp/nonexistent", d)
	if err == nil {
		t.Error("SpliceByPath with zero size returned nil, want error")
	}
}
