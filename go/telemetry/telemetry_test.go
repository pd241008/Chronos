package telemetry

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestObserveDisabled logs nothing when path is empty.
func TestObserveDisabled(t *testing.T) {
	l := New("")
	l.Observe(MetricDescriptorUs, 100*time.Microsecond, 1)
	l.Close() // should not panic
}

// TestObserveEnabled writes a CSV record.
func TestObserveEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "latency.csv")
	l := New(path)
	l.Observe(MetricSpliceUs, 126*time.Microsecond, 42)
	l.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	str := string(data)
	if len(str) == 0 {
		t.Error("telemetry log is empty")
	}
	if !contains(str, "splice_us") {
		t.Errorf("log missing splice_us metric: %s", str)
	}
	if !contains(str, "42") {
		t.Errorf("log missing pid 42: %s", str)
	}
}

// TestCloseIdempotent ensures Close can be called multiple times.
func TestCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "latency2.csv")
	l := New(path)
	l.Observe(MetricContainment, 418*time.Microsecond, 7)
	l.Close()
	l.Close() // should not panic
	_ = path
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
