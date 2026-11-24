// Package telemetry logs the granular latency breakdown for the Chronos
// containment pipeline:
//   ~82 us  eBPF interception   (kernel side)
//   ~210 us descriptor collection (ringbuf read + Merkle verify)
//   ~126 us extent restoration    (surgical pwrite splice)
// target average containment latency ~418 us.
package telemetry

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
	"time"
)

// Metric names recorded by the daemon.
const (
	MetricInterceptUs  = "intercept_us"   // eBPF interception (reported by kernel, logged here)
	MetricDescriptorUs = "descriptor_us"  // ringbuf read + merkle verify
	MetricSpliceUs     = "splice_us"      // extent restoration
	MetricContainment  = "containment_us" // total containment latency
	MetricEvent        = "containment_event"
)

// Logger writes latency breakdown records to a CSV file.
type Logger struct {
	mu   sync.Mutex
	w    *csv.Writer
	file *os.File
}

// New creates a telemetry logger. If path is empty, logging is disabled.
func New(path string) *Logger {
	l := &Logger{}
	if path != "" {
		f, err := os.Create(path)
		if err == nil {
			l.file = f
			l.w = csv.NewWriter(f)
			l.w.Write([]string{"ts_ns", "metric", "value_us", "pid"})
		}
	}
	return l
}

// Observe records a single latency measurement.
func (l *Logger) Observe(metric string, d time.Duration, pid uint32) {
	if l.w == nil {
		return
	}
	l.mu.Lock()
	l.w.Write([]string{
		time.Now().Format("2006-01-02T15:04:05.999999999"),
		metric,
		d.String(),
		fmt.Sprintf("%d", pid),
	})
	l.w.Flush()
	l.mu.Unlock()
}

// Close flushes and closes the log file.
func (l *Logger) Close() {
	if l.w != nil {
		l.w.Flush()
	}
	if l.file != nil {
		l.file.Close()
	}
}
