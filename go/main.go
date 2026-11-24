// Package main is the Chronos userspace orchestration daemon.
//
// It consumes eBPF ring-buffer telemetry via zero-copy shared memory,
// verifies pre-image integrity with BLAKE3 Merkle commitments, and performs
// surgical extent splicing via targeted pwrite64 calls to restore affected
// file regions when an anomaly is confirmed.
//
// Pipeline per extent descriptor:
//   ringbuf.Read() -> Merkle.VerifyExtent() -> (anomaly?) Splicer.Splice()
//   Each stage is timed and logged to the telemetry CSV.
//
// Build:   cd go && go build -o chronosd .
// Run:     sudo ./chronosd -ringbuf /sys/fs/bpf/chronos_ringbuf -log latency.csv
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"chronosd/blake3"
	"chronosd/ringbuf"
	"chronosd/splicing"
	"chronosd/telemetry"
)

var (
	ringbufPath = flag.String("ringbuf", "/sys/fs/bpf/chronos_ringbuf",
		"pinned eBPF ringbuf path")
	logFile = flag.String("log", "", "latency breakdown CSV path")
	verify  = flag.Bool("verify", true,
		"enable BLAKE3 Merkle pre-image verification")
)

func main() {
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("chronosd: starting userspace orchestration layer")

	// Open the pinned eBPF ring buffer (zero-copy shared memory).
	rb, err := ringbuf.Open(*ringbufPath)
	if err != nil {
		log.Fatalf("ringbuf open: %v", err)
	}
	defer rb.Close()

	merkle := blake3.NewMerkle()
	splicer := splicing.NewSplicer()
	tel := telemetry.New(*logFile)
	defer tel.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Asynchronous consumption loop. Each iteration processes one extent
	// descriptor end-to-end without holding any global lock (lock-free per
	// descriptor); the ringbuf reader owns its own atomic consumer cursor.
	go func() {
		for {
			select {
			case <-stop:
				rb.Stop()
				return
			default:
				desc, err := rb.Read()
				if err != nil {
					if err == ringbuf.ErrStopped {
						return
					}
					log.Printf("ringbuf read: %v", err)
					continue
				}

				processDescriptor(desc, merkle, splicer, tel)
			}
		}
	}()

	log.Println("chronosd: consumption loop running; awaiting descriptors")
	<-stop
	log.Println("chronosd: shutting down")
}

// processDescriptor handles a single extent descriptor: verify integrity
// with BLAKE3 Merkle, and if anomalous, surgically splice the pre-image
// back into the backing file.
func processDescriptor(d *ringbuf.ExtentDesc,
	merkle *blake3.Merkle, splicer *splicing.Splicer, tel *telemetry.Logger) {

	// Stage 1: cryptographic verification of the pre-image extent.
	t0 := time.Now()
	ok, err := merkle.VerifyExtent(d)
	tel.Observe(telemetry.MetricDescriptorUs, time.Since(t0), d.PID)
	if err != nil {
		log.Printf("merkle verify pid=%d err=%v", d.PID, err)
		return
	}

	if !*verify {
		// Verification disabled: trust the descriptor and restore.
		ok = true
	}

	if ok {
		// Pre-image is trustworthy: surgically splice it back into the
		// backing file at its original offset.
		t1 := time.Now()
		if err := splicer.Splice(d); err != nil {
			log.Printf("splice pid=%d fd=%d err=%v", d.PID, d.FD, err)
			tel.Observe(telemetry.MetricSpliceUs, time.Since(t1), d.PID)
			return
		}
		tel.Observe(telemetry.MetricSpliceUs, time.Since(t1), d.PID)
		tel.Observe(telemetry.MetricEvent, 0, d.PID)
		log.Printf("chronosd: restored extent pid=%d ino=%d offset=%d size=%d",
			d.PID, d.Ino, d.Offset, d.Size)
	} else {
		log.Printf("chronosd: pre-image integrity check FAILED pid=%d; skipping restore",
			d.PID)
	}

	tel.Observe(telemetry.MetricContainment, time.Since(time.Unix(0, int64(d.TsNs))), d.PID)
}
