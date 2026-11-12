// Chronos Go Userspace Orchestration Daemon (skeleton)
// Consumes eBPF ring-buffer telemetry via zero-copy shared memory, verifies
// pre-image integrity with BLAKE3 Merkle commitments, and performs surgical
// extent splicing via targeted pwrite calls to restore affected regions.

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"chronosd/ringbuf"
	"chronosd/blake3"
	"chronosd/splicing"
	"chronosd/telemetry"
)

var (
	ringbufPath = flag.String("ringbuf", "/sys/fs/bpf/chronos_ringbuf", "pinned eBPF ringbuf path")
	verifyEvery = flag.Duration("verify", 0, "Merkle re-verification interval (0 = per extent)")
	logFile     = flag.String("log", "", "latency breakdown log path")
)

func main() {
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("chronosd: starting userspace orchestration layer")

	rb, err := ringbuf.Open(*ringbufPath)
	if err != nil {
		log.Fatalf("ringbuf open: %v", err)
	}
	defer rb.Close()

	merkle := blake3.NewMerkle()
	splicer := splicing.NewSplicer()
	tel := telemetry.New(*logFile)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

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

				t0 := time.Now()
				ok, err := merkle.VerifyExtent(desc)
				tel.Observe("verify_us", time.Since(t0))
				if err != nil {
					log.Printf("merkle verify pid=%d err=%v", desc.PID, err)
					continue
				}

				if !ok {
					t1 := time.Now()
					if err := splicer.Splice(desc); err != nil {
						log.Printf("splice pid=%d fd=%d err=%v", desc.PID, desc.FD, err)
					}
					tel.Observe("splice_us", time.Since(t1))
					tel.Observe("containment_event", 1)
				}
				tel.Observe("descriptor_us", time.Since(t0))
			}
		}
	}()

	<-stop
	log.Println("chronosd: shutting down")
}
