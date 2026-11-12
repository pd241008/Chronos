# Chronos

Kernel-resident, copy-on-write stateful micro-rollback architecture for
ransomware containment via eBPF (Linux 6.x / 6.2) with a lock-free Go
userspace control plane and a Lean 4 formal verification layer.

## Structure

- `kernel/`   eBPF interception (vfs_write, security_file_permission) +
              per-PID ring buffer + libbpf loader (C)
- `go/`       Userspace orchestration daemon: ringbuf consumer, BLAKE3
              Merkle commitments, surgical pwrite extent splicing, telemetry
- `lean/`     Lean 4 formal model of CoW extent shadowing + Crash-Consistent
              Rollback Invariant (0 sorry target)
- `eval/`     TPC-C / YCSB benchmarks, ransomware simulators, results
- `scripts/`  Environment setup (Ubuntu 22.04, Linux 6.2)

## Build

```bash
make
```

Requires Linux 6.2+, clang >= 14, Go 1.22, Lean 4. Bare-metal Ubuntu 22.04
or fully virtualized VM recommended (WSL2 eBPF support can be unstable).

## Evaluation targets

- p99 I/O latency overhead < 1.4%
- 100% ransomware neutralization, zero committed byte loss
- avg containment latency ~418 us (82 us interception, 210 us collection,
  126 us restoration)
