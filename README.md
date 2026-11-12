# 🏰 Chronos

## 📓 Ransomware Micro-Rollback via eBPF

Chronos is a kernel-resident, copy-on-write (CoW) stateful micro-rollback
architecture that bridges the detection-to-actuation gap in ransomware
defense. It couples in-path eBPF virtual file system interception with a
lock-free Go userspace control plane and a Lean 4 formal verification
layer to restore bit-exact pre-infection file state.

---

## 🧭 How to Read This

> [!IMPORTANT]  
> Every pattern here comes from a real decision made under real
> constraints. Architecture decisions live in
> `docs/01-documentation/adrs/` (one ADR per decision). This README is the
> living navigation index, not a duplicate of decision bodies.

This is not a generic list of "best practices." If an architecture choice
is documented here, it is backed by an ADR and an implementation layer.

---

## 🗺️ Navigation

| Section | Path | Description |
|---------|------|-------------|
| **Kernel Interception Layer** | `kernel/` | eBPF `vfs_write` + `security_file_permission` interception, rolling byte-entropy, magic-byte delta, per-PID ring buffer, libbpf loader |
| **Userspace Orchestration Layer** | `go/` | Async Go daemon: ringbuf consumer, BLAKE3 Merkle verification, surgical `pwrite` extent splicing, telemetry |
| **Formal Verification Layer** | `lean/` | Lean 4 CoW state-transition machine, Crash-Consistent Rollback Invariant (0 sorry target) |
| **Evaluation Layer** | `eval/` | TPC-C / YCSB benchmarks, ransomware simulators (LockBit 3.0, BlackCat/ALPHV, Akira), results |
| **Architecture Decisions** | `docs/01-documentation/adrs/` | ADR-001…006: constraints, options, decision, consequences |
| **Scripts** | `scripts/` | Environment setup (Ubuntu 22.04, Linux 6.2) |

---

## 🏗️ Architecture

Chronos has three layers, each building on the previous:

1. **Kernel Interception Layer** — eBPF kprobes on `vfs_write` and
   `security_file_permission` classify each write (sub-microsecond rolling
   byte-entropy + magic-byte delta) before the dirty page crosses the
   VFS→page-cache boundary. Suspect pre-image extents are diverted into a
   cache-aligned, per-PID `BPF_MAP_TYPE_RINGBUF`.
2. **Userspace Orchestration Layer** — an async, lock-free Go daemon
   consumes ring-buffer telemetry via zero-copy shared memory, verifies
   pre-image integrity with BLAKE3 Merkle commitments, and restores
   affected regions via surgical `pwrite64` extent splicing.
3. **Formal Verification Layer** — a Lean 4 deterministic state machine
   models CoW extent shadowing; the Crash-Consistent Rollback Invariant
   proves process termination + inverse descriptor replay restores
   bit-exact pre-infection state without orphan inodes or journal
   desynchronization.

---

## ⚡ Evaluation Targets

| Metric | Target |
|--------|--------|
| p99 I/O latency overhead (benign) | < 1.4% |
| Ransomware neutralization | 100% |
| Committed byte loss | 0 |
| Average containment latency | ~418 μs |
| eBPF interception | ~82 μs |
| Descriptor collection | ~210 μs |
| Extent restoration | ~126 μs |
| Speedup vs. volume snapshots | ~3,850× |

Workloads: PostgreSQL TPC-C + RocksDB YCSB on NVMe.
Ransomware simulators: LockBit 3.0, BlackCat/ALPHV, Akira.

---

## 🛠️ Build

Requires Linux 6.2+, clang ≥ 14, Go 1.22, Lean 4. Bare-metal Ubuntu 22.04
or fully virtualized VM recommended (WSL2 eBPF support is unstable for
deep VFS hooks).

```bash
# 1. Environment
bash scripts/setup.sh

# 2. Build eBPF + Go daemon
make

# 3. Generate vmlinux.h on the target host (run once)
make -C kernel/ebpf vmlinux
```

---

## 📜 Git Conventions

Commits follow [Conventional Commits](
https://www.conventionalcommits.org): `<type>[scope]: <description>`.
Allowed types: `feat`, `fix`, `chore`, `refactor`, `test`, `docs`, `perf`,
`revert`. One logical change per commit; no bare descriptions.

Recent history:

```text
docs: add Design-Dungeons-style ADRs and README navigation
docs: ADR-006 evaluation constraints (TPC-C/YCSB, simulators, latency)
docs: ADR-005 Lean 4 formal verification layer
docs: ADR-004 Go userspace orchestration layer
docs: ADR-003 entropy + magic-byte classification
docs: ADR-002 per-PID ring buffer pre-image capture
docs: ADR-001 kernel eBPF interception layer
feat: add eval TPC-C/YCSB, simulators, scripts, root files
feat: add Go userspace orchestration daemon skeleton
feat: add kernel eBPF interception layer skeleton
```

---
