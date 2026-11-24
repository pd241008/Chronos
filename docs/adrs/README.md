# 🗂️ Architecture Decision Records

> **This is the catalog.** A single template plus curated Chronos decisions live
> here. ADR bodies live in this repo (canonical home: `docs/adrs/`). This file
> routes to them and highlights the decisions worth studying.

---

## ✍️ How to Write an ADR

- Use the single canonical [`adr-template.md`](./adr-template.md).
- One decision per ADR. Record: **Context** (constraints, facts, no bias) →
  **Options Considered** → **Decision** (one-sentence why) → **Consequences**
  (good / bad) → **Revisit When**.
- The body lives in this repo. ADRs are the source of truth for the "why"
  behind Chronos.

---

## ⭐ Curated Chronos Decisions

| # | Pattern | ADR file | What it demonstrates |
| :- | :--- | :--- | :--- |
| 1 | Kernel interception | [`ADR-001`](./ADR-001.md) | eBPF vfs_write + security_file_permission on Linux 6.2 |
| 2 | Pre-image capture | [`ADR-002`](./ADR-002.md) | Cache-aligned per-PID BPF_MAP_TYPE_RINGBUF |
| 3 | Anomaly classification | [`ADR-003`](./ADR-003.md) | Rolling byte-entropy + magic-byte delta |
| 4 | Userspace orchestration | [`ADR-004`](./ADR-004.md) | Go daemon, BLAKE3 Merkle, pwrite splicing |
| 5 | Formal verification | [`ADR-005`](./ADR-005.md) | Lean 4 CoW state machine, Crash-Consistent Rollback Invariant |
| 6 | Evaluation constraints | [`ADR-006`](./ADR-006.md) | TPC-C/YCSB, ransomware simulators, latency targets |

---

## 📚 Full Catalog

### Chronos — ransomware micro-rollback via eBPF

Canonical: `docs/adrs/`
- [ADR-001 Kernel interception layer](ADR-001.md)
- [ADR-002 Per-PID ring buffer pre-image capture](ADR-002.md)
- [ADR-003 Entropy + magic-byte anomaly classification](ADR-003.md)
- [ADR-004 Go userspace orchestration layer](ADR-004.md)
- [ADR-005 Lean 4 formal verification](ADR-005.md)
- [ADR-006 Evaluation & benchmark constraints](ADR-006.md)

---

## ⚖️ Why Not Duplicate Every ADR Here?

Keeping one template + curated catalog + links avoids stale duplicate bodies
drifting out of sync with the source and keeps the playbook readable.

_See the [root README](../../README.md) for the full navigation._
