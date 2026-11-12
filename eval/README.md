# Chronos Evaluation Layer

Benchmarks and ransomware simulators for Phase 4 evaluation:

- tpcc/   PostgreSQL TPC-C workload harness
- ycsb/   RocksDB YCSB workload harness
- simulators/ Dummy ransomware simulators (LockBit 3.0, BlackCat/ALPHV, Akira)
- results/  Latency breakdown logs

Targets:
  - p99 I/O latency overhead < 1.4%
  - 100% neutralization, zero committed byte loss
  - avg containment latency ~418 us
    (82 us eBPF interception, 210 us descriptor collection, 126 us extent restoration)
