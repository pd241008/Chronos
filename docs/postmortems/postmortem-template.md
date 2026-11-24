# Postmortem: <title>

> **Date:** YYYY-MM-DD
> **Project:** Chronos

---

## 💥 What we expected

Describe the intended behavior, the assumption that was made, and the
failure mode that was believed to be impossible or handled.

---

## 📉 What actually happened

Describe the observed failure, its impact, the trigger, and the
detection path (monitoring, alert, user report, etc.). Include numeric
evidence where available (latency, byte loss, error rate).

---

## 🧠 What we learned

List the root cause and the corrective action. Include any decision
reversals and the conditions under which the original decision would be
revisited (e.g. a measurable threshold such as ~50k events/day).

---

## 🔗 Related records

- Corresponding ADR: [`docs/adrs/ADR-NNNN.md`](../adrs/ADR-NNNN.md)
- Related tests: `kernel/ebpf/test/` or `go/*_test.go`

---

**Convention:** Postmortems document real failures actually encountered.
Do not write one speculatively — if no incident has occurred, this
template remains unused.
