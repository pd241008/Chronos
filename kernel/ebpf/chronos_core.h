// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Chronos core classification logic — shared between the eBPF program and the
// host unit tests. Pure C (no BPF helpers) so it compiles for both targets.

#ifndef __CHRONOS_CORE_H__
#define __CHRONOS_CORE_H__

/* Integer types (__u8, __u32, __u64, __s32) are provided by linux/types.h
 * (pulled in via linux/bpf.h) when compiled for eBPF. Host unit tests define
 * them as uint8_t/uint32_t/uint64_t/int32_t before including this header. */

#define CHRONOS_ENTROPY_WINDOW    64              /* rolling sample bytes      */
#define CHRONOS_ENTROPY_THRESHOLD 7680            /* 7.5 bits/byte * 1024 fp   */
#define CHRONOS_MAGIC_DELTA_MAX   4               /* max magic mismatch        */
#define CHRONOS_RINGBUF_SIZE      (1 << 22)       /* 4 MiB per-PID ringbuf     */
#define CHRONOS_MAX_EXTENT        1024          /* max diverted extent bytes */
#define CHRONOS_CACHE_LINE        64
#define LOG2_SCALE                1024            /* fixed-point scale         */
#define MAX_SAMPLES               1024            /* decay threshold           */

struct __attribute__((aligned(CHRONOS_CACHE_LINE))) chronos_extent_desc {
	__u32  pid;
	__u32  tid;
	__u64  ts_ns;
	__u64  ino;
	__u64  size;
	__u64  offset;
	__u32  fd;
	__u32  dev_major;
	__u32  dev_minor;
	__u8   mode;
	__u8   pad0[3];
	__u8   magic[16];
	__u8   magic_delta;
	__u8   pad1[3];
	__s32  entropy_fixed;
	__u8   pad2[4];
	__u8   data[CHRONOS_MAX_EXTENT];
};

/* Per-PID rolling entropy state (histogram lives in map memory in eBPF). */
struct chronos_entropy_state {
	__u32  byte_hist[256];  /* rolling byte frequency histogram      */
	__u64  total_count;     /* total bytes sampled                   */
	__u64  last_ts;         /* last update timestamp                 */
	__u32  win_pos;         /* position within rolling window        */
	__u8   win[CHRONOS_ENTROPY_WINDOW];
	__u8   pad[3];
};

/* Fixed-point floor(log2(n)) * LOG2_SCALE, n >= 1. Bounded loop. */
static inline __s32 chronos_log2_fixed(__u64 n)
{
	__s32 r = 0;
	if (n == 0)
		return 0;
	for (__u32 i = 0; i < 64; i++) {
		if (n <= 1)
			break;
		n >>= 1;
		r += LOG2_SCALE;
	}
	return r;
}

/* Compute a lightweight rolling entropy estimate (fixed-point *1024) over the
 * accumulated histogram stored in map memory.
 *
 * Uses distinct-byte count as a Shannon-entropy proxy: uniform/high-entropy
 * data (e.g. encryption) spreads across many byte values, while structured or
 * repeated data concentrates on few. distinct=256 -> 8192 (8 bits/byte);
 * distinct=240 -> 7680 (7.5 bits/byte, the suspicion threshold). This avoids
 * a per-byte log2 loop and keeps the eBPF instruction count tiny. */
static inline __s32 chronos_entropy_compute(struct chronos_entropy_state *st)
{
	__u64 total = st->total_count;
	__u32 distinct = 0;

	if (total == 0)
		return 0;

	for (__u32 i = 0; i < 256; i++)
		if (st->byte_hist[i])
			distinct++;

	/* distinct / 256 * 8 bits, fixed point *1024  ==  distinct * 32 */
	return (__s32)((__u64)distinct * 32);
}

/* Update rolling histogram with up to CHRONOS_ENTROPY_WINDOW new bytes.
 * The loop is bounded to a fixed 64 iterations so every stack read is at a
 * constant offset (verifier-safe). Bytes beyond `len` are skipped. */
static inline void chronos_entropy_update(struct chronos_entropy_state *st,
					  const __u8 *data, __u32 len)
{
	__u32 n = len < CHRONOS_ENTROPY_WINDOW ? len : CHRONOS_ENTROPY_WINDOW;
	for (__u32 i = 0; i < CHRONOS_ENTROPY_WINDOW; i++) {
		if (i < n) {
			st->byte_hist[data[i]]++;
			st->win[st->win_pos % CHRONOS_ENTROPY_WINDOW] = data[i];
			st->win_pos++;
			st->total_count++;
		}
	}
	if (st->total_count > MAX_SAMPLES) {
		for (__u32 i = 0; i < 256; i++)
			st->byte_hist[i] >>= 1;
		st->total_count >>= 1;
	}
}

/* Structural magic-byte delta: mismatch count between observed and expected
 * leading bytes. Returns count of differing bytes. */
static inline __u8 chronos_magic_delta(const __u8 *observed,
				       const __u8 *expected, __u32 n)
{
	__u8 d = 0;
	for (__u32 i = 0; i < n; i++) {
		if (observed[i] != expected[i])
			d++;
	}
	return d;
}

/* Classify decision: suspect if entropy >= threshold OR magic_delta > max. */
static inline int chronos_is_suspect(__s32 entropy_fixed, __u8 magic_delta)
{
	return entropy_fixed >= CHRONOS_ENTROPY_THRESHOLD ||
	       magic_delta > CHRONOS_MAGIC_DELTA_MAX;
}

#endif /* __CHRONOS_CORE_H__ */
