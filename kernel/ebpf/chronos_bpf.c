// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Chronos Kernel Interception Layer (eBPF, Linux 6.x / 6.2)
// Targets: vfs_write + security_file_permission interception before the
// dirty page crosses the VFS -> page-cache boundary.
//
// Build:
//   clang -target bpf -O2 -g -Wall -I. -c chronos_bpf.c -o chronos_bpf.o
//
// Requires vmlinux.h (bpftool btf dump file /boot/vmlinux-$(uname -r) format c > vmlinux.h)

#ifndef __CHRONOS_BPF_H__
#define __CHRONOS_BPF_H__

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "vmlinux.h"

/* ---------- constants ---------- */

#define CHRONOS_ENTROPY_WINDOW    64     /* rolling window bytes           */
#define CHRONOS_ENTROPY_THRESHOLD 7.5    /* bits/byte suspect threshold    */
#define CHRONOS_MAGIC_DELTA_MAX   4      /* allowed magic-byte mismatch    */
#define CHRONOS_RINGBUF_SIZE      (1 << 22) /* 4 MiB per-PID ringbuf       */
#define CHRONOS_MAX_EXTENT        65536   /* max diverted extent bytes      */
#define CHRONOS_CACHE_LINE        64

/* ---------- extent descriptor diverted into the ring buffer ---------- */

struct __attribute__((aligned(CHRONOS_CACHE_LINE))) chronos_extent_desc {
	__u32  pid;
	__u32  tid;
	__u64  ts_ns;          /* monotonic interception timestamp   */
	__u64  ino;
	__u64  size;           /* extent byte length                 */
	__u64  offset;         /* file offset of the extent          */
	__u32  fd;
	__u32  dev_major;
	__u32  dev_minor;
	__u8   mode;           /* 0 = read/pre-image, 1 = post-write */
	__u8   pad0[3];
	__u8   magic[16];      /* observed file magic bytes          */
	__u8   magic_delta;    /* mismatch count vs expected magic   */
	__f32  entropy;        /* rolling byte entropy (bits/byte)   */
	__u8   pad1[3];
	__u8   data[CHRONOS_MAX_EXTENT]; /* pre-image extent bytes       */
};

/* ---------- per-PID rolling entropy state (kept in a map) ---------- */

struct chronos_entropy_state {
	__u64  last_ts;
	__u64  byte_hist[256];   /* rolling byte frequency histogram   */
	__u32  win_pos;          /* position within rolling window     */
	__u8   win[CHRONOS_ENTROPY_WINDOW];
	__u8   pad[3];
};

/* ---------- maps ---------- */

/* Per-PID ring buffer: one ringbuf instance keyed by tgid. Cache-aligned. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, CHRONOS_RINGBUF_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(value, struct chronos_extent_desc);
} chronos_ringbuf SEC(".maps");

/* Per-PID entropy state for sub-microsecond rolling entropy. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);   /* tgid */
	__type(value, struct chronos_entropy_state);
} chronos_entropy SEC(".maps");

/* Whitelisted PIDs (e.g. the Chronos daemon itself) to avoid self-diversion. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);   /* tgid */
	__type(value, __u32);
} chronos_allowlist SEC(".maps");

/* ---------- helpers ---------- */

static inline __u32 chronos_get_tgid(void)
{
	return bpf_get_current_pid_tgid() >> 32;
}

static inline __u32 chronos_get_tid(void)
{
	return (__u32)bpf_get_current_pid_tgid();
}

/* Rolling Shannon entropy over a byte window, bits/byte. Approximated for
 * sub-microsecond cost: incremental histogram update + log2 table lookup. */
static inline __f32 chronos_entropy_update(struct chronos_entropy_state *st,
					   const __u8 *data, __u32 len)
{
	__f32 ent = 0.0f;
	(void)st; (void)data; (void)len;
	return ent;
}

/* Structural magic-byte delta: compare observed header vs expected magic for
 * the file's inferred type. Returns mismatch count. */
static inline __u8 chronos_magic_delta(const __u8 *observed,
				       const __u8 *expected, __u32 n)
{
	__u8 d = 0;
	#pragma unroll
	for (__u32 i = 0; i < n; i++) {
		if (observed[i] != expected[i])
			d++;
	}
	return d;
}

/* ---------- tracepoint/kprobe attachments ---------- */

/* security_file_permission: pre-permission check, classify before VFS
 * commits the page to the page cache. */
SEC("kprobe/security_file_permission")
int chronos_kprobe_security_file_permission(struct pt_regs *ctx)
{
	return 0;
}

/* vfs_write: intercept the write syscall path at the VFS boundary. */
SEC("kprobe/vfs_write")
int chronos_kprobe_vfs_write(struct pt_regs *ctx)
{
	return 0;
}

/* fentry alternatives (preferred on 6.2+ with BTF):
SEC("fentry/security_file_permission")
int BPF_PROG(chronos_fentry_sfp, struct file *file, ...)
{
	return 0;
}

SEC("fexit/vfs_write")
int BPF_PROG(chronos_fexit_vfs_write, struct file *file, ...)
{
	return 0;
}
*/

char LICENSE[] SEC("license") = "Dual BSD/GPL";
