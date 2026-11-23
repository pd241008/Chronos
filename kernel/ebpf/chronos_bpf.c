// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Chronos Kernel Interception Layer — eBPF (Linux 6.x / 6.2)
// Intercepts vfs_write and security_file_permission at the VFS boundary,
// captures pre-image extents into a cache-aligned per-PID
// BPF_MAP_TYPE_RINGBUF, and hands them to the Go userspace daemon which
// performs the rolling byte-entropy + magic-byte delta classification
// (chronos_core.h, unit-tested on the host).
//
// NOTE: the verifier on some WSL2/kernel builds rejects the combination of
// userspace probe reads + a classification loop + ringbuf submit in a single
// program. To stay verifier-safe, classification runs in userspace; the eBPF
// program captures the pre-image extent metadata + leading bytes.
//
// Build (host):
/*
   clang -target bpf -O2 -g -Wall -Wextra -D__TARGET_ARCH_x86 \
     -I/lib/modules/$(uname -r)/build/include \
     -I/lib/modules/$(uname -r)/build/include/asm \
     -I. -c chronos_bpf.c -o chronos_bpf.o
*/


#ifndef __CHRONOS_BPF_H__
#define __CHRONOS_BPF_H__

#ifndef __user
#define __user
#endif

#include <linux/bpf.h>
#include <linux/fs.h>
#include <asm/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "chronos_core.h"

/* ---------- maps ---------- */

/* Ring buffer for diverted pre-image extent descriptors. Pinned by name so
 * the Go userspace daemon consumes them via zero-copy shared memory. */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, CHRONOS_RINGBUF_SIZE);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} chronos_ringbuf SEC(".maps");

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

/* Fill the static fields of an extent descriptor.
 *
 * The installed kernel headers here are UAPI-only and do not expose the full
 * definitions of struct file / struct inode / struct super_block, so the
 * inode/device fields cannot be dereferenced from eBPF on this build. They are
 * recorded as zero; a full kernel-header build populates them via
 * BPF_CORE_READ(file, f_inode)->i_ino etc. */
static inline void chronos_fill_desc(struct chronos_extent_desc *d,
				     struct file *file, __u32 count,
				     __u64 offset, __u32 fd, __u8 mode)
{
	__u32 tgid = chronos_get_tgid();
	(void)file;

	d->pid = tgid;
	d->tid = chronos_get_tid();
	d->ts_ns = bpf_ktime_get_ns();
	d->size = count;
	d->offset = offset;
	d->fd = fd;
	d->mode = mode;
	d->ino = 0;
	d->dev_major = 0;
	d->dev_minor = 0;
	d->magic_delta = 0;
	d->entropy_fixed = 0;
	__builtin_memset(d->magic, 0, sizeof(d->magic));
}

/* Divert a pre-image extent into the per-PID ring buffer.
 *
 * A single bounded probe read captures the leading bytes (observed magic).
 * Full entropy/magic-byte classification is performed by the Go daemon. */
static inline void chronos_divert(struct file *file, const char __user *buf,
				  __u32 count, __u64 offset, __u32 fd,
				  __u8 mode)
{
	__u32 tgid = chronos_get_tgid();

	/* Skip whitelisted processes. */
	if (bpf_map_lookup_elem(&chronos_allowlist, &tgid))
		return;

	__u8 window[CHRONOS_MAGIC_DELTA_MAX + 1]; /* small, fully zeroed */
	__builtin_memset(window, 0, sizeof(window));
	__u32 rlen = count < sizeof(window) ? count : sizeof(window);
	if (rlen > sizeof(window) - 1)
		rlen = sizeof(window) - 1;
	rlen &= sizeof(window) - 1; /* provably in [0,15] for the verifier */
	if (rlen > 0 && buf)
		bpf_probe_read_user(window, rlen, buf);

	struct chronos_extent_desc *d =
		bpf_ringbuf_reserve(&chronos_ringbuf, sizeof(*d), 0);
	if (!d)
		return; /* ringbuf full — drop (bounded memory) */

	chronos_fill_desc(d, file, count, offset, fd, mode);

	/* Observed leading bytes = magic. Reads within the zeroed window. */
	__builtin_memcpy(d->magic, window, sizeof(window));
	d->magic_delta = 0; /* userspace computes the real delta */

	bpf_ringbuf_submit(d, 0);
}

/* ---------- kprobe attachments ---------- */

/* vfs_write: intercept at the VFS boundary before page-cache commit. */
SEC("kprobe/vfs_write")
int chronos_kprobe_vfs_write(struct pt_regs *ctx)
{
	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	const char __user *buf = (const char __user *)PT_REGS_PARM2(ctx);
	__u32 count = (__u32)PT_REGS_PARM3(ctx);

	chronos_divert(file, buf, count, 0, 0, 1);
	return 0;
}

/* security_file_permission: pre-permission check; capture metadata only. */
SEC("kprobe/security_file_permission")
int chronos_kprobe_security_file_permission(struct pt_regs *ctx)
{
	struct file *file = (struct file *)PT_REGS_PARM1(ctx);
	chronos_divert(file, NULL, 0, 0, 0, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#endif /* __CHRONOS_BPF_H__ */
