// vmlinux.h placeholder.
// Generate on the target host with:
//   bpftool btf dump file /boot/vmlinux-$(uname -r) format c > vmlinux.h
// Required before building chronos_bpf.c on Linux 6.2.
#ifndef __VMLINUX_H__
#define __VMLINUX_H__
/* Core kernel types are injected here by bpftool. */
#endif
