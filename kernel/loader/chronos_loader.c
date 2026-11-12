// Chronos Kernel libbpf loader skeleton (C)
// Attaches chronos_bpf.o to vfs_write / security_file_permission and pins
// the per-PID ring buffer map for zero-copy consumption by the Go daemon.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int handle_ringbuf(void *ctx, void *data, size_t size)
{
	(void)ctx; (void)data; (void)size;
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int err;

	(void)argc; (void)argv;

	obj = bpf_object__open_file("chronos_bpf.o", NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "failed to open eBPF object\n");
		return 1;
	}

	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "failed to load eBPF object: %d\n", err);
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "chronos_kprobe_vfs_write");
	if (prog) {
		if (bpf_program__attach(prog)) {
			fprintf(stderr, "attach vfs_write failed\n");
		}
	}

	prog = bpf_object__find_program_by_name(obj, "chronos_kprobe_security_file_permission");
	if (prog) {
		if (bpf_program__attach(prog)) {
			fprintf(stderr, "attach security_file_permission failed\n");
		}
	}

	int rb_map_fd = bpf_object__find_map_fd_by_name(obj, "chronos_ringbuf");
	if (rb_map_fd < 0) {
		fprintf(stderr, "ringbuf map not found\n");
		return 1;
	}

	fprintf(stderr, "chronos loader: attached, ringbuf map fd=%d\n", rb_map_fd);

	while (1) {
		pause();
	}

	return 0;
}
