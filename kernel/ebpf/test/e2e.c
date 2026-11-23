// Chronos Phase 1 — end-to-end test: load the eBPF object, attach kprobes,
// write suspicious data to a temp file, and verify a pre-image extent
// descriptor appears in the ring buffer.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg)                                              \
	do {                                                            \
		checks++;                                               \
		if (!(cond)) {                                          \
			fprintf(stderr, "FAIL: %s\n", msg);               \
			failures++;                                       \
		}                                                       \
	} while (0)

#pragma pack(push, 1)
struct e2e_desc {
	__u32 pid;
	__u32 tid;
	__u64 ts_ns;
	__u64 ino;
	__u64 size;
	__u64 offset;
	__u32 fd;
	__u32 dev_major;
	__u32 dev_minor;
	__u8 mode;
	__u8 pad0[3];
	__u8 magic[16];
	__u8 magic_delta;
	__u8 pad1[3];
	__s32 entropy_fixed;
	__u8 pad2[4];
};
#pragma pack(pop)

static volatile bool got_desc = false;

static int ringbuf_cb(void *ctx, void *data, size_t size)
{
	struct e2e_desc *d = data;
	(void)ctx;
	if (size >= sizeof(*d) && d->size > 0 && !got_desc) {
		got_desc = true;
		fprintf(stderr, "e2e: captured extent pid=%u size=%llu mode=%u\n",
			d->pid, (unsigned long long)d->size, d->mode);
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *obj = argc > 1 ? argv[1] : "./chronos_bpf.o";
	struct bpf_object *objp;
	struct bpf_program *prog;
	struct bpf_link *links[2] = {NULL, NULL};
	struct ring_buffer *rb = NULL;
	int map_fd, err;
	int tfd;

	if (access(obj, R_OK) != 0) {
		fprintf(stderr, "cannot read %s (run make first)\n", obj);
		return 2;
	}

	objp = bpf_object__open_file(obj, NULL);
	CHECK(objp != NULL, "eBPF object opens");
	if (!objp)
		return 1;

	err = bpf_object__load(objp);
	CHECK(err == 0, "eBPF object loads into kernel");

	if (err != 0)
		goto out;

	/* Attach both kprobes. */
	prog = bpf_object__find_program_by_name(objp,
						"chronos_kprobe_vfs_write");
	CHECK(prog != NULL, "chronos_kprobe_vfs_write program present");
	if (prog) {
		links[0] = bpf_program__attach_kprobe(prog, false, "vfs_write");
		CHECK(links[0] != NULL, "attached kprobe/vfs_write");
	}
	prog = bpf_object__find_program_by_name(objp,
				"chronos_kprobe_security_file_permission");
	if (prog) {
		links[1] = bpf_program__attach_kprobe(prog, false,
				"security_file_permission");
		CHECK(links[1] != NULL,
		      "attached kprobe/security_file_permission");
	}

	/* Open the ring buffer map and poll via libbpf ringbuf reader. */
	map_fd = bpf_object__find_map_fd_by_name(objp, "chronos_ringbuf");
	CHECK(map_fd >= 0, "chronos_ringbuf map fd");
	if (map_fd >= 0) {
		rb = ring_buffer__new(map_fd, ringbuf_cb, NULL, NULL);
		CHECK(rb != NULL, "ringbuf reader opened");
	}

	/* Drain any leftover descriptors from previous runs. */
	if (rb) {
		int i;
		for (i = 0; i < 100 && ring_buffer__poll(rb, 0) > 0; i++)
			;
	}

	/* Write suspicious (high-entropy-looking) data to a temp file. */
	tfd = open("/tmp/chronos_e2e_testfile",
		   O_CREAT | O_WRONLY | O_TRUNC, 0644);
	CHECK(tfd >= 0, "test file created");
	if (tfd >= 0) {
		static const __u8 payload[64] = {
			0xee, 0x3a, 0x9f, 0x1c, 0x4b, 0x7d, 0xa2, 0x51,
			0x38, 0xf4, 0x6c, 0x21, 0x9b, 0xd7, 0x0a, 0x83,
			0xe1, 0x4c, 0x2f, 0x7a, 0x59, 0x10, 0x66, 0x33,
			0xbb, 0x8d, 0x42, 0xf1, 0xa7, 0xc4, 0x29, 0x5e,
		};
		ssize_t w = write(tfd, payload, sizeof(payload));
		CHECK(w == (ssize_t)sizeof(payload), "test file written");
		close(tfd);
	}

	/* Poll for the descriptor produced by our write (bounded, break early). */
	if (rb) {
		int i;
		for (i = 0; i < 30 && !got_desc; i++)
			ring_buffer__poll(rb, 100);
	}
	CHECK(got_desc, "ring buffer captured a pre-image extent descriptor");

out:
	if (rb)
		ring_buffer__free(rb);
	if (links[0])
		bpf_link__destroy(links[0]);
	if (links[1])
		bpf_link__destroy(links[1]);
	if (objp)
		bpf_object__close(objp);
	unlink("/tmp/chronos_e2e_testfile");

	printf("e2e: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
