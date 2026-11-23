// Chronos Phase 1 — integration test: load the eBPF object with libbpf and
// verify the maps and programs are present and well-formed. Attempts a kprobe
// attach but reports (not hard-fails) if the kernel blocks it (e.g. WSL2
// without kprobe access).

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char **argv)
{
	const char *obj = argc > 1 ? argv[1] : "./chronos_bpf.o";
	struct bpf_object *objp;
	struct bpf_map *map;
	struct bpf_program *prog;
	int err;

	if (access(obj, R_OK) != 0) {
		fprintf(stderr, "cannot read %s (run make first)\n", obj);
		return 2;
	}

	objp = bpf_object__open_file(obj, NULL);
	CHECK(objp != NULL, "eBPF object opens");
	if (!objp)
		return 1;

	/* Verify maps exist with expected types. */
	map = bpf_object__find_map_by_name(objp, "chronos_ringbuf");
	CHECK(map != NULL, "chronos_ringbuf map present");
	if (map)
		CHECK(bpf_map__type(map) == BPF_MAP_TYPE_RINGBUF,
		      "chronos_ringbuf is RINGBUF");

	map = bpf_object__find_map_by_name(objp, "chronos_allowlist");
	CHECK(map != NULL, "chronos_allowlist map present");
	if (map)
		CHECK(bpf_map__type(map) == BPF_MAP_TYPE_LRU_HASH,
		      "chronos_allowlist is LRU_HASH");

	/* Verify programs exist with expected sections/types. */
	prog = bpf_object__find_program_by_name(objp, "chronos_kprobe_vfs_write");
	CHECK(prog != NULL, "chronos_kprobe_vfs_write program present");

	prog = bpf_object__find_program_by_name(objp,
						"chronos_kprobe_security_file_permission");
	CHECK(prog != NULL, "chronos_kprobe_security_file_permission present");

	/* Load the object (validates with the kernel verifier). */
	err = bpf_object__load(objp);
	CHECK(err == 0, "eBPF object loads into kernel");

	if (err == 0) {
		/* Attempt attach (best effort; may be restricted). */
		prog = bpf_object__find_program_by_name(objp,
							"chronos_kprobe_vfs_write");
		if (prog) {
			struct bpf_link *link =
				bpf_program__attach_kprobe(prog, false, "vfs_write");
			if (link) {
				CHECK(1, "attached kprobe/vfs_write");
				bpf_link__destroy(link);
			} else {
				fprintf(stderr,
					"INFO: kprobe/vfs_write attach blocked (kernel restriction)\n");
			}
		}
	}

	bpf_object__close(objp);

	printf("integration: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
