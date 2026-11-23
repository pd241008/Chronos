// Chronos Phase 1 — systems test: load the eBPF object via the libbpf loader
// path and attach both kprobes (vfs_write, security_file_permission).
// Runs the loader briefly, verifies attach, then tears down.

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <signal.h>
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
	struct bpf_program *prog;
	struct bpf_link *links[2] = {NULL, NULL};
	int err, i;

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

	if (err == 0) {
		/* Attach both kprobes. */
		int n = 0;
		prog = bpf_object__find_program_by_name(objp,
							"chronos_kprobe_vfs_write");
		if (prog) {
			links[n] = bpf_program__attach_kprobe(prog, false,
							      "vfs_write");
			CHECK(links[n] != NULL, "attached kprobe/vfs_write");
			n++;
		}
		prog = bpf_object__find_program_by_name(objp,
				"chronos_kprobe_security_file_permission");
		if (prog) {
			links[n] = bpf_program__attach_kprobe(prog, false,
				"security_file_permission");
			CHECK(links[n] != NULL,
			      "attached kprobe/security_file_permission");
			n++;
		}

		/* Keep attached briefly so a real write would be intercepted. */
		usleep(200000);

		/* Detach all. */
		for (i = 0; i < 2; i++)
			if (links[i])
				bpf_link__destroy(links[i]);
	}

	bpf_object__close(objp);

	printf("systems: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
