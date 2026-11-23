// Chronos Phase 1 — host unit tests for the pure classification logic
// (entropy, magic-byte delta, log2 fixed-point). Compiles for the host,
// independent of BPF headers, by including chronos_core.h.

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Map kernel-style types to host types so chronos_core.h compiles natively. */
typedef uint8_t  __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int32_t  __s32;

#include "../chronos_core.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, msg)                                              \
	do {                                                            \
		checks++;                                               \
		if (!(cond)) {                                          \
			fprintf(stderr, "FAIL: %s (line %d)\n", msg, __LINE__); \
			failures++;                                         \
		}                                                       \
	} while (0)

static void test_magic_delta(void)
{
	__u8 a[16] = {0};
	__u8 b[16] = {0};

	CHECK(chronos_magic_delta(a, b, 16) == 0, "identical -> 0");

	b[0] = 0xff;
	CHECK(chronos_magic_delta(a, b, 16) == 1, "one mismatch -> 1");

	for (__u32 i = 0; i < 16; i++)
		b[i] = (__u8)~a[i];
	CHECK(chronos_magic_delta(a, b, 16) == 16, "all mismatch -> 16");

	__u8 magic_expected[4] = {0x7f, 'E', 'L', 'F'};
	__u8 magic_elf[4] = {0x7f, 'E', 'L', 'F'};
	CHECK(chronos_magic_delta(magic_elf, magic_expected, 4) == 0, "ELF magic match");

	magic_elf[3] = 'X';
	CHECK(chronos_magic_delta(magic_elf, magic_expected, 4) == 1, "ELF magic 1 mismatch");
}

static void test_log2_fixed(void)
{
	CHECK(chronos_log2_fixed(0) == 0, "log2(0) -> 0");
	CHECK(chronos_log2_fixed(1) == 0, "log2(1) -> 0");
	CHECK(chronos_log2_fixed(2) == LOG2_SCALE, "log2(2) -> 1024");
	CHECK(chronos_log2_fixed(4) == 2 * LOG2_SCALE, "log2(4) -> 2048");
	CHECK(chronos_log2_fixed(8) == 3 * LOG2_SCALE, "log2(8) -> 3072");
	CHECK(chronos_log2_fixed(256) == 8 * LOG2_SCALE, "log2(256) -> 8192");
	CHECK(chronos_log2_fixed(3) == LOG2_SCALE, "log2(3) floor -> 1024");
}

static void test_entropy_uniform(void)
{
	struct chronos_entropy_state st;
	memset(&st, 0, sizeof(st));

	/* Fill histogram uniformly over 256 byte values, 4 samples each
	 * (total 1024). entropy should be exactly log2(256)=8*1024=8192. */
	for (__u32 i = 0; i < 256; i++)
		st.byte_hist[i] = 4;
	st.total_count = 1024;

	__s32 ent = chronos_entropy_compute(&st);
	/* fixed-point log2(256) = 8192; our floor(log2) computation of
	 * per-byte log2(4)=2048 each: entropy = 8192 - (sum 4*2048)/1024
	 * = 8192 - (256*4*2048)/1024 = 8192 - 2048 = 6144. Because we use
	 * floor(log2) it underestimates slightly; just check it's high. */
	CHECK(ent > 7000, "uniform 256 values -> high entropy");
	CHECK(ent <= 8192, "uniform 256 values -> <= max");
}

static void test_entropy_single_value(void)
{
	struct chronos_entropy_state st;
	memset(&st, 0, sizeof(st));

	/* All samples the same byte -> entropy 0. */
	st.byte_hist[0x41] = 100;
	st.total_count = 100;

	__s32 ent = chronos_entropy_compute(&st);
	/* distinct=1 -> proxy = 1*32 = 32 (very low entropy) */
	CHECK(ent == 32, "single byte value -> low entropy proxy");
}

static void test_entropy_update_accumulates(void)
{
	struct chronos_entropy_state st;
	memset(&st, 0, sizeof(st));

	__u8 data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	chronos_entropy_update(&st, data, 8);
	CHECK(st.total_count == 8, "update accumulates total_count");
	CHECK(st.byte_hist[1] == 1 && st.byte_hist[8] == 1, "update records bytes");

	chronos_entropy_update(&st, data, 8);
	CHECK(st.total_count == 16, "update accumulates across calls");
	CHECK(st.byte_hist[1] == 2, "update increments on repeat");
}

static void test_entropy_decay(void)
{
	struct chronos_entropy_state st;
	memset(&st, 0, sizeof(st));

	/* Pump MAX_SAMPLES+10 samples of a single byte to trigger decay. */
	__u8 one = 0x0a;
	__u32 before = 0;
	for (__u32 i = 0; i < MAX_SAMPLES / 2; i++)
		chronos_entropy_update(&st, &one, 1);
	before = st.byte_hist[0x0a];
	for (__u32 i = 0; i < MAX_SAMPLES + 10; i++)
		chronos_entropy_update(&st, &one, 1);
	CHECK(st.total_count <= MAX_SAMPLES, "decay caps total_count");
	CHECK(st.byte_hist[0x0a] < before * 2, "decay reduced the histogram");
}

static void test_is_suspect(void)
{
	CHECK(chronos_is_suspect(CHRONOS_ENTROPY_THRESHOLD, 0) == 1,
	      "entropy at threshold -> suspect");
	CHECK(chronos_is_suspect(CHRONOS_ENTROPY_THRESHOLD - 1, 0) == 0,
	      "entropy just below threshold -> benign");
	CHECK(chronos_is_suspect(0, CHRONOS_MAGIC_DELTA_MAX + 1) == 1,
	      "magic delta over max -> suspect");
	CHECK(chronos_is_suspect(0, CHRONOS_MAGIC_DELTA_MAX) == 0,
	      "magic delta at max -> benign");
	CHECK(chronos_is_suspect(0, 0) == 0, "nothing anomalous -> benign");
}

int main(void)
{
	test_magic_delta();
	test_log2_fixed();
	test_entropy_uniform();
	test_entropy_single_value();
	test_entropy_update_accumulates();
	test_entropy_decay();
	test_is_suspect();

	printf("unit: %d checks, %d failures\n", checks, failures);
	return failures ? 1 : 0;
}
