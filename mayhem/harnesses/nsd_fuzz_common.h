/*
 * Shared helpers for the NSD fuzz harnesses (mayhem/harnesses/).
 *
 * The harnesses link the same objects nsd-checkzone links (everything but the
 * objects that carry a main()), so they provide the few process-level symbols
 * nsd-checkzone.c provides too (the global `nsd`, writepid, ...).
 */
#ifndef NSD_FUZZ_COMMON_H
#define NSD_FUZZ_COMMON_H

#include "config.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "nsd.h"
#include "options.h"
#include "util.h"
#include "namedb.h"
#include "region-allocator.h"

/* Same stubs as nsd-checkzone.c: these live in nsd.c, which has main(). */
struct nsd nsd;
int writepid(struct nsd *ATTR_UNUSED(n)) { return 0; }
void unlinkpid(const char *ATTR_UNUSED(file), const char *ATTR_UNUSED(username)) {}
void bind8_stats(struct nsd *ATTR_UNUSED(n)) {}
void sig_handler(int ATTR_UNUSED(sig)) {}

/* Discard log output: every rejected input logs, and stderr I/O would
 * dominate the exec time. Crashes are reported by the sanitizers. */
static void
fuzz_log_discard(int ATTR_UNUSED(priority), const char *ATTR_UNUSED(message))
{
}

/*
 * nsd's fatal paths call exit() (error(), flex's YY_FATAL_ERROR, the
 * "checked during syntax parse" exits in options.c). An exit() while an input
 * is being processed is turned into abort(), so it is reported as a crash
 * with a stack (docs: lift exit() to abort()). Exits outside an input
 * (libFuzzer's own shutdown) are unaffected.
 *
 * The handler is registered on the first input, not in LLVMFuzzerInitialize:
 * libFuzzer registers its own exit callback (which _Exit()s with "fuzz target
 * exited") after LLVMFuzzerInitialize, and atexit handlers run newest first,
 * so ours has to be registered later than libFuzzer's to run before it.
 */
static volatile int fuzz_in_input;

static void
fuzz_exit_to_abort(void)
{
	if (fuzz_in_input)
		abort();
}

static int fuzz_one(const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static int exit_handler_set;
	int r;
	if (!exit_handler_set) {
		atexit(fuzz_exit_to_abort);
		exit_handler_set = 1;
	}
	fuzz_in_input = 1;
	r = fuzz_one(data, size);
	fuzz_in_input = 0;
	return r;
}

static void
fuzz_quiet_logs(void)
{
	log_init("nsd-fuzz");
	/* NSD_FUZZ_LOG=<verbosity> keeps nsd's log on stderr (triage aid) */
	if (getenv("NSD_FUZZ_LOG")) {
		verbosity = atoi(getenv("NSD_FUZZ_LOG"));
		return;
	}
	log_set_log_function(fuzz_log_discard);
	verbosity = 0;
}

/* A private scratch directory under $TMPDIR (default /tmp). */
static char fuzz_dir[512];

static const char *
fuzz_scratch_dir(void)
{
	const char *t;
	if (fuzz_dir[0])
		return fuzz_dir;
	t = getenv("TMPDIR");
	if (!t || !*t)
		t = "/tmp";
	snprintf(fuzz_dir, sizeof(fuzz_dir), "%s/nsd-fuzz-XXXXXX", t);
	if (!mkdtemp(fuzz_dir)) {
		perror("mkdtemp");
		abort();
	}
	return fuzz_dir;
}

/* Write `len` bytes to <scratch>/<name>; returns the path (static buffer
 * owned by the caller via `out`). Aborts on I/O failure: that is an
 * environment problem, not an input property. */
static void
fuzz_write_file(const char *name, const void *data, size_t len, char *out,
	size_t outlen)
{
	FILE *f;
	snprintf(out, outlen, "%s/%s", fuzz_scratch_dir(), name);
	f = fopen(out, "wb");
	if (!f) {
		perror(out);
		abort();
	}
	if (len && fwrite(data, 1, len, f) != len) {
		perror(out);
		abort();
	}
	fclose(f);
}

static region_type *
fuzz_region_create(void)
{
	return region_create_custom(xalloc, free, DEFAULT_CHUNK_SIZE,
		DEFAULT_LARGE_OBJECT_SIZE, DEFAULT_INITIAL_CLEANUP_SIZE, 1);
}

#endif /* NSD_FUZZ_COMMON_H */
