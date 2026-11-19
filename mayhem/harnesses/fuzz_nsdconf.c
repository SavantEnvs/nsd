/*
 * fuzz_nsdconf: nsd.conf parsing as nsd / nsd-checkconf do it:
 * parse_options_file() (options.c, configlexer.lex, configparser.y), with the
 * semantic checks parse_options_file runs itself (key/ACL/tls-auth lookups,
 * pattern and zone resolution, TSIG key setup in key_options_setup).
 *
 * Per-input state: a fresh options region per input; the parser's global
 * `cfg_parser` and the flex buffer are reset after every input
 * (cfg_parser = NULL, c_lex_destroy(), as nsd_options_destroy does under
 * MEMCLEAN).
 *
 * `include:` is confined the way nsd confines it when it runs chrooted
 * (nsd.c sets cfg_parser->chroot): includes must lie under a scratch path
 * that does not exist, so the include code runs (path check, glob, open
 * failure) but no other file is read; "<chroot>/../x" cannot escape either,
 * as the kernel fails the lookup at the missing directory. Two reasons: an input's result must not depend on files
 * outside it, and the lexer keeps a static include stack that a syntax error
 * inside an included file leaves populated (pointing at the FILE that
 * parse_options_file has already closed), which would leak into the next
 * input in the same process.
 */
#include "nsd_fuzz_common.h"

int c_lex_destroy(void);

static char no_dir[600];

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_quiet_logs();
	/* never created; cfg_parser->chroot has a trailing slash */
	snprintf(no_dir, sizeof(no_dir), "%s/no-such-dir/", fuzz_scratch_dir());
	return 0;
}

static void
conf_err_discard(void *ATTR_UNUSED(arg), const char *ATTR_UNUSED(msg))
{
}

static int
fuzz_one(const uint8_t *data, size_t size)
{
	char path[1024];
	region_type *region;
	struct nsd_options *opt;

	fuzz_write_file("nsd.conf", data, size, path, sizeof(path));
	region = fuzz_region_create();
	opt = nsd_options_create(region);
	cfg_parser = (config_parser_state_type *)region_alloc_zero(region,
		sizeof(config_parser_state_type));
	cfg_parser->chroot = no_dir;
	(void)parse_options_file(opt, path, conf_err_discard, NULL, NULL);
	c_lex_destroy();
	cfg_parser = NULL;
	region_destroy(region);
	unlink(path);
	return 0;
}
