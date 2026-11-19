/*
 * fuzz_zonefile / fuzz_ixfr_create: what `nsd-checkzone [-p] [-i old] <zone> <file>`
 * does (nsd-checkzone.c check_zone()), in process.
 *
 * Input format (text):
 *   line 1         the zone name, as given on nsd-checkzone's command line
 *   rest           the zone file (simdzone parser, zonec.c callbacks)
 * FUZZ_IXFR_CREATE build only: the rest is split at the first line that is
 * exactly "$$NEW$$": before it is the OLD zone file (-i), after it the NEW one,
 * and the IXFR between them is created (ixfrcreate.c) and read back (ixfr.c).
 *
 * After a clean load the zone is NSEC3-prehashed as nsd does when it serves
 * it, and printed (`-p`, rdata.c print functions) to /dev/null.
 *
 * Per-input state: the options region, the namedb and the files in the
 * scratch dir are created and destroyed for every input. Only the scratch
 * dir name and the /dev/null stream persist.
 */
#include "nsd_fuzz_common.h"
#include "zonec.h"
#include "nsec3.h"
#include "ixfr.h"
#include "ixfrcreate.h"
#include "difffile.h"
#include "dname.h"

static FILE *devnull;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc; (void)argv;
	fuzz_quiet_logs();
	devnull = fopen("/dev/null", "w");
	if (!devnull)
		abort();
	(void)fuzz_scratch_dir();
	return 0;
}

static void
remove_ixfr_files(const char *zfile)
{
	char p[1200];
	int i;
	snprintf(p, sizeof(p), "%s.ixfr", zfile);
	unlink(p);
	for (i = 2; i < 10; i++) {
		snprintf(p, sizeof(p), "%s.ixfr.%d", zfile, i);
		unlink(p);
	}
}

static int
fuzz_one(const uint8_t *data, size_t size)
{
	const uint8_t *nl;
	char *name;
	const uint8_t *body;
	size_t bodylen;
	char zpath[1024], opath[1024];
	const char *oldzone = NULL;
	region_type *region;
	const dname_type *dname;
	zone_options_type *zo;
	zone_type *zone;
	unsigned errors;
	struct ixfr_create *ixfrcr = NULL;

	nl = memchr(data, '\n', size);
	if (!nl)
		return -1;
	name = malloc((size_t)(nl - data) + 1);
	memcpy(name, data, (size_t)(nl - data));
	name[nl - data] = 0;
	body = nl + 1;
	bodylen = size - (size_t)(body - data);

#ifdef FUZZ_IXFR_CREATE
	{
		static const char sep[] = "\n$$NEW$$\n";
		const uint8_t *s = NULL, *p;
		for (p = body; p + sizeof(sep) - 1 <= body + bodylen; p++) {
			if (memcmp(p, sep, sizeof(sep) - 1) == 0) {
				s = p;
				break;
			}
		}
		if (!s) {
			free(name);
			return -1;
		}
		fuzz_write_file("old.zone", body, (size_t)(s - body) + 1,
			opath, sizeof(opath));
		oldzone = opath;
		bodylen -= (size_t)(s + sizeof(sep) - 1 - body);
		body = s + sizeof(sep) - 1;
	}
#endif
	fuzz_write_file("input.zone", body, bodylen, zpath, sizeof(zpath));

	/* nsd-checkzone.c main() + check_zone() */
	memset(&nsd, 0, sizeof(nsd));
	region = fuzz_region_create();
	nsd.region = region;	/* zone_ixfr_create() allocates here */
	nsd.options = nsd_options_create(region);
	nsd.db = namedb_open(nsd.options);
	dname = dname_parse(nsd.options->region, name);
	if (!dname) {
		/* nsd-checkzone: error("cannot parse zone name") -> exit */
		namedb_close(nsd.db);
		region_destroy(region);
		free(name);
		return -1;
	}
	zo = zone_options_create(nsd.options->region);
	memset(zo, 0, sizeof(*zo));
	zo->node.key = dname;
	zo->name = name;
	/* nsd-checkzone leaves the pattern NULL; nsd itself always has one,
	 * and the IXFR read-back path needs it (store-ixfr: yes). */
	zo->pattern = pattern_options_create(nsd.options->region);
	zo->pattern->pname = "fuzz";
	zo->pattern->store_ixfr = 1;
	zone = namedb_zone_create(nsd.db, dname, zo);

	if (oldzone) {
		errors = zonec_read(nsd.db, nsd.db->domains, name, oldzone,
			zone);
		if (errors > 0)
			goto done;
		ixfrcr = ixfr_create_start(zone, zpath, IXFR_SIZE_DEFAULT, 1);
		if (!ixfrcr)
			goto done;
		delete_zone_rrs(nsd.db, zone);
	}

	errors = zonec_read(nsd.db, nsd.db->domains, name, zpath, zone);
	if (errors > 0) {
		ixfr_create_cancel(ixfrcr);
		ixfrcr = NULL;
		goto done;
	}
	if (ixfrcr) {
		if (ixfr_create_perform(ixfrcr, zone, 0, &nsd, zpath, 1)) {
			/* read the IXFR back as nsd does at startup */
			ixfr_read_from_file(&nsd, zone, zpath);
		}
		ixfr_create_free(ixfrcr);
		ixfrcr = NULL;
	}
	/* what nsd does after loading a zone it will serve */
	prehash_zone_complete(nsd.db, zone);
	/* -p */
	print_rrs(devnull, zone);
	fflush(devnull);

done:
	if (zone->ixfr) {
		zone_ixfr_free(zone->ixfr);
		zone->ixfr = NULL;
	}
	namedb_close(nsd.db);
	nsd.db = NULL;
	region_destroy(region);
	nsd.options = NULL;
	nsd.region = NULL;
	unlink(zpath);
	if (oldzone) {
		unlink(oldzone);
		remove_ixfr_files(zpath);
	}
	free(name);
	return 0;
}
