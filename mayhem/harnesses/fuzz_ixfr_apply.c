/*
 * fuzz_ixfr_apply: a zone transfer reply from a primary, received by xfrd and
 * then applied to the loaded zone by the reload, the way a secondary nsd
 * handles it:
 *   1. xfrd (xfrd.c) has an AXFR or IXFR request outstanding for
 *      example.com: the request is built and, for the keyed primary,
 *      TSIG-signed exactly as xfrd_tcp_setup_write_packet() does.
 *   2. every reply packet goes through xfrd_handle_received_xfr_packet():
 *      query ID, RCODE, TSIG (xfrd_xfr_process_tsig), SOA serials and RR
 *      checks (xfrd_parse_received_xfr_packet, xfrd_xfr_check_rrs); packets
 *      that pass are spooled with diff_write_packet() and the transfer is
 *      committed with diff_write_commit().
 *   3. only a transfer xfrd committed is applied: apply_ixfr_for_zone() reads
 *      the spool file back (difffile.c apply_ixfr: packet_read_rr, IXFR
 *      delete/add, AXFR replace, SOA checks; ixfr_store with store-ixfr: yes;
 *      NSEC3 prehash), as the reload's apply_xfr task does.
 *
 * Input: byte 0     flags: bit 0 the transfer runs over TCP (else UDP),
 *                   bit 1 the request went to the TSIG-keyed primary,
 *                   bit 2 xfrd already holds the zone (serial 1), so it asks
 *                   for an IXFR (else a fresh secondary asks for an AXFR);
 *        bytes 1-2  the query ID of the outstanding request (network order);
 *        then       the reply packets, each a 2-byte length (network order)
 *                   and that many bytes of DNS message, as on a TCP zone
 *                   transfer stream (over UDP, each is one datagram).
 *
 * Per-input state: a fresh namedb with the zone loaded from the fixed zone
 * file, a fresh nsd.region, a fresh xfrd state (region, zone, transfer, TSIG
 * record) and a fresh spool file; xfrd's timers are removed from the event
 * base before the input ends. Kept read-only across inputs: the parsed
 * nsd.conf (zone options, request-xfr ACLs: xfrd_handle_received_xfr_packet
 * does not write them) and the TSIG key table (tsig_init/key_options_tsig_add).
 */
#include "nsd_fuzz_common.h"
#include "difffile.h"
#include "xfrd-disk.h"
#include "xfrd.h"
#include "xfrd-tcp.h"
#include "zonec.h"
#include "nsec3.h"
#include "ixfr.h"
#include "dname.h"
#include "packet.h"
#include "tsig.h"
#include "mini_event.h"

static const char base_zone[] =
"$ORIGIN example.com.\n"
"$TTL 3600\n"
"@\tIN SOA ns1 hostmaster 1 7200 3600 1209600 300\n"
"\tIN NS ns1\n"
"\tIN MX 10 mail\n"
"ns1\tIN A 192.0.2.53\n"
"mail\tIN A 192.0.2.25\n"
"www\tIN A 192.0.2.80\n"
"www\tIN AAAA 2001:db8::80\n"
"c1\tIN CNAME www\n"
"*.wild\tIN TXT \"wildcard\"\n"
"deleg\tIN NS ns.deleg\n"
"ns.deleg\tIN A 192.0.2.54\n";

static const char conf_fmt[] =
"server:\n"
"\tzonesdir: \"%s\"\n"
"\txfrdir: \"%s\"\n"
"\tzonelistfile: \"%s/zone.list\"\n"
"key:\n"
"\tname: \"tsig.example.\"\n"
"\talgorithm: hmac-sha256\n"
"\tsecret: \"K2tf3TRjvQkVCmJF3/Z9vA==\"\n"
"zone:\n"
"\tname: \"example.com\"\n"
"\tzonefile: \"example.com.zone\"\n"
"\trequest-xfr: 192.0.2.1 NOKEY\n"
"\trequest-xfr: 192.0.2.2 tsig.example.\n"
"\tstore-ixfr: yes\n";

#define FLAG_TCP   0x01
#define FLAG_KEYED 0x02
#define FLAG_IXFR  0x04

static char zone_path[1024];
static const dname_type *zone_dname;
static struct zone_options *zone_opts;
static struct event_base *xfrd_base;
static time_t ev_secs;
static struct timeval ev_tv;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char conf[2048], path[1024], dir_slash[600];
	const char *dir;
	region_type *optregion;
	(void)argc; (void)argv;

	fuzz_quiet_logs();
	dir = fuzz_scratch_dir();
	snprintf(dir_slash, sizeof(dir_slash), "%s/", dir);
	fuzz_write_file("example.com.zone", base_zone, sizeof(base_zone) - 1,
		zone_path, sizeof(zone_path));
	snprintf(conf, sizeof(conf), conf_fmt, dir, dir_slash, dir);
	fuzz_write_file("nsd.conf", conf, strlen(conf), path, sizeof(path));

	memset(&nsd, 0, sizeof(nsd));
	nsd.pid = getpid();
	optregion = fuzz_region_create();
	if (!tsig_init(optregion))
		abort();
	nsd.options = nsd_options_create(optregion);
	if (!parse_options_file(nsd.options, path, NULL, NULL, NULL)) {
		fprintf(stderr, "fuzz_ixfr_apply: cannot parse %s\n", path);
		abort();
	}
	key_options_tsig_add(nsd.options);
	zone_dname = dname_parse(optregion, "example.com.");
	zone_opts = zone_options_find(nsd.options, zone_dname);
	if (!zone_dname || !zone_opts)
		abort();
	/* xfrd's event base (nsd_child_event_base() with mini_event): only
	 * used for the zone refresh and reload timers, never dispatched */
	xfrd_base = (struct event_base *)event_init(&ev_secs, &ev_tv);
	if (!xfrd_base)
		abort();
	return 0;
}

/* the apex SOA of the loaded zone, as xfrd learns it (SOAINFO task) */
static int
zone_soa(zone_type *zone, xfrd_soa_type *soa)
{
	rrset_type *rrset = domain_find_rrset(zone->apex, zone, TYPE_SOA);
	if (!rrset || rrset->rr_count == 0)
		return 0;
	xfrd_copy_soa(soa, rrset->rrs[0]);
	return 1;
}

static int
fuzz_one(const uint8_t *data, size_t size)
{
	uint8_t flags;
	uint16_t qid, qtype;
	size_t pos;
	zone_type *zone;
	struct xfrd_state xstate;
	xfrd_zone_type *xz;
	region_type *xregion;
	buffer_type *req, *pkt;
	int apex_compress = 0;
	enum xfrd_packet_result res = xfrd_packet_more;

	if (size < 3)
		return -1;
	flags = data[0];
	qid = (uint16_t)((data[1] << 8) | data[2]);

	/* the reload side: zone_ixfr_create() allocates in nsd.region */
	nsd.region = fuzz_region_create();
	nsd.db = namedb_open(nsd.options);
	if (!nsd.db)
		abort();
	zone = namedb_zone_create(nsd.db, zone_dname, zone_opts);
	if (zonec_read(nsd.db, nsd.db->domains, zone_opts->name, zone_path,
		zone) != 0)
		abort();
	prehash_zone_complete(nsd.db, zone);

	/* the xfrd side: a secondary zone as xfrd_init_slave_zone() sets it
	 * up, with no reload to send to (can_send_reload == 0) and a reload
	 * that just happened (so a new one waits on the reload timer) */
	xregion = fuzz_region_create();
	memset(&xstate, 0, sizeof(xstate));
	xstate.region = xregion;
	xstate.nsd = &nsd;
	xstate.event_base = xfrd_base;
	xstate.zones = rbtree_create(xregion,
		(int (*)(const void *, const void *))dname_compare);
	xstate.xfrfilenumber = 1;
	xstate.can_send_reload = 0;
	xfrd = &xstate;
	xstate.reload_timeout.tv_sec = xfrd_time() + 3600;
	xfrd_init_slave_zone(&xstate, zone_opts);
	xz = (xfrd_zone_type *)rbtree_search(xstate.zones, zone_dname);
	if (!xz)
		abort();
	xz->master_num = (flags & FLAG_KEYED) ? 1 : 0;
	xz->master = acl_find_num(zone_opts->pattern->request_xfr,
		xz->master_num);
	if (!xz->master)
		abort();
	xz->tcp_conn = (flags & FLAG_TCP) ? 0 : -1;
	if (flags & FLAG_IXFR) {
		if (!zone_soa(zone, &xz->soa_disk))
			abort();
		xz->soa_disk_acquired = xfrd_time();
		xz->soa_nsd = xz->soa_disk;
		xz->soa_nsd_acquired = xz->soa_disk_acquired;
	}
	xz->query_id = qid;

	/* the outstanding request (xfrd-tcp.c xfrd_tcp_setup_write_packet) */
	qtype = (flags & FLAG_IXFR) ? TYPE_IXFR : TYPE_AXFR;
	req = buffer_create(xregion, QIOBUFSZ);
	xfrd_setup_packet(req, qtype, CLASS_IN, xz->apex, qid,
		qtype == TYPE_IXFR ? &apex_compress : NULL);
	xfrd_prepare_zone_xfr(xz, qtype);
	if (qtype == TYPE_IXFR) {
		NSCOUNT_SET(req, 1);
		xfrd_write_soa_buffer(req, xz->apex, &xz->soa_disk,
			apex_compress);
	}
	if (xz->master->key_options && xz->master->key_options->tsig_key)
		xfrd_tsig_sign_request(req, &xz->latest_xfr->tsig, xz->master);

	/* the reply packets, until xfrd is done with the transfer */
	pkt = buffer_create(xregion, QIOBUFSZ);
	pos = 3;
	while (pos < size && res == xfrd_packet_more) {
		size_t len;
		if (pos + 2 <= size) {
			len = ((size_t)data[pos] << 8) | data[pos + 1];
			pos += 2;
			if (len > size - pos)
				len = size - pos;
		} else {
			/* a trailing byte without a full length: one packet */
			len = size - pos;
		}
		buffer_clear(pkt);
		buffer_write(pkt, data + pos, len);
		buffer_flip(pkt);
		pos += len;
		res = xfrd_handle_received_xfr_packet(xz, pkt);
	}

	/* xfrd committed the transfer to its spool file: the reload applies
	 * it (it may still return xfrd_packet_bad to look for an even newer
	 * serial; the committed file is applied regardless) */
	if (xz->latest_xfr && xz->latest_xfr->acquired != 0) {
		uint64_t fnum = xz->latest_xfr->xfrfilenumber;
		FILE *in = xfrd_open_xfrfile(&nsd, fnum, "r");
		if (!in)
			abort();
		(void)apply_ixfr_for_zone(&nsd, zone, in, nsd.options, NULL,
			fnum);
		fclose(in);
	}

	/* per-input teardown: spool file, TSIG record, timers, regions */
	while (xz->latest_xfr)
		xfrd_delete_zone_xfr(xz, xz->latest_xfr);
	if (xz->event_added)
		event_del(&xz->zone_handler);
	if (xstate.reload_added)
		event_del(&xstate.reload_handler);
	xfrd = NULL;
	region_destroy(xregion);

	if (zone->ixfr) {
		zone_ixfr_free(zone->ixfr);
		zone->ixfr = NULL;
	}
	namedb_close(nsd.db);
	nsd.db = NULL;
	region_destroy(nsd.region);
	nsd.region = NULL;
	return 0;
}
