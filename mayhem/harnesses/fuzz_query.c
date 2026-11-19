/*
 * fuzz_query: one DNS query packet through nsd's query path, as the server's
 * UDP/TCP handlers run it (server.c): optional PROXYv2 header
 * (pp2_read_header), query_process() (packet.c, query.c, answer.c, edns.c
 * cookies/NSID, tsig.c, nsec3.c, axfr.c/ixfr.c request side) and
 * query_add_optional(); for AXFR, the follow-up packets via query_axfr().
 *
 * Input: byte 0 = transport flags, the rest = the packet as received.
 *   bit 0  TCP (else UDP)
 *   bit 1  the packet starts with a PROXYv2 header (proxy-protocol-port)
 *   bit 2  the client address is IPv6 (else IPv4)
 *   bit 3  the client is 127.0.0.1/::1 (else a 192.0.2.0/24 / 2001:db8:: address)
 *
 * Set up once (as tpkg/cutest/qtest.c qsetup() does): nsd.conf + two zones in
 * a scratch dir (an unsigned zone with CNAME chains, wildcards, DNAME,
 * delegations with glue; a DNSSEC/NSEC3 zone), parse_options_file,
 * namedb_open, namedb_check_zonefiles, TSIG key, cookie secret, NSID.
 * The loaded database, options and TSIG keys are read-only for queries; the
 * query's region and packet buffer are reset per input (query_reset), and the
 * clock is fixed so cookie checks do not depend on wall time.
 */
#include "nsd_fuzz_common.h"
#include "query.h"
#include "dname.h"
#include "packet.h"
#include "edns.h"
#include "tsig.h"
#include "axfr.h"
#include "ixfr.h"
#include "nsec3.h"
#include "util/proxy_protocol.h"

#include <netinet/in.h>
#include <arpa/inet.h>

static const char example_zone[] =
"$ORIGIN example.com.\n"
"$TTL 3600\n"
"@\tIN SOA ns1 hostmaster 2024010101 7200 3600 1209600 300\n"
"\tIN NS ns1\n"
"\tIN NS ns2.example.net.\n"
"\tIN MX 10 mail\n"
"\tIN TXT \"v=spf1 -all\"\n"
"\tIN CAA 0 issue \"ca.example.net\"\n"
"ns1\tIN A 192.0.2.53\n"
"ns1\tIN AAAA 2001:db8::53\n"
"mail\tIN A 192.0.2.25\n"
"www\tIN A 192.0.2.80\n"
"www\tIN AAAA 2001:db8::80\n"
"c1\tIN CNAME c2\n"
"c2\tIN CNAME c3\n"
"c3\tIN CNAME c4\n"
"c4\tIN CNAME www\n"
"loop1\tIN CNAME loop2\n"
"loop2\tIN CNAME loop1\n"
"ext\tIN CNAME www.example.net.\n"
"*.wild\tIN A 192.0.2.99\n"
"*.wild\tIN TXT \"wildcard\"\n"
"*.cwild\tIN CNAME www\n"
"sub.wild\tIN MX 5 mail\n"
"dn\tIN DNAME example.org.\n"
"dnin\tIN DNAME c1.example.com.\n"
"deleg\tIN NS ns.deleg\n"
"deleg\tIN NS ns.example.net.\n"
"deleg\tIN DS 12345 8 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE42D3A40F1E2A3B4C5D6E7F80\n"
"ns.deleg\tIN A 192.0.2.54\n"
"ns.deleg\tIN AAAA 2001:db8::54\n"
"a.b.c.ent\tIN A 192.0.2.1\n"
"_sip._udp\tIN SRV 10 60 5060 sip\n"
"sip\tIN A 192.0.2.60\n"
"svc\tIN SVCB 1 www alpn=h2,h3 port=8443 ipv4hint=192.0.2.80\n"
"svc\tIN HTTPS 1 . alpn=h2 ech=AEX+DQBBnwAgACCx\n"
"naptr\tIN NAPTR 100 10 \"S\" \"SIP+D2U\" \"\" _sip._udp\n"
"ptr\tIN PTR www\n"
"loc\tIN LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m\n"
"hinfo\tIN HINFO \"PC\" \"Linux\"\n"
"big\tIN TXT \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"\n"
"big\tIN TXT \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"\n"
"big\tIN TXT \"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"\n";

/* A DNSSEC zone with NSEC3 (signatures are syntactically valid filler; nsd
 * does not validate them, it only serves them). */
static const char nsec3_zone[] =
"$ORIGIN example.\n"
"$TTL 3600\n"
"@\tIN SOA ns1.example. bugs.x.w.example. 1 3600 300 3600000 3600\n"
"@\tIN RRSIG SOA 8 1 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"@\tIN NS ns1.example.\n"
"@\tIN RRSIG NS 8 1 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"@\tIN DNSKEY 257 3 8 AwEAAcHqFfhlj1N5+gfj9t6wH1aRxSkWmkeYRBdbmV/VSO5bTH9V3EKsBkMDRhNhUOg2E8UTwD3/04mW0yGm7Vf5ymM=\n"
"@\tIN RRSIG DNSKEY 8 1 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"@\tIN NSEC3PARAM 1 0 1 aabbccdd\n"
"@\tIN RRSIG NSEC3PARAM 8 1 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"ns1\tIN A 192.0.2.1\n"
"ns1\tIN RRSIG A 8 2 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"a\tIN A 192.0.2.2\n"
"a\tIN RRSIG A 8 2 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"*.w\tIN MX 1 a.example.\n"
"*.w\tIN RRSIG MX 8 2 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"sec\tIN NS ns1.sec\n"
"sec\tIN DS 12345 8 2 49FD46E6C4B45C55D4AC69CBD3CD34AC1AFE51DE42D3A40F1E2A3B4C5D6E7F80\n"
"sec\tIN RRSIG DS 8 2 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"ns1.sec\tIN A 192.0.2.3\n"
"insec\tIN NS ns1.insec\n"
"ns1.insec\tIN A 192.0.2.4\n"
"x.y.z\tIN A 192.0.2.5\n"
"x.y.z\tIN RRSIG A 8 4 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom\tIN NSEC3 1 1 1 aabbccdd 2t7b4g4vsa5smi47k61mv5bv1a22bojr NS SOA RRSIG DNSKEY NSEC3PARAM\n"
"0p9mhaveqvm6t7vbl5lop2u3t2rp3tom\tIN RRSIG NSEC3 8 2 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"2t7b4g4vsa5smi47k61mv5bv1a22bojr\tIN NSEC3 1 1 1 aabbccdd 2vptu5timamqttgl4luu9kg21e0aor3s A RRSIG\n"
"2t7b4g4vsa5smi47k61mv5bv1a22bojr\tIN RRSIG NSEC3 8 2 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"2vptu5timamqttgl4luu9kg21e0aor3s\tIN NSEC3 1 1 1 aabbccdd 35mthgpgcu1qg68fab165klnsnk3dpvl MX RRSIG\n"
"2vptu5timamqttgl4luu9kg21e0aor3s\tIN RRSIG NSEC3 8 2 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"35mthgpgcu1qg68fab165klnsnk3dpvl\tIN NSEC3 1 1 1 aabbccdd b4um86eghhds6nea196smvmlo4ors995 NS DS RRSIG\n"
"35mthgpgcu1qg68fab165klnsnk3dpvl\tIN RRSIG NSEC3 8 2 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n"
"b4um86eghhds6nea196smvmlo4ors995\tIN NSEC3 1 1 1 aabbccdd 0p9mhaveqvm6t7vbl5lop2u3t2rp3tom A RRSIG\n"
"b4um86eghhds6nea196smvmlo4ors995\tIN RRSIG NSEC3 8 2 3600 20300101000000 20200101000000 12345 example. aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8gd29ybGQ=\n";

static const char conf_fmt[] =
"server:\n"
"\tzonesdir: \"%s\"\n"
"\txfrdir: \"%s\"\n"
"\tzonelistfile: \"%s/zone.list\"\n"
"\tdatabase: \"\"\n"
"\tverbosity: 0\n"
"\tnsid: \"6e73642d66757a7a\"\n"
"\tanswer-cookie: yes\n"
"\tcookie-secret: \"000102030405060708090a0b0c0d0e0f\"\n"
"\trefuse-any: no\n"
"\tsend-buffer-size: 0\n"
"key:\n"
"\tname: \"tsig.example.\"\n"
"\talgorithm: hmac-sha256\n"
"\tsecret: \"K2tf3TRjvQkVCmJF3/Z9vA==\"\n"
"zone:\n"
"\tname: \"example.com\"\n"
"\tzonefile: \"%s/example.com.zone\"\n"
"\tprovide-xfr: 127.0.0.1 NOKEY\n"
"\tprovide-xfr: ::1 NOKEY\n"
"\tprovide-xfr: 0.0.0.0/0 tsig.example.\n"
"\tprovide-xfr: ::0/0 tsig.example.\n"
"\tallow-notify: 0.0.0.0/0 tsig.example.\n"
"\tallow-notify: 127.0.0.1 NOKEY\n"
"\tstore-ixfr: yes\n"
"zone:\n"
"\tname: \"example\"\n"
"\tzonefile: \"%s/example.zone\"\n"
"\tprovide-xfr: 127.0.0.1 NOKEY\n"
"\tprovide-xfr: 0.0.0.0/0 tsig.example.\n"
"\tallow-query: 0.0.0.0/0 NOKEY\n"
"\tallow-query: ::0/0 NOKEY\n";

/* fake compression table, as in tpkg/cutest/qtest.c (copied from server.c) */
static uint16_t *compressed_dname_offsets;
static size_t compression_table_size;
static domain_type *compressed_dnames[MAXRRSPP];
static query_type *query;
static region_type *server_region;

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char conf[4096], path[1024];
	const char *dir;
	size_t needed;
	(void)argc; (void)argv;

	fuzz_quiet_logs();
	dir = fuzz_scratch_dir();
	fuzz_write_file("example.com.zone", example_zone,
		sizeof(example_zone) - 1, path, sizeof(path));
	fuzz_write_file("example.zone", nsec3_zone, sizeof(nsec3_zone) - 1,
		path, sizeof(path));
	snprintf(conf, sizeof(conf), conf_fmt, dir, dir, dir, dir, dir);
	fuzz_write_file("nsd.conf", conf, strlen(conf), path, sizeof(path));

	memset(&nsd, 0, sizeof(nsd));
	server_region = fuzz_region_create();
	nsd.region = server_region;
#ifdef BIND8_STATS
	nsd.st = (struct nsdst *)region_alloc_zero(nsd.region,
		sizeof(struct nsdst));
#endif
	if (!tsig_init(nsd.region))
		abort();
	pp_init(&write_uint16, &write_uint32);
	nsd.options = nsd_options_create(fuzz_region_create());
	if (!parse_options_file(nsd.options, path, NULL, NULL, NULL)) {
		fprintf(stderr, "fuzz_query: cannot parse %s\n", path);
		abort();
	}
	/* nsd.c: CHAOS id.server / version.bind answers */
	nsd.identity = nsd.options->identity ? nsd.options->identity : "nsd-fuzz";
	nsd.version = nsd.options->version ? nsd.options->version : PACKAGE_STRING;
	key_options_tsig_add(nsd.options);
	reconfig_cookies(&nsd, nsd.options);
	nsd.ipv4_edns_size = nsd.options->ipv4_edns_size;
	nsd.ipv6_edns_size = nsd.options->ipv6_edns_size;
	edns_init_data(&nsd.edns_ipv4, nsd.options->ipv4_edns_size);
	edns_init_data(&nsd.edns_ipv6, nsd.options->ipv6_edns_size);
	nsd.nsid_len = strlen(nsd.options->nsid) / 2;
	nsd.nsid = xalloc(nsd.nsid_len);
	if (hex_pton(nsd.options->nsid, nsd.nsid, nsd.nsid_len) == -1)
		abort();
	edns_init_nsid(&nsd.edns_ipv4, nsd.nsid_len);
	edns_init_nsid(&nsd.edns_ipv6, nsd.nsid_len);

	nsd.db = namedb_open(nsd.options);
	if (!nsd.db)
		abort();
	namedb_check_zonefiles(&nsd, nsd.options, NULL, NULL);
	{
		/* the fixture must be served, or every input is REFUSED */
		const dname_type *z1 = dname_parse(server_region, "example.com.");
		const dname_type *z2 = dname_parse(server_region, "example.");
		zone_type *zz1 = namedb_find_zone(nsd.db, z1);
		zone_type *zz2 = namedb_find_zone(nsd.db, z2);
		if (!zz1 || !zz1->soa_rrset || !zz2 || !zz2->soa_rrset) {
			fprintf(stderr, "fuzz_query: fixture zones did not load\n");
			abort();
		}
	}

	needed = domain_table_count(nsd.db->domains) + 1 + EXTRA_DOMAIN_NUMBERS;
	compressed_dname_offsets = (uint16_t *)xalloc(needed * sizeof(uint16_t));
	memset(compressed_dname_offsets, 0, needed * sizeof(uint16_t));
	compressed_dname_offsets[0] = QHEADERSZ;
	compression_table_size = domain_table_count(nsd.db->domains) + 1;
	query = query_create(server_region, compressed_dname_offsets,
		compression_table_size, compressed_dnames);
	return 0;
}

static void
set_client(query_type *q, uint8_t flags)
{
	memset(&q->remote_addr, 0, sizeof(q->remote_addr));
	if (flags & 4) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&q->remote_addr;
		a->sin6_family = AF_INET6;
		a->sin6_port = htons(53000);
		inet_pton(AF_INET6, (flags & 8) ? "::1" : "2001:db8::7",
			&a->sin6_addr);
		q->remote_addrlen = (socklen_t)sizeof(*a);
	} else {
		struct sockaddr_in *a = (struct sockaddr_in *)&q->remote_addr;
		a->sin_family = AF_INET;
		a->sin_port = htons(53000);
		inet_pton(AF_INET, (flags & 8) ? "127.0.0.1" : "192.0.2.7",
			&a->sin_addr);
		q->remote_addrlen = (socklen_t)sizeof(*a);
	}
	memcpy(&q->client_addr, &q->remote_addr, sizeof(q->client_addr));
	q->client_addrlen = q->remote_addrlen;
}

/* server.c consume_pp2_header(), which is static: validate the header,
 * take the client address from it and strip it from the packet. */
static int
consume_pp2(query_type *q)
{
	buffer_type *buf = q->packet;
	struct pp2_header *header;
	size_t sz;
	if (pp2_read_header(buffer_begin(buf), buffer_remaining(buf)) != 0)
		return 0;
	header = (struct pp2_header *)buffer_begin(buf);
	sz = PP2_HEADER_SIZE + read_uint16(&header->len);
	if (sz > buffer_limit(buf))
		return 0;
	if ((header->ver_cmd & 0xF) == PP2_CMD_LOCAL ||
	    header->fam_prot == PP2_UNSPEC_UNSPEC)
		goto done;
	if (header->fam_prot == PP2_INET_STREAM ||
	    header->fam_prot == PP2_INET_DGRAM) {
		struct sockaddr_in *a = (struct sockaddr_in *)&q->client_addr;
		if (ntohs(header->len) < PP2_HEADER_LEN_INET)
			return 0;
		a->sin_family = AF_INET;
		memmove(&a->sin_addr.s_addr, &header->addr.addr4.src_addr, 4);
		memmove(&a->sin_port, &header->addr.addr4.src_port, 2);
		q->client_addrlen = (socklen_t)sizeof(*a);
	} else if (header->fam_prot == PP2_INET6_STREAM ||
		   header->fam_prot == PP2_INET6_DGRAM) {
		struct sockaddr_in6 *a = (struct sockaddr_in6 *)&q->client_addr;
		if (ntohs(header->len) < PP2_HEADER_LEN_INET6)
			return 0;
		memset(a, 0, sizeof(*a));
		a->sin6_family = AF_INET6;
		memmove(&a->sin6_addr, header->addr.addr6.src_addr, 16);
		memmove(&a->sin6_port, &header->addr.addr6.src_port, 2);
		q->client_addrlen = (socklen_t)sizeof(*a);
	} else {
		return 0;
	}
	q->is_proxied = 1;
done:
	/* as for a UDP packet: move the rest over the PROXYv2 header */
	memmove(header, ((char *)header) + sz, buffer_limit(buf) - sz);
	buffer_set_limit(buf, buffer_limit(buf) - sz);
	return 1;
}

static int
fuzz_one(const uint8_t *data, size_t size)
{
	uint8_t flags;
	int is_tcp;
	uint32_t now = 1700000000;
	query_state_type st;

	if (size < 1)
		return -1;
	flags = data[0];
	data++;
	size--;
	is_tcp = flags & 1;
	/* the server reads at most a full DNS message into the buffer */
	if (size > MAX_PACKET_SIZE)
		return -1;

	query_reset(query, is_tcp ? TCP_MAX_MESSAGE_LEN : UDP_MAX_MESSAGE_LEN,
		is_tcp);
	set_client(query, flags);
	buffer_write(query->packet, data, size);
	buffer_flip(query->packet);

	if (flags & 2) {
		if (!consume_pp2(query))
			return 0;
	}

	st = query_process(query, &nsd, &now);
	if (st == QUERY_DISCARDED)
		return 0;
	query_add_optional(query, &nsd, &now);
	buffer_flip(query->packet);

	/* zone transfer: produce the remaining packets, as
	 * handle_tcp_writing() does; ends when the zone has been sent */
	while (is_tcp && (st == QUERY_IN_AXFR || st == QUERY_IN_IXFR)) {
		buffer_clear(query->packet);
		if (st == QUERY_IN_AXFR)
			st = query_axfr(&nsd, query, 0);
		else
			st = query_ixfr(&nsd, query);
		if (st != QUERY_PROCESSED)
			query_add_optional(query, &nsd, &now);
		buffer_flip(query->packet);
	}
	return 0;
}
