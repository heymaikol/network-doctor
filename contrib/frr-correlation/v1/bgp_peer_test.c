/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Test the actual hook with pinned FRR objects; these are not live captures. */
#include <zebra.h>
#include <assert.h>
#include "lib/netdoc.h"
#include "lib/zclient.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_aspath.h"

static json_object *records[4];
static unsigned record_count;

static void capture(json_object *record)
{
	assert(record_count < array_size(records));
	records[record_count++] = record;
}

#define ndoc_emit capture
#include "bgp.inc"
#undef ndoc_emit

static const char *text(json_object *record, const char *key)
{
	json_object *value;
	assert(json_object_object_get_ex(record, key, &value));
	return json_object_get_string(value);
}

static uint64_t number(json_object *record, const char *key)
{
	json_object *value;
	assert(json_object_object_get_ex(record, key, &value));
	return json_object_get_uint64(value);
}

static void check_identity(json_object *record, const char *key, const char *kind,
			   uint64_t id)
{
	char expected[96];
	snprintf(expected, sizeof(expected), "%s/%s/%" PRIu64, ndoc_epoch(), kind, id);
	assert(!strcmp(text(record, key), expected));
}

static void run(const char *name, sa_family_t first, sa_family_t second)
{
	struct bgp bgp = {0};
	struct peer_connection connections[2] = {0};
	struct peer peers[2] = {0};
	struct bgp_path_info paths[2] = {0};
	struct attr attributes[2] = {0};
	struct aspath aspath = {.str = "65001"};
	struct zapi_route api = {0};
	sa_family_t families[] = {first, second};
	unsigned count = second == AF_UNSPEC ? 1 : 2, accepted = 0;
	bool refused = false;

	printf("BGP_PEER_TEST case=%s\n", name);
	fflush(stdout);
	assert(str2prefix("198.51.100.0/24", &api.prefix));
	api.safi = SAFI_UNICAST;
	api.tableid = 254;
	api.nexthop_num = count;
	for (unsigned i = 0; i < count; i++) {
		struct peer *peer = &peers[i];
		struct bgp_path_info *path = &paths[i];
		peer->bgp = &bgp;
		peer->connection = &connections[i];
		peer->sort = BGP_PEER_EBGP;
		peer->ndoc_id = 10 + i;
		peer->ndoc_session = 20 + i;
		peer->as = 65001;
		peer->local_as = 65000;
		peer->connection->su.sa.sa_family = families[i];
		if (families[i] == AF_INET)
			assert(inet_pton(AF_INET, "192.0.2.2", &peer->connection->su.sin.sin_addr) == 1);
		else if (families[i] == AF_INET6)
			assert(inet_pton(AF_INET6, "2001:db8::2", &peer->connection->su.sin6.sin6_addr) == 1);
		attributes[i].aspath = &aspath;
		path->peer = peer;
		path->attr = &attributes[i];
		path->flags = BGP_PATH_VALID | BGP_PATH_SELECTED;
		path->ndoc_id = 30 + i;
		path->ndoc_revision = 7;
		api.nexthops[i].type = NEXTHOP_TYPE_IPV4;
		assert(inet_pton(AF_INET, "192.0.2.1", &api.nexthops[i].gate.ipv4) == 1);
		ndoc_bgp_path(path, &api, i);
		if (families[i] == AF_INET) {
			const struct ndoc_contributor *contributor = &api.ndoc.paths[accepted];
			json_object *record = records[accepted];
			assert(api.ndoc.count == accepted + 1);
			assert(path->ndoc_revision == 8);
			assert(contributor->path == path->ndoc_id && contributor->peer == peer->ndoc_id);
			assert(contributor->session == peer->ndoc_session && contributor->revision == 8);
			assert(contributor->leg == i);
			assert(!strcmp(text(record, "event"), "bgp_path"));
			assert(!strcmp(text(record, "peer_address"), "192.0.2.2"));
			assert(!strcmp(text(record, "nexthop"), "192.0.2.1"));
			check_identity(record, "path_id", "path", path->ndoc_id);
			check_identity(record, "peer_id", "peer", peer->ndoc_id);
			check_identity(record, "session_id", "session", peer->ndoc_session);
			assert(number(record, "revision") == 8);
			accepted++;
		} else {
			refused = true;
			assert(api.ndoc_bad && api.ndoc.count == accepted);
			assert(path->ndoc_revision == 7 && record_count == accepted);
		}
		assert(path->ndoc_id == 30 + i && peer->ndoc_id == 10 + i);
		assert(peer->ndoc_session == 20 + i);
	}
	ndoc_bgp_submit(&api);
	assert(record_count == accepted + 1);
	if (refused) {
		assert(!CHECK_FLAG(api.message, ZAPI_MESSAGE_NETDOC) && api.ndoc.count == 0);
		assert(api.ndoc.announcement == 0);
		assert(!strcmp(text(records[accepted], "event"), "refusal"));
	} else {
		assert(CHECK_FLAG(api.message, ZAPI_MESSAGE_NETDOC));
		assert(api.ndoc.count == count && api.ndoc.announcement);
		assert(!strcmp(text(records[accepted], "event"), "bgp_submission"));
	}
	for (unsigned i = 0; i < record_count; i++)
		json_object_put(records[i]);
	record_count = 0;
}

int main(void)
{
	char scratch[] = "/tmp/netdoc-bgp-peer.XXXXXX", output[192];
	assert(mkdtemp(scratch));
	assert(setenv("NETDOC_CORRELATION_DIR", scratch, 1) == 0);
	ndoc_init("bgpd");
	assert(ndoc_enabled());
	run("ipv4", AF_INET, AF_UNSPEC);
	run("ipv6", AF_INET6, AF_UNSPEC);
	run("unspecified", AF_UNSPEC, AF_UNSPEC);
	run("unix", AF_UNIX, AF_UNSPEC);
	run("ipv4-then-ipv6", AF_INET, AF_INET6);
	run("ipv6-then-ipv4", AF_INET6, AF_INET);
	ndoc_finish();
	snprintf(output, sizeof(output), "%s/bgpd.%s.jsonl", scratch, ndoc_epoch());
	assert(unlink(output) == 0 && rmdir(scratch) == 0);
	puts("BGP_PEER_TESTS_PASSED cases=6");
	return 0;
}
