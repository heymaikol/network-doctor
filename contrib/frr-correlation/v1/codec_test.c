/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Synthetic wire tests against the actual compiled libfrr, not live evidence. */
#include <zebra.h>
#include <assert.h>
#include "lib/netdoc.h"
#include "lib/stream.h"

int main(void)
{
	struct stream *s = stream_new(8192), *short_s;
	struct ndoc_submission in = {0}, out = {0};
	size_t size;
	strlcpy(in.epoch, "11111111-1111-1111-1111-111111111111", sizeof(in.epoch));
	in.announcement = 7;
	in.count = 2;
	in.paths[0] = (struct ndoc_contributor){1, 2, 3, 4, 0};
	in.paths[1] = (struct ndoc_contributor){5, 6, 7, 8, 1};
	assert(ndoc_encode(s, &in) == 0);
	size = stream_get_endp(s);
	assert(ndoc_decode(s, &out) == 0);
	assert(!strcmp(in.epoch, out.epoch) && in.announcement == out.announcement && in.count == out.count);
	for (unsigned i = 0; i < in.count; i++) {
		assert(in.paths[i].path == out.paths[i].path && in.paths[i].peer == out.paths[i].peer);
		assert(in.paths[i].session == out.paths[i].session && in.paths[i].revision == out.paths[i].revision);
		assert(in.paths[i].leg == out.paths[i].leg);
	}
	for (size_t n = 0; n < size; n++) {
		short_s = stream_new(8192);
		stream_put(short_s, s->data, n);
		memset(&out, 0, sizeof(out));
		assert(ndoc_decode(short_s, &out) == -1);
		stream_free(short_s);
	}
	stream_set_getp(s, 0);
	s->data[0] ^= 1;
	assert(ndoc_decode(s, &out) == -1);
	stream_reset(s);
	in.count = NDOC_LIMIT + 1;
	assert(ndoc_encode(s, &in) == -1);
	in.count = 1;
	in.paths[0].path = 0;
	assert(ndoc_encode(s, &in) == 0);
	assert(ndoc_decode(s, &out) == -1);
	stream_reset(s);
	in.paths[0].path = 1;
	in.paths[0].leg = NDOC_LIMIT;
	assert(ndoc_encode(s, &in) == 0);
	assert(ndoc_decode(s, &out) == -1);
	stream_free(s);
	puts("CODEC_TESTS_PASSED");
	return 0;
}
