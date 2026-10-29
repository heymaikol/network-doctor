/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Synthetic wire tests against the actual compiled libfrr, not live evidence. */
#include <zebra.h>
#include <assert.h>
#include "lib/netdoc.h"
#include "lib/stream.h"

static unsigned negatives;

static void refused(struct stream *s, const struct ndoc_submission *in)
{
	struct ndoc_submission out = {0};
	stream_reset(s);
	assert(ndoc_encode(s, in) == 0);
	assert(ndoc_decode(s, &out) == -1);
	negatives++;
}

int main(void)
{
	struct stream *s = stream_new(8192), *short_s;
	struct ndoc_submission in = {0}, out = {0};
	unsigned char bytes[8192];
	unsigned roundtrips = 0, truncations = 0, mutations = 0;
	uint32_t state = 407;
	size_t size;
	strlcpy(in.epoch, "11111111-1111-1111-1111-111111111111", sizeof(in.epoch));
	in.announcement = UINT64_MAX;
	for (unsigned i = 0; i < NDOC_LIMIT; i++)
		in.paths[i] = (struct ndoc_contributor){i + 1, i + 65, i + 129, UINT64_MAX, i};
	for (unsigned n = 1; n <= NDOC_LIMIT; n++) {
		in.count = n;
		stream_reset(s);
		memset(&out, 0, sizeof(out));
		assert(ndoc_encode(s, &in) == 0);
		assert(ndoc_decode(s, &out) == 0);
		assert(!strcmp(in.epoch, out.epoch) && in.announcement == out.announcement && in.count == out.count);
		for (unsigned i = 0; i < n; i++) {
			assert(in.paths[i].path == out.paths[i].path && in.paths[i].peer == out.paths[i].peer);
			assert(in.paths[i].session == out.paths[i].session && in.paths[i].revision == out.paths[i].revision);
			assert(in.paths[i].leg == out.paths[i].leg);
		}
		roundtrips++;
	}
	size = stream_get_endp(s);
	assert(size < sizeof(bytes));
	memcpy(bytes, s->data, size);
	for (size_t n = 0; n < size; n++) {
		short_s = stream_new(8192);
		stream_put(short_s, bytes, n);
		memset(&out, 0, sizeof(out));
		assert(ndoc_decode(short_s, &out) == -1);
		stream_free(short_s);
		truncations++;
	}
	stream_set_getp(s, 0);
	s->data[0] ^= 1;
	assert(ndoc_decode(s, &out) == -1);
	negatives++;
	/* Mutate wire counts directly so encoder guards cannot mask decoder bugs. */
	for (unsigned n = 0; n <= NDOC_LIMIT + 1; n += NDOC_LIMIT + 1) {
		size_t count_offset = sizeof(uint32_t) + sizeof(in.epoch) + sizeof(uint64_t);
		size_t contributor_size = 4 * sizeof(uint64_t) + sizeof(uint16_t);
		stream_reset(s);
		stream_put(s, bytes, size);
		s->data[count_offset] = 0;
		s->data[count_offset + 1] = n;
		/* A full extra contributor prevents truncation from masking a missing bound. */
		if (n > NDOC_LIMIT)
			stream_put(s, bytes + size - contributor_size, contributor_size);
		assert(ndoc_decode(s, &out) == -1);
		negatives++;
	}
	in.announcement = 0;
	refused(s, &in);
	in.announcement = UINT64_MAX;
	in.paths[0].path = 0;
	refused(s, &in);
	in.paths[0].path = 1;
	in.paths[0].peer = 0;
	refused(s, &in);
	in.paths[0].peer = 65;
	in.paths[0].session = 0;
	refused(s, &in);
	in.paths[0].session = 129;
	in.paths[0].revision = 0;
	refused(s, &in);
	in.paths[0].revision = UINT64_MAX;
	in.paths[NDOC_LIMIT - 1].leg = NDOC_LIMIT;
	refused(s, &in);
	in.paths[NDOC_LIMIT - 1].leg = NDOC_LIMIT - 1;
	in.epoch[35] = 0;
	refused(s, &in);
	in.epoch[35] = '1';
	in.epoch[36] = 'X';
	refused(s, &in);
	in.epoch[36] = 0;
	stream_reset(s);
	in.count = 0;
	assert(ndoc_encode(s, &in) == -1);
	negatives++;
	in.count = NDOC_LIMIT + 1;
	assert(ndoc_encode(s, &in) == -1);
	negatives++;
	for (unsigned i = 0; i < 512; i++) {
		stream_reset(s);
		stream_put(s, bytes, size);
		state = state * 1664525U + 1013904223U;
		s->data[state % size] ^= (unsigned char)((state >> 24) | 1);
		memset(&out, 0, sizeof(out));
		int result = ndoc_decode(s, &out);
		assert(result == 0 || result == -1);
		if (result == 0)
			assert(out.count > 0 && out.count <= NDOC_LIMIT);
		mutations++;
	}
	stream_free(s);
	printf("CODEC_TESTS_PASSED roundtrips=%u truncations=%u semantic_negatives=%u mutations=%u max_wire_bytes=%zu\n",
	       roundtrips, truncations, negatives, mutations, size);
	return 0;
}
