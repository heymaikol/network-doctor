/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef FRR_NETDOC_H
#define FRR_NETDOC_H
#include "lib/json.h"
#include "lib/prefix.h"

#define NDOC_LIMIT 64
#define ZAPI_MESSAGE_NETDOC 0x0800
struct stream;
struct ndoc_contributor {
	uint64_t path, peer, session, revision;
	uint16_t leg;
};
struct ndoc_submission {
	char epoch[37];
	uint64_t announcement;
	uint16_t count;
	struct ndoc_contributor paths[NDOC_LIMIT];
};
extern void ndoc_init(const char *daemon);
extern void ndoc_finish(void);
extern bool ndoc_enabled(void);
extern uint64_t ndoc_next(void);
extern const char *ndoc_epoch(void);
extern json_object *ndoc_record(const char *event);
extern void ndoc_emit(json_object *record);
extern void ndoc_num(json_object *j, const char *key, uint64_t value);
extern void ndoc_ref(json_object *j, const char *key, const char *epoch,
		     const char *kind, uint64_t id);
extern void ndoc_prefix(json_object *j, const char *key, const struct prefix *p);
extern void ndoc_paths(json_object *j, const struct ndoc_submission *s);
extern int ndoc_encode(struct stream *s, const struct ndoc_submission *sub);
extern int ndoc_decode(struct stream *s, struct ndoc_submission *sub);
#endif
