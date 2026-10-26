/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <zebra.h>
#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <pthread.h>
#include <stdatomic.h>
#include "lib/netdoc.h"
#include "lib/netdoc_build.h"
#include "lib/stream.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint64_t ids;
static uint64_t sequence, written;
static _Atomic int output = -1;
static _Atomic bool failed;
static char epoch[37], daemon_name[32];

bool ndoc_enabled(void) { return output >= 0; }
uint64_t ndoc_next(void) { return atomic_fetch_add(&ids, 1) + 1; }
const char *ndoc_epoch(void) { return epoch; }
void ndoc_num(json_object *j, const char *k, uint64_t n)
{
	json_object_object_add(j, k, json_object_new_uint64(n));
}
void ndoc_ref(json_object *j, const char *k, const char *e, const char *kind, uint64_t id)
{
	char b[96];
	snprintf(b, sizeof(b), "%s/%s/%" PRIu64, e, kind, id);
	json_object_string_add(j, k, b);
}
void ndoc_prefix(json_object *j, const char *k, const struct prefix *p)
{
	char b[PREFIX_STRLEN];
	prefix2str(p, b, sizeof(b));
	json_object_string_add(j, k, b);
}
json_object *ndoc_record(const char *event)
{
	json_object *j = json_object_new_object();
	json_object_string_add(j, "event", event);
	return j;
}
void ndoc_emit(json_object *j)
{
	struct timespec mono, utc;
	const char *text;
	char *line;
	size_t len;
	pthread_mutex_lock(&lock);
	if (output < 0 || failed)
		goto done;
	if (sequence >= 1000000 || clock_gettime(CLOCK_MONOTONIC, &mono) ||
	    clock_gettime(CLOCK_REALTIME, &utc)) {
		failed = true;
		goto done;
	}
	ndoc_num(j, "seq", ++sequence);
	ndoc_num(j, "monotonic_ns", (uint64_t)mono.tv_sec * 1000000000 + mono.tv_nsec);
	ndoc_num(j, "utc_ns", (uint64_t)utc.tv_sec * 1000000000 + utc.tv_nsec);
	json_object_string_add(j, "epoch", epoch);
	json_object_string_add(j, "daemon", daemon_name);
	text = json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
	len = strlen(text);
	if (len > 65535 || written + len + 1 > 67108864) {
		failed = true;
		goto done;
	}
	line = malloc(len + 1);
	if (!line) { failed = true; goto done; }
	memcpy(line, text, len);
	line[len] = '\n';
	if (write(output, line, len + 1) != (ssize_t)(len + 1))
		failed = true;
	written += len + 1;
	free(line);
done:
	pthread_mutex_unlock(&lock);
	json_object_put(j);
}
void ndoc_init(const char *daemon)
{
	const char *dir = getenv("NETDOC_CORRELATION_DIR");
	char path[PATH_MAX];
	unsigned char r[16];
	struct stat st;
	struct utsname host;
	char boot[38] = {0};
	int bootfd;
	json_object *j;
	if (!dir || !*dir || (strcmp(daemon, "bgpd") && strcmp(daemon, "zebra")))
		return;
	if (getrandom(r, sizeof(r), 0) != sizeof(r))
		return;
	snprintf(epoch, sizeof(epoch),
		 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		 r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7],
		 r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
	strlcpy(daemon_name, daemon, sizeof(daemon_name));
	if (snprintf(path, sizeof(path), "%s/%s.%s.jsonl", dir, daemon, epoch) >= (int)sizeof(path))
		return;
	output = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (output < 0) return;
	j = ndoc_record("start");
	json_object_string_add(j, "schema", "netdoc-frr-correlation/v1");
	json_object_string_add(j, "build_id", NETDOC_BUILD_ID);
	json_object_string_add(j, "frr_source", "87fe21fda92ce9e2ba3eaf2b0a327bf71ee183ef");
	json_object_string_add(j, "os", "linux");
	if (uname(&host)) failed = true;
	else {
		json_object_string_add(j, "machine", host.machine);
		json_object_string_add(j, "kernel", host.release);
	}
	bootfd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
	if (bootfd < 0 || read(bootfd, boot, 37) != 37) failed = true;
	if (bootfd >= 0) close(bootfd);
	boot[36] = 0;
	json_object_string_add(j, "boot_id", boot);
	if (stat("/proc/self/ns/net", &st)) failed = true;
	else ndoc_num(j, "netns_inode", st.st_ino);
	ndoc_emit(j);
}
void ndoc_finish(void)
{
	json_object *j;
	off_t before;
	if (output < 0) return;
	before = lseek(output, 0, SEEK_CUR);
	if (fsync(output)) failed = true;
	j = ndoc_record("end");
	json_object_boolean_add(j, "complete", !failed);
	ndoc_emit(j);
	if (fsync(output)) failed = true;
	/* A failed flush must not leave a seemingly complete trailer. */
	if (failed && before >= 0) ftruncate(output, before);
	close(output);
	output = -1;
}
void ndoc_paths(json_object *j, const struct ndoc_submission *s)
{
	json_object *a = json_object_new_array();
	if (s->count) ndoc_ref(j, "announcement_id", s->epoch, "announcement", s->announcement);
	for (unsigned i = 0; i < s->count; i++) {
		const struct ndoc_contributor *c = &s->paths[i];
		json_object *p = json_object_new_object();
		ndoc_ref(p, "path_id", s->epoch, "path", c->path);
		ndoc_ref(p, "peer_id", s->epoch, "peer", c->peer);
		ndoc_ref(p, "session_id", s->epoch, "session", c->session);
		ndoc_num(p, "revision", c->revision);
		ndoc_num(p, "leg", c->leg);
		json_object_array_add(a, p);
	}
	json_object_object_add(j, "contributors", a);
}
int ndoc_encode(struct stream *s, const struct ndoc_submission *sub)
{
	if (!sub->count || sub->count > NDOC_LIMIT) return -1;
	stream_putl(s, 0x4e444301);
	stream_put(s, sub->epoch, 37);
	stream_putq(s, sub->announcement);
	stream_putw(s, sub->count);
	for (unsigned i = 0; i < sub->count; i++) {
		const struct ndoc_contributor *c = &sub->paths[i];
		stream_putq(s, c->path); stream_putq(s, c->peer);
		stream_putq(s, c->session); stream_putq(s, c->revision);
		stream_putw(s, c->leg);
	}
	return 0;
}
int ndoc_decode(struct stream *s, struct ndoc_submission *sub)
{
	uint32_t magic;
	STREAM_GETL(s, magic);
	if (magic != 0x4e444301) return -1;
	STREAM_GET(sub->epoch, s, 37);
	if (sub->epoch[36] || strlen(sub->epoch) != 36) return -1;
	STREAM_GETQ(s, sub->announcement);
	STREAM_GETW(s, sub->count);
	if (!sub->announcement || !sub->count || sub->count > NDOC_LIMIT) return -1;
	for (unsigned i = 0; i < sub->count; i++) {
		struct ndoc_contributor *c = &sub->paths[i];
		STREAM_GETQ(s, c->path); STREAM_GETQ(s, c->peer);
		STREAM_GETQ(s, c->session); STREAM_GETQ(s, c->revision);
		STREAM_GETW(s, c->leg);
		if (!c->path || !c->peer || !c->session || !c->revision || c->leg >= NDOC_LIMIT)
			return -1;
	}
	return 0;
stream_failure:
	return -1;
}
