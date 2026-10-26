/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Synthetic IO faults exercise the real writer, never live FRR evidence. */
#include <zebra.h>
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <stdatomic.h>
#include "lib/netdoc.h"

static const char *mode;
static unsigned writes, flushes, closes, truncates;
static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static bool entered, release_write;
static _Atomic unsigned shutdown_calls;

static ssize_t test_write(int fd, const void *buf, size_t len)
{
	writes++;
	if (writes == 1 && !strcmp(mode, "startup")) {
		pthread_mutex_lock(&gate);
		entered = true;
		pthread_cond_broadcast(&changed);
		while (!release_write) pthread_cond_wait(&changed, &gate);
		pthread_mutex_unlock(&gate);
	}
	if (writes == 3 && !strcmp(mode, "trailer_write")) { errno = EIO; return -1; }
	if (writes == 2) {
		if (!strcmp(mode, "concurrent")) {
			pthread_mutex_lock(&gate);
			entered = true;
			pthread_cond_broadcast(&changed);
			while (!release_write) pthread_cond_wait(&changed, &gate);
			pthread_mutex_unlock(&gate);
		}
		if (!strcmp(mode, "write_error")) { errno = EIO; return -1; }
		if (!strcmp(mode, "write_eintr")) { errno = EINTR; return -1; }
		if (!strcmp(mode, "write_zero")) return 0;
		if (!strcmp(mode, "write_short")) return write(fd, buf, len / 2);
	}
	return write(fd, buf, len);
}
static int test_fsync(int fd)
{
	flushes++;
	if ((!strcmp(mode, "flush_before") && flushes == 1) ||
	    (!strcmp(mode, "flush_after") && flushes == 2)) {
		errno = EIO; return -1;
	}
	return fsync(fd);
}
static int test_close(int fd)
{
	int result = close(fd);
	closes++;
	if (!strcmp(mode, "close") || !strcmp(mode, "close_eintr")) {
		errno = !strcmp(mode, "close") ? EIO : EINTR; return -1;
	}
	return result;
}
static int test_ftruncate(int fd, off_t length)
{
	(void)fd; (void)length;
	truncates++;
	errno = EIO;
	return -1;
}
static int test_renameat(int olddir, const char *old, int newdir, const char *next)
{
	if (!strcmp(mode, "publish")) { errno = ENOSPC; return -1; }
	return renameat(olddir, old, newdir, next);
}
#define write test_write
#define fsync test_fsync
#define close test_close
#define ftruncate test_ftruncate
#define renameat test_renameat
#include "netdoc.c"
#undef write
#undef fsync
#undef close
#undef ftruncate
#undef renameat

static void *write_records(void *unused)
{
	(void)unused;
	for (unsigned i = 0; i < 1000; i++) {
		json_object *j = ndoc_record("writer_test");
		ndoc_num(j, "id", ndoc_next());
		ndoc_emit(j);
	}
	return NULL;
}
static void *finish(void *unused)
{
	(void)unused;
	atomic_fetch_add(&shutdown_calls, 1);
	ndoc_finish();
	return NULL;
}
static void *initialize(void *unused)
{
	(void)unused;
	ndoc_init("zebra");
	return NULL;
}
static void test_startup(void)
{
	pthread_t initializer, writer, finisher;
	assert(!pthread_create(&initializer, NULL, initialize, NULL));
	pthread_mutex_lock(&gate);
	while (!entered) pthread_cond_wait(&changed, &gate);
	assert(!ndoc_enabled()); /* The start record is still being written. */
	assert(!pthread_create(&writer, NULL, write_records, NULL));
	assert(!pthread_create(&finisher, NULL, finish, NULL));
	while (!atomic_load(&shutdown_calls)) sched_yield();
	release_write = true;
	pthread_cond_broadcast(&changed);
	pthread_mutex_unlock(&gate);
	assert(!pthread_join(initializer, NULL));
	assert(!pthread_join(writer, NULL));
	assert(!pthread_join(finisher, NULL));
	ndoc_finish();
	unsigned before = writes;
	ndoc_emit(ndoc_record("late"));
	assert(failed && !published && output == -1 && closes == 2 && writes == before);
}
int main(int argc, char **argv)
{
	pthread_t writers[4], finishers[2];
	assert(argc == 2);
	mode = argv[1];
	if (!strcmp(mode, "startup")) { test_startup(); puts("WRITER_TEST_PASSED"); return 0; }
	ndoc_init("zebra");
	assert(ndoc_enabled());
	unsigned before = closes;
	if (!strcmp(mode, "concurrent") || !strcmp(mode, "joined")) {
		for (unsigned i = 0; i < 4; i++) assert(!pthread_create(&writers[i], NULL, write_records, NULL));
		if (!strcmp(mode, "concurrent")) {
			pthread_mutex_lock(&gate);
			while (!entered) pthread_cond_wait(&changed, &gate);
			for (unsigned i = 0; i < 2; i++) assert(!pthread_create(&finishers[i], NULL, finish, NULL));
			while (atomic_load(&shutdown_calls) != 2) sched_yield();
			assert(closes == before); /* The blocked writer still owns the fd. */
			release_write = true;
			pthread_cond_broadcast(&changed);
			pthread_mutex_unlock(&gate);
			for (unsigned i = 0; i < 2; i++) assert(!pthread_join(finishers[i], NULL));
		}
		for (unsigned i = 0; i < 4; i++) assert(!pthread_join(writers[i], NULL));
	} else if (!strcmp(mode, "oversize")) {
		char large[65536];
		memset(large, 'x', sizeof(large) - 1);
		large[sizeof(large) - 1] = 0;
		json_object *j = ndoc_record("writer_test");
		json_object_string_add(j, "large", large);
		ndoc_emit(j);
	} else ndoc_emit(ndoc_record("writer_test"));
	ndoc_finish();
	assert(output == -1 && closes == before + 1);
	int reused = open("/dev/null", O_WRONLY | O_CLOEXEC);
	assert(reused >= 0);
	unsigned written_before = writes;
	ndoc_finish();
	assert(closes == before + 1 && writes == written_before);
	if (!strcmp(mode, "late") || !strcmp(mode, "concurrent")) {
		ndoc_emit(ndoc_record("late"));
		assert(failed && !published && writes == written_before);
		ndoc_finish();
	}
	/* Truncation failure is immaterial: no rollback-by-truncate remains. */
	assert(!truncates);
	assert(fcntl(reused, F_GETFD) >= 0);
	assert(!close(reused));
	puts("WRITER_TEST_PASSED");
	return 0;
}
