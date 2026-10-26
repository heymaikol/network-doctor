/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Concurrent logger stress test; these events are not live FRR evidence. */
#include <zebra.h>
#include <assert.h>
#include <pthread.h>
#include "lib/netdoc.h"

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
int main(void)
{
	pthread_t writers[4];
	ndoc_init("zebra");
	assert(ndoc_enabled());
	for (unsigned i = 0; i < 4; i++) assert(!pthread_create(&writers[i], NULL, write_records, NULL));
	for (unsigned i = 0; i < 4; i++) assert(!pthread_join(writers[i], NULL));
	ndoc_finish();
	puts("WRITER_TEST_PASSED");
	return 0;
}
