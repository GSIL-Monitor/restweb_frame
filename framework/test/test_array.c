/*
 * test_array.c
 *
 *  Created on: 2014-1-9
 *      Author: li.lei
 */



#include "navi_simple_array.h"
#include <assert.h>

static void test_create() {
	navi_pool_t* pool = navi_pool_create(0x1000);
	navi_array_t* hs = navi_array_create(pool, 1, sizeof(int));
	navi_array_create(pool, 1000, sizeof(int));
	navi_array_create(pool, 10000, sizeof(int));
	navi_array_create(pool, 12, sizeof(char*));
	navi_pool_destroy(pool);
}

static void test_array() {
	navi_pool_t* pool = navi_pool_create(0x1000);
	navi_array_t* hs = navi_array_create(pool, 10, sizeof(int));

	assert( 0 == navi_array_size(hs));

	int *pi = navi_array_push(hs);
	assert( pi == navi_array_item(hs, 0));

	*pi = 0;

	int i = 1;
	for ( ; i<10000; i++) {
		pi = navi_array_push(hs);
		*pi = i;
		assert( pi == navi_array_item(hs, i));
	}
	for (i=0 ; i<10000; i++) {
		 pi = navi_array_item(hs, i);
		 assert ( i == *pi);
	}

	i = 0;
	int j, k=0;
	navi_array_part_t* part;
	for ( ; i<hs->part_size; i++) {
		part = hs->parts[i];
		if (part == NULL)
			break;
		pi = part->allocs;
		for ( j = 0; j < part->used; j++, pi++) {
			assert ( k++ == *pi );
		}
	}
	navi_pool_destroy(pool);
}
int main() {
	test_create();
	test_array();
}
