/*
 * test_hash.c
 *
 *  Created on: 2013-9-18
 *      Author: li.lei
 */


#include "navi_simple_hash.h"
#include <assert.h>


static void test_create() {
	navi_pool_t* pool = navi_pool_create(0x1000);
	navi_hash_t* hs = navi_hash_init(pool);
	navi_pool_destroy(pool);
}

static void test_hash() {
	navi_pool_t* pool = navi_pool_create(0x1000);
	navi_hash_t* hs = navi_hash_init(pool);

	char buf[256];
	int i;
	for(i=0; i<1024; i++) {
		sprintf(buf,"%d",i);
		assert (NAVI_HASH_NEW == navi_hash_set_gr(hs,buf,(void*)i) );
	}

	for(i=0; i<1024; i++) {
		sprintf(buf,"%d",i);
		int ret = (int)navi_hash_get_gr(hs,buf);
		assert(ret==i);
	}

	for(i=0; i<1024; i++) {
		sprintf(buf,"%d",i);
		assert (NAVI_HASH_REPLACE == navi_hash_set_gr(hs,buf,(void*)i) );
	}

	navi_hash_reset(hs);

	for(i=0; i<1024; i++) {
		sprintf(buf,"%d",i);
		assert (NAVI_HASH_NEW == navi_hash_set_gr(hs,buf,(void*)i) );
	}

	navi_pool_destroy(pool);
}

static void test_del() {
	navi_pool_t* pool = navi_pool_create(0x1000);
	navi_hash_t* hs = navi_hash_init(pool);

	char buf[256];
	int i;
	for(i=0; i<512; i++) {
		sprintf(buf,"%d",i);
		navi_hash_set_gr(hs,buf,(void*)i);
	}

	navi_hash_del(hs,"234");
	navi_hash_del(hs,"456");

	for ( ; i<4096; i++) {
		sprintf(buf,"%d",i);
		navi_hash_set_gr(hs,buf,(void*)i);
	}

	for(i=0; i<4096; i++) {
		sprintf(buf,"%d",i);
		int ret = (int)navi_hash_get_gr(hs,buf);
		if (i==234)
			assert(ret==0);
		else if (i==456)
			assert(ret==0);
		else
			assert(ret==i);
	}

	navi_pool_destroy(pool);
}

int main() {
	test_create();
	test_hash();
	test_del();
}
