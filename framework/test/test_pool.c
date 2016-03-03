/*
 * test_pool.c
 *
 *  Created on: 2013-9-18
 *      Author: li.lei
 */


#include "navi_pool.h"
#include <stdlib.h>
#include <assert.h>

static void test_create() {
	navi_pool_t *pool = navi_pool_create(0x1000);

	assert(pool == pool->d.alloc);
	assert((u_char*)pool+0x1000 == pool->d.end);
	assert(pool->current == pool);
	assert(pool->large == NULL);
	assert(pool->last_req_pool == NULL);
	assert(pool->d.last == pool->d.alloc + sizeof(navi_pool_t));
	assert(pool->d.next==NULL);
	assert(pool->d.failed==0);

	navi_pool_destroy(pool);
}

struct test_st {
	void* a;
	int b;
	char c;
};

static void test_alloc() {
	navi_pool_t *pool = navi_pool_create(0x800);

	assert( pool->d.last == (char*)pool + sizeof(navi_pool_t));

	printf("last:%p\n",pool->d.last);

	void * obj = navi_pool_alloc(pool,sizeof(struct test_st));

	printf("obj:%p last:%p\n",obj,pool->d.last);

	assert( (u_char*)obj + sizeof(struct test_st) == pool->d.last );

	obj = navi_pool_alloc(pool,sizeof(struct test_st));

	assert( (u_char*)obj + sizeof(struct test_st) == pool->d.last );

	printf("obj:%p last:%p\n",obj,pool->d.last);

	obj = navi_pool_nalloc(pool,3);
	printf("obj:%p last:%p\n",obj,pool->d.last);

	obj = navi_pool_alloc(pool,sizeof(struct test_st));
	assert((unsigned long)obj % 8 == 0);
	printf("obj:%p last:%p\n",obj,pool->d.last);

	obj = navi_pool_alloc(pool,0x800); //large alloc
	assert(obj==pool->large->alloc);

	navi_pool_reset(pool);

	int i=0;
	void* prev=NULL,*cur=NULL;
	while(i<2000) {
		if (prev) {
			printf("%d ",(uint8_t*)cur - (uint8_t*)prev);
		}
		if (cur)
			prev = cur;
		cur = navi_pool_alloc(pool,sizeof(unsigned long));
		i++;
	}

	int** a = navi_pool_calloc(pool, 10000, sizeof(int*));


	navi_pool_destroy(pool);
}


int main() {
	test_create();
	test_alloc();
}
