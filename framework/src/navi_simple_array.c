/*
 * navi_simple_array.c
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#include "navi_simple_array.h"

navi_array_t *navi_array_create(navi_pool_t* pool, uint32_t pre_alloc,
    size_t elmt_sz)
{
	navi_array_t* a = navi_pool_calloc(pool, 1, sizeof(navi_array_t));
	if (!a)
		return NULL;

	a->parts = navi_pool_calloc(pool, 4, sizeof(navi_array_part_t*));
	if (a->parts == NULL)
		return NULL;
	a->part_size = 4;

	a->pool = pool;
	a->count = 0;
	a->alloc_bunch = pre_alloc;
	a->elmt_size = elmt_sz;
	return a;
}

void *navi_array_push(navi_array_t *a)
{
	if (!a)
		return NULL;
	int i;
	for (i = 0; i < a->part_size && a->parts[i]; i++) {
		if (a->count < a->alloc_bunch * (i + 1)) {
			break;
		}
	}

	if (i == a->part_size) {
		navi_array_part_t** na = navi_pool_calloc(a->pool, (a->part_size * 2),
		    sizeof(navi_array_part_t*));
		if (!na)
			return NULL;

		memcpy(na, a->parts, a->part_size * sizeof(navi_array_part_t*));
		a->parts = na;
		a->part_size *= 2;
	}

	if (a->parts[i] == NULL) {
		a->parts[i] = navi_pool_calloc(a->pool, 1,
		    sizeof(navi_array_part_t) + a->alloc_bunch * a->elmt_size);
		if (!a->parts[i])
			return NULL;
	}

	a->count++;
	return (void*) ((char*) a->parts[i]->allocs
	    + (a->elmt_size * a->parts[i]->used++));
}

void *navi_array_item(navi_array_t* a, int idx)
{
	if (!a)
		return 0;

	if (idx < 0 && idx >= -(a->count)) {
		idx = a->count + idx;
	}

	if (idx >= 0 && idx < a->count) {
		return (void*) ((char*) a->parts[idx / a->alloc_bunch]->allocs
		    + idx % a->alloc_bunch * a->elmt_size);
	}
	else
		return NULL;
}

void* navi_array_iter(navi_array_t* a)
{
	if (a->its==NULL) {
		a->its = navi_pool_calloc(a->pool,1,sizeof(navi_griter_mgr_t));
		navi_griter_mgr_init(a->its, a->pool);
	}
	navi_griter_t* it = navi_griter_get(a->its);
	it->ctx = (void*)a;
	it->i = 0;
	it->j = 0;
	return it;
}

void* navi_array_iter_next(void* it)
{
	navi_griter_t* iter = (navi_griter_t*)it;
	navi_array_t* a = (navi_array_t*)iter->ctx;
	navi_array_part_t* part = a->parts[iter->i];
	void* ret = NULL;

	if (part) {
		if (iter->j < part->used) {
			ret =  (void*)((char*) part->allocs + iter->j++ * a->elmt_size);
		}

		if (iter->j == a->alloc_bunch) {
			if (iter->i < a->part_size) {
				iter->j = 0;
				iter->i++;
			}
		}

		return ret;
	}
	return NULL;
}

void navi_array_iter_destroy(void* it)
{
	navi_griter_recycle(it);
}

