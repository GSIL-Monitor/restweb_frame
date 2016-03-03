/*
 * navi_simple_array.h
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#ifndef NAVI_SIMPLE_ARRAY_H_
#define NAVI_SIMPLE_ARRAY_H_
#include "navi_gr_iter.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct navi_array_s navi_array_t;

typedef struct navi_array_part_s {
	size_t used;
	char allocs[0];
}navi_array_part_t;

struct navi_array_s
{
	navi_array_part_t** parts;
	size_t count; //元素个数
	size_t part_size;
	size_t elmt_size; //元素大小
	size_t alloc_bunch; //一次分配数目
	navi_pool_t *pool; //所属pool
	navi_griter_mgr_t* its;
};

navi_array_t *navi_array_create(navi_pool_t* pool, uint32_t pre_alloc,
    size_t elmt_sz);
static inline size_t navi_array_size(navi_array_t* a)
{
	if (!a)
		return 0;
	return a->count;
}
void *navi_array_push(navi_array_t *a);
void *navi_array_item(navi_array_t* a, int idx);

void* navi_array_iter(navi_array_t* a);
void* navi_array_iter_next(void* it);
void navi_array_iter_destroy(void* it);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_SIMPLE_ARRAY_H_ */
