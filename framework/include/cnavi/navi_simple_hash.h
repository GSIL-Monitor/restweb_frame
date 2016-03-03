/*
 * navi_simple_hash.h
 *
 *  Created on: 2013-9-9
 *      Author: li.lei
 */

#ifndef NAVI_SIMPLE_HASH_H_
#define NAVI_SIMPLE_HASH_H_

#include "navi_common_define.h"
#include "navi_gr_iter.h"
#include "navi_pool.h"

#define NAVI_HASH_OK 0
#define NAVI_HASH_NEW 1
#define NAVI_HASH_REPLACE 2

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct navi_hent_s {
	char* k;
	void* v;
	size_t h;
	void (*vfree)(void*);
	struct navi_hent_s *next;
	chain_node_t list_link;
}navi_hent_t;

typedef struct navi_hash_s {
	navi_hent_t** b;
	uint32_t size_stage;
	uint32_t used;
	navi_pool_t* pool;

	chain_node_t list_link;
	navi_griter_mgr_t *it_mgr;
}navi_hash_t;

navi_hash_t* navi_hash_init(navi_pool_t* pool);
navi_hash_t* navi_hash_init_with_heap(void);
void navi_hash_destroy(navi_hash_t* hash);

int navi_hash_set(navi_hash_t* hash,const char* key,const char* v);
const char* navi_hash_get(navi_hash_t* hash,const char* key);

int navi_hash_set_gr(navi_hash_t* hash,const char* key,void* v);
int navi_hash_set_gr2(navi_hash_t* hash, const char* key, void* v, void (*vfree)(void*) );
void* navi_hash_get_gr(navi_hash_t* hash,const char* key);

int navi_hash_del(navi_hash_t* hash,const char* key);

void navi_hash_reset(navi_hash_t* hash);

void* navi_hash_iter(navi_hash_t* hash);
void navi_hash_iter_destroy(void* it);
navi_hent_t* navi_hash_iter_next(void* it);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_SIMPLE_HASH_H_ */
