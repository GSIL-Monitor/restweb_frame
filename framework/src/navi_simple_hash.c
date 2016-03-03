/*
 * navi_simple_hash.c
 *
 *  Created on: 2013-9-9
 *      Author: li.lei
 */


#include "navi_pool.h"
#include "navi_simple_hash.h"
#include "navi_list.h"

static size_t hash_str(const void *ptr)
{
    const char *str = (const char *)ptr;

    size_t hash = 5381;
    size_t c;

    while((c = (size_t)*str))
    {
        hash = ((hash << 5) + hash) + c;
        str++;
    }

    return hash;
}


static size_t primes[] = {
    7, 13, 23, 53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593,
    49157, 98317, 196613/* 393241, 786433, 1572869, 3145739, 6291469,
    12582917, 25165843, 50331653, 100663319, 201326611, 402653189,
    805306457, 1610612741*/
};

static void navi_rehash(navi_hash_t* src)
{
	size_t bsz=0;
	if (sizeof(primes)/sizeof(size_t) > src->size_stage+1) {
		bsz = primes[src->size_stage+1];
	}
	else
		return;

	navi_hent_t** nb;
	if (src->pool){
		nb = navi_pool_calloc(src->pool,bsz, sizeof(navi_hent_t*));
	}
	else{
		nb = calloc(bsz, sizeof(navi_hent_t*));
	}
	if (!nb)
		return;

	src->size_stage += 1;

	chain_node_t *link = src->list_link.next;
	navi_hent_t* e;
	navi_hent_t** pe;
	size_t buck_sz = primes[src->size_stage];
	size_t b_idx;

	while(link != &src->list_link) {
		e = (navi_hent_t*)((char*)link - offsetof(navi_hent_t,list_link));

		e->next = NULL;
		b_idx = e->h % buck_sz;
		pe = nb + b_idx;

		while(*pe) {
			pe = &(*pe)->next;
		}

		*pe = e;
		link = link->next;
	}

	if ( src->pool == NULL) {
		free(src->b);
	}
	src->b = nb;
	return;
}

navi_hash_t* navi_hash_init(navi_pool_t* pool)
{
	if (!pool)
		return NULL;

	navi_hash_t* ret = navi_pool_calloc(pool,1, sizeof(navi_hash_t));
	if (!ret)
		return NULL;

	ret->pool = pool;

	size_t buck_sz = primes[ret->size_stage];
	ret->b = (navi_hent_t**)navi_pool_calloc(pool,buck_sz, sizeof(navi_hent_t*));

	if ( ! ret->b )
		return NULL;

	navi_list_init(&ret->list_link);
	return ret;
}

navi_hash_t* navi_hash_init_with_heap(void)
{
	navi_hash_t* ret = calloc(1, sizeof(navi_hash_t));
	if (!ret)
		return NULL;

	size_t buck_sz = primes[ret->size_stage];
	ret->b = (navi_hent_t**)calloc(buck_sz, sizeof(navi_hent_t*));

	if ( ! ret->b )
		return NULL;

	navi_list_init(&ret->list_link);
	return ret;
}

void navi_hash_reset(navi_hash_t* hash)
{
	size_t buck_sz = primes[hash->size_stage];
	memset(hash->b, 0x00, sizeof(navi_hent_t*)*buck_sz);

	chain_node_t *link = hash->list_link.next;
	navi_hent_t* e;
	while(link != &hash->list_link) {
		e = (navi_hent_t*)((char*)link - offsetof(navi_hent_t,list_link));
		link = link->next;
		if (e->vfree)
			e->vfree(e->v);
		if (hash->pool == NULL) {
			free(e->k);
			free(e);
		}
	}

	navi_list_init(&hash->list_link);

	if ( hash->it_mgr ) {
		navi_griter_t* it;
		chain_node_t* link = hash->it_mgr->using_iter.next;
		while(link != &hash->it_mgr->using_iter) {
			it = navi_list_data(link, navi_griter_t, link);
			link = link->next;
			it->cur = hash->list_link.next;
		}
	}
}

static int navi_hash_set_impl(navi_hash_t* hash, const char* key, void* v, void (*vfree)(void*))
{
	if (!hash || !key || strlen(key)==0 )
			return NAVI_ARG_ERR;

	size_t h = hash_str(key);
	size_t buck_sz = primes[hash->size_stage];
	size_t idx = h % buck_sz;

	char* kcp=NULL;

	navi_hent_t** pe = hash->b + idx;
	navi_hent_t* e;
	while(*pe) {
		e = *pe;
		if (e->h == h && strcmp(e->k,key)==0 ) {
			if (e->vfree) {
				e->vfree(e->v);
				e->vfree = NULL;
			}

			e->v = v;

			if(vfree)
				e->vfree = vfree;
			break;
		}
		pe = &(*pe)->next;
	}

	if (*pe==NULL) {
		if (hash->pool){
			e = navi_pool_calloc(hash->pool,1, sizeof(navi_hent_t));
		}
		else{
			e = calloc(1, sizeof(navi_hent_t));
		}
		if (!e)
			return NAVI_INNER_ERR;
		*pe = e;
		if (hash->pool){
			kcp = navi_pool_strdup(hash->pool,key);
		}
		else{
			kcp = strdup(key);
		}
		if (!kcp)
			return NAVI_INNER_ERR;

		e->k = kcp;
		e->v = v;
		e->h = h;

		if (vfree) e->vfree = vfree;

		navi_list_insert_tail(&hash->list_link,&e->list_link);
		hash->used++;

		if ((double)hash->used/buck_sz >= 1.2)
			navi_rehash(hash);

		return NAVI_HASH_NEW;
	}
	else
		return NAVI_HASH_REPLACE;
}

int navi_hash_set_gr(navi_hash_t* hash,const char* key,void* v)
{
	return navi_hash_set_impl(hash, key, v, NULL);
}

int navi_hash_set_gr2(navi_hash_t* hash,const char* key,void* v, void (*vfree)(void*))
{
	return navi_hash_set_impl(hash, key, v, vfree);
}

int navi_hash_set(navi_hash_t* hash,const char* key,const char* v)
{
	if (!key || strlen(key)==0 || !v )
		return NAVI_ARG_ERR;

	char *vcp;
	if (hash->pool){
		vcp = navi_pool_strdup(hash->pool,v);
		if (!vcp)
			return NAVI_INNER_ERR;
		return navi_hash_set_impl(hash,key,vcp, NULL);
	}
	else{
		vcp = strdup(v);
		if (!vcp)
			return NAVI_INNER_ERR;
		return navi_hash_set_impl(hash,key,vcp,free);
	}
}

void* navi_hash_get_gr(navi_hash_t* hash,const char* key)
{
	if (!hash || !key || strlen(key)==0 )
		return NULL;

	size_t h = hash_str(key);
	size_t buck_sz = primes[hash->size_stage];
	size_t idx = h % buck_sz;

	navi_hent_t* e = hash->b[idx];

	while(e) {
		if ( e->h==h && strcmp(key,e->k)==0 ) {
			return e->v;
		}
		e = e->next;
	}
	return NULL;
}

const char* navi_hash_get(navi_hash_t* hash,const char* key)
{
	return (const char*)navi_hash_get_gr(hash,key);
}

int navi_hash_del(navi_hash_t* hash,const char* key)
{
	if (!hash || !key || strlen(key)==0 )
		return NAVI_ARG_ERR;

	size_t h = hash_str(key);
	size_t buck_sz = primes[hash->size_stage];
	size_t idx = h % buck_sz;

	navi_hent_t** pe = hash->b + idx;
	navi_hent_t* e;
	while(*pe) {
		e = *pe;
		if (e->h == h && strcmp(e->k,key)==0 ) {
			if (hash->it_mgr) {
				navi_griter_t* it;
				chain_node_t* itlk = hash->it_mgr->using_iter.next;
				while(itlk != &hash->it_mgr->using_iter) {
					it = navi_list_data(itlk, navi_griter_t, link);
					if (it->cur == &e->list_link) {
						it->cur = e->list_link.next;
					}
					itlk = itlk->next;
				}
			}

			navi_list_remove(&e->list_link);

			*pe = e->next;
			if (e->vfree)
				e->vfree(e->v);
			if (hash->pool == NULL){
				free(e->k);
				free(e);
			}
			return 1;
		}
		pe = &(*pe)->next;
	}

	return 0;
}

void navi_hash_destroy(navi_hash_t* hs)
{
	if (!hs) return;
	if (hs->pool) {
		if (hs->it_mgr) navi_griter_mgr_clean(hs->it_mgr);
		navi_pool_destroy(hs->pool);
	}
	else {
		chain_node_t *link = hs->list_link.next;
		navi_hent_t* e;
		while(link != &hs->list_link) {
			e = (navi_hent_t*)((char*)link - offsetof(navi_hent_t,list_link));
			link = link->next;
			if (e->vfree)
				e->vfree(e->v);
			free(e->k);
			free(e);
		}

		free(hs->b);
		if (hs->it_mgr) navi_griter_mgr_clean(hs->it_mgr);
		free(hs->it_mgr);
		free(hs);
		return;
	}
}

#define ITER_MAGIC 0x1786aecd

void* navi_hash_iter(navi_hash_t* hash)
{
	if (!hash) return NULL;
	if (hash->it_mgr == NULL) {
		if (hash->pool) {
			hash->it_mgr = (navi_griter_mgr_t*)navi_pool_calloc(hash->pool,1,
				sizeof(navi_griter_mgr_t));
		}
		else {
			hash->it_mgr = (navi_griter_mgr_t*)calloc(1, sizeof(navi_griter_mgr_t));
		}
		if (!hash->it_mgr) return NULL;
		navi_griter_mgr_init(hash->it_mgr, hash->pool);
	}

	navi_griter_t* it = navi_griter_get(hash->it_mgr);
	it->cur = hash->list_link.next;
	it->ctx = &hash->list_link;
	it->_magic = ITER_MAGIC;
	return it;
}

void navi_hash_iter_destroy(void* it)
{
	navi_griter_t* iter = (navi_griter_t*)it;
	if (!iter || iter->_magic != ITER_MAGIC)
		return;
	navi_griter_recycle(iter);
}

navi_hent_t* navi_hash_iter_next(void* it)
{
	navi_griter_t* iter = (navi_griter_t*)it;
	if (!iter || iter->_magic != ITER_MAGIC)
		return NULL;
	chain_node_t* lk = (chain_node_t*)iter->cur;
	if (lk == iter->ctx)
		return NULL;
	navi_hent_t* ret = navi_list_data(lk, navi_hent_t, list_link);
	iter->cur = lk->next;
	return ret;
}
