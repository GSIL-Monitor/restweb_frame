/*
 * navi_pool.c
 *
 *  Created on: 2013-9-4
 *      Author: li.lei
 */

/*
 * Copyright (C) Igor Sysoev
 */

#include "navi_pool.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static void *navi_pool_alloc_block(navi_pool_t *pool, size_t size);
static void *navi_pool_alloc_large(navi_pool_t *pool, size_t size);
static void* navi_memalign(size_t alignment, size_t size);

#define NAVI_MAX_BLOCK_LOAD (4096-sizeof(navi_pool_t))

#define navi_align_ptr(p, a)                                                   \
    (u_char *) (((uintptr_t) (p) + ((uintptr_t) a - 1)) & ~((uintptr_t) a - 1))

#define NAVI_ALIGNMENT sizeof(unsigned long)
#define NAVI_POOL_ALIGNMENT 16

void* navi_memalign(size_t alignment, size_t size)
{
	void *p;
	int err;
	err = posix_memalign(&p, alignment, size);
	if (err)
		p = NULL;
	return p;
}

navi_pool_t *navi_pool_create(size_t size)
{
	navi_pool_t *p;

	if (size < 256)
		size = 256;

	p = navi_memalign(NAVI_POOL_ALIGNMENT, size);
	if (p == NULL) {
		return NULL;
	}

	p->d.alloc = (u_char*)p;
	p->d.last = (u_char *) p + sizeof(navi_pool_t);
	p->d.end = (u_char *) p + size;
	p->d.next = NULL;
	p->d.failed = 0;

	size = size - sizeof(navi_pool_t);
	p->max = (size < NAVI_MAX_BLOCK_LOAD) ? size : NAVI_MAX_BLOCK_LOAD;

	p->current = p;
	p->last_req_pool = NULL;
	p->large = NULL;
	return p;
}

void navi_pool_init(navi_pool_t* p, void* alloc, size_t size)
{
	p->d.alloc = alloc;
	p->d.last = (u_char*) p + sizeof(navi_pool_t);
	p->d.end = (u_char*) p + size;
	p->d.next = NULL;
	p->d.failed = 0;

	size = size - sizeof(navi_pool_t);
	p->max = (size < NAVI_MAX_BLOCK_LOAD) ? size : NAVI_MAX_BLOCK_LOAD;
	p->current = p;
	p->last_req_pool = NULL;
	p->large = NULL;
}

void navi_pool_destroy(navi_pool_t *pool)
{
	navi_pool_t *p, *n;
	navi_pool_large_t *l;

	for (l = pool->large; l; l = l->next) {
		if (l->alloc) {
			free(l->alloc);
		}
	}

	for (p = pool, n = pool->d.next; /* void */; p = n, n = n->d.next) {
		free(p->d.alloc);

		if (n == NULL) {
			break;
		}
	}
}

void navi_pool_reset(navi_pool_t* pool)
{
	navi_pool_t *p, *n;
	navi_pool_large_t *l;
	int i;

	for (l = pool->large; l; l = l->next) {
		if (l->alloc) {
			free(l->alloc);
		}
	}

	pool->large = NULL;

	for (p = pool, n = pool->d.next, i = 0; /* void */;
	    p = n, n = n->d.next, i++) {
		if (i < 3) {
			p->d.last = (u_char *) p + sizeof(navi_pool_t);
		}
		else if (i == 3) {
			p->d.last = (u_char *) p + sizeof(navi_pool_t);
			p->d.next = NULL;
		}
		else {
			free(p->d.alloc);
		}

		if (n == NULL)
			break;
	}

	pool->current = pool;
}

void * navi_pool_alloc(navi_pool_t *pool, size_t size)
{
	u_char *m;
	navi_pool_t *p;

	if (size==0)
		return NULL;

	if (size <= pool->max) {
		p = pool->current;
		do {
			m = navi_align_ptr(p->d.last, NAVI_ALIGNMENT);
			if ((size_t) (p->d.end - m) >= size) {

				p->d.last_req_sz = size;
				pool->last_req_pool = p;
				p->d.last = m + size;
				return m;
			}

			p = p->d.next;
		}
		while (p);

		return navi_pool_alloc_block(pool, size);
	}

	return navi_pool_alloc_large(pool, size);
}

void* navi_pool_nalloc(navi_pool_t *pool, size_t size)
{
	u_char *m;
	navi_pool_t *p;

	if(size==0)
		return NULL;

	if (size <= pool->max) {
		p = pool->current;
		do {
			m = p->d.last;
			if ((size_t) (p->d.end - m) >= size) {
				p->d.last = m + size;

				p->d.last_req_sz = size;
				pool->last_req_pool = p;
				return m;
			}

			p = p->d.next;
		}
		while (p);

		return navi_pool_alloc_block(pool, size);
	}

	return navi_pool_alloc_large(pool, size);
}

static void *navi_pool_alloc_block(navi_pool_t *pool, size_t size)
{
	u_char *m;
	size_t psize;
	navi_pool_t *p, *new, *current;

	psize = (size_t) (pool->d.end - (u_char *) pool);
	m = navi_memalign(NAVI_POOL_ALIGNMENT, psize);
	if (m == NULL) {
		return NULL;
	}

	new = (navi_pool_t *) m;
	new->d.alloc = (uint8_t*)m;
	new->d.end = m + psize;
	new->d.next = NULL;
	new->d.failed = 0;

	m += sizeof(navi_pool_data_t);
	m = navi_align_ptr(m, NAVI_ALIGNMENT);

	new->d.last_req_sz = size;
	pool->last_req_pool = new;

	new->d.last = m + size;

	current = pool->current;

	for (p = current; p->d.next; p = p->d.next) {
		if (p->d.failed++ > 4) {
			current = p->d.next;
		}
	}

	p->d.next = new;
	pool->current = current ? current : new;
	return m;
}

static void *navi_pool_alloc_large(navi_pool_t *pool, size_t size)
{
	void *p;
	uint32_t n;
	navi_pool_large_t *large;

	p = malloc(size);
	if (p == NULL) {
		return NULL;
	}
	n = 0;

	for (large = pool->large; large; large = large->next) {
		if (large->alloc == NULL) {
			large->alloc = p;
			return p;
		}

		if (n++ > 3) {
			break;
		}
	}

	large = navi_pool_alloc(pool, sizeof(navi_pool_large_t));
	if (large == NULL) {
		free(p);
		return NULL;
	}

	large->alloc = p;
	large->next = pool->large;
	pool->large = large;

	return p;
}

void navi_pool_free(navi_pool_t *pool, void *p)
{
	navi_pool_large_t *l;
	navi_pool_t* last_req_pool = pool->last_req_pool;
	if (last_req_pool) {
		if (last_req_pool->d.last - last_req_pool->d.last_req_sz == p) {
			last_req_pool->d.last -= last_req_pool->d.last_req_sz;
			last_req_pool->d.last_req_sz = 0;
			pool->last_req_pool = NULL;
		}
	}

	for (l = pool->large; l; l = l->next) {
		if (p == l->alloc) {
			free(l->alloc);
			l->alloc = NULL;
			return;
		}
	}

	return;
}

void *navi_pool_calloc(navi_pool_t *pool, size_t nelmts, size_t elmt_sz)
{
	void *p;
	p = navi_pool_alloc(pool, nelmts * elmt_sz);
	if (p) {
		memset(p, 0x00, nelmts * elmt_sz);
	}

	return p;
}

char* navi_pool_strdup(navi_pool_t* pool, const char* src)
{
	if (!pool || !src)
		return NULL;

	char* cp = (char*) navi_pool_nalloc(pool, strlen(src) + 1);
	if (!cp)
		return NULL;
	strcpy(cp, src);
	return cp;
}

