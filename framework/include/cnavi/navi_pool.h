/*
 * navi_pool.h
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 *      Desc:
 *      	摘取ngx_pool_t实现，并简化。
 */

#ifndef NAVI_POOL_H_
#define NAVI_POOL_H_

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct navi_pool_large_s  navi_pool_large_t;

struct navi_pool_large_s {
	navi_pool_large_t	*next;
	void	*alloc;
};

typedef struct navi_pool_s navi_pool_t;

typedef struct {
	u_char	*alloc;
	u_char	*last;
	u_char	*end;
	navi_pool_t	*next;
	uint32_t	failed;

	uint32_t	last_req_sz;
} navi_pool_data_t;

struct navi_pool_s {
	navi_pool_data_t       d;
	uint32_t	max;
	navi_pool_t	*current;
	navi_pool_t *last_req_pool;
	navi_pool_large_t	*large;
};

void *navi_pool_alloc(navi_pool_t *pool, size_t size);
void *navi_pool_nalloc(navi_pool_t *pool, size_t size);
void *navi_pool_calloc(navi_pool_t *pool, size_t nelmts, size_t elmt_sz);

void navi_pool_free(navi_pool_t *pool, void *p);
navi_pool_t *navi_pool_create(size_t size);
void navi_pool_destroy(navi_pool_t* pool);
void navi_pool_reset(navi_pool_t* pool);

char* navi_pool_strdup(navi_pool_t* pool,const char* src);

void navi_pool_init(navi_pool_t* pool,void* alloc,size_t size);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_POOL_H_ */
