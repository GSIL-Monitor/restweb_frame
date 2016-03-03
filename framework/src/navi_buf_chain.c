/*
 * navi_buf_chain.c
 *
 *  Created on: 2013-9-23
 *      Author: li.lei
 */

#include "navi_buf_chain.h"
#include "navi_frame_log.h"
#include "navi_common_define.h"

#define NAVI_CHAIN_POOL_DEFAULT 512

navi_buf_chain_t* navi_buf_chain_init(navi_pool_t* pool)
{
	navi_buf_chain_t* chain = navi_pool_calloc(pool, 1, sizeof(navi_buf_chain_t));

	if (chain == NULL)
		return NULL;

	chain->pool = pool;
	chain->read_node = chain->tail = &chain->head;
	return chain;
}

#define ND_SIZE_256(sz) (((sz)+255) & 0x7fffff00 )

void navi_buf_chain_print(navi_buf_chain_t* chain)
{
	if ( chain->head == NULL ) {
		printf("chain:%p: empty. ptail:%p, pread:%p\n",chain, chain->tail, chain->read_node);
	}

	printf("chain:%p{head:%p,ptail:%p,pread:%p}",chain,chain->head, chain->tail, chain->read_node);
	navi_buf_node_t* nd = chain->head;
	int i=0;
	do {
		if ( i++ % 4 == 0)
			printf( "\nn:%p[s:%d l:%p lp:%p] ", nd, nd->size, nd->next, &nd->next);
		else
			printf( "n:%p[s:%d l:%p lp:%p] ", nd, nd->size, nd->next, &nd->next);
	} while ( (nd = nd->next));
	printf("\n");
	fflush(stdout);
}

int navi_buf_chain_append(navi_buf_chain_t* chain,const uint8_t* part, size_t sz)
{
	if (!chain || sz == 0 || sz >= 0x7ffffffff || part == NULL)
		return NAVI_ARG_ERR;

	navi_buf_node_t* nd = *chain->tail;
	navi_buf_node_t* rnd = *chain->read_node;
	size_t off = 0;

	if ( nd ) {
		if (nd->read == 0) {
			size_t left = nd->capacity - nd->size;
			if (left >= sz ) {
				memcpy(nd->buf + nd->size, part, sz);
				nd->size += sz;
				chain->sum += sz;
				return NAVI_OK;
			}
			else if (left > 0) {
				memcpy(nd->buf + nd->size, part, left);
				nd->size += left;
				off = left;
			}
			chain->tail = &nd->next;
		}
		else {
			chain->tail = &nd->next;
		}
	}

	nd = NULL;

	while ( chain->recycle ) {
		nd = chain->recycle;
		chain->recycle = nd->next;
		nd->next = NULL;

		if ( nd->capacity >= sz - off ) {
			memcpy(nd->buf, part + off, sz - off);
			nd->size = sz - off;

			off = sz;

			*chain->tail = nd;
			break;
		}
		else {
			memcpy(nd->buf, part + off, nd->capacity);
			nd->size = nd->capacity;

			*chain->tail = nd;
			chain->tail = &nd->next;

			off += nd->capacity;
		}
	}

	if ( off != sz) {
		navi_buf_node_t* nd = navi_pool_calloc(chain->pool, 1,
			sizeof(navi_buf_node_t));
		if (!nd) {
			NAVI_SYSERR_LOG("alloc navi_buf_node_t failed");
			return NAVI_INNER_ERR;
		}
		nd->capacity = ND_SIZE_256(sz - off);
		void* buf = navi_pool_nalloc(chain->pool, nd->capacity);
		if (!buf) {
			NAVI_SYSERR_LOG();
			navi_pool_free(chain->pool, nd);
			return NAVI_INNER_ERR;
		}

		nd->buf = buf;
		nd->size = sz - off;
		memcpy(buf, part + off, sz - off);
		*chain->tail = nd;
	}

	chain->sum += sz;
	return NAVI_OK;
}

int navi_buf_chain_append_file(navi_buf_chain_t* chain,int fd, size_t pos)
{
	if (!chain || fd == -1)
		return NAVI_ARG_ERR;
	navi_buf_node_t* nd = *chain->tail;
	if ( nd )
		chain->tail = &nd->next;//file buf always in independent ndoe
	nd = navi_pool_calloc(chain->pool, 1, sizeof(navi_buf_node_t));
	if (!nd) {
		NAVI_SYSERR_LOG("alloc navi_buf_node_t failed");
		return NAVI_INNER_ERR;
	}
	nd->capacity = 4;
	void* buf = navi_pool_nalloc(chain->pool, nd->capacity);
	if (!buf) {
		NAVI_SYSERR_LOG();
		navi_pool_free(chain->pool, nd);
		return NAVI_INNER_ERR;
	}
	
	nd->buf = buf;//just for recyle compare
	nd->infile = 1;
	nd->fd = fd;
	struct stat stbuf;
	fstat(fd, &stbuf);
	if (stbuf.st_size < pos) {
		pos = stbuf.st_size;
	}
	nd->filepos = pos;
	nd->size = stbuf.st_size - pos;

	chain->sum += nd->size;

	*chain->tail = nd;
	chain->tail = &nd->next;
	return NAVI_OK;
}

int navi_buf_chain_append_part_file(navi_buf_chain_t* chain, int fd, size_t pos_begin,
		size_t content_size)
{
	if (!chain || fd == -1)
		return NAVI_ARG_ERR;
	navi_buf_node_t* nd = *chain->tail;
	if ( nd )
		chain->tail = &nd->next;//file buf always in independent ndoe
	nd = navi_pool_calloc(chain->pool, 1, sizeof(navi_buf_node_t));
	if (!nd) {
		NAVI_SYSERR_LOG("alloc navi_buf_node_t failed");
		return NAVI_INNER_ERR;
	}
	nd->capacity = 4;
	void* buf = navi_pool_nalloc(chain->pool, nd->capacity);
	if (!buf) {
		NAVI_SYSERR_LOG();
		navi_pool_free(chain->pool, nd);
		return NAVI_INNER_ERR;
	}

	nd->buf = buf;//just for recyle compare
	nd->infile = 1;
	nd->fd = fd;
	nd->filepos = pos_begin;
	nd->size = content_size;

	chain->sum += content_size;
	*chain->tail = nd;
	chain->tail = &nd->next;
	return NAVI_OK;
}


int navi_buf_chain_insert_head(navi_buf_chain_t* chain, const uint8_t* part, size_t sz)
{
	if (!chain || sz == 0 || part == NULL)
		return NAVI_ARG_ERR;

	navi_buf_node_t* nd = NULL;
	size_t off = 0;

	navi_buf_node_t* newhead = NULL;
	navi_buf_node_t** last_insert = NULL;
	//bool mod_tail = (chain->head != NULL);

	while ( chain->recycle ) {
		nd = chain->recycle;
		chain->recycle = nd->next;
		nd->next = NULL;

		if ( nd->capacity >= sz - off ) {
			memcpy(nd->buf, part + off, sz - off);
			nd->size = sz - off;

			off = sz;
			if (newhead == NULL) {
				newhead = nd;
				last_insert = &nd;
			}
			else {
				*last_insert = nd;
			}
			//last_insert = &nd->next;
			break;
		}
		else {
			memcpy(nd->buf, part + off, nd->capacity);
			nd->size = nd->capacity;

			off += nd->capacity;

			if (newhead == NULL) {
				newhead = nd;
				last_insert = &nd;
			}
			else {
				*last_insert = nd;
			}
			last_insert = &nd->next;
		}
	}

	if ( off != sz) {
		navi_buf_node_t* nd = navi_pool_calloc(chain->pool, 1,
			sizeof(navi_buf_node_t));
		if (!nd) {
			NAVI_SYSERR_LOG("alloc navi_buf_node_t failed");
			return NAVI_INNER_ERR;
		}
		nd->capacity = ND_SIZE_256(sz - off);
		void* buf = navi_pool_nalloc(chain->pool, nd->capacity);
		if (!buf) {
			NAVI_SYSERR_LOG();
			navi_pool_free(chain->pool, nd);
			return NAVI_INNER_ERR;
		}
		memcpy(buf, part + off, sz - off);

		nd->buf = buf;
		nd->size = sz - off;

		if (newhead == NULL) {
			newhead = nd;
			last_insert = &nd;
		}
		else {
			*last_insert = nd;
		}

		//last_insert = &nd->next;
	}

    if (chain->head != NULL) {
		(*last_insert)->next = chain->head;
	}
	else {
		chain->tail = last_insert;
	}
	chain->head = newhead;
	//if ( mod_tail ) {
	//	chain->tail = last_insert;
	//}
	chain->sum += sz;
	return NAVI_OK;
}

int navi_buf_chain_insert_head_file(navi_buf_chain_t* chain, int fd, size_t pos,
		size_t size)
{
	if (!chain || fd == -1)
		return NAVI_ARG_ERR;
	navi_buf_node_t* nd = navi_pool_calloc(chain->pool, 1, sizeof(navi_buf_node_t));
	if (!nd) {
		NAVI_SYSERR_LOG("alloc navi_buf_node_t failed");
		return NAVI_INNER_ERR;
	}
	nd->capacity = 4;
	void* buf = navi_pool_nalloc(chain->pool, nd->capacity);
	if (!buf) {
		NAVI_SYSERR_LOG();
		navi_pool_free(chain->pool, nd);
		return NAVI_INNER_ERR;
	}
	
	nd->buf = buf;//just for recyle compare
	nd->infile = 1;
	nd->fd = fd;
	nd->filepos = pos;
	nd->size = size;

	chain->sum += size;

	if (chain->head == NULL) {
		chain->head = nd;
		chain->tail = &nd->next;
	}
	else {
		nd->next = chain->head;
		chain->head = nd;
	}
	return NAVI_OK;

}


size_t navi_buf_chain_get_content(navi_buf_chain_t* chain, uint8_t* buf,
    size_t sz)
{
	if (!chain)
		return 0;

	if (buf == NULL || sz == 0)
		return chain->sum;

	navi_buf_node_t* nd = chain->head;
	uint8_t* p = buf;
	size_t left = sz;
	while (nd && left>0 ) {
		if ( left > nd->size ) {
			memcpy(p, nd->buf, nd->size);
			left -= nd->size;
			p += nd->size;
		}
		else {
			memcpy(p, nd->buf, left);
			left = 0;
			break;
		}
		nd = nd->next;
	}
	return chain->sum;
}

size_t navi_buf_chain_read_part(navi_buf_chain_t* chain, uint8_t** buf)
{
	if ( chain->head == NULL  || *chain->read_node == NULL) {
		*buf = NULL;
		return 0;
	}

	(*(chain->read_node))->read = 1;
	*buf = (*(chain->read_node))->buf;
	size_t ret  = (*(chain->read_node))->size;

	chain->read_node = &((*(chain->read_node))->next);
	return ret;
}

void navi_buf_chain_recycle(navi_buf_chain_t* chain, void *busy_part/*, size_t *offset*/)
{
	if (busy_part == NULL) {
		navi_buf_chain_recycle_readed(chain);
		return;
	}
	navi_buf_node_t* nd = chain->head;
	if (nd == NULL) {
		chain->tail = chain->read_node = &chain->head;
		return;
	}

	while(nd) {
		if (nd->buf == busy_part && nd->read)
			break;
		else {
			nd = nd->next;
		}
	};

	if ( !nd ) return;

	do {
		nd = chain->head;
		if ( nd->buf == busy_part && nd->read) {
			break;
		}

		chain->head = nd->next;

        if ( chain->read_node == &nd->next) {
			chain->read_node = &chain->head;
        }

        if ( chain->tail == &nd->next ) {
			chain->tail = &chain->head;
        }

		if (!nd->infile) {
			chain->sum -= nd->size;
			nd->size = 0;
			nd->read = 0;
			nd->next = chain->recycle;
			chain->recycle = nd;
		}
	}while(1);
}

void navi_buf_chain_recycle_readed(navi_buf_chain_t* chain)
{
	if ( chain->head == NULL  || chain->read_node == &chain->head) {
		return;
	}

	do {
		navi_buf_node_t* nd = chain->head;
		chain->head = chain->head->next;

		nd->read = 0;
		nd->next = chain->recycle;
		chain->recycle = nd;
		chain->sum -= nd->size;
		nd->size = 0;
		
		if (chain->tail == &nd->next)
			chain->tail = &chain->head;

		if ( &nd->next == chain->read_node) {
			chain->read_node = &chain->head;
			break;
		}
	} while (1);
}
