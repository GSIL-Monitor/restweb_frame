/*
 * navi_gr_iter.c
 *
 *  Created on: 2014-4-25
 *      Author: li.lei
 */


#include "navi_gr_iter.h"
#include "navi_list.h"

#define NAVI_ITER_RECYCLED 0x9ecf79a3

static navi_griter_t* navi_griter_new(navi_griter_mgr_t* mgr)
{
	navi_griter_t* iter ;
	if (mgr->pool)
		iter = navi_pool_calloc(mgr->pool, 1, sizeof(navi_griter_t));
	else
		iter = calloc(1,sizeof(navi_griter_t));

	if (!iter) {
		return NULL;
	}
	iter->mgr = mgr;
	navi_list_insert_head(&mgr->using_iter, &iter->link);
	return iter;
}

void navi_griter_recycle(navi_griter_t* iter)
{
	navi_griter_mgr_t* mgr = (navi_griter_mgr_t* )iter->mgr;
	iter->cur = NULL;
	iter->ctx = NULL;
	iter->_magic = NAVI_ITER_RECYCLED;
	navi_list_remove(&iter->link);
	navi_list_insert_head(&mgr->iter_pool, &iter->link);
}

static navi_griter_t* navi_griter_reuse(navi_griter_mgr_t* mgr)
{
	navi_griter_t* ret = NULL;
	if (mgr->iter_pool.next != &mgr->iter_pool)
		ret = navi_list_data(mgr->iter_pool.next, navi_griter_t, link);

	if (ret) {
		navi_list_remove(&ret->link);
		navi_list_insert_head(&mgr->using_iter,&ret->link);
	}
	return ret;
}

navi_griter_t* navi_griter_get(navi_griter_mgr_t* mgr)
{
	navi_griter_t* iter = navi_griter_reuse(mgr);
	if (!iter) {
		iter = navi_griter_new(mgr);
	}
	return iter;
}

void navi_griter_mgr_init(navi_griter_mgr_t* mgr, navi_pool_t* pool)
{
	navi_list_init(&mgr->iter_pool);
	navi_list_init(&mgr->using_iter);
	mgr->pool = pool;
}

void navi_griter_mgr_clean(navi_griter_mgr_t* mgr)
{
	if (mgr->pool) return;

	chain_node_t* l = mgr->using_iter.next;
	while ( l != &mgr->using_iter ) {
		navi_griter_t* it = navi_list_data(l,navi_griter_t,link);
		l = l->next;
		free(it);
	}

	l = mgr->iter_pool.next;
	while ( l != &mgr->iter_pool ) {
		navi_griter_t* it = navi_list_data(l,navi_griter_t,link);
		l = l->next;
		free(it);
	}
}
