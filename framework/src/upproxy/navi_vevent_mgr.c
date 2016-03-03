/*
 * navi_vevent_mgr.c
 *
 *  Created on: 2014-04-08
 *      Author: yanguotao@youku.com
 */

#include "navi_vevent_mgr.h"
#include "navi_request_impl.h"
#include "navi_list.h"
#include "navi_frame_log.h"

#include <assert.h>

static navi_vevent_mgr_t *navi_ve_mgr = NULL;

navi_vehandler_t * navi_request_join_vevent(navi_request_t* r, const char *name, navi_vevent_handler_fp handler, 
	navi_vevent_handler_reinit_fp reinit, void *ctx)
{
	navi_vehandler_t *p_vehandler;
	navi_request_impl_t *req = navi_req_h2i(r);

	if (req != req->main){
		return NULL;
	}

	chain_node_t *req_link= &req->main_data->ve_link;
	chain_node_t * node = req_link->next;
	while (node != req_link){
		p_vehandler = navi_list_data(node, navi_vehandler_t, req_link);
		if (!strcmp(p_vehandler->ve->name, name)){
			assert(p_vehandler->ve_link.next != &p_vehandler->ve_link);
			return p_vehandler;
		}
		node = node->next;
	}

	navi_pool_t *pool = navi_request_pool(r);
	p_vehandler = navi_pool_calloc(pool, 1, sizeof(navi_vehandler_t));
	if (p_vehandler == NULL){
		return NULL;
	}
	p_vehandler->binded_req = r;
	p_vehandler->handler = handler;
	p_vehandler->reinit = reinit;
	p_vehandler->ctx = ctx;
	navi_list_insert_tail(req_link, &p_vehandler->req_link);

	if (navi_ve_mgr == NULL){
		navi_ve_mgr = calloc(1, sizeof(navi_vevent_mgr_t));
		navi_ve_mgr->hash = navi_hash_init_with_heap();
		navi_list_init(&navi_ve_mgr->ready_link);
		navi_list_init(&navi_ve_mgr->clean_link);
	}

	navi_vevent_t *ve =  navi_hash_get_gr(navi_ve_mgr->hash, name);
	if (ve == NULL){
		ve = calloc(1, sizeof(navi_vevent_t));
		ve->name = strdup(name);
		navi_list_init(&ve->vh_link);
		navi_list_init(&ve->status_link);
		navi_hash_set_gr(navi_ve_mgr->hash, name, ve);
		navi_griter_mgr_init(&ve->vh_its, NULL);
		ve->_magic = NAVI_VE_MAGIC;
	}

	navi_list_insert_tail(&ve->vh_link, &p_vehandler->ve_link);
	p_vehandler->ve = ve;

	if ( req->drive_from_rest ) {
		navi_request_trigger_rest_drive(r);
	}

	return p_vehandler;
}

navi_vevent_t *navi_vevent_get(const char *name)
{
	if (navi_ve_mgr == NULL || navi_ve_mgr->hash == NULL || name == NULL){
		return NULL;
	}
	
	navi_vevent_t *ve =  navi_hash_get_gr(navi_ve_mgr->hash, name);

	return ve;
}

static void navi_vevent_destroy(navi_vevent_t *ve){
	chain_node_t* nd = ve->vh_link.next;
	navi_vehandler_t* vh;
	while ( nd != &ve->vh_link ) {
		vh = navi_list_data(nd,navi_vehandler_t,ve_link);
		nd = nd->next;
		navi_list_remove(&vh->req_link);
	}

	navi_list_remove(&ve->status_link);
	navi_hash_del(navi_ve_mgr->hash , ve->name);
	if (ve->trig_free) {
		ve->trig_free(ve->trigger_data);
		ve->trig_free = NULL;
		ve->trigger_data = NULL;
	}
	free(ve->name);
	ve->destroy(ve->imp);
	navi_griter_mgr_clean(&ve->vh_its);
	free(ve);
}

void navi_vehandler_cancel(navi_vehandler_t* vh)
{
	navi_vevent_t* ve = vh->ve;
	assert(vh->ve_link.next != &vh->ve_link);
	assert(vh->ve_link.prev != &vh->ve_link);
	assert(vh->req_link.next != &vh->req_link);
	assert(vh->req_link.prev != &vh->req_link);
	navi_vevent_advance_vhiters(ve, vh);
	navi_list_remove(&vh->ve_link);
	navi_list_remove(&vh->req_link);
	memset(vh, 0x00, sizeof(navi_vehandler_t));
	if (navi_list_empty(&(ve->vh_link))){
		navi_vevent_triggered(ve);
		navi_list_insert_tail(&navi_ve_mgr->clean_link, &ve->status_link);
		ve->status = NAVI_VE_ZOMBIE;
		if(ve->destroy)ve->destroy(ve->imp);
		assert( 1== navi_hash_del(navi_ve_mgr->hash, ve->name) );
		free(ve->name);
		ve->name = NULL;
		ve->imp = NULL;
	}
}

void navi_request_quit_vevent(navi_request_t* r, const char* name){
	navi_vehandler_t *p_vehandler;
	navi_request_impl_t* req = navi_req_h2i(r);

	if (req != req->main){
		return;
	}

	chain_node_t *req_link= &req->main_data->ve_link;
	chain_node_t * node =	req_link->next;
	chain_node_t *next_node;
	while (node != req_link){
		next_node = node->next;
		p_vehandler = navi_list_data(node, navi_vehandler_t, req_link);
		if (!strcmp(p_vehandler->ve->name, name)){
			navi_vehandler_cancel(p_vehandler);
			return;
		}
		node = next_node;
	}

	if ( req->drive_from_rest ) {
		navi_request_trigger_rest_drive(r);
	}
}

void navi_request_quitall_vevent(navi_request_t* r)
{
	navi_vehandler_t *p_vehandler;
	navi_request_impl_t* req = navi_req_h2i(r);

	if (req != req->main){
		return;
	}

	chain_node_t *req_link= &req->main_data->ve_link;	
	chain_node_t * node = req_link->next;
	while (node != req_link){
		p_vehandler = navi_list_data(node, navi_vehandler_t, req_link);
		navi_vehandler_cancel(p_vehandler);
		node = req_link->next;
	}

	if ( req->drive_from_rest ) {
		navi_request_trigger_rest_drive(r);
	}
}

void navi_vevent_ready(navi_vevent_t *ve,void* trig_data, navi_vevent_trigger_free freefp)
{
	//如果不做判断，会导致链表数据破坏
	if( ve->status == NAVI_VE_IDLE ) {
		navi_list_insert_tail(&navi_ve_mgr->ready_link, &ve->status_link);
		assert(ve->trigger_data==NULL && ve->trig_free==NULL);
		ve->trigger_data = trig_data;
		ve->trig_free = freefp;
		ve->status = NAVI_VE_READY;
	}
	else if (ve->status == NAVI_VE_READY){
		NAVI_FRAME_LOG(NAVI_LOG_DEBUG, "trigger already ready event:%s",
			ve->name);
		if (ve->trig_free) {
			ve->trig_free(ve->trigger_data);
		}
		ve->trig_free = freefp;
		ve->trigger_data = trig_data;
	}
	else {
		if (freefp)
			freefp(trig_data);
	}
}

void navi_vevent_triggered(navi_vevent_t* ve)
{
	if (ve->status == NAVI_VE_READY) {
		navi_list_remove(&ve->status_link);
		ve->status = NAVI_VE_IDLE;
	}
	if (ve->trig_free) {
		ve->trig_free(ve->trigger_data);
	}
	ve->trigger_data = NULL;
	ve->trig_free = NULL;
}

navi_vevent_mgr_t *navi_vevent_mgr_get(void)
{
	return navi_ve_mgr;
}

void navi_vevent_mgr_clean_zombie_ve(void)
{
	if (navi_ve_mgr == NULL){
		return;
	}

	navi_vevent_t* ve_rcy;
	chain_node_t* link = navi_ve_mgr->clean_link.next;
	while(link != &navi_ve_mgr->clean_link ) {
		ve_rcy = navi_list_data(link, navi_vevent_t, status_link);
		navi_list_remove(&ve_rcy->status_link);
		link = navi_ve_mgr->clean_link.next;
		navi_griter_mgr_clean(&ve_rcy->vh_its);
		free(ve_rcy);
	}
}

void navi_vevent_mgr_destroy()
{
	if (navi_ve_mgr == NULL || navi_ve_mgr->hash == NULL){
		return;
	}

	navi_hash_t *h = navi_ve_mgr->hash;
	navi_hent_t* e;
	void* it = navi_hash_iter(h);
	while ((e=navi_hash_iter_next(it))) {
		navi_vevent_destroy((navi_vevent_t*)(e->v));
		//e->v=NULL;
	}
	navi_hash_iter_destroy(it);

	navi_vevent_t* ve_rcy;
	chain_node_t* link = navi_ve_mgr->clean_link.next;
	while(link != &navi_ve_mgr->clean_link ) {
		ve_rcy = navi_list_data(link, navi_vevent_t, status_link);
		link = link->next;
		navi_griter_mgr_clean(&ve_rcy->vh_its);
		free(ve_rcy);
	}

	navi_hash_destroy(h);
	free(navi_ve_mgr);
	navi_ve_mgr = NULL;
}

#define VH_ITER_MAGIC 0x8871eeac

void* navi_vevent_vh_it(navi_vevent_t* ve)
{
	navi_griter_t* it = navi_griter_get(&ve->vh_its);
	it->_magic = VH_ITER_MAGIC;
	it->cur = ve->vh_link.next;
	it->ctx = &ve->vh_link;
	return it;
}

navi_vehandler_t* navi_vevent_vh_it_next(void* it)
{
	navi_griter_t* iter = (navi_griter_t*)it;
	if ( iter->_magic != VH_ITER_MAGIC)
		return NULL;

	chain_node_t* lk = (chain_node_t*)iter->cur;
	if (lk == iter->ctx)
		return NULL;

	navi_vehandler_t* ret = navi_list_data(lk,navi_vehandler_t,ve_link);
	if (lk == lk->next || lk->next==NULL ) {
		chain_node_t* head = (chain_node_t*)iter->ctx;
		lk = head->next;

		while ( lk != head) {
			assert(lk->next != lk);
			lk = lk->next;
		}

		navi_vevent_t* ve = navi_list_data(head, navi_vevent_t, vh_link);
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "vevent:%s:%d vehandler iter impl unknown error",
			ve->name, ve->status);

		if (ve->_magic == NAVI_VE_MAGIC) {
			iter->cur = head->next;
			if (iter->cur == head)
				return NULL;
			ret = navi_list_data(lk,navi_vehandler_t,ve_link);
			iter->cur = lk->next;
			return ret;
		}
		else {
			iter->mgr = NULL;
			return NULL;
		}

		/****
		iter->cur = head->next;
		if (iter->cur == head)
			return NULL;
		ret = navi_list_data(lk,navi_vehandler_t,ve_link);
		iter->cur = lk->next;
		return ret;
		****/
	}

	iter->cur = lk->next;
	return ret;
}

void navi_vevent_vh_it_destroy(void* it)
{
	navi_griter_t* iter = (navi_griter_t*)it;
	if (iter->mgr == NULL) {
		free(iter);
		return;
	}
	if ( iter->_magic != VH_ITER_MAGIC)
		return;
	navi_griter_recycle(it);
}

void navi_vevent_advance_vhiters(navi_vevent_t* ve, navi_vehandler_t* vh)
{
	navi_griter_mgr_t* itmgr = &ve->vh_its;
	navi_griter_t* it;
	chain_node_t* link = itmgr->using_iter.next;
	while(link != &itmgr->using_iter) {
		it = navi_list_data(link, navi_griter_t, link);
		if (  it->cur == vh ) {
			assert(vh->ve_link.next != &vh->ve_link);
			it->cur = vh->ve_link.next;
		}
		link = link->next;
	}
}
