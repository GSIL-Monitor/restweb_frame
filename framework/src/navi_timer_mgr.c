/*
 * navi_timer_mgr.c
 *
 *  Created on: 2013-9-2
 *      Author: li.lei
 */

#include "navi_timer_mgr.h"
#include "navi_frame_log.h"
#include "navi_list.h"

navi_timer_h navi_timer_add(navi_timer_mgr_t *mgr, navi_timer_type_e type,
    uint32_t to_ms, timer_handler_fp fun, void* args,
    timer_handler_fp destroyer, void* ctx)
{
	if (!mgr || !fun)
		return NULL;

	if (type != NAVI_TIMER_INTERVAL && type != NAVI_TIMER_ONCE)
		return NULL;

	navi_timer_t* tmr = (navi_timer_t*) calloc(1, sizeof(navi_timer_t));
	if (!tmr)
		return NULL;
	tmr->handler = fun;
	tmr->destroyer = destroyer;
	tmr->args = args;
	tmr->navi_ctx = ctx;
	tmr->type = type;
	tmr->to_ms = to_ms;
	tmr->mgr = mgr;

	navi_list_insert_tail(&mgr->regist, &tmr->link);
	tmr->stage = NAVI_TIMER_REGISTED;

	return tmr;
}

void* navi_timer_iter(navi_timer_mgr_t* mgr, navi_timer_stage_e e)
{
	if (mgr == NULL)
		return NULL;

	navi_griter_t* it = navi_griter_get(&mgr->it_mgr);

	switch (e) {
	case NAVI_TIMER_REGISTED:
		if (navi_list_empty(&mgr->regist))
			it->cur = NULL;
		else {
			it->cur = navi_list_data(mgr->regist.next,navi_timer_t,link);
		}
		it->ctx = &mgr->regist;
		break;
	case NAVI_TIMER_RUNNING:
		if (navi_list_empty(&mgr->running))
			it->cur = NULL;
		else {
			it->cur = navi_list_data(mgr->running.next,navi_timer_t,link);
		}
		it->ctx = &mgr->running;
		break;
	case NAVI_TIMER_CANCEL:
		if (navi_list_empty(&mgr->cancel))
			it->cur = NULL;
		else {
			it->cur = navi_list_data(mgr->cancel.next,navi_timer_t,link);
		}
		it->ctx = &mgr->cancel;
		break;
	}
	return it;
}

navi_timer_h navi_timer_iter_next(void* it)
{
	navi_griter_t* iter = (navi_griter_t*)it;
	if (iter->cur == NULL)
		return NULL;

	navi_timer_t* ret = iter->cur;
	chain_node_t *link = ret->link.next;
	if (link == iter->ctx) {
		iter->cur = NULL;
	}
	else {
		iter->cur = navi_list_data(link,navi_timer_t, link);
	}
	return (void*)ret;
}

void navi_timer_iter_destroy(void* it)
{
	navi_griter_recycle(it);
}

navi_timer_h navi_timer_get(navi_timer_mgr_t* mgr, navi_timer_stage_e e)
{
	switch (e) {
	case NAVI_TIMER_REGISTED:
		if (navi_list_empty(&mgr->regist))
			return NULL;
		return navi_list_data(mgr->regist.next,navi_timer_t,link);
	case NAVI_TIMER_RUNNING:
		if (navi_list_empty(&mgr->running))
			return NULL;
		return navi_list_data(mgr->running.next,navi_timer_t,link);
	case NAVI_TIMER_CANCEL:
		if (navi_list_empty(&mgr->cancel))
			return NULL;
		return navi_list_data(mgr->cancel.next,navi_timer_t,link);
	}
	return NULL;
}

void navi_timer_running(navi_timer_h h, void* drive_ctx)
{
	navi_timer_t* tmr = (navi_timer_t*) h;
	if (!tmr || tmr->stage == NAVI_TIMER_ZOMBIE)
		return;
	if (tmr->stage == NAVI_TIMER_RUNNING) {
		return;
	}

	navi_timer_mgr_t* mgr = (navi_timer_mgr_t*) tmr->mgr;

	tmr->driver_peer = drive_ctx;

	chain_node_t* it_link = mgr->it_mgr.using_iter.next;
	while ( it_link != &mgr->it_mgr.using_iter ) {
		navi_griter_t* it = (navi_griter_t*)navi_list_data(it_link,navi_griter_t,link);
		if ( it->cur == tmr) {
			navi_timer_iter_next(it);
		}
		it_link = it_link->next;
	}

	navi_list_remove(&tmr->link);
	navi_list_insert_tail(&mgr->running,&tmr->link);
	tmr->stage = NAVI_TIMER_RUNNING;
}

void navi_timer_cancel(navi_timer_h h)
{
	navi_timer_t* tmr = (navi_timer_t*) h;
	if (!tmr || tmr->stage == NAVI_TIMER_ZOMBIE)
		return;
	if (tmr->stage == NAVI_TIMER_CANCEL)
		return;
	if (tmr->stage == NAVI_TIMER_REGISTED) {
		navi_timer_canceled(h);
		return;
	}

	navi_timer_mgr_t* mgr = (navi_timer_mgr_t*) tmr->mgr;

	chain_node_t* it_link = mgr->it_mgr.using_iter.next;
	while ( it_link != &mgr->it_mgr.using_iter ) {
		navi_griter_t* it = (navi_griter_t*)navi_list_data(it_link,navi_griter_t,link);
		if ( it->cur == tmr) {
			navi_timer_iter_next(it);
		}
		it_link = it_link->next;
	}

	if ( tmr->driver_cancel_handler ) {
		navi_list_remove(&tmr->link);

		tmr->stage = NAVI_TIMER_ZOMBIE;

		void* driver = tmr->driver_peer;
		if (driver) {
			tmr->driver_cancel_handler(tmr);
			tmr->driver_peer = NULL;
		}

		if (tmr->destroyer)
			(tmr->destroyer)(tmr->args);
		tmr->destroyer = NULL;
		//navi_timer_cleanup(tmr);
	}
	else {
		navi_list_remove(&tmr->link);
		navi_list_insert_tail(&mgr->cancel,&tmr->link);
		tmr->stage = NAVI_TIMER_CANCEL;
		if (tmr->destroyer)
			(tmr->destroyer)(tmr->args);
		tmr->destroyer = NULL;
	}
}

void navi_timer_canceled(navi_timer_h h)
{
	navi_timer_t* tmr = (navi_timer_t*) h;
	if (!tmr || tmr->stage == NAVI_TIMER_ZOMBIE)
		return;

	navi_timer_mgr_t* mgr = (navi_timer_mgr_t*) tmr->mgr;
	chain_node_t* it_link = mgr->it_mgr.using_iter.next;
	while ( it_link != &mgr->it_mgr.using_iter ) {
		navi_griter_t* it = (navi_griter_t*)navi_list_data(it_link,navi_griter_t,link);
		if ( it->cur == tmr) {
			navi_timer_iter_next(it);
		}
		it_link = it_link->next;
	}

	navi_list_remove2(&tmr->link);
	tmr->stage = NAVI_TIMER_ZOMBIE;
	if ( tmr->driver_cancel_handler ) {
		void* driver = tmr->driver_peer;
		if (driver) {
			tmr->driver_cancel_handler(tmr);
			tmr->driver_peer = NULL;
		}
	}


	if (tmr->destroyer)
		(tmr->destroyer)(tmr->args);
	tmr->destroyer = NULL;
}

void navi_timer_cleanup(navi_timer_h h) {
	navi_timer_t* tmr = (navi_timer_t*)h;
	if ( tmr->stick == 0 )
		free(h);
}

void navi_timer_mgr_init(navi_timer_mgr_t* mgr) {
	if (!mgr)
		return;

	memset(mgr, 0x00, sizeof(navi_timer_mgr_t));

	navi_list_init(&mgr->regist);
	navi_list_init(&mgr->running);
	navi_list_init(&mgr->cancel);
	navi_griter_mgr_init(&mgr->it_mgr,NULL);
}

void navi_timer_mgr_clean(navi_timer_mgr_t* mgr)
{
	if (!mgr) return;

	navi_timer_t* tmr;
	while (tmr = navi_timer_get(mgr, NAVI_TIMER_REGISTED)) {
		navi_timer_canceled(tmr);
		navi_timer_cleanup(tmr);
	}
	while (tmr = navi_timer_get(mgr, NAVI_TIMER_RUNNING)) {
		navi_timer_canceled(tmr);
		navi_timer_cleanup(tmr);
	}
	while (tmr = navi_timer_get(mgr, NAVI_TIMER_CANCEL)) {
		navi_timer_canceled(tmr);
		navi_timer_cleanup(tmr);
	}

	navi_griter_mgr_clean(&mgr->it_mgr);
}

void navi_timer_mgr_cancelall(navi_timer_mgr_t* mgr)
{
	if (!mgr) return;

	void* it = navi_timer_iter(mgr, NAVI_TIMER_REGISTED);
	navi_timer_t *h;
	while( h = navi_timer_iter_next(it) ) {
		navi_timer_cancel(h);
		navi_timer_cleanup(h);
	}
	navi_timer_iter_destroy(it);

	it = navi_timer_iter(mgr, NAVI_TIMER_RUNNING);
	while( h = navi_timer_iter_next(it) ) {
		navi_timer_cancel(h);
		//navi_timer_canceled(h);
	}
	navi_timer_iter_destroy(it);
}

void navi_timer_mgr_clean_spec(navi_timer_mgr_t* mgr, void* according_ctx)
{
	if (mgr==NULL || according_ctx==NULL)
		return;

	void *it = navi_timer_iter(mgr, NAVI_TIMER_REGISTED);
	navi_timer_t *h;
	while( h = navi_timer_iter_next(it) ) {
		if (h->navi_ctx == according_ctx) {
			navi_timer_canceled(h);
			navi_timer_cleanup(h);
		}
	}
	navi_timer_iter_destroy(it);

	it = navi_timer_iter(mgr, NAVI_TIMER_RUNNING);
	while( h = navi_timer_iter_next(it) ) {
		if (h->navi_ctx == according_ctx) {
			navi_timer_canceled(h);
		}
	}
	navi_timer_iter_destroy(it);

	it = navi_timer_iter(mgr, NAVI_TIMER_CANCEL);
	while( h = navi_timer_iter_next(it) ) {
		if (h->navi_ctx == according_ctx) {
			navi_timer_canceled(h);
		}
	}
	navi_timer_iter_destroy(it);
}

void navi_timer_timeout(navi_timer_h h)
{
	navi_timer_t* tmr = (navi_timer_t*) h;
	if (!tmr)
		return;

	if (tmr->stage == NAVI_TIMER_ZOMBIE) {
		return;
	}

	if (tmr->stage == NAVI_TIMER_CANCEL) {
		navi_timer_canceled(tmr);
		return;
	}

	if (tmr->handler)
		(tmr->handler)(tmr->args);

	if (tmr->type == NAVI_TIMER_ONCE) {
		navi_timer_canceled(tmr);
	}
}

bool navi_timer_is_zombie(navi_timer_h h)
{
	navi_timer_t* tmr = (navi_timer_t*) h;
	if (!tmr)
		return false;

	return tmr->stage == NAVI_TIMER_ZOMBIE;
}
