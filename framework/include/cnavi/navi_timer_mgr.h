/*
 * navi_timer_mgr.h
 *
 *  Created on: 2013-9-2
 *      Author: li.lei
 */

#ifndef NAVI_TIMER_MGR_H_
#define NAVI_TIMER_MGR_H_

#include "navi_common_define.h"
#include "navi_gr_iter.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum _navi_timer_type_e
{
	NAVI_TIMER_INVALID_TYPE,
	NAVI_TIMER_INTERVAL,
	NAVI_TIMER_ONCE
} navi_timer_type_e;

typedef enum _navi_timer_stage_e
{
	NAVI_TIMER_REGISTED,
	NAVI_TIMER_RUNNING,
	NAVI_TIMER_CANCEL,
	NAVI_TIMER_ZOMBIE //½©Ê¬timer
} navi_timer_stage_e;

typedef void* navi_timer_h;
typedef int (*timer_handler_fp)(void* timer_args);

typedef struct navi_timer_s
{
	timer_handler_fp handler;
	timer_handler_fp destroyer;
	void* args;
	void* driver_peer;
	void (*driver_cancel_handler)(struct navi_timer_s* driver_peer);
	void* navi_ctx;
	navi_timer_type_e type;
	uint32_t to_ms;

	chain_node_t link;
	void* mgr;
	navi_timer_stage_e stage;
	int stick;
} navi_timer_t;

typedef struct navi_timer_mgr_s
{
	chain_node_t regist;
	chain_node_t running;
	chain_node_t cancel;
	navi_griter_mgr_t it_mgr;
} navi_timer_mgr_t;

void navi_timer_mgr_init(navi_timer_mgr_t* mgr);
void navi_timer_mgr_clean(navi_timer_mgr_t* mgr);
void navi_timer_mgr_cancelall(navi_timer_mgr_t* mgr);
void navi_timer_mgr_clean_spec(navi_timer_mgr_t* mgr, void* according_ctx);

navi_timer_h navi_timer_add(navi_timer_mgr_t *mgr, navi_timer_type_e type,
    uint32_t to_ms, timer_handler_fp fun, void* args,
    timer_handler_fp destroyer, void* ctx);
void navi_timer_cancel(navi_timer_h h);

void* navi_timer_iter(navi_timer_mgr_t* mgr, navi_timer_stage_e e);
navi_timer_h navi_timer_iter_next(void* it);
void navi_timer_iter_destroy(void* it);

navi_timer_h navi_timer_get(navi_timer_mgr_t* mgr, navi_timer_stage_e e);

void navi_timer_running(navi_timer_h h, void* drive_ctx);
void navi_timer_canceled(navi_timer_h h);
void navi_timer_timeout(navi_timer_h h);
bool navi_timer_is_zombie(navi_timer_h h);
void navi_timer_cleanup(navi_timer_h h);

typedef void* (*navi_timer_driver_install_fp)(navi_timer_t* timer);
typedef void (*navi_timer_driver_cancel_fp)(navi_timer_t* driver);
static inline void navi_timer_bind_driver(navi_timer_h h, void* driver, navi_timer_driver_cancel_fp clean)
{
	navi_timer_t* tmr = (navi_timer_t*)h;
	tmr->driver_peer = driver;
	tmr->driver_cancel_handler = clean;
}

#ifdef __cplusplus
}
#endif

#endif /* NAVI_TIMER_MGR_H_ */
