/*
 * navi_vevent_mgr.h
 *
 *  Created on: 2014-04-08
 *      Author: yanguotao@youku.com
 */

#ifndef NAVI_VEVENT_MGR_H_
#define NAVI_VEVENT_MGR_H_

#include "navi_common_define.h"
#include "navi_request.h"
#include "navi_simple_hash.h"
#include "navi_gr_iter.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum _navi_vevent_action_e
{
	NAVI_VE_TRIGGER_NONE,
	NAVI_VE_TRIGGER_ONE,
	NAVI_VE_TRIGGER_ALL
}navi_vevent_action_e;

typedef enum _navi_vhandler_status_e
{
	NAVI_VH_DENY,
	NAVI_VH_ACCEPT,
	NAVI_VH_ACCEPT_HOLD
}navi_vhandler_status_e;

typedef enum _navi_vevent_status_e
{
	NAVI_VE_IDLE,
	NAVI_VE_READY,
	NAVI_VE_ZOMBIE
}navi_vevent_status_e;

#define NAVI_VE_MAGIC 0x88ae7fda

typedef struct navi_vevent_s navi_vevent_t;
typedef int (*navi_vevent_handler_fp)(navi_request_t* req, navi_vevent_t *ve, void* ctx, void* ev_data);
typedef int (*navi_vevent_handler_reinit_fp)(navi_request_t* req, navi_vevent_t *ve, void* ctx);
typedef int (*navi_vevent_imp_destroy_fp)( void* imp);

typedef struct navi_vehandler_s
{
	navi_request_t *binded_req;
	navi_vevent_t* ve;
	navi_vevent_handler_fp handler;
	navi_vevent_handler_reinit_fp reinit;
	void* ctx;
	chain_node_t req_link;
	chain_node_t ve_link;
}navi_vehandler_t;

typedef int (*navi_vevent_proc_fp)(navi_vevent_t *ve);
typedef int (*navi_vevent_reset)(navi_vevent_t *ve);
typedef void (*navi_vevent_trigger_free)(void* trigger_data);
struct navi_vevent_s
{
	char *name;
	void *trigger_data;
	navi_vevent_trigger_free trig_free;
	navi_vevent_proc_fp proc;
	navi_vevent_reset reset;
	navi_vevent_imp_destroy_fp destroy;
	chain_node_t vh_link;
	chain_node_t status_link;
	navi_vevent_status_e status;
	void *imp;
	navi_griter_mgr_t vh_its;
	uint32_t _magic;
};

typedef struct navi_vevent_mgr_s
{
	chain_node_t ready_link;
	chain_node_t clean_link; //即使vehandler全部摘下，也不直接destroyevent，分步处理
	navi_hash_t *hash;
}navi_vevent_mgr_t;

navi_vehandler_t * navi_request_join_vevent(navi_request_t* r, const char *name, navi_vevent_handler_fp handler, navi_vevent_handler_reinit_fp reinit, void *ctx);
void navi_request_quit_vevent(navi_request_t* r, const char* name);
void navi_request_quitall_vevent(navi_request_t* r);

void* navi_vevent_vh_it(navi_vevent_t* ve);
navi_vehandler_t* navi_vevent_vh_it_next(void* it);
void navi_vevent_vh_it_destroy(void* it);
void navi_vevent_advance_vhiters(navi_vevent_t* ve, navi_vehandler_t* vh);

navi_vevent_t *navi_vevent_get(const char *name);
void navi_vevent_ready(navi_vevent_t *ve, void* trigger_data, navi_vevent_trigger_free trig_free);
void navi_vevent_triggered(navi_vevent_t* ve);

//void navi_vevent_cancel(navi_vevent_t* ve);

void navi_vehandler_cancel(navi_vehandler_t* vh);

void navi_vevent_mgr_destroy(void);
navi_vevent_mgr_t *navi_vevent_mgr_get(void);
void navi_vevent_mgr_clean_zombie_ve(void);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_VEVENT_MGR_H_ */

