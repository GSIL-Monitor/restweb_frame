/*
 * navi_request_impl.c
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 */

#include "navi_request_impl.h"
#include "navi_request_driver.h"
#include "navi_request.h"
#include "navi_module_mgr.h"
#include "navi_module_impl.h"
#include "navi_frame_log.h"
#include "navi_request_common.c"
#include "navi_inner_util.h"
#include "navi_list.h"
#include <sys/time.h>

static int navi_request_check_main(navi_request_t* main);
static void navi_request_canceled( navi_request_impl_t* req);

int navi_request_parse_main_uri(navi_request_t* handle, const char* base, size_t base_len)
{
	if (!check_req_h(handle))
		return NAVI_ARG_ERR;

	navi_request_impl_t* main = navi_req_h2i(handle);
	main = main->main;

	if (!main->uri || strlen(main->uri) == 0)
		return NAVI_INNER_ERR;

	char* tmp_uri = NULL;
	if ( base && base[0]=='/' && base_len > 0) {
		tmp_uri = (char*) navi_pool_strdup(main->pool_storage, main->uri + base_len);
	}
	else {
		tmp_uri = (char*) navi_pool_strdup(main->pool_storage, main->uri);
	}

	if (!tmp_uri)
		return NAVI_INNER_ERR;

	char* tokctx;
	char* module = strtok_r(tmp_uri, "/", &tokctx);
	char* method = strtok_r(NULL, "/", &tokctx);

	if (!module || !method ) {
		return NAVI_CLI_ERR;
	}

	char* pdot = strstr(method, ".json");
	if (pdot) {
		if ( pdot != method ) {
			*pdot = 0;
		}
		else {
			return NAVI_CLI_ERR;
		}
	}

	if (!navi_is_symbol_word(module) || strlen(module)>64
		|| !navi_is_symbol_word(method) || strlen(method)>64 ) {
		return NAVI_CLI_ERR;
	}

	while ( *tokctx == '/' )
		tokctx++;

	if (*tokctx == 0)
		main->main_data->rest_uri = NULL;
	else {
		main->main_data->rest_uri = tokctx;
	}

	main->main_data->module = module;
	main->main_data->method = method;
	main->main_data->rest_uri = tokctx;
	return NAVI_OK;
}

void navi_request_set_status(navi_request_t* handle,
    navi_request_status_e status)
{
	if (!check_req_h(handle))
		return;
	navi_request_impl_t* req = navi_req_h2i(handle);

	if (req->navi_status == status)
		return;

	switch (req->navi_status)
	{
	case NAVI_REQUEST_REGISTED:
		if (status == NAVI_REQUEST_DRIVER_PROCESSING) {
			quit_reg_chain(req);
			navi_request_cost_ns(handle);
		}
		else
			goto error_status;
		break;
	case NAVI_REQUEST_CANCEL_REGISTED:
		if (status == NAVI_REQUEST_CANCELED) {
			req->navi_status = status;
			navi_request_canceled(req);
			return;
		}
		else
			goto error_status;
		break;
	case NAVI_REQUEST_DRIVER_PROCESSING:
		if (status != NAVI_REQUEST_FRAME_PROCESSING
		    && status != NAVI_REQUEST_CANCEL_REGISTED)
			goto error_status;
		break;
	case NAVI_REQUEST_FRAME_PROCESSING:
		if (status != NAVI_REQUEST_COMPLETE
		    && status != NAVI_REQUEST_PROC_FAILED)
			goto error_status;
		break;
	default:
		return;
	}

	req->navi_status = status;
	if (status == NAVI_REQUEST_PROC_FAILED) {
		if (req->pending_subs == 0) {
			if (req->handle.clean_up_own)
				(req->handle.clean_up_own)(&req->handle,req->handle.ctx_own);
			if (req->handle.clean_up)
				(req->handle.clean_up)(&req->handle,req->handle.custom_ctx);

			if (req->parent) {
				req->parent->pending_subs--;
			}

			if (req->recycle_flag)
				recycle_sub(req);
			else {
				if ( req->main != req )
					navi_request_cost_ns(handle);
				if (0 == navi_http_response_get_status(handle)) {
					navi_http_response_set_status(handle, 500);
					navi_http_response_set_header(handle, "Navi-Frame-Ctrl",
						"process failed");
				}
			}
		}
	}
	else if (status == NAVI_REQUEST_COMPLETE ) {
		if (req->handle.clean_up_own)
			(req->handle.clean_up_own)(&req->handle,req->handle.ctx_own);
		if (req->handle.clean_up)
			(req->handle.clean_up)(&req->handle,req->handle.custom_ctx);

		if (req->parent) {
			req->parent->pending_subs--;
		}

		if (req->recycle_flag)
			recycle_sub(req);
		else if ( req->main != req )
			navi_request_cost_ns(handle);
	}
	return;

error_status:
	NAVI_FRAME_LOG(NAVI_LOG_ERR,"invalid request status changing");
	return;
}

static void detach_all_subs(navi_request_t* handle)
{
	navi_request_impl_t* pr = navi_req_h2i(handle);
	navi_request_impl_t* sub = pr->child, *o;
	while (sub) {
		o = sub;
		sub = sub->next;
		if (o->navi_status == NAVI_REQUEST_REGISTED) {
			o->navi_status = NAVI_REQUEST_CANCELED;
			quit_reg_tree(o);
			recycle_sub(o);
			if (pr->pending_subs)
				pr->pending_subs--;
		}
		else if (o->navi_status == NAVI_REQUEST_DRIVER_PROCESSING||
			o->navi_status == NAVI_REQUEST_FRAME_PROCESSING) {
			navi_request_cancel(&o->handle);
		}
	}
}

static void call_process_step(navi_request_t* handle)
{
	int ret = 0;
	bool step_check = false;
	if (navi_request_get_status(handle) == NAVI_REQUEST_DRIVER_PROCESSING) {
		navi_request_set_status(handle, NAVI_REQUEST_FRAME_PROCESSING);
		if (handle->process_own) {
			ret = handle->process_own(handle, handle->ctx_own);
			if (ret) {
				detach_all_subs(handle);
				navi_request_set_status(handle, NAVI_REQUEST_PROC_FAILED);
			}
			handle->process_own = NULL;
		}
	}
	navi_request_impl_t* req = navi_req_h2i(handle);
//main_ctrl:

	if ( req->main != req ) {
		if (ret == 0 && req->pending_subs == 0 && handle->process_request) {
			navi_request_process_fp swp = handle->process_request;
			handle->process_request = NULL;
			ret = swp(handle, handle->custom_ctx);
			if (ret) {
				detach_all_subs(handle);
				navi_request_set_status(handle, NAVI_REQUEST_PROC_FAILED);
				handle->process_request = NULL;
			}
		}

		if ( req->pending_subs==0 && ret == 0)
			navi_request_set_status(handle, NAVI_REQUEST_COMPLETE);
	}
	else {
main_ctrl:
		if (ret==0 && req->pending_subs==0 && !navi_request_has_timers(handle)
			&& !navi_request_has_vh(handle) && handle->process_request) {
			navi_request_process_fp swp = handle->process_request;
			handle->process_request = NULL;
			ret = swp(handle, handle->custom_ctx);
			if (ret && ret!=NAVI_CONCLUDED && ret!=NAVI_DENY) {
				detach_all_subs(handle);
				navi_http_request_abort_bigpost(handle);
				navi_timer_mgr_cancelall(&req->main_data->timers);
				navi_request_quitall_vevent(req);
				navi_request_set_status(handle, NAVI_REQUEST_PROC_FAILED);
				handle->process_request = NULL;
				if ( req->main == req )
					req->navi_status = NAVI_REQUEST_COMPLETE;
			}
			else if (ret==NAVI_CONCLUDED || ret == NAVI_DENY) {
				navi_module_impl_t* mod_impl = NULL;
				switch(req->main_data->cur_stage) {
				case NAVI_ROOT_STAGE_PREV_APP:
				{
					mod_impl = navi_mod_h2i(req->ic_mod->module);
					if(req->main_data->cur_ctrl==NAVI_ROOT_NO_CTRL) {
						if(ret==NAVI_CONCLUDED&&(mod_impl->ret_ctrl_mask&NAVI_IC_ALLOW_CONCLUDE)) {
							req->main_data->cur_ctrl = NAVI_ROOT_CONCLUDE;
						}
						else if(ret==NAVI_DENY&&(mod_impl->ret_ctrl_mask&NAVI_IC_ALLOW_DENEY)) {
							req->main_data->cur_ctrl = NAVI_ROOT_DENYED;
						}
					}
				}
				break;
				case NAVI_ROOT_STAGE_APP:{
					mod_impl = navi_mod_h2i(req->app_mod);
					if(req->main_data->cur_ctrl==NAVI_ROOT_NO_CTRL) {
						if(ret==NAVI_DENY&&(mod_impl->ret_ctrl_mask&NAVI_IC_ALLOW_DENEY)) {
							req->main_data->cur_ctrl = NAVI_ROOT_DENYED;
							navi_http_request_abort_bigpost(handle);
						}
					}
				}
				break;
				case NAVI_ROOT_STAGE_POST_APP:{
					mod_impl = navi_mod_h2i(req->ic_mod->module);
					if(req->main_data->cur_ctrl==NAVI_ROOT_NO_CTRL) {
						if(ret==NAVI_DENY&&(mod_impl->ret_ctrl_mask&NAVI_IC_ALLOW_DENEY)) {
							req->main_data->cur_ctrl = NAVI_ROOT_DENYED;
						}
					}
				}
				break;
				default:
					break;
				}
				ret = 0;
			}
		}

		if ( ret || (req->pending_subs == 0 && !navi_request_has_timers(handle) && !navi_request_has_vh(handle))) {
			if (req->main_data->cur_stage != NAVI_ROOT_STAGE_FINALIZED) {
				if (step_check==false) {
					handle->process_request = navi_mgr_step_request;
					ret = 0;
					step_check = true;
					goto main_ctrl;
				}
				else
					return;
			}

			if ( ret==0 ) {
				navi_request_set_status(handle, NAVI_REQUEST_COMPLETE);
			}
		}
	}
}

static void navi_request_canceled( navi_request_impl_t* req)
{
	navi_request_impl_t* parent = req->parent, *sv;

	quit_cancel_chain(req);

	if (req->pending_subs <= 0) {
		req->pending_subs = 0;

		if (req->handle.clean_up_own)
			(req->handle.clean_up_own)(&req->handle,req->handle.ctx_own);
		if (req->handle.clean_up)
			(req->handle.clean_up)(&req->handle,req->handle.custom_ctx);
		navi_request_impl_t* parent = req->parent;
		if ( req->recycle_flag )
			recycle_sub(req);
		else {
			if (0 == navi_http_response_get_status(&req->handle)) {
				navi_http_response_set_status(&req->handle, 500);
				navi_http_response_set_header(&req->handle, "Navi-Frame-Ctrl",
					"canceled");
			}
			navi_request_cost_ns(&req->handle);
		}
		if (parent && parent->pending_subs > 0)
			parent->pending_subs--;

		while(parent) {
			sv = parent;
			parent = parent->parent;

			if (sv->pending_subs <= 0) {
				sv->pending_subs = 0;

				if (sv->navi_status == NAVI_REQUEST_CANCELED ||
					sv->navi_status == NAVI_REQUEST_PROC_FAILED ) {
					if (sv->handle.clean_up_own)
						(sv->handle.clean_up_own)(&req->handle,req->handle.ctx_own);
					if (sv->handle.clean_up)
						(sv->handle.clean_up)(&req->handle,req->handle.custom_ctx);
					if (parent && parent->pending_subs>0 ) {
						parent->pending_subs--;
					}
					if ( sv->recycle_flag )
						recycle_sub(sv);
					else {
						if (0 == navi_http_response_get_status(&sv->handle)) {
							navi_http_response_set_status(&sv->handle, 500);
							navi_http_response_set_header(&sv->handle, "Navi-Frame-Ctrl",
								sv->navi_status == NAVI_REQUEST_CANCELED?"canceled":"process failed");
						}
						navi_request_cost_ns(&sv->handle);
					}
				}
				else if (sv->navi_status == NAVI_REQUEST_FRAME_PROCESSING) {
					call_process_step(&sv->handle);
				}
				else
					break;
			}
			else
				break;
		}
	}
}

void navi_request_call_process(navi_request_t* handle)
{
	if (!check_req_h(handle))
		return;

	navi_request_impl_t* req = navi_req_h2i(handle);
	if (req->navi_status != NAVI_REQUEST_DRIVER_PROCESSING &&
		req->navi_status != NAVI_REQUEST_FRAME_PROCESSING)
		return;
	req->own_resp_arrived = 1; //true;
	navi_request_impl_t* parent = req->parent , *o;
	call_process_step(handle);

	while (parent) {
		if (parent->pending_subs == 0 && parent->own_resp_arrived) {
			o = parent;
			parent = parent->parent;
			call_process_step(&o->handle);
			if (o->navi_status == NAVI_REQUEST_STATUS_INVALID  ||
				o->navi_status == NAVI_REQUEST_COMPLETE ||
				o->pending_subs == 0) {
				//parent = parent->parent;
				continue;
			}
			else
				break;
		}
		else
			break;
	}
}

void navi_request_bigpost_prepare(navi_request_t* handle, const char* file_path )
{
	if (!check_req_h(handle))
		return;

	navi_request_impl_t* req = navi_req_h2i(handle);
	if ( req->main != req )
		return;
	if	(req->navi_status != NAVI_REQUEST_FRAME_PROCESSING)
		return;
	if (!req->main_data->bigpost_file)
		return;

	req->main_data->bigpost_temp_file = navi_pool_strdup(req->pool_storage, file_path);
	return;
}

void navi_request_bigpost_ready(navi_request_t* handle)
{
	if (!check_req_h(handle))
		return;

	navi_request_impl_t* req = navi_req_h2i(handle);
	if ( req->main != req )
		return;
	if	(req->navi_status != NAVI_REQUEST_FRAME_PROCESSING)
		return;

	if (!req->main_data->bigpost_file)
		return;


	req->main_data->bigpost_complete = 1;
	if ( req->main_data->bigpost_temp_file == NULL)
		return;

	if ( req->main_data->cur_stage == NAVI_ROOT_STAGE_APP ) {
		navi_mgr_step_request(handle,NULL);
	}
	assert(req->main_data->cur_stage > NAVI_ROOT_STAGE_APP);
	return;
}

#define INIT_POOL_SIZE (sizeof(navi_request_impl_t)+0x1000)

navi_request_t* navi_request_init()
{
	navi_request_impl_t* req = (navi_request_impl_t*) malloc(INIT_POOL_SIZE);
	if (req == NULL) {
		NAVI_SYSERR_LOG();
		return NULL;
	}

	memset(req, 0x00, sizeof(navi_request_impl_t) + sizeof(navi_pool_t));
	req->handle._magic = NAVI_HANDLE_MAGIC;
	navi_pool_init(req->pool_storage, req, 0x1000);

	req->main = req;

	navi_list_init(&req->rest_drive_link);
	int ret = navi_request_check_main(&req->handle);
	if (ret != NAVI_OK) {
		NAVI_SYSERR_LOG();
		navi_request_free(&req->handle);
		return NULL;
	}
	req->own_resp_arrived = 1; //true;

	return &req->handle;
}

static void navi_request_clean( navi_request_impl_t* req) {
	navi_request_impl_t* next = req->child;
	while (next) {
		navi_request_clean(next);
		next = next->next;
	}

	navi_pool_destroy(req == req->main ? req->pool_storage : req->cld_dp);
}

void navi_request_free(navi_request_t* h)
{
	if (!check_req_h(h))
		return;
	navi_request_impl_t* req = navi_req_h2i(h);
	if (req->main != req)
		return;

	navi_list_remove(&req->rest_drive_link);

	if ( req->main_data->bigpost_file ) {
		if (req->main_data->bigpost_temp_file && req->main_data->bigpost_abort)
			unlink(req->main_data->bigpost_temp_file);
	}

	if (req->main_data) {
		if (req->main_data->resp)navi_response_clean(req->main_data->resp);
		chain_node_t* link = req->main_data->recycle_chain.next;
		navi_request_impl_t* recycled;
		while ( link != & req->main_data->recycle_chain ) {
			recycled = (navi_request_impl_t*)((char*)link - offsetof(navi_request_impl_t, cmd_link));
			navi_pool_destroy(recycled->cld_dp);
			link = link->next;
		}

		navi_timer_mgr_clean(&req->main_data->timers);
	}
	navi_request_clean(req);
}

void navi_request_reset(navi_request_t* h)
{
	if (!check_req_h(h))
		return;
	navi_request_impl_t* req = navi_req_h2i(h);
	if (req->main != req)
		return;
	navi_response_clean(req->main_data->resp);

	navi_request_impl_t* next = req->child;
	while (next) {
		navi_request_clean(next);
		next = next->next;
	}

	chain_node_t* link = req->main_data->recycle_chain.next;
	navi_request_impl_t* recycled;
	while ( link != & req->main_data->recycle_chain ) {
		recycled = (navi_request_impl_t*)((char*)link - offsetof(navi_request_impl_t, cmd_link));
		navi_pool_destroy(recycled->cld_dp);
		link = link->next;
	}
	memset(req, 0x00, sizeof(navi_request_impl_t));
	navi_pool_reset(req->pool_storage);
}

static int navi_request_check_main(navi_request_t* main)
{
	navi_request_impl_t* req = navi_req_h2i(main);
	req = req->main;

	if (!req->main_data) {
		navi_main_req_data_t *main_data = (navi_main_req_data_t*) navi_pool_calloc(
		    req->pool_storage, 1, sizeof(navi_main_req_data_t));

		if (!main_data)
			return NAVI_INNER_ERR;

		navi_list_init(&main_data->ve_link);
		navi_list_init(&main_data->reg_chain);
		navi_list_init(&main_data->cancel_chain);
		navi_list_init(&main_data->recycle_chain);
		navi_griter_mgr_init(&main_data->iter_mgr, req->pool_storage);
		navi_timer_mgr_init(&main_data->timers);

		main_data->auto_finalize = 1;
		main_data->file_body_fd = -1;

		req->main_data = main_data;
	}

	return NAVI_OK;
}

int navi_request_set_xcaller(navi_request_t* main, const char* xcaller)
{
	if (!xcaller || strlen(xcaller) == 0)
		return NAVI_ARG_ERR;
	int ret = navi_request_check_main(main);
	if (ret != NAVI_OK)
		return ret;

	navi_request_impl_t* req = navi_req_h2i(main);

	req->main_data->xcaller = navi_pool_strdup(req->pool_storage, xcaller);
	if (req->main_data->xcaller == NULL) {
		NAVI_SYSERR_LOG();
		return NAVI_INNER_ERR;
	}

	return NAVI_OK;
}

int navi_request_set_cli_ip(navi_request_t* main, const char* cli_ip)
{
	if (!cli_ip || strlen(cli_ip) == 0)
		return NAVI_ARG_ERR;
	int ret = navi_request_check_main(main);
	if (ret != NAVI_OK)
		return ret;

	navi_request_impl_t* req = navi_req_h2i(main);

	req->main_data->cli_ip = navi_pool_strdup(req->pool_storage, cli_ip);
	if (req->main_data->cli_ip == NULL) {
		NAVI_SYSERR_LOG();
		return NAVI_INNER_ERR;
	}
	return NAVI_OK;
}

void* navi_request_get_driver_peer(navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;
	navi_request_impl_t* req = navi_req_h2i(h);
	return req->driver_peer;
}

void navi_request_set_driver_peer(navi_request_t* h,void* peer,void* (*get_peer_pool)(void*))
{
	if (!check_req_h(h))
		return;
	navi_request_impl_t* req = navi_req_h2i(h);
	req->driver_peer = peer;
	if ( req->main == req ) {
		req->main_data->get_driver_peer_pool = get_peer_pool;
	}
}

/***************************************************
 * 子请求遍历iterator管理
 ***************************************************/

void* navi_request_regist_iter(navi_request_t* mh)
{
	if (!check_req_h(mh))
		return NULL;

	navi_request_impl_t* main = (navi_req_h2i(mh))->main;
	navi_griter_t* iter = navi_griter_get(&main->main_data->iter_mgr);
	iter->_magic = NAVI_ITER_REG_MAGIC;
	iter->ctx = (void*) &main->main_data->reg_chain;
	iter->cur = (void*) main->main_data->reg_chain.next;
	return iter;
}

navi_request_t* navi_request_regist_iter_next(void* iter)
{
	navi_griter_t* it = (navi_griter_t*) iter;
	if (!it || it->_magic != NAVI_ITER_REG_MAGIC)
		return NULL;

	if (it->cur == it->ctx)
		return NULL;

	navi_request_t* ret = (navi_request_t*)navi_list_data(it->cur,navi_request_impl_t,cmd_link);
	it->cur = ((chain_node_t*) it->cur)->next;
	return ret;
}

void navi_request_regist_iter_destroy(void* it)
{
	navi_griter_t* iter = (navi_griter_t*) it;
	if (!iter || iter->_magic != NAVI_ITER_REG_MAGIC)
		return;
	navi_griter_recycle(iter);
}

void* navi_request_cancel_iter(navi_request_t* mh)
{
	if (!check_req_h(mh))
		return NULL;

	navi_request_impl_t* main = (navi_req_h2i(mh))->main;
	navi_griter_t* iter = navi_griter_get(&main->main_data->iter_mgr);
	iter->cur = (void*) main->main_data->cancel_chain.next;
	iter->_magic = NAVI_ITER_CANCEL_MAGIC;
	iter->ctx = (void*) &main->main_data->cancel_chain;
	return iter;
}

navi_request_t* navi_request_cancel_iter_next(void* iter)
{
	navi_griter_t* it = (navi_griter_t*) iter;
	if (!it || it->_magic != NAVI_ITER_CANCEL_MAGIC)
		return NULL;

	if (it->cur == it->ctx)
		return NULL;

	navi_request_t* ret = (navi_request_t*)navi_list_data(it->cur,navi_request_impl_t,cmd_link);
	it->cur = ((chain_node_t*) it->cur)->next;
	return ret;
}

void navi_request_cancel_iter_destroy(void* it)
{
	navi_griter_t* iter = (navi_griter_t*) it;
	if (!iter || iter->_magic != NAVI_ITER_CANCEL_MAGIC)
		return;
	navi_griter_recycle(iter);
}

bool navi_request_has_vh(navi_request_t* rh)
{
	navi_request_impl_t* ri = navi_req_h2i(rh);
	if ( ri != ri->main ) return false;

	if (navi_list_empty(&ri->main_data->ve_link))
		return false;

	return true;
}

bool navi_request_has_timers(navi_request_t* rh )
{
	navi_request_impl_t* ri = navi_req_h2i(rh);
	if ( ri != ri->main ) return false;

	if (!navi_list_empty(&ri->main_data->timers.regist) ||
		!navi_list_empty(&ri->main_data->timers.running))
		return true;

	return false;
}

bool navi_request_can_step(navi_request_t* rh)
{
	navi_request_impl_t* ri = navi_req_h2i(rh);
	if ( ri != ri->main ) return false;

	if ( ri->pending_subs > 0 ) {
		return false;
	}

	if (!navi_list_empty(&ri->main_data->timers.regist) ||
		!navi_list_empty(&ri->main_data->timers.running))
		return false;

	if (!navi_list_empty(&ri->main_data->ve_link))
		return false;

	navi_main_req_data_t* main_data = ri->main_data;
	if ( !main_data->auto_finalize )
		return false;

	if ( main_data->outbody_stream && !main_data->outbody_stream_eof )
		return false;

	if ( main_data->bigpost_file && (main_data->bigpost_complete == 0  && main_data->bigpost_abort == 0))
		return false;

	return true;
}

navi_timer_mgr_t* navi_request_timers(navi_request_t* rh)
{
	navi_request_impl_t* ri = navi_req_h2i(rh);
	if ( ri != ri->main ) return NULL;
	return &ri->main_data->timers;
}

void* navi_request_get_driver_pool(navi_request_t* req)
{
	navi_request_impl_t* ri = navi_req_h2i(req);
	return ri->main->main_data->get_driver_peer_pool(ri->driver_peer);
}

bool navi_request_incomplete(navi_request_t* main)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	navi_main_req_data_t* data = ri->main->main_data;
	if (data->bigpost_file) {
		if (data->bigpost_abort || data->bigpost_complete ==0)
			return true;
	}

	if (data->outbody_stream) {
		if (data->outbody_stream_eof==0 || data->outbody_stream_incomplete)
			return true;
	}

	return false;
}

void navi_request_drive_flag(navi_request_t* main, navi_request_drive_type_e type)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( type == NAVI_REQ_DRIVE_FROM_REST) {
		ri->main->drive_from_rest = 1;
	}
	else {
		ri->main->drive_from_rest = 0;
	}
}

void navi_request_drive_flag_reset(navi_request_t* main)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	ri->main->drive_from_rest = 1;
}

static void (*s_trigger_request_rest_drive)() = NULL;
static void (*s_request_rest_drive)(navi_request_t* main) = NULL;
static chain_node_t s_rest_driving_reqs = {&s_rest_driving_reqs,&s_rest_driving_reqs};

void navi_request_driver_rest_hook(
	void (*drive_trigger)(),
	void (*drive_handler)(navi_request_t* main)
)
{
	s_trigger_request_rest_drive = drive_trigger;
	s_request_rest_drive = drive_handler;
}

void navi_request_trigger_rest_drive(navi_request_t* main)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( ri->main != ri ) return;

	if ( navi_list_empty(&ri->rest_drive_link) ) {
		navi_list_insert_tail(&s_rest_driving_reqs, &ri->rest_drive_link);
		//printf("trigger rest drive for:%p %08x\n", main, main->_magic);
		s_trigger_request_rest_drive();
	}
}

void navi_request_rest_drive()
{
	chain_node_t* nd = s_rest_driving_reqs.next;
	chain_node_t tmp = {&tmp, &tmp};
	while ( nd != &s_rest_driving_reqs ) {
		navi_request_impl_t* req = navi_list_data(nd, navi_request_impl_t, rest_drive_link);
		assert( check_req_h(&req->handle) );
		nd = nd->next;
		navi_list_remove(&req->rest_drive_link);
		navi_list_insert_tail(&tmp, &req->rest_drive_link);
		//s_request_rest_drive(&req->handle);
	}

	nd = tmp.next;
	while ( nd != &tmp) {
		navi_request_impl_t* req = navi_list_data(nd, navi_request_impl_t, rest_drive_link);
		//printf("rest drive for %p %08x\n", &req->handle, req->handle._magic);
		assert( check_req_h(&req->handle) );
		nd = nd->next;
		navi_list_remove(&req->rest_drive_link);
		s_request_rest_drive(&req->handle);
	}
}

navi_buf_chain_t* navi_request_get_streaming(navi_request_t* main, ssize_t* streaming_sz, bool *is_abort)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if (ri->main != ri ) return NULL;
	if (ri->main_data->outbody_stream == 0) return NULL;
	if ( streaming_sz ) {
		*streaming_sz = ri->main_data->streaming_body_total;
	}
	if ( is_abort ) {
		*is_abort = ri->main_data->outbody_stream_incomplete != 0;
	}
	return ri->main_data->streamed_body_buf;
}

bool navi_request_should_emerg_resp(navi_request_t* rh)
{
	navi_request_impl_t* ri = navi_req_h2i(rh);
	if ( ri != ri->main ) return false;
	return ri->main_data->should_emerg_resp;
}
