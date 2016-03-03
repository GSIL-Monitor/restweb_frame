/*
 * navi_module.c
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 */

#include "navi_module_impl.h"
#include "navi_module_mgr.h"
#include "navi_request_impl.h"
#include "navi_frame_log.h"
#include "navi_task_mgr.h"

#define RESP_HEADER_MODULE_METHOD "Module-method"
int navi_module_default_process(navi_module_t* mh, navi_request_t* rh)
{
	if (!check_navi_mod_h(mh) || !check_req_h(rh))
		return NAVI_ARG_ERR;

	navi_module_impl_t* mod = navi_mod_h2i(mh);
	navi_request_impl_t* req = navi_req_h2i(rh);

	if (req->main != req)
		return NAVI_ARG_ERR;

	if (req->main_data->method == NULL || 0==strlen(req->main_data->method))
		return NAVI_ARG_ERR;

	navi_method_proc_t* mt_fp = (navi_method_proc_t*) navi_hash_get_gr(mod->methods,
		req->main_data->method);

	if (!mt_fp) {
		char tmp_buf[256];
		snprintf(tmp_buf, sizeof(tmp_buf), "Module:%s method:%s not found",
		    req->main_data->module, req->main_data->method);
		navi_http_response_set_status(rh, 405);
		navi_http_response_set_header(rh, RESP_HEADER_MODULE_METHOD, tmp_buf);
		navi_response_set_desc( navi_request_response_obj(rh),405, mh->mod_name, tmp_buf );
		return NAVI_DENY;
	}

	return mt_fp->method(mh, rh);
}

navi_timer_h navi_module_add_interval_timer(navi_module_t* mh, uint32_t tm_ms,
    timer_handler_fp fun, void* args, timer_handler_fp destroy)
{
	if (!check_navi_mod_h(mh))
		return NULL;

	navi_module_impl_t* mi = navi_mod_h2i(mh);
	navi_module_mgr_t* navi_mgr = (navi_module_mgr_t*) mi->navi_mgr;
	navi_timer_mgr_t* timer_mgr = &navi_mgr->timer_mgr;

	navi_timer_h ret = navi_timer_add(timer_mgr, NAVI_TIMER_INTERVAL,
	    tm_ms, fun, args, destroy, mi);
	return ret;
}

navi_timer_h navi_module_add_once_timer(navi_module_t* mh, uint32_t tm_ms,
    timer_handler_fp fun, void* args, timer_handler_fp destroy)
{
	navi_module_impl_t* mi = navi_mod_h2i(mh);
	navi_module_mgr_t* navi_mgr = (navi_module_mgr_t*) mi->navi_mgr;
	navi_timer_mgr_t* timer_mgr = &navi_mgr->timer_mgr;

	return navi_timer_add(timer_mgr, NAVI_TIMER_ONCE, tm_ms, fun, args, destroy,
	    mi);
}

void navi_module_cancel_timer(navi_timer_h h)
{
	navi_timer_cancel(h);
}

navi_module_t* navi_request_current_module(navi_request_t* rh)
{
	if (!check_req_h(rh))
			return NULL;

	navi_request_impl_t* ri = navi_req_h2i(rh);
	navi_request_impl_t* root = ri->main;

	switch(root->main_data->cur_stage) {
	case NAVI_ROOT_STAGE_PREV_APP:
	case NAVI_ROOT_STAGE_POST_APP:
		if (root->ic_chain && root->ic_mod) {
			return root->ic_mod->module;
		}
		break;
	case NAVI_ROOT_STAGE_APP:
		if(root->app_mod) return root->app_mod;
		break;
	default:
		break;
	}
	return NULL;
}

navi_module_mono_mode_e navi_module_mono_mode(navi_module_t* mh)
{
	navi_module_impl_t* mi = navi_mod_h2i(mh);
	navi_module_mgr_t* navi_mgr = (navi_module_mgr_t*) mi->navi_mgr;
	if (navi_mgr->mono_ctrl == NULL) return NOT_MONO_MOD;

	navi_module_mono_ctrl_t* ctrl = (navi_module_mono_ctrl_t*)
		navi_hash_get_gr(navi_mgr->mono_ctrl, mh->mod_name);

	if (!ctrl) return NOT_MONO_MOD;
	if (ctrl->mono_run)
		return MONO_LEADER;
	else
		return MONO_FOLLOWER;
}

navi_pool_t* navi_module_pool(navi_module_t* mh)
{
	navi_module_impl_t* mi = navi_mod_h2i(mh);
	return mi->pool;
}
