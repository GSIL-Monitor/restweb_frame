/*
 * navi_upreq.c
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#include "navi_upreq.h"
#include "navi_upgroup_mgr.h"
#include "navi_frame_log.h"

int navi_upreq_init(navi_upreq_t* req)
{
	memset(&req->result, 0x00, sizeof(navi_upreq_result_t));
	memset(&req->policy, 0x00, sizeof(navi_upreq_policy_t));

	/****
	if (req->out_pack == NULL || 0 == navi_buf_chain_get_content(req->out_pack, NULL, 0)) {
		navi_upreq_error_lt(req, NVUP_RESULT_CLI_ERROR, -1,
		    "output package is empty. invalid proxy impl");
		return NAVI_INNER_ERR;
	}
	****/

	if (req->procs == NULL || req->bind_channel == NULL || req->group_name == NULL) {
		navi_upreq_error_lt(req, NVUP_RESULT_CLI_ERROR, -1,
		    "upreq parameters incomplete. invalid proxy impl");
		navi_upreq_destroy(req);
		navi_request_cancel(req->bind_channel);
		return NAVI_INNER_ERR;
	}

	req->policy.pool = req->pool;
	if (NAVI_OK != navi_upreq_resolve_policy(navi_upgroup_mgr_instance(NULL),
		req, &req->policy) ) {
		NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "upgroup:%s upreq init error. code:%d, desc:%s",
			req->group_name, req->result.code, req->result.session_err_desc);
		navi_upreq_destroy(req);
		navi_request_cancel(req->bind_channel);
		return NAVI_INNER_ERR;
	}
	return NAVI_OK;
}

void navi_upreq_destroy(navi_upreq_t* req)
{
	if (req->procs->destroy)
		(req->procs->destroy)(req);

	switch (req->result.content_type) {
	case NVUP_RESULT_DATA_JSON:
		json_decref(req->result.js);
		break;
	case NVUP_RESULT_DATA_HEAP_BIN:
		free(req->result.bin.data);
		break;
	default:
		break;
	}

	if (req->policy.gr_data)
		json_decref(req->policy.gr_data);
}

typedef struct nvup_saved_ctx_s {
	navi_upreq_t* inject;
	void* ctx_own;
	navi_request_process_fp process;
	navi_request_process_fp cleanup;
}nvup_saved_ctx_t;

static int navi_upreq_cleanup_handler(navi_request_t* req, void* up_ctx)
{
	nvup_saved_ctx_t*  sv = (nvup_saved_ctx_t*)up_ctx;
	navi_upreq_t* up_req = sv->inject;
	if (!up_ctx) return NAVI_OK;
	navi_upreq_destroy(up_req);
	if (sv->cleanup)
		sv->cleanup(req, sv->ctx_own);
	return NAVI_OK;
}

static int navi_upreq_process_handler(navi_request_t* req, void* up_ctx)
{
	nvup_saved_ctx_t*  sv = (nvup_saved_ctx_t*)up_ctx;
	navi_upreq_t* up_req = sv->inject;
	if (!up_ctx) return NAVI_OK;
	if (up_req->procs->proc_result)
		up_req->procs->proc_result(up_req, &up_req->result);

	if (up_req->result.code == NVUP_RESULT_CONN_FAILED ||
		up_req->result.code == NVUP_RESULT_RW_FAILED ||
		up_req->result.code == NVUP_RESULT_CONN_TIMEOUT ||
		up_req->result.code == NVUP_RESULT_RW_TIMEOUT) {

		navi_upgroup_mgr_t* mgr = navi_upgroup_mgr_instance(NULL);
		navi_upserver_t* srv = navi_upgroup_mgr_get_server(mgr, up_req->group_name, up_req->policy.server_name);
		navi_upserver_on_upreq_failed(srv, up_req->result.code);

	}
	if (sv->process)
		sv->process(req, sv->ctx_own);
	return NAVI_OK;
}

void navi_request_bind_upreq(navi_upreq_t* up, navi_request_t* binded)
{
	up->bind_channel = binded;
	up->pool = navi_request_pool(binded);

	nvup_saved_ctx_t* sv = navi_pool_calloc(up->pool, 1, sizeof(nvup_saved_ctx_t));
	sv->ctx_own  =  binded->ctx_own;
	sv->process = binded->process_own;
	sv->cleanup = binded->clean_up;
	sv->inject = up;

	binded->ctx_own = sv;
	binded->clean_up_own = navi_upreq_cleanup_handler;
	binded->process_own = navi_upreq_process_handler;
}

navi_upreq_t* navi_request_binded_upreq(navi_request_t* request)
{
	nvup_saved_ctx_t* sv = (nvup_saved_ctx_t*)request->ctx_own;
	if (sv) return sv->inject;
	return NULL;
}

int navi_upreq_proto_append_out(navi_upreq_t* req, uint8_t* o, size_t sz)
{
	if (req->out_pack == NULL) {
		req->out_pack = navi_buf_chain_init(navi_request_pool(req->bind_channel));
		if (req->out_pack == NULL) {
			navi_upreq_error_lt(req, NVUP_RESULT_INNER_ERROR, -1, "memory error");
			return NAVI_INNER_ERR;
		}
	}

	if (NAVI_OK != navi_buf_chain_append(req->out_pack, o, sz)) {
		navi_upreq_error_lt(req, NVUP_RESULT_INNER_ERROR, -1, "memory error");
		return NAVI_INNER_ERR;
	}

	return NAVI_OK;
}



const char* navi_upreq_get_policy_key(navi_upreq_t* up, const char* key)
{
	const char* ret = NULL;
	if ( up && up->procs && up->procs->get_policy_key ) {
		ret = up->procs->get_policy_key(up, key);
	}

	if (ret == NULL)
	{
		navi_request_t* req = navi_upreq_channel(up);
		if (0 == strcmp(key, "client_ip")) {
			return navi_request_cli_ip(req);
		}
		else if (0 == strcmp(key, "x-caller")) {
			return navi_request_xcaller(req);
		}
		else if (0 == strcmp(key, "service")) {
			return navi_request_service(req);
		}
		else if (0 == strcmp(key, "module")) {
			return navi_request_module(req);
		}
		else if (0 == strcmp(key, "method")) {
			return navi_request_method(req);
		}
		else {
			return navi_http_request_get_arg(req, key);
		}
	}
	else
		return ret;
}
