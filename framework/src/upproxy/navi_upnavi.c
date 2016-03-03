/*
 * navi_upnavi.c
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#include "navi_inner_util.h"
#include "navi_upnavi.h"
#include "navi_upgroup_mgr.h"

static const char* nvup_navi_get_policy_key(navi_upreq_t* up, const char* key);
static void nvup_navi_build_navi_resp(navi_upreq_t* up, navi_upreq_result_t* result);
static void nvup_navi_destroy(navi_upreq_t* up);

navi_upreq_proc_t g_nvup_navi_proc =
{
	nvup_navi_get_policy_key,
	NULL,
	nvup_navi_build_navi_resp,
	nvup_navi_destroy
};

navi_upnavi_t* navi_request_bind_upnavi_ctx(navi_request_t* binded,
    const char* srv_grp, const char* module,
    const char* method, const char* xcaller,const char* remote_root_uri,
    navi_upnavi_proc_result_fp process, void* ctx,
    navi_upnavi_cleanup_ctx_fp cleanup)
{
	navi_pool_t* pool = navi_request_pool(binded);
	navi_upnavi_t* obj = (navi_upnavi_t*)navi_pool_calloc(pool, 1, sizeof(navi_upnavi_t));
	if (!obj)
		return NULL;


	obj->base.group_name = navi_pool_strdup(pool,srv_grp);
	obj->base.procs = &g_nvup_navi_proc;
	obj->base.proto = NVUP_PROTO_NAVI;
	obj->base.out_pack = NULL;
	if (remote_root_uri && strlen(remote_root_uri)) {
		obj->root_uri = navi_pool_strdup(pool,remote_root_uri);
	}
	obj->module = navi_pool_strdup(pool, module);
	obj->method = navi_pool_strdup(pool, method);
	obj->process = process;
	obj->cleanup = cleanup;
	obj->ctx = ctx;

	if (xcaller && strlen(xcaller)) {
		obj->xcaller = navi_pool_strdup(pool, xcaller);
		navi_http_request_set_header(binded, "x-caller", xcaller);
	}

	navi_request_bind_upreq(&obj->base, binded);
	return obj;
}

navi_upnavi_t* navi_request_bind_upnavi_ctx_ext(navi_request_t* binded,
    const char* srv_grp, const char* srv_name, const char* module,
    const char* method, const char* xcaller,const char* remote_root_uri,
    navi_upnavi_proc_result_fp process, void* ctx,
    navi_upnavi_cleanup_ctx_fp cleanup)
{
	navi_upnavi_t* obj = navi_request_bind_upnavi_ctx(binded, srv_grp, module, method, 
		xcaller, remote_root_uri, process, ctx, cleanup);
	if (!obj)
		return NULL;
	if (srv_name){
		obj->base.srv_name = navi_request_strdup(binded,srv_name);
	}
	
	return obj;
}

int navi_upnavi_launch(navi_upnavi_t* up)
{
	if (NAVI_OK != navi_upreq_init(&up->base)) {
		return NAVI_INNER_ERR;
	}
	navi_upgroup_mgr_t* mgr = navi_upgroup_mgr_instance(NULL);

	navi_upreq_policy_t *policy = &up->base.policy;
	const char* driver_uri = mgr->http_driver_path;

	char* inner_uri = navi_build_uri(5, driver_uri, policy->root_uri, up->root_uri,
		up->module, up->method);

	navi_http_request_set_uri(up->base.bind_channel, inner_uri, 0);
	free(inner_uri);

	navi_hent_t* he;
	void* it;
	if (policy->gr_args) {
		it = navi_hash_iter(policy->gr_args);
		while ((he=navi_hash_iter_next(it))) {
			navi_http_request_set_arg(up->base.bind_channel, he->k, (const char*)he->v);
		}
		navi_hash_iter_destroy(it);
	}

	if (policy->gr_headers) {
		it = navi_hash_iter(policy->gr_headers);
		while ((he=navi_hash_iter_next(it))) {
			if ( strcasecmp(he->k, "x-caller")==0 && up->xcaller ) {
				continue;
			}
			navi_http_request_set_header(up->base.bind_channel, he->k, (const char*)he->v);
		}
		navi_hash_iter_destroy(it);
	}

	up->cost = - cur_time_us();
	return NAVI_OK;
}

static const char* nvup_navi_get_policy_key(navi_upreq_t* up, const char* key)
{
	navi_upnavi_t* up_navi = (navi_upnavi_t*) ((char*) up -
	    offsetof(navi_upnavi_t, base));
	const char* probe_arg = NULL;
	if ( (probe_arg = navi_http_request_get_arg(up->bind_channel, key)) ) {
		return probe_arg;
	}
	else if ( 0 == strcasecmp("module", key) ) {
		return up_navi->module;
	}
	else if ( 0 == strcasecmp("method", key) ) {
		return up_navi->method;
	}
	else if ( 0 == strcasecmp("x-caller", key) ) {
		return up_navi->xcaller;
	}
	else if ( 0 == strcasecmp("root", key) ) {
		return up_navi->root_uri;
	}
	return NULL;
}

static void nvup_navi_build_navi_resp(navi_upreq_t* up, navi_upreq_result_t* result)
{
	navi_upnavi_t* up_navi = (navi_upnavi_t*)((char*)up - offsetof(navi_upnavi_t, base));
	json_t* up_json = NULL;
	json_error_t js_err;

	if (up_navi->process == NULL)
		return;

	navi_response_t resp;
	memset(&resp, 0x00, sizeof(navi_response_t));

	up_navi->cost += cur_time_us();
	resp.cost = (double)up_navi->cost / 1000000;
	resp.error.code = 0x7fffffff;
	resp.error.provider = "navi uprequest proxy";

	if (result->code != NVUP_RESULT_UNSET) {
		resp.error.code = result->code;
		resp.error.desc = "navi upproxy error";
		if (result->err)
			resp.error.desc = result->err;
	}
	else {
		result->code = NVUP_RESULT_SESSION_OK;
		result->ess_logic_code = 0;
		int http_code = navi_http_response_get_status(up->bind_channel);
		resp.http_size  = navi_http_response_get_body(up->bind_channel,(const uint8_t**) &resp.http);

		if (resp.http_size == 0) {
			result->content_type = NVUP_RESULT_DATA_NULL;
		}
		else {
			up_json = json_loads(resp.http, &js_err);
			if (up_json) {
				result->content_type = NVUP_RESULT_DATA_JSON;
				result->js = up_json;
				resp.json_response = up_json;
				json_t* js_e = json_object_get(up_json, "e");
				if (js_e && json_is_object(js_e)) {
					json_t* je = json_object_get(js_e, "code");
					resp.error.desc = resp.error.provider = NULL;
					if (je && json_is_number(je)) {
						resp.error.code = (int)json_number_value(je);
					}
					je = json_object_get(js_e, "desc");
					if (je && json_is_string(je)) {
						resp.error.desc = (char*)json_string_value(je);
					}
					je = json_object_get(js_e, "provider");
					if (je && json_is_string(je)){
						resp.error.provider = (char*)json_string_value(je);
					}
				}
			}
			else {
				result->content_type = NVUP_RESULT_DATA_POOL_BIN;
				result->bin.data = (uint8_t*)resp.http;
				result->bin.size = resp.http_size;
			}
		}

		if (http_code==200) {
			if (resp.error.code == 0x7fffffff) {
				resp.error.code = 0;
				resp.error.desc = "success";
			}
			if (!up_json) {
				resp.error.desc = "http 200 OK but not navi response";
			}
		}
		else {
			if (resp.error.code == 0x7fffffff) {
				resp.error.code = http_code;
				resp.error.desc = "http error";
			}
		}
	}

	up_navi->process(up_navi, &resp, up_navi->ctx);
	return;
}

static void nvup_navi_destroy(navi_upreq_t* up)
{
	navi_upnavi_t* up_navi = (navi_upnavi_t*) ((char*) up -
	    offsetof(navi_upnavi_t, base));
	if (up_navi->cleanup)
		up_navi->cleanup(up_navi, up_navi->ctx);
	return;
}

