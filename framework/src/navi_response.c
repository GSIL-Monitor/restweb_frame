/*
 * navi_reponse.c
 *
 *  Created on: 2013-9-10
 *      Author: li.lei
 */

#include "navi_response.h"
#include "navi_request_impl.h"
#include "navi_frame_log.h"

static void resp_clean(navi_response_t* obj)
{
	obj->cost = 0;
	obj->error.code = NULL_CODE;
	obj->error.desc = obj->error.provider = NULL;
	if(obj->json_response)json_decref(obj->json_response);
	obj->json_response = NULL;
	free(obj->http);
	obj->http = NULL;
	obj->changed = 0;
}

navi_response_t* navi_response_init(void* rh)
{
	navi_request_t* main = (navi_request_t*)rh;
	if (!check_req_h(main))
		return NULL;

	navi_request_impl_t* mi = (navi_req_h2i(main))->main;

	if (mi->main_data->resp == NULL) {
		mi->main_data->resp = navi_pool_calloc(mi->pool_storage,1, sizeof(navi_response_t));
		if (mi->main_data->resp) {
			mi->main_data->resp->error.code = NULL_CODE;
			mi->main_data->resp->main = main;
		}
	}
	else {
		resp_clean(mi->main_data->resp);
		mi->main_data->resp->main = main;
	}

	return mi->main_data->resp;
}

void navi_response_set_desc(navi_response_t* obj,int code,const char* prvdr,const char* desc)
{
	navi_request_t* main = (navi_request_t* )obj->main;
	navi_request_impl_t* mi = navi_req_h2i(main);
	char* pcp=NULL,*dcp=NULL;
	if (prvdr) {
		pcp = navi_pool_strdup(mi->pool_storage,prvdr);
	}

	if (desc) {
		dcp = navi_pool_strdup(mi->pool_storage,desc);
	}

	obj->error.code = code;
	obj->error.provider = pcp;
	obj->error.desc = dcp;

	obj->changed = 1;
	return;
}

void navi_response_set_content(navi_response_t* obj,json_t* ctnt,int copy)
{
	navi_request_t* main = (navi_request_t* )obj->main;
	navi_request_impl_t* mi = navi_req_h2i(main);

	if (obj->json_response)
		json_decref(obj->json_response);

	if (copy) {
		obj->json_response = json_deep_copy(ctnt);
	}
	else
		obj->json_response = ctnt;

	obj->changed = 1;
	return;
}

void navi_response_with_js_callback(navi_response_t* obj, const char* cbnm)
{
	navi_request_t* main = (navi_request_t* )obj->main;
	if (!cbnm || 0==strlen(cbnm)) {
		obj->js_callback = NULL;
		return;
	}
	obj->js_callback = navi_pool_strdup(navi_request_pool(main),cbnm);
}

char* navi_response_http_body(navi_response_t* obj,int grab_flag)
{
	if (obj->changed==0 && obj->http && grab_flag==0)
		return obj->http;

	if (obj->json_response==NULL)
		obj->json_response = json_object();

	json_t* js_e = json_object();
	json_object_set_new(js_e,"code",json_integer(obj->error.code));
	json_object_set_new(js_e,"provider",json_string(obj->error.provider?obj->error.provider:""));
	json_object_set_new(js_e,"desc",json_string(obj->error.desc?obj->error.desc:""));

	json_object_set_new(obj->json_response,"e",js_e);

	char time_buf[40];
	snprintf(time_buf,40,"%.6f",obj->cost);
	json_object_set_new(obj->json_response,"cost",json_string(time_buf));

	navi_request_t* req = (navi_request_t* )obj->main;
	navi_request_impl_t* ri = navi_req_h2i(req);
	if (ri->main_data->trace) {
		json_t* trace = navi_trace_json(ri->main_data->trace);
		if (trace)
			json_object_set_new(obj->json_response, "trace", trace);
	}

	if (obj->http) {
		free(obj->http);
		obj->http = NULL;
	};
	obj->changed = 0;

	char* http_raw = json_dumps(obj->json_response,JSON_INDENT(2)|JSON_COMPACT|JSON_PRESERVE_ORDER);
	if (obj->js_callback) {
		char* tmp = (char*)malloc(strlen(http_raw)+strlen(obj->js_callback)+32);
		tmp[0]=0;
		sprintf(tmp, "%s(\r\n%s\r\n);", obj->js_callback, http_raw);
		free(http_raw);
		http_raw = tmp;
	}
	if (grab_flag) {
		return http_raw;
	}

	obj->http = http_raw;
	return obj->http;
}

void navi_response_clean(navi_response_t* obj)
{
	resp_clean(obj);
}
