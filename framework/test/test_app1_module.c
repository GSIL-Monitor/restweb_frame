/*
 * test_app1_module.c
 *
 *  Created on: 2013-9-23
 *      Author: li.lei
 */


#include "navi_module.h"
#include "navi_request.h"

static void echo_request(navi_request_t* req) {
	navi_response_t* resp = navi_request_response_obj(req);
	json_t* js = json_object();
	json_object_set_new(js,"module",json_string(navi_request_module(req)));
	json_object_set_new(js,"method",json_string(navi_request_method(req)));
	json_object_set_new(js,"service",json_string(navi_request_service(req)));
	const char* body;
	if ( 0 < navi_http_request_get_post(req,&body) ) {
		json_object_set_new(js,"post",json_string(body));
	}
	navi_response_set_content(resp,js,0);
	navi_response_set_desc(resp,0,"","");
}

NAVI_MODULE_INIT(test_app1,module)
{
	module->module_data = NULL;
	return NAVI_OK;
}

NAVI_MODULE_FREE(test_app1,module)
{

}

NAVI_MODULE_METHOD(test_app1,method1,module,request)
{
	echo_request(request);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_app1,method2,module,request)
{
	echo_request(request);
	return NAVI_OK;
}
static int normal_sub_proc(navi_request_t* r,void* ctx) {
	navi_http_response_set_status(r,200);
	navi_http_response_set_body(r,ctx,strlen((const char*)ctx)+1);
	return NAVI_OK;
}

static int normal_sub_bin_body_proc(navi_request_t* r,void* ctx) {
	navi_http_response_set_status(r,200);
	char buf[128];
	memset(buf,0x00,128);
	buf[0]='l';
	buf[127]='l';
	navi_http_response_set_body(r,buf,sizeof(buf));
	return NAVI_OK;
}

static int abnormal_sub_proc(navi_request_t* r,void* ctx) {
	navi_request_add_sub(r,"/ssub1?a=av&b=bv",NULL,NULL,0,normal_sub_proc,"sub1body",NULL);
	navi_request_t* sub = navi_request_add_sub(r,"/ssub2?a=av&b=bv",NULL,NULL,0,normal_sub_proc,"sub1body",NULL);
	navi_request_recycle_on_end(sub);
	navi_request_add_sub(sub,"/ssub1?a=av&b=bv",NULL,NULL,0,normal_sub_proc,"sub1body",NULL);
	return NAVI_FAILED;
}


NAVI_MODULE_METHOD(test_app1,normal_sub,module,request)
{
	navi_request_add_sub(request,"/sub1?a=av&b=bv",NULL,NULL,0,normal_sub_proc,"sub1body",NULL);
	navi_request_t* sub = navi_request_add_sub(request,"/sub2?a=av&b=bv",NULL,NULL,0,normal_sub_proc,"sub2body",NULL);
	navi_request_add_sub(sub,"/ssub1?a=av&b=bv",NULL,NULL,0,normal_sub_proc,"sub1body",NULL);
	sub = navi_request_add_sub(sub,"/ssub1?a=av&b=bv",NULL,NULL,0,normal_sub_proc,"sub1body",NULL);
	navi_request_add_sub(sub,"/ssub1?a=av&b=bv",NULL,NULL,0,normal_sub_proc,"sub1body",NULL);
	navi_request_add_sub(request,"/sub3?a=av&b=bv",NULL,NULL,0,normal_sub_proc,"sub3body",NULL);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_app1,tree,module,request)
{
	navi_request_t* h = navi_request_add_sub(request,"/level_1_1",NULL,NULL,0,abnormal_sub_proc,"1_1_no_recycle",NULL);

	navi_request_t* h21 = navi_request_add_sub(h, "/level_2_1_procefailed", NULL, NULL, 0, abnormal_sub_proc,"2_1_procfailed", NULL);
	navi_request_t* h22 = navi_request_add_sub(h, "/level_2_2", NULL, NULL, 0, normal_sub_proc,"2_2_normal", NULL);
	navi_request_t* h23 = navi_request_add_sub(h, "/level_2_3", NULL, NULL, 0, normal_sub_proc,"2_3_normal", NULL);
	navi_request_recycle_on_end(h23);


	navi_request_add_sub(h21, "/level_3_1_canceled_cause_parent", NULL, NULL, 0, normal_sub_proc,"3_1_canceled_cause_parent_failed", NULL);
	h = navi_request_add_sub(h21, "/level_3_2", NULL, NULL, 0, normal_sub_proc,"3_2_canceled_cause_parent_failed", NULL);
	navi_request_recycle_on_end(h);
	h = navi_request_add_sub(h21, "/level_3_3", NULL, NULL, 0, normal_sub_proc,"3_3_canceled_cause_parent_failed", NULL);
	navi_request_add_sub(h, "/level_4_1", NULL, NULL, 0, normal_sub_proc,"4_1_canceled_cause_anst_failed", NULL);

	navi_request_add_sub(h23, "/level_3_4", NULL, NULL, 0, normal_sub_proc,"xxx", NULL);
	h = navi_request_add_sub(h23, "/level_3_5", NULL, NULL, 0, normal_sub_proc,"xxx", NULL);
	navi_request_add_sub(h, "/level_4_x", NULL, NULL, 0, normal_sub_proc,"xxx", NULL);
	navi_request_recycle_on_end(h);

	h = navi_request_add_sub(h22, "/level_3_6", NULL, NULL, 0, NULL,NULL, NULL);
	h->process_own = abnormal_sub_proc;
	h->ctx_own = "XXXX";

	navi_request_add_sub(h, "/level_4_10", NULL, NULL, 0, NULL,NULL, NULL);
	navi_request_add_sub(h, "/level_4_11", NULL, NULL, 0, NULL,NULL, NULL);

	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_app1,abnormal_sub,module,request)
{
	navi_request_add_sub(request,"/absub1?a=av&b=bv",NULL,NULL,0,normal_sub_bin_body_proc,"sub1body",NULL);
	navi_request_add_sub(request,"/absub2?a=av&b=bv",NULL,NULL,0,abnormal_sub_proc,"sub2body",NULL);
	return NAVI_OK;
}


