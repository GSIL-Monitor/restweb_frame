/*
 * test_app2_module.c
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

NAVI_MODULE_INIT(test_app2,module)
{
	module->module_data = NULL;
	return NAVI_OK;
}

NAVI_MODULE_FREE(test_app2,module)
{

}

NAVI_MODULE_METHOD(test_app2,method1,module,request)
{
	echo_request(request);
	return NAVI_OK;
}


NAVI_MODULE_METHOD(test_app2,method2,module,request)
{
	echo_request(request);
	return NAVI_OK;
}
