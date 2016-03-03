/*
 * test_http_proxy_module.c
 *
 *  Created on: 2014-1-21
 *      Author: li.lei
 */
#include "navi_module.h"
#include "navi_request.h"
#include "navi_uphttp.h"


NAVI_MODULE_INIT(test_http_proxy,module)
{
	module->module_data = NULL;
	return NAVI_OK;
}

NAVI_MODULE_FREE(test_http_proxy,module)
{

}

NAVI_MODULE_METHOD(test_http_proxy,post,module,request)
{
	navi_request_t* sub = navi_request_new_sub(request);

	const char* uri = navi_http_request_get_arg(request, "remote_uri");
	const char* group = navi_http_request_get_arg(request,"group");
	navi_http_request_set_post(sub,"11111111",8);
	navi_request_launch_uphttp(sub, group, uri);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_http_proxy,get,module,request)
{
	navi_request_t* sub = navi_request_new_sub(request);

	const char* uri = navi_http_request_get_arg(request, "remote_uri");
	const char* group = navi_http_request_get_arg(request,"group");
	navi_http_request_set_args_raw(sub,"a=av&b=bv&c=cv");
	navi_request_launch_uphttp(sub, group, uri);
	return NAVI_OK;
}
