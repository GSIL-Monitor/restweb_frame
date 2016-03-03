/*
 * test_navi_proxy.c
 *
 *  Created on: 2014-1-21
 *      Author: li.lei
 */



#include "navi_module.h"
#include "navi_request.h"
#include "navi_upnavi.h"


NAVI_MODULE_INIT(test_navi_proxy,module)
{
	module->module_data = NULL;
	return NAVI_OK;
}

NAVI_MODULE_FREE(test_navi_proxy,module)
{

}

NAVI_MODULE_METHOD(test_navi_proxy,get,module,request)
{
	navi_request_t* sub = navi_request_new_sub(request);

	navi_upnavi_t* up = navi_request_bind_upnavi(sub, "test_navi", "test_http_proxy", "get", "", "testnavi", NULL);
	navi_upnavi_set_arg(up, "group","test_http");
	navi_upnavi_set_arg(up, "uri", "/");
	navi_upnavi_launch(up);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_navi_proxy,post,module,request)
{
	navi_request_t* sub = navi_request_new_sub(request);

	navi_upnavi_t* up = navi_request_bind_upnavi(sub, "test_navi", "test_http_proxy", "post", "", "testnavi", NULL);
	navi_upnavi_set_arg(up, "group","test_http");
	navi_upnavi_set_arg(up, "uri", "/");
	navi_upnavi_post_raw(up, "111111", 6);
	navi_upnavi_launch(up);
	return NAVI_OK;
}

