/*
 * test_post_module.c
 *
 *  Created on: 2013-9-23
 *      Author: li.lei
 */

#include "navi_module.h"
#include "navi_request.h"

NAVI_MODULE_INIT(test_post1,module)
{
	module->module_data = NULL;
	return NAVI_OK;
}

NAVI_MODULE_FREE(test_post1,module)
{

}

NAVI_MODULE_REQUEST_PROC(test_post1,module,request)
{
	return NAVI_OK;
}
