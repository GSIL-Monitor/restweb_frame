/*
 * test_ic_module.c
 *
 *  Created on: 2013-9-23
 *      Author: li.lei
 */


#include "navi_module.h"
#include "navi_request.h"


NAVI_MODULE_FREE(test_prev1,module)
{

}

NAVI_MODULE_REQUEST_PROC(test_prev1,module,request)
{
	return NAVI_OK;
}
