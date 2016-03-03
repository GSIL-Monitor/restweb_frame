/*
 * navi_upgroup_policy_rest.c
 *
 *  Created on: 2014-08-20
 *      Author: yanguotao@youku.com
 */

#include "navi_upgroup_policy_rest.h"
#include "navi_upserver.h"
#include "navi_frame_log.h"


NAVI_UPGROUP_POLICY_INIT_FUNC(rest, impl, cfg)
{
	return NAVI_OK;
}

NAVI_UPGROUP_POLICY_RESOLVE_FUNC(rest, impl, req)
{
	navi_upgroup_t* upgrp = impl->group;

	char *srv_name = req->srv_name;

	if (srv_name == NULL){
		return NULL;
	}

	navi_upserver_t* up_server = navi_upgroup_get_server(upgrp, srv_name);

	return up_server;
}

NAVI_UPGROUP_POLICY_DESTROY_FUNC(rest, impl)
{
	
	return;
}

NAVI_UPSERVER_POLICY_INIT_FUNC(rest, srv, srv_cfg)
{

	return NAVI_OK;
}
