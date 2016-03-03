/** \brief 
 * navi_upserver_local.c
 *  Created on: 2015-2-26
 *      Author: li.lei
 *  brief: 
 */

#include "navi_upserver_local.h"
#include "navi_upgroup.h"
#include "navi_frame_log.h"

static int local_upserver_init(navi_upserver_impl_t* srv, json_t* cfg);
static int local_upserver_get_addr_fp(navi_upserver_impl_t* srv, struct sockaddr_storage* addr);

static navi_upserver_procs_t s_upsrv_local_procs =
{
	local_upserver_init,
	local_upserver_get_addr_fp,
	NULL,
	NULL
};

navi_upserver_procs_t *g_upsrv_local_procs = &s_upsrv_local_procs;

int local_upserver_init(navi_upserver_impl_t* srv, json_t* cfg)
{
	srv->impl_data = NULL;
	json_t* je = json_object_get(cfg, "unix_path");
	navi_upgroup_t* group = (navi_upgroup_t*) srv->upserver->group;

	const char* unix_path = NULL;
	if ( !je || !json_is_string(je) ) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s port config invalid: unix_path is mandatory",
		    group->group_name, srv->upserver->server_name);
		return NAVI_CONF_ERR;
	}
	unix_path = json_string_value(je);
	if ( !strlen(unix_path)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s port config invalid: unix_path is mandatory",
		    group->group_name, srv->upserver->server_name);
		return NAVI_CONF_ERR;
	}

	struct sockaddr_un* peer_addr = navi_pool_calloc(srv->upserver->pool, 1,
		sizeof(struct sockaddr_un));

	srv->impl_data = peer_addr;
	peer_addr->sun_family = AF_UNIX;
	size_t sz = strlen(unix_path) > ( sizeof(peer_addr->sun_path)-1 ) ?
		(sizeof(peer_addr->sun_path)-1) : strlen(unix_path);

	memcpy(peer_addr->sun_path, unix_path,sz);
	peer_addr->sun_path[sz] = 0;

	srv->upserver->status = NVUP_SRV_RESOLVED;
	return NAVI_OK;
}

int local_upserver_get_addr_fp(navi_upserver_impl_t* srv, struct sockaddr_storage* addr)
{
	struct sockaddr_un* un = srv->impl_data;
	memcpy(addr, un, sizeof(struct sockaddr_un));
	return NAVI_OK;
}



