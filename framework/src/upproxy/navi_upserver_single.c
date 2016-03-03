/*
 * navi_upserver_single.c
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#include "navi_upserver_single.h"
#include "navi_upgroup.h"
#include "navi_frame_log.h"
#include <netdb.h>

int single_upserver_init(navi_upserver_impl_t* srv, json_t* cfg);
int single_upserver_get_addr_fp(navi_upserver_impl_t* srv, struct sockaddr_storage* addr);

static navi_upserver_procs_t s_upsrv_single_procs =
{
	single_upserver_init,
	single_upserver_get_addr_fp,
	NULL,
	NULL
};

navi_upserver_procs_t *g_upsrv_single_procs = &s_upsrv_single_procs;

typedef struct single_upserver_data_t
{
	navi_array_t* addrs; //struct sockaddr_in元素数组
	int cur_selected; //当前被使用的地址的序号
} single_upserver_data_t;

int single_upserver_init(navi_upserver_impl_t* srv, json_t* cfg)
{
	srv->impl_data = NULL;
	json_t* je = json_object_get(cfg, "port");
	uint16_t port = 0xffff;
	navi_upgroup_t* group = (navi_upgroup_t*) srv->upserver->group;
	if (je && json_is_integer(je)) {
		int ti = json_integer_value(je);
		if (ti > 0 && ti < 65535) {
			port = (uint16_t) ti;
		}
	}

	if (port == 0xffff) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s port config invalid",
		    group->group_name, srv->upserver->server_name);
		return NAVI_CONF_ERR;
	}

	const char* jsv = NULL;
	je = json_object_get(cfg, "host");
	struct sockaddr_in tmp_addr;
	if (je) {
		if (json_is_string(je) && strlen(jsv = json_string_value(je))) {
			if (0 < inet_pton(AF_INET, jsv, &tmp_addr.sin_addr)) {
				single_upserver_data_t* impl = navi_pool_calloc(srv->upserver->pool,
				    1, sizeof(single_upserver_data_t));
				srv->impl_data = impl;
				impl->addrs = navi_array_create(srv->upserver->pool, 1,
				    sizeof(struct sockaddr_in));
				struct sockaddr_in* paddr = navi_array_push(impl->addrs);
				paddr->sin_addr.s_addr = tmp_addr.sin_addr.s_addr;
				paddr->sin_port = htons(port);
				paddr->sin_family = AF_INET;
				impl->cur_selected = 0;
			}
			else {
				NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s host config invalid",
				    group->group_name, srv->upserver->server_name);
				return NAVI_CONF_ERR;
			}
		}
		else {
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s host config invalid",
			    group->group_name, srv->upserver->server_name);
			return NAVI_CONF_ERR;
		}
	}
	else {
		je = json_object_get(cfg, "domain");
		if (!je) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s host/domain config absent",
			    group->group_name, srv->upserver->server_name);
			return NAVI_CONF_ERR;
		}

		if (!json_is_string(je) || 0 == strlen(jsv = json_string_value(je))) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s domain config invalid",
			    group->group_name, srv->upserver->server_name);
			return NAVI_CONF_ERR;
		}

		struct hostent *h;
		h = gethostbyname(jsv);

		if	( h == NULL || h->h_addr_list[0] == NULL ){
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s domain not found",
				group->group_name, srv->upserver->server_name);
			return NAVI_CONF_ERR;
		}

		int i;
		for ( i = 0; h->h_addr_list[i] != NULL; i++) {}

		single_upserver_data_t* impl = navi_pool_calloc(srv->upserver->pool,
			1, sizeof(single_upserver_data_t));
		srv->impl_data = impl;
		impl->addrs = navi_array_create(srv->upserver->pool, i,
			sizeof(struct sockaddr_in));
		impl->cur_selected = 0;

		for ( i = 0; h->h_addr_list[i] != NULL; i++) {
			struct sockaddr_in* paddr = navi_array_push(impl->addrs);
			paddr->sin_addr.s_addr = *(in_addr_t *) (h->h_addr_list[i]);
			paddr->sin_port = htons(port);
			paddr->sin_family = AF_INET;
		}
	}

	srv->upserver->status = NVUP_SRV_RESOLVED;
	return NAVI_OK;
}

int single_upserver_get_addr_fp(navi_upserver_impl_t* srv, struct sockaddr_storage* addr)
{
	single_upserver_data_t* impl = srv->impl_data;
	struct sockaddr_in* paddr = (struct sockaddr_in*)impl->addrs->parts[0]->allocs;
	if (impl->addrs->count == 1) {
		memcpy(addr, paddr, sizeof(struct sockaddr_in));
	}
	else {
		memcpy(addr, paddr + impl->cur_selected, sizeof(struct sockaddr_in));
		impl->cur_selected = (impl->cur_selected+1)%impl->addrs->count;
	}
	return NAVI_OK;
}
