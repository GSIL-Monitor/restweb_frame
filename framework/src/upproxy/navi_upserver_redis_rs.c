/*
 * navi_upserver_redis_rs.c
 *
 *  Created on: 2014-01-24
 *      Author: yanguotao@youku.com
 */

#include "navi_upserver_redis_rs.h"
#include "navi_upgroup.h"
#include "navi_frame_log.h"
#include "navi_up_network.h"
#include "navi_upproto_redis.h"
#include <netdb.h>

int redis_rs_upserver_init(navi_upserver_impl_t* srv, json_t* cfg);
int redis_rs_upserver_get_addr_fp(navi_upserver_impl_t* srv, struct sockaddr_storage* addr);
int redis_rs_upserver_onfailed_fp(navi_upserver_impl_t* srv, navi_upreq_code_e code);
bool redis_rs_upserver_resolve(navi_upserver_impl_t* srv);

static navi_upserver_procs_t s_upsrv_redis_rs_procs =
{
	redis_rs_upserver_init,
	redis_rs_upserver_get_addr_fp,
	redis_rs_upserver_onfailed_fp,
	NULL
};

navi_upserver_procs_t *g_upsrv_redis_rs_procs = &s_upsrv_redis_rs_procs;
navi_rs_servers_t *g_rs_servers = NULL;

int redis_rs_upserver_init(navi_upserver_impl_t* srv, json_t* cfg)
{
	srv->impl_data = NULL;
	json_t* je, *json_host, *json_port;
	uint16_t port;
	int size;
	navi_upgroup_t* group = (navi_upgroup_t*) srv->upserver->group;

	redis_rs_upserver_data_t* impl = navi_pool_calloc(srv->upserver->pool,
				1, sizeof(redis_rs_upserver_data_t));
	const char* jsv = NULL;
	je = json_object_get(cfg, "repl_set");
	struct sockaddr_in tmp_addr;
	if (je  == NULL || !json_is_array(je)){
		json_host = json_object_get(cfg, "host");
		if (json_is_string(json_host) && strlen(jsv = json_string_value(json_host))) {
			if (0 < inet_pton(AF_INET, jsv, &tmp_addr.sin_addr)) {
				impl->addrs = navi_array_create(srv->upserver->pool, 1,  sizeof(struct sockaddr_in));
				struct sockaddr_in* paddr = navi_array_push(impl->addrs);
				paddr->sin_addr.s_addr = tmp_addr.sin_addr.s_addr;
				json_port = json_object_get(je, "port");
				int ti = json_integer_value(json_port);
				if (ti > 0 && ti <= 65535){
					port =(uint16_t)ti;
					paddr->sin_port =  htons(port);
				}
				else {
					NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s port config invalid",
						group->group_name, srv->upserver->server_name);
					navi_pool_free(srv->upserver->pool, impl->addrs);
					navi_pool_free(srv->upserver->pool, impl);
					return NAVI_CONF_ERR;
				}
				paddr->sin_family = AF_INET;
				impl->cur_selected = 0;
			}
			else {
				NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s host config invalid",
				    group->group_name, srv->upserver->server_name);
				navi_pool_free(srv->upserver->pool, impl);
				return NAVI_CONF_ERR;
			}
		}
		else {
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s host config invalid",
			    group->group_name, srv->upserver->server_name);
			navi_pool_free(srv->upserver->pool, impl);
			return NAVI_CONF_ERR;
		}
	}
	else{
		size = json_array_size(je);
		if (size == 0){
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s redis_rs config invalid",
			    group->group_name, srv->upserver->server_name);
			navi_pool_free(srv->upserver->pool, impl);
			return NAVI_CONF_ERR;
		}
		impl->addrs = navi_array_create(srv->upserver->pool, size,  sizeof(struct sockaddr_in));
		int index;
		for (index = 0; index < size; index++){
			json_t *value = json_array_get(je, index);
			json_host = json_object_get(value, "host");
			if (json_is_string(json_host) && strlen(jsv = json_string_value(json_host))) {
				if (0 < inet_pton(AF_INET, jsv, &tmp_addr.sin_addr)) {
					struct sockaddr_in* paddr = navi_array_push(impl->addrs);
					paddr->sin_addr.s_addr = tmp_addr.sin_addr.s_addr;
					json_port = json_object_get(value, "port");
					int ti = json_integer_value(json_port);
					if (ti > 0 && ti <= 65535){
						port =(uint16_t)ti;
						paddr->sin_port =  htons(port);
					}
					else {
						NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s port config invalid",
							group->group_name, srv->upserver->server_name);
						navi_pool_free(srv->upserver->pool, impl->addrs);
						navi_pool_free(srv->upserver->pool, impl);
						return NAVI_CONF_ERR;
					}
					paddr->sin_family = AF_INET;			
				}
				else {
					NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s host config invalid",
						group->group_name, srv->upserver->server_name);
					navi_pool_free(srv->upserver->pool, impl->addrs);
					navi_pool_free(srv->upserver->pool, impl);
					return NAVI_CONF_ERR;
				}
				impl->cur_selected = 0;
			}
			else {
				NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s host config invalid",
					group->group_name, srv->upserver->server_name);
				navi_pool_free(srv->upserver->pool, impl->addrs);
				navi_pool_free(srv->upserver->pool, impl);
				return NAVI_CONF_ERR;
			}
		}
	}
	je = json_object_get(cfg, "repl_check_interval");
	if (je != NULL && json_is_integer(je)){
		impl->rs_check_interval = json_integer_value(je);
	}
	else{
		impl->rs_check_interval = DEFAULT_RS_CHECK_INTERVAL;
	}

	je = json_object_get(cfg, "resolve_interval");
	if (je != NULL && json_is_integer(je)){
		impl->resolve_interval = json_integer_value(je);
	}
	else{
		impl->resolve_interval = DEFAULT_RS_RESOLVE_INTERVAL;
	}

	je = json_object_get(cfg, "fail_dura");
	if (je != NULL && json_is_integer(je)){
		impl->fails.fail_dura = json_integer_value(je);
	}
	else{
		impl->fails.fail_dura = DEFAULT_RS_FAIL_DURA;
	}

	je = json_object_get(cfg, "fail_limit");
	if (je != NULL && json_is_integer(je)){
		impl->fails.fail_limit= json_integer_value(je);
	}
	else{
		impl->fails.fail_limit = DEFAULT_RS_FAIL_LIMIT;
	}
	
	srv->impl_data = impl;
	srv->upserver->status = NVUP_SRV_UNRESOLVED;
	redis_rs_upserver_resolve(srv);
	
	if (g_rs_servers == NULL){
		g_rs_servers = (navi_rs_servers_t*) malloc(NVUP_RS_SRVS_OBJ_SIZE);
		navi_pool_init(g_rs_servers->pool, g_rs_servers, 0x1000);
		memset(g_rs_servers, 0x00, sizeof(navi_rs_servers_t));
	}

	if (g_rs_servers->hash == NULL) {
		g_rs_servers->hash = navi_hash_init(g_rs_servers->pool);
	}
	char srv_key[256] = {0};
	char *p = srv_key;
	navi_upgroup_t* grp = (navi_upgroup_t*) srv->upserver->group;
	size_t sz = snprintf(p, sizeof(srv_key), "%s:%s",grp->group_name, srv->upserver->server_name);
	if (sz > sizeof(srv_key)){
		p = (char*)malloc(sz+1);
		sprintf(p, "%s:%s",grp->group_name, srv->upserver->server_name);
	}
	if (navi_hash_get_gr(g_rs_servers->hash, p)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "upserver:%s already exists in rs hash",
		    srv->upserver->server_name);
		if (p != srv_key){
			free(p);
		}
		return NAVI_FAILED;
	}

	if (0 > navi_hash_set_gr(g_rs_servers->hash,  p, srv)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "memory error when add rs server:%s",
		     srv->upserver->server_name);
		if (p != srv_key){
			free(p);
		}
		return NAVI_FAILED;
	}

	if (p != srv_key){
		free(p);
	}
	return NAVI_OK;
}

int redis_rs_upserver_host_in_set(navi_upserver_impl_t* srv, char *host, uint16_t port){
	redis_rs_upserver_data_t* impl = srv->impl_data;
	struct sockaddr_in* paddr = (struct sockaddr_in*)impl->addrs->parts[0]->allocs;
	struct sockaddr_in* pcur_addr;
	char host_str[26]={0};
	int size = impl->addrs->count;
	int i;
	if (host == NULL){
		return -1;
	}
	for (i=0; i<size; i++){
		pcur_addr=paddr+i;
		inet_ntop(AF_INET, &pcur_addr->sin_addr, host_str, sizeof(host_str));
		if (port == ntohs(pcur_addr->sin_port) &&
			strcmp(host, host_str) == 0){
			return i;
		}
	}
	return -1;
}

bool redis_rs_upserver_resolve(navi_upserver_impl_t* srv)
{
	redis_rs_upserver_data_t* impl = srv->impl_data;
	struct sockaddr_in* paddr = (struct sockaddr_in*)impl->addrs->parts[0]->allocs;
	struct sockaddr_in* pcur_addr;
	char recv_buf[2048] = {0};
	const char *info = "*1\r\n$4\r\nINFO\r\n";
	int size = impl->addrs->count;
	int socket_fd;
	int i, len, selected;
	if (size <= 1){
		srv->upserver->status = NVUP_SRV_RESOLVED;
		return true;
	}
	uint64_t cur_time = cur_time_us();
	if (cur_time - impl->last_check< impl->rs_check_interval*1000000){
		return false;
	}
	for (i=0; i<size; i++){
		pcur_addr = paddr+i;
		socket_fd = navi_up_socket_create((const struct sockaddr*)pcur_addr);
		if (socket_fd < 0){
			continue;
		}

		len = navi_up_send(socket_fd, (char *)info, strlen(info));
		if (len <= 0){
			navi_up_socket_close(socket_fd);
			continue;
		}

		navi_pool_t* pool = navi_pool_create(1024);
		nvup_redis_proto_t proto;
		navi_upreq_parse_status_e parse_status;
		nvup_redis_proto_init(&proto, pool, 1024);
		do {
			len = navi_up_recv(socket_fd, recv_buf, sizeof(recv_buf));
			if (len>0) {
				parse_status = nvup_redis_proto_parse_in(&proto, (uint8_t*)recv_buf, len);
			}
			else
				break;
		} while (len > 0 && parse_status == NVUP_PARSE_AGAIN);

		navi_up_socket_close(socket_fd);

		if ( proto.pending_stage != redis_stage_done ) {
			continue;
		}

		if ( proto.proto_type == redis_type_single_bulk) {
			redis_bulk_t* bk = navi_array_item(proto.in_bulks,0);
			char* role = strstr(bk->s, "role:");
			if (role==NULL) {
				continue;
			}
			if (memcmp(role+5, "slave", 5) == 0) {
				char *master_host= strstr(bk->s,"master_host:");
				char *master_port= strstr(bk->s,"master_port:");
				char *master_link_status = strstr(bk->s,"master_link_status:");
				if (master_host == NULL || master_port == NULL || master_link_status == NULL){
					continue;
				}
				if (memcmp(master_link_status+19, "up", 2)){
					continue;
				}
				master_host += 12;
				char *end = strchr(master_host, '\r');
				*end = '\0';
				master_port += 12;
				end = strchr(master_port, '\r');
				*end = '\0';
				uint16_t port = atoi(master_port);
				selected = redis_rs_upserver_host_in_set(srv, master_host, port);
				if (selected >= 0){
					impl->cur_selected=selected;
					srv->upserver->status = NVUP_SRV_RESOLVED;
					impl->last_check = 0;
					impl->last_resolve = cur_time;
					nvup_redis_proto_clean(&proto);
					navi_pool_destroy(pool);
					break;
				}
			}
			else {
				impl->cur_selected = i;
				srv->upserver->status = NVUP_SRV_RESOLVED;
				impl->last_check = 0;
				impl->last_resolve = cur_time;
				nvup_redis_proto_clean(&proto);
				navi_pool_destroy(pool);
				break;
			}
		}
		else {
			nvup_redis_proto_clean(&proto);
			navi_pool_destroy(pool);
			continue;
		}
	}
	if ( i==size ) {
		impl->last_check = cur_time;
		srv->upserver->status = NVUP_SRV_UNRESOLVED;
		return false;
	}
	else {
		return true;
	}

}

int redis_rs_upserver_get_addr_fp(navi_upserver_impl_t* srv, struct sockaddr_storage* addr)
{
	redis_rs_upserver_data_t* impl = srv->impl_data;
	struct sockaddr_in* paddr = (struct sockaddr_in*)impl->addrs->parts[0]->allocs;
	if (srv->upserver->status == NVUP_SRV_UNRESOLVED){
		if (!redis_rs_upserver_resolve(srv)){
			return NAVI_FAILED;
		}		
	}
	if (impl->addrs->count == 1) {
		memcpy(addr, paddr, sizeof(struct sockaddr_in));
	}
	else {
		memcpy(addr, paddr + impl->cur_selected, sizeof(struct sockaddr_in));
	}
	return NAVI_OK;
}

int redis_rs_upserver_onfailed_fp(navi_upserver_impl_t* srv, navi_upreq_code_e code)
{
	redis_rs_upserver_data_t* impl = srv->impl_data;
	if (srv->upserver->status == NVUP_SRV_UNRESOLVED){
		return 0;
	}

	if (code == NVUP_RESULT_CONN_FAILED ||
		code == NVUP_RESULT_RW_FAILED ||
		code == NVUP_RESULT_CONN_TIMEOUT ||
		code == NVUP_RESULT_RW_TIMEOUT) {
		if (impl->fails.count== 0){
			impl->fails.first_fail = cur_time_us();
		}
		impl->fails.count++;
	}

	return 0;
}

