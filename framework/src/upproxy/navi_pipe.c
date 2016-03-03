/*
 * navi_pipe.c
 *
 *  Created on: 2014-04-08
 *      Author: yanguotao@youku.com
 */

#include "navi_pipe.h"
#include "navi_vevent_mgr.h"
#include "navi_redis_notify.h"
#include "navi_list.h"
#include "navi_upgroup_mgr.h"
#include "navi_frame_log.h"

static navi_pipe_mgr_t *navi_pipe_mgr = NULL;

navi_pipe_mgr_t *nvup_pipe_mgr_get(void)
{
	return navi_pipe_mgr;
}

static navi_pipe_buf_item_t *nvup_pipe_get_buf_item(navi_pipe_buf_t *buf)
{
	navi_pipe_buf_item_t *item;
	if (buf->used >= buf->size){
		navi_pipe_buf_item_t *items = calloc(2*buf->size, sizeof(navi_pipe_buf_item_t));
		buf->start = buf->start%buf->size;
		memcpy(items, &buf->items[buf->start], sizeof(navi_pipe_buf_item_t)*(buf->size-buf->start));
		memcpy(items+(buf->size-buf->start), buf->items, sizeof(navi_pipe_buf_item_t)*(buf->used-(buf->size-buf->start)));
		free(buf->items);
		buf->items=items;
		buf->start=0;
		buf->size *= 2;
	}

	item = &(buf->items[(buf->start+buf->used)%buf->size]);
	buf->used++;
	return item;
}

navi_pipe_buf_t *nvup_pipe_create_buf(uint32_t size)
{
	navi_pipe_buf_t *buf = calloc(1, sizeof(navi_pipe_buf_t));
	if (buf == NULL){
		return NULL;
	}

	buf->items = (navi_pipe_buf_item_t *)calloc(size, sizeof(navi_pipe_buf_item_t));
	buf->size=size;
	return buf;
}

void navi_pipe_reset_buf(navi_pipe_buf_t* buf)
{
	if (buf && buf->used>0) {
		int i=0;
		for ( ; i<buf->used; i++) {
			free(buf->items[(buf->start+i)%buf->size].buf);
		}
	}
	buf->start = 0;
	buf->used = 0;
}

static void nvup_pipe_destroy_buf(navi_pipe_buf_t *buf )
{
	if (buf == NULL){
		return;
	}

	if (buf->used){
		int index=0;
		for (; index<buf->used; index++){
			free(buf->items[(buf->start+index)%buf->size].buf);
		}
	}

	free(buf->items);
	free(buf);
}

navi_pipe_t *nvup_pipe_get(const char *pipe_name)
{
	if (navi_pipe_mgr == NULL || navi_pipe_mgr->hash == NULL || pipe_name == NULL){
		return NULL;
	}

	return navi_hash_get_gr(navi_pipe_mgr->hash, pipe_name);
}

int nvup_pipe_set( navi_pipe_t *pipe)
{
	if (navi_pipe_mgr == NULL){
		navi_pipe_mgr = malloc(sizeof(navi_pipe_mgr_t));
		navi_list_init(&navi_pipe_mgr->new_conn_link);
		navi_list_init(&navi_pipe_mgr->close_conn_link);
		navi_list_init(&navi_pipe_mgr->write_link);
		navi_pipe_mgr->hash = navi_hash_init_with_heap();
	}
	if (navi_pipe_mgr->hash == NULL){
		navi_pipe_mgr->hash = navi_hash_init_with_heap();
	}
	char pipe_key[256]={0};
	char *p_key = pipe_key;

	size_t sz = snprintf(p_key, sizeof(pipe_key), "%s:%s", pipe->group, pipe->server_name);
	if (sz > sizeof(pipe_key)){
		p_key = (char*)malloc(sz+1);
		sprintf(p_key, "%s:%s", pipe->group, pipe->server_name);
	}

	navi_list_init(&pipe->link);
	navi_list_init(&pipe->close_conn_link);
	navi_list_init(&pipe->write_link);
	navi_list_insert_tail(&navi_pipe_mgr->new_conn_link, &pipe->new_conn_link);
	navi_hash_set_gr(navi_pipe_mgr->hash, p_key, pipe);
	if (p_key != pipe_key)
		free(p_key);
	return 0;
}

void nvup_pipe_destroy(navi_pipe_t *pipe)
{
	nvup_pipe_destroy_buf(pipe->out_pack );
	navi_pool_destroy(pipe->proto_redis->pool);
	free(pipe->proto_redis->parse_buf.buf);
	free(pipe->proto_redis);
	free(pipe->group);
	free(pipe->server_name);
	free(pipe);
}

 void nvup_pipe_mgr_destroy()
{
	if (navi_pipe_mgr == NULL){
		return;
	}
	navi_hash_t *hash = navi_pipe_mgr->hash;
	if (hash == NULL){
		free(navi_pipe_mgr);
		return;
	}
	navi_hent_t* e;
	void* it = navi_hash_iter(hash);
	while ((e=navi_hash_iter_next(it))) {
		nvup_pipe_destroy((navi_pipe_t*)(e->v));
		e->v = NULL;
	}
	navi_hash_iter_destroy(it);
	navi_hash_destroy(navi_pipe_mgr->hash);
	free(navi_pipe_mgr);
	navi_pipe_mgr = NULL;
}

void navi_pipe_append_msg(navi_pipe_t *pipe, uint8_t* in, size_t sz){
	navi_pipe_buf_item_t *item = nvup_pipe_get_buf_item(pipe->out_pack);
	item->buf=malloc(sz);
	item->pos=item->buf;
	memcpy(item->buf, in, sz);
	item->size = sz;
       if (navi_list_empty(&pipe->new_conn_link) && navi_list_empty(&pipe->write_link)){
		navi_list_insert_tail(&navi_pipe_mgr->write_link, &pipe->write_link);
	}
}

void nvup_pipe_reset_ve(navi_pipe_t *pipe)
{
	chain_node_t *node =  pipe->link.next;
	while(node != &pipe->link){
		navi_redis_notify_t *notify = navi_list_data(node, navi_redis_notify_t, link);
		navi_vevent_t *ve = notify->ve;
		ve->reset(ve);
		node = node->next;
	}
}

int navi_pipe_restart(navi_pipe_t *pipe)
{
	chain_node_t *node =  pipe->link.next;
	if ( pipe->peer_addr.ss_family == AF_INET ) {
		struct sockaddr_in* addr = (struct sockaddr_in*)&pipe->peer_addr;
		NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "pipe reopen. notifies reinit.%s:%d+[%s] ",
			inet_ntoa(addr->sin_addr),  ntohs(addr->sin_port), pipe->local_name);
	}
	else if (pipe->peer_addr.ss_family == AF_UNIX ){
		struct sockaddr_un* addr = (struct sockaddr_un*)&pipe->peer_addr;
		NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "pipe reopen. notifies reinit.%s+[%s] ",
			addr->sun_path, pipe->local_name);
	}
	while(node != &pipe->link){
		navi_redis_notify_t *notify = navi_list_data(node, navi_redis_notify_t, link);
		navi_vevent_t *ve = notify->ve;
		void* it = navi_vevent_vh_it(ve);
		navi_vehandler_t* vh;
		while ( (vh=navi_vevent_vh_it_next(it)) ) {
			if (vh->reinit)
				vh->reinit(vh->binded_req, ve, vh->ctx);
		}
		navi_vevent_vh_it_destroy(it);
		node = node->next;
	}
	return NAVI_OK;
}

static void nvup_pipe_redis_process_result( navi_pipe_t *pipe)
{
	nvup_redis_proto_t *proto = pipe->proto_redis;
	navi_upreq_result_t* result;
	if (proto->proto_type == redis_type_error_reply) {
		if ( pipe->peer_addr.ss_family == AF_INET ) {
			struct sockaddr_in* addr = (struct sockaddr_in*)&pipe->peer_addr;
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "redis protocol parse error for pipe %s:%d+[%s], msg:%s",
				inet_ntoa(addr->sin_addr),  ntohs(addr->sin_port), pipe->local_name,  proto->str_result);
		}
		else if (pipe->peer_addr.ss_family == AF_UNIX ){
			struct sockaddr_un* addr = (struct sockaddr_un*)&pipe->peer_addr;
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "redis protocol parse error for pipe %s+[%s], msg:%s",
				addr->sun_path, pipe->local_name,  proto->str_result);
		}
		//NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "redis protocol parse error for pipe %s:%d+[%s], msg:%s",
		//	inet_ntoa(pipe->peer_addr.sin_addr),  ntohs(pipe->peer_addr.sin_port), pipe->local_name,  proto->str_result);
		if ( navi_list_empty(&pipe->close_conn_link)) {
			navi_list_insert_tail(&navi_pipe_mgr->close_conn_link, &pipe->close_conn_link);
		}
	}
	else if (proto->proto_type == redis_type_status_reply) {
		if (!strcasecmp("PONG",proto->str_result)){
			time_t cur_time = time(NULL);
			if (cur_time-pipe->check.last_start > pipe->check.ping_interval+1){
				pipe->check.ping_interval = NAVI_PIPE_PING_INTERVAL_FAST;
				pipe->check.fails++;
				if (pipe->check.fails > 3 && pipe->status == NAVI_PIPE_STATUS_CONNECTED
						&& navi_list_empty(&pipe->close_conn_link)){
					navi_list_insert_tail(&navi_pipe_mgr->close_conn_link, &pipe->close_conn_link);
				}
			}
			else{
				pipe->check.ping_interval = NAVI_PIPE_PING_INTERVAL;
				pipe->check.fails = 0;
			}
			pipe->check.last_start = 0;
		}
		else{
			if ( pipe->peer_addr.ss_family == AF_INET ) {
				struct sockaddr_in* addr = (struct sockaddr_in*)&pipe->peer_addr;
				NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "unknown redis status reply %s for pipe %s:%d+[%s]",
					proto->str_result, inet_ntoa(addr->sin_addr),
					ntohs(addr->sin_port), pipe->local_name);
			}
			else if (pipe->peer_addr.ss_family == AF_UNIX ){
				struct sockaddr_un* addr = (struct sockaddr_un*)&pipe->peer_addr;
				NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "unknown redis status reply %s for pipe %s+[%s]",
					proto->str_result, addr->sun_path , pipe->local_name);
			}
			//NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "unknown redis status reply %s for pipe %s:%d+[%s]",
			//	proto->str_result, inet_ntoa(pipe->peer_addr.sin_addr),
			//	ntohs(pipe->peer_addr.sin_port), pipe->local_name);
		}
	}
	else if (proto->proto_type == redis_type_multi_bulk) {
		int pt, i;
		navi_array_part_t* part;
		char *key = NULL;
		char *info = NULL;
		for (pt=0; pt<proto->in_bulks->part_size; pt++) {
			part = proto->in_bulks->parts[pt];
			if (!part)
				break;
			redis_bulk_t* bulk = (redis_bulk_t*)part->allocs;
			for (i=0; i<part->used; i++,bulk++) {
				if (bulk->bulk_type == redis_type_single_bulk && bulk->s) {
					if (key == NULL){
						key = bulk->s;
					}
					else{
						info = strdup(bulk->s);
						break;
					}
				}
			}
			if (info)
				break;
		}
		char ve_name[256];
		char* pve_name = ve_name;
		size_t sz = snprintf(pve_name,sizeof(ve_name), "%s::%s", pipe->group, key);
		if( sz>=sizeof(ve_name) ) {
			pve_name = (char*)malloc(sz+1);
			sprintf(pve_name, "%s::%s", pipe->group, key);
		}
		navi_vevent_t *ve = navi_vevent_get(pve_name);
		if (ve == NULL){
			NAVI_FRAME_LOG(NAVI_LOG_INFO, "can not find virture event %s from recieved notice info",
				pve_name);
			free(info);
		}
		else{
			navi_vevent_ready(ve, info, free);
		}

		if (pve_name != ve_name){
			free(pve_name);
		}
	}
	else{
		if ( pipe->peer_addr.ss_family == AF_INET ) {
			struct sockaddr_in* addr = (struct sockaddr_in*)&pipe->peer_addr;
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "not redis multi bulk reply for pipe %s:%d",
				inet_ntoa(addr->sin_addr),  ntohs(addr->sin_port));
		}
		else if (pipe->peer_addr.ss_family == AF_UNIX ){
			struct sockaddr_un* addr = (struct sockaddr_un*)&pipe->peer_addr;
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "not redis multi bulk reply for pipe %s",
				addr->sun_path);
		}
		//NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "not redis multi bulk reply for pipe %s:%d",
		//	inet_ntoa(pipe->peer_addr.sin_addr),  ntohs(pipe->peer_addr.sin_port));
	}

	memset(proto, 0x00, offsetof(nvup_redis_proto_t, parse_buf));
	navi_pool_reset(proto->pool);

}

navi_upreq_parse_status_e nvup_pipe_redis_parse_in(navi_pipe_t* pipe, uint8_t *in, size_t sz)
{	
	if (pipe->proto_redis == NULL) {
		pipe->proto_redis = (nvup_redis_proto_t *)calloc(1, sizeof(nvup_redis_proto_t));
		if (pipe->proto_redis == NULL)
			return NVUP_PARSE_STATUS_INVALID;
		pipe->proto_redis->pool = navi_pool_create(0x1000);

		if (NAVI_OK != nvup_redis_proto_init(pipe->proto_redis, pipe->proto_redis->pool, 1024))
			return NVUP_PARSE_STATUS_INVALID;
	}

	navi_upreq_parse_status_e status = nvup_redis_proto_parse_in(pipe->proto_redis, in, sz);
	if (status == NVUP_PARSE_PROTO_ERROR) {
		if ( navi_list_empty(&pipe->close_conn_link)) {
			navi_list_insert_tail(&navi_pipe_mgr->close_conn_link, &pipe->close_conn_link);
		}
		return status;
	}
	else if (status != NVUP_PARSE_AGAIN){
		do {
			nvup_pipe_redis_process_result(pipe);
			pipe->proto_redis->pending_stage = redis_stage_start;
			status=nvup_redis_proto_parse_in(pipe->proto_redis, NULL, 0);
			if (status == NVUP_PARSE_PROTO_ERROR) {
				if ( navi_list_empty(&pipe->close_conn_link)) {
					navi_list_insert_tail(&navi_pipe_mgr->close_conn_link, &pipe->close_conn_link);
				}
				return status;
			}
		}while (status != NVUP_PARSE_AGAIN);
	}

	return status;
}

int navi_pipe_lose_connection_process(navi_pipe_t *pipe)
{
	navi_upgroup_mgr_t*mgr =  navi_upgroup_mgr_instance(NULL);
	//navi_upreq_policy_t policy;
	struct sockaddr_storage tmp_addr;
	pipe->status = NAVI_PIPE_STATUS_DISCONNECTED;

	if (!mgr){
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "no upgroup manager instance");
		return NAVI_INNER_ERR;
	}
	navi_upgroup_t* grp = (navi_upgroup_t*) navi_hash_get_gr(mgr->groups, pipe->group);
	if (!grp) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "unknown upgroup name:%s for upreq", pipe->group);
		return NAVI_INNER_ERR;
	}
	navi_upserver_t* up_server = navi_upgroup_get_server(grp, pipe->server_name);
	if (!up_server){
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "get server error for group:%s server %s", 
			pipe->group,  pipe->server_name);
		return NAVI_INNER_ERR;
	}
	if (0 != (up_server->procs->get_addr)(&up_server->impl, &tmp_addr)) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "upserver:%s of group:%s unresolved or unreachable",
			grp->group_name, up_server->server_name);
		return NAVI_INNER_ERR;
	}
	
	if ( tmp_addr.ss_family != AF_INET ) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "upserver:%s of group:%s should be ipv4 for redis notify pipe",
			grp->group_name, up_server->server_name);
		return NAVI_INNER_ERR;
	}

	memcpy(&pipe->peer_addr, &tmp_addr, sizeof(struct sockaddr_storage));
	if (navi_list_empty(&pipe->new_conn_link)){
		navi_list_insert_tail(&navi_pipe_mgr->new_conn_link, &pipe->new_conn_link);
	}
	return NAVI_OK;
}

void  navi_pipe_ping(navi_pipe_t *pipe)
{
	if (pipe->status != NAVI_PIPE_STATUS_CONNECTED){
		navi_pipe_lose_connection_process(pipe);
		return;
	}
	
	char *ping_cmd = "*1\r\n$4\r\nPING\r\n";
	time_t cur_time = time(NULL);
	if (pipe->check.last_start != 0 
			&& (cur_time-pipe->check.last_start > pipe->check.ping_interval+1)){
		pipe->check.last_start = cur_time;
		pipe->check.fails++;
		pipe->check.ping_interval = NAVI_PIPE_PING_INTERVAL_FAST;
		if (pipe->check.fails > 3 && pipe->status == NAVI_PIPE_STATUS_CONNECTED
				&& navi_list_empty(&pipe->close_conn_link)){
			pipe->check.last_start = 0;
			navi_list_insert_tail(&navi_pipe_mgr->close_conn_link, &pipe->close_conn_link);
			return;
		}
	}

	pipe->check.last_start = cur_time;

	navi_pipe_append_msg(pipe, ping_cmd, strlen(ping_cmd));
}
