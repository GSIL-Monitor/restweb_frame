/*
 * navi_redis_notify.c
 *
 *  Created on: 2014-04-08
 *      Author: yanguotao@youku.com
 */

#include "navi_redis_notify.h"
#include "navi_upgroup_mgr.h"
#include "navi_frame_log.h"
#include "navi_list.h"

int navi_redis_notify_pipe_regist(const char *group, navi_redis_notify_t* notify){
	navi_upgroup_mgr_t*mgr =  navi_upgroup_mgr_instance(NULL);
	navi_upreq_policy_t policy;
	nvup_policy_inkeys_t in_keys;
	nvup_policy_inkey_t inkey;
	if (group == NULL || notify == NULL){
		return NAVI_FAILED;
	}

	if (!mgr){
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "no upgroup manager instance");
		return NAVI_INNER_ERR;
	}
	navi_upgroup_t* grp = (navi_upgroup_t*) navi_hash_get_gr(mgr->groups, group);
	if (!grp) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "unknown upgroup name:%s for upreq", group);
		return NAVI_INNER_ERR;
	}

	if (grp->proto != NVUP_PROTO_REDIS){
		NAVI_FRAME_LOG(NAVI_LOG_WARNING, "group protocol is not redis");
		return NAVI_INNER_ERR;
	}
	inkey.k = "key";
	inkey.v = (char *)(notify->notify_name);
	navi_list_init(&in_keys);
	navi_list_insert_tail(&in_keys, &inkey.link);
	if (navi_upgroup_policy_query(grp, &in_keys, &policy) != 0){
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "upgroup:%s resolve server failed",
			group);
		return NAVI_INNER_ERR;
	}

	char pipe_key[256]={0};
	char *p_key = pipe_key;

	size_t sz = snprintf(p_key, sizeof(pipe_key), "%s:%s", group, policy.server_name);
	if (sz > sizeof(pipe_key)){
		p_key = (char*)malloc(sz+1);
		sprintf(p_key, "%s:%s", group, policy.server_name);
	}
	navi_pipe_t *pipe  = nvup_pipe_get(p_key);
	if (pipe == NULL){
		pipe = calloc(1, sizeof(navi_pipe_t));
		pipe->group = strdup(group);
		pipe->server_name = strdup(policy.server_name);
		pipe->check.ping_interval = NAVI_PIPE_PING_INTERVAL;
		pipe->proto = NVUP_PROTO_REDIS;
		pipe->out_pack = nvup_pipe_create_buf(256);
		pipe->parse_in = nvup_pipe_redis_parse_in;

		switch(policy.peer_addr.sa_family) {
		case AF_INET:
			memcpy(&pipe->peer_addr, &policy.peer_addr, sizeof(struct sockaddr_in));
			break;
		case AF_INET6:
			memcpy(&pipe->peer_addr, &policy.peer_addr, sizeof(struct sockaddr_in6));
			break;
		case AF_UNIX:
			memcpy(&pipe->peer_addr, &policy.peer_addr, sizeof(struct sockaddr_un));
			break;
		}
		//memcpy(&pipe->peer_addr, &policy.peer_addr, sizeof(struct sockaddr_in));
		//nvup_pipe_set(&pipe->peer_addr, pipe);
		nvup_pipe_set(pipe);
	}

	if (p_key != pipe_key)
		free(p_key);
		
	notify->pipe = pipe;
	navi_list_insert_tail(&pipe->link, &notify->link);

	return NAVI_OK;
}

static int navi_redis_wait_add_pipe_cmd(navi_pipe_t* pipe, const char * notify_name, const char *value)
{
	char buf[256]={0};
	char *p = buf;

	size_t sz = snprintf(p, sizeof(buf), "*3\r\n$8\r\nwait_ext\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
		strlen(notify_name), notify_name, strlen(value), value);
	if (sz > sizeof(buf)){
		p = (char*)malloc(sz+1);
		sprintf(p, "*3\r\n$8\r\nwait_ext\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
			strlen(notify_name), notify_name, strlen(value), value);
	}

	navi_pipe_append_msg(pipe, p, sz);
	if (p != buf){
		free(p);
	}
	return NAVI_OK;
}

int navi_redis_notify_pipe_wait(navi_redis_notify_t* notify, const char *value)
{
	if (notify == NULL){
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "notify %s have not registed yet\r\n",
			notify->notify_name);
		return NAVI_INNER_ERR;
	}

	navi_pipe_t *pipe  = notify->pipe;
	navi_redis_wait_add_pipe_cmd(pipe, notify->notify_name, value);

	return NAVI_OK;
}

static int navi_redis_cancel_add_pipe_cmd(navi_pipe_t* pipe, const char * notify_name)
{
	char buf[256]={0};
	char *p = buf;

	size_t sz = snprintf(p, sizeof(buf), "*2\r\n$11\r\nwait_cancel\r\n$%d\r\n%s\r\n",
		strlen(notify_name), notify_name);
	if (sz > sizeof(buf)){
		p = (char*)malloc(sz+1);
		sprintf(p, "*2\r\n$11\r\nwait_cancel\r\n$%d\r\n%s\r\n",
		    strlen(notify_name), notify_name);
	}

	navi_pipe_append_msg(pipe, p, sz);
	if (p != buf){
		free(p);
	}
	return NAVI_OK;
}

int navi_redis_notify_pipe_cancel(navi_redis_notify_t* notify)
{
	if (notify == NULL){
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "notify %s have not registed yet\r\n",
			notify->notify_name);
		return NAVI_INNER_ERR;
	}

	navi_pipe_t *pipe  = notify->pipe;
	navi_redis_cancel_add_pipe_cmd(pipe, notify->notify_name);

	return NAVI_OK;
}

void navi_redis_notify_destroy(void *imp)
{
	navi_redis_notify_t *notify = (navi_redis_notify_t *)imp;
	navi_list_remove(&notify->link);
	free(notify->notify_name);
	free(notify);
}

