/*
 * navi_pipe.h
 *
 *  Created on: 2014-04-08
 *      Author: yanguotao@youku.com
 */

#ifndef NAVI_PIPE_H_
#define NAVI_PIPE_H_

#include "navi_common_define.h"
#include "navi_upredis.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define NAVI_PIPE_PING_INTERVAL 5//s
#define NAVI_PIPE_PING_INTERVAL_FAST 1//s

typedef struct navi_pipe_buf_item_s
{
	uint32_t size;
	char *buf;
	char *pos; 
}navi_pipe_buf_item_t;

typedef struct navi_pipe_buf_s
{
	navi_pipe_buf_item_t *items;
	uint32_t size;
	uint32_t start;
	uint32_t used;
}navi_pipe_buf_t;

navi_pipe_buf_t *nvup_pipe_create_buf(uint32_t size);
void navi_pipe_reset_buf(navi_pipe_buf_t* buf);
 typedef struct navi_pipe_s navi_pipe_t; 
typedef navi_upreq_parse_status_e (*navi_pipe_parse_in_fp)(navi_pipe_t* pipe, uint8_t* in, size_t sz);
navi_upreq_parse_status_e nvup_pipe_redis_parse_in(navi_pipe_t* pipe, uint8_t *in, size_t sz);
void navi_pipe_append_msg(navi_pipe_t *pipe, uint8_t* in, size_t sz);

navi_pipe_t *nvup_pipe_get(const char *pipe_name);
//int nvup_pipe_set(struct sockaddr_in *paddr, navi_pipe_t *pipe);
int nvup_pipe_set(navi_pipe_t *pipe);
void nvup_pipe_reset_ve(navi_pipe_t *pipe);
int navi_pipe_restart(navi_pipe_t *pipe);
void nvup_pipe_mgr_destroy(void);
void  navi_pipe_ping(navi_pipe_t *pipe);

typedef enum _navi_pipe_status_e
{
	NAVI_PIPE_STATUS_INIT,
	NAVI_PIPE_STATUS_CONNECTED,
	NAVI_PIPE_STATUS_DISCONNECTED
}navi_pipe_status_e;

typedef struct navi_pipe_check_s{
	int ping_interval;
	int fails;
	time_t last_start;	
}navi_pipe_check_t;

struct navi_pipe_s
{
	char *group;
	char *server_name;
	navi_pipe_check_t check;
	navi_pipe_status_e status;
	navi_upreq_proto_type_e proto;
	navi_pipe_buf_t *out_pack;	//请求协议包缓存
	nvup_redis_proto_t *proto_redis;//响应的协议解析
	navi_pipe_parse_in_fp parse_in;
	chain_node_t link;
	chain_node_t new_conn_link;
	chain_node_t close_conn_link;
	chain_node_t write_link;
	struct sockaddr_storage peer_addr;
	char local_name[128];
	void *driver;
};

typedef struct navi_pipe_mgr_s
{
	chain_node_t new_conn_link;
	chain_node_t close_conn_link;
	chain_node_t write_link;
	navi_hash_t *hash;
}navi_pipe_mgr_t;

navi_pipe_mgr_t *nvup_pipe_mgr_get(void);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_PIPE_H_ */

