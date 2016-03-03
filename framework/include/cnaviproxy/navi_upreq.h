/*
 * navi_upreq.h
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 *      Desc:
 */

#ifndef NAVI_UPREQ_H_
#define NAVI_UPREQ_H_
#include "navi_request.h"
#include "navi_buf_chain.h"
#include "navi_simple_hash.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/un.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum navi_upreq_parse_status
{
	NVUP_PARSE_STATUS_INVALID,
	NVUP_PARSE_AGAIN,
	NVUP_PARSE_DONE,
	NVUP_PARSE_PROTO_ERROR
} navi_upreq_parse_status_e;

typedef enum navi_upreq_code
{
	NVUP_RESULT_UNSET,
	NVUP_RESULT_SESSION_OK = 10000,
	NVUP_RESULT_CONN_FAILED = 20001,
	NVUP_RESULT_RW_FAILED = 20002,
	NVUP_RESULT_CONN_TIMEOUT = 20003,
	NVUP_RESULT_RW_TIMEOUT = 20004,
	NVUP_RESULT_UPIN_PROTO_ERROR = 30001,
	NVUP_RESULT_CLI_ERROR = 40001,
	NVUP_RESULT_POLICY_UNRESOLVE = 50001,
	NVUP_RESULT_INNER_ERROR = 50002,
	NVUP_RESULT_TIMEOUT_ABORTED = 50003,
	NVUP_RESULT_ABORTED = 50004
} navi_upreq_code_e;

typedef enum navi_upreq_proto_type
{
	NVUP_PROTO_INVALID,
	NVUP_PROTO_HTTP,
	NVUP_PROTO_NAVI,
	NVUP_PROTO_REDIS
} navi_upreq_proto_type_e;

typedef struct navi_upreq_policy_s
{
	union {
		struct sockaddr peer_addr;
		struct sockaddr_in peer_addr_in;
		struct sockaddr_in6 peer_addr_in6;
		struct sockaddr_un peer_addr_un;
	};
	uint32_t in_proto_buf_sz;
	uint32_t cnn_timeout_ms;
	uint32_t rw_timeout_ms;
	char* server_name;
	//http代理过程中，需要特殊增加的头部. 例如host头部，以解决虚拟主机的问题。
	//还比如，navi外部代理请求的x-caller头部
	char* root_uri;
	navi_hash_t* gr_headers;
	navi_hash_t* gr_args;
	navi_pool_t* pool;
	json_t* gr_data; //策略输出的其他值，以键值标记。用json表达通用数据，可扩展行好
} navi_upreq_policy_t;

typedef struct navi_upreq_s navi_upreq_t;
typedef struct navi_upreq_result_s navi_upreq_result_t;

typedef const char* (*navi_upreq_get_policy_key_fp)(navi_upreq_t* up,
    const char* key);
typedef navi_upreq_parse_status_e (*navi_upreq_parse_in_fp)(navi_upreq_t* up, uint8_t* in, size_t sz);
typedef void (*navi_upreq_destroy_fp)(navi_upreq_t* up);
typedef void (*navi_upreq_proc_result_fp)(navi_upreq_t* up, navi_upreq_result_t* res);

typedef struct navi_upreq_proc_s
{
	// 某些数据服务组的分发策略，是基于请求的。可以归纳为，从请求中获取某几个固定的key值
	// 作为分发策略计算的输入参数，而策略的结果，主要是选中的服务器的ip:port信息
	navi_upreq_get_policy_key_fp get_policy_key;
	// 非http类的navi upreq，需要负责后端服务器返回的响应数据的协议解析
	navi_upreq_parse_in_fp parse_in;
	navi_upreq_proc_result_fp proc_result;
	navi_upreq_destroy_fp destroy;
} navi_upreq_proc_t;

typedef enum navi_upreq_data_type_E
{
	NVUP_RESULT_DATA_NULL,
	NVUP_RESULT_DATA_INT,
	NVUP_RESULT_DATA_DOUBLE,
	NVUP_RESULT_DATA_STRING,
	NVUP_RESULT_DATA_JSON,
	NVUP_RESULT_DATA_PAIR,
	NVUP_RESULT_DATA_POOL_BIN,
	NVUP_RESULT_DATA_HEAP_BIN,
	NVUP_RESULT_DATA_ERR
} navi_upreq_data_type_e;

struct navi_upreq_in_bin_s
{
	uint8_t* data;
	size_t size;
};

struct navi_upreq_result_s
{
	navi_upreq_code_e code;
	char* session_err_desc; /*会话失败时的失败原因*/
	int32_t ess_logic_code;
	navi_upreq_data_type_e content_type;
	union
	{
		int64_t i;
		double d;
		char* s;
		struct
		{
			char* k;
			char* v;
		} pair;
		char* err; /*会话成功，但是后端给出的明确的错误信息*/
		struct navi_upreq_in_bin_s bin; //后端服务返回的数据的二进制格式
		json_t* js; //后端服务返回数据的通用封装
	};
};

//navi upstream请求的公共抽象部分。
struct navi_upreq_s
{
	//upreq的输入参数
	navi_request_t* bind_channel;
	char* group_name;
	char* srv_name;
	navi_upreq_proc_t *procs;
	navi_upreq_proto_type_e proto;

	//请求协议包缓存
	navi_buf_chain_t *out_pack;

	navi_upreq_policy_t policy;
	/**
	 * 非http类的upstream请求使用如下成员。
	 * http类的upstream请求，实际upstream处理是ngx_http_proxy_module
	 * 进行
	 */
	navi_upreq_result_t result;
	navi_pool_t* pool;
};

int navi_upreq_init(navi_upreq_t* req);
void navi_upreq_destroy(navi_upreq_t* req);
const char* navi_upreq_get_policy_key(navi_upreq_t* up, const char* key);

static inline navi_upreq_parse_status_e navi_upreq_parse_in(navi_upreq_t* up, uint8_t* in,
    size_t sz)
{
	return up->procs->parse_in(up, in, sz);
}

static inline void navi_upreq_set_getpolicykey(navi_upreq_t* req, navi_upreq_get_policy_key_fp fp)
{
	navi_upreq_proc_t *nproc = navi_pool_calloc(req->pool, 1, sizeof(navi_upreq_proc_t));
	*nproc = *req->procs;
	nproc->get_policy_key = fp;
	req->procs = nproc;
}

static inline void navi_upreq_set_proc_result(navi_upreq_t* req, navi_upreq_proc_result_fp fp)
{
	navi_upreq_proc_t *nproc = navi_pool_calloc(req->pool, 1, sizeof(navi_upreq_proc_t));
	*nproc = *req->procs;
	nproc->proc_result = fp;
	req->procs = nproc;
}

void navi_request_bind_upreq(navi_upreq_t* up, navi_request_t* binded);
navi_upreq_t* navi_request_binded_upreq(navi_request_t* request);

static inline const navi_upreq_result_t* navi_upreq_result(navi_upreq_t* req)
{
	if (!req)
		return NULL;
	return &req->result;
}

static inline const navi_upreq_policy_t* navi_upreq_policy(navi_upreq_t* req)
{
	if (!req)
		return NULL;
	return &req->policy;
}

static inline navi_request_t* navi_upreq_channel(navi_upreq_t* req)
{
	if (!req)
		return NULL;
	return req->bind_channel;
}

static inline size_t navi_upreq_get_out_package(navi_upreq_t* req, uint8_t* out, size_t buf_sz)
{
	if (!req || !req->out_pack)
		return 0;
	return navi_buf_chain_get_content(req->out_pack, out, buf_sz);
}

static inline void navi_upreq_error_lt(navi_upreq_t* req,
    navi_upreq_code_e code, int32_t ess_code, const char* info)
{
	req->result.code = code;
	req->result.session_err_desc = (char*) info;
	req->result.ess_logic_code = ess_code;
	//if (req->procs->proc_result)
	//	req->procs->proc_result(req, &req->result);
}

static inline void navi_upreq_error(navi_upreq_t* req,
    navi_upreq_code_e code, int32_t ess_code, const char* info)
{
	req->result.code = code;
	req->result.session_err_desc = navi_pool_strdup(req->pool, info);
	req->result.ess_logic_code = ess_code;
	//if (req->procs->proc_result)
	//	req->procs->proc_result(req, &req->result);
}

// 不同的协议代理upreq，有各种数据接口，那些接口负责数据包的封装，调用该函数写入协议输出数据
int navi_upreq_proto_append_out(navi_upreq_t* req, uint8_t* o, size_t sz);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_UPREQ_H_ */
