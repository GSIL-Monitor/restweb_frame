/*
 * navi_request_impl.h
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 */

#ifndef NAVI_REQUEST_IMPL_H_
#define NAVI_REQUEST_IMPL_H_

#include "navi_request.h"
#include "navi_simple_hash.h"
#include "navi_buf_chain.h"
#include "navi_module_mgr.h"
#include "navi_req_trace.h"

#define NAVI_HANDLE_MAGIC 0x87aef391

#define NAVI_ITER_REQ_HEADER_MAGIC 0x9ecf79a9
#define NAVI_ITER_REQ_ARG_MAGIC 0x9ecf79a8
#define NAVI_ITER_RESP_HEADER_MAGIC 0x9ecf79a7
#define NAVI_ITER_REG_MAGIC 0x9ecf79a6
#define NAVI_ITER_CANCEL_MAGIC 0x9ecf79a5
#define NAVI_ITER_SUB_MAGIC 0x9ecf79a4

typedef struct navi_main_req_data_s navi_main_req_data_t;

typedef struct navi_request_impl_s {
	navi_request_t handle;
	void* driver_peer;

	navi_request_method_e http_method;
	char* uri;
	char* args_raw;
	navi_buf_chain_t* post_chain;
	uint8_t* post_content;
	size_t post_size;
	navi_hash_t* args;
	navi_hash_t* headers;

	int resp_http_code;
	navi_hash_t* resp_http_headers;
	uint8_t* resp_http_body;
	size_t resp_http_body_len;

	navi_buf_chain_t* resp_body_chain;

	navi_request_status_e navi_status;
	int64_t cost_us;
	int64_t last_eval_stmp;

	uint32_t pending_subs;
	//bool own_resp_arrived;
	//bool recycle_flag;

    uint32_t resp_rate;//回送响应速率，单位byte/s
    uint32_t resp_rate_after;//回送限速起始大小，单位byte

	int own_resp_arrived:1;
	int recycle_flag:1;
	int drive_from_rest:1;

	struct navi_request_impl_s* parent;
	struct navi_request_impl_s* child;
	struct navi_request_impl_s* next;
	struct navi_request_impl_s* main;

	union {
        //如果是子请求，请求会处在reg链表，proc链表，cancel链表，recycle链表中
        chain_node_t cmd_link;

		//cnavi0.5.0 如果是主请求，指向当前处理主请求的模块，如果是
		//在事前事后内部组件模块链表的处理过程中，还会指向该链表
		navi_module_t* app_mod;
		struct {
			navi_ic_link_t* ic_mod;
			navi_ic_module_chain_t* ic_chain;
		};
	};
	union {
		navi_main_req_data_t *main_data;
		//cnavi0.3.0优化:
		// 子请求的uri, args_raw, post_chain, post_content, args, headers,
		// resp_http_headers, resp_http_body, resp_body_chain 数据成员
		// 使用独立的pool， 便于请求的回收和内存的集约使用。
		navi_pool_t* cld_dp;
	};

	chain_node_t rest_drive_link; /*!< 那些当前没有子请求、定时器、虚事件的主请求，由于输入流未完、输出流未完、或者未开启autofin而延迟进行事后处理时，在上述条件都变为真时，加入navi_module_mgr的redrive链表，对请求进行处理*/

	navi_pool_t pool_storage[0];//内存分配优化
}navi_request_impl_t;

#define check_req_h(h)  ( (h) && (h)->_magic==NAVI_HANDLE_MAGIC )
#define navi_req_h2i(h)  (navi_request_impl_t*)( (char*)(h) - offsetof(navi_request_impl_t,handle) )

typedef enum _navi_root_req_stage_e {
	NAVI_ROOT_STAGE_PREV_APP,
	NAVI_ROOT_STAGE_APP,
	NAVI_ROOT_STAGE_APP_BIGPOST,
	NAVI_ROOT_STAGE_POST_APP,
	NAVI_ROOT_STAGE_FINALIZED
}navi_root_req_stage_e;

typedef enum _navi_root_req_ctrl_e {
	NAVI_ROOT_NO_CTRL,
	NAVI_ROOT_DENYED,
	NAVI_ROOT_CONCLUDE
}navi_root_req_ctrl_e;

struct navi_main_req_data_s {
	char* service;
	char* module;
	char* method;
	char* rest_uri; //!< 在/rootpath/module/method/之后的uri部分，不包括'/'
	char* xcaller;
	char* cli_ip;

	chain_node_t ve_link;
	chain_node_t reg_chain;
	chain_node_t cancel_chain;
	chain_node_t recycle_chain;

	navi_response_t* resp;
	void* navi_mgr;
	//uint32_t mod_idx;

	navi_timer_mgr_t timers; //主请求上的定时器

	uint32_t time_out;
	navi_griter_mgr_t iter_mgr;

	navi_root_req_stage_e cur_stage;
	navi_root_req_ctrl_e cur_ctrl;
	navi_trace_t* trace;

	int should_emerg_resp:1;

	ssize_t streaming_body_total;
	size_t streamed_body_len;
	navi_buf_chain_t* streamed_body_buf;

	void* (*get_driver_peer_pool)(void*);

	char* bigpost_temp_file; //!< bigpost临时文件路径
	int file_body_fd;

	int auto_finalize:1; //!< 标记是否自动finalize。非自动request，更改为自动时，驱动层会进行关闭的处理

	int bigpost_file:1; //!< 要求http请求 body是以完整文件方式提供的
	int bigpost_complete:1; //!< 标记bigpost内容是否完整
	int bigpost_abort:1; //!< 表示bigpost被拒绝

	int outbody_navi:1; //!< 标准的navi输出
	int outbody_bin:1; //!< 以二进制内容整块输出
	int outbody_file:1; //!< 以文件的形式提供http响应
	int outbody_file_cached_fd:1;

	int outbody_stream:1; //!< 内容以流式提供
	int outbody_stream_eof:1; //!<标记输出流是否结束
	int outbody_stream_incomplete:1; //!<标记输出流结束后，是否完整
};

int navi_mgr_step_request(navi_request_t* r, void* ctx);

void* navi_request_get_driver_pool(navi_request_t* req);

#endif /* NAVI_REQUEST_IMPL_H_ */
