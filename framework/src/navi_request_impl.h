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

    uint32_t resp_rate;//������Ӧ���ʣ���λbyte/s
    uint32_t resp_rate_after;//����������ʼ��С����λbyte

	int own_resp_arrived:1;
	int recycle_flag:1;
	int drive_from_rest:1;

	struct navi_request_impl_s* parent;
	struct navi_request_impl_s* child;
	struct navi_request_impl_s* next;
	struct navi_request_impl_s* main;

	union {
        //���������������ᴦ��reg����proc����cancel����recycle������
        chain_node_t cmd_link;

		//cnavi0.5.0 �����������ָ��ǰ�����������ģ�飬�����
		//����ǰ�º��ڲ����ģ������Ĵ�������У�����ָ�������
		navi_module_t* app_mod;
		struct {
			navi_ic_link_t* ic_mod;
			navi_ic_module_chain_t* ic_chain;
		};
	};
	union {
		navi_main_req_data_t *main_data;
		//cnavi0.3.0�Ż�:
		// �������uri, args_raw, post_chain, post_content, args, headers,
		// resp_http_headers, resp_http_body, resp_body_chain ���ݳ�Ա
		// ʹ�ö�����pool�� ��������Ļ��պ��ڴ�ļ�Լʹ�á�
		navi_pool_t* cld_dp;
	};

	chain_node_t rest_drive_link; /*!< ��Щ��ǰû�������󡢶�ʱ�������¼�������������������δ�ꡢ�����δ�ꡢ����δ����autofin���ӳٽ����º���ʱ����������������Ϊ��ʱ������navi_module_mgr��redrive������������д���*/

	navi_pool_t pool_storage[0];//�ڴ�����Ż�
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
	char* rest_uri; //!< ��/rootpath/module/method/֮���uri���֣�������'/'
	char* xcaller;
	char* cli_ip;

	chain_node_t ve_link;
	chain_node_t reg_chain;
	chain_node_t cancel_chain;
	chain_node_t recycle_chain;

	navi_response_t* resp;
	void* navi_mgr;
	//uint32_t mod_idx;

	navi_timer_mgr_t timers; //�������ϵĶ�ʱ��

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

	char* bigpost_temp_file; //!< bigpost��ʱ�ļ�·��
	int file_body_fd;

	int auto_finalize:1; //!< ����Ƿ��Զ�finalize�����Զ�request������Ϊ�Զ�ʱ�����������йرյĴ���

	int bigpost_file:1; //!< Ҫ��http���� body���������ļ���ʽ�ṩ��
	int bigpost_complete:1; //!< ���bigpost�����Ƿ�����
	int bigpost_abort:1; //!< ��ʾbigpost���ܾ�

	int outbody_navi:1; //!< ��׼��navi���
	int outbody_bin:1; //!< �Զ����������������
	int outbody_file:1; //!< ���ļ�����ʽ�ṩhttp��Ӧ
	int outbody_file_cached_fd:1;

	int outbody_stream:1; //!< ��������ʽ�ṩ
	int outbody_stream_eof:1; //!<���������Ƿ����
	int outbody_stream_incomplete:1; //!<���������������Ƿ�����
};

int navi_mgr_step_request(navi_request_t* r, void* ctx);

void* navi_request_get_driver_pool(navi_request_t* req);

#endif /* NAVI_REQUEST_IMPL_H_ */
