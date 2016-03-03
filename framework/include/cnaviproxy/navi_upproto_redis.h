/*
 * navi_upproto_redis.h
 *
 *  Created on: 2013-12-12
 *      Author: li.lei
 *      Desc:
 *      	redis 响应解析模块。upredis接口使用， 某些针对redis-server 的navi_upserver_ping_t
 *      	也需要使用。
 *
 *      	redis 命令结构及输出协议包处理。 公用模块
 */

#ifndef NAVI_UPPROTO_REDIS_H_
#define NAVI_UPPROTO_REDIS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "navi_common_define.h"
#include "navi_upreq_inbuf.h"
#include "navi_simple_array.h"
#include "navi_buf_chain.h"
#include "navi_upreq.h"

typedef enum redis_proto_type_E
{
	redis_type_proto_error,
	redis_type_single_bulk,
	redis_type_multi_bulk,
	redis_type_error_reply,
	redis_type_status_reply,
	redis_type_num
} redis_proto_type_e;

typedef enum redis_proto_stage_E
{
	redis_stage_start,
	redis_stage_number_line,
	redis_stage_single_line,
	redis_stage_bulk_count,
	redis_stage_bulk_start,
	redis_stage_bulk_len,
	redis_stage_bulk_content,
	redis_stage_done
} redis_proto_stage_e;

typedef enum redis_proto_status_E
{
	redis_break_pending,
	redis_break_r,
	redis_break_n
} redis_proto_break_e;

typedef struct redis_bulk_s {
	redis_proto_type_e bulk_type;
	union {
		char* s;
		int64_t i;
	};
} redis_bulk_t;

typedef struct redis_proto_s
{
	redis_proto_type_e proto_type; //redis响应协议类型

	int64_t num_result;
	char* str_result;
	navi_array_t* in_bulks; //redis_bulk_t成员

	int bulk_count; //bulk个数
	int bulk_size; //当前bulk的字节大小
	int cur_bulk_check; //当前bulk已遍历大小
	int cur_num_check;
	redis_proto_break_e break_status;
	redis_proto_stage_e pending_stage;
	redis_proto_type_e pending_bulk_type;

	nvup_inbuf_t parse_buf;
	navi_pool_t* pool;
} nvup_redis_proto_t;

navi_upreq_parse_status_e nvup_redis_proto_parse_in(nvup_redis_proto_t* ctx, uint8_t* in, size_t sz);

static inline int nvup_redis_proto_init(nvup_redis_proto_t* obj, navi_pool_t* pool, size_t parse_buf_sz)
{
	memset(obj, 0x00, sizeof(nvup_redis_proto_t));

	nvup_inbuf_init(&obj->parse_buf, parse_buf_sz);

	if (obj->parse_buf.buf == NULL)
		return NAVI_INNER_ERR;

	obj->pool = pool;
	return NAVI_OK;
}

static inline void nvup_redis_proto_reset(nvup_redis_proto_t* obj)
{
	navi_pool_reset(obj->pool);
	memset( obj, 0x00, offsetof(nvup_redis_proto_t, parse_buf));
}

static inline void nvup_redis_proto_clean(nvup_redis_proto_t* obj)
{
	nvup_inbuf_clean(&obj->parse_buf);
}

typedef enum nvup_redis_cmd_struct_E
{
	NVUP_REDIS_CMDST_INVALID,
	NVUP_REDIS_CMDST_1KEY,
	NVUP_REDIS_CMDST_MKEYS,
	NVUP_REDIS_CMDST_PUR_1ARG,
	NVUP_REDIS_CMDST_PUR_MARGS
} nvup_redis_cmd_struct_e;

typedef enum nvup_redis_keyarg_struct_E
{
	NVUP_REDIS_KEY_0ARG,
	NVUP_REDIS_KEY_1ARG,
	NVUP_REDIS_KEY_2ARG,
	NVUP_REDIS_KEY_MARG
} nvup_redis_keyarg_struct_e;

typedef struct navi_upredis_cmd_key_s
{
	const char* key;
	nvup_redis_keyarg_struct_e arg_st;
	union
	{
		struct
		{ //绝大部分命令除key外，有1~2个参数
			const char* arg1;
			const char* arg2;
		};
		navi_array_t* margs; //少数命令的key之后有多个参数
	};
} nvup_redis_cmd_key_t;

typedef struct navi_upredis_cmd_s
{
	const char* cmd;
	nvup_redis_cmd_struct_e cmd_st;
	union
	{
		nvup_redis_cmd_key_t* s_key; //大部分命令只有1个key，以及对应的参数
		navi_array_t* m_keys; //nvup_redis_cmd_key_t数组。 命令有可一次操作多个key的命令
		const char* s_arg; //纯单一参数命令
		navi_array_t* m_args; //纯多参数命令
	};
} nvup_redis_cmd_t;

void nvup_redis_cmd_2outpack(nvup_redis_cmd_t* cmd, navi_buf_chain_t* out);

/*
 * 如下内容在upredis代理内部代码使用，应用开发者不需要关心
 */
#define UPREDIS_SKEY_0ARG_CMD(OBJ, POOL, CMD, KEY, OCHAIN) do{\
	(OBJ)->cmd = (CMD);\
	(OBJ)->cmd_st = NVUP_REDIS_CMDST_1KEY;\
	(OBJ)->s_key = (nvup_redis_cmd_key_t*) navi_pool_calloc((POOL),1,\
		sizeof(nvup_redis_cmd_key_t));\
	(OBJ)->s_key->arg_st = NVUP_REDIS_KEY_0ARG;\
	(OBJ)->s_key->key = (KEY);\
	nvup_redis_cmd_2outpack((OBJ), (OCHAIN));\
}while(0);

#define UPREDIS_SKEY_MARG_CMD(OBJ, POOL, CMD, KEY, CNT) do{\
	(OBJ)->cmd = (CMD);\
	(OBJ)->cmd_st = NVUP_REDIS_CMDST_1KEY;\
	(OBJ)->s_key = (nvup_redis_cmd_key_t*) navi_pool_calloc((POOL),1,\
		sizeof(nvup_redis_cmd_key_t));\
	(OBJ)->s_key->arg_st = NVUP_REDIS_KEY_MARG;\
	(OBJ)->s_key->key = (KEY);\
	(OBJ)->s_key->margs = navi_array_create((POOL), (CNT),\
		sizeof(char*));\
}while(0);

#define UPREDIS_MKEY_CMD(OBJ,POOL, CMD, CNT) do{\
	(OBJ)->cmd = (CMD);\
	(OBJ)->cmd_st = NVUP_REDIS_CMDST_MKEYS;\
	(OBJ)->m_keys = navi_array_create((POOL),(CNT),\
		sizeof(nvup_redis_cmd_key_t));\
}while(0);

#define UPREDIS_SKEY_1ARG_CMD(OBJ, POOL, CMD, KEY, ARG, OCHAIN) do{\
	(OBJ)->cmd = (CMD);\
	(OBJ)->cmd_st = NVUP_REDIS_CMDST_1KEY;\
	(OBJ)->s_key = (nvup_redis_cmd_key_t*) navi_pool_calloc((POOL),1,\
		sizeof(nvup_redis_cmd_key_t));\
	(OBJ)->s_key->arg_st = NVUP_REDIS_KEY_1ARG;\
	(OBJ)->s_key->key = (KEY);\
	(OBJ)->s_key->arg1 = (ARG);\
	nvup_redis_cmd_2outpack((OBJ), (OCHAIN));\
}while(0);

#define UPREDIS_SKEY_2ARG_CMD(OBJ, POOL, CMD, KEY, ARG1,ARG2, OCHAIN) do{\
	(OBJ)->cmd = (CMD);\
	(OBJ)->cmd_st = NVUP_REDIS_CMDST_1KEY;\
	(OBJ)->s_key = (nvup_redis_cmd_key_t*) navi_pool_calloc((POOL),1,\
		sizeof(nvup_redis_cmd_key_t));\
	(OBJ)->s_key->arg_st = NVUP_REDIS_KEY_2ARG;\
	(OBJ)->s_key->key = (KEY);\
	(OBJ)->s_key->arg1 = (ARG1);\
	(OBJ)->s_key->arg2 = (ARG2);\
	nvup_redis_cmd_2outpack((OBJ), (OCHAIN));\
}while(0);

#define UPREDIS_PUR1ARG_CMD(OBJ,POOL, CMD, ARG, OCHAIN) do{\
	(OBJ)->cmd = (CMD);\
	(OBJ)->cmd_st = NVUP_REDIS_CMDST_PUR_1ARG;\
	(OBJ)->s_arg = (ARG);\
	nvup_redis_cmd_2outpack((OBJ), (OCHAIN));\
}while(0);

#define UPREDIS_PURMARG_CMD(OBJ,POOL, CMD, CNT) do{\
	(OBJ)->cmd = (CMD);\
	(OBJ)->cmd_st = NVUP_REDIS_CMDST_PUR_MARGS;\
	(OBJ)->m_args = navi_array_create((POOL),(CNT),\
		sizeof(char*));\
}while(0);

#ifdef __cplusplus
};
#endif

#endif /* NAVI_UPPROTO_REDIS_H_ */
