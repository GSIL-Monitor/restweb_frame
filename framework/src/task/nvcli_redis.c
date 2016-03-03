/** \brief 
 * nvcli_redis.h
 *  Created on: 2015-1-16
 *      Author: li.lei
 *  brief: 
 */

#include "nvcli_redis.h"

static void nvredis_complete_handler(void* parent, void* cli)
{
	nvcli_redis_t* redis = (nvcli_redis_t*)cli;
	redis->proto2result(&redis->in_parser, &redis->result);
	redis->result_handler(parent, redis, &redis->result);
}

static int nvredis_iheader_parse(void* ss, const unsigned char* in, size_t* sz)
{
	nvcli_redis_t* redis = (nvcli_redis_t*)ss;
	navi_upreq_parse_status_e ret = nvup_redis_proto_parse_in(&redis->in_parser, (uint8_t*)in, *sz);
	switch(ret) {
	case NVUP_PARSE_AGAIN:
		return 0;
	case NVUP_PARSE_DONE:
		redis->base.iheader_done = 1;
		redis->base.input_done = 1;
		redis->result.code = NVUP_RESULT_SESSION_OK;//app handler中需要判断
		redis->in_parser.pending_stage = redis_stage_start;
		return 1;
	default:
		return -1;
	}
}

static int nvredis_ibody_parse(void* ss, const unsigned char* content, size_t* size)
{
	return 1;
}

void nvredis_cleanup(void* sub)
{
	nvcli_redis_t* redis = (nvcli_redis_t*)sub;
	nvup_redis_proto_clean(&redis->in_parser);
	switch (redis->result.content_type) {
	case NVUP_RESULT_DATA_JSON:
		json_decref(redis->result.js);
		break;
	case NVUP_RESULT_DATA_HEAP_BIN:
		free(redis->result.bin.data);
		break;
	default:
		break;
	}
}

static nvcli_proto_proc_t redis_proto = {
	NVCLI_REDIS,
	sizeof(nvcli_redis_t),
	nvredis_iheader_parse,
	nvredis_ibody_parse,
	nvredis_cleanup
};

nvcli_redis_t* nvcli_redis_init(nvcli_parent_t* ctx,
	const struct sockaddr* peer_addr,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval)
{
	navi_grcli_app_proc_t app_procs = {
		(nvcli_error_fp)error_handler,
		nvredis_complete_handler,
		NULL
	};
	nvcli_redis_t* obj = nvcli_init(ctx,&redis_proto, (const navi_grcli_app_proc_t*)&app_procs, app_data, 
		conn_timeout, resp_max_waiting, input_max_interval, peer_addr);
	if (!obj)
		return NULL;

	memset( &obj->cmd, 0x00, sizeof(nvcli_redis_t) - offsetof(nvcli_redis_t, cmd));

	nvup_redis_proto_init(&obj->in_parser, obj->base.private_pool, 512);

	obj->result_handler = result_handler;
	if (obj->base.conn->out_buf == NULL)
		obj->base.conn->out_buf = navi_buf_chain_init(obj->base.conn->pool);//init out buf for cmd
	return obj;
}

int nvcli_redis_del(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "DEL", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;

	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}


int nvcli_redis_mdel(nvcli_redis_t* upreq, const char** keys, size_t sz)
{
	UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.private_pool, "MDEL", sz);
	int j;
	nvup_redis_cmd_key_t* cmd_key;
	for (j=0; j<sz ; j++) {
		cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(upreq->cmd.m_keys);
		cmd_key->key = navi_pool_strdup(upreq->base.private_pool,
			keys[j]);
		cmd_key->arg_st = NVUP_REDIS_KEY_0ARG;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_type(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "TYPE", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_str_result_from_status;

	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_dump(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool,"DUMP", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_str_result_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_restore(nvcli_redis_t* upreq, const char* key, int32_t ttl,  const char* serl /*对象的序列化串*/)
{
	char buf[12];
	snprintf(buf,sizeof(buf),"%d",ttl);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool,"RESTORE", key, buf, serl,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_ok_result_from_status;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_exists(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool,"EXISTS", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_expire(nvcli_redis_t* upreq, const char* key, uint32_t to)
{
	char buf[12];
	snprintf(buf,sizeof(buf),"%u",to);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool,"EXPIRE", key, buf,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_pexpire(nvcli_redis_t* upreq, const char* key, uint64_t to_ms)
{
	char buf[24];
	snprintf(buf,sizeof(buf),"%llu",to_ms);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool,"PEXPIRE", key, buf,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_expireat(nvcli_redis_t* upreq, const char* key, time_t stmp)
{
	char buf[24];
	snprintf(buf,sizeof(buf),"%lld",(int64_t)stmp);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool,"EXPIREAT", key, buf,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_pexpireat(nvcli_redis_t* upreq, const char* key, time_t stmp, uint16_t ms)
{
	uint64_t stmp_ms = (uint64_t)stmp * 1000 + ms;
	char buf[24];
	snprintf(buf,sizeof(buf),"%llu",stmp_ms);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool,"PEXPIREAT", key, buf,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_persist(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool,"PERSIST", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_ttl(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool,"TTL", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_pttl(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool,"PTTL", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_movedb(nvcli_redis_t* upreq, const char* key, uint32_t db)
{
	char buf[12];
	snprintf(buf,sizeof(buf),"%u",db);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool,"MOVE", key, buf,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_sort(nvcli_redis_t* upreq, const char* key, bool desc, bool alpha, size_t limit_off, size_t limit_count,
	const char* by_pattern, const char** get_patterns, size_t get_pttn_sz)
{
	char buf[30];
	char buf1[30];
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "SORT", key, 10);

	const char** parg=NULL;
	if (desc) {
		parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = "DESC";
	}

	if (alpha) {
		parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = "ALPHA";
	}

	if (limit_count) {
		parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = "LIMIT";

		snprintf(buf,sizeof(buf),"%d", limit_off);
		parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = buf;

		snprintf(buf1,sizeof(buf1),"%d", limit_count);
		parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = buf1;
	}

	if (by_pattern) {
		parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = "BY";
		parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = by_pattern;
	}

	int i;
	for (i=0; i<get_pttn_sz; i++) {
		parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = "GET";
		parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = get_patterns[i];
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_set(nvcli_redis_t* upreq, const char* key, const char* value)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool,"SET", key,value,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_ok_result_from_status;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_setex(nvcli_redis_t* upreq, const char* key, const char* value,uint32_t expire_secs)
{
	char buf[24];
	snprintf(buf,sizeof(buf),"%d", expire_secs);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool,"SETEX", key, buf,
		value, upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_ok_result_from_status;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_psetex(nvcli_redis_t* upreq, const char* key, const char* value,uint32_t expire_msecs)
{
	char buf[24];
	snprintf(buf,sizeof(buf),"%d", expire_msecs);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool,"PSETEX", key, buf,
		value, upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_ok_result_from_status;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_setnx(nvcli_redis_t* upreq, const char* key, const char* value)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool,"SETNX", key,value,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_ok_result_from_status;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_set_v2612(nvcli_redis_t* upreq, const char* key, const char* value,
	uint32_t option, uint32_t expire_v)
{
	bool probe_null_mbulk = false;
	if (option == 0) {
		UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool,"SET", key,
			value, upreq->base.conn->out_buf);
	}
	else {
		UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "SET", key, 4);
		const char** parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = value;

		char buf[24];
		if (option|UPREDIS_SET_CMD_OPT_EX) {
			snprintf(buf, sizeof(buf), "%u", expire_v);
			parg = navi_array_push(upreq->cmd.s_key->margs);
			*parg = "EX";
			parg = navi_array_push(upreq->cmd.s_key->margs);
			*parg = navi_pool_strdup(upreq->base.private_pool,buf);
		}
		else if (option|UPREDIS_SET_CMD_OPT_PX) {
			snprintf(buf, sizeof(buf), "%u", expire_v);
			parg = navi_array_push(upreq->cmd.s_key->margs);
			*parg = "PX";
			parg = navi_array_push(upreq->cmd.s_key->margs);
			*parg = navi_pool_strdup(upreq->base.private_pool,buf);
		}

		if (option|UPREDIS_SET_CMD_OPT_NX) {
			parg = navi_array_push(upreq->cmd.s_key->margs);
			*parg = "NX";
			probe_null_mbulk= true;
		}
		else if (option|UPREDIS_SET_CMD_OPT_XX) {
			parg = navi_array_push(upreq->cmd.s_key->margs);
			*parg = "XX";
			probe_null_mbulk=true;
		}
		nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	}

	if (probe_null_mbulk) {
		upreq->proto2result = redisproto_get_ok_or_null_mbulk;
	}
	else {
		upreq->proto2result = redisproto_get_ok_result_from_status;
	}

	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}


int nvcli_redis_getset(nvcli_redis_t* upreq, const char* key, const char* value)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool,"GETSET", key, value,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_str_result_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_append(nvcli_redis_t* upreq, const char* key, const char* value)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool,"APPEND", key,
		value, upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_incr(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "INCR", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_incrby(nvcli_redis_t* upreq, const char* key, int64_t v)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%lld", v);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "INCRBY", key, buf,
		upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_incrbyfloat(nvcli_redis_t* upreq, const char* key, double v)
{
	char buf[40];
	snprintf(buf, sizeof(buf), "%f", v);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "INCRBYFLOAT", key,buf,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_float_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_decr(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "DECR", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_decrby(nvcli_redis_t* upreq, const char* key, int64_t v)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%lld", v);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "DECRBY", key, buf,
		upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}


int nvcli_redis_setrange(nvcli_redis_t* upreq, const char* key, size_t offset, const char* value)
{
	char buf[12];
	snprintf(buf, sizeof(buf), "%u", offset);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "SETRANGE", key, buf,
		value, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_getrange(nvcli_redis_t* upreq, const char* key, int start, int end)
{
	char buf1[12],buf2[12];
	snprintf(buf1,sizeof(buf1),"%d",start);
	snprintf(buf2,sizeof(buf2),"%d",end);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "SETRANGE", key,
		buf1, buf2, upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_str_result_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_get(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool,"GET", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_str_result_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_strlen(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "STRLEN", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_mget(nvcli_redis_t* upreq, const char** keys, size_t sz)
{
	UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.private_pool, "MGET", sz);
	int j;
	nvup_redis_cmd_key_t* cmd_key;
	for (j=0; j<sz ; j++) {
		cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(upreq->cmd.m_keys);
		cmd_key->key = navi_pool_strdup(upreq->base.private_pool,
			keys[j]);
		cmd_key->arg_st = NVUP_REDIS_KEY_0ARG;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_mset(nvcli_redis_t* upreq, nvup_rediskv_t* kvs, size_t sz)
{
	UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.private_pool, "MSET", sz);

	int j;
	nvup_redis_cmd_key_t* cmd_key;
	for (j=0; j<sz ; j++) {
		cmd_key->key = navi_pool_strdup(upreq->base.private_pool,kvs[j].k);
		cmd_key->arg1 = navi_pool_strdup(upreq->base.private_pool,kvs[j].v);
		cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_ok_result_from_status;

	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_msetnx(nvcli_redis_t* upreq, nvup_rediskv_t* kvs, size_t sz)
{
	UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.private_pool, "MSETNX", sz);

	int j;
	nvup_redis_cmd_key_t* cmd_key;
	for (j=0; j<sz ; j++) {
		cmd_key->key = navi_pool_strdup(upreq->base.private_pool,kvs[j].k);
		cmd_key->arg1 = navi_pool_strdup(upreq->base.private_pool,kvs[j].v);
		cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hset(nvcli_redis_t* upreq, const char* key, const char* subkey, const char* v)
{
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HSET", key, subkey, v,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hsetnx(nvcli_redis_t* upreq, const char* key, const char* subkey, const char* v)
{
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HSETNX", key, subkey, v,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hget(nvcli_redis_t* upreq, const char* key, const char* subkey)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HGET", key, subkey,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_str_result_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hdel(nvcli_redis_t* upreq, const char* key, const char* subkey)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HDEL", key, subkey,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hexists(nvcli_redis_t* upreq, const char* key, const char* subkey)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HEXISTS", key, subkey,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hmset(nvcli_redis_t* upreq, const char* key, nvup_rediskv_t* subs, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "HMSET", key, sz*2);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i].k;
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i].v;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_ok_result_from_status;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hmget(nvcli_redis_t* upreq, const char* key, const char** subs, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "HMGET", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hmdel(nvcli_redis_t* upreq, const char* key, const char** subs, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "HDEL", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hgetall(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HGETALL", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_kvpairs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hkeys(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HKEYS", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hvals(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HVALS", key,
			upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hlen(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HLEN", key,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hincrby(nvcli_redis_t* upreq, const char* key, const char* subkey, int64_t v)
{
	char buf[30];
	snprintf(buf, sizeof(buf), "%lld", v);

	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HINCRBY", key, subkey, buf,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_hincrbyfloat(nvcli_redis_t* upreq, const char* key, const char* subkey, double v)
{
	char buf[40];
	snprintf(buf, sizeof(buf), "%f", v);

	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "HINCRBYFLOAT", key, subkey, buf,
		upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_float_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}


int nvcli_redis_lpush(nvcli_redis_t* upreq, const char* key, const char** elmts, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "LPUSH", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = elmts[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_lpushx(nvcli_redis_t* upreq, const char* key, const char** elmts, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "LPUSHX", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = elmts[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_rpush(nvcli_redis_t* upreq, const char* key, const char** elmts, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "RPUSH", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = elmts[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_rpushx(nvcli_redis_t* upreq, const char* key, const char** elmts, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "RPUSHX", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = elmts[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_lpop(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "LPOP", key, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_str_result_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_rpop(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "RPOP", key, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_str_result_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_lset(nvcli_redis_t* upreq, const char* key, int32_t idx, const char* v)
{
	char buf[16];
	snprintf(buf,sizeof(buf), "%lld", idx);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "LSET", key,
		buf, v, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_ok_result_from_status;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_ltrim(nvcli_redis_t* upreq, const char* key, int32_t start, int32_t end)
{
	char buf1[16];
	char buf2[16];
	snprintf(buf1, sizeof(buf1), "%lld", start);
	snprintf(buf2, sizeof(buf2), "%lld", end);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "LTRIM", key,
		buf1, buf2, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_ok_result_from_status;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_lrem(nvcli_redis_t* upreq, const char* key, int32_t count, const char* match)
{
	char buf[16];
	snprintf(buf,sizeof(buf), "%lld", count);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "LSET", key,
		buf, match, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_linsert(nvcli_redis_t* upreq, const char* key, bool before, int32_t pivot, const char* v)
{
	char buf[16];
	snprintf(buf,sizeof(buf), "%lld", pivot);
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "LINSERT", key, 3);
	const char** parg;
	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	if (before)
		*parg = "BEFORE";
	else
		*parg = "AFTER";

	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = buf;

	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = v;

	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_lindex(nvcli_redis_t* upreq, const char* key, int32_t idx)
{
	char buf[16];
	snprintf(buf,sizeof(buf), "%lld", idx);

	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "LINDEX", key,
		buf, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_str_result_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_llen(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "LLEN", key,
		 upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_lrange(nvcli_redis_t* upreq, const char* key, int32_t start, int32_t end)
{
	char buf1[16];
	char buf2[16];
	snprintf(buf1, sizeof(buf1), "%lld", start);
	snprintf(buf2, sizeof(buf2), "%lld", end);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "LRANGE", key,
		buf1, buf2, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}


int nvcli_redis_blpop(nvcli_redis_t* upreq, const char* key, int32_t timeout)
{
	char buf1[16];
	snprintf(buf1, sizeof(buf1), "%lld", timeout);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "BLPOP", key,
		buf1, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_pair_from_mbulk;
	upreq->base.resp_max_waiting = timeout * 1000 * 2 + 3000;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_brpop(nvcli_redis_t* upreq, const char* key, int32_t timeout)
{
	char buf1[16];
	snprintf(buf1, sizeof(buf1), "%lld", timeout);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "BRPOP", key,
		buf1, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_pair_from_mbulk;
	upreq->base.resp_max_waiting = timeout * 1000 * 2 + 3000;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_brpoplpush_self(nvcli_redis_t* upreq, const char* key, int32_t timeout)
{
	char buf1[16];
	snprintf(buf1, sizeof(buf1), "%lld", timeout);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "BRPOPLPUSH", key, key,
		buf1, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_str_result_from_bulk;

	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}


int nvcli_redis_blpop_m(nvcli_redis_t* upreq, const char** keys, size_t sz, uint32_t timeout)
{
	UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.private_pool, "BLPOP",sz);
	char buf[20];
	snprintf( buf, sizeof(buf), "%u", timeout);

	int j;
	nvup_redis_cmd_key_t* cmd_key;
	for (j=0; j<sz ; j++) {
		cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(upreq->cmd.m_keys);
		cmd_key->key = navi_pool_strdup(upreq->base.private_pool,
			keys[j]);
		cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
		cmd_key->arg1 = buf;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);

	upreq->proto2result = redisproto_get_pair_from_mbulk;

	upreq->base.resp_max_waiting = timeout*1000*2 + 3000;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_brpop_m(nvcli_redis_t* upreq, const char** keys, size_t sz, uint32_t timeout)
{
	UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.private_pool, "BRPOP",sz);
	char buf[20];
	snprintf( buf, sizeof(buf), "%u", timeout);

	int j;
	nvup_redis_cmd_key_t* cmd_key;
	for (j=0; j<sz ; j++) {
		cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(upreq->cmd.m_keys);
		cmd_key->key = navi_pool_strdup(upreq->base.private_pool,
			keys[j]);
		cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
		cmd_key->arg1 = buf;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);

	upreq->base.resp_max_waiting = timeout*1000*2 + 3000;
	upreq->proto2result = redisproto_get_pair_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_rpoplpush(nvcli_redis_t* upreq, const char* key, const char* destkey)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "RPOPLPUSH", key,
		destkey, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_str_result_from_bulk;

	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_brpoplpush(nvcli_redis_t* upreq, const char* key, const char* destkey, int32_t timeout)
{
	char buf[20];
	snprintf( buf, sizeof(buf), "%u", timeout);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "BRPOPLPUSH", key,
		destkey, buf, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_str_result_from_bulk;
	upreq->base.resp_max_waiting = timeout*1000*2 + 3000;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_sadd(nvcli_redis_t* upreq, const char* key, const char** mems, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "SADD", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = mems[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_scard(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "SCARD", key,
		 upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_sismember(nvcli_redis_t* upreq, const char* key, const char* mem)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "SISMEMBER", key, mem,
		 upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_smembers(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "SMEMBERS", key,
		 upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_spop(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "SPOP", key,
		 upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_str_result_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_srandmember(nvcli_redis_t* upreq, const char* key, size_t count)
{
	char buf[16];
	snprintf(buf, sizeof(buf), "%u", count);

	if (count <= 1) {
		UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "SMEMBERS", key,
				 upreq->base.conn->out_buf);
		upreq->proto2result = redisproto_get_str_result_from_bulk;
	}
	else {
		UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "SMEMBERS", key,
				 buf, upreq->base.conn->out_buf);
		upreq->proto2result = redisproto_get_strs_from_mbulk;
	}
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_srem(nvcli_redis_t* upreq, const char* key, const char** mems, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "SREM", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = mems[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_zadd(nvcli_redis_t* upreq, const char* key, const nvup_redis_mscore_t* mems, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZADD", key, sz*2);
	size_t i;
	const char** parg;
	char buf[40];
	for (i=0; i<sz; i++){
		snprintf(buf, sizeof(buf), "%f", mems[i].score);
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = navi_pool_strdup(upreq->base.private_pool, buf);
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = mems[i].mem;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_zcard(nvcli_redis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZCARD", key,
		 upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zscore(nvcli_redis_t* upreq, const char* key, const char* mem)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZSCORE", key, mem,
		 upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_float_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zrank(nvcli_redis_t* upreq, const char* key, const char* mem)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZRANK", key, mem,
		 upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zrevrank(nvcli_redis_t* upreq, const char* key, const char* mem)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZREVRANK", key, mem,
		 upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zcount(nvcli_redis_t* upreq, const char* key, double min, double max)
{
	char buf1[40];
	char buf2[40];

	snprintf( buf1, sizeof(buf1), "%f", min);
	snprintf( buf2, sizeof(buf2), "%f", max);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZCOUNT", key, buf1, buf2,
		upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zincrby(nvcli_redis_t* upreq, const char* key, const char* mem, double by)
{
	char buf[40];
	snprintf( buf, sizeof(buf), "%f", by);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZINCRBY", key, buf, mem,
		upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_float_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zrange(nvcli_redis_t* upreq, const char* key, int32_t start_idx, int32_t stop_idx, bool withscore)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZRANGE", key, 3);

	char buf1[40];
	char buf2[40];
	snprintf( buf1, sizeof(buf1), "%d", start_idx);
	snprintf( buf2, sizeof(buf2), "%d", stop_idx);

	const char** parg;

	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = buf1;
	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = buf2;

	if (withscore) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = "WITHSCORES";
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);

	if (withscore)
		upreq->proto2result = redisproto_get_mem_score_from_mbulk;
	else
		upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zrevrange(nvcli_redis_t* upreq, const char* key, int32_t start_idx, int32_t stop_idx, bool withscore)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZREVRANGE", key, 3);

	char buf1[40];
	char buf2[40];
	snprintf( buf1, sizeof(buf1), "%d", start_idx);
	snprintf( buf2, sizeof(buf2), "%d", stop_idx);

	const char** parg;

	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = buf1;
	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = buf2;

	if (withscore) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = "WITHSCORES";
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);

	if (withscore)
		upreq->proto2result = redisproto_get_mem_score_from_mbulk;
	else
		upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zrangebyscore(nvcli_redis_t* upreq, const char* key, double min, double max,
	bool withscore, size_t off, size_t cnt)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZRANGEBYSCORE", key, 6);

	char buf1[40];
	char buf2[40];
	snprintf( buf1, sizeof(buf1), "%f", min);
	snprintf( buf2, sizeof(buf2), "%f", max);

	const char** parg;

	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = buf1;
	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = buf2;

	if (withscore) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = "WITHSCORES";
	}

	if (cnt>0) {
		char buf[16];
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = "LIMIT";

		snprintf( buf, sizeof(buf), "%u", off);
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = navi_pool_strdup(upreq->base.private_pool, buf);
		snprintf( buf, sizeof(buf), "%u", cnt);
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = navi_pool_strdup(upreq->base.private_pool, buf);
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);

	if (withscore)
		upreq->proto2result = redisproto_get_mem_score_from_mbulk;
	else
		upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zrevrangebyscore(nvcli_redis_t* upreq, const char* key, double min, double max,
	bool withscore, size_t off, size_t cnt)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZREVRANGEBYSCORE", key, 6);

	char buf1[40];
	char buf2[40];
	snprintf( buf1, sizeof(buf1), "%f", min);
	snprintf( buf2, sizeof(buf2), "%f", max);

	const char** parg;

	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = buf1;
	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = buf2;

	if (withscore) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = "WITHSCORES";
	}

	if (cnt>0) {
		char buf[16];
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = "LIMIT";

		snprintf( buf, sizeof(buf), "%u", off);
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = navi_pool_strdup(upreq->base.private_pool, buf);
		snprintf( buf, sizeof(buf), "%u", cnt);
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = navi_pool_strdup(upreq->base.private_pool, buf);
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);

	if (withscore)
		upreq->proto2result = redisproto_get_mem_score_from_mbulk;
	else
		upreq->proto2result = redisproto_get_strs_from_mbulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zrem(nvcli_redis_t* upreq, const char* key, const char** mems, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZADD", key, sz);
	size_t i;
	const char** parg;
	char buf[40];
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = mems[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zremrangebyrank(nvcli_redis_t* upreq, const char* key, int32_t start, int32_t stop)
{
	char buf1[40];
	char buf2[40];

	snprintf( buf1, sizeof(buf1), "%d", start);
	snprintf( buf2, sizeof(buf2), "%d", stop);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZREMRANGEBYRANK", key, buf1, buf2,
		upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}
int nvcli_redis_zremrangebyscore(nvcli_redis_t* upreq, const char* key, double min, double max)
{
	char buf1[40];
	char buf2[40];

	snprintf( buf1, sizeof(buf1), "%f", min);
	snprintf( buf2, sizeof(buf2), "%f", max);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.private_pool, "ZREMRANGEBYSCORE", key, buf1, buf2,
		upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_int_result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_lua_evalsha(nvcli_redis_t* upreq, const char* keyspace,
	const navi_upredis_script_t* script, void (*proto2result)(nvup_redis_proto_t*, navi_upreq_result_t*))
{
	UPREDIS_PURMARG_CMD(&upreq->cmd, upreq->base.private_pool, "EVALSHA",
		3 /*script 1 keyspace*/+ script->args_sz);
	char** parg = navi_array_push(upreq->cmd.m_args);
	*parg = script->script_sha;
	parg = navi_array_push(upreq->cmd.m_args);
	*parg = "1";
	parg = navi_array_push(upreq->cmd.m_args);
	*parg = (char*)keyspace;

	int i;
	for (i=0; i<script->args_sz; i++) {
		parg = navi_array_push(upreq->cmd.m_args);
		*parg = script->args[i];
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = proto2result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_lua_eval(nvcli_redis_t* upreq, const char* keyspace, const navi_upredis_script_t* script,
	void (*proto2result)(nvup_redis_proto_t*, navi_upreq_result_t*))
{
	UPREDIS_PURMARG_CMD(&upreq->cmd, upreq->base.private_pool, "EVAL",
		3 /*script 1 keyspace*/+ script->args_sz);
	char** parg = navi_array_push(upreq->cmd.m_args);
	*parg = script->script;
	parg = navi_array_push(upreq->cmd.m_args);
	*parg = "1";
	parg = navi_array_push(upreq->cmd.m_args);
	*parg = (char*)keyspace;

	int i;
	for (i=0; i<script->args_sz; i++) {
		parg = navi_array_push(upreq->cmd.m_args);
		*parg = script->args[i];
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = proto2result;
	nvcli_send_header(&upreq->base, NULL, 0, true);
	return 0;
}

int nvcli_redis_lua_load(nvcli_redis_t* upreq, const char* script)
{
	UPREDIS_PURMARG_CMD(&upreq->cmd, upreq->base.private_pool, "SCRIPT",
		3);
	char** parg = navi_array_push(upreq->cmd.m_args);
	*parg = "LOAD";
	parg = navi_array_push(upreq->cmd.m_args);
	*parg = (char*)script;
	
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.conn->out_buf);
	upreq->proto2result = redisproto_get_str_result_from_bulk;
	nvcli_send_header(&upreq->base, NULL, 0, true);

    return 0;
}

