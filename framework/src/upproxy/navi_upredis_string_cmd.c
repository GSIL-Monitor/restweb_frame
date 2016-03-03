/*
 * navi_upredis_string_cmd.c
 *
 *  Created on: 2013-12-27
 *      Author: li.lei
 */
#include "navi_upredis.h"
#include "navi_uppolicy_query.h"
#include "navi_frame_log.h"

int navi_upredis_set(navi_upredis_t* upreq, const char* key, const char* value)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool,"SET", key,value,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_ok_result_from_status;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_append(navi_upredis_t* upreq, const char* key, const char* value)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool,"APPEND", key,
		value, upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}
int navi_upredis_setex(navi_upredis_t* upreq, const char* key, const char* value,
	uint32_t expire_secs)
{
	char buf[24];
	snprintf(buf,sizeof(buf),"%d", expire_secs);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool,"SETEX", key, buf,
		value, upreq->base.out_pack);

	upreq->proto2result = upredis_get_ok_result_from_status;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_psetex(navi_upredis_t* upreq, const char* key, const char* value,
	uint32_t expire_msecs)
{
	char buf[24];
	snprintf(buf,sizeof(buf),"%d", expire_msecs);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool,"PSETEX", key, buf,
		value,upreq->base.out_pack);

	upreq->proto2result = upredis_get_ok_result_from_status;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_setnx(navi_upredis_t* upreq, const char* key, const char* value)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool,"SETNX", key,
		value,upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

void redisproto_get_ok_or_null_mbulk(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
{
	if (proto->proto_type == redis_type_error_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = proto->str_result;
		result->ess_logic_code = -1;
		return ;
	}
	else if (proto->proto_type == redis_type_status_reply){
		if (!strcasecmp("OK",proto->str_result))
			result->ess_logic_code = 0;
		else
			result->ess_logic_code = -1;
		result->content_type = NVUP_RESULT_DATA_STRING;
		result->s = proto->str_result;
		return ;
	}
	else if (proto->proto_type == redis_type_multi_bulk) {
		if (proto->in_bulks == NULL) {
			result->content_type = NVUP_RESULT_DATA_NULL;
			result->ess_logic_code = 0;
			return ;
		}
	}

	result->content_type = NVUP_RESULT_DATA_ERR;
	result->ess_logic_code = -1;
	result->err = "not expected redis response";
	return ;
}

static void upredis_get_ok_or_null_mbulk(navi_upredis_t* upredis, navi_upreq_result_t* result)
{
	redisproto_get_ok_or_null_mbulk(upredis->proto, result);
}

int navi_upredis_set_v2612(navi_upredis_t* upreq, const char* key, const char* value,
	uint32_t option, uint32_t expire_v)
{
	bool probe_null_mbulk = false;
	if (option == 0) {
		UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool,"SET", key,
			value, upreq->base.out_pack);
	}
	else {
		UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "SET", key, 4);
		const char** parg = navi_array_push(upreq->cmd.s_key->margs);
		*parg = value;

		char buf[24];
		if (option|UPREDIS_SET_CMD_OPT_EX) {
			snprintf(buf, sizeof(buf), "%u", expire_v);
			parg = navi_array_push(upreq->cmd.s_key->margs);
			*parg = "EX";
			parg = navi_array_push(upreq->cmd.s_key->margs);
			*parg = navi_pool_strdup(upreq->base.pool,buf);
		}
		else if (option|UPREDIS_SET_CMD_OPT_PX) {
			snprintf(buf, sizeof(buf), "%u", expire_v);
			parg = navi_array_push(upreq->cmd.s_key->margs);
			*parg = "PX";
			parg = navi_array_push(upreq->cmd.s_key->margs);
			*parg = navi_pool_strdup(upreq->base.pool,buf);
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
		nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	}

	if (probe_null_mbulk) {
		upreq->proto2result = upredis_get_ok_or_null_mbulk;
	}
	else {
		upreq->proto2result = upredis_get_ok_result_from_status;
	}
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_get(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool,"GET", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_str_result_from_bulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_getset(navi_upredis_t* upreq, const char* key, const char* value)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool,"GETSET", key, value,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_str_result_from_bulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_strlen(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "STRLEN", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_setrange(navi_upredis_t* upreq, const char* key, size_t offset,
	const char* value)
{
	char buf[12];
	snprintf(buf, sizeof(buf), "%u", offset);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "SETRANGE", key, buf,
		value, upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_getrange(navi_upredis_t* upreq, const char* key, int start, int end)
{
	char buf1[12],buf2[12];
	snprintf(buf1,sizeof(buf1),"%d",start);
	snprintf(buf2,sizeof(buf2),"%d",end);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "SETRANGE", key,
		buf1, buf2, upreq->base.out_pack);

	upreq->proto2result = upredis_get_str_result_from_bulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_incr(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "INCR", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_incrby(navi_upredis_t* upreq, const char* key, int64_t v)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%lld", v);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "INCRBY", key, buf,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_incrbyfloat(navi_upredis_t* upreq, const char* key, double v)
{
	char buf[40];
	snprintf(buf, sizeof(buf), "%f", v);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "INCRBYFLOAT", key,buf,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_float_from_bulk;
	return navi_upreq_init(&upreq->base);
}


int navi_upredis_decr(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "DECR", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_decrby(navi_upredis_t* upreq, const char* key, int64_t v)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%lld", v);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "DECRBY", key,buf,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}


int navi_upredis_mget(navi_upredis_t* upreq, const char** keys, size_t sz)
{
	navi_uppolicy_bquery_t* bq = navi_uppolicy_bquery_create();
	int i;
	for (i=0; i<sz; i++) {
		nvup_policy_inkeys_t* inkeys = navi_uppolicy_bquery_new_inkeys(bq);
		navi_uppolicy_bquery_add_inkey(bq, inkeys, "key", keys[i]);
	}
	if (NAVI_OK == navi_uppolicy_bquery_resolve(bq, upreq->base.group_name) ){
		if (bq->failed_keys) {
			navi_upreq_error_lt(&upreq->base, NVUP_RESULT_POLICY_UNRESOLVE,
				-1, "have keys not resovled");
			goto failed;
		}

		for (i=0; i<bq->a_policies->count; i++){
			nvup_policy_keygroup_t* keygrp = navi_uppolicy_bquery_get_group(bq, i);
			navi_upreq_policy_t* policy = NULL;
			nvup_policy_inkeys_t** p_keys;
			nvup_redis_cmd_key_t* cmd_key;
			int j,pt;
			navi_array_part_t* part;
			if (i==0) {
				policy = &upreq->base.policy;
				*policy = keygrp->policy;
				policy->gr_data = NULL;
				policy->gr_headers = NULL;
				policy->in_proto_buf_sz = 1024;
				policy->pool = upreq->base.pool;
				policy->server_name = navi_pool_strdup(upreq->base.pool,
					keygrp->policy.server_name);

				UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.pool, "MGET", keygrp->inkeys_group->count);
				for (pt=0; pt<keygrp->inkeys_group->part_size; pt++) {
					part = keygrp->inkeys_group->parts[pt];
					if (!part)
						break;
					p_keys = (nvup_policy_inkeys_t**)part->allocs;
					for (j=0; j<part->used; j++, p_keys++) {
						cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(upreq->cmd.m_keys);
						cmd_key->key = navi_pool_strdup(upreq->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"key"));
						cmd_key->arg_st = NVUP_REDIS_KEY_0ARG;
					}
				}

				nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
				upreq->proto2result = upredis_get_strs_from_mbulk;
			}
			else {
				navi_request_t* sub_nv = navi_request_new_sub(upreq->base.bind_channel);
				navi_upredis_t* sub_redis = navi_request_bind_upredis(sub_nv,upreq->base.group_name,
					NULL);
				policy = &sub_redis->base.policy;
				*policy = keygrp->policy;
				policy->gr_data = NULL;
				policy->gr_headers = NULL;
				policy->in_proto_buf_sz = 1024;
				policy->pool = sub_redis->base.pool;
				policy->server_name = navi_pool_strdup(sub_redis->base.pool,
					keygrp->policy.server_name);

				UPREDIS_MKEY_CMD(&sub_redis->cmd, sub_redis->base.pool, "MGET", keygrp->inkeys_group->count);
				for (pt=0; pt<keygrp->inkeys_group->part_size; pt++) {
					part = keygrp->inkeys_group->parts[pt];
					if (!part)
						break;
					p_keys =  (nvup_policy_inkeys_t**)part->allocs;
					for (j=0; j<part->used; j++, p_keys++) {
						cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(sub_redis->cmd.m_keys);
						cmd_key->key = navi_pool_strdup(sub_redis->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"key"));
						cmd_key->arg_st = NVUP_REDIS_KEY_0ARG;
					}
				}

				nvup_redis_cmd_2outpack(&sub_redis->cmd, sub_redis->base.out_pack);
				sub_redis->proto2result = upredis_add2parent_strs_from_mbulk;
				upredis_result_mr_proc(upreq);
			}
		}
	}
	else {
		navi_upreq_error_lt(&upreq->base,NVUP_RESULT_POLICY_UNRESOLVE,
			-1, "group not found or resolve failed");
		goto failed;
	}
	navi_uppolicy_bquery_destroy(bq);
	return NAVI_OK;

failed:
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "upgroup:%s upreq init error. code:%d, desc:%s",
		&upreq->base.group_name, &upreq->base.result.code, &upreq->base.result.session_err_desc);
	navi_upreq_destroy(&upreq->base);
	navi_request_cancel(upreq->base.bind_channel);
	navi_uppolicy_bquery_destroy(bq);
	return NAVI_INNER_ERR;
}

int navi_upredis_mset(navi_upredis_t* upreq, nvup_rediskv_t* kvs, size_t sz)
{
	navi_uppolicy_bquery_t* bq = navi_uppolicy_bquery_create();
	int i;
	for (i=0; i<sz; i++) {
		nvup_policy_inkeys_t* inkeys = navi_uppolicy_bquery_new_inkeys(bq);
		navi_uppolicy_bquery_add_inkey(bq, inkeys, "key", kvs[i].k);
		navi_uppolicy_bquery_add_inkey(bq, inkeys, "v", kvs[i].v);
	}
	if (NAVI_OK == navi_uppolicy_bquery_resolve(bq, upreq->base.group_name) ){
		if (bq->failed_keys) {
			navi_upreq_error_lt(&upreq->base, NVUP_RESULT_POLICY_UNRESOLVE,
				-1, "have keys not resovled");
			goto failed;
		}

		for (i=0; i<bq->a_policies->count; i++){
			nvup_policy_keygroup_t* keygrp = navi_uppolicy_bquery_get_group(bq, i);
			navi_upreq_policy_t* policy = NULL;
			nvup_policy_inkeys_t** p_keys;
			nvup_redis_cmd_key_t* cmd_key;
			int j,pt;
			navi_array_part_t* part;
			if (i==0) {
				policy = &upreq->base.policy;
				*policy = keygrp->policy;
				policy->gr_data = NULL;
				policy->gr_headers = NULL;
				policy->in_proto_buf_sz = 1024;
				policy->pool = upreq->base.pool;
				policy->server_name = navi_pool_strdup(upreq->base.pool,
					keygrp->policy.server_name);

				UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.pool, "MSET", keygrp->inkeys_group->count);
				for (pt=0; pt<keygrp->inkeys_group->part_size; pt++) {
					part = keygrp->inkeys_group->parts[pt];
					if (!part)
						break;
					p_keys = (nvup_policy_inkeys_t**)part->allocs;
					for (j=0; j<part->used; j++, p_keys++) {
						cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(upreq->cmd.m_keys);
						cmd_key->key = navi_pool_strdup(upreq->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"key"));
						cmd_key->arg1 = navi_pool_strdup(upreq->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"v"));
						cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
					}
				}

				nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
				upreq->proto2result = upredis_get_ok_result_from_status;
			}
			else {
				navi_request_t* sub_nv = navi_request_new_sub(upreq->base.bind_channel);
				navi_upredis_t* sub_redis = navi_request_bind_upredis(sub_nv,upreq->base.group_name,
					NULL);
				policy = &sub_redis->base.policy;
				*policy = keygrp->policy;
				policy->gr_data = NULL;
				policy->gr_headers = NULL;
				policy->in_proto_buf_sz = 1024;
				policy->pool = sub_redis->base.pool;
				policy->server_name = navi_pool_strdup(sub_redis->base.pool,
					keygrp->policy.server_name);

				UPREDIS_MKEY_CMD(&sub_redis->cmd, sub_redis->base.pool, "MSET", keygrp->inkeys_group->count);
				for (pt=0; pt<keygrp->inkeys_group->part_size; pt++) {
					part = keygrp->inkeys_group->parts[pt];
					if (!part)
						break;
					p_keys =  (nvup_policy_inkeys_t**)part->allocs;
					for (j=0; j<part->used; j++, p_keys++) {
						cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(sub_redis->cmd.m_keys);
						cmd_key->key = navi_pool_strdup(sub_redis->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"key"));
						cmd_key->arg1 = navi_pool_strdup(sub_redis->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"v"));
						cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
					}
				}

				nvup_redis_cmd_2outpack(&sub_redis->cmd, sub_redis->base.out_pack);
				sub_redis->proto2result = NULL;
				upredis_result_mr_proc(upreq);
			}
		}
	}
	else {
		navi_upreq_error_lt(&upreq->base,NVUP_RESULT_POLICY_UNRESOLVE,
			-1, "group not found or resolve failed");
		goto failed;
	}
	navi_uppolicy_bquery_destroy(bq);
	return NAVI_OK;

failed:
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "upgroup:%s upreq init error. code:%d, desc:%s",
		&upreq->base.group_name, &upreq->base.result.code, &upreq->base.result.session_err_desc);
	navi_upreq_destroy(&upreq->base);
	navi_request_cancel(upreq->base.bind_channel);
	navi_uppolicy_bquery_destroy(bq);
	return NAVI_INNER_ERR;
}

static void upredis_merge01_2parent_result(navi_upredis_t* child, navi_upreq_result_t* result)
{
	if (child->proto->proto_type != redis_type_num)
		return ;

	navi_request_t* pr_nv = navi_request_get_parent(child->base.bind_channel);
	navi_upreq_result_t* pr_rslt = &(((navi_upreq_t*)pr_nv->ctx_own)->result);

	if (pr_rslt->content_type != NVUP_RESULT_DATA_INT) {
		pr_rslt->content_type = NVUP_RESULT_DATA_INT;
		pr_rslt->i = 0;
	}
	if (child->proto->num_result)
		pr_rslt->i = 1;
}

int navi_upredis_msetnx(navi_upredis_t* upreq, nvup_rediskv_t* kvs, size_t sz)
{
	navi_uppolicy_bquery_t* bq = navi_uppolicy_bquery_create();
	int i;
	for (i=0; i<sz; i++) {
		nvup_policy_inkeys_t* inkeys = navi_uppolicy_bquery_new_inkeys(bq);
		navi_uppolicy_bquery_add_inkey(bq, inkeys, "key", kvs[i].k);
		navi_uppolicy_bquery_add_inkey(bq, inkeys, "v", kvs[i].v);
	}
	if (NAVI_OK == navi_uppolicy_bquery_resolve(bq, upreq->base.group_name) ){
		if (bq->failed_keys) {
			navi_upreq_error_lt(&upreq->base, NVUP_RESULT_POLICY_UNRESOLVE,
				-1, "have keys not resovled");
			goto failed;
		}

		for (i=0; i<bq->a_policies->count; i++){
			nvup_policy_keygroup_t* keygrp = navi_uppolicy_bquery_get_group(bq, i);
			navi_upreq_policy_t* policy = NULL;
			nvup_policy_inkeys_t** p_keys;
			nvup_redis_cmd_key_t* cmd_key;
			int j,pt;
			navi_array_part_t* part;
			if (i==0) {
				policy = &upreq->base.policy;
				*policy = keygrp->policy;
				policy->gr_data = NULL;
				policy->gr_headers = NULL;
				policy->in_proto_buf_sz = 1024;
				policy->pool = upreq->base.pool;
				policy->server_name = navi_pool_strdup(upreq->base.pool,
					keygrp->policy.server_name);

				UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.pool, "MSETNX", keygrp->inkeys_group->count);
				for (pt=0; pt<keygrp->inkeys_group->part_size; pt++) {
					part = keygrp->inkeys_group->parts[pt];
					if (!part)
						break;
					p_keys = (nvup_policy_inkeys_t**)part->allocs;
					for (j=0; j<part->used; j++, p_keys++) {
						cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(upreq->cmd.m_keys);
						cmd_key->key = navi_pool_strdup(upreq->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"key"));
						cmd_key->arg1 = navi_pool_strdup(upreq->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"v"));
						cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
					}
				}

				nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
				upreq->proto2result = upredis_get_int_result;
			}
			else {
				navi_request_t* sub_nv = navi_request_new_sub(upreq->base.bind_channel);
				navi_upredis_t* sub_redis = navi_request_bind_upredis(sub_nv,upreq->base.group_name,
					NULL);
				policy = &sub_redis->base.policy;
				*policy = keygrp->policy;
				policy->gr_data = NULL;
				policy->gr_headers = NULL;
				policy->in_proto_buf_sz = 1024;
				policy->pool = sub_redis->base.pool;
				policy->server_name = navi_pool_strdup(sub_redis->base.pool,
					keygrp->policy.server_name);

				UPREDIS_MKEY_CMD(&sub_redis->cmd, sub_redis->base.pool, "MSETNX", keygrp->inkeys_group->count);
				for (pt=0; pt<keygrp->inkeys_group->part_size; pt++) {
					part = keygrp->inkeys_group->parts[pt];
					if (!part)
						break;
					p_keys =  (nvup_policy_inkeys_t**)part->allocs;
					for (j=0; j<part->used; j++, p_keys++) {
						cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(sub_redis->cmd.m_keys);
						cmd_key->key = navi_pool_strdup(sub_redis->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"key"));
						cmd_key->arg1 = navi_pool_strdup(sub_redis->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"v"));
						cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
					}
				}

				nvup_redis_cmd_2outpack(&sub_redis->cmd, sub_redis->base.out_pack);
				sub_redis->proto2result = upredis_merge01_2parent_result;
				upredis_result_mr_proc(upreq);
			}
		}
	}
	else {
		navi_upreq_error_lt(&upreq->base,NVUP_RESULT_POLICY_UNRESOLVE,
			-1, "group not found or resolve failed");
		goto failed;
	}
	navi_uppolicy_bquery_destroy(bq);
	return NAVI_OK;

failed:
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "upgroup:%s upreq init error. code:%d, desc:%s",
		&upreq->base.group_name, &upreq->base.result.code, &upreq->base.result.session_err_desc);
	navi_upreq_destroy(&upreq->base);
	navi_request_cancel(upreq->base.bind_channel);
	navi_uppolicy_bquery_destroy(bq);
	return NAVI_INNER_ERR;
}

