/*
 * navi_upredis_list_cmd.c
 *
 *  Created on: 2013-12-27
 *      Author: li.lei
 */


#include "navi_upredis.h"
#include "navi_uppolicy_query.h"
#include "navi_frame_log.h"

int navi_upredis_lpush(navi_upredis_t* upreq, const char* key, const char** elmts, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "LPUSH", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = elmts[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_lpushx(navi_upredis_t* upreq, const char* key, const char** elmts, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "LPUSHX", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = elmts[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_rpush(navi_upredis_t* upreq, const char* key, const char** elmts, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "RPUSH", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = elmts[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_rpushx(navi_upredis_t* upreq, const char* key, const char** elmts, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "RPUSHX", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = elmts[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_lpop(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "LPOP", key, upreq->base.out_pack);
	upreq->proto2result = upredis_get_str_result_from_bulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_rpop(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "RPOP", key, upreq->base.out_pack);
	upreq->proto2result = upredis_get_str_result_from_bulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_lset(navi_upredis_t* upreq, const char* key, int32_t idx, const char* v)
{
	char buf[16];
	snprintf(buf,sizeof(buf), "%lld", idx);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "LSET", key,
		buf, v, upreq->base.out_pack);
	upreq->proto2result = upredis_get_ok_result_from_status;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_ltrim(navi_upredis_t* upreq, const char* key, int32_t start, int32_t end)
{
	char buf1[16];
	char buf2[16];
	snprintf(buf1, sizeof(buf1), "%lld", start);
	snprintf(buf2, sizeof(buf2), "%lld", end);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "LTRIM", key,
		buf1, buf2, upreq->base.out_pack);
	upreq->proto2result = upredis_get_ok_result_from_status;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_lrem(navi_upredis_t* upreq, const char* key, int32_t count, const char* match)
{
	char buf[16];
	snprintf(buf,sizeof(buf), "%lld", count);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "LSET", key,
		buf, match, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_linsert(navi_upredis_t* upreq, const char* key, bool before, int32_t pivot, const char* v)
{
	char buf[16];
	snprintf(buf,sizeof(buf), "%lld", pivot);
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "LINSERT", key, 3);
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

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}


int navi_upredis_lindex(navi_upredis_t* upreq, const char* key, int32_t idx)
{
	char buf[16];
	snprintf(buf,sizeof(buf), "%lld", idx);

	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "LINDEX", key,
		buf, upreq->base.out_pack);
	upreq->proto2result = upredis_get_str_result_from_bulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_llen(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "LLEN", key,
		 upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_lrange(navi_upredis_t* upreq, const char* key, int32_t start, int32_t end)
{
	char buf1[16];
	char buf2[16];
	snprintf(buf1, sizeof(buf1), "%lld", start);
	snprintf(buf2, sizeof(buf2), "%lld", end);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "LRANGE", key,
		buf1, buf2, upreq->base.out_pack);
	upreq->proto2result = upredis_get_strs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}


int navi_upredis_blpop(navi_upredis_t* upreq, const char* key, int32_t timeout)
{
	char buf1[16];
	snprintf(buf1, sizeof(buf1), "%lld", timeout);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "BLPOP", key,
		buf1, upreq->base.out_pack);
	upreq->proto2result = upredis_get_pair_from_mbulk;
	int ret = navi_upreq_init(&upreq->base);
	upreq->base.policy.cnn_timeout_ms = 5000;
	upreq->base.policy.rw_timeout_ms = timeout*1000*2 + 3000;
	return ret;
}

int navi_upredis_brpop(navi_upredis_t* upreq, const char* key, int32_t timeout)
{
	char buf1[16];
	snprintf(buf1, sizeof(buf1), "%lld", timeout);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "BRPOP", key,
		buf1, upreq->base.out_pack);
	upreq->proto2result = upredis_get_pair_from_mbulk;
	int ret = navi_upreq_init(&upreq->base);
	upreq->base.policy.cnn_timeout_ms = 5000;
	upreq->base.policy.rw_timeout_ms = timeout*1000*2 + 3000;
	return ret;
}

int navi_upredis_brpoplpush_self(navi_upredis_t* upreq, const char* key, int32_t timeout)
{
	char buf1[16];
	snprintf(buf1, sizeof(buf1), "%lld", timeout);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "BRPOPLPUSH", key, key,
		buf1, upreq->base.out_pack);
	upreq->proto2result = upredis_get_str_result_from_bulk;
	return navi_upreq_init(&upreq->base);
}

static void upredis_parent_list_bpop_mservers(navi_upredis_t* upredis, navi_upreq_result_t* result)
{
	nvup_redis_proto_t* proto = upredis->proto;
	if (proto->proto_type == redis_type_error_reply) {
		return ;
	}
	else if (proto->proto_type != redis_type_multi_bulk) {
		return ;
	}

	if (proto->in_bulks == NULL || proto->in_bulks->count != 2) /*-1*/
	{
		return ;
	}

	redis_bulk_t* bk1 = navi_array_item(proto->in_bulks, 0);
	redis_bulk_t* bk2 = navi_array_item(proto->in_bulks, 1);
	if (bk1->bulk_type != redis_type_single_bulk ||
		bk2->bulk_type != redis_type_single_bulk) {
		return ;
	}

	if (result->content_type == NVUP_RESULT_DATA_NULL) {
		result->ess_logic_code = 0;
		result->content_type = NVUP_RESULT_DATA_PAIR;
		result->pair.k = bk1->s;
		result->pair.v = bk2->s;
		return;
	}
	else if (result->content_type == NVUP_RESULT_DATA_PAIR) {
		result->content_type = NVUP_RESULT_DATA_JSON;
		result->js = json_object();
		json_object_set_new(result->js, result->pair.k, json_string(result->pair.v));
		json_object_set_new(result->js, bk1->s, json_string(bk2->s));
		return;
	}
	else if (result->content_type == NVUP_RESULT_DATA_JSON) {
		json_object_set_new(result->js, bk1->s, json_string(bk2->s));
		return;
	}

	return ;
}

static void upredis_sum2parent_list_bpop_mservers(navi_upredis_t* child, navi_upreq_result_t* nouse)
{
	navi_request_t* pr_nv = navi_request_get_parent(child->base.bind_channel);
	navi_upreq_result_t* result = &(((navi_upreq_t*)pr_nv->ctx_own)->result);

	nvup_redis_proto_t* proto = child->proto;
	if (proto->proto_type != redis_type_multi_bulk) {
		return ;
	}

	if (proto->in_bulks == NULL || proto->in_bulks->count != 2) /*-1*/
	{
		return ;
	}

	redis_bulk_t* bk1 = navi_array_item(proto->in_bulks, 0);
	redis_bulk_t* bk2 = navi_array_item(proto->in_bulks, 1);
	if (bk1->bulk_type != redis_type_single_bulk ||
		bk2->bulk_type != redis_type_single_bulk) {
		return ;
	}

	if (result->content_type == NVUP_RESULT_DATA_NULL) {
		result->ess_logic_code = 0;
		result->content_type = NVUP_RESULT_DATA_PAIR;
		result->pair.k = bk1->s;
		result->pair.v = bk2->s;
		return;
	}
	else if (result->content_type == NVUP_RESULT_DATA_PAIR) {
		result->content_type = NVUP_RESULT_DATA_JSON;
		result->js = json_object();
		json_object_set_new(result->js, result->pair.k, json_string(result->pair.v));
		json_object_set_new(result->js, bk1->s, json_string(bk2->s));
		return;
	}
	else if (result->content_type == NVUP_RESULT_DATA_JSON) {
		json_object_set_new(result->js, bk1->s, json_string(bk2->s));
		return;
	}

	return ;
}

int navi_upredis_blpop_m(navi_upredis_t* upreq, const char** keys, size_t sz, uint32_t timeout)
{
	navi_uppolicy_bquery_t* bq = navi_uppolicy_bquery_create();
	int i;
	char buf[20];
	snprintf( buf, sizeof(buf), "%u", timeout);
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

				UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.pool, "BLPOP", keygrp->inkeys_group->count);
				for (pt=0; pt<keygrp->inkeys_group->part_size; pt++) {
					part = keygrp->inkeys_group->parts[pt];
					if (!part)
						break;
					p_keys = (nvup_policy_inkeys_t**)part->allocs;
					for (j=0; j<part->used; j++, p_keys++) {
						cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(upreq->cmd.m_keys);
						cmd_key->key = navi_pool_strdup(upreq->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"key"));
						cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
						cmd_key->arg1 = buf;
					}
				}

				nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
				upreq->proto2result = upredis_parent_list_bpop_mservers;
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

				UPREDIS_MKEY_CMD(&sub_redis->cmd, sub_redis->base.pool, "BLPOP", keygrp->inkeys_group->count);
				for (pt=0; pt<keygrp->inkeys_group->part_size; pt++) {
					part = keygrp->inkeys_group->parts[pt];
					if (!part)
						break;
					p_keys =  (nvup_policy_inkeys_t**)part->allocs;
					for (j=0; j<part->used; j++, p_keys++) {
						cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(sub_redis->cmd.m_keys);
						cmd_key->key = navi_pool_strdup(sub_redis->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"key"));
						cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
						cmd_key->arg1 = buf;
					}
				}

				nvup_redis_cmd_2outpack(&sub_redis->cmd, sub_redis->base.out_pack);
				sub_redis->proto2result = upredis_sum2parent_list_bpop_mservers;
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

int navi_upredis_brpop_m(navi_upredis_t* upreq, const char** keys, size_t sz, uint32_t timeout)
{
	navi_uppolicy_bquery_t* bq = navi_uppolicy_bquery_create();
	int i;
	char buf[20];
	snprintf(buf, sizeof(buf), "%u", timeout);
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

				UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.pool, "BRPOP", keygrp->inkeys_group->count);
				for (pt=0; pt<keygrp->inkeys_group->part_size; pt++) {
					part = keygrp->inkeys_group->parts[pt];
					if (!part)
						break;
					p_keys = (nvup_policy_inkeys_t**)part->allocs;
					for (j=0; j<part->used; j++, p_keys++) {
						cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(upreq->cmd.m_keys);
						cmd_key->key = navi_pool_strdup(upreq->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"key"));
						cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
						cmd_key->arg1 = buf;
					}
				}

				nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
				upreq->proto2result = upredis_parent_list_bpop_mservers;
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

				UPREDIS_MKEY_CMD(&sub_redis->cmd, sub_redis->base.pool, "BRPOP", keygrp->inkeys_group->count);
				for (pt=0; pt<keygrp->inkeys_group->part_size; pt++) {
					part = keygrp->inkeys_group->parts[pt];
					if (!part)
						break;
					p_keys =  (nvup_policy_inkeys_t**)part->allocs;
					for (j=0; j<part->used; j++, p_keys++) {
						cmd_key = (nvup_redis_cmd_key_t*)navi_array_push(sub_redis->cmd.m_keys);
						cmd_key->key = navi_pool_strdup(sub_redis->base.pool,
							navi_uppolicy_query_getkey(*p_keys,"key"));
						cmd_key->arg_st = NVUP_REDIS_KEY_1ARG;
						cmd_key->arg1 = buf;
					}
				}

				nvup_redis_cmd_2outpack(&sub_redis->cmd, sub_redis->base.out_pack);
				sub_redis->proto2result = upredis_sum2parent_list_bpop_mservers;
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


/********
//这两个指令只有在key和destkey在同一台服务器上时，才会执行。否则拆解为rpop, lpush两个指令，不是原子性的
int navi_upredis_rpoplpush(navi_upredis_t* upreq, const char* key, const char* destkey)
{
}

int navi_upredis_brpoplpush(navi_upredis_t* upreq, const char* key, const char* destkey, int32_t timeout)
{
}
****/

