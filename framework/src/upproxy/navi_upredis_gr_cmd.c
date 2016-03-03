/*
 * navi_upredis_gr_cmd.c
 *
 *  Created on: 2013-12-27
 *      Author: li.lei
 */
#include "navi_upredis.h"
#include "navi_uppolicy_query.h"
#include "navi_frame_log.h"

int navi_upredis_del(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "DEL", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_type(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool,"TYPE", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_str_result_from_status;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_dump(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool,"DUMP", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_str_result_from_bulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_restore(navi_upredis_t* upreq, const char* key, int32_t ttl,
	const char* serl /*对象的序列化串*/)
{
	char buf[12];
	snprintf(buf,sizeof(buf),"%d",ttl);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool,"RESTORE", key, buf, serl,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_ok_result_from_status;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_exists(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool,"EXISTS", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_expire(navi_upredis_t* upreq, const char* key, uint32_t to)
{
	char buf[12];
	snprintf(buf,sizeof(buf),"%u",to);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool,"EXPIRE", key, buf,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_pexpire(navi_upredis_t* upreq, const char* key, uint64_t to_ms)
{
	char buf[24];
	snprintf(buf,sizeof(buf),"%llu",to_ms);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool,"PEXPIRE", key, buf,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_expireat(navi_upredis_t* upreq, const char* key, time_t stmp)
{
	char buf[24];
	snprintf(buf,sizeof(buf),"%lld",(int64_t)stmp);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool,"EXPIREAT", key, buf,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_pexpireat(navi_upredis_t* upreq, const char* key, time_t stmp,
	uint16_t ms)
{
	uint64_t stmp_ms = (uint64_t)stmp * 1000 + ms;
	char buf[24];
	snprintf(buf,sizeof(buf),"%llu",stmp_ms);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool,"PEXPIREAT", key, buf,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_persist(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool,"PERSIST", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_ttl(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool,"TTL", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_pttl(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool,"PTTL", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_movedb(navi_upredis_t* upreq, const char* key, uint32_t db)
{
	char buf[12];
	snprintf(buf,sizeof(buf),"%u",db);
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool,"MOVE", key, buf,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_mdel(navi_upredis_t* upreq, const char** keys, size_t sz)
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

				UPREDIS_MKEY_CMD(&upreq->cmd, upreq->base.pool, "DEL", keygrp->inkeys_group->count);
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

				UPREDIS_MKEY_CMD(&sub_redis->cmd, sub_redis->base.pool, "DEL", keygrp->inkeys_group->count);
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
				sub_redis->proto2result = upredis_sum2parent_int_result;
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

int navi_upredis_sort(navi_upredis_t* upreq, const char* key, bool desc, bool alpha, size_t limit_off,
	size_t limit_count,const char* by_pattern, const char** get_patterns, size_t get_pttn_sz)
{
	char buf[30];
	char buf1[30];
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "SORT", key, 10);

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

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_strs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}
