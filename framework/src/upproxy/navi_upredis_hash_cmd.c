/*
 * navi_upredis_hash_cmd.c
 *
 *  Created on: 2013-12-27
 *      Author: li.lei
 */



#include "navi_upredis.h"

int navi_upredis_hset(navi_upredis_t* upreq, const char* key, const char* subkey, const char* v)
{
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "HSET", key, subkey, v,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hsetnx(navi_upredis_t* upreq, const char* key, const char* subkey, const char* v)
{
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "HSETNX", key, subkey, v,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hget(navi_upredis_t* upreq, const char* key, const char* subkey)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "HGET", key, subkey,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_str_result_from_bulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hdel(navi_upredis_t* upreq, const char* key, const char* subkey)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "HDEL", key, subkey,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hexists(navi_upredis_t* upreq, const char* key, const char* subkey)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "HEXISTS", key, subkey,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hmset(navi_upredis_t* upreq, const char* key, nvup_rediskv_t* subs, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "HMSET", key, sz*2);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i].k;
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i].v;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_ok_result_from_status;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hmget(navi_upredis_t* upreq, const char* key, const char** subs, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "HMGET", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_strs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hmdel(navi_upredis_t* upreq, const char* key, const char** subs, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "HDEL", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

void redisproto_get_kvpairs_from_mbulk(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
{
	if (proto->proto_type == redis_type_error_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = proto->str_result;
		result->ess_logic_code = -1;
		return ;
	}
	else if (proto->proto_type != redis_type_multi_bulk) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not redis multi bulk reply";
		result->ess_logic_code = -1;
		return ;
	}

	if (proto->in_bulks == NULL) /*-1*/
	{
		result->ess_logic_code = 0;
		result->content_type = NVUP_RESULT_DATA_NULL;
		return ;
	}

	int pt, i;
	navi_array_part_t* part;
	json_t* js_obj = json_object();
	const char* sk = NULL;
	for (pt=0; pt<proto->in_bulks->part_size; pt++) {
		part = proto->in_bulks->parts[pt];
		if (!part)
			break;

		redis_bulk_t* bulk = (redis_bulk_t*)part->allocs;
		for (i=0; i<part->used; i++,bulk++) {
			if (bulk->bulk_type != redis_type_single_bulk) {
				result->content_type = NVUP_RESULT_DATA_ERR;
				result->err = "invalid redis multi bulk reply";
				result->ess_logic_code = -1;
				json_decref(js_obj);
				return ;
			}
			if (sk==NULL)
				sk = bulk->s;
				if (sk == NULL) {
					result->content_type = NVUP_RESULT_DATA_ERR;
					result->err = "invalid redis multi bulk reply";
					result->ess_logic_code = -1;
					json_decref(js_obj);
					return ;
				}
			else {
				if (bulk->s)
					json_object_set_new(js_obj, sk, json_string(bulk->s));
				else
					json_object_set_new(js_obj, sk, json_null());
				sk = NULL;
			}
		}
	}

	result->ess_logic_code = 0;
	result->content_type = NVUP_RESULT_DATA_JSON;
	result->js = js_obj;
}

static inline void get_subkvs_from_mbulk(navi_upredis_t* upredis, navi_upreq_result_t* result)
{
	nvup_redis_proto_t* proto = upredis->proto;
	redisproto_get_kvpairs_from_mbulk(proto,result);
}

int navi_upredis_hgetall(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "HGETALL", key,
		upreq->base.out_pack);

	upreq->proto2result = get_subkvs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hkeys(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "HKEYS", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_strs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hvals(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "HVALS", key,
			upreq->base.out_pack);

	upreq->proto2result = upredis_get_strs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hlen(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "HLEN", key,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hincrby(navi_upredis_t* upreq, const char* key, const char* subkey, int64_t v)
{
	char buf[30];
	snprintf(buf, sizeof(buf), "%lld", v);

	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "HINCRBY", key, subkey, buf,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_hincrbyfloat(navi_upredis_t* upreq, const char* key, const char* subkey, double v)
{
	char buf[40];
	snprintf(buf, sizeof(buf), "%f", v);

	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "HINCRBYFLOAT", key, subkey, buf,
		upreq->base.out_pack);

	upreq->proto2result = upredis_get_float_from_bulk;
	return navi_upreq_init(&upreq->base);
}
