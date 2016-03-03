/*
 * navi_upredis_zset_cmd.c
 *
 *  Created on: 2014-1-7
 *      Author: li.lei
 */

#include "navi_upredis.h"

int navi_upredis_zadd(navi_upredis_t* upreq, const char* key, const nvup_redis_mscore_t* mems, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "ZADD", key, sz*2);
	size_t i;
	const char** parg;
	char buf[40];
	for (i=0; i<sz; i++){
		snprintf(buf, sizeof(buf), "%f", mems[i].score);
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = navi_pool_strdup(upreq->base.pool, buf);
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = mems[i].mem;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zcard(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "ZCARD", key,
		 upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zscore(navi_upredis_t* upreq, const char* key, const char* mem)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "ZSCORE", key, mem,
		 upreq->base.out_pack);
	upreq->proto2result = upredis_get_float_from_bulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zrank(navi_upredis_t* upreq, const char* key, const char* mem)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "ZRANK", key, mem,
		 upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zrevrank(navi_upredis_t* upreq, const char* key, const char* mem)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "ZREVRANK", key, mem,
		 upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zcount(navi_upredis_t* upreq, const char* key, double min, double max)
{
	char buf1[40];
	char buf2[40];

	snprintf( buf1, sizeof(buf1), "%f", min);
	snprintf( buf2, sizeof(buf2), "%f", max);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "ZCOUNT", key, buf1, buf2,
		upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zincrby(navi_upredis_t* upreq, const char* key, const char* mem, double by)
{
	char buf[40];
	snprintf( buf, sizeof(buf), "%f", by);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "ZINCRBY", key, buf, mem,
		upreq->base.out_pack);
	upreq->proto2result = upredis_get_float_from_bulk;
	return navi_upreq_init(&upreq->base);
}

void get_mem_score_from_mbulk(navi_upredis_t* upredis, navi_upreq_result_t* result)
{
	redisproto_get_mem_score_from_mbulk(upredis->proto, result);
}

void redisproto_get_mem_score_from_mbulk(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
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
	redis_bulk_t* bulk = NULL;
	const char* sk = NULL;
	for (pt=0; pt<proto->in_bulks->part_size; pt++) {
		part = proto->in_bulks->parts[pt];
		if (!part)
			break;

		bulk = (redis_bulk_t*)part->allocs;
		double score;
		for (i=0; i<part->used; i++,bulk++) {
			if (sk==NULL)
				sk = bulk->s;
			else {
				score = atof(bulk->s);
				json_object_set_new(js_obj, sk, json_real(score));
				sk = NULL;
			}
		}
	}

	result->ess_logic_code = 0;
	result->content_type = NVUP_RESULT_DATA_JSON;
	result->js = js_obj;
}

int navi_upredis_zrange(navi_upredis_t* upreq, const char* key, int32_t start_idx, int32_t stop_idx, bool withscore)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "ZRANGE", key, 3);

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

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);

	if (withscore)
		upreq->proto2result = get_mem_score_from_mbulk;
	else
		upreq->proto2result = upredis_get_strs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zrevrange(navi_upredis_t* upreq, const char* key, int32_t start_idx, int32_t stop_idx, bool withscore)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "ZREVRANGE", key, 3);

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

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);

	if (withscore)
		upreq->proto2result = get_mem_score_from_mbulk;
	else
		upreq->proto2result = upredis_get_strs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zrangebyscore(navi_upredis_t* upreq, const char* key, double min, double max,
	bool withscore, size_t off, size_t cnt)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "ZRANGEBYSCORE", key, 6);

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
		*parg = navi_pool_strdup(upreq->base.pool, buf);
		snprintf( buf, sizeof(buf), "%u", cnt);
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = navi_pool_strdup(upreq->base.pool, buf);
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);

	if (withscore)
		upreq->proto2result = get_mem_score_from_mbulk;
	else
		upreq->proto2result = upredis_get_strs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zrevrangebyscore(navi_upredis_t* upreq, const char* key, double min, double max,
	bool withscore, size_t off, size_t cnt)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "ZREVRANGEBYSCORE", key, 6);

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
		*parg = navi_pool_strdup(upreq->base.pool, buf);
		snprintf( buf, sizeof(buf), "%u", cnt);
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = navi_pool_strdup(upreq->base.pool, buf);
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);

	if (withscore)
		upreq->proto2result = get_mem_score_from_mbulk;
	else
		upreq->proto2result = upredis_get_strs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zrem(navi_upredis_t* upreq, const char* key, const char** mems, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "ZADD", key, sz);
	size_t i;
	const char** parg;
	char buf[40];
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = mems[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zremrangebyrank(navi_upredis_t* upreq, const char* key, int32_t start, int32_t stop)
{
	char buf1[40];
	char buf2[40];

	snprintf( buf1, sizeof(buf1), "%d", start);
	snprintf( buf2, sizeof(buf2), "%d", stop);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "ZREMRANGEBYRANK", key, buf1, buf2,
		upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_zremrangebyscore(navi_upredis_t* upreq, const char* key, double min, double max)
{
	char buf1[40];
	char buf2[40];

	snprintf( buf1, sizeof(buf1), "%f", min);
	snprintf( buf2, sizeof(buf2), "%f", max);
	UPREDIS_SKEY_2ARG_CMD(&upreq->cmd, upreq->base.pool, "ZREMRANGEBYSCORE", key, buf1, buf2,
		upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}
