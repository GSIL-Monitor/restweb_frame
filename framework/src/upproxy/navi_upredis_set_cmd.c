/*
 * navi_upredis_set_cmd.c
 *
 *  Created on: 2013-12-27
 *      Author: li.lei
 */

#include "navi_upredis.h"

int navi_upredis_sadd(navi_upredis_t* upreq, const char* key, const char** mems, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "SADD", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = mems[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_scard(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "SCARD", key,
		 upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_sismember(navi_upredis_t* upreq, const char* key, const char* mem)
{
	UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "SISMEMBER", key, mem,
		 upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_smembers(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "SMEMBERS", key,
		 upreq->base.out_pack);
	upreq->proto2result = upredis_get_strs_from_mbulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_spop(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "SPOP", key,
		 upreq->base.out_pack);
	upreq->proto2result = upredis_get_str_result_from_bulk;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_srandmember(navi_upredis_t* upreq, const char* key, size_t count)
{
	char buf[16];
	snprintf(buf, sizeof(buf), "%u", count);

	if (count <= 1) {
		UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "SMEMBERS", key,
				 upreq->base.out_pack);
		upreq->proto2result = upredis_get_str_result_from_bulk;
	}
	else {
		UPREDIS_SKEY_1ARG_CMD(&upreq->cmd, upreq->base.pool, "SMEMBERS", key,
				 buf, upreq->base.out_pack);
		upreq->proto2result = upredis_get_strs_from_mbulk;
	}
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_srem(navi_upredis_t* upreq, const char* key, const char** mems, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "SREM", key, sz);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = mems[i];
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}
