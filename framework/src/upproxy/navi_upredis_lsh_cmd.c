/*
 * navi_upredis_lsh_cmd.c
 *
 *  Created on: 2014-08-26
 *      Author: yanguotao
 */

#include "navi_upredis.h"

int navi_upredis_lsh_set(navi_upredis_t* upreq, const char* key, nvup_rediskv_t* subs, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "LSH_SET", key, sz*2);
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

int navi_upredis_lsh_del(navi_upredis_t* upreq, const char* key, nvup_rediskv_t* subs, size_t sz)
{
	UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "LSH_DEL", key, sz*2);
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i].k;
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i].v;
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_lsh_mget_nearlest(navi_upredis_t* upreq, const char* key, nvup_rediskv_t* subs,  
	size_t sz, int radius, bool withdistance)
{
	char buf[32] = {0};
	if (withdistance){
		UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "LSH_MGET_NEAREST", key, sz*2 +2);
	}
	else{
		UPREDIS_SKEY_MARG_CMD(&upreq->cmd, upreq->base.pool, "LSH_MGET_NEAREST", key, sz*2 +1);
	}
	size_t i;
	const char** parg;
	for (i=0; i<sz; i++) {
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i].k;
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = subs[i].v;
	}
	snprintf(buf, sizeof(buf), "%d",  radius);
	parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
	*parg = buf;
	if (withdistance){
		parg = (const char**)navi_array_push(upreq->cmd.s_key->margs);
		*parg = "withdistances";
	}
	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	upreq->proto2result =  upredis_get_strs_from_mbulk;
	
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_lsh_len(navi_upredis_t* upreq, const char* key)
{
	UPREDIS_SKEY_0ARG_CMD(&upreq->cmd, upreq->base.pool, "LSH_LEN", key,
		 upreq->base.out_pack);
	upreq->proto2result = upredis_get_int_result;
	return navi_upreq_init(&upreq->base);
}

