/** \brief 
 * nvredis.h
 *  Created on: 2015-1-13
 *      Author: li.lei
 *  brief: 
 */

#ifndef NVCLI_REDIS_H_
#define NVCLI_REDIS_H_

#include "navi_common_define.h"
#include "navi_grcli.h"
#include "../cnaviproxy/navi_upredis.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _nvcli_redis_s
{
	navi_grcli_t base;
	nvup_redis_cmd_t cmd;
	nvup_redis_proto_t in_parser;
	navi_upreq_result_t result;

	void (*proto2result)(nvup_redis_proto_t* proto, navi_upreq_result_t* result);
	void (*result_handler)(void* , struct _nvcli_redis_s* , const navi_upreq_result_t* );
} nvcli_redis_t;

typedef void (*nvredis_result_proc_fp)(void* parent, nvcli_redis_t* ss, const navi_upreq_result_t* result);
typedef void (*nvredis_error_proc_fp)(void* parent, nvcli_redis_t* ss, nvcli_error_e e);

nvcli_redis_t* nvcli_redis_init(nvcli_parent_t* ctx,
	const struct sockaddr* peer_addr,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval);

void nvredis_cleanup(void* sub);

static inline void nvcli_redis_abort(nvcli_redis_t* session)
{
	nvcli_clean(&session->base);
}

static inline void* nvcli_redis_app_data(nvcli_redis_t* session)
{
	return session->base.app_data;
}

static inline void nvcli_redis_set_appdata_cleanup(nvcli_redis_t* ss,
	void (*clean)(void*))
{
	ss->base.app_data_cleanup = clean;
}

static inline navi_pool_t* nvcli_redis_pool(nvcli_redis_t* ss)
{
	return ss->base.private_pool;
}

int nvcli_redis_del(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_mdel(nvcli_redis_t* upreq, const char** keys, size_t sz);
int nvcli_redis_type(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_dump(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_restore(nvcli_redis_t* upreq, const char* key, int32_t ttl,  const char* serl /*对象的序列化串*/);
int nvcli_redis_exists(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_expire(nvcli_redis_t* upreq, const char* key, uint32_t to);
int nvcli_redis_pexpire(nvcli_redis_t* upreq, const char* key, uint64_t to_ms);
int nvcli_redis_expireat(nvcli_redis_t* upreq, const char* key, time_t stmp);
int nvcli_redis_pexpireat(nvcli_redis_t* upreq, const char* key, time_t stmp, uint16_t ms);
int nvcli_redis_persist(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_ttl(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_pttl(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_movedb(nvcli_redis_t* upreq, const char* key, uint32_t db);
int nvcli_redis_sort(nvcli_redis_t* upreq, const char* key, bool desc, bool alpha, size_t limit_off, size_t limit_count,
	const char* by_pattern, const char** get_patterns, size_t get_pttn_sz/*,TODO: const char* store_key*/);

int nvcli_redis_set(nvcli_redis_t* upreq, const char* key, const char* value);
int nvcli_redis_setex(nvcli_redis_t* upreq, const char* key, const char* value,uint32_t expire_secs);
int nvcli_redis_psetex(nvcli_redis_t* upreq, const char* key, const char* value,uint32_t expire_msecs);
int nvcli_redis_setnx(nvcli_redis_t* upreq, const char* key, const char* value);

int nvcli_redis_set_v2612(nvcli_redis_t* upreq, const char* key, const char* value,
	uint32_t option, uint32_t expire_v);

int nvcli_redis_getset(nvcli_redis_t* upreq, const char* key, const char* value);

int nvcli_redis_append(nvcli_redis_t* upreq, const char* key, const char* value);
int nvcli_redis_incr(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_incrby(nvcli_redis_t* upreq, const char* key, int64_t v);
int nvcli_redis_incrbyfloat(nvcli_redis_t* upreq, const char* key, double v);
int nvcli_redis_decr(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_decrby(nvcli_redis_t* upreq, const char* key, int64_t v);

int nvcli_redis_setrange(nvcli_redis_t* upreq, const char* key, size_t offset, const char* value);
int nvcli_redis_getrange(nvcli_redis_t* upreq, const char* key, int start, int end);

int nvcli_redis_get(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_strlen(nvcli_redis_t* upreq, const char* key);

int nvcli_redis_mget(nvcli_redis_t* upreq, const char** keys, size_t sz);
int nvcli_redis_mset(nvcli_redis_t* upreq, nvup_rediskv_t* kvs, size_t sz);
int nvcli_redis_msetnx(nvcli_redis_t* upreq, nvup_rediskv_t* kvs, size_t sz);

int nvcli_redis_hset(nvcli_redis_t* upreq, const char* key, const char* subkey, const char* v);
int nvcli_redis_hsetnx(nvcli_redis_t* upreq, const char* key, const char* subkey, const char* v);
int nvcli_redis_hget(nvcli_redis_t* upreq, const char* key, const char* subkey);
int nvcli_redis_hdel(nvcli_redis_t* upreq, const char* key, const char* subkey);
int nvcli_redis_hexists(nvcli_redis_t* upreq, const char* key, const char* subkey);
int nvcli_redis_hmset(nvcli_redis_t* upreq, const char* key, nvup_rediskv_t* subs, size_t sz);
int nvcli_redis_hmget(nvcli_redis_t* upreq, const char* key, const char** subs, size_t sz);
int nvcli_redis_hmdel(nvcli_redis_t* upreq, const char* key, const char** subs, size_t sz);
int nvcli_redis_hgetall(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_hkeys(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_hvals(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_hlen(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_hincrby(nvcli_redis_t* upreq, const char* key, const char* subkey, int64_t v);
int nvcli_redis_hincrbyfloat(nvcli_redis_t* upreq, const char* key, const char* subkey, double v);

int nvcli_redis_lpush(nvcli_redis_t* upreq, const char* key, const char** elmts, size_t sz);
int nvcli_redis_lpushx(nvcli_redis_t* upreq, const char* key, const char** elmts, size_t sz);
int nvcli_redis_rpush(nvcli_redis_t* upreq, const char* key, const char** elmts, size_t sz);
int nvcli_redis_rpushx(nvcli_redis_t* upreq, const char* key, const char** elmts, size_t sz);
int nvcli_redis_lpop(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_rpop(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_lset(nvcli_redis_t* upreq, const char* key, int32_t idx, const char* v);
int nvcli_redis_ltrim(nvcli_redis_t* upreq, const char* key, int32_t start, int32_t end);
int nvcli_redis_lrem(nvcli_redis_t* upreq, const char* key, int32_t count, const char* match);
int nvcli_redis_linsert(nvcli_redis_t* upreq, const char* key, bool before, int32_t pivot, const char* v);

int nvcli_redis_lindex(nvcli_redis_t* upreq, const char* key, int32_t idx);
int nvcli_redis_llen(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_lrange(nvcli_redis_t* upreq, const char* key, int32_t start, int32_t end);

int nvcli_redis_blpop(nvcli_redis_t* upreq, const char* key, int32_t timeout);
int nvcli_redis_brpop(nvcli_redis_t* upreq, const char* key, int32_t timeout);

int nvcli_redis_brpoplpush_self(nvcli_redis_t* upreq, const char* key, int32_t timeout);

int nvcli_redis_blpop_m(nvcli_redis_t* upreq, const char** keys, size_t sz, uint32_t timeout);
int nvcli_redis_brpop_m(nvcli_redis_t* upreq, const char** keys, size_t sz, uint32_t timeout);
int nvcli_redis_rpoplpush(nvcli_redis_t* upreq, const char* key, const char* destkey);
int nvcli_redis_brpoplpush(nvcli_redis_t* upreq, const char* key, const char* destkey, int32_t timeout);

int nvcli_redis_sadd(nvcli_redis_t* upreq, const char* key, const char** mems, size_t sz);
int nvcli_redis_scard(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_sismember(nvcli_redis_t* upreq, const char* key, const char* mem);
int nvcli_redis_smembers(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_spop(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_srandmember(nvcli_redis_t* upreq, const char* key, size_t count);
int nvcli_redis_srem(nvcli_redis_t* upreq, const char* key, const char** mems, size_t sz);


int nvcli_redis_zadd(nvcli_redis_t* upreq, const char* key, const nvup_redis_mscore_t* mems, size_t sz);
int nvcli_redis_zcard(nvcli_redis_t* upreq, const char* key);
int nvcli_redis_zscore(nvcli_redis_t* upreq, const char* key, const char* mem);
int nvcli_redis_zrank(nvcli_redis_t* upreq, const char* key, const char* mem);
int nvcli_redis_zrevrank(nvcli_redis_t* upreq, const char* key, const char* mem);
int nvcli_redis_zcount(nvcli_redis_t* upreq, const char* key, double min, double max);
int nvcli_redis_zincrby(nvcli_redis_t* upreq, const char* key, const char* mem, double by);
int nvcli_redis_zrange(nvcli_redis_t* upreq, const char* key, int32_t start_idx, int32_t stop_idx, bool withscore);
int nvcli_redis_zrevrange(nvcli_redis_t* upreq, const char* key, int32_t start_idx, int32_t stop_idx, bool withscore);
int nvcli_redis_zrangebyscore(nvcli_redis_t* upreq, const char* key, double min, double max,
	bool withscore, size_t off, size_t cnt);
int nvcli_redis_zrevrangebyscore(nvcli_redis_t* upreq, const char* key, double min, double max,
	bool withscore, size_t off, size_t cnt);
int nvcli_redis_zrem(nvcli_redis_t* upreq, const char* key, const char** mems, size_t sz);
int nvcli_redis_zremrangebyrank(nvcli_redis_t* upreq, const char* key, int32_t start, int32_t stop);
int nvcli_redis_zremrangebyscore(nvcli_redis_t* upreq, const char* key, double min, double max);

int nvcli_redis_lua_evalsha(nvcli_redis_t* upreq, const char* keyspace,
	const navi_upredis_script_t* script, void (*proto2result)(nvup_redis_proto_t*, navi_upreq_result_t*));
int nvcli_redis_lua_eval(nvcli_redis_t* upreq, const char* keyspace, const navi_upredis_script_t* script,
	void (*proto2result)(nvup_redis_proto_t*, navi_upreq_result_t*));

#ifdef __cplusplus
}
#endif


#endif /* NVCLI_REDIS_H_ */
