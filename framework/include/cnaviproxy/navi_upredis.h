/*
 * navi_upredis.h
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#ifndef NAVI_UPREDIS_H_
#define NAVI_UPREDIS_H_
#include "navi_upreq.h"
#include "navi_upproto_redis.h"
#include "navi_simple_array.h"
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct navi_upredis_s navi_upredis_t;
typedef void (*navi_upredis_proc_result_fp)(navi_upredis_t* up, navi_upreq_result_t* res, void* ctx);
typedef void (*navi_upredis_cleanup_ctx_fp)(navi_upredis_t* up, void* ctx);
typedef void (*navi_upredis_proto2result_fp)(navi_upredis_t* up, navi_upreq_result_t* res);

struct navi_upredis_s
{
	navi_upreq_t base;
	nvup_redis_cmd_t cmd;
	navi_upredis_proc_result_fp process;
	navi_upredis_cleanup_ctx_fp cleanup;

	navi_upredis_proto2result_fp proto2result;
	nvup_redis_proto_t *proto;
	void* ctx;
};

navi_upredis_t* navi_request_bind_upredis_ctx(navi_request_t* binded, const char* srv_grp,
    navi_upredis_proc_result_fp proc, void *ctx, navi_upredis_cleanup_ctx_fp cleanup);

navi_upredis_t* navi_request_bind_upredis_ctx_ext(navi_request_t * binded, const char * srv_grp,
    const char * srv_name, navi_upredis_proc_result_fp proc, void * ctx, navi_upredis_cleanup_ctx_fp cleanup);

static inline navi_upredis_t* navi_request_bind_upredis(navi_request_t* binded, const char* srv_grp,
    navi_upredis_proc_result_fp proc)
{
	return navi_request_bind_upredis_ctx(binded, srv_grp, proc, NULL, NULL);
}

static inline navi_upredis_t* navi_request_bind_upredis_ext(navi_request_t* binded, const char* srv_grp,
    const char* srv_name, navi_upredis_proc_result_fp proc)
{
	return navi_request_bind_upredis_ctx_ext(binded, srv_grp, srv_name, proc, NULL, NULL);
}

const char* nvup_redis_get_policy_key(navi_upreq_t* up, const char* key);

/****
 * 通用key命令。如下命令暂时不实现：
 * * KEYS  pattern查找匹配的key列表。需要广播到upgroup各redis server上
 * * MIGRATE  迁移key到别的server上。
 * * OBJECT  获得key在redis server上的当前内部状态信息
 * * RANDOMKEY  需要随机选择还是固定选择upgroup一台redis来获取，不确定
 * * RENAME  对于hash redis集群， 指定新key，需要从源key所在server上的数据DUMP到本地，然后在RESTORE到新的机器上，
 * 			RESTORE成功后，再DEL原机器上的原始key。涉及三个子请求, 可以后续有需求时再添加
 * * RENAMEEX  同上
 * * SCAN 游标操作
 * * 带有store destkey 参数的sort命令
 */
int navi_upredis_del(navi_upredis_t* upreq, const char* key);
int navi_upredis_mdel(navi_upredis_t* upreq, const char** keys, size_t sz);
int navi_upredis_type(navi_upredis_t* upreq, const char* key);
int navi_upredis_dump(navi_upredis_t* upreq, const char* key);
int navi_upredis_restore(navi_upredis_t* upreq, const char* key, int32_t ttl,  const char* serl /*对象的序列化串*/);
int navi_upredis_exists(navi_upredis_t* upreq, const char* key);
int navi_upredis_expire(navi_upredis_t* upreq, const char* key, uint32_t to);
int navi_upredis_pexpire(navi_upredis_t* upreq, const char* key, uint64_t to_ms);
int navi_upredis_expireat(navi_upredis_t* upreq, const char* key, time_t stmp);
int navi_upredis_pexpireat(navi_upredis_t* upreq, const char* key, time_t stmp, uint16_t ms);
int navi_upredis_persist(navi_upredis_t* upreq, const char* key);
int navi_upredis_ttl(navi_upredis_t* upreq, const char* key);
int navi_upredis_pttl(navi_upredis_t* upreq, const char* key);
int navi_upredis_movedb(navi_upredis_t* upreq, const char* key, uint32_t db);
int navi_upredis_sort(navi_upredis_t* upreq, const char* key, bool desc, bool alpha, size_t limit_off, size_t limit_count,
	const char* by_pattern, const char** get_patterns, size_t get_pttn_sz/*,TODO: const char* store_key*/);

/****************************
 *  string 类型命令，如下命令暂时不实现：
 *  bit类操作命令
 */
int navi_upredis_set(navi_upredis_t* upreq, const char* key, const char* value);
int navi_upredis_setex(navi_upredis_t* upreq, const char* key, const char* value,uint32_t expire_secs);
int navi_upredis_psetex(navi_upredis_t* upreq, const char* key, const char* value,uint32_t expire_msecs);
int navi_upredis_setnx(navi_upredis_t* upreq, const char* key, const char* value);

typedef enum upredis_set_cmd_option {
	UPREDIS_SET_CMD_OPT_EMPTY,
	UPREDIS_SET_CMD_OPT_EX=0x1,
	UPREDIS_SET_CMD_OPT_PX=0x2,
	UPREDIS_SET_CMD_OPT_XX=0x4,
	UPREDIS_SET_CMD_OPT_NX=0x8
}upredis_set_cmd_option_e;

int navi_upredis_set_v2612(navi_upredis_t* upreq, const char* key, const char* value,
	uint32_t option, uint32_t expire_v);

int navi_upredis_getset(navi_upredis_t* upreq, const char* key, const char* value);

int navi_upredis_append(navi_upredis_t* upreq, const char* key, const char* value);
int navi_upredis_incr(navi_upredis_t* upreq, const char* key);
int navi_upredis_incrby(navi_upredis_t* upreq, const char* key, int64_t v);
int navi_upredis_incrbyfloat(navi_upredis_t* upreq, const char* key, double v);
int navi_upredis_decr(navi_upredis_t* upreq, const char* key);
int navi_upredis_decrby(navi_upredis_t* upreq, const char* key, int64_t v);

int navi_upredis_setrange(navi_upredis_t* upreq, const char* key, size_t offset, const char* value);
int navi_upredis_getrange(navi_upredis_t* upreq, const char* key, int start, int end);

int navi_upredis_get(navi_upredis_t* upreq, const char* key);
int navi_upredis_strlen(navi_upredis_t* upreq, const char* key);

int navi_upredis_mget(navi_upredis_t* upreq, const char** keys, size_t sz);

typedef struct nvup_rediskv_s {
	const char* k;
	const char* v;
}nvup_rediskv_t;

int navi_upredis_mset(navi_upredis_t* upreq, nvup_rediskv_t* kvs, size_t sz);
int navi_upredis_msetnx(navi_upredis_t* upreq, nvup_rediskv_t* kvs, size_t sz);

/* **********************************
 * hash类型命令. 暂时未实现命令：
 * HSCAN
 */
int navi_upredis_hset(navi_upredis_t* upreq, const char* key, const char* subkey, const char* v);
int navi_upredis_hsetnx(navi_upredis_t* upreq, const char* key, const char* subkey, const char* v);
int navi_upredis_hget(navi_upredis_t* upreq, const char* key, const char* subkey);
int navi_upredis_hdel(navi_upredis_t* upreq, const char* key, const char* subkey);
int navi_upredis_hexists(navi_upredis_t* upreq, const char* key, const char* subkey);
int navi_upredis_hmset(navi_upredis_t* upreq, const char* key, nvup_rediskv_t* subs, size_t sz);
int navi_upredis_hmget(navi_upredis_t* upreq, const char* key, const char** subs, size_t sz);
int navi_upredis_hmdel(navi_upredis_t* upreq, const char* key, const char** subs, size_t sz);
int navi_upredis_hgetall(navi_upredis_t* upreq, const char* key);
int navi_upredis_hkeys(navi_upredis_t* upreq, const char* key);
int navi_upredis_hvals(navi_upredis_t* upreq, const char* key);
int navi_upredis_hlen(navi_upredis_t* upreq, const char* key);
int navi_upredis_hincrby(navi_upredis_t* upreq, const char* key, const char* subkey, int64_t v);
int navi_upredis_hincrbyfloat(navi_upredis_t* upreq, const char* key, const char* subkey, double v);

/***********************************
 * list命令。暂时未实现指令：
 * rpoplpush
 * brpoplpush
 * 有多个key的blpop,brpop
 */
int navi_upredis_lpush(navi_upredis_t* upreq, const char* key, const char** elmts, size_t sz);
int navi_upredis_lpushx(navi_upredis_t* upreq, const char* key, const char** elmts, size_t sz);
int navi_upredis_rpush(navi_upredis_t* upreq, const char* key, const char** elmts, size_t sz);
int navi_upredis_rpushx(navi_upredis_t* upreq, const char* key, const char** elmts, size_t sz);
int navi_upredis_lpop(navi_upredis_t* upreq, const char* key);
int navi_upredis_rpop(navi_upredis_t* upreq, const char* key);
int navi_upredis_lset(navi_upredis_t* upreq, const char* key, int32_t idx, const char* v);
int navi_upredis_ltrim(navi_upredis_t* upreq, const char* key, int32_t start, int32_t end);
int navi_upredis_lrem(navi_upredis_t* upreq, const char* key, int32_t count, const char* match);
int navi_upredis_linsert(navi_upredis_t* upreq, const char* key, bool before, int32_t pivot, const char* v);

int navi_upredis_lindex(navi_upredis_t* upreq, const char* key, int32_t idx);
int navi_upredis_llen(navi_upredis_t* upreq, const char* key);
int navi_upredis_lrange(navi_upredis_t* upreq, const char* key, int32_t start, int32_t end);

int navi_upredis_blpop(navi_upredis_t* upreq, const char* key, int32_t timeout);
int navi_upredis_brpop(navi_upredis_t* upreq, const char* key, int32_t timeout);
// 在指定list上rpop并原子性的lpush到原list上，用于数据到达时的通知机制，但可能会导致
// list数据的顺序有变化（依赖于redis-server的内部实现）
int navi_upredis_brpoplpush_self(navi_upredis_t* upreq, const char* key, int32_t timeout);

int navi_upredis_blpop_m(navi_upredis_t* upreq, const char** keys, size_t sz, uint32_t timeout);
int navi_upredis_brpop_m(navi_upredis_t* upreq, const char** keys, size_t sz, uint32_t timeout);

//这两个指令只有在key和destkey在同一台服务器上时，才会执行。否则拆解为rpop, lpush两个指令，不是原子性的
//int navi_upredis_rpoplpush(navi_upredis_t* upreq, const char* key, const char* destkey);
//int navi_upredis_brpoplpush(navi_upredis_t* upreq, const char* key, const char* destkey, int32_t timeout);


/********************************
 *	set类型命令。如下命令暂时不实现：
 *	SDIFF,
 *	SDIFFSTORE,
 *	SINTER,
 *	SINTERSTORE,
 *	SMOVE,
 *	SUNION,
 *	SUNIONSTORE,
 *	SSCAN
 */

int navi_upredis_sadd(navi_upredis_t* upreq, const char* key, const char** mems, size_t sz);
int navi_upredis_scard(navi_upredis_t* upreq, const char* key);
int navi_upredis_sismember(navi_upredis_t* upreq, const char* key, const char* mem);
int navi_upredis_smembers(navi_upredis_t* upreq, const char* key);
int navi_upredis_spop(navi_upredis_t* upreq, const char* key);
int navi_upredis_srandmember(navi_upredis_t* upreq, const char* key, size_t count);
int navi_upredis_srem(navi_upredis_t* upreq, const char* key, const char** mems, size_t sz);

/********************************
 *	lsh类型命令。
 */
int navi_upredis_lsh_set(navi_upredis_t* upreq, const char* key, nvup_rediskv_t* subs, size_t sz);
int navi_upredis_lsh_del(navi_upredis_t* upreq, const char* key, nvup_rediskv_t* subs, size_t sz);
int navi_upredis_lsh_mget_nearlest(navi_upredis_t* upreq, const char* key, nvup_rediskv_t* subs,  
	size_t sz, int radius, bool withdistance);
int navi_upredis_lsh_len(navi_upredis_t* upreq, const char* key);

/*****************************
 * zset类型命令。 如下命令暂时不实现：
 *	ZINTERSTORE
 *	ZUNIONSTORE
 *	ZSCAN
 */

typedef struct nvup_redis_mscore_s {
	const char* mem;
	double score;
}nvup_redis_mscore_t;

int navi_upredis_zadd(navi_upredis_t* upreq, const char* key, const nvup_redis_mscore_t* mems, size_t sz);
int navi_upredis_zcard(navi_upredis_t* upreq, const char* key);
int navi_upredis_zscore(navi_upredis_t* upreq, const char* key, const char* mem);
int navi_upredis_zrank(navi_upredis_t* upreq, const char* key, const char* mem);
int navi_upredis_zrevrank(navi_upredis_t* upreq, const char* key, const char* mem);
int navi_upredis_zcount(navi_upredis_t* upreq, const char* key, double min, double max);
int navi_upredis_zincrby(navi_upredis_t* upreq, const char* key, const char* mem, double by);
int navi_upredis_zrange(navi_upredis_t* upreq, const char* key, int32_t start_idx, int32_t stop_idx, bool withscore);
int navi_upredis_zrevrange(navi_upredis_t* upreq, const char* key, int32_t start_idx, int32_t stop_idx, bool withscore);
int navi_upredis_zrangebyscore(navi_upredis_t* upreq, const char* key, double min, double max,
	bool withscore, size_t off, size_t cnt);
int navi_upredis_zrevrangebyscore(navi_upredis_t* upreq, const char* key, double min, double max,
	bool withscore, size_t off, size_t cnt);
int navi_upredis_zrem(navi_upredis_t* upreq, const char* key, const char** mems, size_t sz);
int navi_upredis_zremrangebyrank(navi_upredis_t* upreq, const char* key, int32_t start, int32_t stop);
int navi_upredis_zremrangebyscore(navi_upredis_t* upreq, const char* key, double min, double max);

typedef struct navi_upredis_script_s
{
	union {
		char* script;
		char* script_sha;
	};

	char** args;
	size_t args_sz;
}navi_upredis_script_t;

int navi_upredis_lua_evalsha(navi_upredis_t* upreq, const char* keyspace,
	const navi_upredis_script_t* script);
int navi_upredis_lua_eval(navi_upredis_t* upreq, const char* keyspace, const navi_upredis_script_t* script);

//在group的server的address可获取时，将脚本load到服务端，并返回脚本的标记sha
int navi_upredis_lua_load(const char* group, const char* script, char** sha);

int navi_redis_instance_lua_load(const struct sockaddr* addr, const char* script, char** sha);

/***********************************
 * 如下内容在upredis代理内部代码使用，应用开发者不需要关心
 */

void redisproto_get_int_result(nvup_redis_proto_t* proto, navi_upreq_result_t* res);
void redisproto_get_ok_result_from_status(nvup_redis_proto_t* proto, navi_upreq_result_t* res);
void redisproto_get_str_result_from_status(nvup_redis_proto_t* proto, navi_upreq_result_t* res);
void redisproto_get_str_result_from_error(nvup_redis_proto_t* proto, navi_upreq_result_t* res);
void redisproto_get_str_result_from_bulk(nvup_redis_proto_t* proto, navi_upreq_result_t* res);
void redisproto_get_strs_from_mbulk(nvup_redis_proto_t* proto, navi_upreq_result_t* res);
void redisproto_get_pair_from_mbulk(nvup_redis_proto_t* proto, navi_upreq_result_t* res);
void redisproto_get_float_from_bulk(nvup_redis_proto_t* proto, navi_upreq_result_t* res);
void redisproto_get_ok_or_null_mbulk(nvup_redis_proto_t* upredis, navi_upreq_result_t* result);
void redisproto_get_mem_score_from_mbulk(nvup_redis_proto_t* proto, navi_upreq_result_t* result);
void redisproto_get_kvpairs_from_mbulk(nvup_redis_proto_t* proto, navi_upreq_result_t* result);

static inline void upredis_get_int_result(navi_upredis_t* upredis, navi_upreq_result_t* res)
{
	redisproto_get_int_result(upredis->proto, res);
}
static inline void upredis_get_ok_result_from_status(navi_upredis_t* upredis, navi_upreq_result_t* result)
{
	redisproto_get_ok_result_from_status(upredis->proto,result);
}

static inline void upredis_get_str_result_from_status(navi_upredis_t* upredis, navi_upreq_result_t* res)
{
	redisproto_get_str_result_from_status(upredis->proto, res);
}

static inline void upredis_get_str_result_from_error(navi_upredis_t* upredis, navi_upreq_result_t* result)
{
	redisproto_get_str_result_from_error(upredis->proto, result);
}

static inline void upredis_get_str_result_from_bulk(navi_upredis_t* upredis, navi_upreq_result_t* result)
{
	redisproto_get_str_result_from_bulk(upredis->proto, result);
}

static inline void upredis_get_strs_from_mbulk(navi_upredis_t* upredis, navi_upreq_result_t* res)
{
	redisproto_get_strs_from_mbulk(upredis->proto, res);
}

static inline void upredis_get_pair_from_mbulk(navi_upredis_t* upredis, navi_upreq_result_t* res)
{
	redisproto_get_pair_from_mbulk(upredis->proto,res);
}

static inline void upredis_get_float_from_bulk(navi_upredis_t* upredis, navi_upreq_result_t* res)
{
	redisproto_get_float_from_bulk(upredis->proto,res);
}

void upredis_result_mr_proc(navi_upredis_t* upredis);
void upredis_sum2parent_int_result(navi_upredis_t* child, navi_upreq_result_t* res);
void upredis_add2parent_strs_from_mbulk(navi_upredis_t* upredis, navi_upreq_result_t* res);


#ifdef __cplusplus
}
#endif

#endif /* NAVI_UPREDIS_H_ */
