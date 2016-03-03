/*
 * navi_upserver_redis_rs.h
 *
 *  Created on: 2013-12-18
 *      Author: li.lei
 */

#ifndef NAVI_UPSERVER_REDIS_RS_H_
#define NAVI_UPSERVER_REDIS_RS_H_
#include "navi_upserver.h"
#include "navi_simple_array.h"

#define DEFAULT_RS_CHECK_INTERVAL 3

/*在REDIS_RS_FAIL_DURA时间间隔内(以秒为单位)有REDIS_RS_FAIL_LIMIT次失败，
  *认为master需要重新选择
  */
#define DEFAULT_RS_FAIL_DURA 1
#define DEFAULT_RS_FAIL_LIMIT 5
#define DEFAULT_RS_RESOLVE_INTERVAL 30
typedef struct redis_rs_fails_s{
	int fail_dura;
	int fail_limit;
	uint64_t first_fail;
	int count;
}redis_rs_fails_t;

typedef struct redis_rs_upserver_data_s
{
	navi_array_t* addrs; //struct sockaddr_in元素数组
	int cur_selected; //当前被使用的地址的序号
	int rs_check_interval;
	uint64_t last_check;
	int resolve_interval;
	uint64_t last_resolve;
	redis_rs_fails_t fails;
} redis_rs_upserver_data_t;

extern navi_upserver_procs_t* g_upsrv_redis_rs_procs;

typedef struct navi_rs_servers_s{
	navi_hash_t* hash;
	navi_pool_t pool[0];
}navi_rs_servers_t;

#define NVUP_RS_SRVS_OBJ_SIZE (sizeof(navi_rs_servers_t)+0x1000)

extern navi_rs_servers_t* g_rs_servers;

bool redis_rs_upserver_resolve(navi_upserver_impl_t* srv);

#endif /* NAVI_UPSERVER_REDIS_RS_H_ */
