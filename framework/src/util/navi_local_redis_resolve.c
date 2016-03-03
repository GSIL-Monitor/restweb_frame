/*
 * navi_local_redis_resolve.c
 *
 *  Created on: 2015Äê4ÔÂ27ÈÕ
 *      Author: li.lei
 */

#include "navi_local_redis_resolve.h"
#include "navi_upgroup_mgr.h"
#include "navi_uppolicy_query.h"
#include "../navi_frame_log.h"

static char* g_cache_grp = NULL;
static char* g_leveldb_grp = NULL;

static void cfg_cleanup()
{
	if (g_cache_grp)free(g_cache_grp);
	if (g_leveldb_grp)free(g_leveldb_grp);
}

void navi_local_redis_cfg_init(const char* cache_group, const char* leveldb_group)
{
	navi_upgroup_mgr_t* grp_mgr = navi_upgroup_mgr_instance(NULL);
	if (!grp_mgr)return;

	if (cache_group) {
		if ( navi_upgroup_mgr_get_group(grp_mgr,cache_group) == NULL) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "local_cache_group :%s not exist.",
				cache_group);
		}
		g_cache_grp = strdup(cache_group);
	}

	if (leveldb_group) {
		if ( navi_upgroup_mgr_get_group(grp_mgr,leveldb_group) == NULL) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "local_leveldb_group :%s not exist.",
					leveldb_group);
		}
		g_leveldb_grp = strdup(leveldb_group);
	}

	atexit(cfg_cleanup);
}

bool navi_local_redis_resolve(const char* key, navi_upreq_policy_t* result)
{
	if (!g_cache_grp) return false;

	navi_uppolicy_squery_t* redis_resolve = navi_uppolicy_squery_create();
	navi_uppolicy_squery_add_inkey(redis_resolve, "key", key);
	int ret = navi_uppolicy_squery_resolve(redis_resolve, g_cache_grp);
	if (ret == NAVI_OK && result) {
		memcpy(result, &redis_resolve->policy, offsetof(navi_upreq_policy_t,server_name));
		if (result->pool) {
			result->server_name = navi_pool_strdup(result->pool,
				redis_resolve->policy.server_name);
		}
	}
	navi_uppolicy_squery_destroy(redis_resolve);
	return ret==NAVI_OK;
}

bool navi_local_leveldb_resolve(const char* key, navi_upreq_policy_t* result)
{
	if (!g_leveldb_grp) return false;

	navi_uppolicy_squery_t* redis_resolve = navi_uppolicy_squery_create();
	navi_uppolicy_squery_add_inkey(redis_resolve, "key", key);
	int ret = navi_uppolicy_squery_resolve(redis_resolve, g_leveldb_grp);
	if (ret == NAVI_OK && result) {
		memcpy(result, &redis_resolve->policy, offsetof(navi_upreq_policy_t,server_name));
		if (result->pool) {
			result->server_name = navi_pool_strdup(result->pool,
				redis_resolve->policy.server_name);
		}
	}
	navi_uppolicy_squery_destroy(redis_resolve);
	return ret==NAVI_OK;
}

const char* navi_local_redis_group()
{
	return g_cache_grp;
}

const char* navi_local_leveldb_group()
{
	return g_leveldb_grp;
}
