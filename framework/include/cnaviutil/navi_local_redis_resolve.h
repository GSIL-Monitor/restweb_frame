/*
 * navi_local_redis_resolve.h
 *
 *  Created on: 2015Äê4ÔÂ27ÈÕ
 *      Author: li.lei
 */

#ifndef NAVI_LOCAL_REDIS_RESOLVE_H_
#define NAVI_LOCAL_REDIS_RESOLVE_H_

#include "navi_common_define.h"
#include "navi_upreq.h"
#include <jansson.h>
#ifdef __cplusplus
extern "C" {
#endif

void navi_local_redis_cfg_init(const char* cache_group, const char* leveldb_group);

bool navi_local_redis_resolve(const char* key, navi_upreq_policy_t* result);
bool navi_local_leveldb_resolve(const char* key, navi_upreq_policy_t* result);
const char* navi_local_redis_group();
const char* navi_local_leveldb_group();

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_CNAVIUTIL_NAVI_LOCAL_REDIS_RESOLVE_H_ */
