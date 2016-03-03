/*
 * navi_upgroup.h
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#ifndef NAVI_UPGROUP_H_
#define NAVI_UPGROUP_H_
#include "navi_simple_hash.h"
#include "navi_upserver.h"
#include "navi_upreq.h"
#include "navi_uppolicy_query.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct navi_upgroup_s navi_upgroup_t;
typedef struct navi_upgroup_impl_s navi_upgroup_impl_t;
typedef navi_upserver_t* (*navi_upgroup_resolve_server_fp)(navi_upgroup_impl_t* grp, navi_upreq_t* req);
typedef navi_upserver_t* (*navi_upgroup_policy_query_fp)(navi_upgroup_impl_t* grp, nvup_policy_inkeys_t* inkeys,
    navi_upreq_policy_t* result);

typedef int (*navi_upgroup_init_fp)(navi_upgroup_impl_t* grp, json_t* cfg);
typedef void (*navi_upgroup_destroy_fp)(navi_upgroup_impl_t* grp);
typedef void (*navi_upgroup_rebuild_fp)(navi_upgroup_impl_t* grp);

#define NAVI_UPGROUP_POLICY_INIT_NM(name) navi_upgroup_policy_##name##_init
#define NAVI_UPGROUP_POLICY_REBUILD_NM(name) navi_upgroup_policy_##name##_rebuild
#define NAVI_UPGROUP_POLICY_RESOLVE_NM(name) navi_upgroup_policy_##name##_resolve
#define NAVI_UPGROUP_POLICY_QUERY_NM(name) navi_upgroup_policy_##name##_query
#define NAVI_UPGROUP_POLICY_DESTROY_NM(name) navi_upgroup_policy_##name##_destroy

#define NAVI_UPGROUP_POLICY_INIT_FUNC(name, grp, cfg) \
	int NAVI_UPGROUP_POLICY_INIT_NM(name)(navi_upgroup_impl_t* grp, json_t* cfg)

#define NAVI_UPGROUP_POLICY_DESTROY_FUNC(name, grp) \
	void NAVI_UPGROUP_POLICY_DESTROY_NM(name)(navi_upgroup_impl_t* grp)

#define NAVI_UPGROUP_POLICY_REBUILD_FUNC(name, grp) \
	void NAVI_UPGROUP_POLICY_REBUILD_NM(name)(navi_upgroup_impl_t* grp)

#define NAVI_UPGROUP_POLICY_RESOLVE_FUNC(name, grp ,req) \
	navi_upserver_t* NAVI_UPGROUP_POLICY_RESOLVE_NM(name)(navi_upgroup_impl_t* grp,\
    navi_upreq_t* req)

#define NAVI_UPGROUP_POLICY_QUERY_FUNC(name, grp , inkeys, policy) \
	navi_upserver_t* NAVI_UPGROUP_POLICY_QUERY_NM(name)(navi_upgroup_impl_t* grp,\
    nvup_policy_inkeys_t* inkeys, navi_upreq_policy_t* policy)

typedef struct navi_upgroup_procs_s
{
	navi_upgroup_init_fp init;
	navi_upgroup_resolve_server_fp resolve_server;
	navi_upgroup_policy_query_fp query;
	navi_upgroup_rebuild_fp rebuild;
	navi_upgroup_destroy_fp destroy;

	navi_upserver_policy_init_fp server_policy_init;
	navi_upserver_policy_destroy_fp server_policy_destroy;
} navi_upgroup_procs_t;

struct navi_upgroup_impl_s
{
	navi_upgroup_t* group;
	void* data;
};

typedef navi_upreq_proto_type_e navi_upgroup_proto_type_e;

struct navi_upgroup_s
{
	char* group_name;
	navi_upgroup_proto_type_e proto;
	char* policy_name;
	navi_upserver_common_setting_t settings; //各upserver可以继承的设置。
	void* mgr;

	/***
	 * 各policy group的开发者，不需要过多关心如下实现细节
	 */
	struct
	{
		navi_hash_t* hash; //按server的name散列
	} s;

	struct
	{
		navi_upgroup_procs_t procs;
		void* so_handle;
		char* so_name;
		navi_upgroup_impl_t impl;
	} i;

	struct
	{
		json_t* config;
		time_t last_modify;
		char* config_path;
	} c;

	navi_pool_t pool[0];
};

navi_upgroup_t* navi_upgroup_init(const char* group_cfg,
    void* mgr);
navi_upgroup_t* navi_upgroup_create(const char* grp_name, navi_upreq_proto_type_e proto, 
	int connect_timeout_ms,   int rw_timeout_ms, int idle_pool_max, int idle_timeout_ms);
void navi_upgroup_destroy(navi_upgroup_t* grp);

int navi_upgroup_resolve_upreq(navi_upgroup_t* grp, navi_upreq_t* req,
    navi_upreq_policy_t* policy);

int navi_upgroup_policy_query(navi_upgroup_t* grp, nvup_policy_inkeys_t* inkeys,
    navi_upreq_policy_t* result);

static inline void navi_upgroup_rebuild(navi_upgroup_t* grp)
{
	if ( grp && grp->i.procs.rebuild )
		grp->i.procs.rebuild(&grp->i.impl);
}

/*
 * policied upgroup实现中，使用这两个接口访问每个server。 目的是根据自己的策略，组织编排各server。
 * 例如组织server的hash环、round-roubin环等
 */
size_t navi_upgroup_get_servers(navi_upgroup_t* grp, navi_upserver_t** srv, size_t sz);
navi_upserver_t* navi_upgroup_get_server(navi_upgroup_t* grp, const char* nm);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_UPGROUP_H_ */
