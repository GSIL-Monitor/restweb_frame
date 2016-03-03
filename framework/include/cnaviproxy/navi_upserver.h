/*
 * navi_upserver.h
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#ifndef NAVI_UPSERVER_H_
#define NAVI_UPSERVER_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <jansson.h>
#include "navi_simple_hash.h"
#include "navi_upreq.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct navi_upserver_s navi_upserver_t;
typedef struct navi_upserver_impl_s navi_upserver_impl_t;

typedef int (*navi_upserver_get_addr_fp)(navi_upserver_impl_t* srv,
    struct sockaddr_storage* addr);
typedef int (*navi_upserver_init_fp)(navi_upserver_impl_t* srv, json_t* cfg);
typedef int (*navi_upserver_destroy_fp)(navi_upserver_impl_t* srv);
typedef int (*navi_upserver_onfailed_fp)(navi_upserver_impl_t* srv, navi_upreq_code_e code);

/***
 * 不同类型的upserver的初始化、后台地址决断逻辑、销毁的逻辑不尽相同。
 * 例如单服务实例的upserver和redis replicaSet的upserver在如上方面
 * 肯定不相同
 */
typedef struct navi_upserver_procs_s
{
	navi_upserver_init_fp init;
	//upgroup根据策略选定upserver之后，调用该接口获得upserver对应的地址信息
	//可以直接给出单实例服务地址、或者给出cluster的主地址用于写，或者在允许读延迟
	//的cluster下，给读类型请求给出从服务实例地址
	navi_upserver_get_addr_fp get_addr;
	navi_upserver_onfailed_fp on_upreq_failed;
	navi_upserver_destroy_fp destroy;
} navi_upserver_procs_t;

struct navi_upserver_impl_s
{
	navi_upserver_t* upserver;
	void *impl_data;
};

typedef enum navi_upserver_status_E
{
	NVUP_SRV_UNRESOLVED, //起始状态
	NVUP_SRV_RESOLVED,
	NVUP_SRV_UNREACHABLE
} navi_upserver_status_e;

/*
 *  某些upgroup的具体分发策略，可能是基于upserver的信息的，例如基于upserver配置的权重
 *  进行负载分配，也可能upserver的一些动态调整属性
 *  这些信息，维持在upserver policy data中。不同策略的group，要求的数据不尽相同，数据的
 *  求解策略也不尽相同。
 */
typedef int (*navi_upserver_policy_init_fp)(navi_upserver_t* srv, json_t* srv_cfg);
typedef void (*navi_upserver_policy_destroy_fp)(void* setting);

#define NAVI_UPSERVER_POLICY_INIT_NM(name) navi_upserver_policy_##name##_init
#define NAVI_UPSERVER_POLICY_DESTROY_NM(name) navi_upserver_policy_##name##_destroy

#define NAVI_UPSERVER_POLICY_INIT_FUNC(name, srv, srv_cfg) \
	void* NAVI_UPSERVER_POLICY_INIT_NM(name)(navi_upserver_t* srv, json_t* srv_cfg)
#define NAVI_UPSERVER_POLICY_DESTROY_FUNC(name, obj) \
	void NAVI_UPSERVER_POLICY_DESTROY_NM(name)(void* obj)

typedef struct navi_upserver_policy_data_s
{
	void* data;
	navi_upserver_policy_init_fp init;
	navi_upserver_policy_destroy_fp destroy;
} navi_upserver_policy_data_t;

typedef struct navi_upserver_common_setting_s
{
	uint32_t conn_timeout_ms;
	uint32_t rw_timeout_ms;
	uint32_t idle_pool_size;
	uint32_t max_idle_ms;
} navi_upserver_common_setting_t;

struct navi_upserver_s
{
	char* server_name;
	navi_upserver_status_e status;
	navi_upserver_policy_data_t policy_settings;
	navi_upserver_common_setting_t settings;

	navi_upserver_procs_t* procs;
	navi_upserver_impl_t impl;
	void* group;
	json_t* config;
	navi_pool_t pool[0];
};

// 创建upserver的工厂方法
navi_upserver_t* navi_upserver_create(void* grp, const char* srv_name,  json_t* cfg);
navi_upserver_t*navi_upserver_add(const char * grp_name, const char * host, uint16_t port);
void navi_upserver_destroy(navi_upserver_t* srv);

static inline navi_upserver_status_e navi_upserver_status(navi_upserver_t* srv)
{
	return srv->status;
}

static inline void navi_upserver_on_upreq_failed(navi_upserver_t* srv, navi_upreq_code_e code)
{
	if (srv && srv->procs && srv->procs->on_upreq_failed)
		srv->procs->on_upreq_failed(&srv->impl, code);
}

#ifdef __cplusplus
}
#endif

#endif /* NAVI_UPSERVER_H_ */
