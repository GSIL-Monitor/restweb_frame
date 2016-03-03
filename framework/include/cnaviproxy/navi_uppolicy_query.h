/*
 * navi_uppolicy_batch.h
 *
 *  Created on: 2013-12-25
 *      Author: li.lei
 *      Desc:
 *      	以redis的mset命令为例，会有多个key:string，并假设以一致性hash
 *      	分布各key到redis集群的不同机器上。
 *      	简单的set命令，可以通过navi_upredis_set接口，形成navi_upredis_t(
 *      	是navi_upreq_t的子类对象，关联一个navi_request_t)，navi_uppolicy_consist_hash策略模块
 *      	获取navi_upredis_t的key作为策略输入，即可求解出navi_upreq_t的
 *      	navi_upreq_policy_t(向谁发起redis命令)。
 *      	而mset不能以set命令类似的方式进行，需要对所有key分别求解策略，然后
 *      	把相同策略的key聚合，每一个聚合策略key子集对应一个navi_upreq_policy_t，
 *      	为每个policy形成一个新的mset命令(navi_upredis_t)。
 *      	该模块即用于批量的给出策略模块输入key集合，然后对该集合求解，结果是一个
 *      	navi_upreq_policy_t组
 *
 *      	注意： 求解的每个分组的policy，组内所有inkeys得到的policy.gr_headers和policy.gr_data
 *      	的值必须相同，才有分组的必要。如果每各inkeys有不同的gr_headers和gr_data，无需使用本套
 *      	批量查询接口
 */

#ifndef NAVI_UPPOLICY_BATCH_H_
#define NAVI_UPPOLICY_BATCH_H_
#include "navi_common_define.h"
#include "navi_simple_array.h"
#include "navi_upreq.h"

#ifdef __cplusplus
extern "C" {
#endif

//单个策略输入key
typedef struct nvup_policy_inkey_s
{
	char* k;
	char* v;
	chain_node_t link;
} nvup_policy_inkey_t;

//upgroup可能要求多个key作为输入
typedef chain_node_t nvup_policy_inkeys_t;

typedef struct nvup_policy_keygroup_s
{
	navi_upreq_policy_t policy;
	navi_array_t* inkeys_group; //nvup_policy_inkeys_t*
} nvup_policy_keygroup_t;

typedef struct navi_uppolicy_bquery_s
{
	navi_array_t* a_keys; //批量策略输入inkeys。chain_node_t元素类型
	navi_array_t* a_policies; //结果policy数组.nvup_policy_keygroup_t元素类型
	navi_array_t* failed_keys; //nvup_policy_inkeys_t*类型。未能求解的inkeys
	navi_pool_t pool[0];
} navi_uppolicy_bquery_t;

typedef struct navi_uppolicy_squery_s
{
	navi_upreq_policy_t policy;
	nvup_policy_inkeys_t inkeys;
	navi_pool_t pool[0];
}navi_uppolicy_squery_t;

navi_uppolicy_bquery_t* navi_uppolicy_bquery_create();
void navi_uppolicy_bquery_destroy(navi_uppolicy_bquery_t* obj);
nvup_policy_inkeys_t* navi_uppolicy_bquery_new_inkeys(navi_uppolicy_bquery_t* obj);
void navi_uppolicy_bquery_add_inkey(navi_uppolicy_bquery_t* obj, nvup_policy_inkeys_t* keys,
    const char* k, const char* v);

navi_uppolicy_squery_t* navi_uppolicy_squery_create();
void navi_uppolicy_squery_destroy(navi_uppolicy_squery_t* obj);
void navi_uppolicy_squery_add_inkey(navi_uppolicy_squery_t* obj, const char* k, const char* v);
int navi_uppolicy_squery_resolve(navi_uppolicy_squery_t* obj, const char* upgroup);

void* navi_uppolicy_query_inkey_iter(nvup_policy_inkeys_t* keys);
void* navi_uppolicy_query_inkey_next(nvup_policy_inkeys_t* keys, void* iter,
    const char** ok, const char** ov);
const char* navi_uppolicy_query_getkey(nvup_policy_inkeys_t* keys, const char* key);

int navi_uppolicy_bquery_resolve(navi_uppolicy_bquery_t* obj, const char* upgroup);

nvup_policy_keygroup_t* navi_uppolicy_bquery_get_group(navi_uppolicy_bquery_t* obj, int idx);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_UPPOLICY_BATCH_H_ */
