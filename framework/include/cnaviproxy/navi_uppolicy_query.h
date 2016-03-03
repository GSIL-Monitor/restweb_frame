/*
 * navi_uppolicy_batch.h
 *
 *  Created on: 2013-12-25
 *      Author: li.lei
 *      Desc:
 *      	��redis��mset����Ϊ�������ж��key:string����������һ����hash
 *      	�ֲ���key��redis��Ⱥ�Ĳ�ͬ�����ϡ�
 *      	�򵥵�set�������ͨ��navi_upredis_set�ӿڣ��γ�navi_upredis_t(
 *      	��navi_upreq_t��������󣬹���һ��navi_request_t)��navi_uppolicy_consist_hash����ģ��
 *      	��ȡnavi_upredis_t��key��Ϊ�������룬��������navi_upreq_t��
 *      	navi_upreq_policy_t(��˭����redis����)��
 *      	��mset������set�������Ƶķ�ʽ���У���Ҫ������key�ֱ������ԣ�Ȼ��
 *      	����ͬ���Ե�key�ۺϣ�ÿһ���ۺϲ���key�Ӽ���Ӧһ��navi_upreq_policy_t��
 *      	Ϊÿ��policy�γ�һ���µ�mset����(navi_upredis_t)��
 *      	��ģ�鼴���������ĸ�������ģ������key���ϣ�Ȼ��Ըü�����⣬�����һ��
 *      	navi_upreq_policy_t��
 *
 *      	ע�⣺ ����ÿ�������policy����������inkeys�õ���policy.gr_headers��policy.gr_data
 *      	��ֵ������ͬ�����з���ı�Ҫ�����ÿ��inkeys�в�ͬ��gr_headers��gr_data������ʹ�ñ���
 *      	������ѯ�ӿ�
 */

#ifndef NAVI_UPPOLICY_BATCH_H_
#define NAVI_UPPOLICY_BATCH_H_
#include "navi_common_define.h"
#include "navi_simple_array.h"
#include "navi_upreq.h"

#ifdef __cplusplus
extern "C" {
#endif

//������������key
typedef struct nvup_policy_inkey_s
{
	char* k;
	char* v;
	chain_node_t link;
} nvup_policy_inkey_t;

//upgroup����Ҫ����key��Ϊ����
typedef chain_node_t nvup_policy_inkeys_t;

typedef struct nvup_policy_keygroup_s
{
	navi_upreq_policy_t policy;
	navi_array_t* inkeys_group; //nvup_policy_inkeys_t*
} nvup_policy_keygroup_t;

typedef struct navi_uppolicy_bquery_s
{
	navi_array_t* a_keys; //������������inkeys��chain_node_tԪ������
	navi_array_t* a_policies; //���policy����.nvup_policy_keygroup_tԪ������
	navi_array_t* failed_keys; //nvup_policy_inkeys_t*���͡�δ������inkeys
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
