/*
 * navi_upgroup_mgr.h
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#ifndef NAVI_UPGROUP_MGR_H_
#define NAVI_UPGROUP_MGR_H_
#include "navi_upreq.h"
#include "navi_upgroup.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct navi_upgroup_mgr_s
{
	char *root_dir; //server group����Ŀ¼
	char *policy_so_dir; //�������server group��.soĿ¼��
	const char *gr_driver_path; //ͨ�ô���Э���driver�����·����
	const char *http_driver_path; //http�����driver�����·��
	navi_hash_t* groups;
	json_t* common_cfg;
	time_t common_cfg_last;
	navi_pool_t pool[0];
} navi_upgroup_mgr_t;

void navi_upgroup_mgr_refresh(navi_upgroup_mgr_t* mgr);

navi_upgroup_mgr_t* navi_upgroup_mgr_instance(const char* noused);
void navi_upgroup_mgr_instance_destroy();
int navi_upreq_resolve_policy(navi_upgroup_mgr_t* mgr, navi_upreq_t* req,
    navi_upreq_policy_t* policy);

navi_upserver_t* navi_upgroup_mgr_get_server(navi_upgroup_mgr_t* mgr, const char* grp_nm,
	const char* srv_nm);

navi_upgroup_t* navi_upgroup_mgr_get_group(navi_upgroup_mgr_t* mgr, const char* grp_nm);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_UPGROUP_MGR_H_ */
