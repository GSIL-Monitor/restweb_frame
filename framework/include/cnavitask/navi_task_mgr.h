/** \brief 
 * navi_task_mgr.h
 *  Created on: 2015-1-13
 *      Author: li.lei
 *  brief: 
 */

#ifndef NAVI_TASK_MGR_H_
#define NAVI_TASK_MGR_H_

#include "navi_task.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _navi_task_mgr_s
{
	navi_hash_t* all_tasks;
	struct sockaddr_un ctrl_addr;

	navi_pool_t* monitor_pool;
	nvcli_parent_t monitor_runner;
	nvcli_redis_t* redis_local;
	navi_timer_t* ping_timer;
	chain_node_t watch_list;
    chain_node_t zombile_list;
} navi_task_mgr_t;

extern navi_task_mgr_t* g_tasks;

void navi_task_mgr_init(const struct sockaddr_un* ctrl_redis);
void navi_task_mgr_clean();

navi_task_t* navi_task_get_with_fullname(const char* task_fullname);
int navi_task_regist(navi_task_t* task);
void navi_task_unregist(navi_task_t* task);
void navi_task_monitor_notify(navi_task_t* task);
void navi_task_quit_monitor(navi_task_t* task);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_TASK_MGR_H_ */
