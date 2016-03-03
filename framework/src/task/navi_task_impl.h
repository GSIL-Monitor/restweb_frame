/** \brief 
 * navi_task_impl.h
 *  Created on: 2015-1-23
 *      Author: li.lei
 *  brief: 
 */

#ifndef NAVI_TASK_IMPL_H_
#define NAVI_TASK_IMPL_H_

#include "navi_task.h"
#include "navi_simple_hash.h"
#include "navi_module.h"
#include "navi_req_trace.h"
#include "navi_grcli.h"

typedef struct _navi_task_impl_s
{
	navi_task_t app_frame;

	time_t time;

	char* full_name;
	char* notify_list_key;
	char* task_status_key;

	navi_module_t* module;

	chain_node_t monitor_link;
	uint32_t monitor_seq;

	navi_hash_t* on_ctrl_handler;
	navi_trace_t *trace;

	nvcli_parent_t remote_sessions;
	navi_timer_t* check_timer;

	nvcli_redis_t* keepalive_session;
	nvcli_redis_t* get_notify_session;
	int get_notify_retry;

	chain_node_t bg_jobs;

	navi_hash_t* app_contexts;

	int is_local:1;
	int notify_mon:1; //!< 是否已经监控通知
	int recycled:1;
	navi_pool_t pool[0];
} navi_task_impl_t;

void navi_task_notify_arrive(navi_task_impl_t* impl, uint64_t seq);

#endif /* NAVI_TASK_IMPL_H_ */
