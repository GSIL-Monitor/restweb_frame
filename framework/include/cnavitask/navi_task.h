/*
 * navi_task.h
 *
 *  Created on: 2015-1-14
 *      Author: li.lei
 *      Desc： navi task公共接口
 */

#ifndef NAVI_TASK_H_
#define NAVI_TASK_H_

#include "navi_common_define.h"
#include "navi_module.h"
#include "nvcli_http.h"
#include "nvcli_redis.h"
#include "navi_simple_hash.h"
#include "navi_timer_mgr.h"
#include "navi_inner_util.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct _navi_task_s {
	const char* svc_name;
	const char* module_name;
	const char* task_name;
	void *task_data;
	void (*empty_notifier)(struct _navi_task_s* task, void* task_data);
	void (*cleanup)(struct _navi_task_s* task, void* task_data);
} navi_task_t;

typedef void (*nvtask_cleanup_fp)(navi_task_t* task, void* task_data);
typedef void (*nvtask_empty_notifier_fp)(navi_task_t* task, void* task_data);

typedef void (*nvtask_notify_handler_fp)(navi_task_t* task, const json_t* notify_obj);

typedef struct _nvtask_notify_join_s
{
	const char* notify_name;
	nvtask_notify_handler_fp handler;
} nvtask_notify_join_t;


navi_task_t* navi_module_new_task(navi_module_t* module, const char* name, void* task_data,
	nvtask_cleanup_fp clean, nvtask_empty_notifier_fp empty_notifier);
navi_task_t* navi_module_new_local_task(navi_module_t* module, void* task_data,
	nvtask_cleanup_fp clean, nvtask_empty_notifier_fp empty_notifier);
navi_module_t* navi_task_current_module(navi_task_t* task);

navi_task_t* navi_module_get_task(navi_module_t* module, const char* task_name);

/*!
 * \fn	void nvtask_join_notifies(navi_task_t* task, const nvtask_notify_join_t* joins, size_t cnt);\
 * \brief	在初始创建task时，注册task接收外部notify的handler
 * \param	task
 * \param	joins 注册的notify数组，每一项包含一个notify的name, handler元组
 * \param	cnt	注册的notify handler的个数
 */
void nvtask_join_notifies(navi_task_t* task, const nvtask_notify_join_t* joins, size_t cnt);

/*!
 * \fn	void nvtask_close(navi_task_t* task);
 * \brief	关闭task。会清理运行时语境，业务数据，中断已发起的远程会话等
 * \param	task
 */
void nvtask_close(navi_task_t* task);

/*!
 * \fn	const char* nvtask_full_name(navi_task_t* task);
 * \brief	获得task的全名，包含service.module.taskname
 */
const char* nvtask_full_name(navi_task_t* task);

/*!
 * \fn	nvcli_http_t* nvtask_new_http_session(navi_task_t* task, const struct sockaddr* peer, const char* uri);
 * \brief	在task语境下，发起一次远程http会话。
 * \param	task
 * \param	peer 远端地址
 * \param	uri	访问的uri
 */


nvcli_http_t* nvtask_new_http_session(navi_task_t* ctx,
	const struct sockaddr* peer_addr,
	const char* uri,
	nvcli_http_procs_t app_procs,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval);

nvcli_http_t* nvtask_new_http_session_url(navi_task_t* ctx,
	navi_url_parse_t* url,
	nvcli_http_procs_t app_procs,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval);

static inline nvcli_http_t* nvtask_new_http_session2(navi_task_t* ctx,
	const struct sockaddr* peer_addr,
	const char* uri,
	nvcli_http_procs_t app_procs,
	size_t app_data_size,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval)
{
	nvcli_http_t* ret = nvtask_new_http_session(ctx,peer_addr, uri, app_procs, NULL,
		conn_timeout,resp_max_waiting,
		input_max_interval);
	if (app_data_size > 0) {
		ret->base.app_data = navi_pool_calloc(ret->base.private_pool,
			1, app_data_size);
	}
	return ret;
}

static inline nvcli_http_t* nvtask_new_http_session_url2(navi_task_t* ctx,
	navi_url_parse_t* url,
	nvcli_http_procs_t app_procs,
	size_t app_data_size,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval)
{
	nvcli_http_t* ret = nvtask_new_http_session_url(ctx,url,app_procs,NULL,
		conn_timeout, resp_max_waiting, input_max_interval);
	if (app_data_size) {
		ret->base.app_data = navi_pool_calloc(ret->base.private_pool,
			1, app_data_size);
	}
	return ret;
}

/*!
 * \fn	nvcli_redis_t* nvtask_new_redis_session(navi_task_t* task, const struct sockaddr* peer);
 * \brief	在task语境下，发起一次redis会话
 * \param	task
 * \param	peer	redis地址
 */
nvcli_redis_t* nvtask_new_redis_session(navi_task_t* ctx,
	const struct sockaddr* peer_addr,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval);

static inline nvcli_redis_t* nvtask_new_redis_session2(navi_task_t* ctx,
	const struct sockaddr* peer_addr,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler,
	size_t app_data_size,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval)
{
	nvcli_redis_t* ret = nvtask_new_redis_session(ctx,peer_addr, result_handler,
		error_handler, NULL, conn_timeout, resp_max_waiting, input_max_interval);
	if (app_data_size>0) {
		ret->base.app_data = navi_pool_calloc(ret->base.private_pool,1,
			app_data_size);
	}
	return ret;
}

/*!
 * \fn	navi_timer_h nvtask_new_timer(navi_task_t* task, void* timer_data, int timeout_ms,
			nvtask_timer_handler_fp handler,
			nvtask_timer_handler_fp cleanup);
 * \brief	在task语境下，注册一个定时器。只提供一次性定时器。循环定时器通过一次性定时器的重复使用模拟。
 * \param	task
 * \param	timer_data	业务自定义定时器专有数据
 * \param	timeout_ms	定时器时间
 * \param	handler	超时时的处理器
 * \param	cleanup	业务指定的定时器业务语境清理回调
 */
typedef void (*nvtask_timer_handler_fp)(navi_task_t* task, void* timer_data);
navi_timer_h nvtask_new_timer(navi_task_t* task, void* timer_data, int timeout_ms,
	navi_timer_type_e type,
	nvtask_timer_handler_fp handler,
	nvtask_timer_handler_fp cleanup);

void nvtask_cancel_timer(navi_task_t* task, navi_timer_h timer);

void nvtask_trace(navi_task_t* handle, navi_trace_type_e e, const char* fmt, ...);

navi_pool_t* nvtask_pool(navi_task_t* task);
void* nvtask_get_driver_pool(navi_task_t* task);

void* nvtask_regist_app_context(navi_task_t* task, const char* name, size_t context_sz);
void* nvtask_get_app_context(navi_task_t* task, const char* name);
void* nvtask_try_probe_touch_context(navi_task_t* task, const char* name, size_t context_sz);
void nvtask_reset_app_context(navi_task_t* task, const char* name, void* value, size_t context_sz);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_TASK_H_ */
