/** \brief 
 * navi_task.c
 *  Created on: 2015-1-14
 *      Author: li.lei
 *  brief: 
 */

#include "navi_task_mgr.h"
#include "navi_task_impl.h"
#include "../navi_module_impl.h"
#include "../navi_frame_log.h"
#include "navi_module_mgr.h"
#include "navi_bg_job.h"

static void nvtask_start_status_redis(navi_task_impl_t* impl);
static void nvtask_get_notify_redis(navi_task_impl_t* impl);

static void task_nvcli_parent_idle_handler(void* obj)
{
	navi_task_t* tsk = (navi_task_t*)obj;
	navi_task_impl_t* impl = (navi_task_impl_t*)obj;
	if ( !navi_list_empty(&impl->bg_jobs) )
		return;
	if ( tsk->empty_notifier ) {
		tsk->empty_notifier(tsk, tsk->task_data);
	}
	return;
}

static void navi_task_check(navi_task_t* task, void* timer_data)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	nvcli_parent_check_idle(&impl->remote_sessions);
	/***
	navi_module_impl_t* mi = navi_mod_h2i(impl->module);
	navi_module_mgr_t* navi_mgr = (navi_module_mgr_t*) mi->navi_mgr;

	navi_module_impl_t* ck_mi = navi_hash_get_gr(navi_mgr->module_map, task->module_name);

	if ( ck_mi == NULL ) {
		nvtask_close(task);
		return;
	}

	if ( ck_mi != mi ) {
		navi_module_decref(impl->module);
		impl->module = &ck_mi->handle;
		navi_module_incref(impl->module);
	}**/

	if ( !impl->is_local ) {
		nvtask_start_status_redis(impl);
	}
}

navi_task_t* navi_module_new_task(navi_module_t* module, const char* name, void* task_data,
	nvtask_cleanup_fp clean, nvtask_empty_notifier_fp empty_notifier)
{
	navi_module_impl_t* mi = navi_mod_h2i(module);
	navi_module_mgr_t* navi_mgr = (navi_module_mgr_t*) mi->navi_mgr;

	char tmp_buf[1024];
	char *p_full = tmp_buf;
	off_t off = snprintf(tmp_buf, sizeof(tmp_buf), "%s::%s::task-%s", navi_mgr->service_name,
		module->mod_name, name);
	if ( off >= sizeof(tmp_buf)) {
		p_full = (char*)malloc(off+1);
		sprintf(p_full, "%s::%s::task-%s", navi_mgr->service_name, module->mod_name, name);
	}

	navi_task_t* ret = navi_task_get_with_fullname(p_full);
	navi_task_impl_t* impl = NULL;
	if (ret ) {
		goto error;
	}

	impl = (navi_task_impl_t*)calloc(1, sizeof(navi_task_impl_t)+1024);
        navi_pool_init(impl->pool,impl,1024);
	ret = (navi_task_t*)impl;

	ret->svc_name = navi_mgr->service_name;
	ret->module_name = module->mod_name;
	ret->task_data = task_data;
	ret->cleanup = clean;
	ret->empty_notifier = empty_notifier;

	impl->full_name = navi_pool_strdup(impl->pool, p_full);
	ret->task_name = impl->full_name + strlen(impl->full_name) - strlen(name);

	impl->notify_list_key = navi_pool_nalloc(impl->pool, strlen(impl->full_name) + strlen("::notifies")+1);
	sprintf(impl->notify_list_key, "%s::notifies", impl->full_name);

	impl->task_status_key = navi_pool_nalloc(impl->pool, strlen(impl->full_name) + strlen("::status")+1);
	sprintf(impl->task_status_key, "%s::status", impl->full_name);

	impl->module = module;
	navi_module_incref(module);

	nvcli_parent_init(&impl->remote_sessions, impl->pool, ret, task_nvcli_parent_idle_handler);

	impl->is_local = 0;

	if ( p_full != tmp_buf) {
		free(p_full);
	}

	impl->check_timer = nvtask_new_timer(ret, NULL, 1000, NAVI_TIMER_INTERVAL,
		navi_task_check, NULL);
	navi_task_regist(ret);

	navi_list_init(&impl->bg_jobs);

	impl->time = time(NULL);
	return ret;
error:
	if (impl)
		free(impl);
	if ( p_full != tmp_buf) {
		free(p_full);
	}
	return NULL;
}

navi_task_t* navi_module_new_local_task(navi_module_t* module, void* task_data,
	nvtask_cleanup_fp clean, nvtask_empty_notifier_fp empty_notifier)
{
	static uint32_t local_task_id_gen = 0;
	if (local_task_id_gen == 0) {
		local_task_id_gen = rand()%1000000;
	}

	navi_module_impl_t* mi = navi_mod_h2i(module);
	navi_module_mgr_t* navi_mgr = (navi_module_mgr_t*) mi->navi_mgr;

	char tmp_buf[1024];
	char *p_full = tmp_buf;
	off_t off = snprintf(tmp_buf, sizeof(tmp_buf), "%s::%s::localtask-%08X", navi_mgr->service_name,
		module->mod_name, local_task_id_gen++);
	if ( off >= sizeof(tmp_buf)) {
		p_full = (char*)malloc(off+1);
		sprintf(p_full, "%s::%s::localtask-%08X", navi_mgr->service_name, module->mod_name, local_task_id_gen);
	}

	navi_task_t* ret = NULL;
	navi_task_impl_t* impl = NULL;

	impl = (navi_task_impl_t*)calloc(1, sizeof(navi_task_impl_t)+0x1000);
    navi_pool_init(impl->pool,impl,1024);
	ret = (navi_task_t*)impl;

	ret->svc_name = navi_mgr->service_name;
	ret->module_name = module->mod_name;
	ret->task_data = task_data;
	ret->cleanup = clean;
	ret->empty_notifier = empty_notifier;

	impl->full_name = navi_pool_strdup(impl->pool, p_full);
	ret->task_name = impl->full_name + strlen(navi_mgr->service_name) + strlen(module->mod_name) + 4;

	impl->module = module;
	navi_module_incref(module);
	nvcli_parent_init(&impl->remote_sessions, impl->pool, ret, task_nvcli_parent_idle_handler);

	impl->check_timer = nvtask_new_timer(ret, NULL, 1000, NAVI_TIMER_INTERVAL,
		navi_task_check, NULL);

	impl->is_local = 1;

	if ( p_full != tmp_buf) {
		free(p_full);
	}
	navi_list_init(&impl->bg_jobs);

	navi_task_regist(ret);
	return ret;
error:
	if (impl)
		free(impl);
	if ( p_full != tmp_buf) {
		free(p_full);
	}
	return NULL;
}

navi_module_t* navi_task_current_module(navi_task_t* task)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	return impl->module;
}

navi_task_t* navi_module_get_task(navi_module_t* module, const char* name)
{
	navi_module_impl_t* mi = navi_mod_h2i(module);
	navi_module_mgr_t* navi_mgr = (navi_module_mgr_t*) mi->navi_mgr;
	char tmp_buf[1024];
	char *p_full = tmp_buf;
	off_t off = snprintf(tmp_buf, sizeof(tmp_buf), "%s::%s::task-%s", navi_mgr->service_name,
		module->mod_name, name);
	if ( off >= sizeof(tmp_buf)) {
		p_full = (char*)malloc(off+1);
		sprintf(p_full, "%s::%s::task-%s", navi_mgr->service_name, module->mod_name, name);
	}

	navi_task_t* ret = navi_task_get_with_fullname(p_full);
	return ret;
}

void nvtask_join_notifies(navi_task_t* task, const nvtask_notify_join_t* joins, size_t cnt)
{
	if ( !joins || cnt == 0) return;
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	if ( impl->on_ctrl_handler == NULL)
		impl->on_ctrl_handler = navi_hash_init(impl->pool);

	int i;
	for (i=0; i<cnt; i++) {
		if ( joins[i].notify_name == NULL || strlen(joins[i].notify_name) == 0 || joins[i].handler==NULL)
			continue;
		navi_hash_set_gr(impl->on_ctrl_handler, joins[i].notify_name,
			joins[i].handler);
	}

	if ( !impl->notify_mon )
		navi_task_monitor_notify(task);
}

void nvtask_close(navi_task_t* task)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
    if (impl->recycled == 1)
        return;
	impl->remote_sessions.parent_idle_handler = NULL;
	if ( task->cleanup ) {
		task->cleanup(task, task->task_data);
		task->cleanup = NULL;
	}

	chain_node_t* nd = impl->bg_jobs.next;
	while ( nd != &impl->bg_jobs ) {
		navi_bgjob_t* job = navi_list_data(nd, navi_bgjob_t, task_link);
		nd = nd->next;
		navi_bgjob_close(task, job);
	}

	if ( impl->notify_mon)
		navi_task_quit_monitor(task);

	if (impl->trace) {
		json_t* trace_json = navi_trace_json(impl->trace);
		char* trace_str = json_dumps(trace_json,JSON_INDENT(2)|JSON_ENSURE_ASCII|
			JSON_PRESERVE_ORDER|JSON_ESCAPE_SLASH);
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "task [%s] trace [\n%s\n]", impl->full_name,trace_str);
		free(trace_str);
		json_decref(trace_json);
	}

	if (impl->check_timer) {
		nvcli_parent_cancel_timer(&impl->remote_sessions, impl->check_timer);
		//navi_timer_cancel(impl->check_timer);
	}

    nvcli_parent_cleanup(&impl->remote_sessions);
    impl->recycled = 1;
    navi_task_unregist(task);
	navi_module_decref(impl->module);
}

const char* nvtask_full_name(navi_task_t* task)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	return impl->full_name;
}

nvcli_http_t* nvtask_new_http_session(navi_task_t* ctx,
	const struct sockaddr* peer_addr,
	const char* uri,
	nvcli_http_procs_t app_procs,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)ctx;
	return nvcli_http_init(&impl->remote_sessions,peer_addr, uri, app_procs, app_data, conn_timeout,
		resp_max_waiting, input_max_interval);
}

nvcli_http_t* nvtask_new_http_session_url(navi_task_t* ctx,
	navi_url_parse_t* url,
	nvcli_http_procs_t app_procs,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)ctx;
	nvcli_http_t* ret = nvcli_http_init(&impl->remote_sessions,(const struct sockaddr*)&url->addr, url->uri,
		app_procs, app_data, conn_timeout,
		resp_max_waiting, input_max_interval);

	navi_hash_set(ret->o_headers, "host", url->host_text);
	return ret;
}

nvcli_redis_t* nvtask_new_redis_session(navi_task_t* task, const struct sockaddr* peer_addr,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	return nvcli_redis_init(&impl->remote_sessions,peer_addr, result_handler, error_handler, app_data,
		conn_timeout, resp_max_waiting, input_max_interval);
}


navi_timer_h nvtask_new_timer(navi_task_t* task, void* timer_data, int timeout_ms,
	navi_timer_type_e type,
	nvtask_timer_handler_fp handler,
	nvtask_timer_handler_fp cleanup)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	return nvcli_parent_add_timer(&impl->remote_sessions,timeout_ms, type, timer_data,
		(nvcli_parent_timer_fp)handler, (nvcli_parent_timer_fp)cleanup);
}

void nvtask_cancel_timer(navi_task_t* task, navi_timer_h timer)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	nvcli_parent_cancel_timer(&impl->remote_sessions, timer);
}

void nvtask_trace(navi_task_t* handle, navi_trace_type_e e, const char* fmt, ...)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)handle;
	navi_module_impl_t* mi = navi_mod_h2i(impl->module);
	if ( mi->enable_trace ) {
		if ( !impl->trace)
			impl->trace = navi_trace_init(impl->pool);
		va_list vl;
		va_start(vl,fmt);
		navi_vtrace(impl->trace, handle->module_name, e, fmt, vl);
		va_end(vl);
	}
}

void* nvtask_regist_app_context(navi_task_t* handle, const char* name, size_t context_sz)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)handle;
	if (context_sz == 0 || name == NULL || strlen(name) == 0)
		return NULL;
	if (impl->app_contexts == NULL) {
		impl->app_contexts = navi_hash_init(impl->pool);
	}
	void* ctx = navi_hash_get_gr(impl->app_contexts, name);
	if (ctx) return NULL;
	ctx = navi_pool_calloc(impl->pool, 1, context_sz);
	navi_hash_set_gr(impl->app_contexts, name, ctx);
	return ctx;
}

void* nvtask_get_app_context(navi_task_t* handle, const char* name)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)handle;
	if (impl->app_contexts == NULL) return NULL;
	return navi_hash_get_gr(impl->app_contexts, name);
}

void nvtask_reset_app_context(navi_task_t* handle, const char* name, void* value, size_t context_sz)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)handle;
	if (impl->app_contexts == NULL || name==NULL || strlen(name)==0 || context_sz==0) return ;
	void* ctx = navi_hash_get_gr(impl->app_contexts, name);
	if (!ctx ) return;
	if (value) {
		memcpy(ctx, value, context_sz);
	}
	else {
		memset(ctx, 0x00, context_sz);
	}
}

void* nvtask_try_probe_touch_context(navi_task_t* handle, const char* name, size_t context_sz)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)handle;
	if ( name == NULL || strlen(name) == 0 )
		return NULL;
	if (impl->app_contexts == NULL) {
		if (context_sz == 0 )
			return NULL;
		return nvtask_regist_app_context(handle, name, context_sz);
	}

	void* ctx = navi_hash_get_gr(impl->app_contexts, name);
	if (ctx) return ctx;
	return nvtask_regist_app_context(handle,name, context_sz);
}

navi_pool_t* nvtask_pool(navi_task_t* task)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	return impl->pool;
}

void* nvtask_get_driver_pool(navi_task_t* task)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	return impl->remote_sessions.get_driver_pool(impl->remote_sessions.driver);
}

/*******************************
 *  keepalive redis 状态通告
 *******************************/

void nvtask_start_status_proc(void* parent, nvcli_redis_t* ss, const navi_upreq_result_t* result)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)parent;
	time_t epoch = time(NULL);
	if ( result->code != NVUP_RESULT_SESSION_OK ) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "task [%s] nvtask_start_status_proc error:[%d]%s",  impl->full_name, result->code,result->session_err_desc);
	}

    nvredis_cleanup(impl->keepalive_session);
    nvcli_clean(&impl->keepalive_session->base);
	impl->keepalive_session = NULL;
}

void nvtask_start_status_error(void* parent, nvcli_redis_t* ss, nvcli_error_e e)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)parent;
	time_t epoch = time(NULL);
    NAVI_FRAME_LOG(NAVI_LOG_ERR, "task [%s] nvtask_start_status_error:%d", impl->full_name, e);

    nvredis_cleanup(impl->keepalive_session);
    nvcli_clean(&impl->keepalive_session->base);
	impl->keepalive_session = NULL;
}

static void nvtask_start_status_redis(navi_task_impl_t* impl)
{
	if ( impl->keepalive_session != NULL ) {
		return;
	}

#if 1
	struct sockaddr_in si;
	char ip[20] = "10.10.69.213";
	int s;

	si.sin_family = AF_INET;
	si.sin_port = htons(6379);
	if ((s = inet_pton(AF_INET,ip, (void *)&si.sin_addr)) <= 0) {
		return;
	}
	impl->keepalive_session =
		nvtask_new_redis_session(&impl->app_frame, (const struct sockaddr*)&si, nvtask_start_status_proc,
			nvtask_start_status_error, NULL, 500, 8000, 2000);
#else
	impl->keepalive_session =
		nvtask_new_redis_session(&impl->app_frame, (const struct sockaddr*)&g_tasks->ctrl_addr, nvtask_start_status_proc,
			nvtask_start_status_error, 500, 800, 2000);
#endif
	time_t epoch = time(NULL);
	uint64_t has_run = epoch - impl->time;
	impl->time = epoch;
	nvcli_redis_incrby(impl->keepalive_session,impl->task_status_key, has_run);
}

/*******************************
 * 任务redis通知获取
 *******************************/

static void nvtask_notify_lpop_proc(void* parent, nvcli_redis_t* ss, const navi_upreq_result_t* result)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)parent;
	impl->get_notify_session = NULL;
	if ( result->code == NVUP_RESULT_SESSION_OK ) {
		if (result->content_type == NVUP_RESULT_DATA_NULL) {
			impl->get_notify_retry = 0;
			return;
		}
		else if(result->content_type == NVUP_RESULT_DATA_STRING) {
			impl->get_notify_retry = 0;
			json_error_t js_err;
			json_t* notify_data = json_loads(result->s, &js_err);
			if ( notify_data ) {
				json_t* name_js = json_object_get(notify_data, "name");
				if ( name_js && json_is_string(name_js)) {
					nvtask_notify_handler_fp notify_handler = (nvtask_notify_handler_fp)
						navi_hash_get_gr(impl->on_ctrl_handler,json_string_value(name_js));
					if (notify_handler) {
						notify_handler(&impl->app_frame, notify_data);
					}
				}
				json_decref(notify_data);
			}
			nvtask_get_notify_redis(impl); //可能还有数据
		}
		else {
			NAVI_FRAME_LOG(NAVI_LOG_INFO, "task [%s] nvtask_notify_lpop_proc get notify: content_type=%d",
                                impl->full_name, result->content_type);
			impl->get_notify_retry++;

			nvtask_get_notify_redis(impl);
		}
	}
	else {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "task [%s] nvtask_notify_lpop_proc error:[%d]%s",
                        impl->full_name, result->code,result->session_err_desc);
		impl->get_notify_retry++;
		nvtask_get_notify_redis(impl);
	}
}

static void nvtask_notify_lpop_error(void* parent, nvcli_redis_t* ss, nvcli_error_e e)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)parent;
	NAVI_FRAME_LOG(NAVI_LOG_ERR, "task [%s] nvtask_notify_lpop_error:%d", impl->full_name, e);
	impl->get_notify_retry++;
	impl->get_notify_session = NULL;
	nvtask_get_notify_redis(impl);
}

void navi_task_notify_arrive(navi_task_impl_t* impl, uint64_t seq)
{
	if ( seq > impl->monitor_seq ) {
		nvtask_get_notify_redis(impl);
	}
}

static void nvtask_get_notify_redis(navi_task_impl_t* impl)
{
	if ( impl->get_notify_session != NULL) {
		return;
	}
	else if (impl->get_notify_retry >= 5) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "task [%s] nvtask_get_notify_redis tried more than 5 times",impl->full_name);
	}

	impl->get_notify_session =
		nvtask_new_redis_session(&impl->app_frame, (const struct sockaddr*)&g_tasks->ctrl_addr, nvtask_notify_lpop_proc,
			nvtask_notify_lpop_error, NULL, 500, 500, 2000);

	nvcli_redis_lpop(impl->get_notify_session, impl->notify_list_key);
}
