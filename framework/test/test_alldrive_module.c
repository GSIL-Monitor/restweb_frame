/*
 * test_alldrivetest_module.c
 *
 *  Created on: 2015Äê3ÔÂ26ÈÕ
 *      Author: li.lei
 */



#include "navi_module.h"
#include "navi_request.h"
#include "navi_static_content.h"
#include "navi_frame_log.h"
#include "navi_task.h"
#include "exec_util.h"

NAVI_MODULE_INIT(test_alldrive,module)
{
	module->module_data = NULL;
	return NAVI_OK;
}

NAVI_MODULE_FREE(test_alldrive,module)
{

}

static void tsk_tmr1_proc(navi_task_t* task, void* timer_data)
{
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "task_timer1 timedout");
}

static void tsk_tmr2_proc(navi_task_t* task, void* timer_data)
{
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "task_timer2 timedout");
	nvtask_close(task);
}

NAVI_MODULE_METHOD(test_alldrive, task_timer, module, request)
{
	navi_task_t* tsk = navi_module_new_local_task(module, NULL, NULL, NULL);
	nvtask_new_timer(tsk, NULL, 2000, NAVI_TIMER_ONCE, tsk_tmr1_proc, NULL);
	nvtask_new_timer(tsk, NULL, 5000, NAVI_TIMER_ONCE, tsk_tmr2_proc, NULL);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_alldrive,only_timer,module,request)
{
	navi_request_add_timer(request, NULL, NULL, NULL, 1000, false);
	return NAVI_OK;
}

void emerg_resp_timer (navi_request_t* req, navi_timer_h tmr, void* args)
{
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "emerg_resp_timer");
}

NAVI_MODULE_METHOD(test_alldrive,emerg_resp,module,request)
{
	navi_request_add_timer(request, emerg_resp_timer, NULL, NULL, 1000, false);
	navi_request_emerg_response(request);
	return NAVI_OK;
}


void emerg_resp_timer2 (navi_request_t* req, navi_timer_h tmr, void* args)
{
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "emerg_resp_timer");
	int* ctx = (int*)req->custom_ctx;
	if ( 0 == ((*ctx)++) ) {
		navi_request_emerg_response(req);
	}
	if (*ctx == 10)
		navi_request_cancel_timer(req, tmr);
}

NAVI_MODULE_METHOD(test_alldrive,emerg_resp2,module,request)
{
	int* ctx = navi_pool_calloc(navi_request_pool(request),1, sizeof(int));
	navi_request_set_custom_context(request,ctx);
	*ctx = 0;

	navi_request_add_timer(request, emerg_resp_timer2, NULL, NULL, 1000, true);
	return NAVI_OK;
}

void deny_bigpost_timer(navi_request_t* req, navi_timer_h tmr, void* args) {
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "deny_bigpost in timer");
	navi_http_request_abort_bigpost(req);
}

NAVI_MODULE_METHOD(test_alldrive,deny_bigpost,module,request)
{
	if ( navi_http_request_is_bigpost(request) ) {
		navi_request_add_timer(request, deny_bigpost_timer, NULL, NULL, 20, false);
	}
	else {
		NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "deny_bigpost is not big");
	}
	return NAVI_OK;
}

NAVI_MODULE_BIGPOST(test_alldrive,deny_bigpost,mod,req,path)
{
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "deny_bigpost bigpost ready");
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_alldrive,bigpost_step1_addsub,module,request)
{
	navi_request_t* subreq = navi_request_new_sub(request);
	navi_upredis_t* redis = navi_request_bind_upredis(subreq, "redis_local", NULL);
	navi_upredis_set(redis,"test","testvalue");
	return NAVI_OK;
}

NAVI_MODULE_BIGPOST(test_alldrive,bigpost_step1_addsub,mod,req,path)
{
	navi_request_t* subreq = navi_request_new_sub(req);
	navi_upredis_t* redis = navi_request_bind_upredis(subreq, "redis_local", NULL);
	navi_upredis_set(redis,"test2",path);
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "bigpost_step1_addsub bigpost ready:%s", path);
	rename(path, "/tmp/test.post");
	return NAVI_OK;
}

void bigpost_step1_addtimer_redis1(navi_upredis_t* up, navi_upreq_result_t* res, void* ctx)
{
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "bigpost_step1_addtimer subreq redis1");
}

void bigpost_step1_addtimer_redis2(navi_upredis_t* up, navi_upreq_result_t* res, void* ctx)
{
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "bigpost_step1_addtimer subreq redis2");
}

void bigpost_step1_addtimer_redis3(navi_upredis_t* up, navi_upreq_result_t* res, void* ctx)
{
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "bigpost_step1_addtimer subreq redis3");
}

void bigpost_step1_addtimer_timer1(navi_request_t* req, navi_timer_h tmr, void* args) {
NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "bigpost_step1_addtimer timer for method");
}

void bigpost_step1_addtimer_timer2(navi_request_t* req, navi_timer_h tmr, void* args) {
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "bigpost_step1_addtimer timer for bigpost-method");
	navi_request_t* subreq = navi_request_new_sub(req);
	navi_upredis_t* redis = navi_request_bind_upredis(subreq, "redis_local", bigpost_step1_addtimer_redis3);
	navi_upredis_set(redis,"test_aaa","testvalue");
}

NAVI_MODULE_METHOD(test_alldrive,bigpost_step1_addtimer,module,request)
{
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "bigpost_step1_addtimer entry method");
	navi_request_t* subreq = navi_request_new_sub(request);
	navi_upredis_t* redis = navi_request_bind_upredis(subreq, "redis_local", bigpost_step1_addtimer_redis1);
	navi_upredis_set(redis,"test","testvalue");
	navi_request_add_timer(request, bigpost_step1_addtimer_timer1,NULL,NULL,5000,false);
	return NAVI_OK;
}

NAVI_MODULE_BIGPOST(test_alldrive,bigpost_step1_addtimer,mod,req,path)
{
	navi_request_t* subreq = navi_request_new_sub(req);
	navi_upredis_t* redis = navi_request_bind_upredis(subreq, "redis_local", bigpost_step1_addtimer_redis2);
	navi_upredis_set(redis,"test2",path);
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "bigpost_step1_addsub bigpost ready:%s", path);
	rename(path, "/tmp/test.post");
	navi_request_add_timer(req, bigpost_step1_addtimer_timer2,NULL,NULL,1000,false);
	return NAVI_OK;
}

void only_streaming_timer(navi_request_t* req, navi_timer_h tmr, void* args) {
	int* pint = args;
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "only_streaming timer:%d ", *pint);
	char c = 'a' + *pint%26;
	navi_request_respbody_streaming(req, &c, 1);

	navi_request_t* subreq = navi_request_new_sub(req);
	navi_upredis_t* redis = navi_request_bind_upredis(subreq, "redis_local", NULL);
	char value[2] = { c, 0 };
	char *values[1] = {value};
	navi_upredis_set(redis,"test","testvalue");
	navi_upredis_lpush(redis,"test_list_onlystreaming",values, 1);

	if ( (*pint)++ == 1000 ) {
		navi_request_cancel_timer(req, tmr);
		navi_request_respbody_streaming_eof(req);
	}
}

NAVI_MODULE_METHOD(test_alldrive,only_streaming,module,request)
{
	navi_request_respbody_enable_streaming(request, 1000);
	int* pint  = navi_request_alloc(request,sizeof(int));
	*pint = 0;
	navi_request_add_timer(request, only_streaming_timer,pint,NULL,10,true);
	return NAVI_OK;
}

void only_streaming_timer2(navi_request_t* req, navi_timer_h tmr, void* args) {
	int* pint = args;
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "only_streaming2 timer:%d ", *pint);
	char c = 'a' + *pint%26;
	navi_request_respbody_streaming(req, &c, 1);

	if ( (*pint)++ == 10000 ) {
		navi_request_cancel_timer(req, tmr);
		navi_request_respbody_streaming_eof(req);
	}
}

NAVI_MODULE_METHOD(test_alldrive,only_streaming2,module,request)
{
	navi_request_respbody_enable_streaming(request, -1);
	int* pint  = navi_request_alloc(request,sizeof(int));
	*pint = 0;
	navi_request_add_timer(request, only_streaming_timer2,pint,NULL,10,true);
	return NAVI_OK;
}

static void tsk_streaming_timer_handler(navi_task_t* task, void* timer_data)
{
	int *cnt = (int*)timer_data;
	navi_request_t* req = (navi_request_t*)task->task_data;
	if (*cnt > 10000 ) {
		printf("streaming eof\n");
		navi_request_respbody_streaming_eof(req);
		nvtask_close(task);
		return;
	}

	*cnt += 1;

	char buf[40];
	snprintf(buf, sizeof(buf),"%d ", *cnt);
	int i=0;
	for (; i<1000; i++) {
		navi_request_respbody_streaming(req, buf,strlen(buf));
	}
}

NAVI_MODULE_METHOD(test_alldrive,streaming_task,module,request)
{
	navi_request_respbody_enable_streaming(request, -1);
	navi_task_t* tsk  = navi_module_new_local_task(module, request, NULL, NULL);
	int *cnt = (int*)nvtask_regist_app_context(tsk, "counter", sizeof(int));
	*cnt = 0;
	nvtask_new_timer(tsk,cnt,1, NAVI_TIMER_INTERVAL, tsk_streaming_timer_handler, NULL );
	return NAVI_OK;
}

static int timer_handler(void* timer_args)
{
	navi_request_t* req = timer_args;
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "suspend_with_modtimer timer");
	navi_request_enable_autofin(req);
}

NAVI_MODULE_METHOD(test_alldrive, suspend_with_modtimer, module, request)
{
	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "suspend_with_modtimer");
	navi_request_t* subreq = navi_request_new_sub(request);
	navi_upredis_t* redis = navi_request_bind_upredis(subreq, "redis_local", NULL);
	navi_upredis_set(redis,"test","testvalue");
	navi_request_add_timer(request, NULL,NULL,NULL,3000,false);

	navi_request_disable_autofin(request);
	navi_module_add_once_timer(module, 2000, timer_handler, request, NULL);
	return NAVI_OK;
}

static int exec_end_handler(navi_exec_mon_t *cmd, void* context, int status,
	const unsigned char* child_out, size_t sz)
{
	navi_request_t* req = (navi_request_t*)context;
	navi_response_t* resp = navi_request_response_obj(req);
	if (status == 0) {
		navi_response_set_desc(resp, 0, "testall_drive","exec_success");
	}
	else {
		navi_response_set_desc(resp, status, "testall_drive", "exec_failed");
	}
	if ( sz > 0 ) {
		json_t* content = json_object();
		int i=0;
		int escape_cnt = 0;
		for(; i<sz; i++,escape_cnt++) {
			if (!isprint(child_out[i]) ) {
				escape_cnt += 3;
			}
		}

		char* content_str = navi_request_alloc(req, escape_cnt+1);
		char* p = content_str;
		for (i=0; i<sz; i++) {
			if (isprint(child_out[i])) {
				*(p++) = child_out[i];
			}
			else {
				sprintf(p, "\\x%02x", child_out[i]);
				p += 4;
			}
		}
		*p = 0;
		json_object_set_new(content, "exec_output",json_string(content_str) );
		navi_response_set_content(resp, content, 0);
	}
	navi_request_enable_autofin(req);
	return 0;
}

NAVI_MODULE_METHOD(test_alldrive, exec_sleep, module, request)
{
	const char* arg = navi_http_request_get_arg(request, "arg");
	navi_request_disable_autofin(request);
	navi_exec_mon_t* exec = navi_exec_prepare("sleep","/tmp",true, 0, 0,  request,
			exec_end_handler, exec_end_handler);
	if (arg==NULL)
		navi_exec_append_arguments(exec, 1, "5");
	else
		navi_exec_append_arguments(exec, 1, arg);
	navi_exec_run(exec);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_alldrive, exec_echo, module, request)
{
	const char* arg = navi_http_request_get_arg(request, "arg");
	navi_request_disable_autofin(request);
	navi_exec_mon_t* exec = navi_exec_prepare("echo","/tmp",false, 0, 0,  request,
			exec_end_handler, exec_end_handler);
	if (arg==NULL)
		navi_exec_append_arguments(exec, 1, "echo empty");
	else
		navi_exec_append_arguments(exec, 1, arg);
	navi_exec_run(exec);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_alldrive, exec_gr, module, request)
{
	const char* cmd = navi_request_resturi(request);
	const char* rundir = navi_http_request_get_arg(request, "dir");
	const char* args = navi_http_request_get_arg(request, "args");
	const char* occpy = navi_http_request_get_arg(request, "occpy_dir");
	if (rundir==NULL) rundir = "/tmp";

	if (!cmd) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp,-1,"tt","cmd absent");
		return NAVI_OK;
	}

	navi_exec_mon_t* exec = navi_exec_prepare(cmd,rundir, occpy?true:false, 0, 0 ,request,
		exec_end_handler, exec_end_handler);

	if (args)
		navi_exec_append_arguments(exec, 1, args);
	navi_request_disable_autofin(request);
	navi_exec_run(exec);
	return NAVI_OK;
}
