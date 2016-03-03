#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <navi_request.h>
#include <navi_module.h>
#include <navi_task.h>
#include <navi_bg_job.h>
#include <file_monitor.h>
#include <exec_util.h>

#include "ntask_test_log.h"
#include "playlog_handler.h"

typedef struct ntask_data_s {
	navi_hash_t* groups;
	navi_pool_t pool[0];
} ntask_data_t;

int ntask_http_reqbody_generator(void* parent, nvcli_http_t* ss)
{
	ntask_test_log(NAVI_LOG_INFO,"http goon");
	return 1;
}
void ntask_http_resp_start(void* parent, nvcli_http_t* ss)
{
	ntask_test_log(NAVI_LOG_INFO,"http get response head");

}
void ntask_http_respbody_handler(void* parent, nvcli_http_t* ss,
	const unsigned char* content, size_t size)
{
	ntask_test_log(NAVI_LOG_INFO,"http get response body");
}
void ntask_http_session_complete(void* parent, nvcli_http_t* ss)
{
	ntask_test_log(NAVI_LOG_INFO,"http complete");

}
void ntask_http_error_handler(void* parent, nvcli_http_t* ss, nvcli_error_e e)
{
	ntask_test_log(NAVI_LOG_WARNING,"http error");
}


nvcli_http_procs_t ntask_http_proc = {
	ntask_http_error_handler,
	ntask_http_session_complete,
	ntask_http_reqbody_generator,
	ntask_http_resp_start,
	ntask_http_respbody_handler
};

void nvredis_result_proc(void* parent, nvcli_redis_t* ss, const navi_upreq_result_t* result)
{
    ntask_data_t *task = (ntask_data_t*)parent;
    //nvtask_close(task);
	ntask_test_log(NAVI_LOG_INFO,"redis complete");
}

void nvredis_error_proc(void* parent, nvcli_redis_t* ss, nvcli_error_e e)
{
	ntask_test_log(NAVI_LOG_WARNING,"redis error");
}



static char* report_playlog_cmd_sha = NULL;

void playlog_result_proc(void* parent, nvcli_redis_t* ss, const navi_upreq_result_t* result)
{
	if (result->content_type == NVUP_RESULT_DATA_JSON)
		ntask_test_log(NAVI_LOG_INFO,"redis result:%s", json_dumps(result->js, JSON_INDENT(2)|JSON_ENSURE_ASCII|
			JSON_PRESERVE_ORDER|JSON_ESCAPE_SLASH));
	else if (result->content_type == NVUP_RESULT_DATA_STRING || result->content_type == NVUP_RESULT_DATA_ERR)
		ntask_test_log(NAVI_LOG_INFO,"redis result:%s", result->s);
	else if (result->content_type == NVUP_RESULT_DATA_INT)
		ntask_test_log(NAVI_LOG_INFO,"redis result:%d", result->i);
}

void playlog_sha_result_proc(void* parent, nvcli_redis_t* ss, const navi_upreq_result_t* result)
{
	ntask_test_log(NAVI_LOG_INFO,"redis result:\n%s", json_dumps(result->js, JSON_PRESERVE_ORDER));

	if (report_playlog_cmd_sha != NULL) {
		free(report_playlog_cmd_sha);
        report_playlog_cmd_sha = NULL;
	}
	report_playlog_cmd_sha = strdup(result->s);
	ss->result_handler = playlog_result_proc;
}

void playlog_error_proc(void* parent, nvcli_redis_t* ss, nvcli_error_e e)
{
	ntask_test_log(NAVI_LOG_WARNING,"redis error");
}



void ntask_cleanup(navi_task_t* task, void* task_data)
{

}

void ntask_empty_notifier(navi_task_t* task, void* task_data)
{
	ntask_test_log(NAVI_LOG_INFO,"ntask upstream is done");
}

void ntask_timer_handler(navi_task_t* task, void* timer_data)
{
	ntask_test_log(NAVI_LOG_INFO,"ntask timer %d is fired",(int)timer_data);
}

void ntask_timer_cleaner(navi_task_t* task, void* timer_data)
{
	ntask_test_log(NAVI_LOG_INFO,"ntask timer %d is canceled",(int)timer_data);
}

void ntask_encode_handler(navi_task_t* task, const json_t* notify_obj)
{
	ntask_test_log(NAVI_LOG_INFO,"ntask encode start");
}

void ntask_decode_handler(navi_task_t* task, const json_t* notify_obj)
{
	ntask_test_log(NAVI_LOG_INFO,"ntask decode start");
}


NAVI_MODULE_INIT(ntask_test,module)
{
	json_t* http_conf = json_object_get(module->js_conf, "http_group");
	if (!http_conf || !json_is_string(http_conf))
		return NAVI_CONF_ERR;
	json_t* redis_conf = json_object_get(module->js_conf, "redis_group");
	if (!redis_conf || !json_is_string(redis_conf))
		return NAVI_CONF_ERR;

	ntask_test_log_init(module->js_conf);

	ntask_data_t *mdata = (ntask_data_t*)calloc(1,sizeof(ntask_data_t)+1024);
	navi_pool_init(mdata->pool,mdata,1024);

	mdata->groups = navi_hash_init(mdata->pool);
	
	navi_hash_set(mdata->groups, "http_group", json_string_value(http_conf));
	navi_hash_set(mdata->groups, "redis_group", json_string_value(redis_conf));
	
	module->module_data = mdata;
    
	navi_bgjob_workers_startup(2);

	return NAVI_OK;
}

NAVI_MODULE_FREE(ntask_test,module)
{
	if (module->module_data)
		navi_pool_destroy(((ntask_data_t*)module->module_data)->pool);
	ntask_test_log_destroy();
}

int file_create_handler(char *path, char *filename)
{
	ntask_test_log(NAVI_LOG_INFO,"file %s/%s create", path,filename);
}

int file_write_done_handler(char *path, char *filename)
{
	ntask_test_log(NAVI_LOG_INFO,"file %s/%s write done", path,filename);
}

int exec_success_handler(navi_exec_mon_t* cmd, void* context, int status)
{
	ntask_test_log(NAVI_LOG_INFO,"exec: %s done", cmd);
}

int exec_failed_handler(navi_exec_mon_t* cmd, void* context, int status)
{
	ntask_test_log(NAVI_LOG_INFO,"exec: %s failed with status = %d", cmd, status);
}

NAVI_MODULE_METHOD(ntask_test,new_task,module,request)
{
	navi_task_t* task;
	struct sockaddr_in si;
	char ip[20] = "10.10.69.213";
	int s;
	navi_response_t* resp;
	const char * httpinfo;

    si.sin_family = AF_INET;
	si.sin_port = htons(6379);
	if ((s = inet_pton(AF_INET,ip, (void *)&si.sin_addr)) <= 0) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "invalid addr");
		return NAVI_OK;
	}
	
	task = navi_module_get_task(module,"test1");
	if (task == NULL) {
		task = navi_module_new_task(module,"test1",((ntask_data_t*)module->module_data)->pool, ntask_cleanup, ntask_empty_notifier);
       
    	if (task == NULL) {
    		navi_response_t* resp = navi_request_response_obj(request);
    		navi_response_set_desc(resp, -1 , "", "alloc task error");
    		return NAVI_OK;
    	}
        playlog_init(task,(const struct sockaddr *)&si);
	}

	nvcli_redis_t* redis_session = nvtask_new_redis_session(task,(const struct sockaddr *)&si,nvredis_result_proc, nvredis_error_proc, NULL, 200, 100000, 100000);
	if (redis_session == NULL) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "redis connect error");
		return NAVI_OK;
	}

	si.sin_port = htons(80);
	nvcli_http_t* http_session = nvtask_new_http_session(task,(const struct sockaddr *)&si,"/index.html",ntask_http_proc, NULL, 200, 100000, 100000);
	if (http_session == NULL) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "http connect error");
		return NAVI_OK;
	}


	nvcli_http_start(http_session,NV_HTTP_GET);
    nvcli_redis_get(redis_session,"ntask_test:testkey");

    resp = navi_request_response_obj(request);
	httpinfo = navi_hash_get(((ntask_data_t*)module->module_data)->groups, "http_group");
	json_t* js = json_object();
	json_object_set_new(js,"http",json_string(httpinfo));
	
	navi_response_set_content(resp,js,0);
	navi_response_set_desc(resp,0,"","task submit done");

	nvtask_notify_join_t notifys[2] = {{"encode",ntask_encode_handler},{"decode",ntask_decode_handler}};
	nvtask_join_notifies(task,notifys,2);
    return NAVI_OK;
}

NAVI_MODULE_METHOD(ntask_test,close_task,module,request)
{
	navi_task_t* task = navi_module_get_task(module,"test1");
	if (task == NULL)
		return NAVI_OK;
	nvtask_close(task);
    return NAVI_OK;
}

NAVI_MODULE_METHOD(ntask_test,send_file,module,request)
{
	struct sockaddr_in si;
	char ip[20] = "10.10.69.213";
	int s;
	navi_task_t* task = navi_module_get_task(module,"test1");
	if (task == NULL)
		task = navi_module_new_task(module,"test1",((ntask_data_t*)module->module_data)->pool, ntask_cleanup, ntask_empty_notifier);
	if (task == NULL) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "alloc task error");
		return NAVI_OK;
	}

	si.sin_family = AF_INET;
	if ((s = inet_pton(AF_INET,ip, (void *)&si.sin_addr)) <= 0) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "invalid addr");
		return NAVI_OK;
	}
	si.sin_port = htons(8000);
	nvcli_http_t* http_session = nvtask_new_http_session(task,(const struct sockaddr *)&si,"/test1/bigpost/post.json?user=1982",ntask_http_proc, NULL, 200, 100000, 100000);
	if (http_session == NULL) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "http connect error");
		return NAVI_OK;
	}

    http_session->method = NV_HTTP_POST;
	nvcli_http_set_reqheader(http_session,"Content-Type","application/octet-stream");
	
	int fd = open("/opt/zdb/test.tmp",O_RDONLY);
	struct stat sb;
    fstat(fd, &sb);
    size_t filelen = sb.st_size;
	nvcli_http_set_reqbody_process(http_session,filelen,NULL);
	nvcli_http_start(http_session,NV_HTTP_POST);
	nvcli_sendfile(http_session,fd,0,false);
	return NAVI_OK;
}


void navi_bgjob_cleanup_handler(struct _navi_bgjob_t* job,void* job_data)
{
    ntask_test_log(NAVI_LOG_INFO,"bgjob %s clean up",job->full_name);
}

void navi_bgjob_startup_handler(struct _navi_bgjob_t* job, void* job_data)
{
    ntask_test_log(NAVI_LOG_INFO,"bgjob %s is done",job->full_name);
}

void navi_bgjob_stream_handler(struct _navi_bgjob_t* job, void* stream, size_t sz)
{
    ntask_test_log(NAVI_LOG_INFO,"bgjob %s stream hander:%d",job->full_name,sz);
}

void navi_bgjob_complete_handler(navi_task_t* task, struct _navi_bgjob_t* job, void* data)
{
    ntask_test_log(NAVI_LOG_INFO,"bgjob %s is done",job->full_name);
}

void navi_bgjob_error_handler(navi_task_t* task, struct _navi_bgjob_t* job, void* data, const char* err)
{
    ntask_test_log(NAVI_LOG_INFO,"bgjob %s is err:%s",job->full_name,err);
}


NAVI_MODULE_METHOD(ntask_test,new_bgjob,module,request)
{
    navi_task_t* task = navi_module_get_task(module,"test1");
	if (task == NULL)
		task = navi_module_new_task(module,"test1",((ntask_data_t*)module->module_data)->pool, ntask_cleanup, ntask_empty_notifier);
	if (task == NULL) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "alloc task error");
		return NAVI_OK;
	}

    navi_bgjob_t* bgjob1 = navi_bgjob_create(task,"job1",NULL,navi_bgjob_startup_handler,navi_bgjob_cleanup_handler,
                                       navi_bgjob_complete_handler, navi_bgjob_error_handler);
    navi_bgjob_t* bgjob2 = navi_streamed_bgjob_create(task,"job2",NULL,navi_bgjob_startup_handler,navi_bgjob_cleanup_handler,
                                       navi_bgjob_stream_handler,navi_bgjob_complete_handler, navi_bgjob_error_handler);
    return NAVI_OK;
}

NAVI_MODULE_METHOD(ntask_test,new_timer,module,request)
{
	navi_task_t* task = navi_module_get_task(module,"test1");
	if (task == NULL)
		task = navi_module_new_task(module,"test1",((ntask_data_t*)module->module_data)->pool, ntask_cleanup, ntask_empty_notifier);
	if (task == NULL) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "alloc task error");
		return NAVI_OK;
	}

    navi_timer_h tmr = nvtask_new_timer(task,(void*)1,3000,NAVI_TIMER_ONCE,ntask_timer_handler,ntask_timer_cleaner);
	navi_timer_h tmr2 = nvtask_new_timer(task,(void*)2,5000,NAVI_TIMER_ONCE,ntask_timer_handler,ntask_timer_cleaner);

    nvtask_cancel_timer(task,tmr2);
    return NAVI_OK;
}


NAVI_MODULE_METHOD(ntask_test,file_mon,module,request)
{
	navi_file_mon_t * pfmon = calloc(1,sizeof(navi_file_mon_t));
	navi_file_mon_conf_t * pconf = calloc(1,sizeof(navi_file_mon_conf_t));
	pconf->path = "/opt/zdb/test/testdir";
	pconf->create_handler = file_create_handler;
	pconf->closew_handler = file_write_done_handler;
	
	file_mon_init(pfmon);
	file_add_monitor(pfmon, pconf);
	
	return NAVI_OK;    
}

NAVI_MODULE_METHOD(ntask_test,exec_mon,module,request)
{
	navi_exec_mon_t *pexec = exec_prepare("ffmpeg", 2,
		3000, 9, NULL, exec_success_handler,
		exec_failed_handler);
    exec_append_option(pexec,EXEC_OPT_SHORT,"i","/opt/zdb/test/thehobbit.rmvb");
    exec_append_option(pexec,EXEC_OPT_SHORT,"codec","copy");
    exec_append_option(pexec,EXEC_OPT_SHORT,"map","0");
    exec_append_option(pexec,EXEC_OPT_SHORT,"f","segment");
    exec_append_option(pexec,EXEC_OPT_SHORT,"segment_list","out.list");
    exec_append_arguments(pexec,1,"/opt/zdb/test/testdir/out%03d.nut");
#if 0    
	pexec->cmd = "ffmpeg -i /opt/zdb/test/thehobbit.rmvb -codec copy -map 0 -f segment -segment_list out.list /opt/zdb/test/testdir/out%03d.nut";
	pexec->respawn_timeout = 3000;
	pexec->kill_signal = 9;//SIGKILL
	pexec->exit_success = exec_success_handler;
	pexec->exit_abnormal = exec_failed_handler;
#endif
	exec_run(pexec);
	return NAVI_OK;    
}

NAVI_MODULE_METHOD(ntask_test,playlog_report,module,request)
{
	struct sockaddr_in si;
	char ip[20] = "10.10.69.213";
	int s;
	navi_task_t* task = navi_module_get_task(module,"test1");
	if (task == NULL)
		task = navi_module_new_task(module,"test1",((ntask_data_t*)module->module_data)->pool, ntask_cleanup, ntask_empty_notifier);
	if (task == NULL) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "alloc task error");
		return NAVI_OK;
	}

	si.sin_family = AF_INET;
	if ((s = inet_pton(AF_INET,ip, (void *)&si.sin_addr)) <= 0) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "invalid addr");
		return NAVI_OK;
	}
	si.sin_port = htons(6379);
	nvcli_redis_t* redis_session = nvtask_new_redis_session(task,(const struct sockaddr *)&si,playlog_result_proc, playlog_error_proc,200, 100000, 100000);
	if (redis_session == NULL) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "redis connect error");
		return NAVI_OK;
	}
	navi_pool_t * pool = navi_pool_create(4096);
	navi_array_t * input_param = navi_array_create(pool,4, sizeof(playlog_t));
	playlog_t* ent = navi_array_push(input_param);
	ent->fileid = "fileid1";
	ent->count = "1";
	ent = navi_array_push(input_param);
	ent->fileid = "fileid2";
	ent->count = "2";
	ent = navi_array_push(input_param);
	ent->fileid = "fileid3";
	ent->count = "3";
	ent = navi_array_push(input_param);
	ent->fileid = "fileid4";
	ent->count = "4";
	ent = navi_array_push(input_param);
	ent->fileid = "fileid5";
	ent->count = "5";
	ent = navi_array_push(input_param);
	ent->fileid = "fileid6";
	ent->count = "6";
	ent = navi_array_push(input_param);
	ent->fileid = "fileid7";
	ent->count = "7";
	ent = navi_array_push(input_param);
	ent->fileid = "fileid8";
	ent->count = "8";
	ent = navi_array_push(input_param);
	ent->fileid = "fileid9";
	ent->count = "9";
	ent = navi_array_push(input_param);
	ent->fileid = "fileid10";
	ent->count = "10";
	
	playlog_report(redis_session,pool,input_param);
    return NAVI_OK;
}

NAVI_MODULE_METHOD(ntask_test,playlog_update,module,request)
{
	struct sockaddr_in si;
	char ip[20] = "10.10.69.213";
	int s;
	navi_task_t* task = navi_module_get_task(module,"test1");
	if (task == NULL)
		task = navi_module_new_task(module,"test1",((ntask_data_t*)module->module_data)->pool, ntask_cleanup, ntask_empty_notifier);
	if (task == NULL) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "alloc task error");
		return NAVI_OK;
	}

	si.sin_family = AF_INET;
	if ((s = inet_pton(AF_INET,ip, (void *)&si.sin_addr)) <= 0) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "invalid addr");
		return NAVI_OK;
	}
	si.sin_port = htons(6379);
	nvcli_redis_t* redis_session = nvtask_new_redis_session(task,(const struct sockaddr *)&si,playlog_result_proc, playlog_error_proc,200, 100000, 100000);
	if (redis_session == NULL) {
		navi_response_t* resp = navi_request_response_obj(request);
		navi_response_set_desc(resp, -1 , "", "redis connect error");
		return NAVI_OK;
	}
	navi_pool_t * pool = navi_pool_create(4096);
	playlog_lru_get(redis_session,5,pool);
	nvcli_redis_t* redis_session2 = nvtask_new_redis_session(task,(const struct sockaddr *)&si,playlog_result_proc, playlog_error_proc,200, 100000, 100000);
	playlog_lru_update(redis_session2);
    return NAVI_OK;
}


