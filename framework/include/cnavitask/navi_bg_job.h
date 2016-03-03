/** \brief 
 * navi_bg_job.h
 *  Created on: 2015-1-23
 *      Author: li.lei
 *  brief: 后台独立JOB处理线程。
 */

#ifndef NAVI_BG_JOB_H_
#define NAVI_BG_JOB_H_

#include "nvcli_common.h"
#include <pthread.h>
#include "navi_task.h"

typedef struct _navi_bgjob_t
{
	char* full_name; //<! 发起该job的task的全名
	char* name;
	void* job_start_data;
	pthread_t tid;
	chain_node_t link;
	chain_node_t task_link;
	char* error_desc;

	void (*job_startup_handler)(struct _navi_bgjob_t*,void*);
	void (*job_cleanup_handler)(struct _navi_bgjob_t*,void*);

	void (*job_stream_handler)(struct _navi_bgjob_t*, void*, size_t);

	void (*job_complete_handler)(navi_task_t* task, struct _navi_bgjob_t*,void*);
	void (*job_error_handler)(navi_task_t* task, struct _navi_bgjob_t*, void*, const char*);

	pthread_mutex_t status_lk;

	navi_task_t* _main;

	int input_stream:1;
	int input_done:1;

	int regist:1;
	int run:1;
	int complete:1;
	int error:1;
	int closed:1;
	int reaping:1;
} navi_bgjob_t;

typedef void (*navi_bgjob_stream_data_clean_fp)(void* stream_data,size_t sz);

typedef struct _navi_bgjob_stream_t
{
	navi_bgjob_t* job;
	void* stream_data;
	size_t size;
	navi_bgjob_stream_data_clean_fp stream_data_clean;
	chain_node_t link;
} navi_bgjob_stream_t;

typedef void (*navi_bgjob_cleanup_handler_fp)(struct _navi_bgjob_t* job, void* job_data);
typedef void (*navi_bgjob_startup_handler_fp)(navi_bgjob_t* job, void* job_data);
typedef void (*navi_bgjob_stream_handler_fp)(navi_bgjob_t* job, void* stream, size_t sz);
typedef void (*navi_bgjob_complete_fp)(navi_task_t* task, struct _navi_bgjob_t* job, void* job_data);
typedef void (*navi_bgjob_error_fp)(navi_task_t* task, struct _navi_bgjob_t* job, void* job_data, const char* err);

typedef struct _navi_bgjob_worker_t
{
	pthread_mutex_t status_mutex;
	pthread_cond_t status_cond;
	pthread_t tid;

	pthread_mutex_t queue_lock;
	pthread_cond_t queue_cond;
	chain_node_t job_stream_queue; //<!对stream job有效，navi_bgjob_stream_t链表
	chain_node_t job_cancel_queue; //<!对stream job有效，取消某个job。navi_bgjob_stream_t链表
	chain_node_t reg_jobs; //<! navi_bgjob_t链表

	pthread_mutex_t end_lock;
	chain_node_t end_jobs; //<! navi_bgjob_t链表

	navi_hash_t* stream_running;
	int run:1;
	int stop:1;
} navi_bgjob_worker_t;

typedef struct _navi_bgjob_queue_t
{
	int worker_limit;
	pthread_t main_tid;
	chain_node_t completes;
	navi_hash_t* all_jobs;
	navi_bgjob_worker_t *workers;
} navi_bgjob_queue_t;

//必须在nginx worker进程主线程中发起
navi_bgjob_t* navi_bgjob_create(navi_task_t* task, const char* job_name, void* job_start_data,
	navi_bgjob_startup_handler_fp startup,
	navi_bgjob_cleanup_handler_fp cleanup,
	navi_bgjob_complete_fp complete_notifier,
	navi_bgjob_error_fp error_notifier);

navi_bgjob_t* navi_streamed_bgjob_create(navi_task_t* task, const char* job_name, void* job_start_data,
	navi_bgjob_startup_handler_fp startup,
	navi_bgjob_cleanup_handler_fp cleanup,
	navi_bgjob_stream_handler_fp stream_proc,
	navi_bgjob_complete_fp complete_notifier,
	navi_bgjob_error_fp error_notifier);

void navi_bgjob_close(navi_task_t* task, navi_bgjob_t* job);

bool navi_streamed_bgjob_push(navi_bgjob_t* job, void* stream, size_t sz,navi_bgjob_stream_data_clean_fp clean);
bool navi_streamed_bgjob_input_done(navi_bgjob_t* job);
void navi_streamed_bgjob_cancel(navi_bgjob_t* job);

void navi_bgjob_failed(navi_bgjob_t* job, const char* err, ...);
void navi_bgjob_complete(navi_bgjob_t* job);

navi_task_t* navi_bgjob_get_task(navi_bgjob_t* job);

void navi_bgjob_workers_startup(int worker_cnt);
void navi_bgjob_workers_close();
void navi_bgjob_reap_jobs();

#endif /* NAVI_BG_JOB_H_ */
