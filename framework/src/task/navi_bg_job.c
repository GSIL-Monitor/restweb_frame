/** \brief 
 * navi_bg_job.c
 *  Created on: 2015-1-26
 *      Author: li.lei
 *  brief: 
 */

#include "navi_bg_job.h"
#include <assert.h>
#include "navi_task_impl.h"
#include "navi_task_mgr.h"

static pthread_once_t thr_spec_once = PTHREAD_ONCE_INIT;
static pthread_key_t thr_spec_worker;
static navi_bgjob_queue_t *s_job_queue = NULL;

static void bgjob_worker_key_once(void)
{
	pthread_key_create(&thr_spec_worker,NULL);
}
static  size_t
hash_string(const char* __s)
{
  unsigned long __h = 0;
  for ( ; *__s; ++__s)
    __h = 5*__h + *__s;
  return (size_t)(__h);
}

static void cleanup_job_reg(navi_bgjob_t* job)
{
	navi_list_remove(&job->link);
	navi_list_remove(&job->task_link);
	if(job->full_name)free(job->full_name);
	if(job->job_cleanup_handler) {
		job->job_cleanup_handler(job, job->job_start_data);
		job->job_cleanup_handler = NULL;
	}
	free(job);
}

navi_bgjob_t* navi_bgjob_create(navi_task_t* task, const char* job_name, void* job_start_data,
	navi_bgjob_startup_handler_fp startup,
	navi_bgjob_cleanup_handler_fp cleanup,
	navi_bgjob_complete_fp complete_notifier,
	navi_bgjob_error_fp error_notifier)
{
	if ( 0 == pthread_equal(s_job_queue->main_tid,pthread_self()))
		return NULL;

	if (!task || !job_name || !startup || !complete_notifier || !error_notifier ) {
		return NULL;
	}

	char buf[1024];
	off_t off = snprintf(buf,sizeof(buf),"%s::%s", nvtask_full_name(task), job_name);
	char *p = buf;
	if ( off >= sizeof(buf) ) {
		p = (char*)malloc(off+1);
		sprintf(p,"%s::%s", nvtask_full_name(task), job_name);
	}
	else {
		p = strdup(buf);
	}

	if ( navi_hash_get_gr(s_job_queue->all_jobs, p) ) {
		free(p);
		return NULL;
	}

	navi_bgjob_t* job = (navi_bgjob_t*)calloc(1,sizeof(navi_bgjob_t));
	navi_list_init(&job->link);
	navi_list_init(&job->task_link);
	job->full_name = p;
	job->name = p + strlen(p) - strlen(job_name);
	job->job_start_data = job_start_data;
	job->job_startup_handler = startup;
	job->job_cleanup_handler = cleanup;
	job->job_complete_handler = complete_notifier;
	job->job_error_handler = error_notifier;

	job->_main = task;

	pthread_mutex_init(&job->status_lk,NULL);

	navi_task_impl_t* task_impl = (navi_task_impl_t*)task;
	navi_list_insert_tail(&task_impl->bg_jobs, &job->task_link);

	navi_bgjob_worker_t* worker = s_job_queue->workers + hash_string(p)%s_job_queue->worker_limit;
	pthread_mutex_lock(&worker->queue_lock);
	navi_list_insert_tail(&worker->reg_jobs, &job->link);
	pthread_mutex_unlock(&worker->queue_lock);
	pthread_cond_signal(&worker->queue_cond);
	return job;
}

navi_bgjob_t* navi_streamed_bgjob_create(navi_task_t* task, const char* job_name, void* job_start_data,
	navi_bgjob_startup_handler_fp startup,
	navi_bgjob_cleanup_handler_fp cleanup,
	navi_bgjob_stream_handler_fp stream_proc,
	navi_bgjob_complete_fp complete_notifier,
	navi_bgjob_error_fp error_notifier)
{
	if ( 0 == pthread_equal(s_job_queue->main_tid,pthread_self()))
		return NULL;

	if (!task || !job_name || !complete_notifier
		|| !stream_proc || !error_notifier ) {
		return NULL;
	}

	char buf[1024];
	off_t off = snprintf(buf,sizeof(buf),"%s::%s", nvtask_full_name(task), job_name);
	char *p = buf;
	if ( off >= sizeof(buf) ) {
		p = (char*)malloc(off+1);
		sprintf(p,"%s::%s", nvtask_full_name(task), job_name);
	}
	else {
		p = strdup(buf);
	}

	if ( navi_hash_get_gr(s_job_queue->all_jobs, p) ) {
		free(p);
		return NULL;
	}

	navi_bgjob_t* job = (navi_bgjob_t*)calloc(1,sizeof(navi_bgjob_t));
	navi_list_init(&job->link);
	navi_list_init(&job->task_link);
	job->full_name = p;
	job->name = p + strlen(p) - strlen(job_name);
	job->job_start_data = job_start_data;
	job->job_startup_handler = startup;
	job->job_stream_handler = stream_proc;
	job->job_cleanup_handler = cleanup;
	job->job_complete_handler = complete_notifier;
	job->job_error_handler = error_notifier;
	job->input_stream  = 1;

	job->_main = task;

	pthread_mutex_init(&job->status_lk,NULL);

	navi_task_impl_t* task_impl = (navi_task_impl_t*)task;
	navi_list_insert_tail(&task_impl->bg_jobs, &job->task_link);

	navi_bgjob_worker_t* worker = s_job_queue->workers + hash_string(p)%s_job_queue->worker_limit ;

	pthread_mutex_lock(&worker->queue_lock);
	navi_list_insert_tail(&worker->reg_jobs, &job->link);
	pthread_mutex_unlock(&worker->queue_lock);
	pthread_cond_signal(&worker->queue_cond);
	return job;
}

static void streamed_bgjob_cancel(navi_bgjob_t *job)
{
	bool complete = false;
	pthread_mutex_lock(&job->status_lk);
	complete = job->complete;
	pthread_mutex_unlock(&job->status_lk);

	if ( complete )
		return ;

	navi_bgjob_worker_t* worker = s_job_queue->
		workers + hash_string(job->full_name)%s_job_queue->worker_limit;

	navi_bgjob_stream_t* se = (navi_bgjob_stream_t*)calloc(1,sizeof(navi_bgjob_stream_t));
	se->job = job;
	navi_list_init(&se->link);

	pthread_mutex_lock(&worker->queue_lock);
	navi_list_insert_tail(&worker->job_cancel_queue,&se->link);
	pthread_mutex_unlock(&worker->queue_lock);
}

void navi_bgjob_close(navi_task_t* task, navi_bgjob_t* job)
{
	if ( 0 == pthread_equal(s_job_queue->main_tid,pthread_self()))
		return ;

	if ( !task || !job || !job->full_name)
		return;

	navi_bgjob_t* run_job = NULL;

	if ( NULL == (run_job=navi_hash_get_gr(s_job_queue->all_jobs, job->full_name)) ) {
		return;
	}

	if ( run_job != job)
		return;

	bool complete = false;

	pthread_mutex_lock(&job->status_lk);
	job->closed = 1;
	complete = job->complete;
	pthread_mutex_unlock(&job->status_lk);

	navi_list_remove(&job->task_link);
	job->_main  = NULL;

	navi_hash_del(s_job_queue->all_jobs, job->full_name);
	if ( !complete ) {
		streamed_bgjob_cancel(job);
	}
	else {
		cleanup_job_reg(job);
	}
}

bool navi_streamed_bgjob_push(navi_bgjob_t* job, void* stream, size_t sz,navi_bgjob_stream_data_clean_fp clean)
{
	if ( 0 == pthread_equal(s_job_queue->main_tid,pthread_self()))
		return false;

	if ( !job || !job->full_name || (!stream && !sz) )
		return false;

	navi_bgjob_t* run_job = navi_hash_get_gr(s_job_queue->all_jobs, job->full_name);
	if (!run_job || job != run_job)
		return false;

	bool complete = false;
	pthread_mutex_lock(&job->status_lk);
	complete = job->complete;
	pthread_mutex_unlock(&job->status_lk);

	if ( complete )
		return false;

	navi_bgjob_worker_t* worker = s_job_queue->
		workers + hash_string(job->full_name)%s_job_queue->worker_limit;

	navi_bgjob_stream_t* se = (navi_bgjob_stream_t*)calloc(1,sizeof(navi_bgjob_stream_t));
	se->job = job;
	se->stream_data = stream;
	se->size= sz;
	se->stream_data_clean = clean;
	navi_list_init(&se->link);

	pthread_mutex_lock(&worker->queue_lock);
	navi_list_insert_tail(&worker->job_stream_queue,&se->link);
	pthread_mutex_unlock(&worker->queue_lock);
	return true;
}

bool navi_streamed_bgjob_input_done(navi_bgjob_t* job)
{
	return navi_streamed_bgjob_push(job, NULL, 0, NULL);
}

void navi_streamed_bgjob_cancel(navi_bgjob_t* job)
{
	if ( 0 == pthread_equal(s_job_queue->main_tid,pthread_self()))
		return ;

	if ( !job || !job->full_name )
		return ;

	navi_bgjob_t* run_job = navi_hash_get_gr(s_job_queue->all_jobs, job->full_name);
	if (!run_job || job != run_job)
		return ;

	streamed_bgjob_cancel(job);
}

void navi_bgjob_failed(navi_bgjob_t* job, const char* err, ...)
{
	if (0 == pthread_equal(job->tid,pthread_self())) {
		return;
	}

	navi_bgjob_worker_t* worker = (navi_bgjob_worker_t*)
		pthread_getspecific(thr_spec_worker);

	if ( job->input_stream ) {
		navi_hash_del(worker->stream_running, job->full_name);
		job->input_done = 1;
	}

	char buf[1024];
	char *p = buf;
	va_list vl;
	va_start(vl,err);
	off_t off = vsnprintf(buf,sizeof(buf), err,vl);
	if ( off >= sizeof(buf) ) {
		p = (char*)malloc(off+1);
		vsprintf(p, err,vl);
	}
	va_end(vl);

	if ( p == buf ) {
		p = strdup(buf);
	}

	job->error_desc = p;

	pthread_mutex_lock(&job->status_lk);
	job->complete = 1;
	job->error = 1;
	if ( job->closed ) {
		cleanup_job_reg(job);
		pthread_mutex_unlock(&job->status_lk);
		return;
	}
	pthread_mutex_unlock(&job->status_lk);

	pthread_mutex_lock(&worker->end_lock);
	navi_list_insert_tail(&worker->end_jobs, &job->link);
	pthread_mutex_unlock(&worker->end_lock);
}

void navi_bgjob_complete(navi_bgjob_t* job)
{
	if (0 == pthread_equal(job->tid,pthread_self())) {
		return;
	}

	navi_bgjob_worker_t* worker = (navi_bgjob_worker_t*)
		pthread_getspecific(thr_spec_worker);

	if ( job->input_stream ) {
		navi_hash_del(worker->stream_running, job->full_name);
		job->input_done = 1;
	}

	pthread_mutex_lock(&job->status_lk);
	job->complete = 1;
	if ( job->closed ) {
		cleanup_job_reg(job);
		pthread_mutex_unlock(&job->status_lk);
		return;
	}
	pthread_mutex_unlock(&job->status_lk);

	pthread_mutex_lock(&worker->end_lock);
	navi_list_insert_tail(&worker->end_jobs, &job->link);
	pthread_mutex_unlock(&worker->end_lock);
}

static void cleanup_job_stream_qe(navi_bgjob_stream_t* stream)
{
	navi_list_remove(&stream->link);
	if (stream->stream_data_clean && stream->stream_data)
		stream->stream_data_clean(stream->stream_data, stream->size);
	free(stream);
}

static void* worker_run(void* wk)
{
	navi_bgjob_worker_t* worker = (navi_bgjob_worker_t*)wk;
	pthread_mutex_lock(&worker->status_mutex);
	worker->tid = pthread_self();
	worker->run = 1;
	pthread_setspecific(thr_spec_worker, worker);
	pthread_cond_signal(&worker->status_cond);
	pthread_mutex_unlock(&worker->status_mutex);

	while (true) {
		chain_node_t reg_list;
		chain_node_t stream_list;
		chain_node_t cancel_list;
		bool wait  = true;
		bool stop = false;
        navi_list_init(&reg_list);
        navi_list_init(&stream_list);
        navi_list_init(&cancel_list);
		pthread_mutex_lock(&worker->status_mutex);
		stop = worker->stop;
		pthread_mutex_unlock(&worker->status_mutex);

		pthread_mutex_lock(&worker->queue_lock);
		if ( !navi_list_empty(&worker->reg_jobs) ) {
			navi_list_give(&worker->reg_jobs,&reg_list);
			wait = false;
		}
		if ( !navi_list_empty(&worker->job_stream_queue)) {
			navi_list_give(&worker->job_stream_queue,&stream_list);
			wait = false;
		}
		if ( !navi_list_empty(&worker->job_cancel_queue)) {
			navi_list_give(&worker->job_cancel_queue,&cancel_list);
			wait = false;
		}

		if (wait) {
			if (!stop) {
				pthread_cond_wait(&worker->queue_cond,&worker->queue_lock);
				pthread_mutex_unlock(&worker->queue_lock);
			}
			else {
				pthread_mutex_unlock(&worker->queue_lock);
				break;
			}
		}
		else if (stop ) {
			pthread_mutex_unlock(&worker->queue_lock);
			chain_node_t* nd = reg_list.next;
			navi_bgjob_stream_t* stnd;
			navi_bgjob_t* job;

			while ( nd != &reg_list ) {
				job = navi_list_data(nd,navi_bgjob_t,link);
				nd = nd->next;
				cleanup_job_reg(job);
			}

			nd = stream_list.next;
			while ( nd != &stream_list) {
				stnd = navi_list_data(nd,navi_bgjob_stream_t,link);
				nd = nd->next;
				cleanup_job_stream_qe(stnd);
			}

			nd = cancel_list.next;
			while ( nd != &cancel_list) {
				stnd = navi_list_data(nd,navi_bgjob_stream_t,link);
				nd = nd->next;
				cleanup_job_stream_qe(stnd);
			}

			void* it = navi_hash_iter(worker->stream_running);
			navi_hent_t* he ;
			while ( (he = navi_hash_iter_next(it))) {
				navi_bgjob_failed((navi_bgjob_t*)he->v, "canceled on exit");
			}
			navi_hash_iter_destroy(worker->stream_running);

			navi_hash_destroy(worker->stream_running);
			worker->stream_running = NULL;
		}
		else {
			pthread_mutex_unlock(&worker->queue_lock);

			chain_node_t *nd = stream_list.next;
			navi_bgjob_stream_t* se;
			navi_bgjob_t* run_job;
			while ( nd != &stream_list ) {
				se = navi_list_data(nd, navi_bgjob_stream_t,link);
				nd = nd->next;

				run_job = navi_hash_get_gr(worker->stream_running,se->job->full_name);
				if ( run_job && se->job == run_job && !run_job->input_done) {
					assert(run_job->run && run_job->input_stream);
					if (se->stream_data == NULL) {
						run_job->input_done = 1;
						navi_bgjob_complete(run_job);
					}
					else {
						run_job->job_stream_handler(run_job, se->stream_data, se->size);
						se->stream_data_clean(se->stream_data,se->size);
						se->stream_data_clean = NULL;
					}
					cleanup_job_stream_qe(se);
				}
			}

			nd = reg_list.next;
			navi_bgjob_t* reg_job;
			while ( nd != &reg_list ) {
				reg_job = navi_list_data(nd,navi_bgjob_t,link);
				nd = nd->next;
				navi_hash_set_gr(worker->stream_running,reg_job->full_name, reg_job);
				reg_job->regist = 1;
				reg_job->tid = pthread_self();
			}

			nd = cancel_list.next;

			while ( nd != &cancel_list) {
				se = navi_list_data(nd, navi_bgjob_stream_t,link);
				nd = nd->next;

				run_job = se->job;
				if ( run_job ) {
					navi_hash_del(worker->stream_running, run_job->full_name);
					if (se->job->regist && !se->job->run) {
						navi_list_remove(&se->job->link);
						cleanup_job_reg(se->job); //
					}
					else if (se->job->run) {
						if ( se->job->input_done) {
							navi_bgjob_complete(se->job);
						}
						else
							navi_bgjob_failed(se->job, "job canceled");
					}
				}

				cleanup_job_stream_qe(se);
			}

			nd = reg_list.next;
			while ( nd != &reg_list) {
				reg_job = navi_list_data(nd,navi_bgjob_t,link);
				nd = nd->next;

				if (reg_job->input_stream) {
					navi_hash_set_gr(worker->stream_running, reg_job->full_name, reg_job);
				}
				reg_job->run = 1;
				if ( reg_job->job_startup_handler) {
					reg_job->job_startup_handler(reg_job,reg_job->job_start_data);
				}
				if ( !reg_job->input_stream ) {
					navi_bgjob_complete(reg_job);
				}
			}

			nd = stream_list.next;
			while ( nd != &stream_list ) {
				se = navi_list_data(nd, navi_bgjob_stream_t,link);
				nd = nd->next;

				run_job = navi_hash_get_gr(worker->stream_running,se->job->full_name);
				if ( run_job && se->job == run_job && !run_job->input_done) {
					assert(run_job->run && run_job->input_stream);
					if (se->stream_data == NULL) {
						run_job->input_done = 1;
						navi_bgjob_complete(run_job);
					}
					else {
						run_job->job_stream_handler(run_job, se->stream_data, se->size);
						se->stream_data_clean(se->stream_data,se->size);
						se->stream_data_clean = NULL;
					}
				}
				cleanup_job_stream_qe(se);
			}
		}

		if (stop)
			break;
	}

	return NULL;
}

static void navi_bgjob_worker_start(navi_bgjob_worker_t* worker)
{
	pthread_mutex_init(&worker->status_mutex,NULL);
	pthread_cond_init(&worker->status_cond, NULL);
	pthread_mutex_init(&worker->queue_lock,NULL);
	pthread_cond_init(&worker->queue_cond,NULL);
	pthread_mutex_init(&worker->end_lock,NULL);
	pthread_once(&thr_spec_once,bgjob_worker_key_once);

	worker->stream_running = navi_hash_init_with_heap();
	navi_list_init(&worker->job_stream_queue);
	navi_list_init(&worker->job_cancel_queue);
	navi_list_init(&worker->reg_jobs);
	navi_list_init(&worker->end_jobs);

	pthread_create(&worker->tid, NULL, worker_run, worker);

	pthread_mutex_lock(&worker->status_mutex);
	while( !worker->run ) {
		pthread_cond_wait(&worker->status_cond, &worker->status_mutex);
	}
	pthread_mutex_unlock(&worker->status_mutex);
}

void navi_bgjob_workers_startup(int worker_cnt)
{
	if (worker_cnt <= 0)
		return;
	if (s_job_queue)
		return;
	s_job_queue = (navi_bgjob_queue_t*)calloc(1,sizeof(navi_bgjob_queue_t));
	s_job_queue->main_tid = pthread_self();
	if (worker_cnt >= 256)
		worker_cnt = 256;

	s_job_queue->worker_limit = worker_cnt;

	navi_list_init(&s_job_queue->completes);

	s_job_queue->workers = (navi_bgjob_worker_t*)calloc(s_job_queue->worker_limit,
		sizeof(navi_bgjob_worker_t));

	s_job_queue->all_jobs = navi_hash_init_with_heap();

	int i=0;
	for( i=0; i< s_job_queue->worker_limit; i++) {
		navi_bgjob_worker_start(s_job_queue->workers + i);
	}
}

void navi_bgjob_workers_close()
{
	if ( 0 == pthread_equal(s_job_queue->main_tid, pthread_self()))
		return;

	int i;
	for (i=0; i<s_job_queue->worker_limit; i++) {
		navi_bgjob_worker_t* worker = s_job_queue->workers + i;
		pthread_mutex_lock(&worker->status_mutex);
		worker->stop = 1;
		pthread_mutex_unlock(&worker->status_mutex);
		pthread_cond_signal(&worker->queue_cond);
	}

	for (i=0; i<s_job_queue->worker_limit; i++) {
		navi_bgjob_worker_t* worker = s_job_queue->workers + i;
		pthread_join(worker->tid, NULL);
		free(worker);
	}
}

void navi_bgjob_reap_jobs()
{
	if ( 0 == pthread_equal(s_job_queue->main_tid, pthread_self()))
		return;

	int i;

	for (i=0; i<s_job_queue->worker_limit; i++) {
		navi_bgjob_worker_t* worker = s_job_queue->workers + i;
		pthread_mutex_lock(&worker->end_lock);
		navi_list_give(&worker->end_jobs, &s_job_queue->completes);
		pthread_mutex_unlock(&worker->end_lock);
	}

	navi_task_t* task = NULL;
	navi_task_impl_t* task_impl;
	chain_node_t* nd = &s_job_queue->completes;
	navi_bgjob_t* job = NULL;
	while ( nd != &s_job_queue->completes ) {
		job =  navi_list_data(nd,navi_bgjob_t,link);
		nd = nd->next;
		job->reaping = 1;
		if (job->closed) {
			cleanup_job_reg(job);
		}
		else {
			task = navi_bgjob_get_task(job);
			if ( ! task ) {
				cleanup_job_reg(job);
			}
			else {
				task_impl = (navi_task_impl_t*)task;
				if ( job->error ) {
					if ( job->job_error_handler) {
						job->job_error_handler(task, job, job->job_start_data, job->error_desc);
					}
				}
				else if ( job->job_complete_handler ) {
					job->job_complete_handler(task, job, job->job_start_data);
				}
				nvcli_parent_check_idle(&task_impl->remote_sessions);
			}
		}
	}
}

navi_task_t* navi_bgjob_get_task(navi_bgjob_t* job)
{
	if ( 0 == pthread_equal(s_job_queue->main_tid, pthread_self())) {
		return NULL;
	}

	if ( navi_list_empty(&job->task_link) ) {
		return NULL;
	}
	else {
		return job->_main;
	}
}
