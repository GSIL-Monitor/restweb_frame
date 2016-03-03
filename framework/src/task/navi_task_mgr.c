/** \brief 
 * navi_task_mgr.c
 *  Created on: 2015-1-14
 *      Author: li.lei
 *  brief: 
 */

#include "navi_task_mgr.h"
#include "navi_task_impl.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <assert.h>

navi_task_mgr_t* g_tasks = NULL;

static void send_wait(navi_task_impl_t*  impl);

static int task_notify_parse(void* ss, const unsigned char* in, size_t sz)
{
	char* task_nm = NULL;
	char* notify_seq = NULL;
	nvcli_redis_t* redis = (nvcli_redis_t*)ss;
	navi_upreq_parse_status_e ret;
	if ( redis->base.input_timer ) {
		navi_timer_cancel(redis->base.input_timer);
		redis->base.input_timer = NULL;
		//if ( redis->base.input_max_interval > 0) {
		//	redis->base.input_timer = navi_timer_add(&redis->base.parent->timer_mgr, NAVI_TIMER_ONCE,
		//		redis->base.input_max_interval, nvcli_resp_timedout, ss, NULL, NULL);
		//}
		nvcli_parent_need_drive(redis->base.parent);
	}
parse:
	ret = nvup_redis_proto_parse_in(&redis->in_parser, (uint8_t*)in, sz);
	switch(ret) {
	case NVUP_PARSE_AGAIN:
		return 0;
	case NVUP_PARSE_DONE:
		
		if ( redis->in_parser.proto_type == redis_type_status_reply) {
			//PONG
			//if ( redis->in_parser.parse_buf.cur_probe == redis->in_parser.parse_buf.cur_last )
			//	return 1;
		}
		else if ( redis->in_parser.proto_type == redis_type_multi_bulk) {
			void* it = navi_array_iter(redis->in_parser.in_bulks);
			redis_bulk_t* bulk;
			while ( (bulk = navi_array_iter_next(it))) {
				if (task_nm==NULL) {
					task_nm = bulk->s;
				}
				else {
					notify_seq = bulk->s;
					break;
				}
			}
			navi_array_iter_destroy(it);
			if (notify_seq) {
				uint32_t v = strtol(notify_seq, NULL, 10);
				navi_task_t* task = navi_task_get_with_fullname(task_nm);
				if ( task && ((navi_task_impl_t*)task)->notify_mon)
					navi_task_notify_arrive((navi_task_impl_t*)task, v);
			}
		}
		redis->in_parser.pending_stage = redis_stage_start;
		if ( redis->in_parser.parse_buf.cur_probe == redis->in_parser.parse_buf.cur_last )
			return 0;
		else {
			in = NULL;
			sz = 0;
			goto parse;
		}
	default:
		return -1;
	}
}

static inline int _task_notify_parse(void* ss, const unsigned char* in, size_t* sz)
{
	size_t t = *sz;
	*sz = 0;
	return task_notify_parse(ss, in, t);
}

static int task_notify_body_parse(void* ss, const unsigned char* content, size_t* size)
{
	return -1;
}

static void task_notify_pipe_cleanup(void* sub)
{
	nvcli_redis_t* redis = (nvcli_redis_t*)sub;
	nvup_redis_proto_clean(&redis->in_parser);
}

static void task_notify_pipe_error(void* cli_parent, void* cli, nvcli_error_e e);

static nvcli_proto_proc_t private_proto = {
	NVCLI_REDIS,
	sizeof(nvcli_redis_t),
	_task_notify_parse,
	task_notify_body_parse,
	task_notify_pipe_cleanup
};


static void cli_do_nothing(void* cli_parent, void* cli)
{

}
static void task_do_nothing(void* parent, nvcli_redis_t* ss, const navi_upreq_result_t* result)
{

}

static navi_grcli_app_proc_t private_app = {
	task_notify_pipe_error,
	cli_do_nothing,
	NULL
};

static int reconn_task_ctrl() {
	//nvcli_clean(&g_tasks->redis_local->base,0);
	//nvredis_cleanup(g_tasks->redis_local);
#if 0
	struct sockaddr_in si;
	char ip[20] = "10.10.69.213";
	int s;

	si.sin_family = AF_INET;
	si.sin_port = htons(6379);
	if ((s = inet_pton(AF_INET,ip, (void *)&si.sin_addr)) <= 0) {
		return;
	}
	g_tasks->redis_local = nvcli_redis_init(&g_tasks->monitor_runner,(const struct sockaddr*)&si
						, task_do_nothing, task_notify_pipe_error, 200, 100000, 100000);
#else

	g_tasks->redis_local = nvcli_redis_init(&g_tasks->monitor_runner,(const struct sockaddr*)&g_tasks->ctrl_addr
							, task_do_nothing, (nvredis_error_proc_fp)task_notify_pipe_error, NULL, 200, 100000, 100000);
#endif
	if(g_tasks->redis_local == NULL || g_tasks->redis_local->base.conn == NULL)
		return 0;

	chain_node_t *nd = g_tasks->watch_list.next;
	while ( nd != &g_tasks->watch_list ) {
		navi_task_impl_t* impl = navi_list_data(nd,navi_task_impl_t, monitor_link);
		nd = nd->next;
		send_wait(impl);
	}
	
	return 1;
}

void navi_task_zombile_clean()
{
    chain_node_t* task_nd = g_tasks->zombile_list.next;
	navi_task_impl_t* impl;
	while ( task_nd != &g_tasks->zombile_list ) {
		impl = navi_list_data(task_nd, navi_task_impl_t, monitor_link);
		task_nd = task_nd->next;
		navi_list_remove(&impl->monitor_link);
        
		navi_pool_destroy(impl->pool);
	} 
}

static void task_notify_pipe_error(void* cli_parent, void* cli, nvcli_error_e e)
{
	if (&g_tasks->redis_local->base != cli)
		return;
	//nvcli_clean(&g_tasks->redis_local->base);
	nvredis_cleanup(g_tasks->redis_local);
	g_tasks->redis_local = NULL;
}
static void task_notify_pipe_ping(void* parent, void* timer_arg)
{
	int rc;
	if (g_tasks) {
		if (g_tasks->redis_local == NULL) {
			if ((rc = reconn_task_ctrl()) != 1)
				return;
		}

		char *ping_cmd = "*1\r\n$4\r\nPING\r\n";
		nvcli_send_body(&g_tasks->redis_local->base,ping_cmd,strlen(ping_cmd), true);
		nvacnn_set_reading(g_tasks->redis_local->base.conn, task_notify_parse);

        //clean zombile task
        navi_task_zombile_clean();
	}
}

void navi_task_mgr_init(const struct sockaddr_un* ctrl_redis)
{
	if (!g_tasks) {
		g_tasks  = (navi_task_mgr_t*)calloc(1,sizeof(navi_task_mgr_t));
	}

	g_tasks->all_tasks = navi_hash_init_with_heap();
	memcpy(&g_tasks->ctrl_addr, ctrl_redis, sizeof(struct sockaddr_un));

	g_tasks->monitor_pool = navi_pool_create(4096);
	nvcli_parent_init(&g_tasks->monitor_runner, g_tasks->monitor_pool, g_tasks, NULL);
	navi_list_init(&g_tasks->watch_list);
    navi_list_init(&g_tasks->zombile_list);
	typedef void (*nvredis_result_proc_fp)(void* parent, nvcli_redis_t* ss, const navi_upreq_result_t* result);
	typedef void (*nvredis_error_proc_fp)(void* parent, nvcli_redis_t* ss, nvcli_error_e e);

	//g_tasks->redis_local = nvcli_redis_init(&g_tasks->monitor_runner,(const struct sockaddr*)&g_tasks->ctrl_addr
	//	, task_do_nothing, (nvredis_error_proc_fp)task_notify_pipe_error, NULL, 200, 100000, 100000);

	//g_tasks->redis_local =  nvcli_init(&g_tasks->monitor_runner, &private_proto, &private_app,
	//	200, 100000, 100000, (const struct sockaddr*)&g_tasks->ctrl_addr);

	//g_tasks->ping_timer = nvcli_parent_add_timer(&g_tasks->monitor_runner,1000, NAVI_TIMER_INTERVAL, NULL,
	//	task_notify_pipe_ping, NULL);

	//assert(g_tasks->redis_local);
}

void navi_task_mgr_clean()
{
	if ( g_tasks->all_tasks == NULL)
		return;

	void* it = navi_hash_iter(g_tasks->all_tasks);
	navi_hent_t* hent;
	while ( (hent = navi_hash_iter_next(it))) {
		nvtask_close((navi_task_t*)hent->v);
	}
	navi_hash_iter_destroy(it);

	navi_hash_destroy(g_tasks->all_tasks);
	g_tasks->all_tasks = NULL;

	nvcli_parent_cleanup(&g_tasks->monitor_runner);

    navi_task_zombile_clean();

	free(g_tasks);
	g_tasks=NULL;
}

navi_task_t* navi_task_get_with_fullname(const char* task_fullname)
{
	if ( g_tasks == NULL || g_tasks->all_tasks == NULL)
		return NULL;
	return (navi_task_t*)navi_hash_get_gr(g_tasks->all_tasks, task_fullname);
}

int navi_task_regist(navi_task_t* task)
{
	if ( g_tasks == NULL)
		return -1;

	navi_hash_set_gr(g_tasks->all_tasks, nvtask_full_name(task), task);
	return 0;
}

void navi_task_unregist(navi_task_t* task)
{
	if ( g_tasks == NULL)
		return;
    navi_task_impl_t* impl = (navi_task_impl_t*)task;
	navi_hash_del(g_tasks->all_tasks, impl->full_name);
    navi_list_insert_tail(&g_tasks->zombile_list, &impl->monitor_link);
}

void navi_task_monitor_notify(navi_task_t* task)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	impl->notify_mon = 1;
	navi_list_insert_head(&g_tasks->watch_list, &impl->monitor_link);
	send_wait(impl);
}

static void send_wait(navi_task_impl_t*  impl)
{
	char buf[1024]={0};
	char *p = buf;
	const char* full_name = impl->full_name;
	char value[40];
	snprintf(value, sizeof(value), "%010u", impl->monitor_seq);

	size_t sz = snprintf(p, sizeof(buf), "*3\r\n$8\r\nwait_ext\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
		strlen(full_name), full_name, strlen(value), value);
	if (sz > sizeof(buf)){
		p = (char*)malloc(sz+1);
		sprintf(p, "*3\r\n$8\r\nwait_ext\r\n$%d\r\n%s\r\n$%d\r\n%s\r\n",
			strlen(full_name), full_name, strlen(value), value);
	}

	nvcli_send_body(&g_tasks->redis_local->base,buf,sz, false);
	nvacnn_set_reading(g_tasks->redis_local->base.conn, task_notify_parse);
	if (p != buf){
		free(p);
	}
}

static void send_wait_cancel(navi_task_impl_t* impl)
{
	char buf[1024]={0};
	char *p = buf;
	const char* full_name = impl->full_name;

	size_t sz = snprintf(p, sizeof(buf), "*2\r\n$11\r\nwait_cancel\r\n$%d\r\n%s\r\n",
		strlen(full_name), full_name);
	if (sz > sizeof(buf)){
		p = (char*)malloc(sz+1);
		sprintf(p, "*2\r\n$11\r\nwait_cancel\r\n$%d\r\n%s\r\n",
			strlen(full_name), full_name);
	}

	nvcli_send_body(&g_tasks->redis_local->base,buf,sz, false);
	nvacnn_set_reading(g_tasks->redis_local->base.conn, task_notify_parse);
	if (p != buf){
		free(p);
	}
}

void navi_task_quit_monitor(navi_task_t* task)
{
	navi_task_impl_t* impl = (navi_task_impl_t*)task;
	impl->notify_mon = 0;
	navi_list_remove(&impl->monitor_link);
	send_wait_cancel(impl);
}
