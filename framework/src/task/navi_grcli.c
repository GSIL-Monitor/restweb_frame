/** \brief 
 * navi_grcli.c
 *  Created on: 2015-1-15
 *      Author: li.lei
 *  brief: 
 */

#include "navi_grcli.h"
#include <assert.h>

void nvcli_parent_need_drive(nvcli_parent_t* parent);
static void nvcli_resp_timedout(void* parent, void* ss);

static int nvcli_parse_in(void* cli, const unsigned char* content, size_t size)
{
	navi_grcli_t* ss = (navi_grcli_t*)cli;
	int ret;
	size_t body_off = 0;

	if ( ss->input_timer ) {
		nvcli_parent_cancel_timer(ss->parent, ss->input_timer);
		ss->input_timer = NULL;
		if (ss->input_max_interval > 0) {
			 ss->input_timer = nvcli_parent_add_timer(ss->parent, ss->input_max_interval, NAVI_TIMER_ONCE, cli,
				nvcli_resp_timedout, NULL);
		}

		/***
		navi_timer_cancel(ss->input_timer);
		ss->input_timer = NULL;
		if ( ss->input_max_interval > 0) {
			ss->input_timer = navi_timer_add(&ss->parent->timer_mgr, NAVI_TIMER_ONCE,
				ss->input_max_interval, nvcli_resp_timedout, cli, NULL, NULL);
		}
		nvcli_parent_need_drive(ss->parent);*/
	}

	if ( !ss->iheader_done) {
		body_off = size;
		ret = ss->proto_procs->iheader_parser(cli, content, &body_off);
		switch ( ret ) {
		case 1:
			if ( body_off == size ) {
				ss->iheader_done = 1;
				ss->input_done = 1;
				if ( ss->output_done ) {
					ss->app_procs.session_complete_handler(ss->parent->parent,ss);
					nvcli_clean(ss);
				}
				return 1;
			}
			else {
				return -1;
			}
		case 2:
			ss->iheader_done = 1;
			break;
		default:
			break;
		}
	}

	if ( ss->iheader_done ) {
		size_t cur_sz = size - body_off;
		ret = ss->proto_procs->ibody_parser(cli, content + body_off, &cur_sz);
		if ( ret == 1) {
			ss->input_done = 1;
			if ( cur_sz != size - body_off )
				return -1;
			else {
				if (ss->output_done) {
					ss->app_procs.session_complete_handler(ss->parent->parent,ss);
					nvcli_clean(ss);
				}
				return 1;
			}
		}
	}

	return ret;
}

static void nvcli_error_handler(void* cli, nvcli_error_e e)
{
	navi_grcli_t* ss = (navi_grcli_t*)cli;
	if ( ss->app_procs.session_error_handler) {
		ss->app_procs.session_error_handler(ss->parent->parent, cli, e);
	}
	nvcli_clean(ss);
	
	return;
}

static int nvcli_output_goon(void* cli)
{
	navi_grcli_t* ss = (navi_grcli_t*)cli;
	if ( ss->output_timer ) {
		nvcli_parent_cancel_timer(ss->parent, ss->output_timer);
		//navi_timer_cancel(ss->output_timer);
		ss->output_timer = NULL;
	}
	if ( ss->app_procs.obody_goon_handler ) {
		int ret = ss->app_procs.obody_goon_handler(ss->parent->parent, cli);

		if ( ret == 1) {
			ss->output_done = 1;
			if (ss->input_done) {
				ss->app_procs.session_complete_handler(ss->parent->parent,ss);
			}
		}
		return ret;
	}
	else {
		ss->output_done = 1;
		if (ss->input_done) {
			ss->app_procs.session_complete_handler(ss->parent->parent,ss);
		}
		return 1;
	}
}

static void* get_recycle_cli(nvcli_parent_t* parent, nvcli_proto_e proto)
{
	if ( proto >= NVCLI_DUMMY )
		return NULL;

	chain_node_t* lst = &parent->client_pool[proto];

	if ( navi_list_empty(lst) ) {
		return NULL;
	}

	chain_node_t* nd = navi_list_head(lst);
	navi_list_remove(nd);

	navi_grcli_t* cli = navi_list_data(nd, navi_grcli_t, parent_link);
	cli->recycled = 0;
	return (void*)cli;
}

static void nvcli_resp_timedout(void* parent, void* ss)
{
	navi_grcli_t* cli = (navi_grcli_t*)ss;
	nvcli_error_handler(cli, NVCLI_RESP_TIMEDOUT);
	return;
}

static void nvcli_output_timedout(void* parent, void* ss)
{
	navi_grcli_t* cli = (navi_grcli_t*)ss;
	nvcli_error_handler(cli, NVCLI_SEND_TIMEDOUT);
	return;
}

/***
static int nvcli_resp_timedout(void* ss)
{
	navi_grcli_t* cli = (navi_grcli_t*)ss;
	nvcli_error_handler(cli, NVCLI_RESP_TIMEDOUT);
	return 0;
}

static int nvcli_output_timedout(void* ss)
{
	navi_grcli_t* cli = (navi_grcli_t*)ss;
	nvcli_error_handler(cli, NVCLI_SEND_TIMEDOUT);
	return 0;
}***/

static void nvcli_unbind_conn(void* app)
{
	navi_grcli_t* cli = (navi_grcli_t*)app;
	cli->conn = NULL;
}

void nvcli_bind_new_conn(navi_grcli_t *cli,const struct sockaddr* peer,int conn_timeout)
{
	if (cli->conn != NULL)
		nvacnn_close(cli->conn);

	navi_aconn_t* conn = nvacnn_get_conn(peer, cli, nvcli_unbind_conn, conn_timeout);

	conn->pool = cli->private_pool;
	cli->conn = conn;
	conn->app_reading_status = 0x01;//default monitor read event
	conn->app_error_handler = nvcli_error_handler;
	conn->app_output_goon_handler = nvcli_output_goon;
	if (conn->driver == NULL) {
		//需要发起连接
		if (conn->link.next != NULL)
			navi_list_remove(&conn->link);//可能已经在active_aconns中
		navi_list_insert_tail(&cli->parent->active_aconns, &conn->link);
		nvcli_parent_need_drive(cli->parent);
	}
}

void* nvcli_init(nvcli_parent_t* parent,
	const nvcli_proto_proc_t* proto_procs,const navi_grcli_app_proc_t* app_procs, void* app_data, 
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval,
	const struct sockaddr* peer)
{
	if (parent == NULL || proto_procs == NULL || peer == NULL || app_procs == NULL ||
		app_procs->session_complete_handler == NULL || app_procs->session_error_handler == NULL)
		return NULL;

	void* ret = get_recycle_cli(parent, proto_procs->proto);

	if ( !ret ) {
		ret = navi_pool_calloc(parent->pool, 1, proto_procs->proto_obj_size);
	}

	navi_grcli_t* cli = (navi_grcli_t*)ret;
	cli->proto_procs = proto_procs;
	if (app_procs) {
		cli->app_procs.session_error_handler = app_procs->session_error_handler;
		cli->app_procs.session_complete_handler = app_procs->session_complete_handler;
		cli->app_procs.obody_goon_handler = app_procs->obody_goon_handler;
	}
    cli->app_data = app_data;
	cli->private_pool = navi_pool_create(1024);

	cli->resp_max_waiting = 2000;
	if ( resp_max_waiting > 0 ) {
		if ( resp_max_waiting < 20 /*ms*/) {
			resp_max_waiting = 20;
		}
		cli->resp_max_waiting = resp_max_waiting;
	}

	cli->input_max_interval = 200;
	if ( input_max_interval > 0) {
		if ( input_max_interval < 20 /*ms*/) {
			input_max_interval = 20;
		}
		else if (input_max_interval >= 10000 ) {
			input_max_interval = 10000;
		}
		cli->input_max_interval = input_max_interval;
	}

	cli->parent = parent;
	nvcli_bind_new_conn(cli,peer,conn_timeout);
	
	navi_list_insert_tail(&parent->clients, &cli->parent_link);
	parent->client_cnt++;

	return cli;
}

void nvcli_set_obody_handler(navi_grcli_t* cli, nvcli_output_goon_fp handler)
{
	if(!cli)return;
	cli->app_procs.obody_goon_handler = handler;
}

void nvcli_set_complete_handler(navi_grcli_t* cli, nvcli_complete_fp handler)
{
	if(!cli)return;
	cli->app_procs.session_complete_handler = handler;
}

void nvcli_set_error_handler(navi_grcli_t* cli, nvcli_error_fp handler)
{
	if(!cli)return;
	cli->app_procs.session_error_handler = handler;
}

void nvcli_clean(navi_grcli_t* cli)
{
	if ( cli->recycled ) return;

	if (cli->app_data_cleanup && cli->app_data ) {
		cli->app_data_cleanup(cli->app_data);
		cli->app_data_cleanup = NULL;
		cli->app_data = NULL;
	}

	if (cli->input_timer) {
		nvcli_parent_cancel_timer(cli->parent, cli->input_timer);
		//navi_timer_cancel(cli->input_timer);
		cli->input_timer = NULL;
	}
	if (cli->output_timer) {
		nvcli_parent_cancel_timer(cli->parent, cli->output_timer);
		//navi_timer_cancel(cli->output_timer);
		cli->output_timer = NULL;
	}

	if ( cli->conn ) {
		if (cli->conn->driver == NULL) {//连接尚未建立
			nvacnn_close(cli->conn);
		}
		else if (cli->conn->err) {
			nvacnn_close(cli->conn);
		}
		else if ( cli->has_output ) {
			if ( cli->output_done && cli->input_done ) {
				cli->conn->app_reading_status = 0x02;//nvcli_parse_in中调用时尚未来得及修改状态，在此修正
				nvacnn_add_idle(cli->conn);
			}
			else {
				nvacnn_close(cli->conn);
			}
		}
		else {
			nvacnn_add_idle(cli->conn);
		}
		cli->conn = NULL;
	}

	memset(&cli->app_procs, 0x00, sizeof(navi_grcli_app_proc_t));
	navi_pool_reset(cli->private_pool);
	cli->input_max_interval = 0;
	cli->resp_max_waiting = 0;

	cli->flags = 0;

	navi_list_remove(&cli->parent_link);
	cli->parent->client_cnt--;

	assert(cli->parent->client_cnt>=0);

	chain_node_t* pool_lst = &cli->parent->client_pool[cli->proto_procs->proto];
	navi_list_insert_head(pool_lst, &cli->parent_link);
	cli->recycled = 1;

	nvcli_parent_check_idle(cli->parent);
	return;
}

void nvcli_send_header(navi_grcli_t* cli, const unsigned char* content, size_t size,
	bool start_reading)
{
	cli->has_output = 1;
	//if ( content && size > 0) {//redis 直接设置out_buf
	if ( content && size > 0 && navi_buf_chain_get_content(cli->conn->out_buf, NULL, 0)) {
		nvacnn_write(cli->conn, content, size, nvcli_output_goon, true);
	}
	else {
		nvacnn_write(cli->conn, content, size, nvcli_output_goon, false);
	}
	//}
	navi_list_remove(&cli->conn->link);//可能已经在active_aconns中
	navi_list_insert_tail(&cli->parent->active_aconns,&cli->conn->link);

	cli->oheader_done = 1;
	if (start_reading) {
		nvacnn_set_reading(cli->conn, nvcli_parse_in);

        if (cli->input_timer != NULL) {
        	nvcli_parent_cancel_timer(cli->parent, cli->input_timer);
        }

        if ( cli->conn->ready == 0) {
        	cli->input_timer = nvcli_parent_add_timer(cli->parent,cli->resp_max_waiting,
        			NAVI_TIMER_ONCE, cli, nvcli_resp_timedout, NULL);
        }
        else {
        	cli->input_timer = nvcli_parent_add_timer(cli->parent,
        			cli->resp_max_waiting + cli->conn->conn_timeout_ms + 10,
        			NAVI_TIMER_ONCE, cli, nvcli_resp_timedout, NULL);
        }

	}
    
	if (cli->output_timer != NULL) {
		nvcli_parent_cancel_timer(cli->parent, cli->output_timer);
    }

	if (cli->conn->ready == 0) {
		cli->output_timer = nvcli_parent_add_timer(cli->parent, cli->conn->conn_timeout_ms + 100,
				NAVI_TIMER_ONCE,
				cli, nvcli_output_timedout, NULL);
	}
	else {
		cli->output_timer = nvcli_parent_add_timer(cli->parent, 10000, NAVI_TIMER_ONCE,
				cli, nvcli_output_timedout, NULL);
	}

}

void nvcli_send_body(navi_grcli_t* cli, const unsigned char* content, size_t size,
	bool start_reading)
{
	cli->has_output = 1;
	nvacnn_write(cli->conn, content, size, nvcli_output_goon, false);
	navi_list_remove(&cli->conn->link);//可能已经在active_aconns中
	navi_list_insert_tail(&cli->parent->active_aconns,&cli->conn->link);

	if (start_reading) {
		nvacnn_set_reading(cli->conn, nvcli_parse_in);

        if (cli->input_timer != NULL) {
        	nvcli_parent_cancel_timer(cli->parent, cli->input_timer);
        	cli->input_timer = NULL;
        }
        if ( cli->conn->ready == 0) {
        	cli->input_timer = nvcli_parent_add_timer(cli->parent,cli->resp_max_waiting,
        			NAVI_TIMER_ONCE, cli, nvcli_resp_timedout, NULL);
        }
        else {
        	cli->input_timer = nvcli_parent_add_timer(cli->parent,
        			cli->resp_max_waiting + cli->conn->conn_timeout_ms + 10,
        			NAVI_TIMER_ONCE, cli, nvcli_resp_timedout, NULL);
        }
	}

	if (cli->output_timer != NULL) {
		nvcli_parent_cancel_timer(cli->parent, cli->output_timer);
		cli->output_timer = NULL;
    }
	if (cli->conn->ready == 0) {
		cli->output_timer = nvcli_parent_add_timer(cli->parent, cli->conn->conn_timeout_ms + 100,
				NAVI_TIMER_ONCE,
				cli, nvcli_output_timedout, NULL);
	}
	else {
		cli->output_timer = nvcli_parent_add_timer(cli->parent, 10000, NAVI_TIMER_ONCE,
				cli, nvcli_output_timedout, NULL);
	}
}

void nvcli_prepare_body(navi_grcli_t* cli, const unsigned char* content, size_t size)
{
	nvacnn_write(cli->conn, content, size, nvcli_output_goon, false);
}

void nvcli_prepare_file_body(navi_grcli_t* cli, int fd, size_t pos, size_t size)
{
	if (fd == -1) return;
	nvacnn_sendfile(cli->conn, fd, pos,size, nvcli_output_goon, false);
}

void nvcli_sendfile(navi_grcli_t* cli, int fd, size_t pos, size_t size, bool start_reading)
{
	if (fd == -1)
		return;
	cli->has_output = 1;
	nvacnn_sendfile(cli->conn, fd, pos,size, nvcli_output_goon, false);
	navi_list_remove(&cli->conn->link);//可能已经在active_aconns中
	navi_list_insert_tail(&cli->parent->active_aconns,&cli->conn->link);

	if ( start_reading) {
		nvacnn_set_reading(cli->conn, nvcli_parse_in);
        if (cli->input_timer != NULL) {
        	nvcli_parent_cancel_timer(cli->parent, cli->input_timer);
        }

        if ( cli->conn->ready == 0) {
        	cli->input_timer = nvcli_parent_add_timer(cli->parent,cli->resp_max_waiting,
        			NAVI_TIMER_ONCE, cli, nvcli_resp_timedout, NULL);
        }
        else {
        	cli->input_timer = nvcli_parent_add_timer(cli->parent,
        			cli->resp_max_waiting + cli->conn->conn_timeout_ms + 10,
        			NAVI_TIMER_ONCE, cli, nvcli_resp_timedout, NULL);
        }
	}

	if (cli->conn->ready == 0) {
		cli->output_timer = nvcli_parent_add_timer(cli->parent, cli->conn->conn_timeout_ms + 100,
				NAVI_TIMER_ONCE,
				cli, nvcli_output_timedout, NULL);
	}
	else {
		cli->output_timer = nvcli_parent_add_timer(cli->parent, 10000, NAVI_TIMER_ONCE,
				cli, nvcli_output_timedout, NULL);
	};

}


static chain_node_t s_all_parents = {&s_all_parents, &s_all_parents};

static navi_timer_driver_install_fp  s_driver_timer_installer = NULL;
static navi_timer_driver_cancel_fp s_driver_timer_cancler = NULL;
static nvacnn_driver_install_fp s_driver_aconn_installer = NULL;
static nvacnn_driver_process_fp s_driver_aconn_processor = NULL;
static nvacnn_driver_close_fp s_driver_aconn_closer = NULL;
static nvacnn_driver_set_idle_fp s_driver_aconn_idle_setter = NULL;
static nvacnn_driver_quit_idle_fp s_driver_aconn_idle_quiter = NULL;

static nvcli_parent_create_driver_fp s_driver_parent_driver_creater = NULL;
static nvcli_parent_get_driverpool_fp s_driver_parent_driverpool_getter = NULL;
static nvcli_parent_cleanup_driver_fp s_driver_parent_driver_cleaner = NULL;

static navi_driver_setup_fp s_navi_driver_setup = NULL;

void nvcli_parent_driver_regist(navi_timer_driver_install_fp timer_installer,
	navi_timer_driver_cancel_fp timer_cancler,
	nvacnn_driver_install_fp aconn_installer,
	nvacnn_driver_process_fp aconn_processor,
	nvacnn_driver_close_fp aconn_closer,
	nvacnn_driver_set_idle_fp aconn_set_idle,
	nvacnn_driver_quit_idle_fp aconn_quit_idle,
	nvcli_parent_create_driver_fp parent_driver_creater,
	nvcli_parent_get_driverpool_fp parent_dirvepool_getter,
	nvcli_parent_cleanup_driver_fp parent_driver_cleaner,
	navi_driver_setup_fp driver_setup)
{
	s_driver_timer_installer = timer_installer;
	s_driver_timer_cancler = timer_cancler;
	s_driver_aconn_installer = aconn_installer;
	s_driver_aconn_processor = aconn_processor;
	s_driver_aconn_closer = aconn_closer;
	s_driver_aconn_idle_setter = aconn_set_idle;
	s_driver_aconn_idle_quiter = aconn_quit_idle;
	
	s_driver_parent_driver_creater = parent_driver_creater;
	s_driver_parent_driverpool_getter = parent_dirvepool_getter;
	s_driver_parent_driver_cleaner = parent_driver_cleaner;

	s_navi_driver_setup = driver_setup;
}

void nvcli_parent_need_drive(nvcli_parent_t* parent)
{
	navi_list_remove(&parent->drive_link);
	navi_list_insert_tail(&s_all_parents, &parent->drive_link);
	s_navi_driver_setup();
}

static void nvcli_parent_process(nvcli_parent_t* cli_parent)
{
	void* tm_iter = navi_timer_iter(&cli_parent->timer_mgr,NAVI_TIMER_REGISTED);
	navi_timer_t* tmr;
	while ( tmr = navi_timer_iter_next(tm_iter)) {
		void* driver = s_driver_timer_installer(tmr);
		navi_timer_bind_driver(tmr, driver, s_driver_timer_cancler);
		navi_timer_running(tmr, driver);
	}

	chain_node_t* cnn_nd = cli_parent->active_aconns.next;
	navi_aconn_t* conn;

	while ( cnn_nd != &cli_parent->active_aconns ) {
		conn = navi_list_data(cnn_nd, navi_aconn_t, link);
		cnn_nd = cnn_nd->next;
		navi_list_remove(&conn->link);
		if ( conn->driver == NULL) {
			conn->driver = s_driver_aconn_installer(conn);
			nvacnn_set_driver(conn, conn->driver,
				s_driver_aconn_processor, s_driver_aconn_closer,
				s_driver_aconn_idle_setter,
				s_driver_aconn_idle_quiter);
		}
		nvacnn_process_driver(conn);
	}

	return;
}

void nvcli_parents_drive(nvcli_parent_create_driver_fp create_driver, nvcli_parent_get_driverpool_fp get_driver_pool,
	nvcli_parent_cleanup_driver_fp cleanup_driver)
{
	chain_node_t* nd = s_all_parents.next;
	nvcli_parent_t* obj;

	while ( nd != &s_all_parents) {
		obj = navi_list_data(nd,nvcli_parent_t,drive_link);
		if ( obj->driver == NULL) {
			obj->driver = create_driver(obj);
			obj->get_driver_pool = get_driver_pool;
			obj->driver_cleanup = cleanup_driver;
		}
		nd = nd->next;
		navi_list_remove(&obj->drive_link);
		nvcli_parent_process(obj);
	}
}

void nvcli_parent_init(nvcli_parent_t* parent, navi_pool_t* pool, void* parent_obj,
	void (*parent_idle_handler)(void*))
{
	navi_list_init(&parent->clients);
	parent->client_cnt = 0;
	navi_timer_mgr_init(&parent->timer_mgr);
	parent->pool = pool;
	navi_list_init(&parent->active_aconns);
	navi_list_init(&parent->drive_link);
	navi_list_init(&parent->client_pool[NVCLI_HTTP]);
	navi_list_init(&parent->client_pool[NVCLI_REDIS]);

	parent->parent = parent_obj;
	parent->parent_idle_handler = parent_idle_handler;
}

void nvcli_parent_cleanup(nvcli_parent_t* parent)
{
	chain_node_t* cli_nd = parent->clients.next;
	navi_grcli_t* cli;

	if ( parent->driver && parent->driver_cleanup ) {
		parent->driver_cleanup(parent->driver);
		parent->driver = NULL;
		parent->driver_cleanup = NULL;
	}

	while ( cli_nd != &parent->clients) {
		cli = navi_list_data(cli_nd, navi_grcli_t, parent_link);
		cli_nd = cli_nd->next;
		navi_list_remove(&cli->parent_link);
		nvcli_clean(cli);
	}

	navi_list_remove(&parent->drive_link);

	navi_timer_mgr_clean(&parent->timer_mgr);

	chain_node_t* proto_pool = &parent->client_pool[NVCLI_HTTP];
	cli_nd = proto_pool->next;
	while (cli_nd != proto_pool) {
		cli = navi_list_data(cli_nd, navi_grcli_t, parent_link);
		cli_nd = cli_nd->next;
		navi_list_remove(&cli->parent_link);
		navi_pool_destroy(cli->private_pool);
	}

	proto_pool = &parent->client_pool[NVCLI_REDIS];
	cli_nd = proto_pool->next;
	while (cli_nd != proto_pool) {
		cli = navi_list_data(cli_nd, navi_grcli_t, parent_link);
		cli_nd = cli_nd->next;
		navi_list_remove(&cli->parent_link);
		navi_pool_destroy(cli->private_pool);
	}
}

void nvcli_parent_check_idle(nvcli_parent_t* parent)
{
	if (parent->client_cnt == 0 && navi_list_empty(&parent->timer_mgr.regist)
		&& navi_list_empty(&parent->timer_mgr.running) ) {
		if (parent->parent_idle_handler) {
			parent->parent_idle_handler(parent->parent);
		}
	}
}

typedef struct _nvcli_parent_timer_t
{
	nvcli_parent_t* parent;
	void* arg;
	nvcli_parent_timer_fp handler;
	nvcli_parent_timer_fp cleanup;
} nvcli_parent_timer_t;

static int nvcli_parent_timer_process(void* wrapper)
{
	nvcli_parent_timer_t* tmr = (nvcli_parent_timer_t*)wrapper;
	tmr->handler(tmr->parent->parent, tmr->arg);
	nvcli_parent_check_idle(tmr->parent);
	return 0;
}

static int nvcli_parent_timer_clean(void* wrapper)
{
	nvcli_parent_timer_t* tmr = (nvcli_parent_timer_t*)wrapper;
	if ( tmr->cleanup ) {
		tmr->cleanup(tmr->parent->parent, tmr->arg);
	}
	nvcli_parent_check_idle(tmr->parent);
	return 0;
}

navi_timer_h nvcli_parent_add_timer(nvcli_parent_t* parent, int timeout_ms,
	navi_timer_type_e type,
	void* timer_arg,
	nvcli_parent_timer_fp timer_handler,
	nvcli_parent_timer_fp timer_cleanup)
{
	nvcli_parent_timer_t* wrapper = navi_pool_calloc(parent->pool, 1, sizeof(nvcli_parent_timer_t));
	wrapper->arg = timer_arg;
	wrapper->handler = timer_handler;
	wrapper->cleanup = timer_cleanup;
	wrapper->parent = parent;

	navi_timer_t* tmr = navi_timer_add(&parent->timer_mgr,type, timeout_ms,
		nvcli_parent_timer_process, wrapper, nvcli_parent_timer_clean,NULL);
	nvcli_parent_need_drive(parent);
	return tmr;
}

void nvcli_parent_cancel_timer(nvcli_parent_t* parent, navi_timer_h timer)
{
	navi_timer_t* tmr = (navi_timer_t*)timer;
	assert(tmr->mgr == &parent->timer_mgr);
	navi_timer_cancel(timer);
	navi_timer_cleanup(timer);
}
