/** \brief 
 * navi_async_network.c
 *  Created on: 2015-1-15
 *      Author: li.lei
 *  brief: 
 */

#include "navi_async_conn.h"
#include "../navi_frame_log.h"
#include "navi_inner_util.h"
#include <assert.h>

static nvacnn_pool_mgr_t s_conn_pool = {
	200,
	0,
	NULL
};

static int nvacnn_input_unexpected(void* app, const unsigned char* dummy, size_t dmy)
{
	return -1;
}

static void peer_pool_clean(void* v)
{
	navi_peer_aconn_pool_t* pool = (navi_peer_aconn_pool_t*)v;
	chain_node_t* nd = pool->idles.next;
	navi_aconn_t* cnn;
	while ( nd != &pool->idles ) {
		cnn = navi_list_data(nd,navi_aconn_t,link);
		nd = nd->next;
		navi_list_remove(&cnn->link);
		cnn->driver_quit_idle_handler(cnn);
		nvacnn_close(cnn);
		free(cnn);
	}

	free(pool);
}

navi_aconn_t* nvacnn_get_conn(const struct sockaddr* peer, void* app,
	nvacnn_app_unbind_fp unbind_handler, int conn_timeout_ms)
{
	if ( !app || !unbind_handler)
		return NULL;
	navi_aconn_t* ret = nvacnn_get_idle(peer);
	NAVI_FRAME_LOG(NAVI_LOG_DEBUG, "nvacnn_get_idle return %p", ret);
	if ( ret == NULL ) {
		ret = (navi_aconn_t*)calloc(1,sizeof(navi_aconn_t));
		switch(peer->sa_family) {
		case AF_INET:
			memcpy(&ret->peer_addr_in, peer, sizeof(struct sockaddr_in));
			break;
		case AF_INET6:
			memcpy(&ret->peer_addr_in6, peer, sizeof(struct sockaddr_in6));
			break;
		case AF_UNIX:
			memcpy(&ret->peer_addr_un, peer, sizeof(struct sockaddr_un));
			break;
		}
		ret->conn_timeout_ms = conn_timeout_ms;
	}
	ret->app = app;
	ret->app_unbind_handler = unbind_handler;
	ret->app_input_handler = nvacnn_input_unexpected;
	ret->busy_outbuflast = &ret->busy_outbuf;
	return ret;
}

void nvacnn_set_short(navi_aconn_t* cnn, bool short_conn)
{
	if ( short_conn)
		cnn->use_once = 1;
	else
		cnn->use_once = 0;
}

bool nvacnn_is_idle(navi_aconn_t* conn)
{
	if ( conn->has_output && conn->app_reading_status==0x02
		&& conn->app_write_status == 0x03)
		return true;
	else if ( conn->idle )
		return true;
	else if ( !conn->has_output )
		return true;
	return false;
}

void nvacnn_write(navi_aconn_t* conn, const unsigned char* content, size_t size,
	nvacnn_output_goon_fp goon,bool pre)
{
	assert(conn != NULL);
	if(conn->out_buf == NULL) {
		conn->out_buf = navi_buf_chain_init(conn->pool);
	}
	if (content && size > 0) {//支持直接设置out_buf，发送时不指定新content
		if (pre)
			navi_buf_chain_insert_head(conn->out_buf, content, size);
		else
			navi_buf_chain_append(conn->out_buf, content, size);
	}

	conn->has_output = 1;
	if (goon) {
		conn->app_write_status = 0x01;
		conn->app_output_goon_handler = goon;
	}
	else {
		conn->app_write_status = 0x02;
	}
	return;
}

void nvacnn_sendfile(navi_aconn_t* conn, int fd, size_t pos, size_t size, nvacnn_output_goon_fp goon, bool pre)
{
	assert(conn != NULL);
	if(conn->out_buf == NULL) {
		conn->out_buf = navi_buf_chain_init(conn->pool);
	}

	if (pre)
		navi_buf_chain_insert_head_file(conn->out_buf, fd, pos, size);
	else
		navi_buf_chain_append_part_file(conn->out_buf, fd, pos,size);

	conn->has_output = 1;
	if (goon) {
		conn->app_write_status = 0x01;
		conn->app_output_goon_handler = goon;
	}
	else {
		conn->app_write_status = 0x02;
	}
	return;
}


void nvacnn_set_reading(navi_aconn_t* conn, nvacnn_parse_in_fp handler)
{
	conn->app_reading_status = 0x01;
	conn->app_input_handler = handler;
}

void nvacnn_close(navi_aconn_t* conn)
{
	if (conn->zombie) {
		return;
	}
	if ( conn->app ) {
		conn->app_unbind_handler(conn->app);
		conn->app = NULL;
	}
	if (conn->driver) {
		conn->driver_close_handler(conn);
	}

	navi_list_remove(&conn->link);
	conn->zombie = 1;
	//free(conn);
}

void nvacnn_set_peer_pool(const struct sockaddr* peer, int idle_pool_size,
	int idle_timeout_ms, int conn_used_max)
{
	char addr_str[256];
	navi_addr_to_str(peer, addr_str);

	if ( s_conn_pool.peer_idle_idx == NULL) {
		s_conn_pool.peer_idle_idx = navi_hash_init_with_heap();
	}

	navi_peer_aconn_pool_t* peer_pool = navi_hash_get_gr(s_conn_pool.peer_idle_idx,addr_str);
	if ( peer_pool == NULL) {
		peer_pool = (navi_peer_aconn_pool_t*)calloc(1,sizeof(navi_peer_aconn_pool_t));

		navi_hash_set_gr2(s_conn_pool.peer_idle_idx, addr_str, peer_pool, peer_pool_clean);
	}
	if ( idle_pool_size <= 0) {
		idle_pool_size = 0;
	}
	else if (idle_pool_size >= 128) {
		idle_pool_size = 128;
	}

	if (idle_timeout_ms <= 0 ) {
		idle_timeout_ms = 0;
	}
	else if (idle_timeout_ms <= 1000) {
		idle_timeout_ms = 1000;
	}

	if ( conn_used_max <= 0) {
		conn_used_max = 0;
	}

	peer_pool->idle_pool_size = idle_pool_size;
	peer_pool->idle_timeout = idle_timeout_ms;
	peer_pool->conn_used_limit = conn_used_max;
	return;
}

void nvacnn_set_global_pool(int max_idle_conn)
{
	if (max_idle_conn<=0) {
		max_idle_conn = 32;
	}
	else if (max_idle_conn >= 1024)
		max_idle_conn = 1024;

	s_conn_pool.idle_total_limit = max_idle_conn;
}

void nvacnn_remove_idle(navi_aconn_t* idle)
{
	navi_peer_aconn_pool_t* peer_pool = (navi_peer_aconn_pool_t*)idle->app;
	navi_list_remove(&idle->link);
	peer_pool->cur_idle_count--;
	s_conn_pool.idle_total--;
	idle->driver_quit_idle_handler(idle);
	idle->app = NULL;
	nvacnn_close(idle);
}

void nvacnn_add_idle(navi_aconn_t* idle)
{
	char addr_str[256];
	off_t off = 0;

	navi_addr_to_str(&idle->peer_addr, addr_str);

	if ( s_conn_pool.peer_idle_idx == NULL) {
		s_conn_pool.peer_idle_idx = navi_hash_init_with_heap();
	}

	navi_peer_aconn_pool_t* peer_pool = navi_hash_get_gr(s_conn_pool.peer_idle_idx,addr_str);
	if ( peer_pool == NULL) {
		peer_pool = (navi_peer_aconn_pool_t*)calloc(1,sizeof(navi_peer_aconn_pool_t));
		peer_pool->idle_pool_size = 50;
		peer_pool->idle_timeout = 60000;
		peer_pool->conn_used_limit = 1000000;
		navi_list_init(&peer_pool->idles);
		navi_hash_set_gr2(s_conn_pool.peer_idle_idx, addr_str, peer_pool, peer_pool_clean);
	}

	if ( !nvacnn_is_idle(idle)) {
		nvacnn_close(idle);
		return;
	}

	if ( idle->use_once ) {
		nvacnn_close(idle);
		return;
	}

	idle->used_cnt++;
	if ( idle->used_cnt >= peer_pool->conn_used_limit) {
		nvacnn_close(idle);
		return;
	}

	if ( peer_pool->idle_pool_size <= peer_pool->cur_idle_count ) {
		nvacnn_close(idle);
		return;
	}

	navi_list_remove(&idle->link);

	idle->flags = 0;
	idle->idle = 1;
	idle->ready = 1;

	idle->out_buf = NULL;
	idle->app_output_goon_handler = NULL;
	idle->app_error_handler = NULL;
	idle->app = peer_pool;

	idle->app_input_handler = nvacnn_input_unexpected;

	idle->driver_set_idle_handler(idle, peer_pool->idle_timeout);

	peer_pool->cur_idle_count++;
	s_conn_pool.idle_total++;
	navi_list_insert_head(&peer_pool->idles, &idle->link);
	NAVI_FRAME_LOG(NAVI_LOG_DEBUG, "nvacnn_add_idle with %p", idle);
	return;
}

navi_aconn_t* nvacnn_get_idle(const struct sockaddr* peer)
{
	char addr_str[256];
	off_t off = 0;

	navi_addr_to_str(peer, addr_str);

	if ( s_conn_pool.peer_idle_idx ) {
		navi_peer_aconn_pool_t* peer_pool = navi_hash_get_gr(s_conn_pool.peer_idle_idx,addr_str);
		if (!peer_pool) {
			return NULL;
		}
		if ( peer_pool->cur_idle_count <= 0)
			return NULL;

		chain_node_t* cnn_nd = navi_list_head(&peer_pool->idles);
		navi_list_remove(cnn_nd);
		peer_pool->cur_idle_count--;
		s_conn_pool.idle_total--;
		assert(peer_pool->cur_idle_count>=0);
		assert(s_conn_pool.idle_total>=0);

		navi_aconn_t* conn = navi_list_data(cnn_nd,navi_aconn_t,link);
		conn->driver_quit_idle_handler(conn);
		conn->idle = 0;
		conn->busy_outbuf = NULL;
		conn->busy_outbuflast = &conn->busy_outbuf;
		return conn;
	}
	return NULL;
}

void nvacnn_check_global_pool()
{
	if ( s_conn_pool.idle_total >= s_conn_pool.idle_total_limit) {
		double drop_rate = (double)(s_conn_pool.idle_total- s_conn_pool.idle_total_limit)/
			s_conn_pool.idle_total_limit;

		void* it = navi_hash_iter(s_conn_pool.peer_idle_idx);
		navi_hent_t* hent;
		navi_peer_aconn_pool_t* peer_pool = NULL;
		while ( hent = navi_hash_iter_next(it)) {
			peer_pool = (navi_peer_aconn_pool_t*)hent->v;
			if (peer_pool->cur_idle_count <= 1)
				continue;
			int drop_cnt = peer_pool->cur_idle_count * drop_rate;
			if ( drop_cnt == 0)
				drop_cnt = 1;

			chain_node_t* cnn_nd = peer_pool->idles.next;
			while ( cnn_nd != &peer_pool->idles && drop_cnt-- > 0) {
				navi_aconn_t* cnn = navi_list_data(cnn_nd,navi_aconn_t,link);
				cnn_nd = cnn_nd->next;
				navi_list_remove(&cnn->link);
				cnn->driver_quit_idle_handler(cnn);
				nvacnn_close(cnn);

				peer_pool->cur_idle_count--;
				s_conn_pool.idle_total--;
			}
		}
		navi_hash_iter_destroy(it);
	}
}

void nvacnn_clean_global_pool()
{
	navi_hash_destroy(s_conn_pool.peer_idle_idx);
	s_conn_pool.peer_idle_idx = NULL;
	s_conn_pool.idle_total = 0;
}

void nvacnn_input_arrive(navi_aconn_t* conn, const unsigned char* in, size_t size)
{
    int ret = 1;
	if(conn->app_input_handler==NULL) {
		if ( conn->app_error_handler) {
			if (conn->app) {
				conn->app_unbind_handler(conn->app);
				conn->app_error_handler(conn->app, NVCLI_UNEXPECTED_INPUT);
			}
			conn->app = NULL;
			nvacnn_close(conn);
		}
	}
	else {
		int ret = conn->app_input_handler(conn->app, in, size);
		if ( ret == -1 ) {
			if ( conn->idle ) {
				nvacnn_remove_idle(conn);
			}
			else {
				conn->app_reading_status = 0x03;
				if (conn->app) {
					conn->app_unbind_handler(conn->app);
					conn->app_error_handler(conn->app, NVCLI_PROTO_ERROR);
				}
				conn->app = NULL;
				nvacnn_close(conn);
			}
		}
		else if (ret == 0) {
			conn->app_reading_status = 0x01;
		}
		else if (ret == 1) {
			conn->app_reading_status = 0x02;
			conn->app_input_handler = nvacnn_input_unexpected;
		}
	}
}

void nvacnn_output_gone(navi_aconn_t* conn)
{
	if( conn->app && conn->app_output_goon_handler ) {
		int ret = conn->app_output_goon_handler(conn->app);
		if ( ret == -1) {
			if ( conn->app && conn->app_error_handler) {
				conn->app_unbind_handler(conn->app);
				conn->app_error_handler(conn->app, NVCLI_OUTPUT_INCOMPLETE);
			}
			conn->app = NULL;
			nvacnn_close(conn);
		}
		else if ( ret == 1) {
			conn->app_write_status = 0x03;
		}
		else {
			if ( 0 == navi_buf_chain_get_content(conn->out_buf, NULL, 0)) {
				conn->app_write_status = 0x03;
			}
			else {
				conn->app_write_status = 0x01;
			}
		}
	}
}

void nvacnn_has_problem(navi_aconn_t* conn, nvcli_error_e e)
{
	if ( conn->idle ) {
		nvacnn_remove_idle(conn);
	}
	else {
		if ( conn->app ) {
			conn->app_unbind_handler(conn->app);
			if (conn->app_error_handler)
				conn->app_error_handler(conn->app, e);
		}
		conn->app = NULL;
		nvacnn_close(conn);
	}
}

void nvacnn_idle_timedout(navi_aconn_t* conn)
{
	if (conn->idle ) {
		nvacnn_remove_idle(conn);
	}
}

void nvacnn_set_driver(navi_aconn_t* conn, void* driver,
	nvacnn_driver_process_fp process,
	nvacnn_driver_close_fp closer,
	nvacnn_driver_set_idle_fp set_idle,
	nvacnn_driver_quit_idle_fp quit_idle)
{
	conn->driver = driver;
	conn->driver_close_handler = closer;
	conn->driver_process_handler = process;
	conn->driver_set_idle_handler = set_idle;
	conn->driver_quit_idle_handler = quit_idle;
}

void nvacnn_process_driver(navi_aconn_t* conn)
{
	conn->driver_process_handler(conn);
}
