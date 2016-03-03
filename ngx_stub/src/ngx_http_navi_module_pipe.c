/*
 * ngx_http_navi_module_pipe.c
 *
 *  Created on: 2014-04-18
 *      Author: yanguotao@youku.com
 */

#define NGX_HTTP_NAVI_PIPE_BUF_LEN 4096
#define NGX_HTTP_NAVI_PIPE_TIMEOUT 200
#define NGX_HTTP_NAVI_PIPE_RECONNECT 200

#include <cnaviproxy/navi_pipe.h>

typedef struct ngx_http_navi_pipe_s
{
    ngx_connection_t *connection;
    int connecting;
    ngx_event_t *check_ev;
    ngx_log_t      *log;
    ngx_buf_t     rcv_buf;
    ngx_queue_t link;
    void *ctx;
}ngx_http_navi_pipe_t;

static void ngx_http_navi_pipe_close_connection(ngx_http_navi_pipe_t *ngx_pipe)
{
    navi_pipe_t *pipe = ngx_pipe->ctx;
    memset(pipe->local_name, 0x00, sizeof(pipe->local_name));

    if (ngx_pipe->connection){
        ngx_close_connection(ngx_pipe->connection);
        ngx_log_error(NGX_LOG_WARN, ngx_pipe->log, 0, "pipe connection for %s:%s closed",
                pipe->group, pipe->server_name);
    }
    ngx_pipe->connection = NULL;
    ngx_pipe->rcv_buf.pos = ngx_pipe->rcv_buf.start;
    ngx_pipe->rcv_buf.last = ngx_pipe->rcv_buf.start;
    pipe->status = NAVI_PIPE_STATUS_DISCONNECTED;
    navi_pipe_reset_buf(pipe->out_pack);
    nvup_pipe_reset_ve(pipe);
}

static void ngx_http_navi_pipe_rev_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c = ev->data;
    ngx_http_navi_pipe_t *ngx_pipe = c->data;
    navi_pipe_t *pipe = ngx_pipe->ctx;
    ssize_t n;
    ngx_int_t status = 0;

    if (ev->timedout) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_http_navi_pipe_close_connection(ngx_pipe);
            return;
        }
    }

    if (ev->timer_set) {
        ngx_del_timer(ev);
    }

    for ( ;; ) {

        n = c->recv(c, ngx_pipe->rcv_buf.last, ngx_pipe->rcv_buf.end - ngx_pipe->rcv_buf.last);

        if (n == NGX_AGAIN) {
            if (status == NVUP_PARSE_AGAIN){
                ngx_add_timer(ev, NGX_HTTP_NAVI_PIPE_TIMEOUT);
            }

            ngx_http_navi_pipe_process();
            ngx_http_navi_ve_process(NULL);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_http_navi_pipe_close_connection(ngx_pipe);

                return;
            }

            return;
        }

        if (n == 0) {
            ngx_log_error(NGX_LOG_ERR, ngx_pipe->log, 0,
                          "pipe prematurely closed connection");
        }

        if (n == NGX_ERROR || n == 0) {
            ngx_http_navi_pipe_process();
            ngx_http_navi_ve_process(NULL);
            ngx_http_navi_pipe_close_connection(ngx_pipe);
            return;        
        }

        status = nvup_pipe_redis_parse_in(pipe, ngx_pipe->rcv_buf.last, n);
    }

    ngx_http_navi_pipe_process();
    ngx_http_navi_ve_process(NULL);
}

static void ngx_http_navi_pipe_wev_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c = ev->data;
    ngx_http_navi_pipe_t *ngx_pipe = c->data;
    navi_pipe_t *pipe = ngx_pipe->ctx;
    ssize_t n;

    if (ev->timedout) {
         ngx_http_navi_pipe_close_connection(ngx_pipe);
        return;
    }

    if (ev->timer_set) {
        ngx_del_timer(c->write);
    }

    if (ngx_pipe->connecting) {
    	ngx_pipe->connecting = 0;

    	pipe->local_name[0] = 0;
    	struct sockaddr_storage ss;
    	socklen_t slen = sizeof(struct sockaddr_storage);
    	if ( 0 == getsockname(c->fd, (struct sockaddr*)&ss, &slen) ) {
			if( ss.ss_family == AF_INET) {
				struct sockaddr_in* pin = (struct sockaddr_in*)&ss;
				snprintf(pipe->local_name, sizeof(pipe->local_name),"%s:%d", inet_ntoa(pin->sin_addr) ,
					ntohs(pin->sin_port));
				struct sockaddr_in* paddr = (struct sockaddr_in*)&pipe->peer_addr;
				ngx_log_error(NGX_LOG_NOTICE, ngx_pipe->log, 0, "navi pipe for %s:%d from %s wev ready",
					inet_ntoa(paddr->sin_addr) ,  ntohs(paddr->sin_port), pipe->local_name);
			}
			else if (ss.ss_family == AF_INET6 ) {

			}
			else {

			}
    	}
    }

    navi_pipe_buf_t *buf = pipe->out_pack;
    while (buf->used>0){
         navi_pipe_buf_item_t *item = &(buf->items[buf->start%buf->size]);
         int send = item->size -(item->pos-item->buf);
         n = c->send(c, (u_char *)(item->pos), item->size);

         if (n == NGX_ERROR) {
              ngx_http_navi_pipe_close_connection(ngx_pipe);
             break;
        }

        if (n == NGX_AGAIN) {
            ngx_add_timer(c->write, NGX_HTTP_NAVI_PIPE_TIMEOUT);

            if (ngx_handle_write_event(ev, 0) != NGX_OK) {
                ngx_http_navi_pipe_close_connection(ngx_pipe);
                break;
            }
            break;
        }
        if (n < send){
              item->pos += send;	
        }
        else if (n == send){
            free(item->buf);
            buf->start = (buf->start+1)%buf->size;
            buf->used--;
        }
    }
}

static void  ngx_http_navi_pipe_check(ngx_event_t *ev)
{
    if (ev->timedout){
        ngx_http_navi_pipe_t *ngx_pipe = ev->data;
        navi_pipe_t *pipe = ngx_pipe->ctx;
        navi_pipe_ping(pipe);
        ngx_http_navi_pipe_process();
        if (!ngx_exiting)
        	ngx_add_timer(ngx_pipe->check_ev, pipe->check.ping_interval*1000);
    }
}

static ngx_int_t ngx_http_navi_pipe_connect(navi_pipe_t *pipe)
{
    int                rc;
    ngx_int_t          event;
    ngx_err_t          err;
    ngx_uint_t         level;
    ngx_socket_t       s;
    ngx_event_t       *rev, *wev;
    ngx_connection_t  *c;
     char name[256]={0};

    ngx_http_navi_pipe_t *ngx_pipe = (ngx_http_navi_pipe_t *)pipe->driver;
    if (ngx_pipe == NULL){
        ngx_pipe = ngx_pcalloc(pcycle->pool, sizeof(ngx_http_navi_pipe_t));
        ngx_pipe->rcv_buf.start = ngx_palloc(pcycle->pool, NGX_HTTP_NAVI_PIPE_BUF_LEN);
        ngx_pipe->rcv_buf.pos = ngx_pipe->rcv_buf.start;
        ngx_pipe->rcv_buf.last = ngx_pipe->rcv_buf.start;
        ngx_pipe->rcv_buf.end = ngx_pipe->rcv_buf.start + NGX_HTTP_NAVI_PIPE_BUF_LEN;
        ngx_pipe->check_ev = ngx_pcalloc(pcycle->pool, sizeof(ngx_event_t));
        ngx_pipe->check_ev ->handler = ngx_http_navi_pipe_check;
        ngx_pipe->check_ev->data = ngx_pipe;
        ngx_pipe->log = pcycle->log;
        ngx_pipe->ctx = pipe;
        pipe->driver = ngx_pipe;
        ngx_queue_insert_tail(&ngx_pipe_mgr, &ngx_pipe->link);
    }

    size_t addr_sz = 0;
    if (pipe->peer_addr.ss_family == AF_INET) {
    	struct sockaddr_in* addr = (struct sockaddr_in*)&pipe->peer_addr;
    	snprintf(name, sizeof(name),  "%s:%d", inet_ntoa(addr->sin_addr),  ntohs(addr->sin_port));
    	addr_sz = sizeof(struct sockaddr_in);
    }
    else if (pipe->peer_addr.ss_family == AF_UNIX ) {
    	struct sockaddr_un* addr  = (struct sockaddr_un*)&pipe->peer_addr;
    	snprintf(name, sizeof(name),  "unix:%s", addr->sun_path);
    	addr_sz = sizeof(struct sockaddr_un);
    }
    else if (pipe->peer_addr.ss_family == AF_INET6 ) {
    	addr_sz = sizeof(struct sockaddr_in6);
    	struct sockaddr_in6* addr = (struct sockaddr_in6*)&pipe->peer_addr;
    	inet_ntop(AF_INET6 , &addr->sin6_addr, name, sizeof(name));
    }

    struct sockaddr * addr = (struct sockaddr*)&pipe->peer_addr;
    s = ngx_socket(addr->sa_family, SOCK_STREAM, 0);
   
    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, ngx_pipe->log, 0, "socket %d", s);
    
    if (s == -1) {
        ngx_log_error(NGX_LOG_ALERT, ngx_pipe->log, ngx_socket_errno,
            ngx_socket_n " failed");
        return NGX_ERROR;
    }
    
    c = ngx_get_connection(s, ngx_pipe->log);
    if (c == NULL) {
        if (ngx_close_socket(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, ngx_pipe->log, ngx_socket_errno,
                ngx_close_socket_n "failed");
        }
    
        return NGX_ERROR;
    }

    /*use default SO_RCVBUF*/
    
    if (ngx_nonblocking(s) == -1) {
        ngx_log_error(NGX_LOG_ALERT, pcycle->log, ngx_socket_errno,
                ngx_nonblocking_n " failed");
    
        goto failed;
    }
    
    int rcvbufsz = 61440 ;
    if ( 0 != setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rcvbufsz, sizeof(int)) ) {
        ngx_log_error(NGX_LOG_ALERT, pcycle->log, ngx_socket_errno,
           "pipe set rcvbufsize failed");
    }
    rcvbufsz = 61440 ;
    if (0 != setsockopt(s, SOL_SOCKET, SO_SNDBUF, &rcvbufsz, sizeof(int)) ) {
    	ngx_log_error(NGX_LOG_ALERT, pcycle->log, ngx_socket_errno,
    	    "pipe set sndbufsize failed");
    }

    c->recv = ngx_recv;
    c->send = ngx_send;
    c->recv_chain = ngx_recv_chain;
    c->send_chain = ngx_send_chain;
    
    c->sendfile = 1;

    c->log_error =  NGX_LOG_ERR; 
    
    if (addr->sa_family == AF_UNIX) {
        c->tcp_nopush = NGX_TCP_NOPUSH_DISABLED;
        c->tcp_nodelay = NGX_TCP_NODELAY_DISABLED;
    }

    rev = c->read;
    wev = c->write;
    
    rev->log = ngx_pipe->log;
    wev->log = ngx_pipe->log;
    rev->handler = ngx_http_navi_pipe_rev_handler;
    wev->handler = ngx_http_navi_pipe_wev_handler;
    rev->data = c;
    wev->data = c;	
    c->data = ngx_pipe;
    ngx_pipe->connection = c;
    
    c->number = ngx_atomic_fetch_add(ngx_connection_counter, 1);

    if (ngx_add_conn) {
        if (ngx_add_conn(c) == NGX_ERROR) {
    	    goto failed;
        }
    }

    ngx_log_debug3(NGX_LOG_DEBUG_EVENT, ngx_pipe->log, 0,
		"connect to %s fd:%d #%d", name, s, c->number);

    rc = connect(s, addr,  addr_sz);

    if (rc == -1) {
        err = ngx_socket_errno;

        if (err != NGX_EINPROGRESS)
        {
            if (err == NGX_ECONNREFUSED
#if (NGX_LINUX)
                /*
                 * Linux returns EAGAIN instead of ECONNREFUSED
                 * for unix sockets if listen queue is full
                 */
                || err == NGX_EAGAIN
#endif
                || err == NGX_ECONNRESET
                || err == NGX_ENETDOWN
                || err == NGX_ENETUNREACH
                || err == NGX_EHOSTDOWN
                || err == NGX_EHOSTUNREACH)
            {
                level = NGX_LOG_ERR;

            } else {
                level = NGX_LOG_CRIT;
            }

            ngx_log_error(level, c->log, err, "connect() to pipe %s failed",
                          name);

            ngx_close_connection(c);
            ngx_pipe->connection = NULL;

            return NGX_DECLINED;
        }
    }

    if (ngx_add_conn) {
        if (rc == -1) {

            /* NGX_EINPROGRESS */
        	ngx_pipe->connecting = 1;
            return NGX_AGAIN;
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_pipe->log, 0, "connected");

        wev->ready = 1;

        return NGX_OK;
    }

    if (ngx_event_flags & NGX_USE_AIO_EVENT) {

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, pcycle->log, ngx_socket_errno,
                       "connect(): %d", rc);

        /* aio, iocp */

        if (ngx_blocking(s) == -1) {
            ngx_log_error(NGX_LOG_ALERT, pcycle->log, ngx_socket_errno,
                          ngx_blocking_n " failed");
            goto failed;
        }

        /*
         * FreeBSD's aio allows to post an operation on non-connected socket.
         * NT does not support it.
         *
         * TODO: check in Win32, etc. As workaround we can use NGX_ONESHOT_EVENT
         */

        rev->ready = 1;
        wev->ready = 1;

        return NGX_OK;
    }

    if (ngx_event_flags & NGX_USE_CLEAR_EVENT) {

        /* kqueue */

        event = NGX_CLEAR_EVENT;

    } else {

        /* select, poll, /dev/poll */

        event = NGX_LEVEL_EVENT;
    }

    if (ngx_add_event(rev, NGX_READ_EVENT, event) != NGX_OK) {
        goto failed;
    }

    if (rc == -1) {

        /* NGX_EINPROGRESS */

        if (ngx_add_event(wev, NGX_WRITE_EVENT, event) != NGX_OK) {
            goto failed;
        }

        return NGX_AGAIN;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ngx_pipe->log, 0, "connected");

    wev->ready = 1;

    return NGX_OK;

failed:

    ngx_close_connection(c);
    ngx_pipe->connection = NULL;

    return NGX_ERROR;
}

static void ngx_http_navi_pipe_new_connect(void)
{
    /*建立pipe连接*/
    navi_pipe_mgr_t *pipe_mgr = nvup_pipe_mgr_get();
    if (pipe_mgr  == NULL || pipe_mgr ->hash == NULL){
        return;
    }
    chain_node_t *node = pipe_mgr ->new_conn_link.next;
    chain_node_t *next_node;
    while(node != &pipe_mgr ->new_conn_link){
        navi_pipe_t *pipe = ngx_queue_data(node, navi_pipe_t, new_conn_link);
        next_node = node->next;
        if (ngx_http_navi_pipe_connect(pipe) != NGX_ERROR){
            ngx_queue_remove(node);
            ngx_queue_init(node);
            if (pipe->status == NAVI_PIPE_STATUS_DISCONNECTED){
                navi_pipe_restart(pipe);
            }
            pipe->status = NAVI_PIPE_STATUS_CONNECTED;
        }

        ngx_http_navi_pipe_t *ngx_pipe= (ngx_http_navi_pipe_t *)(pipe->driver);
        ngx_add_timer(ngx_pipe->check_ev, pipe->check.ping_interval);

        node=next_node;
    }
}

static void ngx_http_navi_pipe_to_close(void)
{
    /*断开pipe连接*/
    navi_pipe_mgr_t *pipe_mgr = nvup_pipe_mgr_get();
    if (pipe_mgr  == NULL || pipe_mgr ->hash == NULL){
        return;
    }
    chain_node_t *node = pipe_mgr ->close_conn_link.next;
    chain_node_t *next_node;
    while(node != &pipe_mgr ->close_conn_link){
        next_node = node->next;
        navi_pipe_t *pipe = ngx_queue_data(node, navi_pipe_t, close_conn_link);

        ngx_http_navi_pipe_t *ngx_pipe = pipe->driver;
        if (ngx_pipe && ngx_pipe->connection){
            ngx_http_navi_pipe_close_connection(ngx_pipe);
        }
        ngx_queue_remove(node);
        ngx_queue_init(node);

        node = next_node;
    }
}

static void ngx_http_navi_pipe_to_write(void)
{
    navi_pipe_mgr_t *pipe_mgr = nvup_pipe_mgr_get();
    if (pipe_mgr  == NULL || pipe_mgr ->hash == NULL){
        return;
    }
    chain_node_t *node = pipe_mgr ->write_link.next;
    chain_node_t *next_node;
    while(node != &pipe_mgr ->write_link){
        next_node = node->next;
        navi_pipe_t *pipe = ngx_queue_data(node, navi_pipe_t, write_link);
        ngx_http_navi_pipe_t *ngx_pipe = pipe->driver;
	 if (ngx_pipe && ngx_pipe->connection) {
            ngx_event_t *wev = ngx_pipe->connection->write;
            if (wev->ready){
                ngx_http_navi_pipe_wev_handler(wev);
            }
            else if (ngx_handle_write_event(wev, 0) != NGX_OK){
                ngx_http_navi_pipe_close_connection(ngx_pipe);
            }
    	}
    	
        ngx_queue_remove(node);
        ngx_queue_init(node);
        node=next_node;
    }
}

static void ngx_http_navi_pipe_process(void)
{
    ngx_http_navi_pipe_new_connect();
    ngx_http_navi_pipe_to_close();
    ngx_http_navi_pipe_to_write();
}

static void ngx_http_navi_pipe_mgr_destroy(void)
{    
    ngx_queue_t*node =  ngx_pipe_mgr.next;
    ngx_queue_t *next_node;
    while(node != &ngx_pipe_mgr){
        next_node = node->next;
        ngx_http_navi_pipe_t *ngx_pipe = ngx_queue_data(node, ngx_http_navi_pipe_t, link);
 
        if (ngx_pipe->connection){
            ngx_close_connection(ngx_pipe->connection);
        }

        if (ngx_pipe->check_ev && ngx_pipe->check_ev->timer_set){
            ngx_del_timer(ngx_pipe->check_ev);
        }

        node=next_node;
    }
}

