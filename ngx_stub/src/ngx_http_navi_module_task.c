/** \brief 
 * ngx_http_navi_module_util.c
 *  Created on: 2015-2-15
 *      Author: zoudaobing
 *  brief: 为task的网络连接和timer提供驱动支持
 */

extern ngx_cycle_t* pcycle;

static ngx_event_t *task_driver_timer = NULL;
void navi_driver_setup();

void navi_timer_driver_handler(ngx_event_t *ev)
{
    if (ev->timedout) {
        navi_timer_t *ptimer = (navi_timer_t *)(ev->data);
        ptimer->stick = 1;
        if (ptimer == NULL){
            return;
        }

        if (navi_timer_is_zombie(ptimer)){
        	ptimer->stick = 0;
            navi_timer_cleanup(ptimer);
            //ev->data = NULL;
            //free(ev);
            return;
        }
    
        navi_timer_timeout(ptimer);
        ptimer->stick = 0;
        if (navi_timer_is_zombie(ptimer)){
            navi_timer_cleanup(ptimer);
            //ev->data = NULL;
            //free(ev);
            return;
        }
        if (ptimer->type == NAVI_TIMER_INTERVAL &&  !ngx_exiting) {
            ngx_add_timer(ev,  ptimer->to_ms);
        }
    }
}



void* navi_timer_driver_install(navi_timer_t* timer)
{
	ngx_event_t *ev;
	ev = timer->driver_peer;
	if (ev == NULL) {

        ev = calloc(1, sizeof(ngx_event_t));
        if (ev == NULL) {
			ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "alloc event failed");
	   		return NULL;
        }

        ev->handler = navi_timer_driver_handler;
        ev->data = timer;
        ev->log = pcycle->log;
	}
	ngx_add_timer(ev, timer->to_ms);
	return ev;
}

void navi_timer_driver_cancel(navi_timer_t* timer)
{
	ngx_event_t *ev;
	ev = timer->driver_peer;
	if (ev == NULL)
		return;
	timer->driver_peer = NULL;
	ev->data = NULL;
	if (ev->timer_set)
		ngx_del_timer(ev);
	free(ev);
}

void* nvcli_parent_create_driver(nvcli_parent_t* parent)
{
	ngx_pool_t	*pool;
	pool = ngx_create_pool(256, pcycle->log);
    if (NULL == pool) {
        return NULL;
    }
	return pool;
}

void* nvcli_parent_get_driverpool(void* driver)
{
	return driver;
}

void nvcli_parent_cleanup_driver(void* driver)
{
	if (NULL != driver) {
		ngx_destroy_pool((ngx_pool_t*)driver);
	}
}

ngx_chain_t* alloc_chain_node(ngx_pool_t* pool)
{
	ngx_chain_t** pcl = &pool->chain;
	ngx_chain_t* cl = NULL;
	while (*pcl) {
		if ( (*pcl)->buf == NULL ||
				(*pcl)->buf->tag != navi_driver_setup) {
			pcl = &((*pcl)->next);
			continue;
		}
		else  {
			cl = *pcl;
			*pcl = (*pcl)->next;
			cl->next = NULL;
		}
	}
	
	if (!cl) {
		cl = ngx_alloc_chain_link(pool);
		cl->buf = ngx_pcalloc(pool,sizeof(ngx_buf_t));
		cl->buf->temporary = 1;
		cl->buf->tag = navi_driver_setup;
		cl->next = NULL;
	}
	return cl;
}


ngx_int_t make_buf_node(ngx_pool_t* pool,ngx_buf_t* buf, navi_buf_node_t* node)
{
	if (pool == NULL || node == NULL || buf == NULL) {
		return NGX_ERROR;
	}
	ngx_buf_t *b = buf;
	b->start = node->buf;

	if (node->infile) {
		ngx_fd_t  fd = node->fd;
		ngx_file_info_t fi;
		ngx_int_t rc = ngx_fd_info(fd, &fi);
		if (rc == NGX_FILE_ERROR)
			return NGX_ERROR;
		if (b->file == NULL)
			b->file = ngx_pcalloc(pool, sizeof(ngx_file_t));
	    if (b->file == NULL)
	        return NGX_ERROR;

	    b->file_pos = node->filepos;
		if (node->size == 0) {
		    b->file_last = ngx_file_size(&fi);
			node->size = b->file_last;//update navi buf node
		}
		else {
			b->file_last = node->filepos + node->size;
			//b->file_last = node->size;
		}
	    b->in_file = b->file_last ? 1: 0;
	    //b->last_buf = 1;
	    b->last_in_chain = 1;
		b->temporary = 0;
	    b->file->fd = fd;//TODO:name and log unset
	    b->file->directio = 0;
	}
	else {		
		b->pos = node->buf;
		b->last = ((u_char*)node->buf)+node->size;
		b->end = ((u_char*)node->buf)+node->capacity;
		b->temporary = 1;
	}
	return NGX_OK;
}

void destroy_conn(ngx_connection_t *c)
{
	if (NULL == c || c->destroyed)
		return;
	c->destroyed = 1;
	if (c->pool)
		ngx_destroy_pool(c->pool);
	ngx_close_connection(c);
}


void nvacnn_driver_read_handler(ngx_event_t *ev)
{
	ngx_connection_t    *c;
	navi_aconn_t        *ac;
	ngx_buf_t           *b;
	size_t              size;
    ssize_t             n;
	
	c = ev->data;
	ac = c->data;

	if (c->destroyed)
		return;

	if (ac->ready == 0) {
		nvacnn_has_problem(ac, NVCLI_CONNECTING_FAILED);
		ac->err = 1;
		return;
	}

	if (ev->timedout) {
		nvacnn_has_problem(ac,NVCLI_RESP_TIMEDOUT);
		return;
	}

	if (ev->timer_set) {
		ngx_del_timer(ev);
	}

	if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

	b = c->buffer;
	size = 4096;//default

	if (b == NULL) {
		b = ngx_create_temp_buf(c->pool, size);
		if (b == NULL) {
			ngx_log_error(NGX_LOG_INFO, ev->log, 0, "ngx_create_temp_buf failed");
			ngx_http_close_connection(c);
			return;
		}

		c->buffer = b;

	} else if (b->start == NULL) {

		b->start = ngx_palloc(c->pool, size);
		if (b->start == NULL) {
			ngx_log_error(NGX_LOG_INFO, ev->log, 0, "ngx_palloc read buf failed");
			ngx_http_close_connection(c);
			return;
		}

		b->pos = b->start;
		b->last = b->start;
		b->end = b->last + size;
	}

	for (;;) {
		n = c->recv(c, b->last, size);//每次读取放入b中，之前内容覆盖
		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
               "recv %d return %d",c->fd,n);
		if (n == NGX_AGAIN) {

			/*
			 * We are trying to not hold c->buffer's memory for an idle connection.
			*/
			if (ngx_pfree(c->pool, b->start) == NGX_OK) {
				b->start = NULL;
			}
			if (ac->zombie) {
				free(ac);
				return;
			}

			return;
		}

		if (n == NGX_ERROR) {
			nvacnn_has_problem(ac,NVCLI_BROKEN);
			return;
		}

		if (n == 0) {
			ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0,
						  "peer closed connection");
			nvacnn_has_problem(ac,NVCLI_PEER_CLOSE);
			return;
		}

		nvacnn_input_arrive(ac,b->last,n);
		if (ac->zombie) {
			free(ac);
			return;
		}

	}

}


void nvacnn_driver_write_handler(ngx_event_t *ev)
{
	ngx_connection_t    *c;
	navi_aconn_t        *ac;
	size_t               size;
	ngx_chain_t         *cl,*cn,*newchain;
	navi_buf_node_t		*ln;
	
	c = ev->data;
	ac = c->data;

	if (c->destroyed)
		return;

	if (ev->timedout) {
		if (ac->ready)
			nvacnn_has_problem(ac,NVCLI_SEND_TIMEDOUT);
		else
			nvacnn_has_problem(ac, NVCLI_CONNECTING_TIMEDOUT);
		return;
	}

	if (ev->timer_set) {
		ngx_del_timer(ev);
	}

	if (ac->err) {
		return;
	}
	else {
		ac->ready = 1;
	}

	if (c->close) {
        ngx_http_close_connection(c);
        return;
    }

	if (ac->out_buf != NULL) {
		/* link out buf to send chain*/
	    for (ln = *ac->out_buf->read_node; ln; ln = ln->next) {
	        cl = alloc_chain_node(c->pool);
	        if (cl == NULL) {
				ngx_log_error(NGX_LOG_INFO, ev->log, 0, "alloc_chain_node failed");
	            return ;
	        }

			if (make_buf_node(c->pool,cl->buf, ln) == NGX_ERROR) {
				ngx_free_chain(c->pool,cl);
				ngx_log_error(NGX_LOG_INFO, ev->log, 0, "make_buf_node failed");
				return;
			}

			*ac->busy_outbuflast = cl;
			ac->busy_outbuflast = (void**)&cl->next;
	        
			ac->out_buf->read_node = &ln->next;//update navi buf chain read pos
	    }
		*ac->busy_outbuflast = NULL;
	}

	size = 0;
	for (cl = ac->busy_outbuf; cl; cl = cl->next) {
		size += ngx_buf_size(cl->buf);
	}
	
    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
               "ready to write %d bytes to %d",size,c->fd);

	if (size == 0 || ac->busy_outbuf == NULL) {
		nvacnn_output_gone(ac);
		if (ac->zombie) {
			free(ac);
			return;
		}
		if (ac->app_write_status == 0x03) {//结束发送，取消可写事件监听
			ngx_del_event(ev, NGX_WRITE_EVENT, 0);
		}
		return;
	}

	newchain = c->send_chain(c, ac->busy_outbuf, NGX_MAX_SIZE_T_VALUE);//unlimited

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ev->log, 0,
                   "http send chain return %p", newchain);
	
    if (newchain == NGX_CHAIN_ERROR) {
        c->error = 1;
		nvacnn_has_problem(ac,NVCLI_BROKEN);
		return;
    }
	else {
		if (newchain == NULL) {
			navi_buf_chain_recycle_readed(ac->out_buf/*,NULL,NULL*/);
			nvacnn_output_gone(ac);
			if (ac->zombie) {
				free(ac);
				return;
			}
			if (ac->app_write_status == 0x03) {//结束发送，取消可写事件监听
				ngx_del_event(ev, NGX_WRITE_EVENT, 0);
			}
		}
		else {
			
			if (newchain->buf->in_file)
				navi_buf_chain_recycle(ac->out_buf,newchain->buf->start/*,(size_t*)&newchain->buf->file_pos*/);
			else {
				//size_t oldsize = newchain->buf->last-newchain->buf->start;
				navi_buf_chain_recycle(ac->out_buf,newchain->buf->start/*,&oldsize*/);
				//newchain->buf->last = ((u_char*)newchain->buf->start)+oldsize;
			}
		}
	}

	for (cl = ac->busy_outbuf; cl && cl != newchain; /* void */) {
        cn = cl;
        cl = cl->next;
		ngx_free_chain(c->pool,cn);
	}

	ac->busy_outbuf = newchain;
	if (ac->busy_outbuf == NULL)
        ac->busy_outbuflast = &ac->busy_outbuf;
	
	return;
}


void* nvacnn_driver_install(navi_aconn_t* conn)
{
	ngx_int_t		   rc;
	ngx_connection_t * c;
	ngx_peer_connection_t *pc;
	ngx_pool_t                 *pool;
	
	pool = ngx_create_pool(2048, pcycle->log);
    if (pool == NULL) {
       ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "create pool failed");
	   return NULL;
    }

	pc = ngx_pcalloc(pool, sizeof(ngx_peer_connection_t));
	if (pc == NULL) {
	   ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "alloc ngx_peer_connection_t failed");
	   return NULL;
	}

	pc->sockaddr = &conn->peer_addr;
	switch(pc->sockaddr->sa_family) {
	case AF_INET:
		pc->socklen = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		pc->socklen = sizeof(struct sockaddr_in6);
		break;
	case AF_UNIX:
		pc->socklen = strlen(((struct sockaddr_un*)pc->sockaddr)->sun_path) + sizeof(((struct sockaddr_un*)pc->sockaddr)->sun_family);
		break;
	default:
		pc->socklen = sizeof(struct sockaddr);
		break;
	}

	pc->name = ngx_pcalloc(pool, sizeof(ngx_str_t));
	if (pc->name == NULL) {
       ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "alloc ngx_str_t failed");
	   return NULL;
    }
	pc->name->data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
    if (pc->name->data == NULL) {
        ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "alloc sockaddr str failed");
			return NULL;
    }

#if nginx_version >= 1006002 
    pc->name->len = ngx_sock_ntop(pc->sockaddr, pc->socklen,
                             pc->name->data,
                             NGX_SOCKADDR_STRLEN, 0);
#else
	pc->name->len = ngx_sock_ntop(pc->sockaddr, pc->name->data,
								 NGX_SOCKADDR_STRLEN, 0);
#endif

    if (pc->name->len == 0) {
        ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "ngx_sock_ntop failed");
		return NULL;
    }

    pc->get = ngx_event_get_peer;
	pc->log = pcycle->log;
    pc->log_error = NGX_ERROR_ERR;

	rc = ngx_event_connect_peer(pc);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "ngx_event_connect_peer %V ret %d",pc->name,rc);
		return NULL;
    }
    
	c = pc->connection;
	c->data = conn;
    c->write->handler = nvacnn_driver_write_handler;
    c->read->handler = nvacnn_driver_read_handler;
	c->sendfile = 1;
	c->read->log = c->log;
	c->read->data = c;
    c->write->log = c->log;
	c->write->data = c;
	c->pool = pool;
	conn->driver = c;
	if (rc == NGX_AGAIN) {
        conn->app_write_status = 0x02;//添加写监听
        ngx_add_timer(c->write, conn->conn_timeout_ms);
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
           "connect to %V in progress", pc->name);
    }
	else {
		ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
           "connect to %V success", pc->name);
	}
	return c;
}

void nvacnn_driver_close(navi_aconn_t* conn)
{
	if (NULL != conn->driver) {
		ngx_connection_t* c = (ngx_connection_t*)conn->driver;
		conn->driver = NULL;
		destroy_conn(c);
	}
}

void nvacnn_driver_set_idle(navi_aconn_t* conn, int idle_timeout_ms)
{
	ngx_connection_t *c = conn->driver;
    //app_input_handler在加入idle链表时已设为nvacnn_input_unexpected
    //所以不需修改连接的read_handler，也不需要取消读事件监听
    //最终连接由空闲超时触发关闭，或者意外数据到达(包括对端关闭)导致关闭
	ngx_add_timer(c->read,idle_timeout_ms);
}

void nvacnn_driver_quit_idle(navi_aconn_t* conn)
{
	ngx_connection_t *c = conn->driver;
	ngx_event_t * rev = c->read;
	if (rev->timer_set)
		ngx_del_timer(rev);
}

void navi_driver_timeout_handler(ngx_event_t *ev)
{
	nvcli_parents_drive(nvcli_parent_create_driver,nvcli_parent_get_driverpool,nvcli_parent_cleanup_driver);
}

void navi_driver_setup() 
{
	if (task_driver_timer == NULL) {
		task_driver_timer = ngx_pcalloc(pcycle->pool, sizeof(ngx_event_t));
        if (task_driver_timer == NULL) {
			ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "alloc event failed");
	   		return ;
        }

        task_driver_timer->handler = navi_driver_timeout_handler;
        task_driver_timer->data = pcycle->connections;//for debug
        task_driver_timer->log = pcycle->log;

	}
	ngx_post_event(task_driver_timer, &ngx_posted_events);
}


void nvacnn_driver_process(navi_aconn_t* conn)
{
	ngx_connection_t    *c;
	ngx_event_t       *rev, *wev;
	
	c = conn->driver;
	if (c == NULL) {
		ngx_log_error(NGX_LOG_INFO, pcycle->log, 0, "connection not init yet");
        return ;
	}
	
	rev = c->read;
	if (conn->app_reading_status == 0x01 && !rev->active) {
		if (ngx_add_event(rev, NGX_READ_EVENT, 0) == NGX_ERROR) {
			ngx_log_error(NGX_LOG_INFO, rev->log, 0, "add read event failed");
			return ;
		}
	}

	wev = c->write;
	if ((conn->app_write_status == 0x01 || conn->app_write_status == 0x02) && (!wev->active || !wev->ready)) {
		if (ngx_add_event(wev, NGX_WRITE_EVENT, 0) == NGX_ERROR) {
			ngx_log_error(NGX_LOG_INFO, wev->log, 0, "add write event failed");
    	}
	}
}
