/** \brief 
 * ngx_http_navi_module_util.c
 *  Created on: 2015-3-19
 *      Author: zoudaobing
 *  brief: 为文件和子进程监控提供驱动支持
 */

#define BUF_LEN  32768

static unsigned char event_buf[BUF_LEN];

extern ngx_int_t        ngx_process_slot;
extern ngx_int_t        ngx_last_process;
extern ngx_process_t    ngx_processes[NGX_MAX_PROCESSES];

static void dummy_write_handler(ngx_event_t * ev)
{
	return;
}

static ngx_connection_t* init_dummy_conn(void *data, int fd, ngx_event_handler_pt readhandler)
{
	ngx_connection_t *c = calloc(1,sizeof(ngx_connection_t));
	if (c == NULL) {
	   ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "calloc ngx_connection_t failed");
	   return NULL;
	}

	c->read = calloc(1,sizeof(ngx_event_t));
	if (c->read == NULL) {
	   ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "calloc ngx_event_t failed");
	   free(c);
	   return NULL;
	}

	c->write = calloc(1,sizeof(ngx_event_t));
	if (c->write == NULL) {
	   ngx_log_error(NGX_LOG_ERR, pcycle->log, 0, "calloc ngx_event_t failed");
	   free(c->read);
	   free(c);
	   return NULL;
	}
	
    if (ngx_nonblocking(fd) == -1) {
        ngx_log_error(NGX_LOG_ALERT, pcycle->log, errno,
                      "init_dummy_conn ngx_nonblocking failed");
    }

	c->fd = fd;
	c->data = data;
    c->log = pcycle->log;
	c->read->data = c;
	c->read->log = pcycle->log;
	c->read->handler = readhandler;

	c->write->data = c;
	c->write->log = pcycle->log;
	c->write->handler = dummy_write_handler;

	if (ngx_add_event(c->read, NGX_READ_EVENT, 0) == NGX_ERROR) {
		ngx_log_error(NGX_LOG_INFO, pcycle->log, 0, "add dummy conn read event failed");
		free(c->read);
		free(c->write);
		free(c);
		return NULL;
	}
	
	return c;	
}

static void destroy_dummy_conn(ngx_connection_t *c)
{
	if (c == NULL)
		return ;

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
	if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }

	if (ngx_del_conn) {
        ngx_del_conn(c, 0);

    } else {
        if (c->read->active || c->read->disabled) {
            ngx_del_event(c->read, NGX_READ_EVENT, 0);
        }
		if (c->write->active || c->write->disabled) {
            ngx_del_event(c->write, NGX_WRITE_EVENT, 0);
        }
    }

	if (c->read->prev) {
        ngx_delete_posted_event(c->read);
    }

    if (c->write->prev) {
        ngx_delete_posted_event(c->write);
    }

    close(c->fd);

	c->fd = -1;
    c->read->closed = 1;
    c->write->closed = 1;

	free(c->read);
	free(c->write);
	free(c);
}

static void file_event_handler(ngx_event_t *ev)
{
	ngx_connection_t    *c;
	navi_file_mon_t     *s;
    ssize_t             n;

	c = ev->data;
	s = c->data;

	if (c->destroyed)
		return;

	if (ev->timedout) {
		ngx_log_error(NGX_LOG_ERR, ev->log, 0, "file mon: read event timeout");
		return;
	}

	if (ev->timer_set) {
		ngx_del_timer(ev);
	}

	if (c->close) {
		ngx_log_error(NGX_LOG_ERR, ev->log, 0, "file mon: dummy conn closed");
		s->driver = NULL;
        destroy_dummy_conn(c);
        return;
    }

	for (;;) {
		n = read(c->fd,event_buf,BUF_LEN);
		ngx_log_debug2(NGX_LOG_DEBUG_EVENT, ev->log, 0,
               "read %d return %d",c->fd,n);

		if ( n == -1 ) {
			if ( errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}
			else {
				s->driver = NULL;
				destroy_dummy_conn(c);
				return;
			}
		}
		else if ( n == 0 ) {
			ngx_log_error(NGX_LOG_ERR, ev->log, 0, "file mon: notifyfd was closed");
			s->driver = NULL;
			destroy_dummy_conn(c);
			return;
		}
		else {
			file_event_dispatch(s,event_buf,n);
		}
	}
}

static void  cleanup_exec_driver(ngx_event_t *ev)
{
	ngx_connection_t   *c;
	c = ev->data;
	destroy_dummy_conn(c);
}

static void exec_event_handler2(ngx_event_t* ev)
{
	ngx_connection_t   *c;
	navi_exec_mon_t    *s;
	int                 i;

	c = ev->data;
	s = c->data;

    for (i = 0; i < ngx_last_process; i++) {
        if (ngx_processes[i].pid == s->pid) {
			s->status = ngx_processes[i].status;
			ngx_processes[i].pid = -1;//reset
            break;
        }
    }

	if (i == ngx_last_process) {
        ngx_log_error(NGX_LOG_ALERT, pcycle->log, 0,
              "can not find process info of %d",
              s->pid);
        s->status = -128;
	}

	ngx_post_event(ev, &ngx_posted_events);
	ev->handler = cleanup_exec_driver;
	navi_exec_child_dead(s);
}

static void exec_event_handler(ngx_event_t *ev)
{
	ngx_connection_t   *c;
	navi_exec_mon_t    *s;

	c = ev->data;
	s = c->data;

	int n = 0;
	int dead = 0;

	for (;;) {
		n = read(c->fd,event_buf,BUF_LEN);

		if ( n == -1 ) {
			if ( errno == EAGAIN || errno == EWOULDBLOCK) {
				return;
			}
			else {
				s->driver = NULL;
				dead = 1;
				break;
			}
		}
		else if ( n == 0 ) {
			s->driver = NULL;
			dead = 1;
			break;
		}
		else {
			navi_exec_child_output(s, event_buf, n);
		}
	}

	ev->handler = exec_event_handler2;
	ngx_event_add_timer(ev,10);
	return;
}

static void * file_mon_install(navi_file_mon_t *s)
{
	if (s->driver != NULL)
		return s->driver;
	return init_dummy_conn(s,s->notifyfd,file_event_handler);
}

static void exec_reg_process(pid_t pid, char *name, void *data)
{
	int s;
    for (s = 0; s < ngx_last_process; s++) {
        if (ngx_processes[s].pid == -1) {
            break;
        }
    }

    if (s == NGX_MAX_PROCESSES) {
        ngx_log_error(NGX_LOG_ALERT, pcycle->log, 0,
                      "no more than %d processes can be spawned",
                      NGX_MAX_PROCESSES);
        return ;
    }

    ngx_processes[s].proc = NULL;
    ngx_processes[s].data = data;
    ngx_processes[s].name = name;
    ngx_processes[s].exiting = 0;

    ngx_processes[s].pid = pid;
    ngx_processes[s].exited = 0;
    ngx_processes[s].respawn = 0;
    ngx_processes[s].just_spawn = 0;
    ngx_processes[s].detached = 1;
	
    if (s == ngx_last_process) {
        ngx_last_process++;
    }	
}

static void * exec_mon_install(navi_exec_mon_t *s)
{
	if (s->driver != NULL)
		return s->driver;
	exec_reg_process(s->pid,s->cmd_human,s);
	return init_dummy_conn(s,s->pipefd,exec_event_handler);
}

static void file_mon_uninstall(navi_file_mon_t *s)
{
	ngx_connection_t    *c;
	c = s->driver;
	destroy_dummy_conn(c);
	s->driver = NULL;
}

static ngx_int_t ngx_http_navi_init_util()
{
	file_mon_set(file_mon_install,file_mon_uninstall);
	navi_exec_mon_set(exec_mon_install);
	return 0;
}

