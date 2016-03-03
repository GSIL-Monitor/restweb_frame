/*
 * ngx_http_navi_module.c
 *
 *  Created on: 2013-9-23
 *      Author: yanguotao@youku.com
 */
#include <assert.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <cnavidriver/navi_module_driver.h>
#include <cnavidriver/navi_module_mgr.h>
#include <cnavidriver/navi_request_driver.h>
#include <cnaviproxy/navi_upgroup_mgr.h>
#include <cnaviproxy/navi_vevent_mgr.h>
#include <cnaviproxy/navi_pipe.h>
#include <cnavitask/navi_task_mgr.h>
#include <cnavitask/navi_grcli.h>
#include <cnavitask/navi_async_conn.h>

#include <cnaviutil/file_monitor.h>
#include <cnaviutil/exec_util.h>

#include <cnavi/navi_list.h>

#include <ngx_http_navi_module.h>
#include <ngx_http_navi_module_task.c>
#include <ngx_http_navi_module_util.c>
#include <ngx_http_navi_module_setup.c>

#include <ngx_http_navi_module_upstream.c>
#include <ngx_http_navi_module_pipe.c>
#include <ngx_http_navi_module_bigpost.c>


extern bool navi_is_symbol_word(const char* word);

static ngx_event_t *navi_req_rest_driver_ev = NULL;

static void ngx_http_navi_request_rest_driver_trigger();
static navi_root_run_e ngx_http_navi_root_run_impl(navi_request_t* root, bool trig_ve, bool trig_app);
static void ngx_http_navi_check_emerg_resp(navi_request_t* main_req);

static void ngx_http_navi_streaming_resp_proc(navi_request_t* navi);

/*将post请求的buf设置到cnavi*/
static ngx_int_t ngx_http_navi_process_postbuf(navi_request_t *navi_req, ngx_http_request_t* r)
{
    ngx_chain_t         *cl;
    ngx_buf_t* postbuf = NULL;
    ngx_int_t rc;
    if (r->method != NGX_HTTP_POST){
        return NGX_ERROR;
    }

    if (r->request_body == NULL || r->request_body->bufs == NULL){
        return NGX_ERROR;
    }
    for (cl = r->request_body->bufs; cl; cl = cl->next) {
        postbuf =  cl->buf;  
        ngx_int_t postlen = ngx_buf_size(postbuf);
        if (postlen > 0){            
            if(ngx_buf_in_memory(postbuf)) {
                rc = navi_http_request_append_post(navi_req, postbuf->pos, postlen);
                if (rc != NGX_OK){
                    return rc;		
                }
            } else if ((NULL != r->request_body->temp_file) 
            		&& (NGX_INVALID_FILE != r->request_body->temp_file->file.fd)){
            	 u_char* post = ngx_palloc(r->pool, postlen+1);	
                ssize_t nread = ngx_read_file(&(r->request_body->temp_file->file), post, postlen, 0);
                post[nread] = '\0';
                return navi_http_request_append_post(navi_req, post, postlen);
            } 
        }
    }

    return NGX_OK;
}

/*获取根navi req对应的ngx_http_request*/
static ngx_http_request_t * ngx_http_navi_get_root_req(navi_request_t *req)
{
    if (req == NULL){
        return NULL;
    }
    navi_request_t *root = navi_request_get_root(req);
    return (ngx_http_request_t*)navi_request_get_driver_peer(root);	
}

static void move_upgrade_configs(ngx_conf_t* cf) {
	DIR* dir = NULL;
	struct dirent* file_dirent;
	ngx_http_navi_main_conf_t* mcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_navi_module);
	if (mcf==NULL)
		return;
	if (mcf->navi_directory.len==0)
		return;
	char conf_path[1024];
	char tmp_path[1024];
	char new_path[1024];
	struct stat stbuf;
	snprintf(conf_path,sizeof(conf_path),"%.*s/conf_upgrade",
		(int)mcf->navi_directory.len, (char*)mcf->navi_directory.data);

	dir = opendir(conf_path);
	if (!dir) {
		return;
	}

	while ((file_dirent = readdir(dir))) {
		if (strlen(file_dirent->d_name) <= strlen(".json"))
			continue;
		if (strcmp(".json",
			file_dirent->d_name + strlen(file_dirent->d_name) - strlen(".json"))
			!= 0)
			continue;

		snprintf(tmp_path, sizeof(tmp_path), "%s/%s", conf_path,
			file_dirent->d_name);
		if (-1 == stat(tmp_path, &stbuf))
			continue;

		if (!S_ISREG(stbuf.st_mode))
			continue;

		json_error_t js_err;
		json_t* cf = json_load_file(tmp_path,&js_err);
		json_t* je = json_object_get(cf, "module_name");
		const char *mod_nm = NULL;
		if (je && json_is_string(je)) {
			mod_nm = json_string_value(je);
		}
		if (mod_nm==NULL || !navi_is_symbol_word(mod_nm)) {
			json_decref(cf);
			continue;
		}
		json_decref(cf);

		snprintf(new_path, sizeof(new_path), "%.*s/%s", (int)mcf->navi_directory.len,
			(char*)mcf->navi_directory.data, file_dirent->d_name);
		rename(tmp_path, new_path);
	}

	closedir(dir);
}

/*装载filter,在post configuraton的时候被调用
* 主要用于劫持子请求的响应
*/
static ngx_int_t ngx_http_navi_post_config(ngx_conf_t *cf)
{
    next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_navi_header_filter;

    next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_navi_body_filter;

    move_upgrade_configs(cf);

    return NGX_OK;
}

/*header filter,对于本模块的子请求，强制响应体保存在内存中*/
static ngx_int_t ngx_http_navi_header_filter(ngx_http_request_t *r) 
{
    ngx_http_post_subrequest_t      *psr;
    ngx_http_navi_ctx_t              *old_ctx;
    ngx_http_navi_ctx_t              *ctx;
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    psr = r->post_subrequest;
       	
    if (psr != NULL
    	&& psr->handler == ngx_http_navi_sr_end_handler
    	&& psr->data != NULL)
    {
        old_ctx = psr->data;
    
        if (ctx == NULL) {
            ctx = old_ctx;
            ngx_http_set_ctx(r, ctx, ngx_http_navi_module);
        } else {	
            psr->data = ctx;
        }
    }
    
    //对于子请求，跳过后续的Header filter
    if (ctx && (ctx->navi_req) !=NULL && (ctx->navi_req)  != navi_request_get_root(ctx->navi_req)) {
        /* 使子请求的响应体在内存中 */
        r->filter_need_in_memory = 1;
        r->main->count++;
        return NGX_OK;
    }
    
    return next_header_filter(r);
}

/*将子请求的响应体拷贝到navi request的响应体*/
static ngx_int_t ngx_http_navi_copy_chain(navi_request_t *req, ngx_chain_t *in)
{
    ngx_chain_t     *cl;

    for (cl = in; cl; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            if (navi_http_response_append_body(req, cl->buf->pos, cl->buf->last - cl->buf->pos) 
                    != NAVI_OK){
                return NGX_ERROR;
            }
        }
    }

    return NGX_OK;
}

/*对于子请求，将响应体拷贝到navi request的响应体*/
static ngx_int_t ngx_http_navi_body_filter(ngx_http_request_t *r, ngx_chain_t *in) 
{
    ngx_int_t                        rc;
    ngx_http_navi_ctx_t       *ctx;
    navi_request_t               *req;
    ngx_http_navi_ctx_t       *pr_ctx;
    
    if (in == NULL) {
    	return next_body_filter(r, NULL);
    }
    
    ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    
    if (!ctx ) {
    	return next_body_filter(r, in);
    }

    req = ctx->navi_req;
    if (req == NULL){
        return NGX_ERROR;
    }

    ngx_http_request_t *pr = ngx_http_navi_get_root_req(req);
    if (pr == NULL){
         return NGX_ERROR;
    }

    if (r == pr || r == r->main){
        return next_body_filter(r, in);
    }

    pr_ctx = ngx_http_get_module_ctx(r->parent, ngx_http_navi_module);
    if (pr_ctx == NULL) {
        return NGX_ERROR;
    }
    
    rc = ngx_http_navi_copy_chain(req, in);
    
    for (; in; in = in->next) {
        in->buf->pos = in->buf->last;
        in->buf->file_pos = in->buf->file_last;
    }
    
    return NGX_OK;
}

/*将navi request设置的post请求内容设置到ngx_http_request中*/
static  ngx_int_t  ngx_http_navi_set_post(ngx_http_request_t *r, 
	const u_char *post_content, ngx_int_t post_len)
{
    ngx_http_request_body_t         *body;
    if (post_len <= 0){
        return NGX_ERROR;	
    }
	
    body = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    
    if (body == NULL) {
        return NGX_ERROR;
    }

    r->method_name.len = 4;
    r->method_name.data = (u_char *)"POST ";
    r->method = NGX_HTTP_POST;

    ngx_buf_t *b = ngx_create_temp_buf(r->pool, post_len);
    if (b == NULL) {
        return NGX_ERROR;
    }

    b->last = ngx_copy(b->last, post_content, post_len);

    body->bufs = ngx_alloc_chain_link(r->pool);
    if (body->bufs == NULL) {
        return NGX_ERROR;
    }

    body->bufs->buf = b;
    body->bufs->next = NULL;

    body->buf = b;
    r->request_body = body;

    r->headers_in.content_length_n = post_len;

    return NGX_OK;
}

static void ngx_http_navi_cleanup_navi_req(void* cln_data)
{
	navi_request_t* main_req = cln_data;
	navi_request_free(main_req);
}

/*将ngx_http_request的相关信息设置到navi request*/
static navi_request_t * ngx_http_navi_build_request(ngx_http_request_t* r)
{
    ngx_int_t rc;
    navi_request_t*navi_req = navi_request_init();
    if (navi_req == NULL){
        return NULL;
    }
    char* uri = ngx_palloc(r->pool,r->uri.len+1);
    ngx_memcpy(uri,r->uri.data,(size_t)r->uri.len);
    uri[r->uri.len] = '\0';
    rc = navi_http_request_set_uri(navi_req, uri,  0);
    if (rc != NAVI_OK){
        navi_request_free(navi_req);
        return NULL;
    }

    ngx_http_core_loc_conf_t*  loc_conf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    if(	NAVI_OK != navi_request_parse_main_uri(navi_req, (const char*)loc_conf->name.data, loc_conf->name.len) ) {
    	 navi_request_free(navi_req);
    	return NULL;
    }

    if(r->args.len > 0){
        char* args = ngx_palloc(r->pool,r->args.len+1);
        ngx_memcpy(args,r->args.data,(size_t)r->args.len);
        args[r->args.len] = '\0';
        rc = navi_http_request_set_args_raw(navi_req, args);
        if (rc != NAVI_OK){
            navi_request_free(navi_req);
            return NULL;
        }
    }
    
    char *cli_ip = NULL;
    {
        ngx_list_t* headersin = &(r->headers_in.headers);
        ngx_list_part_t *part = &(headersin->part);
        ngx_table_elt_t * header = part->elts;
        ngx_uint_t i;
        for (i = 0; /* void */; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }
            if( (header+i)->key.data) {
                if( strcasecmp((char*)(header+i)->key.data,"x-caller")==0){
                    rc = navi_request_set_xcaller(navi_req, (const char*)(header+i)->value.data);
                    if (rc != NAVI_OK){
                        navi_request_free(navi_req);
                        return NULL;
                    }
                }
                else if (strcasecmp((char*)(header+i)->key.data,"host") == 0)
                    continue;
                //else if (strcasecmp((char*)(header+i)->key.data,"content-length") == 0)
            	//	continue;
                else if (strcasecmp((char*)(header+i)->key.data,"connection") == 0)
                    continue;
                else if (strcasecmp((char*)(header+i)->key.data,"transfer-encoding") == 0)
                    continue;

                navi_http_request_set_header(navi_req,(const char*)(header+i)->key.data,(const char*)(header+i)->value.data);
            }
        }
    }
    
    if(r->connection->addr_text.len){
        cli_ip = ngx_palloc(r->pool,r->connection->addr_text.len+1);
        ngx_memcpy(cli_ip,r->connection->addr_text.data,r->connection->addr_text.len);
        cli_ip[r->connection->addr_text.len] = 0;
        rc = navi_request_set_cli_ip(navi_req, cli_ip);
        if (rc != NAVI_OK){
            navi_request_free(navi_req);
            return NULL;
        }
    }

    //if (r->method == NGX_HTTP_POST){
     //   ngx_http_navi_process_postbuf(navi_req, r);
    //}
    
    if ( navi_req ) {
    	ngx_http_cleanup_t* cln = ngx_http_cleanup_add(r,0);
    	cln->data =  navi_req;
    	cln->handler = ngx_http_navi_cleanup_navi_req;
    }

    return navi_req;
}

static void ngx_http_navi_ve_handler(navi_vevent_t *ve, navi_request_t* source_root)
{
	navi_vevent_action_e action = ve->proc(ve);
	navi_vhandler_status_e status;
	void* it;
	navi_vehandler_t *vh;
	navi_request_t *navi_req;
 	navi_vevent_triggered(ve);
 	if (action == NAVI_VE_TRIGGER_ONE){
 		it = navi_vevent_vh_it(ve);
 		while ( (vh=navi_vevent_vh_it_next(it)) ) {
 			navi_req = vh->binded_req;
 			navi_request_drive_flag(navi_req, NAVI_REQ_DRIVE_VEVENT_HANDLER);
			status = vh->handler(navi_req, ve, vh->ctx, ve->trigger_data);
			if (status == NAVI_VH_DENY){
				continue;
			}
			else if (status == NAVI_VH_ACCEPT){
				navi_vehandler_cancel(vh);
				if ( navi_req != source_root) {
					ngx_http_navi_root_run(navi_req, false, true);
				}
				break;
			}
			else if (status == NAVI_VH_ACCEPT_HOLD){
				if ( navi_req != source_root) {
					ngx_http_navi_root_run(navi_req, false, true);
				}

				break;
			}
 		}
 		navi_vevent_vh_it_destroy(it);
	}
	else if (action == NAVI_VE_TRIGGER_ALL){
		it = navi_vevent_vh_it(ve);
		while ( (vh=navi_vevent_vh_it_next(it)) ) {
			navi_req = vh->binded_req;
 			navi_request_drive_flag(navi_req, NAVI_REQ_DRIVE_VEVENT_HANDLER);
			status = vh->handler(navi_req, ve, vh->ctx, ve->trigger_data);
			if (status == NAVI_VH_ACCEPT){
				navi_vehandler_cancel(vh);
			}
			if (status != NAVI_VH_DENY){
				if ( navi_req != source_root) {
					ngx_http_navi_root_run(navi_req,false, true);
				}
			}
		}
		navi_vevent_vh_it_destroy(it);
 	}
}

static void ngx_http_navi_ve_process(navi_request_t* source_root){
    navi_vevent_mgr_t *ve_mgr = navi_vevent_mgr_get();

    if (ve_mgr == NULL || ve_mgr->hash == NULL){
        return;
    }
    
    chain_node_t *node =  ve_mgr->ready_link.next;
    while(node != &ve_mgr->ready_link){
        navi_vevent_t *ve = navi_list_data(node, navi_vevent_t, status_link);
        //next_node = node->next;
        assert( ve->status == NAVI_VE_READY );
        assert( ve->_magic == NAVI_VE_MAGIC );
        ngx_http_navi_ve_handler(ve,source_root);
        node=ve_mgr->ready_link.next;
    }
}

/*子请求结束的回调处理，
*设置http响应状态，并调用navi的处理
*之后需要再添加子请求
*对取消的子请求，需要结束，如果子请求
*为upstream类型，需要再结束前调用upstream的清除函数
*当所有子请求结束时调用ngx_http_navi_main_end_handler
*/
static ngx_int_t ngx_http_navi_sr_end_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_int_t status;
    ngx_http_navi_ctx_t* req_ctx;
    navi_request_t* navi;
    navi_request_t* root;

    if (data == NULL){
        return NGX_ERROR;
    }

    req_ctx = (ngx_http_navi_ctx_t *)data;
    if (req_ctx->processed){
        return NGX_OK;
    }
    req_ctx->processed = 1;
    navi = req_ctx->navi_req;

    if ( NAVI_REQUEST_CANCEL_REGISTED == navi_request_get_status(navi) ) {
    	navi_request_set_status(navi, NAVI_REQUEST_CANCELED);
    	return NGX_OK;
    }


    status = r->headers_out.status;
    if (status == 0){
        navi_http_response_set_status(navi, rc);
    }
    else{
        navi_http_response_set_status(navi, status);
    }

    root = navi_request_get_root(navi);
    navi_request_drive_flag(root, NAVI_REQ_DRIVE_SUBREQ_HANDLER);
    navi_request_call_process(navi);
    ngx_http_request_t*  ngx_root = navi_request_get_driver_peer(root);
    navi_root_run_e ret = ngx_http_navi_root_run_impl(root, true, true);
	switch (ret) {
	case NAVI_ROOT_RUN_COMPLETE:
		if (ngx_root != ngx_root->main){
			ngx_root->write_event_handler = ngx_http_handler;
			ngx_http_navi_main_end_handler(ngx_root);
		}
		else {
			ngx_root->write_event_handler = ngx_http_navi_main_end_handler;
		}
		break;
	case NAVI_ROOT_RUN_NEW_SUBS:
		break;
	default:
		break;
	}

    return NGX_OK;
}

/*主请求结束时的最终输出，
* 从cnavi模块获取响应体进行输出
*/
static ngx_int_t ngx_http_navi_main_end_handler_common(ngx_http_request_t* r)
{
	static ngx_str_t nv_std_resp_type = ngx_string("text/plain");
	//static ngx_str_t unknown_resp_type = ngx_string("application/octet-stream");

    ngx_http_navi_ctx_t* req_ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    ngx_event_t *ev= (ngx_event_t *)req_ctx->req_timeout_ev;
    if (ev != NULL && ev->timer_set) {
        ngx_del_timer(ev);
        req_ctx->req_timeout_ev = NULL;
    }

    ngx_chain_t	*p_out_chain = NULL;
    navi_request_t* main_req = navi_request_get_root(req_ctx->navi_req);
    if(r->header_sent)
        goto done;

    ngx_int_t rc;
    ngx_int_t len = 0;
    ngx_int_t http_status;
    char *resp_content = NULL;
    navi_respbody_type_e  nv_resp_type = navi_request_respbody_type(main_req);
    //if (nv_resp_type == NAVI_RESP_STREAM ) {
    //	goto done;
    //}

    ngx_str_t* p_contenttype = NULL;
    ngx_buf_t*	b=NULL;
    http_status = navi_http_response_get_status(main_req);
    if (http_status == 0)
    	http_status = 200;
    if ( nv_resp_type == NAVI_RESP_NAVI_STANDARD) {
    	p_contenttype = &nv_std_resp_type;
    }

    void *it = navi_http_response_header_iter(main_req);
    const char* arg, *val;
    ngx_str_t  key, value;
    while ((arg = navi_http_response_header_iter_next(it,&val))) {
    	key.len = strlen(arg);
    	key.data = (u_char*)arg;
    	value.len = strlen(val);
    	value.data = (u_char*)val;
    	if ( strcasecmp(arg, "content-type") == 0 ) {
    		p_contenttype = NULL;
    	}
    	else if ( strcasecmp(arg, "connection") == 0 ) {
    		if ( strcmp(val, "close") == 0 ) {
    			r->keepalive = 0;
    		}
    		else if ( strcmp(val, "keep-alive") == 0) {
    			r->keepalive = 1;
    		}
    		continue;
    	}
    	ngx_http_navi_add_header_out(r, &key, &value);
    }
    navi_http_response_header_iter_destroy(it);

    if( nv_resp_type != NAVI_RESP_FILE){
        len =  navi_http_response_get_body(main_req, (const uint8_t**)&resp_content);
        if (len > 0){
        	p_out_chain = ngx_alloc_chain_link(r->pool);
        	if ( !p_out_chain )
        		return NGX_ERROR;

        	b = ngx_calloc_buf(r->pool);

            if (b == NULL){
                return NGX_ERROR;
            }

            b->pos = b->start = (u_char*)resp_content;
            b->last = b->end = b->pos + len;
            b->last_buf = 1;
            b->temporary = 1;
            p_out_chain->buf = b;
            p_out_chain->next = NULL;
        }
    }
    else{
        int fd = navi_request_respbody_filefd(main_req);
        if(fd > 0){
            struct stat st;
            memset(&st, 0, sizeof(st));
            if(!ngx_fd_info(fd, &st)){
            	p_out_chain = ngx_alloc_chain_link(r->pool);
				if ( !p_out_chain )
					return NGX_ERROR;

                len = st.st_size;
                b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
                if(!b) return NGX_ERROR;
                b->last_buf = 1;
                b->in_file = 1;
                b->file_pos = 0;
                b->file_last = st.st_size;
                b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
                if(!b->file) return NGX_ERROR;
                b->file->fd = fd;
                b->file->log = r->connection->log;
                p_out_chain->buf = b;
                p_out_chain->next = NULL;
            }
        }
        else {
        	len = 0;
        	p_contenttype = NULL;
        	http_status = 500;
        }
    }

    //ngx_http_set_ctx(r, NULL, ngx_http_navi_module);
     //输出响应
    rc = ngx_http_navi_respond_header(r,p_contenttype,len,http_status,NULL);
    if ( rc == NGX_ERROR ) {
    	return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
done:
	if ( navi_request_incomplete(main_req) ) {
		rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
		ngx_http_output_filter(r,p_out_chain);
		return rc;
	}
	else
		return ngx_http_output_filter(r,p_out_chain);
}

/*主请求结束时的最终处理
*ngx_http_navi_main_end_handler_common是没有子请求的调用
*/
static void ngx_http_navi_main_end_handler(ngx_http_request_t* r)
{
    ngx_int_t rc = NGX_OK;

    ngx_http_navi_ctx_t* ngx_ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    int run_in_entrance = ngx_ctx->run_in_entrance;
   
    rc = ngx_http_navi_main_end_handler_common(r);
    ngx_http_send_special(r,NGX_HTTP_LAST);
    r->count=1;
    if ( run_in_entrance == 0 )
    	ngx_http_finalize_request(r, rc);
}

/*添加子请求*/
static ngx_int_t ngx_http_navi_add_subrequest(ngx_http_request_t *r, navi_request_t *sub, ngx_uint_t flags)
{
    ngx_time_t                    *tp;
    ngx_connection_t              *c;
    ngx_http_request_t            *sr;
    ngx_http_post_subrequest_t *ps;
    ngx_str_t* uri_query;
    ngx_http_core_srv_conf_t      *cscf;
    ngx_http_navi_ctx_t *ctx;
  
    sr = ngx_pcalloc(r->pool, sizeof(ngx_http_request_t));
    if (sr == NULL) {
        return NGX_ERROR;
    }

    sr->signature = NGX_HTTP_MODULE;

    c = r->connection;
    sr->connection = c;
    sr->pool = r->pool;
	
    sr->ctx = ngx_pcalloc(sr->pool, sizeof(void *) * ngx_http_max_module);
    if (sr->ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_list_init(&sr->headers_in.headers, sr->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }
	
    if (ngx_list_init(&sr->headers_out.headers, sr->pool, 20,
                      sizeof(ngx_table_elt_t))
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    sr->main_conf = cscf->ctx->main_conf;
    sr->srv_conf = cscf->ctx->srv_conf;
    sr->loc_conf = cscf->ctx->loc_conf;

    ngx_http_clear_content_length(sr);
    ngx_http_clear_accept_ranges(sr);
    ngx_http_clear_last_modified(sr);

    sr->method = NGX_HTTP_GET;
    sr->http_version = r->http_version;

    sr->request_line = r->request_line;
    ngx_int_t uri_len = navi_http_request_get_uri_query(sub,  NULL, 0);	
    uri_query = ngx_palloc(sr->pool, sizeof(*uri_query)+uri_len+1);
    uri_query->data = (u_char*)(uri_query+1);
    uri_query->len = uri_len+1;
    uri_query->len =  navi_http_request_get_uri_query(sub,  (char *)(uri_query->data), uri_query->len);	
    sr->uri = *uri_query;
    sr->uri_end = sr->uri.data + sr->uri.len;
    u_char *p = (u_char *)strstr((char *)(sr->uri.data), "?") ;
    if (p != NULL){
        sr->args_start = ++p;    
        sr->args.len = sr->uri_end  - sr->args_start;
        sr->args.data = sr->args_start;
        sr->args_start = NULL;
        sr->uri.len -= (sr->args.len+1);
    }
    u_char *dst, *src;
    dst=src= sr->uri.data;
    ngx_unescape_uri(&dst, &src, sr->uri.len, NGX_UNESCAPE_URI);
    *dst='\0';
    sr->uri.len = dst -sr->uri.data;
    sr->uri_end = dst;
	
    ngx_log_debug(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http subrequest \"%V\"", uri_query);

    sr->subrequest_in_memory = (flags & NGX_HTTP_SUBREQUEST_IN_MEMORY) != 0;
    sr->waited = (flags & NGX_HTTP_SUBREQUEST_WAITED) != 0;

    sr->unparsed_uri = r->unparsed_uri;
    sr->method_name = ngx_http_core_get_method;
    sr->http_protocol = r->http_protocol;

    void *it = navi_http_request_header_iter(sub);
    const char* arg, *val;
    ngx_str_t  key, value;
    while ((arg = navi_http_request_header_iter_next(it,&val))) {
        key.len = strlen(arg);
        key.data = (u_char*) ngx_pcalloc(sr->pool, key.len);
        ngx_memcpy(key.data, arg, key.len);
        value.len = strlen(val);
        value.data = (u_char*) ngx_pcalloc(sr->pool, value.len);
        ngx_memcpy(value.data, val, value.len);
        ngx_http_navi_add_header_in(sr, &key, &value);
    }
    navi_http_request_header_iter_destroy(it);

    const u_char *post_content;
    ngx_int_t post_len;
    post_len = navi_http_request_get_post(sub, &post_content);

    if (post_len > 0){
        ngx_http_navi_set_post(sr, post_content, post_len);
    }
    ngx_http_set_exten(sr);

    ctx = ngx_pcalloc(sr->pool, sizeof(ngx_http_navi_ctx_t) );
    if (sr->ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->navi_req = sub;
    navi_request_set_driver_peer(sub, sr, NULL);
    ngx_http_set_ctx(sr, ctx, ngx_http_navi_module);

    ps = ngx_pnalloc(sr->pool, sizeof(ngx_http_post_subrequest_t));
    ps->handler = ngx_http_navi_sr_end_handler;
    ps->data = ctx;

    sr->main = r->main;
    sr->parent = r->main;
    sr->post_subrequest = ps;
    sr->read_event_handler = ngx_http_request_empty_handler;
    sr->write_event_handler = ngx_http_handler;

    ngx_http_core_main_conf_t  *cmcf = ngx_http_get_module_main_conf(r->main, ngx_http_core_module);
    sr->variables = ngx_pcalloc(sr->pool, cmcf->variables.nelts * sizeof(ngx_http_variable_value_t));

    sr->log_handler = r->log_handler;

    sr->internal = 1;

    sr->discard_body = r->discard_body;
    sr->expect_tested = 1;
    sr->main_filter_need_in_memory = r->main_filter_need_in_memory;

    sr->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;

    tp = ngx_timeofday();
    sr->start_sec = tp->sec;
    sr->start_msec = tp->msec;

    r->main->count = 2;

    return ngx_http_post_request(sr, NULL);
}

/*主请求超时处理函数
*将所有处于nginx处理过程的子请求取消，
*并结束请求，若子请求为upstream类型
*需要在结束子请求之前清除upstream
*/
static void ngx_http_navi_main_timeout(ngx_event_t* ev) {
    if (ev->timedout) {
        ngx_http_request_t* r = (ngx_http_request_t*)ev->data;
        ngx_http_request_t* sr;
        ngx_http_navi_ctx_t* req_ctx;
        navi_request_t* root;
        navi_request_t* navi;

        req_ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
        if (req_ctx == NULL){
            return;
        }
        root = navi_request_get_root(req_ctx->navi_req);
        navi_request_set_process(root, NULL);
        navi_request_abort_root(root, "timeout");
        ngx_http_navi_reqtimer_process(root);
        navi_request_quitall_vevent(root);
        navi_http_response_set_status(root, NGX_HTTP_REQUEST_TIME_OUT);
        void  *iter = navi_request_cancel_iter(root);
        while((navi = navi_request_cancel_iter_next(iter))) {
            sr = (ngx_http_request_t*)navi_request_get_driver_peer(navi);
            if (sr->upstream && sr->upstream->cleanup){
                /*调用ngx_http_upstream_cleanup*/
                r->main->count++;
                (*(sr->upstream->cleanup))(sr);
            }
            //navi_request_set_status(navi, NAVI_REQUEST_CANCELED);
            r->main->count++;
            ngx_http_finalize_request(sr, NGX_HTTP_REQUEST_TIME_OUT);
        }
        navi_request_cancel_iter_destroy(iter);
	
        ngx_http_navi_main_end_handler(r);
    }
}


static void
ngx_http_navi_check_broken_connection(ngx_http_request_t *r)
{
	ngx_http_navi_ctx_t* req_ctx;
	navi_request_t* root;
	ngx_event_t* ev = r->connection->read;

	req_ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
	if (req_ctx == NULL){
	   return;
	}
	root = navi_request_get_root(req_ctx->navi_req);

    int                  n;
    char                 buf[1];
    ngx_err_t            err;
    ngx_int_t            event;
    ngx_connection_t     *c;

    c = r->connection;

    if (c->error || c->close) {
        if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
            event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;
            ngx_del_event(ev, event, 0);
        }
		err = NGX_ECONNABORTED;
        goto abort_cleanup;
    }

    n = recv(c->fd, buf, 1, MSG_PEEK);

    err = ngx_socket_errno;

    if (ev->write && (n >= 0 || err == NGX_EAGAIN)) {
        return;
    }

    if ((ngx_event_flags & NGX_USE_LEVEL_EVENT) && ev->active) {
        event = ev->write ? NGX_WRITE_EVENT : NGX_READ_EVENT;
        ngx_del_event(ev, event, 0);
    }

    if (n > 0) {
        return;
    }

    if (n == -1) {
        if (err == NGX_EAGAIN) {
        	ngx_handle_read_event(c->read, 0);
            return;
        }

        ev->error = 1;

    } else { /* n == 0 */
        err = 0;
    }

    ev->eof = 1;
    c->error = 1;

abort_cleanup:
	ngx_log_error(NGX_LOG_INFO, ev->log, err,
                  "client prematurely closed connection");
    navi_request_drive_flag(root, NAVI_REQ_DRIVE_ABORT_HANDLER);
	navi_request_set_process(root, NULL);
	navi_request_abort_root(root, "timeout");
	ngx_http_navi_root_run_impl(root,false,false);
	ngx_http_navi_main_end_handler_common(r);
	r->main->count = 1;
	ngx_http_finalize_request(r, NGX_HTTP_CLIENT_CLOSED_REQUEST);
}
static void* ngx_http_request_get_pool(void* ngx_req)
{
	ngx_http_request_t* r = (ngx_http_request_t*)ngx_req;
	return r->pool;
}
/*请求处理入口*/
static ngx_int_t ngx_http_navi_process_request(ngx_http_request_t* r)
{
    ngx_int_t rc;
//    navi_request_t* sub;
//    void* iter_sub;
    navi_request_t *navi_req = NULL;
    ngx_http_navi_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    /*
    if(!ctx){
        navi_req = ngx_http_navi_build_request(r);
        if (navi_req == NULL){
             ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_OK;
        }
        navi_request_set_driver_peer(navi_req, r, ngx_http_request_get_pool);
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_navi_ctx_t));
        ctx->navi_req = navi_req;
        ctx->run_in_entrance = 1;
        ngx_http_set_ctx(r, ctx, ngx_http_navi_module);
    }
    else{
    navi_req = ctx->navi_req;
    }*/
    navi_req = ctx->navi_req;

    navi_request_drive_flag(navi_req,NAVI_REQ_DRIVE_STARTUP_HANDLER);
    rc = navi_mgr_run_request(navi_module_mgr, navi_req);
    if (rc != NAVI_OK){
    	navi_request_abort_root(navi_req, "inner error");
    	ngx_http_navi_root_run_impl(navi_req,false, false);
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_OK;
    }

    ngx_int_t timeout = navi_request_timeout(navi_req);
    if (timeout != 0 && r == r->main){
        ngx_event_t *ev = ngx_pcalloc(r->pool, sizeof(ngx_event_t));
        ev->handler  = ngx_http_navi_main_timeout;
        ev->data = r;
        ctx->req_timeout_ev = ev;
        ngx_add_timer(ev, timeout);
    }
    ngx_http_navi_root_run_impl(navi_req, true, false);

    if (NAVI_REQUEST_COMPLETE == navi_request_get_status(navi_req)) {
    	if (ctx->run_in_entrance) {
    		r->main->count = 1;
    		return ngx_http_navi_main_end_handler_common(r);
    	}
    	else {
    		r->main->count = 1;
    		int rc = ngx_http_navi_main_end_handler_common(r);
    		ngx_http_finalize_request(r, rc);
    		return rc;
    	}
    }
    else{
        ++r->main->count;
    }

    ngx_http_navi_main_conf_t* mcf = ngx_http_get_module_main_conf(r, ngx_http_navi_module);
    if (mcf->client_check){
        r->read_event_handler = ngx_http_navi_check_broken_connection;
    }
    return NGX_DONE;
}

/*模块检测超时处理函数
*检测navi模块目录，更新模块
*调用模块定时处理函数
*最后需要再次添加定时器
*注意，处于ngx_exiting状态时不能再添加定时器
*/
static void ngx_http_navi_module_check(ngx_event_t *ev) 
{
    if (ev->timedout){ 
        navi_mgr_check_modules(navi_module_mgr);
        ngx_http_navi_global_timer_process();

        if (!ngx_exiting) {
            ngx_add_timer(ev,  (ngx_msec_t)(ev->data)*1000);
        }
    }
    navi_vevent_mgr_clean_zombie_ve();
}

/*模块定时器超时处理函数,
*需要清理处理zombie状态的定时器,
*调用超时处理回调,
*如果是周期定时器，还需要再次加入ngx_event_timer_rbtree,
*注意，处于ngx_exiting状态时不能再添加定时器
*/
void ngx_http_navi_timer_handler(ngx_event_t *ev) 
{
    if (ev->timedout) {
        navi_timer_t *ptimer = (navi_timer_t *)(ev->data);
        if (ptimer == NULL){
            return;
        }
        if (navi_timer_is_zombie(ptimer)){
            navi_timer_cleanup(ptimer);
            ev->data = NULL;
            return;
        }
    
        ptimer->stick = 1;
        navi_timer_timeout(ptimer);
        ptimer->stick = 0;
        if (navi_timer_is_zombie(ptimer)){
            navi_timer_cleanup(ptimer);
            ev->data = NULL;
            return;
        }
        if (ptimer->type == NAVI_TIMER_INTERVAL &&  !ngx_exiting) {
            ngx_add_timer(ev,  ptimer->to_ms);
        }
    }
}

typedef struct navi_reqtimer_ctx_s {
	navi_request_t* root;
	navi_timer_t* tmr;
}navi_reqtimer_ctx_t;

static void ngx_http_navi_reqtimer_handler(ngx_event_t* ev)
{
	navi_reqtimer_ctx_t* tmr_ctx = (navi_reqtimer_ctx_t*)(ev->data);
	navi_timer_t* tmr = tmr_ctx->tmr;

	if (navi_timer_is_zombie(tmr)) {
		navi_timer_cleanup(tmr);
		return;
	}

	navi_request_t* navi_root = tmr_ctx->root;

	tmr->stick = 1;
    navi_request_drive_flag(navi_root, NAVI_REQ_DRIVE_TIMER_HANDLER);
	navi_timer_timeout(tmr);
	tmr->stick = 0;
	if (tmr->stage == NAVI_TIMER_RUNNING) {
		tmr->driver_peer = ev;
		ngx_add_timer(ev,tmr->to_ms);
	}
	else if (tmr->stage == NAVI_TIMER_CANCEL){
		navi_timer_canceled(tmr);
		navi_timer_cleanup(tmr);
	}
	else {
		tmr->driver_peer = NULL;
		if ( navi_timer_is_zombie(tmr) ) {
			tmr->stick = 0;
			navi_timer_cleanup(tmr);
		}
	}

	ngx_http_navi_root_run(navi_root, true, true);
}

static void ngx_http_navi_reqtimer_process(navi_request_t* nv_root)
{
	ngx_http_request_t* ngx_root = navi_request_get_driver_peer(nv_root);
	navi_timer_mgr_t* tmr_mgr = navi_request_timers(nv_root);
	if (!tmr_mgr) return;

	void* it = navi_timer_iter(tmr_mgr, NAVI_TIMER_CANCEL);
	navi_timer_t* tmr;
	while ( (tmr = navi_timer_iter_next(it)) ) {
		ngx_event_t* tmr_impl = tmr->driver_peer;
		if (tmr_impl == NULL)continue;
		ngx_del_timer(tmr_impl);
		navi_timer_canceled(tmr);
		navi_timer_cleanup(tmr);
	}
	navi_timer_iter_destroy(it);

	it = navi_timer_iter(tmr_mgr, NAVI_TIMER_REGISTED);
	while ( (tmr = navi_timer_iter_next(it)) ) {
		ngx_event_t* ev = ngx_pcalloc( ngx_root->pool, sizeof(ngx_event_t) );
		navi_reqtimer_ctx_t* ev_ctx = ngx_pcalloc( ngx_root->pool, sizeof(navi_reqtimer_ctx_t));
		ev->handler = ngx_http_navi_reqtimer_handler;
		ev_ctx->tmr = tmr;
		ev_ctx->root = nv_root;
		ev->data = ev_ctx;
		navi_timer_running(tmr, ev);
		ngx_add_timer(ev, tmr->to_ms);
	}
	navi_timer_iter_destroy(it);
}

/*处理模块定时器，将新注册的定时器加入ngx_event_timer_rbtree，
* 将取消的定时器从ngx_event_timer_rbtree中移除
*/
static void  ngx_http_navi_modtimer_cleanup(navi_timer_t* tmr)
{
	if (tmr->driver_peer) {
		ngx_event_t* ev = (ngx_event_t*)(tmr->driver_peer);
		tmr->driver_peer = NULL;
		ngx_event_del_timer(ev);
	}
}
static void  ngx_http_navi_global_timer_process( )
{
    void *iter;
    navi_timer_t *ptimer;
    iter = navi_timer_iter(&(navi_module_mgr->timer_mgr), NAVI_TIMER_REGISTED);
    while((ptimer = navi_timer_iter_next(iter))){
        ngx_event_t *ev = ngx_pcalloc(pcycle->pool, sizeof(ngx_event_t));
        ev->handler  = ngx_http_navi_timer_handler;
        ev->data = ptimer; 
        ev->log = pcycle->log;
        navi_timer_running(ptimer, ev);
        navi_timer_bind_driver(ptimer, ev,ngx_http_navi_modtimer_cleanup );
        ngx_add_timer(ev, ptimer->to_ms);
    }
    navi_timer_iter_destroy(iter);

    /**
    iter = navi_timer_iter(&(navi_module_mgr->timer_mgr), NAVI_TIMER_CANCEL);
    while((ptimer = navi_timer_iter_next(iter))){
        ngx_event_del_timer((ngx_event_t*)(ptimer->driver_peer));
        navi_timer_canceled(ptimer);
        navi_timer_cleanup(ptimer);
    }
    navi_timer_iter_destroy(iter);
    **/
}

static navi_root_run_e ngx_http_navi_root_run_impl(navi_request_t* root, bool trig_ve, bool trig_app)
{
	navi_request_drive_flag(root, NAVI_REQ_DRIVE_STARTUP_HANDLER);
	navi_root_run_e to_drive = NAVI_ROOT_RUN_WAITING;
	void* iter;
	navi_request_t* navi;
	ngx_http_request_t* sr;
	ngx_http_request_t* ngx_root = navi_request_get_driver_peer(root);
	ngx_int_t ret;
	if(trig_ve)ngx_http_navi_ve_process(root);
	iter = navi_request_cancel_iter(root);
	while((navi = navi_request_cancel_iter_next(iter))) {
		sr = (ngx_http_request_t*)navi_request_get_driver_peer(navi);
		if (sr->upstream && sr->upstream->cleanup){
			/*调用ngx_http_upstream_cleanup*/
			ngx_root->main->count++;
			(*(sr->upstream->cleanup))(sr);
		}
		//navi_request_set_status(navi, NAVI_REQUEST_CANCELED);
		ngx_root->main->count++;
		ngx_http_finalize_request(sr, NGX_HTTP_REQUEST_TIME_OUT);
	}
	navi_request_cancel_iter_destroy(iter);

	if ( trig_app ) {
		navi_request_call_process(root);
		if(trig_ve)ngx_http_navi_ve_process(root);
	}

	uint32_t tmp_limit;
	navi_request_get_resp_rate(root, &tmp_limit, NULL);
	ngx_root->limit_rate = tmp_limit;
    //navi_request_get_resp_rate(root, (uint32_t*)&ngx_root->limit_rate, (uint32_t*)&ngx_root->limit_rate_after);
	ngx_http_navi_streaming_resp_proc(root);
	ngx_http_navi_pipe_process();
	ngx_http_navi_reqtimer_process(root);
	ngx_http_navi_global_timer_process();
	ngx_http_navi_check_emerg_resp(root);
	if ( NAVI_REQUEST_COMPLETE == navi_request_get_status(root)) {
		to_drive = NAVI_ROOT_RUN_COMPLETE;
	}
	else {
		iter = navi_request_regist_iter(root);
		while((navi = navi_request_regist_iter_next(iter))) {
			ret = ngx_http_navi_add_subrequest(ngx_root, navi, 0);
			if (ret == NGX_OK){
				navi_request_set_status(navi, NAVI_REQUEST_DRIVER_PROCESSING);
				to_drive = NAVI_ROOT_RUN_NEW_SUBS;
			}
		}
		navi_request_regist_iter_destroy(iter);

		iter = navi_request_cancel_iter(root);
		while((navi = navi_request_cancel_iter_next(iter))) {
			sr = (ngx_http_request_t*)navi_request_get_driver_peer(navi);
			if (sr->upstream && sr->upstream->cleanup){
				/*调用ngx_http_upstream_cleanup*/
				ngx_root->main->count++;
				(*(sr->upstream->cleanup))(sr);
			}
			ngx_root->main->count++;
			ngx_http_finalize_request(sr, NGX_HTTP_REQUEST_TIME_OUT);
		}
		navi_request_cancel_iter_destroy(iter);

		if ( ngx_root->main->count == 1) {
			ngx_root->main->count++;
		}
	}

	navi_request_drive_flag_reset(root);
	return to_drive;
}

static void ngx_http_navi_check_emerg_resp(navi_request_t* main_req)
{
	static ngx_str_t nv_std_resp_type = ngx_string("text/plain");
	//static ngx_str_t unknown_resp_type = ngx_string("application/octet-stream");
	if ( !navi_request_should_emerg_resp(main_req) )
		return;

	ngx_http_request_t* r = navi_request_get_driver_peer(main_req);
	navi_respbody_type_e  nv_resp_type = navi_request_respbody_type(main_req);
	if (nv_resp_type == NAVI_RESP_STREAM ) {
		return;
	}
	if ( r->header_sent )
		return;

	ngx_chain_t	*p_out_chain = NULL;
//	ngx_int_t rc;
	ngx_int_t len = 0;
	ngx_int_t http_status;
	char *resp_content = NULL;

	//ngx_str_t* p_contenttype = &nv_std_resp_type;
	ngx_str_t* p_contenttype = NULL;
	ngx_buf_t*	b=NULL;
	http_status = navi_http_response_get_status(main_req);
	if ( nv_resp_type == NAVI_RESP_NAVI_STANDARD) {
		p_contenttype = &nv_std_resp_type;
	}

	void *it = navi_http_response_header_iter(main_req);
	const char* arg, *val;
	ngx_str_t  key, value;
	while ((arg = navi_http_response_header_iter_next(it,&val))) {
		key.len = strlen(arg);
		key.data = (u_char*)arg;
		value.len = strlen(val);
		value.data = (u_char*)val;

		if ( strcasecmp(arg, "content-type") == 0 ) {
			p_contenttype = NULL;
		}
		else if ( strcasecmp(arg, "connection") == 0 ) {
			if ( strcmp(val, "close") == 0 ) {
				r->keepalive = 0;
			}
			else if ( strcmp(val, "keep-alive") == 0) {
				r->keepalive = 1;
			}
			continue;
		}
		ngx_http_navi_add_header_out(r, &key, &value);
	}
	navi_http_response_header_iter_destroy(it);

	if( nv_resp_type != NAVI_RESP_FILE){
		len =  navi_http_response_get_body(main_req, (const uint8_t**)&resp_content);
		if (len > 0){
			p_out_chain = ngx_alloc_chain_link(r->pool);
			b = ngx_calloc_buf(r->pool);
			b->pos = b->start = (u_char*)resp_content;
			b->last = b->end = b->pos + len;
			b->last_buf = 1;
			b->temporary = 1;
			p_out_chain->buf = b;
			p_out_chain->next = NULL;
		}
	}
	else{
		int fd = navi_request_respbody_filefd(main_req);
		if(fd > 0){
			struct stat st;
			memset(&st, 0, sizeof(st));
			if(!ngx_fd_info(fd, &st)){
				p_out_chain = ngx_alloc_chain_link(r->pool);
				len = st.st_size;
				b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
				b->last_buf = 1;
				b->in_file = 1;
				b->file_pos = 0;
				b->file_last = st.st_size;
				b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
				b->file->fd = fd;
				b->file->log = r->connection->log;
				p_out_chain->buf = b;
				p_out_chain->next = NULL;
			}
		}
		else {
			len = 0;
			p_contenttype = NULL;
			http_status = 500;
		}
	}
	//输出响应
	ngx_http_navi_respond_header(r,p_contenttype,len,http_status,NULL);
	ngx_http_output_filter(r,p_out_chain);
}

static void ngx_http_navi_root_run(navi_request_t* root, bool trig_ve, bool trig_app)
{
	ngx_http_request_t* r = navi_request_get_driver_peer(root);
	switch(ngx_http_navi_root_run_impl(root, trig_ve, trig_app)) {
	case NAVI_ROOT_RUN_COMPLETE:
		if (r != r->main){
			r->write_event_handler = ngx_http_handler;
			ngx_http_navi_main_end_handler(r);
		}
		else {
			r->write_event_handler = ngx_http_navi_main_end_handler;
			ngx_http_post_request(r, NULL);
			ngx_connection_t* c = r->connection;
			ngx_http_run_posted_requests(c);
		}
		break;
	case NAVI_ROOT_RUN_NEW_SUBS: {
		ngx_connection_t* c = r->connection;
		ngx_http_run_posted_requests(c);
	}
		break;
	default:
		break;
	}
}

static void ngx_http_navi_root_rest_run(navi_request_t* root)
{
	ngx_http_navi_root_run(root, false, true);
}

/*post请求读完body之后的回调*/
static void ngx_http_navi_body_handler(ngx_http_request_t* r)
{
	ngx_http_navi_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
	ngx_http_navi_process_postbuf(ctx->navi_req, r);
    ngx_http_navi_process_request(r);
}

/*content handler*/
static ngx_int_t ngx_http_navi_init_handler(ngx_http_request_t* r)
{
    ngx_int_t rc = NGX_OK;
    
    navi_request_t* navi_req = ngx_http_navi_build_request(r);
	if (navi_req == NULL){
		ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
		return NGX_OK;
	}
	navi_request_set_driver_peer(navi_req, r, ngx_http_request_get_pool);
	ngx_http_navi_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_navi_ctx_t));
	ctx->navi_req = navi_req;
	ctx->run_in_entrance = 1;
	r->allow_ranges = 1;
	ngx_http_set_ctx(r, ctx, ngx_http_navi_module);

    if(r->method == NGX_HTTP_GET){
        rc = ngx_http_navi_process_request(r);
        ctx->run_in_entrance = 0;
        return rc;
    }
    else if(r->method == NGX_HTTP_HEAD){
        ngx_http_send_header(r);
        return ngx_http_output_filter(r, NULL);
    }
    else if(r->method == NGX_HTTP_POST){
    	/**
        navi_request_t *navi_req = ngx_http_navi_build_request(r);
        if (navi_req == NULL){
            ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
            return NGX_OK;
        }
        navi_request_set_driver_peer(navi_req, r, ngx_http_request_get_pool);
        ngx_http_navi_ctx_t *ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_navi_ctx_t));
        ctx->navi_req = navi_req;
        ngx_http_set_ctx(r, ctx, ngx_http_navi_module);
        **/
        bool is_bigpost = navi_mgr_judge_bigpost(navi_module_mgr, navi_req);

        /* body内存放在单个buf或文件中 */
        r->request_body_in_single_buf = 1;
        r->request_body_in_persistent_file = 0;
        r->request_body_in_clean_file = 0;
        r->request_body_file_log_level = 0;
        if(is_bigpost){
        	rc = ngx_http_navi_bigpost_process(r);
        }
        else{
        	rc = ngx_http_read_client_request_body(r, ngx_http_navi_body_handler);
        }
        ctx->run_in_entrance = 0;
        return rc;
    }
    else if(r->method == NGX_HTTP_OPTIONS)
    {
        ngx_http_navi_add_header_out(r, &NGX_HTTP_NAVI_HEADER_ACCESS_CTRL, &NGX_HTTP_NAVI_HEADER_ACCESS_CTRL_VALUE);
        int rc = ngx_http_navi_main_end_handler_common(r);
        ngx_http_finalize_request(r, rc);
        return rc;
    }
    ngx_http_navi_add_header_out(r, &NGX_HTTP_NAVI_HEADER_ALLOW, &NGX_HTTP_NAVI_ALLOW_METHOD);
    return NGX_HTTP_NOT_ALLOWED;
}

static ngx_int_t ngx_http_navi_set_header_in_util(ngx_http_request_t *r, 
	ngx_http_navi_header_val_t *hv, ngx_str_t *value, ngx_table_elt_t **out)
{
    ngx_table_elt_t  *h, **old;

    if (hv->offset) {
        old = (ngx_table_elt_t **) ((char *) &r->headers_in + hv->offset);
    } else {
        old = NULL;	
    }

    if (old == NULL || *old == NULL) {
        h =  ngx_list_push(&r->headers_in.headers);
        old = &h;
    }
    else{
        h= *old;
    }

    if (value->len == 0) {
        h->hash = 0;
    }
    else{
        h->hash = hv->hash;
    }

    h->hash = hv->hash;
    h->key = hv->key;
    h->value = *value;
    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);

    if (out) {
        *out = h;
    }

    return NGX_OK;
}

static ngx_int_t ngx_http_navi_set_header_in(ngx_http_request_t *r, 
	ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    return ngx_http_navi_set_header_in_util(r, hv, value, NULL);
}
	
static ngx_int_t ngx_http_navi_set_connection_header_in(ngx_http_request_t *r,
    ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    r->headers_in.connection_type = 0;

    if (value->len == 0) {
        return ngx_http_navi_set_header_in(r, hv, value);
    }

    if (ngx_strcasestrn(value->data, "close", 5 - 1)) {
        r->headers_in.connection_type = NGX_HTTP_CONNECTION_CLOSE;
        r->headers_in.keep_alive_n = -1;

    } else if (ngx_strcasestrn(value->data, "keep-alive", 10 - 1)) {
        r->headers_in.connection_type = NGX_HTTP_CONNECTION_KEEP_ALIVE;
    }

    return ngx_http_navi_set_header_in(r, hv, value);
}

static ngx_int_t ngx_http_navi_set_host_header_in(ngx_http_request_t *r, 
	ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    r->headers_in.server = *value;

    return ngx_http_navi_set_header_in(r, hv, value);
}

static ngx_int_t ngx_http_navi_set_user_agent_header_in(ngx_http_request_t *r,
    ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    u_char  *user_agent, *msie;

    /* clear existing settings */

    r->headers_in.msie = 0;
    r->headers_in.msie6 = 0;
    r->headers_in.opera = 0;
    r->headers_in.gecko = 0;
    r->headers_in.chrome = 0;
    r->headers_in.safari = 0;
    r->headers_in.konqueror = 0;

    if (value->len == 0) {
        return ngx_http_navi_set_header_in(r, hv, value);
    }

    /* check some widespread browsers */

    user_agent = value->data;

    msie = ngx_strstrn(user_agent, "MSIE ", 5 - 1);

    if (msie && msie + 7 < user_agent + value->len) {

        r->headers_in.msie = 1;

        if (msie[6] == '.') {

            switch (msie[5]) {
            case '4':
            case '5':
                r->headers_in.msie6 = 1;
                break;
            case '6':
                if (ngx_strstrn(msie + 8, "SV1", 3 - 1) == NULL) {
                    r->headers_in.msie6 = 1;
                }
                break;
            }
        }
    }

    if (ngx_strstrn(user_agent, "Opera", 5 - 1)) {
        r->headers_in.opera = 1;
        r->headers_in.msie = 0;
        r->headers_in.msie6 = 0;
    }

    if (!r->headers_in.msie && !r->headers_in.opera) {

        if (ngx_strstrn(user_agent, "Gecko/", 6 - 1)) {
            r->headers_in.gecko = 1;

        } else if (ngx_strstrn(user_agent, "Chrome/", 7 - 1)) {
            r->headers_in.chrome = 1;

        } else if (ngx_strstrn(user_agent, "Safari/", 7 - 1)
                   && ngx_strstrn(user_agent, "Mac OS X", 8 - 1))
        {
            r->headers_in.safari = 1;

        } else if (ngx_strstrn(user_agent, "Konqueror", 9 - 1)) {
            r->headers_in.konqueror = 1;
        }
    }

    return ngx_http_navi_set_header_in(r, hv, value);
}

static ngx_int_t
ngx_http_navi_set_content_length_header_in(ngx_http_request_t *r,
    ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    off_t           len;

    if (value->len == 0) {
        r->headers_in.content_length_n = -1;
        return ngx_http_navi_set_header_in(r, hv, value);
    }

    len = ngx_atosz(value->data, value->len);
    if (len == NGX_ERROR) {
        return NGX_ERROR;
    }

    r->headers_in.content_length_n = len;

    return ngx_http_navi_set_header_in(r, hv, value);
}

static ngx_int_t ngx_http_navi_set_cookie_header(ngx_http_request_t *r,
    ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    ngx_table_elt_t  **cookie, *h;

    if (r->headers_in.cookies.nalloc == 0) {
        if (ngx_array_init(&r->headers_in.cookies, r->pool, 2, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    if (ngx_http_navi_set_header_in_util(r, hv, value, &h) == NGX_ERROR) {
        return NGX_ERROR;
    }

    if (value->len == 0) {
        return NGX_OK;
    }

    cookie = ngx_array_push(&r->headers_in.cookies);
    if (cookie == NULL) {
        return NGX_ERROR;
    }

    *cookie = h;
    return NGX_OK;
}

static ngx_http_navi_set_header_t  ngx_http_navi_set_handlers_heads_in[] = {

#if (NGX_HTTP_GZIP)
    { ngx_string("Accept-Encoding"),
                 offsetof(ngx_http_headers_in_t, accept_encoding),
                 ngx_http_navi_set_header_in },

    { ngx_string("Via"),
                 offsetof(ngx_http_headers_in_t, via),
                 ngx_http_navi_set_header_in },
#endif

    { ngx_string("Host"),
                 offsetof(ngx_http_headers_in_t, host),
                 ngx_http_navi_set_host_header_in },

    { ngx_string("Connection"),
                 offsetof(ngx_http_headers_in_t, connection),
                 ngx_http_navi_set_connection_header_in },

    { ngx_string("If-Modified-Since"),
                 offsetof(ngx_http_headers_in_t, if_modified_since),
                 ngx_http_navi_set_header_in },

    { ngx_string("User-Agent"),
                 offsetof(ngx_http_headers_in_t, user_agent),
                 ngx_http_navi_set_user_agent_header_in },

    { ngx_string("Referer"),
                 offsetof(ngx_http_headers_in_t, referer),
                 ngx_http_navi_set_header_in },

    { ngx_string("Content-Type"),
                 offsetof(ngx_http_headers_in_t, content_type),
                 ngx_http_navi_set_header_in },

    { ngx_string("Range"),
                 offsetof(ngx_http_headers_in_t, range),
                 ngx_http_navi_set_header_in },

    { ngx_string("If-Range"),
                 offsetof(ngx_http_headers_in_t, if_range),
                 ngx_http_navi_set_header_in },

    { ngx_string("Transfer-Encoding"),
                 offsetof(ngx_http_headers_in_t, transfer_encoding),
                 ngx_http_navi_set_header_in },

    { ngx_string("Expect"),
                 offsetof(ngx_http_headers_in_t, expect),
                 ngx_http_navi_set_header_in },

    { ngx_string("Authorization"),
                 offsetof(ngx_http_headers_in_t, authorization),
                 ngx_http_navi_set_header_in },

    { ngx_string("Keep-Alive"),
                 offsetof(ngx_http_headers_in_t, keep_alive),
                 ngx_http_navi_set_header_in },

    { ngx_string("Content-Length"),
                 offsetof(ngx_http_headers_in_t, content_length),
                 ngx_http_navi_set_content_length_header_in },

    { ngx_string("Cookie"),
                 0,
                 ngx_http_navi_set_cookie_header },

#if (NGX_HTTP_REALIP)
    { ngx_string("X-Real-IP"),
                 offsetof(ngx_http_headers_in_t, x_real_ip),
                 ngx_http_navi_set_header_in },
#endif

    { ngx_null_string, 0, ngx_http_navi_set_header_in }
};

/*设置header in 头部*/
static  ngx_int_t ngx_http_navi_add_header_in(ngx_http_request_t* r, 
	const ngx_str_t* key, const ngx_str_t* value) 
{
    ngx_http_navi_header_val_t         hv;
    ngx_http_navi_set_header_t        *handlers = ngx_http_navi_set_handlers_heads_in;
    ngx_uint_t                        i;

    hv.hash = ngx_hash_key_lc(key->data, key->len);
    hv.key = *key;

    hv.offset = 0;    
    hv.handler = NULL;

    for (i = 0; handlers[i].name.len; i++) {
        if (hv.key.len != handlers[i].name.len
            || ngx_strncasecmp(hv.key.data, handlers[i].name.data,
                               handlers[i].name.len) != 0)
        {
            continue;
        }
        hv.offset = handlers[i].offset;
        hv.handler = handlers[i].handler;
        break;
    }

    if (handlers[i].name.len == 0 && handlers[i].handler) {
        hv.offset = handlers[i].offset;
        hv.handler = handlers[i].handler;
    }

    if (hv.handler == NULL) {
        return NGX_ERROR;
    }

    return hv.handler(r, &hv, (ngx_str_t *)value); 
}

static ngx_int_t ngx_http_navi_set_header_out(ngx_http_request_t *r, 
	ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    ngx_table_elt_t  *h, **old;

    if (hv->offset) {
        old = (ngx_table_elt_t **) ((char *) &r->headers_out + hv->offset);
    } else {
        old = NULL;	
    }

    if (old == NULL || *old == NULL) {
        h =  ngx_list_push(&r->headers_out.headers);
        old = &h;
    }
    else{
        h= *old;
    }

    if (value->len == 0) {
        h->hash = 0;
    }
    else{
        h->hash = hv->hash;
    }

    h->hash = hv->hash;
    h->key = hv->key;
    h->value = *value;
    h->lowcase_key = ngx_pnalloc(r->pool, h->key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }

    ngx_strlow(h->lowcase_key, h->key.data, h->key.len);
	
    return NGX_OK;
}

static ngx_int_t ngx_http_navi_set_last_modified_header_out(ngx_http_request_t *r,
    ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    r->headers_out.last_modified_time = ngx_http_parse_time(value->data,
                                                            value->len);

    return ngx_http_navi_set_header_out(r, hv, value);
}

static ngx_int_t
ngx_http_navi_set_content_length_header_out(ngx_http_request_t *r,
    ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    off_t           len;

    len = ngx_atosz(value->data, value->len);
    if (len == NGX_ERROR) {
        return NGX_ERROR;
    }

    r->headers_out.content_length_n = len;

    return NGX_OK;
}

static ngx_int_t
ngx_http_navi_set_content_type_header_out(ngx_http_request_t *r,
    ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    r->headers_out.content_type_len = value->len;
    r->headers_out.content_type = *value;
    r->headers_out.content_type_hash = hv->hash;
    r->headers_out.content_type_lowcase = NULL;

    return NGX_OK;
}

static ngx_int_t
ngx_http_navi_set_cache_control_header_out(ngx_http_request_t *r,
    ngx_http_navi_header_val_t *hv, ngx_str_t *value)
{
    ngx_array_t      *pa;
    ngx_table_elt_t  *ho, **ph;

    pa = (ngx_array_t *) ((char *) &r->headers_out + hv->offset);

    if (pa->elts == NULL) {
        if (ngx_array_init(pa, r->pool, 2, sizeof(ngx_table_elt_t *))
            != NGX_OK)
        {
            return NGX_ERROR;
        }
    }

    ph = ngx_array_push(pa);
    if (ph == NULL) {
        return NGX_ERROR;
    }

    ho = ngx_list_push(&r->headers_out.headers);
    if (ho == NULL) {
        return NGX_ERROR;
    }

    ho->value = *value;
    ho->hash = hv->hash;
    ngx_str_set(&ho->key, "Cache-Control");
    *ph = ho;

    return NGX_OK;
}

static ngx_http_navi_set_header_t  ngx_http_navi_set_handlers_heads_out[] = {

    { ngx_string("Server"),
                 offsetof(ngx_http_headers_out_t, server),
                 ngx_http_navi_set_header_out },

    { ngx_string("Date"),
                 offsetof(ngx_http_headers_out_t, date),
                 ngx_http_navi_set_header_out },

    { ngx_string("Content-Encoding"),
                 offsetof(ngx_http_headers_out_t, content_encoding),
                 ngx_http_navi_set_header_out },

    { ngx_string("Location"),
                 offsetof(ngx_http_headers_out_t, location),
                 ngx_http_navi_set_header_out },

    { ngx_string("Refresh"),
                 offsetof(ngx_http_headers_out_t, refresh),
                 ngx_http_navi_set_header_out },

    { ngx_string("Last-Modified"),
                 offsetof(ngx_http_headers_out_t, last_modified),
                 ngx_http_navi_set_last_modified_header_out },

    { ngx_string("Content-Range"),
                 offsetof(ngx_http_headers_out_t, content_range),
                 ngx_http_navi_set_header_out },

    { ngx_string("Accept-Ranges"),
                 offsetof(ngx_http_headers_out_t, accept_ranges),
                 ngx_http_navi_set_header_out },

    { ngx_string("WWW-Authenticate"),
                 offsetof(ngx_http_headers_out_t, www_authenticate),
                 ngx_http_navi_set_header_out },

    { ngx_string("Expires"),
                 offsetof(ngx_http_headers_out_t, expires),
                 ngx_http_navi_set_header_out },

    { ngx_string("E-Tag"),
                 offsetof(ngx_http_headers_out_t, etag),
                 ngx_http_navi_set_header_out },

    { ngx_string("ETag"),
                 offsetof(ngx_http_headers_out_t, etag),
                 ngx_http_navi_set_header_out },

    { ngx_string("Content-Length"),
                 offsetof(ngx_http_headers_out_t, content_length),
                 ngx_http_navi_set_content_length_header_out },

    { ngx_string("Content-Type"),
                 offsetof(ngx_http_headers_out_t, content_type),
                 ngx_http_navi_set_content_type_header_out },

    { ngx_string("Cache-Control"),
                 offsetof(ngx_http_headers_out_t, cache_control),
                 ngx_http_navi_set_cache_control_header_out },

    { ngx_null_string, 0, ngx_http_navi_set_header_out }
};

/*设置header out 头部*/
static  ngx_int_t ngx_http_navi_add_header_out(ngx_http_request_t* r, 
	const ngx_str_t* key, const ngx_str_t* value) 
{
    ngx_http_navi_header_val_t         hv;
    ngx_http_navi_set_header_t        *handlers = ngx_http_navi_set_handlers_heads_out;
    ngx_uint_t                        i;

    hv.hash = ngx_hash_key_lc(key->data, key->len);
    hv.key = *key;

    hv.offset = 0;    
    hv.handler = NULL;

    for (i = 0; handlers[i].name.len; i++) {
        if (hv.key.len != handlers[i].name.len
            || ngx_strncasecmp(hv.key.data, handlers[i].name.data,
                               handlers[i].name.len) != 0)
        {
            continue;
        }
        hv.offset = handlers[i].offset;
        hv.handler = handlers[i].handler;
        break;
    }

    if (handlers[i].name.len == 0 && handlers[i].handler) {
        hv.offset = handlers[i].offset;
        hv.handler = handlers[i].handler;
    }

    if (hv.handler == NULL) {
        return NGX_ERROR;
    }

    return hv.handler(r, &hv, (ngx_str_t *)value); 
}

/*设置输出响应头*/
static ngx_int_t ngx_http_navi_respond_header(ngx_http_request_t *r, ngx_str_t* content_type, 
        ngx_int_t content_len, ngx_int_t status_code, const ngx_str_t *status_line)
{
    if(content_type != NULL){
        r->headers_out.content_type.len=content_type->len;
        r->headers_out.content_type.data = content_type->data;
        r->headers_out.content_type_len = r->headers_out.content_type.len;
    }
    else {
    	ngx_http_set_content_type(r);
    }
    if(content_len > 0){
        r->headers_out.content_length_n = content_len;
    }
    else if (content_len == -1 ){
        r->headers_out.content_length_n = -1;
    }
    else {
        r->headers_out.content_length_n = 0;
        r->header_only = 1;
    }

    r->headers_out.status = status_code;
    if(status_line != NULL){
        r->headers_out.status_line.len = status_line->len;
        r->headers_out.status_line.data = status_line->data;
    }
    return ngx_http_send_header(r);
}

static ngx_chain_t* ngx_http_navi_streaming_get_chain(ngx_http_request_t* ngx)
{
	ngx_chain_t** pcl = &ngx->pool->chain;
	ngx_chain_t* cl = NULL;
	while (*pcl) {
		if ( (*pcl)->buf == NULL ||
				(*pcl)->buf->tag != ngx_http_navi_streaming_resp_proc) {
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
		cl = ngx_alloc_chain_link(ngx->pool);
		cl->buf = ngx_pcalloc(ngx->pool,sizeof(ngx_buf_t));
		cl->buf->temporary = 1;
		cl->buf->tag = ngx_http_navi_streaming_resp_proc;
		cl->next = NULL;
	}

	return cl;
}

static void ngx_http_navi_streaming_resp_proc(navi_request_t* navi)
{
//	static ngx_str_t nv_std_resp_type = ngx_string("text/plain");
//	static ngx_str_t unknown_resp_type = ngx_string("application/octet-stream");

	ngx_http_request_t* ngx = navi_request_get_driver_peer(navi);
	if ( ngx->main != ngx)
		return;
	if ( NAVI_RESP_STREAM != navi_request_respbody_type(navi) ) {
		return;
	}
	ssize_t will_send_total = 0;
	bool has_aborted = false;
	navi_buf_chain_t* nv_chain = navi_request_get_streaming(navi,&will_send_total, &has_aborted);
	if (!nv_chain)
		return;
	//ngx_http_navi_ctx_t* ngx_nv_ctx = ngx_http_get_module_ctx(ngx, ngx_http_navi_module);

	if ( !ngx->header_sent ) {
		//ngx_str_t* p_contenttype = &unknown_resp_type;
		ngx_str_t* p_contenttype = NULL;
//		ngx_int_t rc;
		ngx_int_t len = will_send_total;
		ngx_int_t http_status;
		http_status = navi_http_response_get_status(navi);
		if (http_status == 0)
			http_status = 200;

		if ( has_aborted ) {
			http_status = 500;
			len = 0;
		}

		void *it = navi_http_response_header_iter(navi);
		const char* arg, *val;
		ngx_str_t  key, value;
		while ((arg = navi_http_response_header_iter_next(it,&val))) {
			key.len = strlen(arg);
			key.data = (u_char*)arg;
			value.len = strlen(val);
			value.data = (u_char*)val;
			if ( strcasecmp(arg, "content-type") == 0 ) {
				p_contenttype = NULL;
			}
			else if ( strcasecmp(arg, "connection") == 0 ) {
				if ( strcmp(val, "close") == 0 ) {
					ngx->keepalive = 0;
				}
				else if ( strcmp(val, "keep-alive") == 0) {
					ngx->keepalive = 1;
				}
				continue;
			}
			ngx_http_navi_add_header_out(ngx, &key, &value);
		}
		navi_http_response_header_iter_destroy(it);
		ngx_int_t ret = ngx_http_navi_respond_header(ngx,p_contenttype,len,http_status,NULL);
		if (ret == NGX_ERROR ) {
			navi_request_respbody_streaming_abort(navi);
			has_aborted = true;
		}
	}

	size_t part_sz = 0;
	uint8_t* part_raw = NULL;
	if ( has_aborted ) {
		while ( (part_sz = navi_buf_chain_read_part(nv_chain,&part_raw )) ) {}
		navi_buf_chain_recycle_readed(nv_chain);
		return;
	}

	ngx_chain_t* out = NULL, *cl=NULL;
	ngx_chain_t** pcl = NULL;

	while ( (part_sz = navi_buf_chain_read_part(nv_chain,&part_raw ))) {
		cl = ngx_http_navi_streaming_get_chain(ngx);
		if (out==NULL) out = cl;
		if (pcl) *pcl = cl;
		pcl = &(cl->next);
		cl->buf->start = cl->buf->pos = part_raw;
		cl->buf->end = cl->buf->last = part_raw + part_sz;
	}

	if (!out) return;

	/***
	if ( will_send_total == -1) {
		cl->buf->flush = 1;
		cl->buf->last_buf = 0;
	}
	else {
		cl->buf->flush = 1;
		cl->buf->last_buf = 0;
	}**/

	ngx_int_t ret = ngx_http_output_filter(ngx,out);

	if ( ret == NGX_AGAIN ) {
		ngx_http_finalize_request(ngx, ret);
	}
	else if (ret == NGX_ERROR) {
		navi_request_respbody_streaming_abort(navi);
	}

	if ( ngx->out == NULL ) {
		navi_buf_chain_recycle_readed(nv_chain);
		return;
	}
	else if (ngx->out->buf->tag == ngx_http_navi_streaming_resp_proc){
		//size_t ngx_buf_pos = ngx->out->buf->pos - ngx->out->buf->start;
		//size_t navi_buf_pos = ngx_buf_pos;

		navi_buf_chain_recycle(nv_chain, ngx->out->buf->start);
		/**
		navi_buf_chain_recycle(nv_chain, ngx->out->buf->start,
			&navi_buf_pos);
		if ( navi_buf_pos > ngx_buf_pos ) {
			ngx->out->buf->last = ngx->out->buf->end = ngx->out->buf->start + navi_buf_pos;
		}**/
		return;
	}
}

static void ngx_http_navi_request_rest_driver_timer_handler(ngx_event_t *ev)
{
    navi_request_rest_drive();
}

static void ngx_http_navi_request_rest_driver_trigger()
{
    if(!navi_req_rest_driver_ev){
        navi_req_rest_driver_ev = ngx_pcalloc(pcycle->pool, sizeof(ngx_event_t));
        if(!navi_req_rest_driver_ev)
            return;
        navi_req_rest_driver_ev->log = pcycle->log;
        navi_req_rest_driver_ev->handler = ngx_http_navi_request_rest_driver_timer_handler;
    }
    ngx_post_event(navi_req_rest_driver_ev, &ngx_posted_events);
}
