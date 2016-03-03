/*
 * ngx_http_navi_module_upstream.c
 *
 *  Created on: 2014-01-15
 *      Author: yanguotao@youku.com
 */

static ngx_int_t ngx_http_navi_upstream_init_upstream(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us) 
{
    ngx_http_navi_main_conf_t* mcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_navi_module);
    ngx_http_navi_up_main_conf_t *up_mcf = &(mcf->up_main_conf);
    ngx_navi_up_data_t* prv_data = ngx_pcalloc(cf->pool, sizeof(ngx_navi_up_data_t));
    
    ngx_queue_init(&prv_data->free_cache_ents);
    
    us->peer.init = ngx_http_navi_upstream_init_request;
    us->peer.data = prv_data;
    
    up_mcf->srv_conf = us;
    
    return NGX_OK;
}

static ngx_int_t ngx_http_navi_upstream_init_request(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us) 
{
    r->upstream->peer.get = ngx_http_navi_upstream_get_peer;
    r->upstream->peer.free = ngx_http_navi_upstream_free_peer;
    ngx_navi_up_request_peer_data_t* d = ngx_pcalloc(r->pool,
        sizeof(ngx_navi_up_request_peer_data_t));
    d->policy = (ngx_navi_up_data_t*)us->peer.data;
    d->req_ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    d->req = r;
    	
    r->upstream->peer.data = d;
    return NGX_OK;
}

static ngx_int_t ngx_http_navi_upstream_get_peer(ngx_peer_connection_t *pc, void *data) 
{
    ngx_navi_up_request_peer_data_t* pd = (ngx_navi_up_request_peer_data_t*)data;
    ngx_http_request_t* req = pd->req;
    
    pc->tries = 0; //控制不进行错误重试
    ngx_http_navi_ctx_t *ctx = ngx_http_get_module_ctx(req, ngx_http_navi_module);
    navi_request_t *navi_req = ctx->navi_req;
    navi_upreq_t 	*up_req = navi_request_binded_upreq(navi_req);

     /*对于http upstream, 设置连接超时和读写超时*/
    ngx_http_upstream_t   *u = req->upstream;
    if (up_req->proto == NVUP_PROTO_HTTP && u->conf!=NULL){
        ngx_http_upstream_conf_t *original_conf = u->conf;
	 u->conf = ngx_pcalloc(req ->pool,sizeof(ngx_http_upstream_conf_t));
	 ngx_memcpy(u->conf, original_conf, sizeof(ngx_http_upstream_conf_t));
        u->conf->connect_timeout = up_req->policy.cnn_timeout_ms;
  	 u->conf->send_timeout = up_req->policy.rw_timeout_ms;
        u->conf->read_timeout = up_req->policy.rw_timeout_ms;
    }

    struct sockaddr* peer_addr = NULL;
    socklen_t peer_addr_len = 0;
    char key[256];

    switch( up_req->policy.peer_addr.sa_family) {
    case AF_INET:
    {
    	peer_addr = ngx_pcalloc(req->pool, sizeof(struct sockaddr_in));
    	peer_addr_len = sizeof(struct sockaddr_in);
    	inet_ntop(AF_INET,&up_req->policy.peer_addr_in.sin_addr, key, peer_addr_len);
    	char* p = key + strlen(key);
    	sprintf(p,":%u", ntohs(up_req->policy.peer_addr_in.sin_port));
    	break;
    }
    case AF_INET6:
    	peer_addr = ngx_pcalloc(req->pool, sizeof(struct sockaddr_in6));
    	peer_addr_len = sizeof(struct sockaddr_in6);
    	inet_ntop(AF_INET6,&up_req->policy.peer_addr_in6.sin6_addr, key, peer_addr_len);
    	char* p = key + strlen(key);
    	sprintf(p,":%u", ntohs(up_req->policy.peer_addr_in6.sin6_port));
    	break;
    case AF_UNIX:
    	peer_addr = ngx_pcalloc(req->pool, sizeof(struct sockaddr_un));
    	peer_addr_len = sizeof(struct sockaddr_un);
    	sprintf(key, "unix:%s", up_req->policy.peer_addr_un.sun_path);
    	break;
    default:
    	break;
    }

    ngx_memcpy(peer_addr, &(up_req->policy.peer_addr),peer_addr_len);
    
    pc->connection = NULL;
    pc->sockaddr = (struct sockaddr*)peer_addr;
    pc->socklen = peer_addr_len;

    pc->name = ngx_pcalloc(req->pool, sizeof(ngx_str_t));
    pc->name->len = ngx_strlen(key);
    pc->name->data = ngx_pcalloc(req->pool,  pc->name->len+1);
    ngx_memcpy(pc->name->data, key,  pc->name->len);

    if (pd->policy->grp_conn_pools) {
        ngx_navi_up_conn_pool_t* cnn_pool = navi_hash_get_gr(pd->policy->grp_conn_pools, key);
        if (cnn_pool) {
            if (cnn_pool->cur_cached > 0) {
                ngx_queue_t* cache_lnk=NULL;
                ngx_navi_up_conn_cache_ent_t* cache_e = NULL;
                cache_lnk = ngx_queue_head(&cnn_pool->cache);
                ngx_queue_remove(cache_lnk);
                cache_e = ngx_queue_data(cache_lnk, ngx_navi_up_conn_cache_ent_t, queue);
                cache_e->pool->cur_cached-=1;
                ngx_queue_insert_head(&pd->policy->free_cache_ents, cache_lnk);
                
                ngx_connection_t* c = cache_e->connection;
                c->idle = 0;
                c->log = pc->log;
                c->read->log = pc->log;
                c->write->log = pc->log;
                c->pool->log = pc->log;
                
                if (c->write->timer_set) {
                    ngx_del_timer(c->write);
                }
                
                pc->connection = c;
                pc->cached = 1;
                return NGX_DONE;
            }
        }
    }

    return NGX_OK;
}

static void
ngx_http_navi_upstream_idle_conn_to_check(ngx_event_t *ev) 
{
    if (ev->timedout) {
        ngx_connection_t  *c= ev->data;
        ngx_navi_up_conn_cache_ent_t* cache_e = (ngx_navi_up_conn_cache_ent_t*)c->data;
        ngx_destroy_pool(c->pool);
        ngx_close_connection(c);
        ngx_queue_remove(&cache_e->queue);
        cache_e->pool->cur_cached -= 1;
        ngx_queue_insert_head(&cache_e->policy->free_cache_ents, &cache_e->queue);
    }
}

static void
ngx_http_navi_upstream_idle_conn_rev(ngx_event_t *ev) 
{
    int                n;
    char               buf[1];
    ngx_connection_t  *c;
    ngx_navi_up_conn_cache_ent_t* cache_e = NULL;
    
    c = ev->data;
    cache_e = (ngx_navi_up_conn_cache_ent_t*)c->data;
    
    if (c->close) {
        goto close;
    }
    
    n = recv(c->fd, buf, 1, MSG_PEEK);
    
    if (n == -1 && ngx_socket_errno == NGX_EAGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            goto close;
        }
        
        return;
    }
    
close:
    ngx_destroy_pool(c->pool);
    ngx_close_connection(c);
    ngx_queue_remove(&cache_e->queue);
    cache_e->pool->cur_cached -= 1;
    ngx_queue_insert_head(&cache_e->policy->free_cache_ents, &cache_e->queue);
}

static void ngx_http_navi_upstream_free_peer(ngx_peer_connection_t *pc,
    void *data, ngx_uint_t state) 
{
    ngx_navi_up_request_peer_data_t* pd = (ngx_navi_up_request_peer_data_t*)data;
    ngx_connection_t* c = pc->connection;
    ngx_navi_up_data_t* policy = pd->policy;
    ngx_http_request_t* req = pd->req;
    ngx_http_navi_ctx_t *ctx = ngx_http_get_module_ctx(req, ngx_http_navi_module);
    navi_request_t *navi_req = ctx->navi_req;
    navi_upreq_t 	*up_req = navi_request_binded_upreq(navi_req);

    if (navi_request_get_status(navi_req) ==  NAVI_REQUEST_CANCEL_REGISTED){
        goto no_keep;
    }

    navi_upgroup_mgr_t* mgr = navi_upgroup_mgr_instance(NULL);
    navi_upserver_t * up_server = 
        navi_upgroup_mgr_get_server(mgr, up_req->group_name, up_req->policy.server_name);
    if (up_server == NULL){
        goto no_keep;
    }
	
    if (state & NGX_PEER_FAILED || ngx_exiting) {
        goto no_keep;
    }

    if (c==NULL || c->read->eof || c->read->error || c->read->timedout
        || c->write->error || c->write->timedout || c->close) {
        goto no_keep;
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        goto no_keep;
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }
    if (c->write->timer_set) {
        ngx_del_timer(c->write);
    }
    ngx_event_add_timer(c->write, up_server->settings.max_idle_ms);
    
    c->write->handler = ngx_http_navi_upstream_idle_conn_to_check;
    c->read->handler = ngx_http_navi_upstream_idle_conn_rev;
    
    c->log = ngx_cycle->log;
    c->read->log = ngx_cycle->log;
    c->write->log = ngx_cycle->log;
    c->pool->log = ngx_cycle->log;
    c->idle = 1;

    /*将连接加入连接池*/
    char key[26];
    inet_ntop(AF_INET,&((struct sockaddr_in*)pc->sockaddr)->sin_addr, key, pc->socklen);
    char* p = key + strlen(key);
    sprintf(p,":%u", ntohs(((struct sockaddr_in*)pc->sockaddr)->sin_port));
    
    if (policy->grp_conn_pools==NULL) {
        policy->hash_mem = navi_pool_create(4096);
        policy->grp_conn_pools = navi_hash_init(policy->hash_mem);
    }

    ngx_navi_up_conn_pool_t* cnn_pool = navi_hash_get_gr(policy->grp_conn_pools, key);
    /*获得缓存entry*/
    ngx_queue_t* cache_lnk = NULL;
    ngx_navi_up_conn_cache_ent_t* cache_e=NULL;
    if (cnn_pool==NULL) {
        cnn_pool = ngx_pcalloc(ngx_cycle->pool,sizeof(ngx_navi_up_conn_pool_t));
        cnn_pool->max_caches = up_server->settings.idle_pool_size;
        cnn_pool->cur_cached = 0;
        cnn_pool->max_idle_to = up_server->settings.max_idle_ms;
        ngx_queue_init(&cnn_pool->cache);
        navi_hash_set_gr(policy->grp_conn_pools,key,cnn_pool);
    }
    else {
        /*看连接池是否超限*/
        if (cnn_pool->cur_cached >= cnn_pool->max_caches + 10) {
            while (cnn_pool->cur_cached >= cnn_pool->max_caches) {
                cache_lnk = ngx_queue_last(&cnn_pool->cache);
                ngx_queue_remove(cache_lnk);
                cnn_pool->cur_cached -= 1;
                
                cache_e = ngx_queue_data(cache_lnk,ngx_navi_up_conn_cache_ent_t, queue);
                ngx_destroy_pool(cache_e->connection->pool);
                ngx_close_connection(cache_e->connection);
                
                ngx_queue_insert_head(&cache_e->policy->free_cache_ents, cache_lnk);
            }
        }
    }

    cache_lnk = NULL;
    cache_e=NULL;
    if (!ngx_queue_empty(&policy->free_cache_ents)) {
        cache_lnk = ngx_queue_head(&policy->free_cache_ents);
        ngx_queue_remove(cache_lnk);
        cache_e = ngx_queue_data(cache_lnk,ngx_navi_up_conn_cache_ent_t, queue);
    }
    else {
        cache_e = ngx_pcalloc(ngx_cycle->pool,sizeof(ngx_navi_up_conn_cache_ent_t));
    }
    
    cache_e->connection = pc->connection;
    cache_e->pool = cnn_pool;
    cache_e->policy = policy;
    cnn_pool->cur_cached += 1;
    cache_e->connection->data = cache_e;
    ngx_queue_insert_head(&cnn_pool->cache, &cache_e->queue);
    
    if (c->read->ready) {
        ngx_http_navi_upstream_idle_conn_rev(c->read);
    }
    
    pc->connection = NULL;
    return;

no_keep:
    if (c != NULL){
        ngx_destroy_pool(c->pool);
        ngx_close_connection(c);
        pc->connection = NULL;
    }
    return;
}

/*
 * 在ngx解析配置之前，增加一个upstream 分组， 名为navi_ds。该分组全局可见。
 */
static ngx_int_t ngx_http_navi_upstream_add_srv_grp(ngx_conf_t* cf) 
{
    ngx_url_t u;
    ngx_memzero(&u, sizeof(ngx_url_t));
    u.host.data = (u_char *)"navi_ds";
    u.host.len = strlen("navi_ds");
    u.no_resolve = 1;
    
    ngx_http_upstream_srv_conf_t* up_srv =
        ngx_http_upstream_add(cf, &u, NGX_HTTP_UPSTREAM_CREATE
    								|NGX_HTTP_UPSTREAM_MAX_FAILS
    								|NGX_HTTP_UPSTREAM_FAIL_TIMEOUT
    								);
    
    if (up_srv==NULL)
        return NGX_ERROR;
    
    up_srv->peer.init_upstream = ngx_http_navi_upstream_init_upstream;
    return NGX_OK;
}

/*模块检测超时处理函数
*检测navi upstream模块目录，更新模块
*最后需要再次添加定时器
*注意，处于ngx_exiting状态时不能再添加定时器
*/
static void ngx_http_navi_upstream_module_check(ngx_event_t *ev) 
{
    if (ev->timedout){ 
        navi_upgroup_mgr_t *mgr = navi_upgroup_mgr_instance(NULL);
        navi_upgroup_mgr_refresh(mgr);

        if (!ngx_exiting) {
            ngx_add_timer(ev,  (ngx_msec_t)(ev->data)*1000);
        }
    }
}

ngx_int_t ngx_http_navi_upstream_reinit_request(ngx_http_request_t *r)
{
	return NAVI_OK;
}

ngx_int_t ngx_http_navi_upstream_create_request(ngx_http_request_t *r) 
{
    ngx_http_navi_ctx_t     *ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    navi_request_t    *navi_req = ctx->navi_req;
    navi_upreq_t *up_req = navi_request_binded_upreq(navi_req);
    ngx_int_t len = navi_upreq_get_out_package(up_req, NULL, 0);
    if (len <= 0){
        navi_upreq_error_lt(up_req, NVUP_RESULT_INNER_ERROR, -1, "get out package error");
        return NGX_ERROR;
    }
    
    ngx_buf_t *b = ngx_create_temp_buf(r->pool, len);
    ngx_chain_t* cl = ngx_alloc_chain_link(r->pool);
    b->last += navi_upreq_get_out_package(up_req, b->last, len);
    cl->buf = b;
    cl->next = NULL;
    
    r->upstream->request_bufs = cl;
    
    return NGX_OK;
}

ngx_int_t	ngx_http_navi_upstream_header_ignore(ngx_http_request_t *r) 
{
    r->upstream->headers_in.status_n = 200;
    return NGX_OK;
}

void ngx_http_navi_upstream_finalize_request(ngx_http_request_t *r, ngx_int_t rc) {
    ngx_http_navi_ctx_t    *ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    navi_request_t *navi_req = ctx->navi_req;
    navi_upreq_t *up_req = navi_request_binded_upreq(navi_req);

    if (rc == NGX_OK) {
        r->headers_out.status = 200;
        ngx_http_send_header(r);
    }
    else if (rc == NGX_HTTP_GATEWAY_TIME_OUT){
        navi_upreq_error_lt(up_req, NVUP_RESULT_RW_TIMEOUT, -1, "Connect or Read write timeout");
    }
    else if (rc == NGX_HTTP_BAD_GATEWAY){
        navi_upreq_error_lt(up_req, NVUP_RESULT_CONN_FAILED, -1, "Connect failed, bad gateway");
    }
}

ngx_int_t ngx_http_navi_upstream_input_filter_init(void *data) 
{
    ngx_http_request_t* r = (ngx_http_request_t*)data;
    r->upstream->length = -1;
    return NGX_OK;
}

ngx_int_t ngx_http_navi_upstream_input_filter(void *data, ssize_t bytes) 
{
    ngx_http_request_t* r = (ngx_http_request_t*)data;
    ngx_http_upstream_t* u = r->upstream;
    ngx_buf_t* in_buf = &u->buffer;
    ngx_http_navi_ctx_t     *ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    navi_request_t    *navi_req = ctx->navi_req;
    navi_upreq_t *up_req = navi_request_binded_upreq(navi_req);
    navi_upreq_parse_status_e ret = navi_upreq_parse_in(up_req, in_buf->pos, bytes);
    in_buf->pos = in_buf->last = in_buf->start;
    
    if (ret != NVUP_PARSE_AGAIN){
         u->length = 0;
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_navi_upstream_handler(ngx_http_request_t *r) 
{
    ngx_int_t                   rc;
    ngx_http_upstream_t        *u;
    ngx_http_navi_main_conf_t* mcf =
        ngx_http_get_module_main_conf(r, ngx_http_navi_module);
    ngx_http_navi_up_main_conf_t *up_mcf = &(mcf->up_main_conf);
    ngx_http_navi_ctx_t    *ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    navi_request_t *navi_req = ctx->navi_req;
    navi_upreq_t *up_req = navi_request_binded_upreq(navi_req);

    if (ngx_http_upstream_create(r) != NGX_OK) {
        navi_upreq_error_lt(up_req, NVUP_RESULT_INNER_ERROR, -1, "create upstream error");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    u = r->upstream;
    u->output.tag = (ngx_buf_tag_t)&ngx_http_navi_module;
    /*
     * 常规的upstream模块，在每个location下有相关指令，信息存入xxx_loc_conf_t->upstream
     * 配置，此处，nvds配置全局只有一个location，相关连接控制参数在json中。
     * 为每一个请求单独分配ngx_http_upstream_conf_t，并从json中获取相关配置。
     */
    u->conf = ngx_pcalloc(r->pool,sizeof(ngx_http_upstream_conf_t));
    if (u->conf==NULL){
        navi_upreq_error_lt(up_req, NVUP_RESULT_INNER_ERROR, -1, "memory error");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    /*设置该标记后，不会触发downstream输出。
     *不会使用event pipe进行upstream->downstream的响应流传递
     */
    r->subrequest_in_memory = 1;
    
    u->conf->upstream = up_mcf->srv_conf;

    /*如果是subrequest_in_memory，则始终使用u->buffer作为读入缓冲*/
    u->conf->buffer_size = up_req->policy.in_proto_buf_sz;
    u->conf->ignore_client_abort = 1;
    u->conf->connect_timeout = up_req->policy.cnn_timeout_ms;
    u->conf->send_timeout = up_req->policy.rw_timeout_ms;
    u->conf->read_timeout = up_req->policy.rw_timeout_ms;
    u->conf->send_lowat = 0;
    
    u->conf->next_upstream = 0;
    u->conf->intercept_errors = 0;
    u->conf->intercept_404 = 0;
    
    u->create_request = ngx_http_navi_upstream_create_request;
    u->reinit_request = ngx_http_navi_upstream_reinit_request; //不进行重试，也就不需要reinit_request
    /*process_header只使用一个大小固定的缓冲区来解析头部，
     *不一定适用于所有协议。
     *所以不使用该阶段，直接跳入upstream input filter阶段
     */
    u->process_header = ngx_http_navi_upstream_header_ignore;
    u->abort_request = NULL; // abort_request未被使用到
    u->finalize_request = ngx_http_navi_upstream_finalize_request;
    r->state = 0;
    
    u->input_filter_init = ngx_http_navi_upstream_input_filter_init;
    /*读取头部的结尾，从socket缓冲区获得数据后，
     *需要对这批数据进行filter处理。
     *主要是进行协议包剩余量的计算。
     *nvds除此之为，会将接收数据传递给上层
     */
    u->input_filter = ngx_http_navi_upstream_input_filter;
    u->input_filter_ctx = r;
    
    rc = ngx_http_read_client_request_body(r, ngx_http_upstream_init);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }
    
    return NGX_DONE;
}

static char *
ngx_http_navi_upstream_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    ngx_http_core_loc_conf_t*  loc_conf =
        ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    ngx_http_navi_main_conf_t* mcf =
        ngx_http_conf_get_module_main_conf(cf, ngx_http_navi_module);
    ngx_http_navi_up_main_conf_t *up_mcf = &(mcf->up_main_conf);
    
    /*必须是明确的location内配置*/
    if (loc_conf->exact_match || loc_conf->noregex || loc_conf->named)
        return NGX_CONF_ERROR;
    
    up_mcf->enable_nvds_location.data = ngx_pstrdup(cf->pool, &loc_conf->name);
    up_mcf->enable_nvds_location.len = loc_conf->name.len;
    loc_conf->handler = ngx_http_navi_upstream_handler;
    return NGX_CONF_OK;
}

