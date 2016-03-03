
//#include <cnaviutil/navi_static_content.h>

static const uint32_t OPEN_FILE_CACHE_SIZE = 4 * 1024;

typedef struct ngx_navi_open_file_cache_s
{
    ngx_open_file_cache_t *file_cache;
    time_t                 file_valid_time;
    ngx_uint_t             file_min_uses;

}ngx_navi_open_file_cache_t;

static int ngx_http_navi_bigpost_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    if (r->expect_tested
            || r->headers_in.expect == NULL
            || r->http_version < NGX_HTTP_VERSION_11)
    {
        return NGX_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1
            || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
                sizeof("100-continue") - 1)
            != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "send 100 Continue");

    n = r->connection->send(r->connection,
            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    return NGX_ERROR;
}



static int ngx_http_navi_bigpost_process(ngx_http_request_t* r);

static ngx_int_t ngx_http_navi_bigpost_save_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
#if (NGX_DEBUG)
    ngx_chain_t               *cl;
#endif
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

#if (NGX_DEBUG)

    for (cl = rb->bufs; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                "http body old buf t:%d f:%d %p, pos %p, size: %z "
                "file: %O, size: %z",
                cl->buf->temporary, cl->buf->in_file,
                cl->buf->start, cl->buf->pos,
                cl->buf->last - cl->buf->pos,
                cl->buf->file_pos,
                cl->buf->file_last - cl->buf->file_pos);
    }

    for (cl = in; cl; cl = cl->next) {
        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                "http body new buf t:%d f:%d %p, pos %p, size: %z "
                "file: %O, size: %z",
                cl->buf->temporary, cl->buf->in_file,
                cl->buf->start, cl->buf->pos,
                cl->buf->last - cl->buf->pos,
                cl->buf->file_pos,
                cl->buf->file_last - cl->buf->file_pos);
    }

#endif

    /* TODO: coalesce neighbouring buffers */

    if (ngx_chain_add_copy(r->pool, &rb->bufs, in) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return NGX_OK;
}

static int ngx_http_navi_bigpost_chunked_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    return NGX_OK;
}

static int ngx_http_navi_bigpost_length_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    size_t                     size;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, *tl, *out, **ll;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

    if (rb->rest == -1) {
        rb->rest = r->headers_in.content_length_n;
    }

    out = NULL;
    ll = &out;

    for (cl = in; cl; cl = cl->next) {

        if (rb->rest == 0) {
            break;
        }

        tl = ngx_chain_get_free_buf(r->pool, &rb->free);
        if (tl == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b = tl->buf;

        ngx_memzero(b, sizeof(ngx_buf_t));

        b->temporary = 1;
        b->tag = (ngx_buf_tag_t)&ngx_http_navi_bigpost_process;
        b->start = cl->buf->pos;
        b->pos = cl->buf->pos;
        b->last = cl->buf->last;
        b->end = cl->buf->end;

        size = cl->buf->last - cl->buf->pos;

        if ((off_t) size < rb->rest) {
            cl->buf->pos = cl->buf->last;
            rb->rest -= size;

        } else {
            cl->buf->pos += (size_t) rb->rest;
            rb->rest = 0;
            b->last = cl->buf->pos;
            b->last_buf = 1;
        }

        *ll = tl;
        ll = &tl->next;
    }

    rc = ngx_http_navi_bigpost_save_filter(r, out);

    ngx_chain_update_chains(r->pool, &rb->free, &rb->busy, &out,
            (ngx_buf_tag_t)&ngx_http_navi_bigpost_process);

    return rc;
}

static int ngx_http_navi_bigpost_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    if (r->headers_in.chunked) {
        return ngx_http_navi_bigpost_chunked_filter(r, in);

    } else {
        return ngx_http_navi_bigpost_length_filter(r, in);
    }
}

/*bigpost请求读完body之后的回调*/
static void ngx_http_navi_bigpost_post_handler(ngx_http_request_t* r)
{
    ngx_http_request_body_t   *rb = r->request_body;
    navi_scfd_t scfd;
    scfd.fd = rb->temp_file->file.fd;
    scfd.is_temp = 1;
    navi_scfile_write_comfirm(&scfd);
    --r->main->count;
    ngx_http_navi_ctx_t *navi_ctx = (ngx_http_navi_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_navi_module);
    navi_request_drive_flag(navi_ctx->navi_req, NAVI_REQ_DRIVE_BIGPOST_HANDLER);
    //if(!navi_http_request_is_bigpost_abort(navi_ctx->navi_req))
    navi_request_bigpost_ready(navi_ctx->navi_req);
    ngx_http_navi_root_run(navi_ctx->navi_req, true, true);
}

static int ngx_http_navi_bigpost_write_temp(ngx_http_request_t *r)
{
    ssize_t                    n;
    ngx_chain_t               *cl;
    ngx_temp_file_t           *tf;
    ngx_http_request_body_t   *rb;

    rb = r->request_body;

    if (rb->temp_file == NULL) {
        navi_scfd_t *nv_scfd = NULL;
        ngx_http_navi_ctx_t *navi_ctx = (ngx_http_navi_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_navi_module);
        if(!navi_ctx || !navi_ctx->navi_req)
            return NGX_ERROR;
        void *fmgr = navi_mgr_get_bigpost_filemgr(navi_module_mgr, navi_ctx->navi_req);
        int err = 0;
        if(fmgr)
            nv_scfd = navi_scfile_openw_temp(fmgr, &err);
        if(!nv_scfd)
            return NGX_ERROR;

        tf = ngx_pcalloc(r->pool, sizeof(ngx_temp_file_t));
        if (tf == NULL) {
            return NGX_ERROR;
        }
        ngx_int_t len = strlen(nv_scfd->path) + 1;
        tf->file.log = r->connection->log;
        tf->file.fd = nv_scfd->fd;
        tf->file.name.data = (u_char*)ngx_pcalloc(r->pool, len);
        tf->file.name.len = len;
        memcpy(tf->file.name.data, nv_scfd->path, len - 1);
        tf->pool = r->pool;
        tf->clean = 0;
        rb->temp_file = tf;
        navi_request_bigpost_prepare(navi_ctx->navi_req, nv_scfd->path);
        nv_scfd->fd = -1;
        navi_scfd_clean(nv_scfd);
    }

    if (rb->bufs == NULL) {
        return NGX_OK;
    }

    n = ngx_write_chain_to_temp_file(rb->temp_file, rb->bufs);

    /* TODO: n == 0 or not complete and level event */

    if (n == NGX_ERROR) {
        return NGX_ERROR;
    }

    rb->temp_file->offset += n;

    /* mark all buffers as written */

    for (cl = rb->bufs; cl; cl = cl->next) {
        cl->buf->pos = cl->buf->last;
    }

    rb->bufs = NULL;

    return NGX_OK;
}

static int ngx_http_navi_bigpost_read(ngx_http_request_t *r)
{
    off_t                      rest;
    size_t                     size;
    ssize_t                    n;
    ngx_int_t                  rc;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, out;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;

    c = r->connection;
    rb = r->request_body;

    int output_cnt = 0;

    for ( ;; ) {
        for ( ;; ) {
            if (rb->buf->last == rb->buf->end) {

                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                rc = ngx_http_navi_bigpost_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }

                /* write to file */

                if (ngx_http_navi_bigpost_write_temp(r) != NGX_OK) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                /* update chains */

                rc = ngx_http_navi_bigpost_filter(r, NULL);

                if (rc != NGX_OK) {
                    return rc;
                }

                if (rb->busy != NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                rb->buf->pos = rb->buf->start;
                rb->buf->last = rb->buf->start;
                output_cnt++;
            }

            size = rb->buf->end - rb->buf->last;
            rest = rb->rest - (rb->buf->last - rb->buf->pos);

            if ((off_t) size > rest) {
                size = (size_t) rest;
            }

            n = c->recv(c, rb->buf->last, size);
            if (n == NGX_AGAIN)
                break;

            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;
            r->request_length += n;

            if (n == rest) {
                /* pass buffer to request body filter chain */

                out.buf = rb->buf;
                out.next = NULL;

                rc = ngx_http_navi_bigpost_filter(r, &out);

                if (rc != NGX_OK) {
                    return rc;
                }
            }

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
            /* 边缘触发下， 此处是一处逻辑错误 。 else {
            	if ( output_cnt >= 1024 )
            		break;
            }*/
        }//second for

        if (rb->rest == 0) {
            break;
        }

        if (!c->read->ready) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }//first for

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    if (rb->temp_file || r->request_body_in_file_only) {

        /* save the last part */

        if (ngx_http_navi_bigpost_write_temp(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        if (rb->temp_file->file.offset != 0) {

            cl = ngx_chain_get_free_buf(r->pool, &rb->free);
            if (cl == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            b = cl->buf;

            ngx_memzero(b, sizeof(ngx_buf_t));

            b->in_file = 1;
            b->file_last = rb->temp_file->file.offset;
            b->file = &rb->temp_file->file;

            rb->bufs = cl;

        } else {
            rb->bufs = NULL;
        }
    }

    r->read_event_handler = ngx_http_block_reading;
    rb->post_handler(r);
    return NGX_OK;
}

static void ngx_http_navi_bigpost_read_handler(ngx_http_request_t *r)
{
    ngx_http_request_body_t   *rb = NULL;
    ngx_int_t  rc;
    ngx_http_navi_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_navi_module);
    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        goto err;
    }

    if(navi_http_request_is_bigpost_abort(ctx->navi_req)){
        r->discard_body = 1;
        goto err;
    }

    rc = ngx_http_navi_bigpost_read(r);

    if (rc < NGX_HTTP_SPECIAL_RESPONSE) {
        return;
    }
err:
    rb = r->request_body;
    navi_scfd_t scfd;
    scfd.fd = rb->temp_file->file.fd;
    scfd.path = (char*)rb->temp_file->file.name.data;
    navi_scfile_write_abort(&scfd);
    navi_request_abort_root(ctx->navi_req, "bigpost broken");
    ngx_http_navi_root_run(ctx->navi_req, false, false);
}

static int ngx_http_navi_bigpost_process(ngx_http_request_t* r)
{
    ngx_int_t rc;
    size_t preread = 0;
    ssize_t size = 0;
    ngx_buf_t *b = NULL;
    ngx_http_request_body_t *rb = NULL;
    ngx_chain_t *cl = NULL;
    ngx_http_core_loc_conf_t  *clcf = NULL;
    ngx_http_client_body_handler_pt post_handler = ngx_http_navi_bigpost_post_handler;
    rc = ngx_http_navi_process_request(r);
    if(rc == NGX_OK || rc != NGX_DONE)
        return rc;
    ngx_http_navi_ctx_t *navi_ctx = (ngx_http_navi_ctx_t*)ngx_http_get_module_ctx(r, ngx_http_navi_module);
    if(!navi_ctx || !navi_ctx->navi_req)
        return NGX_OK;
    if(navi_http_request_is_bigpost_abort(navi_ctx->navi_req)){
        r->discard_body = 1;
    }

    r->main->count++;
    if (r != r->main || r->request_body || r->discard_body) {
        post_handler(r);
        return NGX_OK;
    }

    if (ngx_http_navi_bigpost_test_expect(r) != NGX_OK) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }
     
    rb->rest = -1;
    rb->post_handler = post_handler;
    r->request_body = rb;

    preread = r->header_in->last - r->header_in->pos;
    if (preread) {
        /* there is the pre-read part of the request body */
        ngx_chain_t out;
        out.buf = r->header_in;
        out.next = NULL;

        rc = ngx_http_navi_bigpost_filter(r, &out);

        if (rc != NGX_OK) {
            goto done;
        }

        r->request_length += preread - (r->header_in->last - r->header_in->pos);

        if (!r->headers_in.chunked
                && rb->rest > 0
                && rb->rest <= (off_t) (r->header_in->end - r->header_in->last))
        {
            /* the whole request body may be placed in r->header_in */

            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            b->temporary = 1;
            b->start = r->header_in->pos;
            b->pos = r->header_in->pos;
            b->last = r->header_in->last;
            b->end = r->header_in->end;

            rb->buf = b;

            r->read_event_handler = ngx_http_navi_bigpost_read_handler;
            r->write_event_handler = ngx_http_request_empty_handler;

            rc = ngx_http_navi_bigpost_read(r);
            goto done;
        }
    }
    else {
        /* set rb->rest */
        if (ngx_http_navi_bigpost_filter(r, NULL) != NGX_OK) {
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            goto done;
        }
    }
    if (rb->rest == 0) {
        /* the whole request body was pre-read */
        if (r->request_body_in_file_only) {
            if (ngx_http_navi_bigpost_write_temp(r) != NGX_OK) {
                rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                goto done;
            }

            if (rb->temp_file->file.offset != 0) {
                cl = ngx_chain_get_free_buf(r->pool, &rb->free);
                if (cl == NULL) {
                    rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
                    goto done;
                }

                b = cl->buf;

                ngx_memzero(b, sizeof(ngx_buf_t));

                b->in_file = 1;
                b->file_last = rb->temp_file->file.offset;
                b->file = &rb->temp_file->file;

                rb->bufs = cl;

            } else {
                rb->bufs = NULL;
            }
        }

        post_handler(r);
        return NGX_OK;
    }

    if (rb->rest < 0) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                "negative request body rest");
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    size = clcf->client_body_buffer_size;
    size += size >> 2;

    /* TODO: honor r->request_body_in_single_buf */

    if (!r->headers_in.chunked && rb->rest < size) {
        size = (ssize_t) rb->rest;

        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
        size = clcf->client_body_buffer_size;
    }

    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        goto done;
    }

    r->read_event_handler = ngx_http_navi_bigpost_read_handler;
    r->write_event_handler = ngx_http_request_empty_handler;

    rc = ngx_http_navi_bigpost_read(r);

done:

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        r->main->count--;
    }
    return rc;
}

static void *ngx_http_navi_open_file_cache_init(void *mgr, int max_cache_size, int min_file_uses, int valid_file_time)
{
    if(!navi_open_file_cache_pool)
        navi_open_file_cache_pool = ngx_create_pool(OPEN_FILE_CACHE_SIZE, pcycle->log);
    if(navi_open_file_cache_pool == NULL){
        ngx_log_error(NGX_LOG_ALERT, pcycle->log, 0,
                          "alloc open file cache buffer failed");
        return NULL;
    }

    ngx_navi_open_file_cache_t *nv_file_cache = ngx_palloc(navi_open_file_cache_pool, sizeof(ngx_navi_open_file_cache_t));
    if(nv_file_cache){
        nv_file_cache->file_cache = ngx_open_file_cache_init(navi_open_file_cache_pool, max_cache_size, (time_t)valid_file_time);
        if(!nv_file_cache->file_cache)
            return NULL;
        nv_file_cache->file_min_uses = min_file_uses;
        nv_file_cache->file_valid_time = valid_file_time;
    }
    return nv_file_cache;
}

static int ngx_http_navi_get_cached_open_file(void* cache, const char* path, void* pool)
{
    ngx_navi_open_file_cache_t *nv_file_cache = (ngx_navi_open_file_cache_t*)cache;
    ngx_open_file_info_t file_info;
    ngx_str_t name;
    name.data = (u_char*)path;
    name.len = strlen(path);

    memset(&file_info, 0 ,sizeof(ngx_open_file_info_t));
    file_info.min_uses = nv_file_cache->file_min_uses;
    file_info.valid = nv_file_cache->file_valid_time;
    ngx_open_cached_file(nv_file_cache->file_cache, &name, &file_info, pool);
    return file_info.fd;
}

static void ngx_http_navi_delete_cached_open_file(void* cache, const char* path, void* pool)
{
    ngx_navi_open_file_cache_t *nv_file_cache = (ngx_navi_open_file_cache_t*)cache;
    ngx_open_file_info_t file_info;
    ngx_str_t name;
    name.data = (u_char*)path;
    name.len = strlen(path);

    memset(&file_info, 0 ,sizeof(ngx_open_file_info_t));
    ngx_open_cached_file(nv_file_cache->file_cache, &name, &file_info, pool);
}

static bool ngx_http_navi_check_dir(void* cache, const char* path)
{
    ngx_navi_open_file_cache_t *nv_file_cache = (ngx_navi_open_file_cache_t*)cache;
    ngx_open_file_info_t file_info;
    ngx_str_t name;
    name.data = (u_char*)path;
    name.len = strlen(path);

    memset(&file_info, 0 ,sizeof(ngx_open_file_info_t));
    file_info.min_uses = nv_file_cache->file_min_uses;
    file_info.test_dir = 1;
    return ngx_open_cached_file(nv_file_cache->file_cache, &name, &file_info, navi_open_file_cache_pool) == NGX_OK;
}

static void navi_http_navi_open_file_cache_clean(void *mgr, void* cache)
{
    if(navi_open_file_cache_pool){
        ngx_destroy_pool(navi_open_file_cache_pool);
        navi_open_file_cache_pool = NULL;
    }
    return;
}
