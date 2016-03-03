/*
 * navi_request.c
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 */

#include "navi_request.h"
#include "navi_request_impl.h"
#include "navi_response.h"
#include "navi_frame_log.h"
#include "navi_inner_util.h"
#include "navi_request_common.c"
#include "navi_module_impl.h"
#include "navi_static_content.h"
#include <ctype.h>

static int set_args_raw(navi_request_impl_t* req, const char* arg, int unescape);

int navi_http_request_set_uri(navi_request_t* h, const char* uri, int unescape)
{
	if (!check_req_h(h))
		return NAVI_ARG_ERR;

	if (!uri || strlen(uri) == 0 || uri[0] != '/')
		return NAVI_ARG_ERR;

	int uri_len = strlen(uri);
	int ret = NAVI_OK;
	navi_request_impl_t* req = navi_req_h2i(h);

	if (req->navi_status != NAVI_REQUEST_REGISTED && req->main != req)
		return NAVI_ARG_ERR;

	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;

	char *ch_q = strrchr(uri, '?');
	if (ch_q) {
		uri_len = ch_q - uri;
		if (NAVI_OK != (ret = set_args_raw(req, ch_q + 1, unescape)))
			return ret;
	}

	char* cp = (char*) navi_pool_nalloc(pool, uri_len + 1);
	if (!cp) {
		NAVI_SYSERR_LOG();
		return NAVI_INNER_ERR;
	}

	memcpy(cp, uri, uri_len + 1);
	cp[uri_len] = 0;
	if (unescape) {
		navi_unescape_uri((u_char*) cp, strlen(cp), 0);
	}
	req->uri = cp;

	return NAVI_OK;
}

int navi_http_request_set_args_raw(navi_request_t* h, const char* arg)
{
	if (!check_req_h(h))
		return NAVI_ARG_ERR;

	if (!arg || strlen(arg) == 0)
		return NAVI_ARG_ERR;

	navi_request_impl_t* req = navi_req_h2i(h);

	if (req->navi_status != NAVI_REQUEST_REGISTED && req->main != req)
		return NAVI_ARG_ERR;

	return set_args_raw(req, arg, 1);
}

int navi_http_request_set_arg(navi_request_t* h, const char* argnm,
    const char* value)
{
	if (!check_req_h(h))
		return NAVI_ARG_ERR;
	if (!argnm || strlen(argnm) == 0 )
		return NAVI_ARG_ERR;
	if (!value)
		value = "";

	int ret;
	navi_request_impl_t* req = navi_req_h2i(h);
	if (req->navi_status != NAVI_REQUEST_REGISTED && req->main != req)
		return NAVI_ARG_ERR;

	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;

	if (req->args == NULL) {
		req->args = navi_hash_init(pool);
		if (req->args == NULL) {
			NAVI_SYSERR_LOG();
			return NAVI_INNER_ERR;
		}
	}

	ret = navi_hash_set(req->args, argnm, value);
	if (ret == NAVI_HASH_NEW || ret == NAVI_HASH_REPLACE)
		return NAVI_OK;

	NAVI_SYSERR_LOG();
	return ret;
}

static int set_args_raw(navi_request_impl_t* req, const char* arg, int unescape)
{
	char* p_pair, *ctx_pair, *p_key, *p_value, *ctx;
	uint32_t cnt = 0;
	char buf[1024];
	char* tmp = buf;
	int len = strlen(arg);
	int ret = NAVI_OK;

	if (len > 1023) {
		tmp = (char*) malloc(len + 1);
		if (!tmp) {
			NAVI_SYSERR_LOG();
			return NAVI_INNER_ERR;
		}
	}

	strcpy(tmp, arg);
	p_pair = strtok_r(tmp, "&", &ctx_pair);
	while (p_pair) {
		p_key = strtok_r(p_pair, "=", &ctx);
		p_value = strtok_r(NULL, "=", &ctx);
		if (!p_key) {
			if (tmp != buf)
				free(tmp);
			return NAVI_ARG_ERR;
		}

		if (unescape) {
			navi_unescape_uri((u_char*) p_key, strlen(p_key), 0);
			if(p_value)
				navi_unescape_uri((u_char*) p_value, strlen(p_value), 0);
		}

		if (NAVI_OK == (ret = navi_http_request_set_arg(&req->handle, p_key, p_value)))
			cnt++;

		if (ret == NAVI_INNER_ERR) {
			if (tmp != buf)
				free(tmp);
			return ret;
		}

		p_pair = strtok_r(NULL, "&", &ctx_pair);
	};

	if (tmp != buf)
		free(tmp);

	if (cnt)
		return NAVI_OK;
	else
		return NAVI_ARG_ERR;
}

static const char* http_standard_req_headers[] =
    { "Host", "Connection", "If-Modified-Since", "If-Unmodified-Since",
        "User-Agent", "Referer", "Content-Length", "Content-Type", "Range",
        "If-Range", "Transfer-Encoding", "Expect",
        "Accept-Encoding", "Via", "Authorization", "Keep-Alive",
        "X-Forwarded-For",
        "Accept", "Accept-Language", "Cookie",NULL };

static const char* http_standard_resp_headers[] =
    { "Server", "Date", "Content-Length", "Content-Encoding", "Location",
        "Last-Modified", "Accept-Ranges", "Expires", "Cache-Control", "ETag",NULL };

int navi_http_request_set_header(navi_request_t* h, const char* header,
    const char* value)
{
	size_t h_len=0;
	if (!check_req_h(h))
		return NAVI_ARG_ERR;
	if (!header || (h_len=strlen(header)) == 0)
		return NAVI_ARG_ERR;
	if (!value)
		value = "";

	int i;
	/*****
	for (i = 0; http_standard_req_headers[i]; i++) {
		if (strcasecmp(header, http_standard_req_headers[i]) == 0)
			return NAVI_ARG_ERR;
	}
	****/
	navi_request_impl_t* req = navi_req_h2i(h);

	if (req->navi_status != NAVI_REQUEST_REGISTED && req->main != req)
		return NAVI_ARG_ERR;

	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;

	if (req->headers == NULL) {
		req->headers = navi_hash_init(pool);
		if (!req->headers) {
			NAVI_SYSERR_LOG();
			return NAVI_INNER_ERR;
		}
	}
	char case_buf[128];
	char* p_case = case_buf;
	if ( h_len > 127) {
		p_case = (char*)malloc(h_len+1);
	}
	memcpy(p_case,header,h_len+1);
	char* pc = p_case;
	while(*pc) {
		if(islower(*pc)) {
			*pc = toupper(*pc);
		}
		pc++;
	}

	i = navi_hash_set(req->headers, p_case, value);

	if (p_case != case_buf)
		free(p_case);

	if (i == NAVI_HASH_NEW || i == NAVI_HASH_REPLACE)
		return NAVI_OK;
	NAVI_SYSERR_LOG();
	return i;
}

int navi_http_request_set_post(navi_request_t* h, const uint8_t* content,
    size_t size)
{
	if (!check_req_h(h) || size == 0)
		return NAVI_ARG_ERR;

	navi_request_impl_t* req = navi_req_h2i(h);

	if (req->navi_status != NAVI_REQUEST_REGISTED && req->main != req)
		return NAVI_ARG_ERR;

	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;

	if (req->post_size) {
		navi_pool_free(pool,req->post_content);
		req->post_size = 0;
		req->post_content = NULL;
		req->http_method = NAVI_HTTP_METHOD_GET;
	}

	if (req->post_chain) {
		req->post_chain = NULL;
	}

	uint8_t* cp = navi_pool_alloc(pool, size+1);
	if (!cp) {
		NAVI_SYSERR_LOG();
		return NAVI_INNER_ERR;
	}

	memcpy(cp, content, size);
	cp[size] = 0;
	req->http_method = NAVI_HTTP_METHOD_POST;
	req->post_content = cp;
	req->post_size = size;

	return NAVI_OK;
}

int navi_http_request_append_post(navi_request_t* h, const uint8_t* part,
	size_t size)
{
	if (!check_req_h(h) || size == 0 || part == NULL)
			return NAVI_ARG_ERR;

	navi_request_impl_t* req = navi_req_h2i(h);

	if (req->navi_status != NAVI_REQUEST_REGISTED && req->main != req)
		return NAVI_ARG_ERR;

	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;

	if (req->post_chain == NULL) {
		req->post_chain = navi_buf_chain_init(pool);
		if (req->post_chain == NULL) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR,"init post buf chain failed");
			return NAVI_INNER_ERR;
		}
	}

	if (NAVI_OK != navi_buf_chain_append(req->post_chain, part, size) ) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "append post partition failed");
		return NAVI_INNER_ERR;
	}

	return NAVI_OK;
}

size_t navi_http_request_get_uri_query(const navi_request_t* h,char* buf, size_t size)
{
	if ( buf && size ) {
		buf[0] = 0;
	}
	if (!check_req_h(h))
		return 0;

	navi_request_impl_t* req = navi_req_h2i(h);
	size_t escape_len = navi_escape_uri(NULL,req->uri,0);

	void* it = navi_http_request_arg_iter(h);
	const char* arg, *arg_value;
	while ( arg = navi_http_request_arg_iter_next(it,&arg_value) ) {
		escape_len += navi_escape_uri(NULL,(u_char*)arg,2);
		escape_len += navi_escape_uri(NULL,(u_char*)arg_value,2);
		escape_len += 2; //'?aa=aavalue'  '&bb=bbvalue'
	}
	navi_http_request_arg_iter_destroy(it);

	if(buf==NULL)
		return escape_len;

	char* p_ret = NULL;
	char* p = NULL;
	char tmp_buf[4096];

	if ( escape_len >= size ) {
		p_ret = tmp_buf;
		if (escape_len > 4095) {
			p_ret = (char*) malloc(escape_len +1 );
		}
	}
	else {
		p_ret = buf;
	}
	p = p_ret;
	p += navi_escape_uri(p,req->uri,0);
	it = navi_http_request_arg_iter(h);
	int i=0;
	while ( arg = navi_http_request_arg_iter_next(it,&arg_value) ) {
		if (i==0)
			*p++ = '?';
		else if (i>0)
			*p++ = '&';

		p += navi_escape_uri(p,(u_char*)arg,2);
		*p++ = '=';
		p += navi_escape_uri(p,(u_char*)arg_value,2);
		i++;
	}

	if (p_ret != buf) {
		memcpy(buf,p_ret,size);
		buf[size-1] = 0;

		if (p_ret != tmp_buf)
			free(p_ret);
	}

	return escape_len;
}

const char* navi_http_request_get_uri(const navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);
	return req->uri;
}

const char* navi_http_request_get_arg(const navi_request_t* h, const char* nm)
{
	if (!check_req_h(h))
		return NULL;
	if (!nm || strlen(nm) == 0)
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);

	if (req->args == NULL)
		return NULL;

	return navi_hash_get(req->args, nm);
}

const char* navi_http_request_get_header(const navi_request_t* h,
    const char* nm)
{
	size_t h_len=0;
	if (!check_req_h(h))
		return NULL;
	if (!nm || (h_len=strlen(nm)) == 0)
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);

	if (req->headers == NULL)
		return NULL;

	char case_buf[128];
	char* p_case = case_buf;
	if ( h_len > 127) {
		p_case = (char*)malloc(h_len+1);
	}
	memcpy(p_case,nm,h_len+1);
	char* pc = p_case;
	while(*pc) {
		if(islower(*pc)) {
			*pc = toupper(*pc);
		}
		pc++;
	}

	const char* ret= navi_hash_get(req->headers,p_case);
	if ( p_case != case_buf)
		free(p_case);

	return ret;
}

size_t navi_http_request_get_post(const navi_request_t* h, const uint8_t** body)
{
	if (!check_req_h(h))
		return 0;

	navi_request_impl_t* req = navi_req_h2i(h);
	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;

	if (req->post_chain) {
		navi_pool_free(pool,req->post_content);
		req->post_size = navi_buf_chain_get_content(req->post_chain,NULL,0);
		req->post_content = (uint8_t*)navi_pool_alloc(pool,
			req->post_size + 1);

		if (req->post_content == NULL) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR,"build post content from chain failed.");
			req->post_size = 0;
		}
		else {
			navi_buf_chain_get_content(req->post_chain,req->post_content,req->post_size);
			req->post_content[req->post_size] = 0;
		}

		req->post_chain = NULL;
	}

	if (body==NULL)
		return req->post_size;

	if (req->post_size == 0)
		*body = NULL;
	else
		*body = req->post_content;
	return req->post_size;
}

int navi_http_response_set_status(navi_request_t* h, int code)
{
	if (!check_req_h(h))
		return NAVI_ARG_ERR;
	if (code < 100 || code > 599)
		return NAVI_ARG_ERR;

	navi_request_impl_t* req = navi_req_h2i(h);

	req->resp_http_code = code;
	return NAVI_OK;
}

int navi_http_response_set_header(navi_request_t* h, const char* header,
    const char* value)
{
	size_t h_len=0;
	if (!check_req_h(h))
		return NAVI_ARG_ERR;
	if (!header || (h_len=strlen(header)) == 0)
		return NAVI_ARG_ERR;
	if (!value )
		value = "";

	navi_request_impl_t* req = navi_req_h2i(h);
	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;
	int i;
	/****
	for (i = 0; http_standard_resp_headers[i]; i++) {
		if (strcasecmp(header, http_standard_resp_headers[i]) == 0)
			return NAVI_ARG_ERR;
	}
	****/

	if (req->resp_http_headers == NULL) {
		req->resp_http_headers = navi_hash_init(pool);
		if (!req->resp_http_headers) {
			NAVI_SYSERR_LOG();
			return NAVI_INNER_ERR;
		}
	}

	char case_buf[128];
	char* p_case = case_buf;
	if ( h_len > 127) {
		p_case = (char*)malloc(h_len+1);
	}
	memcpy(p_case,header,h_len+1);
	char* pc = p_case;
	while(*pc) {
		if(islower(*pc)) {
			*pc = toupper(*pc);
		}
		pc++;
	}

	i = navi_hash_set(req->resp_http_headers, p_case, value);
	if (p_case != case_buf)
		free(p_case);

	if (i == NAVI_HASH_NEW || i == NAVI_HASH_REPLACE)
		return NAVI_OK;
	NAVI_SYSERR_LOG();
	return i;
}

int navi_http_response_set_body(navi_request_t* h, const uint8_t* content, size_t size)
{
	if (!check_req_h(h) || size == 0)
		return NAVI_ARG_ERR;

	navi_request_impl_t* req = navi_req_h2i(h);
	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;

	if ( req == req->main &&  req->main_data->outbody_stream  )
		return NAVI_FAILED;

	if (req->resp_http_body_len) {
		//if (req->resp_http_body_heap)
		//	free(req->resp_http_body);
		//else
		navi_pool_free(pool,req->resp_http_body);

		req->resp_http_body_len = 0;
		req->resp_http_body = NULL;
		//req->resp_http_body_heap = 0;
	}

	if (req->resp_body_chain) {
		req->resp_body_chain = NULL;
	}

	uint8_t* cp = navi_pool_alloc(pool, size+1);
	if (!cp) {
		NAVI_SYSERR_LOG();
		return NAVI_INNER_ERR;
	}

	memcpy(cp, content, size);
	cp[size] = 0;
	req->resp_http_body = cp;
	req->resp_http_body_len = size;

	if ( req->main == req) {
		req->main_data->outbody_file = 0;
		req->main_data->outbody_navi = 0;
		req->main_data->outbody_bin = 1;
	}

	return NAVI_OK;
}

int navi_http_response_append_body(navi_request_t* h, const uint8_t* part,
	size_t size)
{
	if (!check_req_h(h) || size == 0 || part == NULL)
		return NAVI_ARG_ERR;

	navi_request_impl_t* req = navi_req_h2i(h);

	if ( req == req->main && req->main_data->outbody_stream)
		return NAVI_FAILED;

	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;
	if (req->resp_body_chain == NULL) {
		req->resp_body_chain = navi_buf_chain_init(pool);
		if (req->resp_body_chain == NULL) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR,"init post buf chain failed");
			return NAVI_INNER_ERR;
		}
	}

	if (NAVI_OK != navi_buf_chain_append(req->resp_body_chain, part, size) ) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "append post partition failed");
		return NAVI_INNER_ERR;
	}

	if ( req == req->main ) {
		req->main_data->outbody_file = 0;
		req->main_data->outbody_navi = 0;
		req->main_data->outbody_bin = 1;
	}

	return NAVI_OK;
}

int navi_http_response_get_status(const navi_request_t* h)
{
	if (!check_req_h(h))
		return -1;

	navi_request_impl_t* req = navi_req_h2i(h);

	return req->resp_http_code;
}

const char* navi_http_response_get_header(const navi_request_t* h,
    const char* nm)
{
	size_t h_len=0;
	if (!check_req_h(h))
		return NULL;
	if (!nm || (h_len=strlen(nm)) == 0)
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);

	if (req->resp_http_headers == NULL)
		return NULL;

	char case_buf[128];
	char* p_case = case_buf;
	if ( h_len > 127) {
		p_case = (char*)malloc(h_len+1);
	}
	memcpy(p_case,nm,h_len+1);
	char* pc = p_case;
	while(*pc) {
		if(islower(*pc)) {
			*pc = toupper(*pc);
		}
		pc++;
	}

	const char* ret= navi_hash_get(req->resp_http_headers,p_case);
	if ( p_case != case_buf)
		free(p_case);

	return ret;
}

size_t navi_http_response_get_body(const navi_request_t* h, const uint8_t** body)
{
	if (!check_req_h(h))
		return 0;

	navi_request_impl_t* req = navi_req_h2i(h);
	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;
	if (req->resp_body_chain) {
		//if (req->resp_http_body_heap) {
		//	free(req->resp_http_body);
		//}
		//else
		navi_pool_free(pool,req->resp_http_body);

		//req->resp_http_body_heap = 0;

		req->resp_http_body_len = navi_buf_chain_get_content(req->resp_body_chain,NULL,0);
		req->resp_http_body = (uint8_t*)navi_pool_alloc(pool,
			req->resp_http_body_len + 1);

		if (req->resp_http_body == NULL) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR,"build post content from chain failed.");
			req->resp_http_body_len = 0;
		}
		else {
			navi_buf_chain_get_content(req->resp_body_chain,req->resp_http_body,
				req->resp_http_body_len);
			req->resp_http_body[req->resp_http_body_len] = 0 ;
		}

		req->resp_body_chain = NULL;
	}

	if (body==NULL)
		return req->resp_http_body_len;

	if (req->resp_http_body_len == 0)
		*body = NULL;
	else
		*body = req->resp_http_body;
	return req->resp_http_body_len;
}

bool navi_http_request_is_bigpost(navi_request_t* h)
{
	if (!check_req_h(h))
		return false;

	navi_request_impl_t* req = navi_req_h2i(h);
	return req->main->main_data->bigpost_file != 0;
}

//在主请求入口、结束过程(中间衔接过程)、定时器处理、虚事件处理中
//可以调用该函数。
void navi_http_request_abort_bigpost(navi_request_t* h)
{
	if (!check_req_h(h))
		return ;

	navi_request_impl_t* req = navi_req_h2i(h);
	req = req->main;
	if ( req->main_data->bigpost_file ) {
		if ( !req->main_data->bigpost_complete ) {
			req->main_data->bigpost_abort = 1;
		}
		if ( req->main_data->bigpost_temp_file){
			unlink(req->main_data->bigpost_temp_file);
			req->main_data->bigpost_temp_file = NULL;
		}
	}
}

bool navi_http_request_is_bigpost_abort(navi_request_t* h)
{
	if (!check_req_h(h))
		return true;

	navi_request_impl_t* req = navi_req_h2i(h);
	req = req->main;

    return req->main_data->bigpost_file == 0 || req->main_data->bigpost_abort;
}

navi_response_t* navi_request_response_obj(navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);

	req = req->main;

	if (req->main_data->resp == NULL) {
		req->main_data->resp = navi_response_init(req);
		if (req->main_data->resp == NULL) {
			NAVI_SYSERR_LOG();
		}
	}
	return req->main_data->resp;
}

void navi_request_set_process(navi_request_t* h, navi_request_process_fp fun)
{
	if (!check_req_h(h))
		return;
	h->process_request = fun;
}

void navi_request_set_cleanup(navi_request_t* h, navi_request_process_fp fun)
{
	if (!check_req_h(h))
		return;
	h->clean_up = fun;
}

void navi_request_set_custom_context(navi_request_t* h, void* ctx)
{
	if (!check_req_h(h))
		return;
	h->custom_ctx = ctx;
}

void navi_request_set_process_own(navi_request_t* h, navi_request_process_fp fun)
{
	if (!check_req_h(h))
		return;
	navi_request_impl_t* req = navi_req_h2i(h);
	if (req == req->main)
		return;
	h->process_own = fun;
}

void navi_request_set_cleanup_own(navi_request_t* h, navi_request_process_fp fun)
{
	if (!check_req_h(h))
		return;
	navi_request_impl_t* req = navi_req_h2i(h);
	if (req == req->main)
		return;
	h->clean_up_own = fun;
}

void navi_request_set_context_own(navi_request_t* h, void* ctx)
{
	if (!check_req_h(h))
		return;
	navi_request_impl_t* req = navi_req_h2i(h);
	if (req == req->main)
		return;
	h->ctx_own = ctx;
}

void navi_request_set_timeout(navi_request_t* h, uint32_t to_ms)
{
	if (!check_req_h(h))
		return;

	navi_request_impl_t* req = navi_req_h2i(h);

	if (req->main != req)
		return;
	req->main_data->time_out = to_ms;
}

uint32_t navi_request_timeout(navi_request_t* h)
{
	if (!check_req_h(h))
		return NAVI_ARG_ERR;

	navi_request_impl_t* req = navi_req_h2i(h);
	return req->main->main_data->time_out;
}

const char* navi_request_xcaller(navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);
	return req->main->main_data->xcaller;
}

const char* navi_request_cli_ip(navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);
	return req->main->main_data->cli_ip;
}

const char* navi_request_service(navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);
	return req->main->main_data->service;
}

const char* navi_request_module(navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);
	return req->main->main_data->module;
}

const char* navi_request_method(navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);
	return req->main->main_data->method;
}

const char* navi_request_resturi(navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);
	return req->main->main_data->rest_uri;
}

int64_t navi_request_cost_ns(navi_request_t* h)
{
	if (!check_req_h(h))
		return 0;

	navi_request_impl_t* req = navi_req_h2i(h);
	if (req->last_eval_stmp == 0) {
		req->last_eval_stmp = -cur_time_us();
		req->cost_us = 0;
		return 0;
	}
	else {
		int64_t cur = cur_time_us();
		req->cost_us += cur + req->last_eval_stmp;
		req->last_eval_stmp = -cur;
		return req->cost_us;
	}
}

static void navi_request_add2_reg(navi_request_impl_t* req)
{
	navi_request_impl_t* main = req->main;

	navi_list_insert_tail(&main->main_data->reg_chain, &req->cmd_link);
	req->navi_status = NAVI_REQUEST_REGISTED;
}

static void navi_request_add2_cancel(navi_request_impl_t* req)
{
	navi_request_impl_t* main = req->main;

	navi_list_insert_tail(&main->main_data->cancel_chain, &req->cmd_link);
	req->navi_status = NAVI_REQUEST_CANCEL_REGISTED;
}

navi_request_impl_t* get_recycle_request(navi_request_impl_t* main)
{
	chain_node_t* recycle_list = &main->main_data->recycle_chain;
	if (recycle_list->next==recycle_list)
		return NULL;
	chain_node_t* quiting = recycle_list->next;
	navi_list_remove2(quiting);
	return (navi_request_impl_t*)navi_list_data(quiting,navi_request_impl_t,cmd_link);
}

navi_request_t* navi_request_add_sub(navi_request_t* pr, const char* uri,
    const char* args_raw, const uint8_t* post,
    size_t post_size, navi_request_process_fp fun, void* ctx,
    navi_request_process_fp clean_up)
{
	if (!check_req_h(pr))
		return NULL;

	if ( navi_request_get_status(pr) != NAVI_REQUEST_FRAME_PROCESSING &&
		/*cnavi0.3.0放宽限制，可以以父子请求树一次提交*/
		navi_request_get_status(pr) != NAVI_REQUEST_REGISTED)
		return NULL;

	navi_request_impl_t** pp = NULL;
	navi_request_impl_t* parent = navi_req_h2i(pr);
	navi_request_impl_t* new = get_recycle_request(parent->main);
	if (!new) {
		new = navi_pool_calloc(parent->main->pool_storage, 1, sizeof(navi_request_impl_t));
		new->cld_dp = navi_pool_create(1024);
	}

	if (!new) {
		NAVI_SYSERR_LOG();
		return NULL;
	}

	new->handle._magic = NAVI_HANDLE_MAGIC;
	new->handle.custom_ctx = ctx;
	new->handle.process_request = fun;
	new->handle.clean_up = clean_up;

	new->main = parent->main;
	new->navi_status = NAVI_REQUEST_REGISTED;

	if (uri && strlen(uri)) {
		if (navi_http_request_set_uri(&new->handle, uri, 1) != NAVI_OK)
			return NULL;
	}

	if (args_raw && strlen(args_raw)) {
		if (navi_http_request_set_args_raw(&new->handle, args_raw) != NAVI_OK)
			return NULL;
	}

	new->http_method = NAVI_HTTP_METHOD_GET;

	if (post_size) {
		if (navi_http_request_set_post(&new->handle, post, post_size) != NAVI_OK)
			return NULL;
		new->http_method = NAVI_HTTP_METHOD_POST;
	}

	new->parent = parent;
	parent->pending_subs++;

	pp = &parent->child;

	while (*pp) {
		pp = &((*pp)->next);
	}
	*pp = new;

	char tmp_buf[256];
	snprintf(tmp_buf,sizeof(tmp_buf),"cnavi/%s/%s",navi_request_service(pr),navi_request_module(pr));
	navi_http_request_set_header(&new->handle,"x-caller",tmp_buf);

	navi_request_add2_reg(new);

	if ( new->main->drive_from_rest ) {
		navi_request_trigger_rest_drive(&new->main->handle);
	}

	return &new->handle;
}

void navi_request_cancel(navi_request_t* h)
{
	if (!check_req_h(h))
		return;

	navi_request_impl_t* req = navi_req_h2i(h);

	switch (req->navi_status)
	{
	case NAVI_REQUEST_REGISTED:
		quit_reg_tree(req);
		if (req->parent && req->parent->pending_subs)
			req->parent->pending_subs--;
		recycle_sub(req);
		break;
	case NAVI_REQUEST_DRIVER_PROCESSING:
		navi_request_add2_cancel(req);
		break;
	case NAVI_REQUEST_FRAME_PROCESSING: {
		if ( req->main == req) {
			navi_timer_mgr_cancelall(&req->main_data->timers);
			navi_request_quitall_vevent(req);
			navi_http_request_abort_bigpost(h);
			navi_request_respbody_streaming_abort(&req->handle);
		}
		navi_request_impl_t* sub = req->child;
		while (sub) {
			navi_request_cancel(&sub->handle);
			sub = sub->next;
		}
	}
		break;
	}

	if ( req->main->drive_from_rest ) {
		navi_request_trigger_rest_drive(&req->main->handle);
	}

	return;
}

void navi_request_abort_root(navi_request_t* handle,const char* reason) {
	if (!check_req_h(handle))
		return;
	navi_request_impl_t* req = navi_req_h2i(handle);
	navi_request_impl_t* root = req->main;
	navi_response_t* resp = navi_request_response_obj(handle);
	if (reason) {
		navi_http_response_set_header(&root->handle,"Navi-Frame-Ctrl",reason);
		navi_response_set_desc(resp,-1,"navi frame", reason);
	}
	else {
		navi_http_response_set_header(&root->handle,"Navi-Frame-Ctrl","aborted");
		navi_response_set_desc(resp,-1,"navi frame", "aborted");
	}

	navi_request_cancel(&root->handle);
	req->main_data->cur_ctrl = NAVI_ROOT_DENYED;
}


void navi_request_trace(navi_request_t* handle, navi_trace_type_e e, const char* fmt, ...)
{
	if (!check_req_h(handle))
		return;
	navi_request_impl_t* req = navi_req_h2i(handle);
	navi_request_impl_t* root = req->main;

	navi_module_t* mo = navi_request_current_module(&root->handle);
	navi_module_impl_t* mi = navi_mod_h2i(mo);
	if (mi->enable_trace) {
		if (root->main_data->trace==NULL)
			root->main_data->trace = navi_trace_init(root->pool_storage);

		va_list ap;
		va_start(ap, fmt);
		navi_vtrace(root->main_data->trace,mo->mod_name,e,fmt,ap);
		va_end(ap);
	}
	return;
}

void* navi_request_alloc(navi_request_t* h, size_t sz)
{
	if (!check_req_h(h))
		return NULL;
	navi_request_impl_t* req = navi_req_h2i(h);
	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;
	return navi_pool_alloc(pool,sz);
}

char* navi_request_strdup(navi_request_t* h, const char* src)
{
	if (!check_req_h(h))
		return NULL;
	navi_request_impl_t* req = navi_req_h2i(h);
	navi_pool_t* pool = req->main==req ? req->pool_storage: req->cld_dp;
	return navi_pool_strdup(pool,src);
}

navi_pool_t* navi_request_pool(navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;
	navi_request_impl_t* req = navi_req_h2i(h);
	return req->main==req ? req->pool_storage: req->cld_dp;
}

void* navi_request_sub_iter(navi_request_t* pr, navi_request_status_e status)
{
	if (!check_req_h(pr))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(pr);
	navi_request_impl_t* main = req->main;

	navi_request_impl_t* child;
	navi_griter_t* iter = navi_griter_get(&main->main_data->iter_mgr);

	child = req->child;
	while (child) {
		if (child->navi_status == status) {
			iter->cur = child;
			break;
		}
		child = child->next;
	}

	iter->_magic = NAVI_ITER_SUB_MAGIC;
	iter->ctx = (void*) status;
	return iter;
}

navi_request_t* navi_request_sub_iter_next(void* it)
{
	navi_griter_t* iter = (navi_griter_t*) it;
	navi_request_t* ret = NULL;

	if (iter->_magic != NAVI_ITER_SUB_MAGIC)
		return NULL;

	if (iter->cur == NULL)
		return NULL;

	navi_request_impl_t* child = (navi_request_impl_t*) iter->cur;

	do {
		if (child->navi_status == (navi_request_status_e) iter->ctx) {
			break;
		}
		child = child->next;
	}
	while (child);

	if (!child)
		return NULL;

	ret = &child->handle;

	do {
		child = child->next;
		if (child->navi_status == (navi_request_status_e) iter->ctx) {
			break;
		}
	}
	while (child);

	iter->cur = child;
	return ret;
}

void navi_request_sub_iter_destroy(void* it)
{
	navi_griter_t* iter = (navi_griter_t*) it;
	if (!iter || iter->_magic != NAVI_ITER_SUB_MAGIC)
		return;
	navi_griter_recycle(iter);
}

navi_request_status_e navi_request_get_status(navi_request_t* h)
{
	if (!check_req_h(h))
		return NAVI_ARG_ERR;

	navi_request_impl_t* req = navi_req_h2i(h);
	return req->navi_status;
}

navi_request_t* navi_request_get_parent(const navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);

	req = req->parent;
	if (req)
		return &req->handle;
	else
		return NULL;
}

navi_request_t* navi_request_get_root(const navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);

	req = req->main;
	if (req)
		return &req->handle;
	else
		return NULL;
}

void* navi_http_request_header_iter(const navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);
	return navi_hash_iter(req->headers);
}

const char* navi_http_request_header_iter_next(void* it, const char** value)
{
	if (!it)return NULL;
	navi_hent_t* he = navi_hash_iter_next(it);
	if (!he) return NULL;
	const char* key = he->k;
	if(value)*value = (const char*)he->v;
	return key;
}

void navi_http_request_header_iter_destroy(void* iter)
{
	if (!iter)return;
	navi_hash_iter_destroy(iter);
}

void* navi_http_request_arg_iter(const navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;
	navi_request_impl_t* req = navi_req_h2i(h);
	return navi_hash_iter(req->args);
}

const char* navi_http_request_arg_iter_next(void* it, const char** value)
{
	if (!it)return NULL;
	navi_hent_t* he = navi_hash_iter_next(it);
	if (!he) return NULL;
	const char* key = he->k;
	if(value)*value = (const char*)he->v;
	return key;
}

void navi_http_request_arg_iter_destroy(void* iter)
{
	if (!iter)return ;
	navi_hash_iter_destroy(iter);
}

void* navi_http_response_header_iter(const navi_request_t* h)
{
	if (!check_req_h(h))
		return NULL;

	navi_request_impl_t* req = navi_req_h2i(h);
	return navi_hash_iter(req->resp_http_headers);
}

const char* navi_http_response_header_iter_next(void* it, const char** value)
{
	if (!it)return NULL;
	navi_hent_t* he = navi_hash_iter_next(it);
	if (!he) return NULL;
	const char* key = he->k;
	if(value)*value = (const char*)he->v;
	return key;
}

void navi_http_response_header_iter_destroy(void* it)
{
	if (!it)return;
	navi_hash_iter_destroy(it);
}

void navi_request_recycle_on_end(navi_request_t* req)
{
	if (!check_req_h(req))
		return;

	navi_request_impl_t* ri = navi_req_h2i(req);
	if (ri->main != ri)
		ri->recycle_flag = 1/*true*/;
	return;
}

void navi_request_recycle(navi_request_t* req)
{
	if (!check_req_h(req))
		return;

	navi_request_impl_t* ri = navi_req_h2i(req);

	if (ri->navi_status == NAVI_REQUEST_COMPLETE ||
		ri->navi_status == NAVI_REQUEST_CANCELED ||
		ri->navi_status == NAVI_REQUEST_PROC_FAILED) {
		recycle_sub(ri);
	}
}

typedef struct navi_request_timer_s {
	navi_request_impl_t *req;
	navi_req_timer_fp proc;
	navi_req_timer_fp destroy;
	void* args;
	navi_timer_h handle;
} navi_req_timer_t;

static int navi_req_timer_handler( void* arg)
{
	navi_req_timer_t* tmr = (navi_req_timer_t*)arg;
	if (tmr->proc)
		tmr->proc(&tmr->req->handle, tmr->handle, tmr->args);
	return 0;
}

static int navi_req_timer_destroyer( void* arg)
{
	navi_req_timer_t* tmr = (navi_req_timer_t*)arg;
	if (tmr->destroy)
		tmr->destroy(&tmr->req->handle, tmr->handle, tmr->args);
	free(tmr);
	return 0;
}

navi_timer_h navi_request_add_timer(navi_request_t* rt,
	navi_req_timer_fp proc, void* args, navi_req_timer_fp destroy,
	uint32_t to_ms, bool interval)
{
	navi_request_impl_t* ri = navi_req_h2i(rt);
	if ( ri != ri->main ) return NULL;
	if ( to_ms == 0 ) return NULL;

	navi_req_timer_t* req_tmr = (navi_req_timer_t*)calloc(1, sizeof(navi_req_timer_t));
	req_tmr->args = args;
	req_tmr->proc = proc;
	req_tmr->destroy = destroy;
	req_tmr->req = ri;

	navi_timer_h ret = navi_timer_add(&ri->main_data->timers,
		interval?NAVI_TIMER_INTERVAL:NAVI_TIMER_ONCE, to_ms,
		navi_req_timer_handler,
		req_tmr, navi_req_timer_destroyer, NULL);
	req_tmr->handle = ret;

	if ( ri->drive_from_rest ) {
		navi_request_trigger_rest_drive(rt);
	}

	return ret;
}

void navi_request_cancel_timer(navi_request_t* rt, navi_timer_h th)
{
	navi_request_impl_t* ri = navi_req_h2i(rt);
	if ( ri != ri->main ) return;

	navi_timer_cancel(th);
	if (navi_timer_is_zombie(th))
		navi_timer_cleanup(th);
	else {
		if ( ri->drive_from_rest ) {
			navi_request_trigger_rest_drive(rt);
		}
	}
}

navi_respbody_type_e navi_request_respbody_type(navi_request_t* main)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( ri != ri->main ) return NAVI_RESP_UNKNOWN_TYPE;
	if ( ri->main_data->outbody_stream )
		return NAVI_RESP_STREAM;
	else if (ri->main_data->outbody_file)
		return NAVI_RESP_FILE;
	else if (ri->main_data->outbody_navi)
		return NAVI_RESP_NAVI_STANDARD;
	else if (ri->main_data->outbody_bin)
		return NAVI_RESP_BIN;
	else
		return NAVI_RESP_UNKNOWN_TYPE;
}

int navi_request_set_respbody_scfile(navi_request_t* main, const char* scfile_mgr_path, const char* scfile_id)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( ri != ri->main ) return -1;
	if ( ri->main_data->outbody_stream )
		return -1;

	void* mgr = navi_scfile_mgr_get(scfile_mgr_path);
	if (!mgr)
		return -1;

	int err = 0;
	navi_scfd_t* scfd = navi_request_get_scfile_readfd(main, mgr, scfile_id, &err);
	if (!scfd) {
		NAVI_FRAME_LOG(NAVI_LOG_WARNING, "response static file resource"
			" which not exists:%s %s",scfile_mgr_path, scfile_id);
		return -1;
	}
	ri->main_data->file_body_fd = scfd->fd;
	scfd->fd = -1;
	navi_scfd_clean(scfd);

	ri->main_data->outbody_file_cached_fd = 1;
	ri->main_data->outbody_file = 1;
	ri->main_data->outbody_navi = 0;
	ri->main_data->outbody_bin = 0;

	return 0;
}

int navi_request_respbody_filefd(navi_request_t* main)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( ri != ri->main ) return -1;
	if ( !ri->main_data->outbody_file ) return -1;
	return ri->main_data->file_body_fd;
}

bool navi_request_disable_autofin(navi_request_t* main)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( ri != ri->main ) return false;

	if ( ri->main_data->auto_finalize == 0)
		return true;

	if ( ri->main_data->cur_stage != NAVI_ROOT_STAGE_APP && ri->main_data->cur_stage != NAVI_ROOT_STAGE_APP_BIGPOST ) {
		return false;
	}

	ri->main_data->auto_finalize = 0;
	return true;
}

bool navi_request_enable_autofin(navi_request_t* main)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( ri != ri->main ) return false;

	if ( ri->main_data->auto_finalize )
		return true;

	ri->main_data->auto_finalize = 1;

	if ( ri->drive_from_rest ) {
		if ( navi_request_can_step(main) ) {
			navi_request_trigger_rest_drive(main);
		}
	}

	return true;
}

bool navi_request_respbody_enable_streaming(navi_request_t* main, ssize_t obody_total)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( ri != ri->main ) return false;
	if ( ri->main_data->cur_stage != NAVI_ROOT_STAGE_APP && ri->main_data->cur_stage != NAVI_ROOT_STAGE_APP_BIGPOST ) {
		return false;
	}
	ri->main_data->outbody_stream = 1;
	if (obody_total == 0) {
		ri->main_data->outbody_stream_eof = 1;
	}
	else {
		ri->main_data->streaming_body_total = obody_total<=-1?-1:obody_total;
	}
	return true;
}

ssize_t navi_request_respbody_streaming(navi_request_t* main, const uint8_t* part, size_t sz)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( ri != ri->main ) return -1;
	if ( ri->main_data->outbody_stream == 0 || ri->main_data->streaming_body_total == 0)
		return -1;

	if ( ri->main_data->outbody_stream_eof )
		return -1;

	if ( ri->main_data->streaming_body_total > 0 && ri->main_data->streamed_body_len+sz >
		ri->main_data->streaming_body_total)
		return -1;

	if ( ri->main_data->streamed_body_buf == NULL) {
		ri->main_data->streamed_body_buf = navi_buf_chain_init(ri->pool_storage);
	}

	navi_buf_chain_append(ri->main_data->streamed_body_buf, part, sz);
	ri->main_data->streamed_body_len += sz;

	if (ri->main_data->streaming_body_total>0
			&& ri->main_data->streamed_body_len == ri->main_data->streaming_body_total ) {
		ri->main_data->outbody_stream_eof = 1;
		ri->main_data->outbody_stream_incomplete = 0;
	}

	if ( ri->drive_from_rest) {
		navi_request_trigger_rest_drive(main);
	}
	return sz;
}

void navi_request_respbody_streaming_abort(navi_request_t* main)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( ri != ri->main ) return ;
	if ( ri->main_data->outbody_stream == 0)
		return;
	if (ri->main_data->outbody_stream_eof == 0) {
		ri->main_data->outbody_stream_eof = 1;
		ri->main_data->outbody_stream_incomplete = 1;
	}

	if ( ri->drive_from_rest) {
		if ( navi_request_can_step(main) ) {
			navi_request_trigger_rest_drive(main);
		}
	}
	return;
}

void navi_request_respbody_streaming_eof(navi_request_t* main)
{
	navi_request_impl_t* ri = navi_req_h2i(main);
	if ( ri != ri->main ) return ;
	if ( ri->main_data->outbody_stream == 0)
		return;

	if (ri->main_data->outbody_stream_eof==0) {
		ri->main_data->outbody_stream_eof = 1;
		if (ri->main_data->streaming_body_total>0
			&& ri->main_data->streamed_body_len < ri->main_data->streaming_body_total )
		{
			ri->main_data->outbody_stream_incomplete = 1;
		}
		else
			ri->main_data->outbody_stream_incomplete = 0;
	}

	if ( ri->drive_from_rest) {
		if ( navi_request_can_step(main) ) {
			navi_request_trigger_rest_drive(main);
		}
	}
	return;
}


void navi_request_emerg_response(navi_request_t* handle)
{
	navi_request_impl_t* ri = navi_req_h2i(handle);
	if ( ri != ri->main ) return;
	ri->main_data->should_emerg_resp = 1;

	navi_http_response_set_header(handle, "Connection", "close");
	build_default_main_response(handle,NULL);
}

void navi_request_set_resp_rate(navi_request_t* handle, uint32_t limit_rate, uint32_t limit_rate_after)
{
	navi_request_impl_t* ri = navi_req_h2i(handle);
	if ( ri != ri->main ) return;
	ri->resp_rate = limit_rate;
	ri->resp_rate_after = limit_rate_after;
}

void navi_request_get_resp_rate(navi_request_t* handle, uint32_t *limit_rate, uint32_t *limit_rate_after)
{
	navi_request_impl_t* ri = navi_req_h2i(handle);
	if ( ri != ri->main ) return;
    if(limit_rate)
	    *limit_rate = ri->resp_rate;
    if(limit_rate_after)
	    *limit_rate_after = ri->resp_rate_after;
}
