/*
 * navi_upnavi.h
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#ifndef NAVI_UPNAVI_H_
#define NAVI_UPNAVI_H_
#include "navi_upreq.h"
#include "navi_response.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct navi_upnavi_s navi_upnavi_t;

typedef void (*navi_upnavi_proc_result_fp)(navi_upnavi_t* up, const navi_response_t* res, void* ctx);
typedef void (*navi_upnavi_cleanup_ctx_fp)(navi_upnavi_t* up, void* ctx);

struct navi_upnavi_s
{
	navi_upreq_t base;
	char* root_uri;
	char* module;
	char* method;
	char* xcaller;
	int64_t cost;
	navi_upnavi_proc_result_fp process;
	navi_upnavi_cleanup_ctx_fp cleanup;
	void* ctx;
};

navi_upnavi_t* navi_request_bind_upnavi_ctx(navi_request_t* binded,
    const char* srv_grp,  const char* module,
    const char* method, const char* xcaller,const char* remote_root_uri,
    navi_upnavi_proc_result_fp process, void* ctx,
    navi_upnavi_cleanup_ctx_fp cleanup);

navi_upnavi_t* navi_request_bind_upnavi_ctx_ext(navi_request_t* binded,
    const char* srv_grp, const char* srv_name, const char* module,
    const char* method, const char* xcaller,const char* remote_root_uri,
    navi_upnavi_proc_result_fp process, void* ctx,
    navi_upnavi_cleanup_ctx_fp cleanup);

static inline navi_upnavi_t* navi_request_bind_upnavi(navi_request_t* binded,
    const char* srv_grp,  const char* module,
   const char* method, const char* xcaller,const char* remote_root_uri,
    navi_upnavi_proc_result_fp process)
{
	return navi_request_bind_upnavi_ctx ( binded, srv_grp, module, method,
		xcaller, remote_root_uri, process, NULL, NULL);
}

static inline navi_upnavi_t* navi_request_bind_upnavi_ext(navi_request_t* binded,
    const char* srv_grp,  const char* srv_name, const char* module,
   const char* method, const char* xcaller,const char* remote_root_uri,
    navi_upnavi_proc_result_fp process)
{
	return navi_request_bind_upnavi_ctx_ext( binded, srv_grp, srv_name, module, method,
		xcaller, remote_root_uri, process, NULL, NULL);
}

static inline int navi_upnavi_set_arg(navi_upnavi_t* up, const char* arg, const char* v)
{
	if (!up)
		return NAVI_ARG_ERR;
	return navi_http_request_set_arg(up->base.bind_channel, arg, v);
}

static inline int navi_upnavi_set_header(navi_upnavi_t* up, const char* h, const char* v)
{
	if (!up)
		return NAVI_ARG_ERR;
	return navi_http_request_set_header(up->base.bind_channel, h, v);
}

static inline int navi_upnavi_post_json(navi_upnavi_t* up, const json_t* post)
{
	if (!up)
		return NAVI_ARG_ERR;
	char* d = json_dumps(post, 0);
	navi_http_request_set_post(up->base.bind_channel, d, strlen(d));
	free(d);
	return NAVI_OK;
}

static inline int navi_upnavi_post_raw(navi_upnavi_t* up, const uint8_t* raw, size_t sz)
{
	if (!up)
		return NAVI_ARG_ERR;
	return navi_http_request_set_post(up->base.bind_channel, raw, sz);
}

int navi_upnavi_launch(navi_upnavi_t* up);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_UPNAVI_H_ */
