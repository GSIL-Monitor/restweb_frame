/*
 * restrequest_impl.h
 *
 *  Created on: 2013-8-28
 *      Author: li.lei
 *      Desc：
 *      	navi_request_t的公共接口部分。
 *      	driver和业务层都需要使用本套接口
 */

#ifndef NAVI_REQUEST_H_
#define NAVI_REQUEST_H_

#include "navi_pool.h"
#include "navi_response.h"
#include "navi_common_define.h"
#include "navi_timer_mgr.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum _navi_request_method_e
{
	NAVI_HTTP_METHOD_INVALID,
	NAVI_HTTP_METHOD_GET,
	NAVI_HTTP_METHOD_POST
} navi_request_method_e;

typedef enum _navi_request_status_e
{
	NAVI_REQUEST_STATUS_INVALID,
	//子请求仅在中间层注册，还未在driver层生效。
	//如果在此时对请求cancel，会直接从注册链中移出请求
	NAVI_REQUEST_REGISTED,
	//在中间层注销子请求，还未在driver层生效。
	//只有在进入NAVI_REQUEST_DRIVER_PROCESSING
	//后，子请求才会cancel的需求。
	NAVI_REQUEST_CANCEL_REGISTED,
	//在driver层使得在中间层注册的子请求生效
	NAVI_REQUEST_DRIVER_PROCESSING,
	//driver的http响应已经获得，进入中间层的处理流程
	//此时请求可以再生成子请求
	//此时进行cancel的话，会尝试cancel下级子请求，本请求的状态不变
	NAVI_REQUEST_FRAME_PROCESSING,
	//在NAVI_REQUEST_CANCEL_REGISTED之后，driver层
	//进行了实际的cancel
	NAVI_REQUEST_CANCELED,
	//调用业务层的请求处理回调失败
	//  * 分配资源失败时，流程无法继续。
	//  * 或者是故意的中止处理流程的一种手段
	NAVI_REQUEST_PROC_FAILED,
	//请求已经处理完毕
	NAVI_REQUEST_COMPLETE
} navi_request_status_e;

typedef struct navi_request_s
{
	uint32_t _magic;
	/* 请求处理回调函数。
	 * * 可以是请求的所有子请求都到达某种中止状态后，并且请求本身的响应已到达，且
	 * * process_own_result已经被调用过，调用此回调函数。
	 * * 回调被调用后不再有效
	 * * 对navi主请求而言，就是它的所有子请求完成后，即进行调用
	 */
	int (*process_request)(struct navi_request_s* req, void* custom_ctx);
	int (*clean_up)(struct navi_request_s* req, void* custom_ctx);
	void *custom_ctx;

	/**** cnavi0.3.0 新增回调，原process_request的角色进行拆分, 允许一次提交一个请求树
	 *  当前请求的响应到达之后的回调函数，注意对navi主请求而言，不使用该回调，navi主请求
	 *  的响应是由navi 业务模块给出。 这里的回调只针对子请求，驱动层给出响应后，会调用。
	 *  调用后，回调失效。
	 *
	 *  如果单独提交一个请求，那么process_request和process_own二者设置其中任意一个均可,
	 *  同时设置可也以，但无必要。
	 */
	int (*process_own)(struct navi_request_s* req, void* own_ctx);
	int (*clean_up_own)(struct navi_request_s* req, void* own_ctx);
	void *ctx_own;
} navi_request_t;


typedef void (*navi_req_timer_fp) (navi_request_t* req, navi_timer_h tmr, void* args);
typedef int (*navi_request_process_fp)(navi_request_t* req, void* custom_ctx);
typedef int (*navi_request_bigpost_fp)(navi_request_t* req, void* custom_ctx, const char* file_path);

/* 	@func navi_http_request_set_uri
 * 	@desc
 * 		设置请求的uri。unescape指明是否需要还原转义序列
 * 		在串中，可以包含args串。args 串从最后一个?开始
 */
int navi_http_request_set_uri(navi_request_t* req, const char* uri,int unescape);

/* 	@func navi_htp_request_set_args_raw
 * 	@desc
 * 		设置args串，需要是url args转义格式。
 */
int navi_http_request_set_args_raw(navi_request_t* req, const char* arg);

/* 	@func navi_http_request_set_arg
 * 	@desc
 * 		设置单个arg，argnm，argvalue都使用非转义格式
 *		如果已经存在，则覆盖。
 */
int navi_http_request_set_arg(navi_request_t* req, const char* argnm,
    const char* value);

/* 	@func navi_http_request_set_header
 * 	@desc
 * 		设置单个header。
 */
int navi_http_request_set_header(navi_request_t* req, const char* header,
    const char* value);

/* 	@func navi_http_request_set_post
 * 	@desc
 * 		设置http请求为post方法，并给出post内容。内容会被拷贝。
 */
int navi_http_request_set_post(navi_request_t* req, const uint8_t* content,
    size_t size);

/*	@func navi_http_request_append_post
 * 	@desc
 * 		支持逐片append方式设置post内容。post内容缓存，在get_post时，拼接为完整的post
 * 		内容，并清空之前的分片链表。
 */
int navi_http_request_append_post(navi_request_t* req, const uint8_t* part,
	size_t size);

/*	@func navi_http_request_get_uri_query
 * 	@desc
 * 		获得请求的uri?args串。是url转义格式
 * 		返回值是转义后的长度，即使buf为null，也可以返回
 */
size_t navi_http_request_get_uri_query(const navi_request_t* req,char* buf, size_t size);
const char* navi_http_request_get_uri(const navi_request_t* req);
const char* navi_http_request_get_arg(const navi_request_t* req, const char* nm);
const char* navi_http_request_get_header(const navi_request_t* req, const char* nm);

/*	@func navi_http_request_get_post
 * 	@desc
 * 		看请求是否是post方法，如果是返回post内容的长度。
 * 		如果body传入为非空，则body带出post内容位置
 */
size_t navi_http_request_get_post(const navi_request_t* req, const uint8_t** body);

bool navi_http_request_is_bigpost(navi_request_t* req);
void navi_http_request_abort_bigpost(navi_request_t* req);
bool navi_http_request_is_bigpost_abort(navi_request_t* req);

void* navi_http_request_header_iter(const navi_request_t* req);
const char* navi_http_request_header_iter_next(void* iter, const char** value);
void navi_http_request_header_iter_destroy(void* iter);

void* navi_http_request_arg_iter(const navi_request_t* req);
const char* navi_http_request_arg_iter_next(void* iter, const char** value);
void navi_http_request_arg_iter_destroy(void* iter);

/*
 * 	@func navi_http_response_set_status
 * 	@desc
 * 		为rest请求设置http响应码。必须是合法的http响应码
 */
int navi_http_response_set_status(navi_request_t* req, int code);
/*
 * 	@func navi_http_response_set_header
 * 	@desc
 * 		设置rest请求的http响应头部。不能是http标准头部。
 */
int navi_http_response_set_header(navi_request_t* req, const char* header, const char* value);
/*
 * 	@func navi_http_response_set_body
 * 	@desc
 * 		设置http响应体。如果content是堆分配的，且希望交给中间层管理内存，则heap_flag设置为1
 */
int navi_http_response_set_body(navi_request_t* req, const uint8_t* content,
    size_t size);

/*	@func navi_http_response_append_body
 * 	@desc
 * 		支持逐片append方式设置响应内容。内容片缓存为链，在get_body时，拼接为完整的body
 * 		内容，并清空之前的分片链表。
 */
int navi_http_response_append_body(navi_request_t* req, const uint8_t* part,
	size_t size);

int navi_http_response_get_status(const navi_request_t* req);
const char* navi_http_response_get_header(const navi_request_t* req,
    const char* header);
void* navi_http_response_header_iter(const navi_request_t* req);
const char* navi_http_response_header_iter_next(void* iter, const char** value);
void navi_http_response_header_iter_destroy(void* iter);

size_t navi_http_response_get_body(const navi_request_t* req, const uint8_t** body);

/*
 * 	@func navi_request_response_obj
 * 	@desc
 * 		适用于主navi_request_t，获得与其关联的navi_response_t对象。
 * 		获得后，业务模块使用navi_response接口操作最终的响应结果。
 */
navi_response_t* navi_request_response_obj(navi_request_t* req);

void navi_request_set_process(navi_request_t* req, navi_request_process_fp fun);
void navi_request_set_cleanup(navi_request_t* req, navi_request_process_fp fun);
void navi_request_set_custom_context(navi_request_t* req, void* ctx);

/*
 * cnavi 0.3.0 新增
 */
void navi_request_set_process_own(navi_request_t* req, navi_request_process_fp fun);
void navi_request_set_cleanup_own(navi_request_t* req, navi_request_process_fp fun);
void navi_request_set_context_own(navi_request_t* req, void* ctx);

//对主请求的超时控制
void navi_request_set_timeout(navi_request_t* main, uint32_t to_ms);
uint32_t navi_request_timeout(navi_request_t* main);

const char* navi_request_xcaller(navi_request_t* main);
const char* navi_request_cli_ip(navi_request_t* main);
const char* navi_request_service(navi_request_t* main);
const char* navi_request_module(navi_request_t* main);

/*!
 * \fn const char* navi_request_resturi(navi_request_t* main);
 * \brief 获取主请求uri中去除navi入口根路径、module分量，method分量之后的剩余部分，不包括'/'
 */
const char* navi_request_method(navi_request_t* main);
const char* navi_request_resturi(navi_request_t* main);
int64_t navi_request_cost_ns(navi_request_t* req);

/*
 * 	@func navi_request_add_sub
 * 	@args
 * 		pr	父请求
 * 		uri 子请求uri，必须是同一个driver层内能够识别的uri。
 * 		args_raw  进过url args转义的args串
 * 		post/post_size  如果请求需要post内容，则使用这两个参数
 * 		fun	 driver层响应获取后，中间层要调用的函数。或者是所有子请求都处理完毕后，中间层需要调用的父请求的处理函数。
 * 		ctx  应用层在该请求上对应的语境信息
 * 		clean_up  请求处理完毕后，中间层需要调用的清理函数。可以为空
 */
navi_request_t* navi_request_add_sub(navi_request_t* pr, const char* uri,
    const char* args_raw,
    const uint8_t* post, size_t post_size, navi_request_process_fp fun,
    void* ctx,
    navi_request_process_fp clean_up);

static inline navi_request_t* navi_request_new_sub(navi_request_t* pr) {
	return navi_request_add_sub(pr, NULL, NULL, NULL, 0, NULL, NULL, NULL);
}

/***
 * 在主请求之上增加、删除定时器的接口，在定时器有效期间，主请求不会结束。
 */

navi_timer_h navi_request_add_timer(navi_request_t* rt,
	navi_req_timer_fp proc, void* args, navi_req_timer_fp destroy,
	uint32_t to_ms, bool interval);

void navi_request_cancel_timer(navi_request_t* rt, navi_timer_h th);


/*
 * 	@func	navi_request_cancel
 * 	@desc
 * 		应用层使用该接口取消已经发出的子请求。
 */
void navi_request_cancel(navi_request_t* req);

void* navi_request_sub_iter(navi_request_t* pr, navi_request_status_e status);
navi_request_t* navi_request_sub_iter_next(void* iter);
void navi_request_sub_iter_destroy(void* iter);

navi_request_status_e navi_request_get_status(navi_request_t* handle);

void navi_request_recycle_on_end(navi_request_t* req);
void navi_request_recycle(navi_request_t* req);

void navi_request_emerg_response(navi_request_t* req);

navi_request_t* navi_request_get_parent(const navi_request_t*);
navi_request_t* navi_request_get_root(const navi_request_t*);

/*
 * 	@func navi_request_abort_root
 * 	@desc
 * 		较少使用。主要用途是，在事前基础模块有子请求时，如果希望等待子请求的结果来决定
 * 		是否继续处理，如果希望提前结束该请求，使用该接口，请求将不经过业务模块处理，直接
 * 		经由事后处理后，完成处理过程。
 *
 * 		也可以在普通业务模块的任一阶段调用该函数。
 *
 * 		效果是： 清除所有注册状态的子请求， 对所有在ngx中等待响应的子请求进行cancel。
 */
void navi_request_abort_root(navi_request_t* req,const char* reason);

void* navi_request_alloc(navi_request_t* req, size_t sz);
char* navi_request_strdup(navi_request_t* req, const char* src);
navi_pool_t* navi_request_pool(navi_request_t* req);

void navi_request_trace(navi_request_t* req, navi_trace_type_e e, const char* fmt, ...);

bool navi_request_disable_autofin(navi_request_t* req);
bool navi_request_enable_autofin(navi_request_t* req);

bool navi_request_respbody_enable_streaming(navi_request_t* main, ssize_t obody_total);
ssize_t navi_request_respbody_streaming(navi_request_t* main, const uint8_t* part, size_t sz);
void navi_request_respbody_streaming_abort(navi_request_t* main);
void navi_request_respbody_streaming_eof(navi_request_t* main);

//设置响应回送速率
void navi_request_set_resp_rate(navi_request_t* handle, uint32_t limit_rate, uint32_t limit_rate_after);
void navi_request_get_resp_rate(navi_request_t* handle, uint32_t *limit_rate, uint32_t *limit_rate_after);

typedef enum _navi_respbody_type_e
{
	NAVI_RESP_NAVI_STANDARD,
	NAVI_RESP_BIN,
	NAVI_RESP_FILE,
	NAVI_RESP_STREAM,
	NAVI_RESP_UNKNOWN_TYPE
}navi_respbody_type_e;

navi_respbody_type_e navi_request_respbody_type(navi_request_t* main);

int navi_request_set_respbody_scfile(navi_request_t* main, const char* scfile_mgr_path, const char* scfile_id);
int navi_request_respbody_filefd(navi_request_t* main);

#ifdef __cplusplus
}
#endif

#endif /* RESTREQUEST_H_ */
