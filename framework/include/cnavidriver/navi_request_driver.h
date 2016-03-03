/*
 * restrequest_hook.h
 *
 *  Created on: 2013-8-28
 *      Author: li.lei
 *      Desc:
 *      	专属于驱动层的操作navi_request_t的接口。
 */

#ifndef NAVI_REQUEST_HOOK_H_
#define NAVI_REQUEST_HOOK_H_

#include "navi_request.h"
#include "navi_buf_chain.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 	@func	navi_request_init
 * 	@desc
 * 		创建navi_request_t
 * 		仅适用于主请求。
 */
navi_request_t* navi_request_init();
void navi_request_free(navi_request_t*);
/*
 * 	@func	navi_reuqest_reset
 * 	@desc
 * 		可以用来复用navi_request_t，置空其各成员项：
 * 		* 请求、响应、语境信息等
 * 		仅适用于主请求。
 */
void navi_request_reset(navi_request_t*);

/*
 * 	@func	navi_request_parse_main_uri
 * 	@desc
 * 		从uri中解析出navi请求的module/method信息。
 * 		仅适用于主请求。
 */
int navi_request_parse_main_uri(navi_request_t* main, const char* base, size_t base_len);

/*
 * 	@func	navi_request_set_status
 * 	@desc
 * 		设置请求的状态。适用于主请求及其派生的子孙。
 * 		内部封装有合法的状态转换规则：
 * 		* NAVI_REQUEST_REGISTED-->NAVI_REQUEST_DRIVER_PROCESSING
 * 		* NAVI_REQUEST_CANCEL_REGISTED->NAVI_REQUEST_CANCELED
 * 		* NAVI_REQUEST_DRIVER_PROCESSING->NAVI_REQUEST_NAVI_PROCESSING
 * 		* NAVI_REQUEST_DRIVER_PROCESSING->NAVI_REQUEST_CANCEL_REGISTED
 * 		* NAVI_REQUEST_NAVI_PROCESSING->NAVI_REQUEST_COMPLETE
 * 		* NAVI_REQUEST_NAVI_PROCESSING->NAVI_REQUEST_PROC_FAILED
 */
void navi_request_set_status(navi_request_t* handle,navi_request_status_e status);

int navi_request_set_xcaller(navi_request_t* main,const char* xcaller);
int navi_request_set_cli_ip(navi_request_t* main,const char* cli_ip);

/*
 * 	@func navi_request_call_process
 * 	@desc
 * 		当某个子请求完成时，driver层调用该接口触发后续流程。
 * 		是navi中间层的请求驱动核心流程的入口
 */
void navi_request_call_process(navi_request_t* req);

void navi_request_bigpost_prepare(navi_request_t* req, const char* file_path );
void navi_request_bigpost_ready(navi_request_t* req);

/*
 * 	@func navi_request_regist_iter/_next/_destroy
 * 	@desc
 * 		驱动层使用该套接口，获取当前被中间层新增注册的子请求。
 * 		驱动层安装这些请求后，需要navi_request_set_status改变其状态
 * 		为NAVI_REQUEST_DRIVER_PROCESSING
 */
void* navi_request_regist_iter(navi_request_t* main);
navi_request_t* navi_request_regist_iter_next(void* iter);
void navi_request_regist_iter_destroy(void* iter);

/*
 * 	@func navi_request_regist_iter/_next/_destroy
 * 	@desc
 * 		驱动层使用该套接口，获取当前被中间层新增的需要取消的子请求。
 * 		(这些子请求已经进入DRIVER_PROCESSING状态，
 * 		所以才需要取消)
 * 		驱动层实际取消这些请求后，需要navi_request_set_status改变其状态
 * 		为NAVI_REQUEST_CANCELED
 */
void* navi_request_cancel_iter(navi_request_t* main);
navi_request_t* navi_request_cancel_iter_next(void* iter);
void navi_request_cancel_iter_destroy(void* iter);

void* navi_request_get_driver_peer(navi_request_t* req);
void navi_request_set_driver_peer(navi_request_t* req,void* peer,
	void* (*get_peer_pool)(void*));

bool navi_request_has_vh(navi_request_t* rh);
bool navi_request_has_timers(navi_request_t* rh );
bool navi_request_can_step(navi_request_t* main);

typedef enum _navi_request_drive_type_e {
	NAVI_REQ_DRIVE_STARTUP_HANDLER,
	NAVI_REQ_DRIVE_BIGPOST_HANDLER,
	NAVI_REQ_DRIVE_SUBREQ_HANDLER,
	NAVI_REQ_DRIVE_TIMER_HANDLER,
	NAVI_REQ_DRIVE_VEVENT_HANDLER,
	NAVI_REQ_DRIVE_ABORT_HANDLER,
	NAVI_REQ_DRIVE_FROM_REST
} navi_request_drive_type_e;

void navi_request_drive_flag(navi_request_t* main, navi_request_drive_type_e type);
void navi_request_drive_flag_reset(navi_request_t* main);

navi_timer_mgr_t* navi_request_timers(navi_request_t* rh);

/*!
 * \brief 外部请求未完整时，结束请求，以及响应输出未完整时，结束请求时，函数返回true，ngx需要关闭连接
 */
bool navi_request_incomplete(navi_request_t* main);

void navi_request_driver_rest_hook(
	void (*drive_trigger)(),
	void (*drive_handler)(navi_request_t* main)
);

void navi_request_trigger_rest_drive(navi_request_t* main);
void navi_request_rest_drive();

navi_buf_chain_t* navi_request_get_streaming(navi_request_t* main, ssize_t* streaming_sz, bool* is_abort);


bool navi_request_should_emerg_resp(navi_request_t* rh);
#ifdef __cplusplus
}
#endif
#endif /* RESTREQUEST_HOOK_H_ */
