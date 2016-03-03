/*
 * restrequest_hook.h
 *
 *  Created on: 2013-8-28
 *      Author: li.lei
 *      Desc:
 *      	ר����������Ĳ���navi_request_t�Ľӿڡ�
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
 * 		����navi_request_t
 * 		��������������
 */
navi_request_t* navi_request_init();
void navi_request_free(navi_request_t*);
/*
 * 	@func	navi_reuqest_reset
 * 	@desc
 * 		������������navi_request_t���ÿ������Ա�
 * 		* ������Ӧ���ﾳ��Ϣ��
 * 		��������������
 */
void navi_request_reset(navi_request_t*);

/*
 * 	@func	navi_request_parse_main_uri
 * 	@desc
 * 		��uri�н�����navi�����module/method��Ϣ��
 * 		��������������
 */
int navi_request_parse_main_uri(navi_request_t* main, const char* base, size_t base_len);

/*
 * 	@func	navi_request_set_status
 * 	@desc
 * 		���������״̬�������������������������
 * 		�ڲ���װ�кϷ���״̬ת������
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
 * 		��ĳ�����������ʱ��driver����øýӿڴ����������̡�
 * 		��navi�м������������������̵����
 */
void navi_request_call_process(navi_request_t* req);

void navi_request_bigpost_prepare(navi_request_t* req, const char* file_path );
void navi_request_bigpost_ready(navi_request_t* req);

/*
 * 	@func navi_request_regist_iter/_next/_destroy
 * 	@desc
 * 		������ʹ�ø��׽ӿڣ���ȡ��ǰ���м������ע���������
 * 		�����㰲װ��Щ�������Ҫnavi_request_set_status�ı���״̬
 * 		ΪNAVI_REQUEST_DRIVER_PROCESSING
 */
void* navi_request_regist_iter(navi_request_t* main);
navi_request_t* navi_request_regist_iter_next(void* iter);
void navi_request_regist_iter_destroy(void* iter);

/*
 * 	@func navi_request_regist_iter/_next/_destroy
 * 	@desc
 * 		������ʹ�ø��׽ӿڣ���ȡ��ǰ���м����������Ҫȡ����������
 * 		(��Щ�������Ѿ�����DRIVER_PROCESSING״̬��
 * 		���Բ���Ҫȡ��)
 * 		������ʵ��ȡ����Щ�������Ҫnavi_request_set_status�ı���״̬
 * 		ΪNAVI_REQUEST_CANCELED
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
 * \brief �ⲿ����δ����ʱ�����������Լ���Ӧ���δ����ʱ����������ʱ����������true��ngx��Ҫ�ر�����
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
