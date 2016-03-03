/*
 * restrequest_impl.h
 *
 *  Created on: 2013-8-28
 *      Author: li.lei
 *      Desc��
 *      	navi_request_t�Ĺ����ӿڲ��֡�
 *      	driver��ҵ��㶼��Ҫʹ�ñ��׽ӿ�
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
	//����������м��ע�ᣬ��δ��driver����Ч��
	//����ڴ�ʱ������cancel����ֱ�Ӵ�ע�������Ƴ�����
	NAVI_REQUEST_REGISTED,
	//���м��ע�������󣬻�δ��driver����Ч��
	//ֻ���ڽ���NAVI_REQUEST_DRIVER_PROCESSING
	//��������Ż�cancel������
	NAVI_REQUEST_CANCEL_REGISTED,
	//��driver��ʹ�����м��ע�����������Ч
	NAVI_REQUEST_DRIVER_PROCESSING,
	//driver��http��Ӧ�Ѿ���ã������м��Ĵ�������
	//��ʱ�������������������
	//��ʱ����cancel�Ļ����᳢��cancel�¼������󣬱������״̬����
	NAVI_REQUEST_FRAME_PROCESSING,
	//��NAVI_REQUEST_CANCEL_REGISTED֮��driver��
	//������ʵ�ʵ�cancel
	NAVI_REQUEST_CANCELED,
	//����ҵ����������ص�ʧ��
	//  * ������Դʧ��ʱ�������޷�������
	//  * �����ǹ������ֹ�������̵�һ���ֶ�
	NAVI_REQUEST_PROC_FAILED,
	//�����Ѿ��������
	NAVI_REQUEST_COMPLETE
} navi_request_status_e;

typedef struct navi_request_s
{
	uint32_t _magic;
	/* ������ص�������
	 * * ��������������������󶼵���ĳ����ֹ״̬�󣬲������������Ӧ�ѵ����
	 * * process_own_result�Ѿ������ù������ô˻ص�������
	 * * �ص������ú�����Ч
	 * * ��navi��������ԣ���������������������ɺ󣬼����е���
	 */
	int (*process_request)(struct navi_request_s* req, void* custom_ctx);
	int (*clean_up)(struct navi_request_s* req, void* custom_ctx);
	void *custom_ctx;

	/**** cnavi0.3.0 �����ص���ԭprocess_request�Ľ�ɫ���в��, ����һ���ύһ��������
	 *  ��ǰ�������Ӧ����֮��Ļص�������ע���navi��������ԣ���ʹ�øûص���navi������
	 *  ����Ӧ����navi ҵ��ģ������� ����Ļص�ֻ��������������������Ӧ�󣬻���á�
	 *  ���ú󣬻ص�ʧЧ��
	 *
	 *  ��������ύһ��������ôprocess_request��process_own����������������һ������,
	 *  ͬʱ���ÿ�Ҳ�ԣ����ޱ�Ҫ��
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
 * 		���������uri��unescapeָ���Ƿ���Ҫ��ԭת������
 * 		�ڴ��У����԰���args����args �������һ��?��ʼ
 */
int navi_http_request_set_uri(navi_request_t* req, const char* uri,int unescape);

/* 	@func navi_htp_request_set_args_raw
 * 	@desc
 * 		����args������Ҫ��url argsת���ʽ��
 */
int navi_http_request_set_args_raw(navi_request_t* req, const char* arg);

/* 	@func navi_http_request_set_arg
 * 	@desc
 * 		���õ���arg��argnm��argvalue��ʹ�÷�ת���ʽ
 *		����Ѿ����ڣ��򸲸ǡ�
 */
int navi_http_request_set_arg(navi_request_t* req, const char* argnm,
    const char* value);

/* 	@func navi_http_request_set_header
 * 	@desc
 * 		���õ���header��
 */
int navi_http_request_set_header(navi_request_t* req, const char* header,
    const char* value);

/* 	@func navi_http_request_set_post
 * 	@desc
 * 		����http����Ϊpost������������post���ݡ����ݻᱻ������
 */
int navi_http_request_set_post(navi_request_t* req, const uint8_t* content,
    size_t size);

/*	@func navi_http_request_append_post
 * 	@desc
 * 		֧����Ƭappend��ʽ����post���ݡ�post���ݻ��棬��get_postʱ��ƴ��Ϊ������post
 * 		���ݣ������֮ǰ�ķ�Ƭ����
 */
int navi_http_request_append_post(navi_request_t* req, const uint8_t* part,
	size_t size);

/*	@func navi_http_request_get_uri_query
 * 	@desc
 * 		��������uri?args������urlת���ʽ
 * 		����ֵ��ת���ĳ��ȣ���ʹbufΪnull��Ҳ���Է���
 */
size_t navi_http_request_get_uri_query(const navi_request_t* req,char* buf, size_t size);
const char* navi_http_request_get_uri(const navi_request_t* req);
const char* navi_http_request_get_arg(const navi_request_t* req, const char* nm);
const char* navi_http_request_get_header(const navi_request_t* req, const char* nm);

/*	@func navi_http_request_get_post
 * 	@desc
 * 		�������Ƿ���post����������Ƿ���post���ݵĳ��ȡ�
 * 		���body����Ϊ�ǿգ���body����post����λ��
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
 * 		Ϊrest��������http��Ӧ�롣�����ǺϷ���http��Ӧ��
 */
int navi_http_response_set_status(navi_request_t* req, int code);
/*
 * 	@func navi_http_response_set_header
 * 	@desc
 * 		����rest�����http��Ӧͷ����������http��׼ͷ����
 */
int navi_http_response_set_header(navi_request_t* req, const char* header, const char* value);
/*
 * 	@func navi_http_response_set_body
 * 	@desc
 * 		����http��Ӧ�塣���content�Ƕѷ���ģ���ϣ�������м������ڴ棬��heap_flag����Ϊ1
 */
int navi_http_response_set_body(navi_request_t* req, const uint8_t* content,
    size_t size);

/*	@func navi_http_response_append_body
 * 	@desc
 * 		֧����Ƭappend��ʽ������Ӧ���ݡ�����Ƭ����Ϊ������get_bodyʱ��ƴ��Ϊ������body
 * 		���ݣ������֮ǰ�ķ�Ƭ����
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
 * 		��������navi_request_t��������������navi_response_t����
 * 		��ú�ҵ��ģ��ʹ��navi_response�ӿڲ������յ���Ӧ�����
 */
navi_response_t* navi_request_response_obj(navi_request_t* req);

void navi_request_set_process(navi_request_t* req, navi_request_process_fp fun);
void navi_request_set_cleanup(navi_request_t* req, navi_request_process_fp fun);
void navi_request_set_custom_context(navi_request_t* req, void* ctx);

/*
 * cnavi 0.3.0 ����
 */
void navi_request_set_process_own(navi_request_t* req, navi_request_process_fp fun);
void navi_request_set_cleanup_own(navi_request_t* req, navi_request_process_fp fun);
void navi_request_set_context_own(navi_request_t* req, void* ctx);

//��������ĳ�ʱ����
void navi_request_set_timeout(navi_request_t* main, uint32_t to_ms);
uint32_t navi_request_timeout(navi_request_t* main);

const char* navi_request_xcaller(navi_request_t* main);
const char* navi_request_cli_ip(navi_request_t* main);
const char* navi_request_service(navi_request_t* main);
const char* navi_request_module(navi_request_t* main);

/*!
 * \fn const char* navi_request_resturi(navi_request_t* main);
 * \brief ��ȡ������uri��ȥ��navi��ڸ�·����module������method����֮���ʣ�ಿ�֣�������'/'
 */
const char* navi_request_method(navi_request_t* main);
const char* navi_request_resturi(navi_request_t* main);
int64_t navi_request_cost_ns(navi_request_t* req);

/*
 * 	@func navi_request_add_sub
 * 	@args
 * 		pr	������
 * 		uri ������uri��������ͬһ��driver�����ܹ�ʶ���uri��
 * 		args_raw  ����url argsת���args��
 * 		post/post_size  ���������Ҫpost���ݣ���ʹ������������
 * 		fun	 driver����Ӧ��ȡ���м��Ҫ���õĺ��������������������󶼴�����Ϻ��м����Ҫ���õĸ�����Ĵ�������
 * 		ctx  Ӧ�ò��ڸ������϶�Ӧ���ﾳ��Ϣ
 * 		clean_up  ��������Ϻ��м����Ҫ���õ�������������Ϊ��
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
 * ��������֮�����ӡ�ɾ����ʱ���Ľӿڣ��ڶ�ʱ����Ч�ڼ䣬�����󲻻������
 */

navi_timer_h navi_request_add_timer(navi_request_t* rt,
	navi_req_timer_fp proc, void* args, navi_req_timer_fp destroy,
	uint32_t to_ms, bool interval);

void navi_request_cancel_timer(navi_request_t* rt, navi_timer_h th);


/*
 * 	@func	navi_request_cancel
 * 	@desc
 * 		Ӧ�ò�ʹ�øýӿ�ȡ���Ѿ�������������
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
 * 		����ʹ�á���Ҫ��;�ǣ�����ǰ����ģ����������ʱ�����ϣ���ȴ�������Ľ��������
 * 		�Ƿ�����������ϣ����ǰ����������ʹ�øýӿڣ����󽫲�����ҵ��ģ�鴦��ֱ��
 * 		�����º������ɴ�����̡�
 *
 * 		Ҳ��������ͨҵ��ģ�����һ�׶ε��øú�����
 *
 * 		Ч���ǣ� �������ע��״̬�������� ��������ngx�еȴ���Ӧ�����������cancel��
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

//������Ӧ��������
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
