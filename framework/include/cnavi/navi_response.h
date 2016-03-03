/*
 * restresponse.h
 *
 *  Created on: 2013-8-28
 *      Author: li.lei
 */

#ifndef RESTR_ESPONSE_H_
#define RESTR_ESPONSE_H_

#include <jansson.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NULL_CODE 0x7fffffff

typedef struct navi_resp_error_s{
	char* provider;
	char* desc;
	int   code;
}navi_resp_error_t;

typedef struct navi_response_s {
	navi_resp_error_t    error;
	double cost;
	json_t*  json_response;
	void* main;
	char* http;
	size_t http_size;
	int changed;
	char* js_callback;
}navi_response_t;

navi_response_t* navi_response_init(void* main);
void navi_response_set_desc(navi_response_t* obj,int code,const char* prvdr,const char* desc);
/*
 * 	@func navi_response_set_content
 * 	@desc
 * 		����json��Ӧ�е�Ӧ�ò��Զ������Ӧ���ݡ�
 * 		copyΪ1ʱ�������ctnt���󣬷���ctnt���󽻸�navi_response_t����
 */
void navi_response_set_content(navi_response_t* obj,json_t* ctnt,int copy);
void navi_response_with_js_callback(navi_response_t* obj, const char* cbnm);

/*
 * 	@func navi_response_http_body
 * 	@desc
 * 		���navi_response_t��Ӧ��http��Ӧ�塣
 * 		grab_flagΪ1ʱ�������ɶѷ������Ӧ�壬���������ڴ�Ĺ���Ȩ������
 * 		navi_response_t���Ϊ���и�http��Ӧ��
 */
char* navi_response_http_body(navi_response_t* obj,int grab_flag);
void navi_response_clean(navi_response_t* obj);

#ifdef __cplusplus
}
#endif

#endif /* RESTRESPONSE_H_ */
