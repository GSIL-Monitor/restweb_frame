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
 * 		设置json响应中的应用层自定义的响应数据。
 * 		copy为1时，会深拷贝ctnt对象，否则ctnt对象交给navi_response_t管理。
 */
void navi_response_set_content(navi_response_t* obj,json_t* ctnt,int copy);
void navi_response_with_js_callback(navi_response_t* obj, const char* cbnm);

/*
 * 	@func navi_response_http_body
 * 	@desc
 * 		获得navi_response_t对应的http响应体。
 * 		grab_flag为1时，会生成堆分配的响应体，并交出该内存的管理权。否则，
 * 		navi_response_t会代为持有该http响应体
 */
char* navi_response_http_body(navi_response_t* obj,int grab_flag);
void navi_response_clean(navi_response_t* obj);

#ifdef __cplusplus
}
#endif

#endif /* RESTRESPONSE_H_ */
