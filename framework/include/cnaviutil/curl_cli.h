/*
 *Copyright (C)2012 1verge.com (http://www.youku.com)
 *nstatus http cli interface
 *Interface descripe:
 *	curl的http封装。发送http请求，负责http响应头部和body的抓取和缓存。
 *Author: lilei
 *Createtime: 2012.09.17
 *MSN: leetstone@hotmail.com
 *Report Bugs: li.lei@youku.com
 *Address: China BeiJing
 *Version: 1.0.0.0
 *Latest modify time:2012.09.25
 */

#ifndef CURL_CLI_H_
#define CURL_CLI_H_

#ifdef __cplusplus
extern "C"{
#endif

typedef void* curl_cli_handle;

#define CURL_CLI_OK 0
#define CURL_CLI_ERROR -1

typedef struct _curl_cli_resp_info
{
	int http_major;
	int http_minor;
	int http_status;
	int http_status_count;	//状态码字符计数
	char *http_error_desc;
	char *http_body;	//响应body
	int http_body_len;	//响应body长度
}curl_cli_resp_info;

curl_cli_handle curl_cli_init(int conn_to_ms,int comm_to_ms,int keepalive);
void curl_cli_conn_timeout(curl_cli_handle h,int to);
void curl_cli_comm_timeout(curl_cli_handle h,int to);
void curl_cli_keepalive(curl_cli_handle h,int swth);

void curl_cli_set_header(curl_cli_handle h,const char* header,const char* value);

/*
 * @func curl_cli_get
 * @desc http get
 * @params
 * 	@arg handle  curl_cli句柄
 * 	@url_args	http://uri?arg1=value1&arg2=value2
 * @return
 * 		CURL_CLI_OK
 * 		CURL_CLI_ERROR	curl内部错误，非HTTP 4xx 5xx错误。用curl_cli_error获得错误描述
 */
int curl_cli_get(curl_cli_handle handle,const char* url_args);

/*
 * @func curl_cli_get
 * @desc 通过url，探测对端的连接性，并且返回使用的本地接口的IP，以及远端的IP地址
 * @return
 * 		CURL_CLI_OK
 * 		CURL_CLI_ERROR	curl错误，说明对端不可达。用curl_cli_error获得错误描述
 */
int curl_cli_peek_url(const char* url,int *http_status,
	char** localip,char** srvip);

/*
 * @func curl_cli_error
 * @desc 返回curl错误信息
 */
const char* curl_cli_error(const curl_cli_handle handle);

/*
 * @func curl_cli_post
 * @desc http post
 * @params
 * 	@arg handle  curl_cli句柄
 * 	@arg url	http://uri
 * 	@arg postbuf	post内容
 * 	@arg size	post长度
 * @return
 * 	CURL_CLI_OK
 * 	CURL_CLI_ERROR	curl内部错误，非HTTP 4xx 5xx错误。用curl_cli_error获得错误描述
 */
int curl_cli_post(curl_cli_handle handle,const char* url, const char* postbuf, int size);

/*
 * @func curl_cli_get_resp
 * @desc 获得http响应信息
 * @params
 * 		@arg in handle
 * @return
 * 	响应信息结构指针
 */
const curl_cli_resp_info* curl_cli_get_resp(const curl_cli_handle handle);

void curl_cli_destroy(curl_cli_handle handle);

#ifdef __cplusplus
}
#endif

#endif /* CURL_CLI_H_ */
