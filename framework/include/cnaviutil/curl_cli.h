/*
 *Copyright (C)2012 1verge.com (http://www.youku.com)
 *nstatus http cli interface
 *Interface descripe:
 *	curl��http��װ������http���󣬸���http��Ӧͷ����body��ץȡ�ͻ��档
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
	int http_status_count;	//״̬���ַ�����
	char *http_error_desc;
	char *http_body;	//��Ӧbody
	int http_body_len;	//��Ӧbody����
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
 * 	@arg handle  curl_cli���
 * 	@url_args	http://uri?arg1=value1&arg2=value2
 * @return
 * 		CURL_CLI_OK
 * 		CURL_CLI_ERROR	curl�ڲ����󣬷�HTTP 4xx 5xx������curl_cli_error��ô�������
 */
int curl_cli_get(curl_cli_handle handle,const char* url_args);

/*
 * @func curl_cli_get
 * @desc ͨ��url��̽��Զ˵������ԣ����ҷ���ʹ�õı��ؽӿڵ�IP���Լ�Զ�˵�IP��ַ
 * @return
 * 		CURL_CLI_OK
 * 		CURL_CLI_ERROR	curl����˵���Զ˲��ɴ��curl_cli_error��ô�������
 */
int curl_cli_peek_url(const char* url,int *http_status,
	char** localip,char** srvip);

/*
 * @func curl_cli_error
 * @desc ����curl������Ϣ
 */
const char* curl_cli_error(const curl_cli_handle handle);

/*
 * @func curl_cli_post
 * @desc http post
 * @params
 * 	@arg handle  curl_cli���
 * 	@arg url	http://uri
 * 	@arg postbuf	post����
 * 	@arg size	post����
 * @return
 * 	CURL_CLI_OK
 * 	CURL_CLI_ERROR	curl�ڲ����󣬷�HTTP 4xx 5xx������curl_cli_error��ô�������
 */
int curl_cli_post(curl_cli_handle handle,const char* url, const char* postbuf, int size);

/*
 * @func curl_cli_get_resp
 * @desc ���http��Ӧ��Ϣ
 * @params
 * 		@arg in handle
 * @return
 * 	��Ӧ��Ϣ�ṹָ��
 */
const curl_cli_resp_info* curl_cli_get_resp(const curl_cli_handle handle);

void curl_cli_destroy(curl_cli_handle handle);

#ifdef __cplusplus
}
#endif

#endif /* CURL_CLI_H_ */
