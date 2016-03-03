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

#include <curl/curl.h>
#include "navi_frame_log.h"
#include "curl_cli.h"
#include <stdlib.h>
#include <string.h>
#include "buffer_util.h"

#define LF     (u_char) 10
#define CR     (u_char) 13
#define SP	(u_char)32
#define HT	(u_char)9
#define CRLF   "\x0d\x0a"

typedef struct curl_cli
{
	CURL *curl_impl;
	ncli_buffer_h head_buf;
	ncli_buffer_h body_buf;
	int conn_timeout_ms; //连接超时
	int comm_timeout_ms; //传输超时
	int keep_alive;
	char error_buf[CURL_ERROR_SIZE]; //curl错误信息空间
	char http_resp_desc[256]; //http response line desc
	curl_cli_resp_info resp_info;
	struct curl_slist* const_custom_headers; //固定递送的请求头部
} CurlCli;

typedef CurlCli* CurlCliHandle;

static int http_status_line_parse(CurlCliHandle h)
{
	u_char ch;
	u_char *p;
	u_char *start, *end;
	u_char *status_desc_start = NULL, *status_desc_end = NULL;
	int status_desc_size = 0;

	enum
	{
		sw_start = 0,
		sw_H,
		sw_HT,
		sw_HTT,
		sw_HTTP,
		sw_first_major_digit,
		sw_major_digit,
		sw_first_minor_digit,
		sw_minor_digit,
		sw_status,
		sw_space_after_status,
		sw_status_text,
		sw_almost_done
	} state;

	state = sw_start;
	start = h->head_buf->content;
	end = h->head_buf->content + h->head_buf->len;

	for (p = start; p < end; p++)
	{
		ch = *p;

		switch (state)
		{

		/* "HTTP/" */
		case sw_start:
			switch (ch)
			{
			case 'H':
				state = sw_H;
				break;
			default:
				return -1;
			}
			break;

		case sw_H:
			switch (ch)
			{
			case 'T':
				state = sw_HT;
				break;
			default:
				return -1;
			}
			break;

		case sw_HT:
			switch (ch)
			{
			case 'T':
				state = sw_HTT;
				break;
			default:
				return -1;
			}
			break;

		case sw_HTT:
			switch (ch)
			{
			case 'P':
				state = sw_HTTP;
				break;
			default:
				return -1;
			}
			break;

		case sw_HTTP:
			switch (ch)
			{
			case '/':
				state = sw_first_major_digit;
				break;
			default:
				return -1;
			}
			break;

			/* the first digit of major HTTP version */
		case sw_first_major_digit:
			if (ch < '1' || ch > '9')
			{
				return -1;
			}

			h->resp_info.http_major = ch - '0';
			state = sw_major_digit;
			break;

			/* the major HTTP version or dot */
		case sw_major_digit:
			if (ch == '.')
			{
				state = sw_first_minor_digit;
				break;
			}

			if (ch < '0' || ch > '9')
			{
				return -1;
			}

			h->resp_info.http_major = h->resp_info.http_major * 10 + ch - '0';
			break;

			/* the first digit of minor HTTP version */
		case sw_first_minor_digit:
			if (ch < '0' || ch > '9')
			{
				return -1;
			}

			h->resp_info.http_minor = ch - '0';
			state = sw_minor_digit;
			break;

			/* the minor HTTP version or the end of the request line */
		case sw_minor_digit:
			if (ch == ' ')
			{
				state = sw_status;
				break;
			}

			if (ch < '0' || ch > '9')
			{
				return -1;
			}

			h->resp_info.http_minor = h->resp_info.http_minor * 10 + ch - '0';
			break;

			/* HTTP status code */
		case sw_status:
			if (ch == ' ')
			{
				break;
			}

			if (ch < '0' || ch > '9')
			{
				return -1;
			}

			h->resp_info.http_status = h->resp_info.http_status * 10 + ch - '0';

			if (++h->resp_info.http_status_count == 3)
			{
				state = sw_space_after_status;
				status_desc_start = p - 2;
			}

			break;
			/* space or end of line */
		case sw_space_after_status:
			switch (ch)
			{
			case ' ':
				state = sw_status_text;
				break;
			case '.': /* IIS may send 403.1, 403.2, etc */
				state = sw_status_text;
				break;
			case CR:
				state = sw_almost_done;
				break;
			case LF:
				goto done;
			default:
				return -1;
			}
			break;

			/* any text until end of line */
		case sw_status_text:
			switch (ch)
			{
			case CR:
				state = sw_almost_done;
				break;
			case LF:
				goto done;
			default:
				break;
			}
			break;

			/* end of status line */
		case sw_almost_done:
			status_desc_end = p - 1;
			switch (ch)
			{
			case LF:
				goto done;
			default:
				return -1;
			}
			break;
		}
	}

	return -1;

	done: if (status_desc_end == NULL)
	{
		status_desc_end = p;
	}

	status_desc_size =
	    (status_desc_end - status_desc_start) < (sizeof(h->http_resp_desc) - 1) ?
	        (status_desc_end - status_desc_start) : (sizeof(h->http_resp_desc) - 1);

	strncpy(h->http_resp_desc, status_desc_start, status_desc_size);
	h->http_resp_desc[status_desc_size] = 0;

	return 0;
}

static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
	return fillin_ncli_buf((ncli_buffer_h*) userp, buffer, size * nmemb);
}

curl_cli_handle curl_cli_init(int cnn_to, int cmm_to, int keepalive)
{
	CURL* tmp_curl;
	CurlCliHandle ret = (CurlCliHandle) malloc(sizeof(CurlCli));
	if (ret == NULL)
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_init error");
		return NULL;
	}
	memset(ret, 0x00, sizeof(CurlCli));

	if (cnn_to > 0)
		ret->conn_timeout_ms = cnn_to;
	if (cmm_to > 0)
		ret->comm_timeout_ms = cmm_to;

	ret->head_buf = init_ncli_buf(1024);
	if (ret->head_buf == NULL)
		goto error_ret;
	ret->body_buf = init_ncli_buf(4096);
	if (ret->body_buf == NULL)
		goto error_ret;

	tmp_curl = curl_easy_init();
	if (tmp_curl == NULL)
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_init error");
		goto error_ret;
	}

	if (ret->conn_timeout_ms)
	{
		if(CURLE_OK != curl_easy_setopt(tmp_curl, CURLOPT_CONNECTTIMEOUT_MS, ret->conn_timeout_ms))
		{
			NAVI_FRAME_LOG(NAVI_LOG_WARNING,"CURLOPT_CONNECTTIMEOUT_MS not supported");
		}
	}
	if (ret->comm_timeout_ms)
	{
		if(CURLE_OK != curl_easy_setopt(tmp_curl, CURLOPT_TIMEOUT_MS, ret->comm_timeout_ms))
		{
			NAVI_FRAME_LOG(NAVI_LOG_WARNING,"CURLOPT_TIMEOUT_MS not supported");
		}
	}

	curl_easy_setopt(tmp_curl, CURLOPT_ERRORBUFFER, ret->error_buf);
	curl_easy_setopt(tmp_curl, CURLOPT_NOPROGRESS, 1);
	if (keepalive == 0)
	{
		ret->const_custom_headers = curl_slist_append(ret->const_custom_headers, "Connection: close");
		ret->keep_alive = 0;
	}
	else
	{
		ret->keep_alive = 1;
		curl_easy_setopt(tmp_curl, CURLOPT_FORBID_REUSE, 0);
	}

	curl_easy_setopt(tmp_curl, CURLOPT_HEADERFUNCTION, write_data);
	curl_easy_setopt(tmp_curl, CURLOPT_WRITEHEADER, (void*)&ret->head_buf);

	curl_easy_setopt(tmp_curl, CURLOPT_WRITEFUNCTION, write_data);
	curl_easy_setopt(tmp_curl, CURLOPT_WRITEDATA, (void*)&ret->body_buf);

	ret->curl_impl = tmp_curl;
	ret->const_custom_headers = curl_slist_append(ret->const_custom_headers, "Content-type: application/octet-stream");
	//禁止100-continue返回。
	ret->const_custom_headers = curl_slist_append(ret->const_custom_headers, "Expect:");

	return ret;
	error_ret: curl_cli_destroy(ret);
	return NULL;
}

void curl_cli_conn_timeout(curl_cli_handle h, int to)
{
	CurlCliHandle eh = (CurlCliHandle) h;
	if (eh == NULL)
		return;
	eh->conn_timeout_ms = to;
	if(CURLE_OK != curl_easy_setopt(eh->curl_impl, CURLOPT_CONNECTTIMEOUT_MS, to))
	{
		NAVI_FRAME_LOG(NAVI_LOG_WARNING,"CURLOPT_CONNECTTIMEOUT_MS not supported");
	}
}
void curl_cli_comm_timeout(curl_cli_handle h, int to)
{
	CurlCliHandle eh = (CurlCliHandle) h;
	if (eh == NULL)
		return;
	eh->comm_timeout_ms = to;
	if(CURLE_OK != curl_easy_setopt(eh->curl_impl, CURLOPT_TIMEOUT_MS, to))
	{
		NAVI_FRAME_LOG(NAVI_LOG_WARNING,"CURLOPT_TIMEOUT_MS not supported");
	}
}
void curl_cli_keepalive(curl_cli_handle h, int swth)
{
	CurlCliHandle eh = (CurlCliHandle) h;
	if (eh == NULL)
		return;
	eh->keep_alive = swth;

	curl_slist_free_all(eh->const_custom_headers);
	eh->const_custom_headers = NULL;
	if (swth)
	{
		eh->const_custom_headers = curl_slist_append(eh->const_custom_headers,
		    "Content-type: application/octet-stream");
		eh->const_custom_headers = curl_slist_append(eh->const_custom_headers, "Expect:");
		curl_easy_setopt(eh->curl_impl, CURLOPT_FORBID_REUSE, 0);
	}
	else
	{
		eh->const_custom_headers = curl_slist_append(eh->const_custom_headers,
		    "Content-type: application/octet-stream");
		//期望服务端执行主动关闭，避免本机客户端端口TIME_WAIT耗尽
		eh->const_custom_headers = curl_slist_append(eh->const_custom_headers, "Connection: close");
		eh->const_custom_headers = curl_slist_append(eh->const_custom_headers, "Expect:");
	}
}

void curl_cli_set_header(curl_cli_handle h,const char* header,const char* value)
{
	struct curl_slist* tmp_list = NULL, *ck;
	if(h == NULL || header==NULL )return;
	CurlCliHandle eh = (CurlCliHandle)h;
	ck = eh->const_custom_headers;

	reset_ncli_buf(&(eh->head_buf));
	fillin_ncli_buf(&(eh->head_buf),header,strlen(header));
	fillin_ncli_buf(&(eh->head_buf),": ",2);
	if(value)
		fillin_ncli_buf(&(eh->head_buf),value,strlen(value)+1);
	else
		fillin_ncli_buf(&(eh->head_buf),"",1);

	int is_replace=0;
	while(ck)
	{
		if(strncasecmp(header,ck->data,strlen(header)) == 0)
		{
			tmp_list = curl_slist_append(tmp_list,eh->head_buf->content);
			is_replace=1;
		}
		else
		{
			tmp_list = curl_slist_append(tmp_list,ck->data);
		}
		ck = ck->next;
	}
	curl_slist_free_all(eh->const_custom_headers);
	if(is_replace==0)
	{
		tmp_list = curl_slist_append(tmp_list,eh->head_buf->content);
	}
	eh->const_custom_headers = tmp_list;
}

static void curl_cli_reset(CurlCliHandle handle)
{
	if (handle == NULL)
	{
		return;
	}
	if (handle->head_buf)
	{
		reset_ncli_buf(&(handle->head_buf));
	}
	if (handle->body_buf)
	{
		reset_ncli_buf(&(handle->body_buf));
	}
	handle->error_buf[0] = 0;
	handle->http_resp_desc[0] = 0;
	memset(&(handle->resp_info), 0x00, sizeof(curl_cli_resp_info));
}

void curl_cli_destroy(curl_cli_handle handle)
{
	CurlCliHandle eh = (CurlCliHandle) handle;
	if (eh == NULL)
	{
		return;
	}
	if (eh->curl_impl)
	{
		curl_easy_cleanup(eh->curl_impl);
	}
	if (eh->body_buf)
	{
		destroy_ncli_buf(eh->body_buf);
	}
	if (eh->head_buf)
	{
		destroy_ncli_buf(eh->head_buf);
	}
	if (eh->const_custom_headers)
	{
		curl_slist_free_all(eh->const_custom_headers);
	}
	free(eh);
}

int curl_cli_peek_url(const char* url, int* http_status,char** localip, char** srvip)
{
	CurlCliHandle eh = (CurlCliHandle) curl_cli_init(2000,200,0);
	int ret=0;
	curl_easy_setopt(eh->curl_impl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(eh->curl_impl, CURLOPT_NOBODY, 1);
	curl_easy_setopt(eh->curl_impl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(eh->curl_impl, CURLOPT_URL, url);

	int retry = 3;
	char* tmplocalip,*tmpsvrip;
	if (localip)
		*localip = NULL;
	if (srvip)
		*srvip = NULL;
	while (retry--)
	{
		ret = curl_easy_perform(eh->curl_impl);
		if (ret != CURLE_OK)
		{
			NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_peek_url error:%d %s", ret, eh->error_buf);
			continue;
		}
		else
		{
			if (-1 == http_status_line_parse(eh))
			{
				NAVI_FRAME_LOG(NAVI_LOG_ERR,"parse response status line failed");
				if(http_status)
				{
					*http_status=-1;
				}
			}
			else
			{
				if(http_status)
				{
					*http_status = eh->resp_info.http_status;
				}
			}
			curl_easy_getinfo(eh->curl_impl, CURLINFO_LOCAL_IP, &tmplocalip);
			curl_easy_getinfo(eh->curl_impl, CURLINFO_PRIMARY_IP, &tmpsvrip);
			if(localip)*localip = strdup(tmplocalip);
			if(srvip)*srvip = strdup(tmpsvrip);
			break;
		}
	}

	curl_cli_destroy(eh);
	return ret;
}

int curl_cli_get(curl_cli_handle handle, const char* url_args)
{
	CurlCliHandle eh = (CurlCliHandle) handle;
	int ret;
	if (handle == NULL)
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_get no handle");
		return -1;
	}
	curl_cli_reset(eh);
	curl_easy_setopt(eh->curl_impl, CURLOPT_HTTPGET, 1);
	curl_easy_setopt(eh->curl_impl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(eh->curl_impl, CURLOPT_URL, url_args);
	curl_easy_setopt(eh->curl_impl, CURLOPT_HTTPHEADER, eh->const_custom_headers);
	ret = curl_easy_perform(eh->curl_impl);
	if (ret != CURLE_OK)
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_get error:%d %s", ret, eh->error_buf);
		return ret;
	}
	eh->resp_info.http_body = eh->body_buf->content;
	eh->resp_info.http_body_len = eh->body_buf->len;
	eh->resp_info.http_error_desc = eh->http_resp_desc;

	if (-1 == http_status_line_parse(eh))
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"parse response status line failed");
		return -1;
	}
	if (-1 == fillin_ncli_buf(&eh->body_buf, "\0", 1))
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_get padding body_buf with \\0 failed");
		return ret;
	}
	return ret;
}

int curl_cli_post(curl_cli_handle handle, const char* url, const char* postbuf, int size)
{
	CurlCliHandle eh = (CurlCliHandle) handle;
	int ret;
	if (handle == NULL)
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_post no handle");
		return -1;
	}
	curl_cli_reset(eh);
	curl_easy_setopt(eh->curl_impl, CURLOPT_POST, 1);
	curl_easy_setopt(eh->curl_impl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(eh->curl_impl, CURLOPT_URL, url);
	curl_easy_setopt(eh->curl_impl, CURLOPT_POSTFIELDS, (void*)postbuf);
	curl_easy_setopt(eh->curl_impl, CURLOPT_POSTFIELDSIZE, size);
	curl_easy_setopt(eh->curl_impl, CURLOPT_HTTPHEADER, eh->const_custom_headers);
	ret = curl_easy_perform(eh->curl_impl);
	if (ret != CURLE_OK)
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_post error:%d %s", ret, eh->error_buf);
		return ret;
	}
	eh->resp_info.http_body = eh->body_buf->content;
	eh->resp_info.http_body_len = eh->body_buf->len;
	eh->resp_info.http_error_desc = eh->http_resp_desc;

	if (-1 == http_status_line_parse(eh))
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"parse response status line failed");
		return -1;
	}
	if (-1 == fillin_ncli_buf(&eh->body_buf, "\0", 1))
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_get padding body_buf with \\0 failed");
		return -1;
	}
	return ret;
}

const curl_cli_resp_info* curl_cli_get_resp(const curl_cli_handle handle)
{
	CurlCliHandle eh = (CurlCliHandle) handle;
	if (handle == NULL)
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_get_resp no handle");
		return NULL;
	}
	return &(eh->resp_info);
}

const char* curl_cli_error(const curl_cli_handle handle)
{
	CurlCliHandle eh = (CurlCliHandle) handle;
	if (handle == NULL)
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"curl_cli_get_resp no handle");
		return NULL;
	}
	return eh->error_buf;
}

