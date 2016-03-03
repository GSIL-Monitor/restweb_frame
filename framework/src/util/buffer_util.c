/*
 *Copyright (C)2012 1verge.com (http://www.youku.com)
 *nstatus internal buffer
 *Interface descripe:
 *	nstatus internal buffer
 *Author: lilei
 *Createtime: 2012.09.17
 *MSN: leetstone@hotmail.com
 *Report Bugs: li.lei@youku.com
 *Address: China BeiJing
 *Version: 1.0.0.0
 *Latest modify time:2012.09.25
 */

#include "buffer_util.h"
#include "navi_frame_log.h"
#include <stdlib.h>

#define RESP_BUF_SIZE(size) ((size_t)(((int)((sizeof(ncli_buffer_t) + (size)) + 255))&0xffffff00))

ncli_buffer_h init_ncli_buf(size_t size)
{
	ncli_buffer_h ret = (ncli_buffer_h) malloc(RESP_BUF_SIZE(size));
	if (ret == NULL)
	{
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"init_curl_resp_buf error");
		return ret;
	}
	ret->len = 0;
	ret->size = RESP_BUF_SIZE(size) - sizeof(ncli_buffer_t);
	return ret;
}

void destroy_ncli_buf(ncli_buffer_h buf)
{
	if (buf)
		free(buf);
}

int fillin_ncli_buf(ncli_buffer_h* buf, const char* in, int size)
{
	ncli_buffer_h obuf = *buf;
	int newsize = obuf->len + size;
	if (newsize > obuf->size)
	{
		newsize = RESP_BUF_SIZE(newsize*2);
		obuf = (ncli_buffer_h) realloc(obuf, newsize);
		if (obuf == NULL)
		{
			NAVI_FRAME_LOG(NAVI_LOG_ERR,"fillin_resp_buf error");
			return -1;
		}
		obuf->size = newsize - sizeof(ncli_buffer_t);
		*buf = obuf;
	}
	if(in)
	{
		memcpy((void*) (obuf->content + obuf->len), (void*) in, size);
		obuf->len += size;
	}
	return size;
}

void reset_ncli_buf(ncli_buffer_h *buf)
{
	ncli_buffer_h obuf = *buf;
	ncli_buffer_h rsbuf = *buf;
	if (obuf->size > 1048576)
	{
		obuf = init_ncli_buf(40960);
		if (obuf)
		{
			destroy_ncli_buf(rsbuf);
			*buf = obuf;
		}
		else
		{
			*buf = rsbuf;
			rsbuf->len = 0;
		}
		return;
	}
	obuf->len = 0;
}

