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

#ifndef BUFFER_UTIL_H_
#define BUFFER_UTIL_H_
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>

#ifdef __cplusplus
extern "C"{
#endif

typedef struct _ncli_buffer
{
	int len;
	int size;
	char content[0];
} ncli_buffer_t;

typedef ncli_buffer_t* ncli_buffer_h;

ncli_buffer_h init_ncli_buf(size_t size);
void destroy_ncli_buf(ncli_buffer_h buf);
int fillin_ncli_buf(ncli_buffer_h* buf, const char* in, int size);
void reset_ncli_buf(ncli_buffer_h *buf);

#ifdef __cplusplus
}
#endif

#endif /* BUFFER_UTIL_H_ */
