/*
 * navi_upreq_proto_buf.h
 *
 *  Created on: 2013-12-23
 *      Author: li.lei
 */

#ifndef NAVI_UPREQ_PROTO_BUF_H_
#define NAVI_UPREQ_PROTO_BUF_H_

#include "navi_common_define.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct nvup_inbuf_s {
	uint8_t* buf; //协议解析缓冲区
	uint8_t* end; //结束位置
	uint8_t* cur_last; //上次写入位置
	uint8_t* cur_pending; //当前协议单元的起始位置
	uint8_t* cur_probe; //当前协议解析位置
}nvup_inbuf_t;

void nvup_inbuf_init(nvup_inbuf_t* obj, size_t sz);

// 返回字节的整数值， 0~255。返回-1时，表示已无数据再获取
static inline int nvup_inbuf_probe(nvup_inbuf_t* obj)
{
	if (obj->cur_probe==obj->cur_last)
		return -1;

	return (int)*obj->cur_probe++;
}

static inline size_t nvup_inbuf_ahead(nvup_inbuf_t* obj, size_t sz)
{
	sz = (obj->cur_last-obj->cur_probe)>=sz ? sz : (obj->cur_last-obj->cur_probe) ;
	obj->cur_probe += sz;
	return sz;
}

// 当某个协议单元完整解析，调用该接口，已解析完成的协议单元所占用缓冲可以被重用
void nvup_inbuf_accept_unit(nvup_inbuf_t* obj);

// navi框架底层驱动调用该函数，将后端返回流写入协议解析缓冲区
void nvup_inbuf_fillin(nvup_inbuf_t* obj,
	uint8_t* in, size_t sz);

void nvup_inbuf_reset(nvup_inbuf_t* obj);

void nvup_inbuf_check(nvup_inbuf_t* buf);

static inline void nvup_inbuf_clean(nvup_inbuf_t* buf) {
	if (buf && buf->buf) {
		free(buf->buf);
		buf->buf = NULL;
	}
}

#ifdef __cplusplus
};
#endif

#endif /* NAVI_UPREQ_PROTO_BUF_H_ */
