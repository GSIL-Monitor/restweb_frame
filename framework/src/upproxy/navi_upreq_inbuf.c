/*
 * navi_upreq_parse_in_buf.c
 *
 *  Created on: 2013-12-23
 *      Author: li.lei
 */

#include "navi_upreq_inbuf.h"

void nvup_inbuf_init(nvup_inbuf_t* obj, size_t sz)
{
	if (obj->buf == NULL) {
		obj->buf = (char*)malloc(sz+1);
		if (obj->buf==NULL)
			return ;
		obj->cur_last = obj->cur_pending =
			obj->cur_probe = obj->buf;
		obj->end = obj->buf + sz;
	}
}

// 当某个协议单元完整解析，调用该接口，已解析完成的协议单元所占用缓冲可以被重用
void nvup_inbuf_accept_unit(nvup_inbuf_t* ctx)
{
	ctx->cur_pending = ctx->cur_probe;
	if (ctx->cur_pending==ctx->cur_last) {
		ctx->cur_pending = ctx->cur_probe = ctx->cur_last = ctx->buf;
	}
	else if((ctx->end - ctx->cur_last)<32){
		size_t mv_off = ctx->cur_pending - ctx->buf;
		memmove(ctx->buf, ctx->cur_pending, ctx->cur_last - ctx->cur_pending);
		ctx->cur_probe = ctx->cur_pending = ctx->buf;
		ctx->cur_last -= mv_off;
	}
}

// navi框架底层驱动调用该函数，将后端返回流写入协议解析缓冲区
void nvup_inbuf_fillin(nvup_inbuf_t* ctx,
	uint8_t* in, size_t sz)
{
	size_t cur_free = ctx->end - ctx->cur_last;
	size_t head_free = ctx->cur_pending - ctx->buf;
	size_t keep_sz = ctx->cur_last - ctx->cur_pending;

	if (in == NULL || sz == 0){
		return;
	}

	if (cur_free>=sz) {
		memcpy(ctx->cur_last, in, sz);
		ctx->cur_last += sz;
	}
	else if (cur_free+head_free >= sz) {
		memmove(ctx->buf,ctx->cur_pending, keep_sz);
		ctx->cur_pending -= head_free;
		ctx->cur_last -= head_free;
		ctx->cur_probe -= head_free;
		memcpy(ctx->cur_last, in, sz);
		ctx->cur_last+= sz;
	}
	else {
		size_t new_sz = keep_sz + sz + 64;
		size_t probe_off = ctx->cur_probe - ctx->cur_pending;
		memmove(ctx->buf,ctx->cur_pending, keep_sz);

		char* new_buf = realloc(ctx->buf, new_sz + 1);
		ctx->buf = new_buf;
		ctx->cur_pending = ctx->buf;
		ctx->cur_last = new_buf + keep_sz;
		ctx->cur_probe = new_buf + probe_off;
		ctx->end = ctx->buf + new_sz;
		memcpy(ctx->cur_last, in, sz);
		ctx->cur_last += sz;
	}
}

void nvup_inbuf_reset(nvup_inbuf_t* obj)
{
	obj->cur_last = obj->cur_pending =
		obj->cur_probe = obj->buf;
}

void nvup_inbuf_check(nvup_inbuf_t* buf) {
	if (buf->cur_probe==buf->end) {
		if(buf->cur_pending==buf->buf) {
			//表示协议缓存不够，需要realloc
			size_t cur_sz = buf->end - buf->buf;
			char* new_buf = (char*)realloc(buf->buf, cur_sz*2 + 1);
			buf->buf = new_buf;
			buf->cur_pending = new_buf;
			buf->cur_last = buf->cur_probe = new_buf+cur_sz;
			buf->end = new_buf+cur_sz*2;
		}
		else {
			size_t mv_sz = buf->cur_pending - buf->buf;
			memmove(buf->buf, buf->cur_pending, buf->end - buf->cur_pending);
			buf->cur_pending = buf->buf;
			buf->cur_last -= mv_sz;
			buf->cur_probe -= mv_sz;
		}
	}
}

