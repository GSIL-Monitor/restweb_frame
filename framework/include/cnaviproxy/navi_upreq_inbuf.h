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
	uint8_t* buf; //Э�����������
	uint8_t* end; //����λ��
	uint8_t* cur_last; //�ϴ�д��λ��
	uint8_t* cur_pending; //��ǰЭ�鵥Ԫ����ʼλ��
	uint8_t* cur_probe; //��ǰЭ�����λ��
}nvup_inbuf_t;

void nvup_inbuf_init(nvup_inbuf_t* obj, size_t sz);

// �����ֽڵ�����ֵ�� 0~255������-1ʱ����ʾ���������ٻ�ȡ
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

// ��ĳ��Э�鵥Ԫ�������������øýӿڣ��ѽ�����ɵ�Э�鵥Ԫ��ռ�û�����Ա�����
void nvup_inbuf_accept_unit(nvup_inbuf_t* obj);

// navi��ܵײ��������øú���������˷�����д��Э�����������
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
