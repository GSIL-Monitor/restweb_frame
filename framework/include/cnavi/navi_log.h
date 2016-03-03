/*
 * navi_log.h
 *
 *  Created on: 2013-9-11
 *      Author: li.lei
 *      Desc: ҵ��ģ�����ʹ�ñ��ӿڣ�������־��
 *     		ҵ��ģ����Զ����Լ�����־�꣬����navi_frame_log.h��
 *     		* ��Ҫ�Զ���һ��ģ���������ڵ�ȫ����־����ͨ��navi_log_init��ʼ��
 *     		* ��־����Ի��ڸ�ȫ����־�������navi_log�ĵ���
 */

#ifndef NAVI_LOG_H_
#define NAVI_LOG_H_
#include <stdlib.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum navi_log_level_e {
	NAVI_LOG_DEBUG,
	NAVI_LOG_INFO,
	NAVI_LOG_NOTICE,
	NAVI_LOG_WARNING,
	NAVI_LOG_ERR,
	NAVI_LOG_EMERG
}navi_log_level;

typedef void* navi_log_h;

navi_log_h navi_log_init(navi_log_level min_level,const char* tag,size_t max_log);
void navi_log_destroy(navi_log_h h);
void navi_log(navi_log_h h,navi_log_level level,const char* fmt,...);
void navi_log_set_minlevel(navi_log_h h,navi_log_level min);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_LOG_H_ */
