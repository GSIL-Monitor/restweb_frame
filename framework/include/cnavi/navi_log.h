/*
 * navi_log.h
 *
 *  Created on: 2013-9-11
 *      Author: li.lei
 *      Desc: 业务模块可以使用本接口，输入日志。
 *     		业务模块可以定义自己的日志宏，仿照navi_frame_log.h。
 *     		* 需要自定义一个模块生存期内的全局日志对象，通过navi_log_init初始化
 *     		* 日志宏可以基于该全局日志对象进行navi_log的调用
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
