/*
 * navi_common_define.h
 *
 *  Created on: 2013-9-4
 *      Author: li.lei
 */

#ifndef NAVI_COMMON_DEFINE_H_
#define NAVI_COMMON_DEFINE_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NAVI_OK 0
#define NAVI_FAILED -6

#define NAVI_ARG_ERR -7
#define NAVI_INNER_ERR -8
#define NAVI_CLI_ERR -9
#define NAVI_CONF_ERR -10

#define NAVI_DECLINED 11
#define NAVI_CONCLUDED 12

#define NAVI_DENY NAVI_DECLINED
#define NAVI_IC_PASS NAVI_OK

//公共的双端链表结构。
typedef struct chian_node_s {
	struct chian_node_s *next;
	struct chian_node_s *prev;
}chain_node_t;

typedef enum navi_trace_type_E {
	TRACE_INFO, //一些用于跟踪的常用信息
	TRACE_COMM_FAIL, //通讯问题
	TRACE_DATA_INAVLID, //数据预期不满足
	TRACE_RETRY, //标记有重试
	TRACE_INNER_ERR, //标记运行期间遇到无法处理的错误
	TRACE_CONFIG_ERR, //配置错误导致
	TRACE_BACKEND_ERR //标记后端返回的错误
}navi_trace_type_e;

#ifdef __cplusplus
}
#endif

#endif /* NAVI_COMMON_DEFINE_H_ */
