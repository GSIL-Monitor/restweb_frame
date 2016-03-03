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

//������˫������ṹ��
typedef struct chian_node_s {
	struct chian_node_s *next;
	struct chian_node_s *prev;
}chain_node_t;

typedef enum navi_trace_type_E {
	TRACE_INFO, //һЩ���ڸ��ٵĳ�����Ϣ
	TRACE_COMM_FAIL, //ͨѶ����
	TRACE_DATA_INAVLID, //����Ԥ�ڲ�����
	TRACE_RETRY, //���������
	TRACE_INNER_ERR, //��������ڼ������޷�����Ĵ���
	TRACE_CONFIG_ERR, //���ô�����
	TRACE_BACKEND_ERR //��Ǻ�˷��صĴ���
}navi_trace_type_e;

#ifdef __cplusplus
}
#endif

#endif /* NAVI_COMMON_DEFINE_H_ */
