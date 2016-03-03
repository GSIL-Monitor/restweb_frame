/*
 * navi_bsession.h
 *
 *  Created on: 2015年6月10日
 *      Author: li.lei
 */

#ifndef NAVI_BSESSION_H_
#define NAVI_BSESSION_H_

#include "navi_common_define.h"
#include "navi_pool.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define BSESSION_DEFAULT_SOCK_BUF 4096
#define BSESSION_DEFAULT_CONN_TIMEOUT 500
#define BSESSION_DEFAULT_TIMEOUT 500

typedef enum navi_bsession_code_E {
	BSESSION_OK,
	BSESSION_SYSERR,
	BSESSION_CONN_FAILED,
	BSESSION_CONN_TIMEDOUT,
	BSESSION_BROKEN,
	BSESSION_REQ_TIMEDOUT,
	BSESSION_RESP_TIMEDOUT,
	BSESSION_PROTO_ERR,
	BSESSION_ABUSED
} navi_bsession_code_e;

/*
 * \brief 要求回调返回0表示响应未完。返回1表示响应完整。-1表示协议错误。
 */
typedef int (*bsession_resp_parser_fp)(void* parse_ctx, const uint8_t* raw, size_t len);
navi_bsession_code_e navi_bsession_request(const struct sockaddr* sa,
	int session_toms,
	int keepalive,
	const uint8_t* req_raw, size_t len,
	bsession_resp_parser_fp parser, void* ctx);

void navi_bsession_util_init();
void navi_bsession_check_idle(bool closeall);

#ifdef __cplusplus
}
#endif

#endif /* INCLUDE_CNAVI_NAVI_BSESSION_H_ */
