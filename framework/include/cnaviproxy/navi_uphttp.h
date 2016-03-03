/*
 * navi_uphttp.h
 *
 *  Created on: 2013-12-11
 *      Author: li.lei
 */

#ifndef NAVI_UPHTTP_H_
#define NAVI_UPHTTP_H_
#include "navi_upreq.h"

#ifdef __cplusplus
extern "C" {
#endif

int navi_request_launch_uphttp(navi_request_t* req, const char* srv_grp, const char* remote_uri);
int navi_request_launch_uphttp_ext(navi_request_t* req, const char* srv_grp, 
	const char* remote_uri, const char *srv_name, const char *host, uint16_t port);
int navi_request_launch_uphttp_tm(navi_request_t* req, const char* srv_grp, const char* remote_uri, 
	int cnn_timeout_ms, int rw_timeout_ms, const char *srv_name, const char *host, uint16_t port);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_UPHTTP_H_ */
