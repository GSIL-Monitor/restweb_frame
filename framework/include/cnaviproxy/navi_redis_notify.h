/*
 * navi_redis_notify.h
 *
 *  Created on: 2014-04-08
 *      Author: yanguotao@youku.com
 */

#ifndef NAVI_REDIS_NOTIFY_H_
#define NAVI_REDIS_NOTIFY_H_

#include "navi_common_define.h"
#include "navi_vevent_mgr.h"
#include "navi_pipe.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct navi_redis_notify_s
{
	navi_vevent_t *ve;
	navi_pipe_t *pipe;
	char *notify_name;
	chain_node_t link;
}navi_redis_notify_t;

int navi_redis_notify_pipe_regist(const char *group, navi_redis_notify_t* notify);
int navi_redis_notify_pipe_wait(navi_redis_notify_t* notify, const char *value);
int navi_redis_notify_pipe_cancel(navi_redis_notify_t* notify);
void navi_redis_notify_destroy(void *imp);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_REDIS_NOTIFY_H_ */

