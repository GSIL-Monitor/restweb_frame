/*
 * navi_log_util.h
 *
 *  Created on: 2013-9-11
 *      Author: li.lei
 */

#ifndef NAVI_LOG_UTIL_H_
#define NAVI_LOG_UTIL_H_

#include "navi_log.h"
#include <errno.h>
#include <error.h>

extern int errno;

extern navi_log_h navi_frame_log;

#define NAVI_SYSERR_LOG(extra) do{\
	NAVI_FRAME_LOG(NAVI_LOG_ERR,extra" %s",strerror(errno));\
}while(0)

#define NAVI_FRAME_LOG(level,...) do{\
	NAVI_FRAME_LOG_FL((level),__VA_ARGS__,"");\
}while(0)

#define NAVI_FRAME_LOG_FL(level,format,...) do{\
	navi_log(navi_frame_log,(level),format"%s {%s:%d}",\
		__VA_ARGS__,__FUNCTION__,__LINE__);\
}while(0)


#endif /* NAVI_LOG_UTIL_H_ */
