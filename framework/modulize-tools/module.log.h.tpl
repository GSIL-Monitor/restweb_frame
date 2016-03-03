/*
 * module.log.h
 *
 *  Created on: 2013Äê10ÔÂ15ÈÕ
 *      Author: li.lei
 */

#ifndef MODULE_%{MODULE_UCASE}_LOG_H_
#define MODULE_%{MODULE_UCASE}_LOG_H_

#include "navi_log.h"
#include <errno.h>
#include <error.h>
#include <jansson.h>

extern int errno;

extern navi_log_h %{MODULE_LCASE}_log_g;

#define %{MODULE_LCASE}_syserr_log(extra) do{\
	%{MODULE_LCASE}_log(NAVI_LOG_ERR,extra" %s",strerror(errno));\
}while(0)

#define %{MODULE_LCASE}_log(level,...) do{\
	%{MODULE_LCASE}_log_fl((level),__VA_ARGS__,"");\
}while(0)

#define %{MODULE_LCASE}_log_fl(level,format,...) do{\
	navi_log(%{MODULE_LCASE}_log_g,(level),format"%s {%s:%d}",\
		__VA_ARGS__,__FUNCTION__,__LINE__);\
}while(0)

void %{MODULE_LCASE}_log_init(const json_t* log_level_cfg);
void %{MODULE_LCASE}_log_destroy();

#endif /* MODULE_LOG_H_ */
