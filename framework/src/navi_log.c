/*
 * navi_log.c
 *
 *  Created on: 2013-9-11
 *      Author: li.lei
 */

#include "navi_log.h"
#include <syslog.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>

typedef struct navi_log_s
{
	int log_level;
	char* log_tag;
	char* log_buf;
	size_t log_buf_sz;
} navi_log_t;

static int syslog_level[NAVI_LOG_EMERG + 1] =
{
    LOG_DEBUG,
    LOG_INFO,
    LOG_NOTICE,
    LOG_WARNING,
    LOG_ERR,
    LOG_CRIT
};

static const char* syslog_level_str[NAVI_LOG_EMERG + 1] =
{
	"<debug>",
	"<info>",
	"<notice>",
	"<warning>",
	"<error>",
	"<critical>"
};

navi_log_h navi_log_init(navi_log_level min_level, const char* tag,
    size_t max_log)
{
	navi_log_t* ret = (navi_log_t*) calloc(1, sizeof(navi_log_t));
	if (!ret)
		return NULL;

	ret->log_level = min_level;
	ret->log_tag = tag ? strdup(tag) : strdup("");

	if (max_log < 256)
		max_log = 256;

	ret->log_buf_sz = max_log + 1;
	ret->log_buf = (char*) malloc(ret->log_buf_sz);
	if (!ret->log_buf)
		navi_log_destroy(ret);

	return ret;
}

void navi_log_destroy(navi_log_h h)
{
	if (!h)
		return;
	navi_log_t* log = (navi_log_t*) h;
	if (log->log_tag)
		free(log->log_tag);
	if (log->log_buf)
		free(log->log_buf);
	free(log);
}

void navi_log(navi_log_h h, navi_log_level level, const char* fmt, ...)
{
	navi_log_t* log = (navi_log_t*) h;
	if (!log || log->log_level > level)
		return;
	char* p = log->log_buf;
	char* t = log->log_buf + log->log_buf_sz;

	openlog(log->log_tag, LOG_PID | LOG_CONS, LOG_USER);
	va_list ap;
	va_start(ap, fmt);
	p += snprintf(p, (size_t) (t - p), "%s  ", syslog_level_str[level]);
	vsnprintf(p, t - p, fmt, ap);
	va_end(ap);
	syslog(syslog_level[level], log->log_buf);
	closelog();
	return;
}

void navi_log_set_minlevel(navi_log_h h, navi_log_level min)
{
	navi_log_t* log = (navi_log_t*) h;
	if (!log)
		return;
	log->log_level = min;
}
