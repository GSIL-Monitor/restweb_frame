/*
 * module.log.c
 *
 *  Created on: 2013Äê10ÔÂ15ÈÕ
 *      Author: li.lei
 */


#include "%{MODULE_LCASE}_log.h"

#define CONF_LOG_LEVEL "log_level"

navi_log_h %{MODULE_LCASE}_log_g = NULL;

void %{MODULE_LCASE}_log_init(const json_t* log_level_cfg)
{
	if (%{MODULE_LCASE}_log_g == NULL) {
		%{MODULE_LCASE}_log_g = navi_log_init(NAVI_LOG_NOTICE, "[%{MODULE_LCASE}]", 512);
	}
	json_t* je = json_object_get(log_level_cfg, CONF_LOG_LEVEL);
	if (je && json_is_string(je)) {
		const char* level = json_string_value(je);

		if (0 == strcmp(level, "debug")) {
			navi_log_set_minlevel(%{MODULE_LCASE}_log_g, NAVI_LOG_DEBUG);
		}
		else if (0 == strcmp(level, "info")) {
			navi_log_set_minlevel(%{MODULE_LCASE}_log_g, NAVI_LOG_INFO);
		}
		else if (0 == strcmp(level, "notice")) {
			navi_log_set_minlevel(%{MODULE_LCASE}_log_g, NAVI_LOG_NOTICE);
		}
		else if (0 == strcmp(level, "warning")) {
			navi_log_set_minlevel(%{MODULE_LCASE}_log_g, NAVI_LOG_WARNING);
		}
		else if (0 == strcmp(level, "error")) {
			navi_log_set_minlevel(%{MODULE_LCASE}_log_g, NAVI_LOG_ERR);
		}
		else if (0 == strcmp(level, "emerge")) {
			navi_log_set_minlevel(%{MODULE_LCASE}_log_g, NAVI_LOG_EMERG);
		}
	}
}

void %{MODULE_LCASE}_log_destroy()
{
	navi_log_destroy(%{MODULE_LCASE}_log_g);
}
