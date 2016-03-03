/*
 * navi_req_trace.h
 *
 *  Created on: 2014-8-6
 *      Author: li.lei
 */

#ifndef NAVI_REQ_TRACE_H_
#define NAVI_REQ_TRACE_H_

#include "navi_common_define.h"
#include "navi_pool.h"
#include "navi_simple_array.h"
#include <jansson.h>

typedef struct navi_trace_entry_s {
	navi_trace_type_e type;
	char* desc;
}navi_trace_entry_t;

typedef struct navi_trace_s {
	navi_array_t* entries;
	navi_pool_t* pool;
}navi_trace_t;

navi_trace_t* navi_trace_init(navi_pool_t* pool);
const char* navi_trace(navi_trace_t* trace, const char* mod_nm, navi_trace_type_e e, const char* fmt, ...);
const char* navi_vtrace(navi_trace_t* trace, const char* mod_nm, navi_trace_type_e e,const char* fmt, va_list ap);
json_t* navi_trace_json(navi_trace_t* trace);

#endif /* NAVI_REQ_TRACE_H_ */
