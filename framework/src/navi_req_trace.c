/*
 * navi_req_trace.c
 *
 *  Created on: 2014-8-6
 *      Author: li.lei
 */

#include "navi_req_trace.h"


static const char* navi_trace_tags[] = {
	"<info> ",
	"<comm> ",
	"<data> ",
	"<retry> ",
	"<server> ",
	"<config> ",
	"<backend> "
};

navi_trace_t* navi_trace_init(navi_pool_t* pool)
{
	navi_trace_t* obj = navi_pool_calloc(pool, 1, sizeof(navi_trace_t));
	obj->pool = pool;
	return obj;
}

const char* navi_trace(navi_trace_t* trace, const char* mod_nm, navi_trace_type_e e, const char* fmt, ...)
{
	if (trace->entries == NULL) {
		trace->entries = navi_array_create(trace->pool, 4, sizeof(navi_trace_entry_t));
	}

	navi_trace_entry_t* ent = navi_array_push(trace->entries);
	ent->type = e;

	char buf[512];
	char* pbuf = buf, *tail = pbuf + 512;
	va_list ap;
	size_t sz;
	sz = sprintf(pbuf, "%s_%s", mod_nm, navi_trace_tags[e]);
	pbuf += sz;
	va_start(ap, fmt);
	sz += vsnprintf(pbuf, tail - pbuf , fmt, ap);
	if ( sz >= sizeof(buf) ) {
		pbuf = navi_pool_alloc(trace->pool, sz+1);
		sz = sprintf(pbuf, "%s_%s", mod_nm, navi_trace_tags[e]);
		vsprintf(pbuf+sz, fmt, ap);
		ent->desc = pbuf;
	}
	else {
		ent->desc = navi_pool_strdup(trace->pool, buf);
	}
	va_end(ap);

	return ent->desc;
}

const char* navi_vtrace(navi_trace_t* trace, const char* mod_nm, navi_trace_type_e e,const char* fmt, va_list vp)
{
	if (trace->entries == NULL) {
		trace->entries = navi_array_create(trace->pool, 4, sizeof(navi_trace_entry_t));
	}

	navi_trace_entry_t* ent = navi_array_push(trace->entries);
	ent->type = e;

	char buf[512];
	char* pbuf = buf, *tail = pbuf + 512;
	size_t sz;
	sz = sprintf(pbuf, "%s_%s",mod_nm, navi_trace_tags[e]);
	pbuf += sz;
	va_list ap;
	va_copy(ap, vp);
	sz += vsnprintf(pbuf, tail - pbuf , fmt, ap);
	if ( sz >= sizeof(buf) ) {
		pbuf = navi_pool_alloc(trace->pool, sz+1);
		sz = sprintf(pbuf, "%s_%s",mod_nm, navi_trace_tags[e]);
		vsprintf(pbuf+sz, fmt, ap);
		ent->desc = pbuf;
	}
	else {
		ent->desc = navi_pool_strdup(trace->pool, buf);
	}
	va_end(ap);

	return ent->desc;
}

json_t* navi_trace_json(navi_trace_t* trace)
{
	if (!trace->entries || trace->entries->count == 0)
		return NULL;

	int pt, i;
	json_t* ret = json_array();
	navi_array_part_t* part;
	for (pt=0; pt<trace->entries->part_size; pt++) {
		part = trace->entries->parts[pt];
		if (!part)
			break;

		navi_trace_entry_t* ent = (navi_trace_entry_t*)part->allocs;
		for (i=0; i<part->used; i++,ent++) {
			json_array_append_new(ret, json_string(ent->desc));
		}
	}
	return ret;
}
