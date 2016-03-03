/** \brief 
 * nvcli_http.h
 *  Created on: 2015-1-13
 *      Author: li.lei
 *  brief: 
 */

#ifndef NVCLI_HTTP_H_
#define NVCLI_HTTP_H_

#include "navi_common_define.h"
#include "navi_grcli.h"
#include "../cnaviproxy/navi_upreq_inbuf.h"
#include "navi_formdata_post.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum _nvcli_http_method
{
	NV_HTTP_GET,
	NV_HTTP_POST,
	NV_HTTP_HEAD,
	NV_HTTP_PUT,
	NV_HTTP_DELETE
}nvcli_http_method;

typedef struct _nvcli_http_parse_state_s
{
	enum {
		status_line,
		in_headers,
		in_body,
		in_complete
	} stage;
	uint32_t state;
	union {
		struct {
			uint8_t* header_name_begin;
			uint8_t* header_name_end;
		};
		uint8_t* chunk_data_begin;
	};
	uint8_t* header_value_begin;
	uint8_t* header_value_end;

	union {
		int chunk_size;
		int cur_body_size;
	};
} nvcli_http_parse_state_t;

typedef struct _nvcli_http_s
{
	navi_grcli_t base;

	nvcli_http_method method;
	const char* uri;
	navi_hash_t* o_args;
	navi_hash_t* o_headers;
	int obody_length;
	int obody_have;

	uint8_t http_major;
	uint8_t http_minor;
	int i_status;
	int64_t icontent_length;
	const char* i_status_desc;
	navi_hash_t* i_headers;

	navi_timer_t* output_timer;

	int (*obody_generator)(void* parent, struct _nvcli_http_s* ss);
	void (*iheader_ready_handler)(void* , struct _nvcli_http_s* );
	void (*ibody_handler)(void* , struct _nvcli_http_s*, const unsigned char*, size_t);

	nvup_inbuf_t iheader_parse_buf;
	nvcli_http_parse_state_t* parse;
	navi_buf_chain_t* ibody_cache;
	unsigned char* ibody_whole;

	int start:1;
	int has_obody:1;
	int obody_chunked:1;
	int o_conn_close:1;
	int i_conn_close:1;
	int ibody_chunked:1;
	int ibody_chunk_fin:1;
	int ibody_app_whole:1;
} nvcli_http_t;

typedef int (*nvhttp_reqbody_generator_fp)(void* parent, nvcli_http_t* ss);
typedef void (*nvhttp_resp_start_fp)(void* parent, nvcli_http_t* ss);
typedef void (*nvhttp_respbody_handler_fp)(void* parent, nvcli_http_t* ss,
	const unsigned char* content, size_t size);
typedef void (*nvhttp_session_complete_fp)(void* parent, nvcli_http_t* ss);
typedef void (*nvhttp_error_handler_fp)(void* parent, nvcli_http_t* ss, nvcli_error_e e);

typedef struct _nvcli_http_procs_t
{
	nvhttp_error_handler_fp session_error_handler;
	nvhttp_session_complete_fp session_complete_handler;
	nvhttp_reqbody_generator_fp obody_goon_handler;
	nvhttp_resp_start_fp iheader_process_handler;
	nvhttp_respbody_handler_fp ibody_process_handler;
} nvcli_http_procs_t;

nvcli_http_t* nvcli_http_init(nvcli_parent_t* ctx,
	const struct sockaddr* peer_addr,
	const char* uri,
	nvcli_http_procs_t app_procs,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval);

static inline void nvcli_http_abort(nvcli_http_t* session)
{
	nvcli_clean(&session->base);
}

static inline void* nvcli_http_app_data(nvcli_http_t* session)
{
	return session->base.app_data;
}

static inline void nvcli_http_set_appdata_cleanup(nvcli_http_t* ss,
	void (*clean)(void*))
{
	ss->base.app_data_cleanup = clean;
}

static inline navi_pool_t* nvcli_http_pool(nvcli_http_t* ss)
{
	return ss->base.private_pool;
}

void nvcli_http_set_error_process(nvcli_http_t* ss, nvhttp_error_handler_fp error_handler);

void nvcli_http_set_reqbody_process(nvcli_http_t* ss, int content_length,
	nvhttp_reqbody_generator_fp body_handler);

int nvcli_http_set_arg(nvcli_http_t* session, const char* arg, const char* v);
const char* nvcli_http_get_arg(nvcli_http_t* session, const char* arg);

void nvcli_http_set_args(nvcli_http_t* session, navi_hash_t* args);

int nvcli_http_set_reqheader(nvcli_http_t* session, const char* header, const char* v);
const char* nvcli_http_get_reqheader(nvcli_http_t* session, const char* header);

int nvcli_http_append_reqbody(nvcli_http_t* session, const unsigned char* body, size_t size);
int nvcli_http_append_reqbody_filepart(nvcli_http_t* session, int fd, off_t foff, size_t size);

int nvcli_http_start(nvcli_http_t* session, nvcli_http_method method);
int nvcli_http_start_formdata(nvcli_http_t* session, navi_formdata_t* form);

void nvcli_http_set_resp_process(nvcli_http_t* ss, nvhttp_resp_start_fp resp_handler );
void nvcli_http_set_respbody_process(nvcli_http_t* ss, nvhttp_respbody_handler_fp ibody_handler,
	bool proc_slice);

int nvcli_http_get_respstatus(nvcli_http_t* session, const char** status_desc);
const char* nvcli_http_get_respheader(nvcli_http_t* session, const char* header);
int64_t nvcli_http_get_respbody_length(nvcli_http_t* session);

int nvcli_http_get_respbody(nvcli_http_t* session, unsigned char** body);

#ifdef __cplusplus
}
#endif


#endif /* NVCLI_HTTP_H_ */
