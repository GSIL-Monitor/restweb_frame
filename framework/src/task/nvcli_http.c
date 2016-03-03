/** \brief 
 * nvcli_http.c
 *  Created on: 2015-1-16
 *      Author: li.lei
 *  brief: 
 */

#include "nvcli_http.h"
#include "navi_inner_util.h"
#include <assert.h>

static int nvhttp_parse_state(nvcli_http_t* ss, nvup_inbuf_t* buf)
{
	enum {
	    sw_start = 0,
	    sw_H,
	    sw_HT,
	    sw_HTT,
	    sw_HTTP,
	    sw_first_major_digit,
	    sw_major_digit,
	    sw_first_minor_digit,
	    sw_minor_digit,
	    sw_status,
	    sw_space_after_status,
	    sw_status_text,
	    sw_almost_done
	} dummy;

	int ch_i = 0;
	unsigned char ch;
	while ((ch_i = nvup_inbuf_probe(buf)) != -1) {
		ch = ch_i;
		switch (ss->parse->state) {

		/* "HTTP/" */
		case sw_start:
			switch (ch) {
			case 'H':
				ss->parse->state = sw_H;
				break;
			default:
				return -1;
			}
			break;

		case sw_H:
			switch (ch) {
			case 'T':
				ss->parse->state = sw_HT;
				break;
			default:
				return -1;
			}
			break;

		case sw_HT:
			switch (ch) {
			case 'T':
				ss->parse->state = sw_HTT;
				break;
			default:
				return -1;
			}
			break;

		case sw_HTT:
			switch (ch) {
			case 'P':
				ss->parse->state = sw_HTTP;
				break;
			default:
				return -1;
			}
			break;

		case sw_HTTP:
			switch (ch) {
			case '/':
				ss->parse->state = sw_first_major_digit;
				break;
			default:
				return -1;
			}
			break;

		/* the first digit of major HTTP version */
		case sw_first_major_digit:
			if (ch < '1' || ch > '9') {
				return -1;
			}

			ss->http_major = ch - '0';
			ss->parse->state = sw_major_digit;
			break;

								/* the major HTTP version or dot */
		case sw_major_digit:
			if (ch == '.') {
				ss->parse->state = sw_first_minor_digit;
				break;
			}

			if (ch < '0' || ch > '9') {
				return -1;
			}

			ss->http_major = ss->http_major * 10 + ch - '0';
			break;

			/* the first digit of minor HTTP version */
		case sw_first_minor_digit:
			if (ch < '0' || ch > '9') {
				return -1;
			}

			ss->http_minor = ch - '0';
			ss->parse->state = sw_minor_digit;
			break;

			/* the minor HTTP version or the end of the request line */
		case sw_minor_digit:
			if (ch == ' ') {
				nvup_inbuf_accept_unit(buf);
				ss->parse->state = sw_status;
				break;
			}

			if (ch < '0' || ch > '9') {
				return -1;
			}

			ss->http_minor = ss->http_minor * 10 + ch - '0';
			break;

			/* HTTP status code */
		case sw_status:
			if (ch == ' ') {
				nvup_inbuf_accept_unit(buf);
				break;
			}

			if (ch < '0' || ch > '9') {
				return -1;
			}

			ss->i_status = ss->i_status * 10 + ch - '0';

			if ( buf->cur_probe - buf->cur_pending == 3) {//probe在ch_i取值后++了
				ss->parse->state = sw_space_after_status;
			}

			break;

			/* space or end of line */
		case sw_space_after_status:
			switch (ch) {
			case ' ':
				ss->parse->state = sw_status_text;
				break;
			case '.':                    /* IIS may send 403.1, 403.2, etc */
				ss->parse->state = sw_status_text;
				break;
			case '\r':
				ss->parse->state = sw_almost_done;
				break;
			case '\n': {
				*(buf->cur_probe - 1) = '\0';
				ss->i_status_desc = navi_pool_strdup(ss->base.private_pool, (char*)buf->cur_pending);
				goto done;
			}
			default:
				return -1;
			}
			break;

			/* any text until end of line */
		case sw_status_text:
			switch (ch) {
			case '\r':
				ss->parse->state = sw_almost_done;
				break;
			case '\n':{
				*(buf->cur_probe - 1) = '\0';
				ss->i_status_desc = navi_pool_strdup(ss->base.private_pool, (char*)buf->cur_pending);
				goto done;
				}
			}
			break;

		/* end of status line */
		case sw_almost_done:
			switch (ch) {
			case '\n': {
				*(buf->cur_probe-2) = '\0';
				ss->i_status_desc = navi_pool_strdup(ss->base.private_pool, (char*)buf->cur_pending);
				goto done;
			}
			default:
				return -1;
			}
			break;
		}
	}

	return 0;
done:
	nvup_inbuf_accept_unit(buf);
	ss->parse->state = 0;
	ss->parse->stage = in_headers;
	ss->ibody_chunked = 0;//default not chunked transfer encoding
	return 1;
}

static int nvhttp_process_headers(nvcli_http_t* ss)
{
	if ( ss->parse->header_name_begin != ss->parse->header_name_end) {
		const char* header_name = ss->parse->header_name_begin;
		const char* header_value = "";
		*(ss->parse->header_name_end) = '\0';
		if ( ss->parse->header_value_begin != ss->parse->header_value_end) {
			*(ss->parse->header_value_end) = '\0';
			header_value = ss->parse->header_value_begin;
		}

		if ( ss->i_headers == NULL) {
			ss->i_headers = navi_hash_init(ss->base.private_pool);
		}


		if ( 0 == strcmp("content-length", header_name ) ) {
			if ( ss->ibody_chunked ) {
				return -1;
			}

			char* pend;
			ss->icontent_length = strtol(header_value, &pend, 10);
			if ( *pend != '\0')
				return -1;
		}
		else if ( 0 == strcmp("connection", header_name )) {
			if ( 0 == strcasecmp(header_value, "keep-alive")) {
				ss->i_conn_close = 0;
				nvacnn_set_short(ss->base.conn, false);
			}
			else if ( 0 == strcasecmp(header_value, "close")){
				ss->i_conn_close = 1;
				nvacnn_set_short(ss->base.conn, true);
			}
		}
		else if ( 0 == strcmp("transfer-encoding", header_name)) {
			if ( ss->icontent_length > 0) {
				return -1;
			}
			if ( strcasecmp("chunked", header_value))
				return -1;

			ss->ibody_chunked = 1;
		}
		navi_hash_set(ss->i_headers, header_name, header_value);
	}
	return 0;
}

static u_char  lowcase[] =
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0-\0\0" "0123456789\0\0\0\0\0\0"
	"\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
	"\0abcdefghijklmnopqrstuvwxyz\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"
	"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

static int nvhttp_parse_headers(nvcli_http_t* ss, nvup_inbuf_t* buf)
{
	enum {
		sw_start = 0,
		sw_name,
		sw_space_before_value,
		sw_value,
		sw_space_after_value,
		sw_ignore_line,
		sw_almost_done,
		sw_header_almost_done
	} dummy;

	/* the last '\0' is not needed because string is zero terminated */

	int ch_i = 0;
	unsigned char ch;
	unsigned char lc;
	while ((ch_i = nvup_inbuf_probe(buf)) != -1) {
		ch = ch_i;
		switch (ss->parse->state) {
		case sw_start:
			ss->parse->header_name_begin = buf->cur_probe - 1;
			switch (ch) {
			case '\r':
				ss->parse->header_name_end = buf->cur_probe -1;
				ss->parse->state = sw_header_almost_done;
				break;
			case '\n':
				ss->parse->header_name_end = buf->cur_probe -1;
				ss->base.iheader_done = 1;
				ss->base.input_done = 1;
				goto done;
			default:
				ss->parse->state = sw_name;
				lc = lowcase[ch];
				*(buf->cur_probe -1 ) = lc;
				if ( lc == 0)
					return -1;
				break;
			}
		break;

		case sw_name:
			lc = lowcase[ch];
			if ( !lc ) {
				switch( ch ) {
				case ':':
					ss->parse->header_name_end = buf->cur_probe - 1;
					ss->parse->state = sw_space_before_value;
					break;
				case '_':
					continue;
				case '\r':
					ss->parse->header_name_end = buf->cur_probe - 1;
					ss->parse->state = sw_almost_done;
					break;
				case '\n':
					ss->parse->header_name_end = buf->cur_probe - 1;
					goto header_done;
				default:
					return -1;
				}
			}
			else {
				*(buf->cur_probe -1 ) = lc;
				continue;
			}
		break;

		case sw_space_before_value:
			switch (ch) {
			case ' ':
				break;
			case '\r':
				ss->parse->header_value_begin = ss->parse->header_value_end =
					buf->cur_probe - 1;
				ss->parse->state = sw_almost_done;
				break;
			case '\n':
				ss->parse->header_value_begin = ss->parse->header_value_end =
					buf->cur_probe - 1;
				goto header_done;
			default:
				ss->parse->header_value_begin = buf->cur_probe -1;
				ss->parse->state = sw_value;
				break;
			}
		break;

		case sw_value:
			switch (ch ) {
			case ' ':
				ss->parse->header_value_end = buf->cur_probe  -1 ;
				ss->parse->state = sw_space_after_value;
				break;
			case '\r':
				ss->parse->header_value_end = buf->cur_probe  -1 ;
				ss->parse->state = sw_almost_done;
				break;
			case '\n':
				ss->parse->header_value_end = buf->cur_probe  -1 ;
				goto header_done;
			}
		break;

		case sw_space_after_value:
			switch (ch) {
			case ' ':
				break;
			case '\r':
				ss->parse->state = sw_almost_done;
				break;
			case '\n':
				goto header_done;
			default:
				ss->parse->state = sw_value;
				break;
			}
		break;

		case sw_almost_done:
			switch (ch) {
			case '\n':
				goto header_done;
			case '\r':
				break;
			default:
				return -1;
			}
		break;

		/* end of header */
		case sw_header_almost_done:
			switch (ch) {
			case '\n':
				goto done;
			default:
				return -1;
			}
		break;

		default:
			assert(0);
			break;
		}

		continue;

	header_done:
		if ( nvhttp_process_headers(ss) ) {
			return -1;
		}
		nvup_inbuf_accept_unit(buf);
		ss->parse->state = 0;
		ss->parse->header_name_begin = NULL;
		ss->parse->header_name_end = NULL;
		ss->parse->header_value_begin = NULL;
		ss->parse->header_value_end = NULL;
	}

	return 0;

done:
	if ( nvhttp_process_headers(ss) ) {
		return -1;
	}
	ss->parse->state = 0;
	ss->parse->header_name_begin = NULL;
	ss->parse->header_name_end = NULL;
	ss->parse->header_value_begin = NULL;
	ss->parse->header_value_end = NULL;
	nvup_inbuf_accept_unit(buf);
	ss->base.iheader_done = 1;
	if ( ss->ibody_chunked || ss->icontent_length > 0) {
		ss->parse->stage = in_body;
	}
	else {
		ss->parse->stage = in_complete;
	}
	return 1;
}

static int nvhttp_iheader_parse(void* ss, const unsigned char* in, size_t* sz)
{
	nvcli_http_t* http = (nvcli_http_t*)ss;
	nvup_inbuf_t* buf = &http->iheader_parse_buf;
	int ret;
	u_char ch;

	if ( http->parse == NULL) {
		http->parse = navi_pool_calloc(http->base.private_pool,1,
			sizeof(nvcli_http_parse_state_t));
		nvup_inbuf_init(buf, 256);
	}
	nvup_inbuf_fillin(buf, (uint8_t*)in, *sz);
header_parse:
	switch( http->parse->stage ) {
	case status_line:
		ret = nvhttp_parse_state(http, buf);
		if ( ret == 1 ) {
			if ( http->http_major == 1 && http->http_minor == 0) {
				nvacnn_set_short(http->base.conn, true);
			}
			if ( buf->cur_probe != buf->cur_last ) {
				goto header_parse;
			}
			else {
				ret = 0;
			}
		}
		break;
	case in_headers:
		ret = nvhttp_parse_headers(http, buf);
		if ( ret == 1 ) {
			*sz -= buf->cur_last - buf->cur_probe;
			nvup_inbuf_reset(buf);
			if ( http->parse->stage == in_body) {
				ret = 2;
			}

			if ( http->iheader_ready_handler) {
				http->iheader_ready_handler(http->base.parent->parent, http);
			}
		}
		break;
	default:
		ret = -1;
		break;
	}

	nvup_inbuf_check(buf);
	return ret;
}

static int nvhttp_ibody_parse(void* ss, const unsigned char* content, size_t* size)
{
	enum {
		sw_chunk_start = 0,
		sw_chunk_size,
		sw_chunk_extension,
		sw_chunk_extension_almost_done,
		sw_chunk_data,
		sw_after_data,
		sw_after_data_almost_done,
		sw_last_chunk_extension,
		sw_last_chunk_extension_almost_done,
		sw_trailer,
		sw_trailer_almost_done,
		sw_trailer_header,
		sw_trailer_header_almost_done
	} dummy;

	nvcli_http_t* http = (nvcli_http_t*)ss;
	nvup_inbuf_t* buf = &http->iheader_parse_buf;
	nvcli_http_parse_state_t* parse = http->parse;
	if ( !http->ibody_chunked) {
		parse->cur_body_size += *size;
		if ( parse->cur_body_size > http->icontent_length ) {
			*size = parse->cur_body_size - http->icontent_length;
			return -1;
		}

		if (http->ibody_app_whole) {
			navi_buf_chain_append(http->ibody_cache, content, *size);
		}
		else {
			if (http->ibody_handler) {
				http->ibody_handler(http->base.parent->parent, http, content, *size);
			}
		}

		if ( parse->cur_body_size == http->icontent_length) {
			if ( http->ibody_handler && http->ibody_app_whole) {
				http->ibody_whole =  navi_pool_nalloc(http->base.private_pool,
					http->icontent_length + 1);
				navi_buf_chain_get_content(http->ibody_cache, http->ibody_whole,
					http->icontent_length );
				http->ibody_whole[http->icontent_length] = '\0';
				http->ibody_handler(http->base.parent->parent, http, http->ibody_whole,
					http->icontent_length);
			}
			nvup_inbuf_clean(buf);
			return 1;
		}

		/****
		if (http->ibody_handler) {
			parse->cur_body_size += *size;
			if ( parse->cur_body_size > http->icontent_length ) {
				*size = parse->cur_body_size - http->icontent_length;
				return -1;
			}
			else {
				if ( http->ibody_app_whole) {
					navi_buf_chain_append(http->ibody_cache, content, *size);
				}
				else {
					http->ibody_handler(http->base.parent->parent, http, content, *size);
				}
			}

			if ( parse->cur_body_size == http->icontent_length) {
				if ( http->ibody_app_whole) {
					uint8_t* whole= navi_pool_nalloc(http->base.private_pool,
						http->icontent_length);
					navi_buf_chain_get_content(http->ibody_cache, whole,
						http->icontent_length);
					http->ibody_handler(http->base.parent->parent, http, whole,
						http->icontent_length);
				}
				nvup_inbuf_clean(buf);
				return 1;
			}
		}
		****/
	}
	else {
		nvup_inbuf_fillin(buf, (uint8_t*)content, *size);
		unsigned char ch;
		int ch_i = 0;
		while ((ch_i = nvup_inbuf_probe(buf)) != -1) {
			ch = ch_i;
			switch( parse->state) {
			case sw_chunk_start:
				if (ch >= '0' && ch <= '9') {
					parse->state = sw_chunk_size;
					parse->chunk_size = ch - '0';
					break;
				}

				unsigned char c = (u_char) (ch | 0x20);

				if (c >= 'a' && c <= 'f') {
					parse->state = sw_chunk_size;
					parse->chunk_size = c - 'a' + 10;
					break;
				}

				return -1;
			case sw_chunk_size:
				if (ch >= '0' && ch <= '9') {
					parse->chunk_size = parse->chunk_size * 16 + (ch - '0');
					break;
				}

				c = (u_char) (ch | 0x20);

				if (c >= 'a' && c <= 'f') {
					parse->chunk_size = parse->chunk_size* 16 + (c - 'a' + 10);
					break;
				}

				if (parse->chunk_size == 0) {

					switch (ch) {
					case '\r':
						parse->state = sw_last_chunk_extension_almost_done;
						break;
					case '\n':
						parse->state = sw_trailer;
						break;
					case ';':
					case ' ':
					case '\t':
						parse->state = sw_last_chunk_extension;
						break;
					default:
						return -1;
					}

					break;
				}
				switch (ch) {
				case '\r':
					parse->state = sw_chunk_extension_almost_done;
					break;
				case '\n':
					parse->state = sw_chunk_data;
					break;
				case ';':
				case ' ':
				case '\t':
					parse->state = sw_chunk_extension;
					break;
				default:
					return -1;
				}
			break;

			case sw_chunk_extension:
				switch (ch) {
				case '\r':
					parse->state = sw_chunk_extension_almost_done;
					break;
				case '\n':
					parse->state = sw_chunk_data;
					break;
				}
			break;

			case sw_chunk_extension_almost_done:
				if (ch == '\n') {
					parse->state = sw_chunk_data;
					break;
				}
				return -1;
			break;
			case sw_chunk_data:
				if ( parse->chunk_data_begin == NULL) {
					parse->chunk_data_begin = buf->cur_probe - 1;
				}
				else {
					int chunk_already = buf->cur_last - parse->chunk_data_begin;
					if ( chunk_already < parse->chunk_size) {
						buf->cur_probe = buf->cur_last;
					}
					else {
						buf->cur_probe = parse->chunk_data_begin + parse->chunk_size;

						parse->state = sw_after_data;

						if ( http->icontent_length == -1) {
							http->icontent_length = parse->chunk_size;
						}
						else {
							http->icontent_length += parse->chunk_size;
						}

						if ( http->ibody_app_whole) {
							navi_buf_chain_append(http->ibody_cache,parse->chunk_data_begin,
									parse->chunk_size);
						}
						else {
							if (http->ibody_handler) {
								http->ibody_handler( http->base.parent->parent, http,
									parse->chunk_data_begin, parse->chunk_size);
							}
						}

						nvup_inbuf_accept_unit(buf);
					}
				}
			break;
			case sw_after_data:
				switch (ch) {
				case '\r':
					parse->state = sw_after_data_almost_done;
					break;
				case '\n':
					parse->state = sw_chunk_start;
					break;
				default:
					return -1;
				}
			break;
			case sw_after_data_almost_done:
				if (ch == '\n') {
					parse->state = 0;
					parse->chunk_data_begin = NULL;
					parse->chunk_size = 0;
				}
				else
					return -1;
			break;
			case sw_last_chunk_extension:
				switch (ch) {
				case '\r':
					parse->state = sw_last_chunk_extension_almost_done;
					break;
				case '\n':
					parse->state = sw_trailer;
					break;
				}
			break;
			case sw_last_chunk_extension_almost_done:
				if (ch == '\n') {
					parse->state = sw_trailer;
					break;
				}
				else
					return -1;
			break;
			case sw_trailer:
				switch (ch) {
				case '\r':
					parse->state = sw_trailer_almost_done;
					break;
				case '\n':
					goto done;
				default:
					parse->state = sw_trailer_header;
					break;
				}
			break;
			case sw_trailer_almost_done:
				if ( ch == '\n') {
					goto done;
				}
				else
					return -1;
			break;
			case sw_trailer_header:
				switch (ch) {
				case '\r':
					parse->state = sw_trailer_header_almost_done;
					break;
				case '\n':
					parse->state = sw_trailer;
					break;
				}
			break;
			case sw_trailer_header_almost_done:
				if (ch == '\n') {
					parse->state = sw_trailer;
					break;
				}
				else
					return -1;
			break;
			default:
				assert(0);
				break;
			}

		}

		done:
		http->ibody_chunk_fin = 1;
		if (http->ibody_app_whole && http->ibody_handler) {
			http->ibody_whole= navi_pool_nalloc(http->base.private_pool,
				http->icontent_length + 1);
			navi_buf_chain_get_content(http->ibody_cache, http->ibody_whole,
				http->icontent_length);
			http->ibody_whole[http->icontent_length] = '\0';
			http->ibody_handler(http->base.parent->parent, http, http->ibody_whole,
				http->icontent_length);
		}
		nvup_inbuf_clean(buf);
		return 1;
	}

	nvup_inbuf_check(buf);
	return 0;
}

static void nvhttp_cleanup(void* sub)
{
	nvcli_http_t* http = (nvcli_http_t*)sub;
	nvup_inbuf_clean(&http->iheader_parse_buf);
	http->ibody_cache = NULL;
}

static nvcli_proto_proc_t http_proto = {
	NVCLI_HTTP,
	sizeof(nvcli_http_t),
	nvhttp_iheader_parse,
	nvhttp_ibody_parse,
	nvhttp_cleanup
};

static int nvhttp_output_goon(void* parent, void* cli)
{
	nvcli_http_t* http = (nvcli_http_t*)cli;
	if (http->obody_generator==NULL) {
		if ( http->has_obody && http->obody_chunked) {
			nvcli_send_body(&http->base, "0\r\n", 3, true);
		}
		return 1;
	}

	int ret = http->obody_generator(parent, cli);
	if ( ret == -1)
		return -1;

	if ( ret == 1) {
		if ( http->has_obody ){
			if (http->obody_chunked==0 ) {
				if (http->obody_have < http->obody_length)
					return -1;
			}
			else {
				nvcli_send_body(&http->base, "0\r\n", 3, true);
				return 1;
			}
		}
		else {
			return 1;
		}
	}
	else {
		if ( http->has_obody) {
			if ( http->obody_chunked==0) {
				if (http->obody_have == http->obody_length)
					return 1;
			}
			return 0;
		}
		else {
			return 1;
		}
	}
	return ret;
}

nvcli_http_t* nvcli_http_init(nvcli_parent_t* ctx,
	const struct sockaddr* peer_addr,
	const char* uri,
	nvcli_http_procs_t app_procs,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval)
{
	//char hoststr[20] = {0};
	nvhttp_reqbody_generator_fp obody_gen_tmp = app_procs.obody_goon_handler;
	app_procs.obody_goon_handler = (nvhttp_reqbody_generator_fp)nvhttp_output_goon;
	nvcli_http_t* obj = nvcli_init(ctx,&http_proto, (const navi_grcli_app_proc_t*)&app_procs, app_data, 
		conn_timeout, resp_max_waiting, input_max_interval, peer_addr);
	if (!obj)
		return NULL;

	memset(&obj->method, 0x00, sizeof(nvcli_http_t) - offsetof(nvcli_http_t, method));

	obj->uri = navi_pool_strdup(obj->base.private_pool, uri);
	obj->o_args = navi_hash_init(obj->base.private_pool);
	obj->o_headers = navi_hash_init(obj->base.private_pool);

	navi_hash_set(obj->o_headers, "Expect", "");
	//inet_ntop(AF_INET,(void *)peer_addr,hoststr,sizeof(hoststr));
	char hoststr[512] = {0};
	navi_addr_to_str(peer_addr, hoststr);
	navi_hash_set(obj->o_headers, "host", hoststr);//http 1.1 header需要host

	obj->obody_generator = obody_gen_tmp;
	obj->iheader_ready_handler = app_procs.iheader_process_handler;
	obj->ibody_handler = app_procs.ibody_process_handler;
	return obj;
}

int nvcli_http_set_reqheader(nvcli_http_t* session, const char* header, const char* v)
{
	if ( session->start )
		return -1;

	if ( !strcasecmp("Expect", header))
		return -1;

	if ( !strcasecmp("Transfer-Encoding", header))
		return -1;

	char* header_lc = navi_pool_strdup(session->base.private_pool, header);
	char* p = header_lc;
	while (*p) {
		if ( lowcase[*p] )
			*p = lowcase[*p];
		p++;
	}

	navi_hash_set(session->o_headers,header_lc,
		navi_pool_strdup(session->base.private_pool,v) );

	if ( strcmp("connection", header_lc)==0 && strcmp(v, "close")==0 ) {
		session->o_conn_close = 1;
	}

	return 0;
}

const char* nvcli_http_get_reqheader(nvcli_http_t* session, const char* header)
{
	char* header_lc = strdup(header);
	char* p = header_lc;
	while (*p) {
		if ( lowcase[*p] )
			*p = lowcase[*p];
		p++;
	}

	const char* ret = navi_hash_get(session->o_headers, header_lc);
	free(header_lc);
	return ret;
}

int nvcli_http_set_arg(nvcli_http_t* session, const char* arg, const char* v)
{
	navi_hash_set(session->o_args, navi_pool_strdup(session->base.private_pool,arg),
		navi_pool_strdup(session->base.private_pool,v));
	return 0;
}

const char* nvcli_http_get_arg(nvcli_http_t* session, const char* arg)
{
	return navi_hash_get(session->o_args, arg);
}

void nvcli_http_set_args(nvcli_http_t* session, navi_hash_t* args)
{
	void* it = navi_hash_iter(args);
	navi_hent_t* he ;
	while ( (he = navi_hash_iter_next(it))) {
		nvcli_http_set_arg(session, he->k, (char*)he->v);
	}
	navi_hash_iter_destroy(it);
}

int nvcli_http_append_reqbody(nvcli_http_t* session, const unsigned char* body, size_t size)
{
	if (!body || size == 0) {
		return -1;
	}

	if (session->start) {
		if ( !session->has_obody )
			return -1;

		if ( !session->ibody_chunked ) {
			if ( session->obody_have == session->obody_length )
				return -1;
			else {
				size_t should_send = size >= (session->obody_length - session->obody_have) ?
					(session->obody_length - session->obody_have) : size;
				session->obody_have += should_send;
				if ( session->obody_have == session->obody_length)
					nvcli_send_body(&session->base, body, should_send, true);
				else
					nvcli_send_body(&session->base, body, should_send, false);

				return 0;
			}
		}
		else {
			char chunk_header[256];
			off_t off = snprintf(chunk_header,sizeof(chunk_header), "%X\r\n", size);
			nvcli_send_body(&session->base, chunk_header, off, false);
			nvcli_send_body(&session->base, body, size, false);
			nvcli_send_body(&session->base, "\r\n", 2, false);
		}
	}
	else {
		//没有启动时，先将内容缓存。
		session->has_obody = 1;
		session->obody_have = size;
		nvcli_prepare_body(&session->base, body, size);
	}

	return 0;
}

int nvcli_http_append_reqbody_filepart(nvcli_http_t* session, int fd, off_t foff, size_t size)
{
	if (fd ==-1 || size == 0) {
		return -1;
	}

	if (session->start) {
		if ( !session->has_obody )
			return -1;

		if ( !session->ibody_chunked ) {
			if ( session->obody_have == session->obody_length )
				return -1;
			else {
				size_t should_send = size >= (session->obody_length - session->obody_have) ?
					(session->obody_length - session->obody_have) : size;
				session->obody_have += should_send;
				if ( session->obody_have == session->obody_length)
					nvcli_sendfile(&session->base, fd, foff, size, true);
					//nvcli_send_body(&session->base, body, should_send, true);
				else
					//nvcli_send_body(&session->base, body, should_send, false);
					nvcli_sendfile(&session->base, fd, foff, size, false);

				return 0;
			}
		}
		else {
			char chunk_header[256];
			off_t off = snprintf(chunk_header,sizeof(chunk_header), "%X\r\n", size);
			nvcli_send_body(&session->base, chunk_header, off, false);
			//nvcli_send_body(&session->base, body, size, false);
			nvcli_sendfile(&session->base, fd, foff, size, false);
			nvcli_send_body(&session->base, "\r\n", 2, false);
		}
	}
	else {
		//没有启动时，先将内容缓存。
		session->has_obody = 1;
		session->obody_have = size;
		//nvcli_prepare_body(&session->base, body, size);
		nvcli_prepare_file_body(&session->base, fd, foff, size);
	}

	return 0;
}

void nvcli_http_set_reqbody_process(nvcli_http_t* ss, int content_length,
	nvhttp_reqbody_generator_fp body_handler)
{
	if ( ss->start)
		return;

	if ( content_length == 0){
		if ( !ss->has_obody ) {
			ss->obody_generator = NULL;
			nvcli_http_set_reqheader(ss, "content-length", "0");
		}
		else {
			ss->obody_length = ss->obody_have;
			char buf[20];
			snprintf(buf,sizeof(buf),"%d", ss->obody_have);
			nvcli_http_set_reqheader(ss, "content-length", buf);
		}
	}
	else if (content_length== -1) {
		ss->has_obody = 1;
		ss->obody_chunked = 1;
		if (body_handler)
			ss->obody_generator = body_handler;

		nvcli_http_set_reqheader(ss, "Transfer-encoding", "chunked");

		if ( navi_buf_chain_get_content(ss->base.conn->out_buf,NULL,0)) {
			char buf[128];
			snprintf(buf,sizeof(buf),"%X\r\n",ss->obody_have);
			navi_buf_chain_insert_head(ss->base.conn->out_buf, buf, strlen(buf));
			navi_buf_chain_append(ss->base.conn->out_buf,"\r\n", 2);
		}
	}
	else {
		int pre_size = navi_buf_chain_get_content(ss->base.conn->out_buf,NULL,0);
		if (pre_size > content_length) {
			content_length = pre_size;
		}

		ss->obody_length = content_length;
		char buf[20];
		snprintf(buf,sizeof(buf),"%d", ss->obody_length);
		nvcli_http_set_reqheader(ss, "content-length", buf);

		if (body_handler)
			ss->obody_generator = body_handler;
	}
}

void nvcli_http_set_error_process(nvcli_http_t* ss, nvhttp_error_handler_fp error_handler)
{
	nvcli_set_error_handler(&ss->base,(nvcli_error_fp)error_handler );
}

static int nvhttp_packet_header(nvcli_http_t* ss, char* buf)
{
	off_t off = 0;

	switch(ss->method) {
	case NV_HTTP_GET:
		if ( buf )
			off += sprintf( buf + off, "GET ");
		else
			off += 4;
		break;
	case NV_HTTP_HEAD:
		if ( buf )
			off += sprintf( buf + off, "HEAD ");
		else
			off += 5;
		break;
	case NV_HTTP_POST:
		if ( buf )
			off += sprintf( buf + off, "POST ");
		else
			off += 5;
		break;
	case NV_HTTP_PUT:
		if ( buf )
			off += sprintf( buf + off, "PUT ");
		else
			off += 4;
		break;
	case NV_HTTP_DELETE:
		if ( buf )
			off += sprintf( buf + off, "DELETE ");
		else
			off += 7;
		break;
	default:
		assert(0);
		break;
	}

	navi_hent_t* hent;
	if ( buf ) {
		off += navi_escape_uri(buf + off, (u_char*)ss->uri, 0);

		void* it = navi_hash_iter(ss->o_args);
		int i=0;
		while ( hent = navi_hash_iter_next(it) ) {
			if ( i++==0 )
				*(buf+off) = '?';
			else
				*(buf+off) = '&';
			off ++;
			off += navi_escape_uri(buf + off, (u_char*)hent->k, 2);
			*(buf+off)='=';
			off ++;
			off += navi_escape_uri(buf + off, (u_char*)hent->v, 2);
		}
		navi_hash_iter_destroy(it);
	}
	else {
		off += navi_escape_uri(NULL,(u_char*)ss->uri,0);
		void* it = navi_hash_iter(ss->o_args);
		while ( hent = navi_hash_iter_next(it) ) {
			off += navi_escape_uri(NULL, (u_char*)hent->k, 2);
			off += navi_escape_uri(NULL, (u_char*)hent->v, 2);
			off += 2;
		}
		navi_hash_iter_destroy(it);
	}

	if ( buf ) {
		off += sprintf( buf+off, " HTTP/1.1\r\n");
	}
	else {
		off += strlen(" HTTP/1.1\r\n");
	}

	void* it = navi_hash_iter(ss->o_headers);
	while ( hent = navi_hash_iter_next(it) ) {
		if ( buf ) {
			off += sprintf(buf+off, "%s: %s\r\n", hent->k, (const char*)hent->v);
		}
		else {
			off += 4 + strlen(hent->k) + strlen((const char*)hent->v);
		}
	}
	navi_hash_iter_destroy(it);

	if ( buf ) {
		off += sprintf( buf+off, "\r\n");
	}
	else
		off += 2;

	return off;
}

int nvcli_http_start(nvcli_http_t* session, nvcli_http_method method)
{
	if ( session->has_obody) {
		if (method==NV_HTTP_GET || method==NV_HTTP_HEAD) {
			session->method = NV_HTTP_POST;
		}
		else
			session->method = method;
	}

	char tmp[1024];
	char* ptmp = tmp;
	int header_sz = nvhttp_packet_header(session, NULL);
	if ( header_sz >= sizeof(tmp) ) {
		ptmp = (char*)malloc(header_sz + 1);
	}

	nvhttp_packet_header(session, ptmp);
	session->start = 1;
	bool start_wait_resp = false;

	if ( !session->has_obody ) {
		start_wait_resp = true;
	}
	else {
		if ( !session->obody_chunked) {
			if (session->obody_have == session->obody_length) {
				start_wait_resp = true;
			}
		}
	}

	nvcli_send_header(&session->base, ptmp, header_sz, start_wait_resp);
	if ( session->o_conn_close) {
		nvacnn_set_short(session->base.conn, true);
	}

	return 0;
}


int nvcli_http_start_formdata(nvcli_http_t* session, navi_formdata_t* form)
{
	session->method = NV_HTTP_POST;

	char tmp[1024];

	snprintf(tmp,sizeof(tmp),"multipart/form-data; boundary=%s",
		form->boundary);

	navi_buf_chain_t* out_chain = navi_formdata_get_body(form);

	nvcli_http_set_reqheader(session, "Content-type", tmp);

	sprintf(tmp, "%d", form->out_chain->sum);
	nvcli_http_set_reqheader(session, "content-length", tmp);

	char* ptmp = tmp;
	int header_sz = nvhttp_packet_header(session, NULL);
	if ( header_sz >= sizeof(tmp) ) {
		ptmp = (char*)malloc(header_sz + 1);
	}

	nvhttp_packet_header(session, ptmp);

	navi_buf_node_t* buf_node = form->out_chain->head;

	while(buf_node) {

		if (!buf_node->infile) {
			nvcli_prepare_body(&session->base, buf_node->buf, buf_node->size);
		}
		else {
			nvcli_prepare_file_body(&session->base, buf_node->fd, buf_node->filepos, buf_node->size);
		}

		buf_node = buf_node->next;
	}


	session->start = 1;
	nvcli_send_header(&session->base, ptmp, header_sz, true);

	if ( session->o_conn_close) {
		nvacnn_set_short(session->base.conn, true);
	}

	return 0;
}

void nvcli_http_set_resp_process(nvcli_http_t* ss, nvhttp_resp_start_fp resp_handler )
{
	if ( ss->base.iheader_done ) {
		return;
	}
	ss->iheader_ready_handler = resp_handler;
}

void nvcli_http_set_respbody_process(nvcli_http_t* ss, nvhttp_respbody_handler_fp ibody_handler,
	bool proc_slice)
{
	if (!ss->start) {
		if (!proc_slice)
			ss->ibody_app_whole = 1;
	}
	else if (ss->ibody_app_whole && proc_slice) {
		return;
	}
	else if (!ss->ibody_app_whole && !proc_slice)
		return;

	if ( !proc_slice && ss->ibody_cache == NULL) {
		ss->ibody_cache = navi_buf_chain_init(ss->base.private_pool);
	}
	ss->ibody_handler = ibody_handler;
}

int nvcli_http_get_respstatus(nvcli_http_t* ss, const char** status_desc)
{
	if ( !ss->base.iheader_done )
		return -1;
	if (status_desc)
		*status_desc = ss->i_status_desc;
	return ss->i_status;
}

const char* nvcli_http_get_respheader(nvcli_http_t* ss, const char* header)
{
    if ( !ss->base.iheader_done )
        return NULL;

    if ( !ss->i_headers ) {
        return NULL;
    }

	char* header_lc = strdup(header);
	char* p = header_lc;
	while (*p) {
		if ( lowcase[*p] )
			*p = lowcase[*p];
		p++;
	}

	const char* ret = navi_hash_get(ss->i_headers, header_lc);
	free(header_lc);
	return ret;
}

int64_t nvcli_http_get_respbody_length(nvcli_http_t* ss)
{
	if ( !ss->base.iheader_done )
		return -2;

	if ( ss->ibody_chunked ) {
		if (ss->ibody_chunk_fin == 0)
			return -1;
	}

	return ss->icontent_length;
}

int nvcli_http_get_respbody(nvcli_http_t* ss, unsigned char** body)
{
	if ( !ss->base.iheader_done )
		return -2;

	if ( ss->ibody_chunked ) {
		if (ss->ibody_chunk_fin == 0)
			return -1;
	}

	if (!body) return ss->icontent_length;
	*body = NULL;
	if (!ss->ibody_app_whole) return ss->icontent_length;

	if (!ss->ibody_whole) {
		ss->ibody_whole= navi_pool_nalloc(ss->base.private_pool,
			ss->icontent_length + 1);
		navi_buf_chain_get_content(ss->ibody_cache, ss->ibody_whole,
			ss->icontent_length);
		ss->ibody_whole[ss->icontent_length] = '\0';
	}

	*body = ss->ibody_whole;
	return ss->icontent_length;
}
