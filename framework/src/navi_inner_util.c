/*
 * navi_inner_util.c
 *
 *  Created on: 2013-9-23
 *      Author: li.lei
 */

#include "navi_inner_util.h"
#include "navi_frame_log.h"
#include <netdb.h>

uint64_t cur_time_us()
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t) tv.tv_sec * 1000000 + tv.tv_usec;
}

size_t navi_rpath_2abs(const char* path, char *abs, size_t abs_sz)
{
	char* p;
	size_t left=1025;
	char tmp_path[1025];
	if (!path || strlen(path)==0)
		return 0;

	p = tmp_path;
	if ( path[0] != '/' ) {
		getcwd(tmp_path,sizeof(tmp_path));
		p += strlen(tmp_path);
		left -= strlen(tmp_path);
		if (left<1)
			return 0;

		if ( *(p-1) == '/' ) {
			p--;
			left++;
			*p = 0;
		}
	}
	else {
		*p++ = '/';
		left--;
	}

	char* dup = strdup(path);
	char* tk,*tk_ctx;
	tk = strtok_r(dup,"/",&tk_ctx);
	for (; tk ; tk=strtok_r(NULL,"/",&tk_ctx) ) {
		if ( strcmp(tk,".") == 0 )
			continue;
		else if ( strcmp(tk,"..") == 0 ) {
			char * r = p - 1;
			while( r!=tmp_path && *r != '/' ) {
				left++;
				r--;
			}

			p = r+1;
		}
		else {
			if ( p-1 != tmp_path && *(p-1)!='/' ) {
				*p++ = '/';
				left--;
			}

			if (left<1 || left < strlen(tk)+1 ) {
				free(dup);
				return 0;
			}

			memcpy(p, tk, strlen(tk));
			p += strlen(tk);
			left -= strlen(tk);
		}
	}

	*p = 0;
	free(dup);

	if (abs == NULL || abs_sz==0) {
		return p - tmp_path;
	}
	else
	{
		memcpy(abs, tmp_path, abs_sz);
		abs[abs_sz-1] = 0;
		return p - tmp_path;
	}
}

size_t navi_escape_uri(u_char* dst, u_char* src, uint8_t type)
{
	size_t len = 0;
	uint32_t *escape;
	static u_char hex[] = "0123456789abcdef";

	/* " ", "#", "%", "?", %00-%1F, %7F-%FF */

	static uint32_t uri[] =
	{ 0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

	/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
	0x80000029, /* 1000 0000 0000 0000  0000 0000 0010 1001 */

	/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
	0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

	/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
	0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	};

	/* " ", "#", "%", "&", "+", "?", %00-%1F, %7F-%FF */

	static uint32_t args[] =
	{ 0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

	/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
	0x88000869, /* 1000 1000 0000 0000  0000 1000 0110 1001 */

	/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
	0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

	/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
	0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	};

	/* not ALPHA, DIGIT, "-", ".", "_", "~" */

	static uint32_t uri_component[] =
	{ 0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

	/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
	0xfc009fff, /* 1111 1100 0000 0000  1001 1111 1111 1111 */

	/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
	0x78000001, /* 0111 1000 0000 0000  0000 0000 0000 0001 */

	/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
	0xb8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */

	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	};

	/* " ", "#", """, "%", "'", %00-%1F, %7F-%FF */

	static uint32_t html[] =
	{ 0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

	/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
	0x000000ad, /* 0000 0000 0000 0000  0000 0000 1010 1101 */

	/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
	0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

	/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
	0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	};

	/* " ", """, "%", "'", %00-%1F, %7F-%FF */

	static uint32_t refresh[] =
	{ 0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

	/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
	0x00000085, /* 0000 0000 0000 0000  0000 0000 1000 0101 */

	/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
	0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

	/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
	0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	0xffffffff /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	};

	/* " ", "%", %00-%1F */

	static uint32_t memcached[] =
	{ 0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

	/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
	0x00000021, /* 0000 0000 0000 0000  0000 0000 0010 0001 */

	/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
	0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

	/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
	0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

	0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
	0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
	0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
	0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
	};

	/* mail_auth is the same as memcached */

	static uint32_t *map[] =
	{ uri, args, uri_component, html, refresh, memcached, memcached };

	escape = map[type];

	if (dst == NULL) {
		/* find the number of the characters to be escaped */
		while (*src != '\0') {
			if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
				len += 2;
			}
			src++;
			len++;
		}
		return len;
	}

	while (*src != '\0') {
		if (escape[*src >> 5] & (1 << (*src & 0x1f))) {
			*dst++ = '%';
			*dst++ = hex[*src >> 4];
			*dst++ = hex[*src & 0xf];
			src++;
			len += 3;
		}
		else {
			*dst++ = *src++;
			len++;
		}
	}
	*dst = '\0';
	return len;
}

void navi_unescape_uri(u_char *dst, size_t size, uint8_t type)
{
	u_char *d, *s, ch, c, decoded;
	enum
	{
		sw_usual = 0,
		sw_quoted,
		sw_quoted_second
	} state;

	d = dst;
	s = dst;

	state = 0;
	decoded = 0;

	while (size--) {

		ch = *s++;

		switch (state)
		{
		case sw_usual:
			if (ch == '?'
			    && (type & (NAVI_UNESCAPE_URI | NAVI_UNESCAPE_REDIRECT))) {
				*d++ = ch;
				goto done;
			}

			if (ch == '%') {
				state = sw_quoted;
				break;
			}

			if(ch=='+')
				*d++ = ' ';
			else
				*d++ = ch;
			break;

		case sw_quoted:

			if (ch >= '0' && ch <= '9') {
				decoded = (u_char) (ch - '0');
				state = sw_quoted_second;
				break;
			}

			c = (u_char) (ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				decoded = (u_char) (c - 'a' + 10);
				state = sw_quoted_second;
				break;
			}

			/* the invalid quoted character */

			state = sw_usual;
			*d++ = '%';
			*d++ = ch;

			break;

		case sw_quoted_second:

			state = sw_usual;

			if (ch >= '0' && ch <= '9') {
				ch = (u_char) ((decoded << 4) + ch - '0');

				if (type & NAVI_UNESCAPE_REDIRECT) {
					if (ch > '%' && ch < 0x7f) {
						*d++ = ch;
						break;
					}

					*d++ = '%';
					*d++ = *(s - 2);
					*d++ = *(s - 1);

					break;
				}

				*d++ = ch;

				break;
			}

			c = (u_char) (ch | 0x20);
			if (c >= 'a' && c <= 'f') {
				ch = (u_char) ((decoded << 4) + c - 'a' + 10);

				if (type & NAVI_UNESCAPE_URI) {
					if (ch == '?') {
						*d++ = ch;
						goto done;
					}

					*d++ = ch;
					break;
				}

				if (type & NAVI_UNESCAPE_REDIRECT) {
					if (ch == '?') {
						*d++ = ch;
						goto done;
					}

					if (ch > '%' && ch < 0x7f) {
						*d++ = ch;
						break;
					}

					*d++ = '%';
					*d++ = *(s - 2);
					*d++ = *(s - 1);
					break;
				}

				*d++ = ch;

				break;
			}

			/* the invalid quoted character */
			*d++ = '%';
			*d++ = *(s-2);
			*d++ = ch;
			break;
		}
	}

	if (state == sw_quoted)
		*d++ = '%';
	else if (state == sw_quoted_second) {
		*d++ = '%';
		*d++ = *(s-1);
	}

done:
	*d = '\0';
	return;
}

size_t encode_base64(uint8_t *dst, const uint8_t *src, size_t src_sz) {
	uint8_t *d;
	const uint8_t *s;
	size_t len;
	static u_char basis64[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	len = src_sz;
	s = src;
	d = dst;

	while (len > 2) {
		*d++ = basis64[(s[0] >> 2) & 0x3f];
		*d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
		*d++ = basis64[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
		*d++ = basis64[s[2] & 0x3f];

		s += 3;
		len -= 3;
	}

	if (len) {
		*d++ = basis64[(s[0] >> 2) & 0x3f];

		if (len == 1) {
			*d++ = basis64[(s[0] & 3) << 4];
			*d++ = '=';

		}
		else {
			*d++ = basis64[((s[0] & 3) << 4) | (s[1] >> 4)];
			*d++ = basis64[(s[1] & 0x0f) << 2];
		}

		*d++ = '=';
	}

	*d = 0;
	return d - dst;
}

char* navi_build_query(navi_pool_t* pool, navi_hash_t* args)
{
	size_t query_sz = 0;
	void* it = navi_hash_iter(args);
	navi_hent_t* hent = NULL;
	while ( (hent = navi_hash_iter_next(it))) {
		query_sz += navi_escape_uri(NULL, hent->k, NAVI_ESCAPE_ARGS);
		query_sz += navi_escape_uri(NULL, (char*)hent->v, NAVI_ESCAPE_ARGS);
	}
	navi_hash_iter_destroy(it);

	query_sz += args->used * 2 ;

	char* ret = navi_pool_alloc(pool, query_sz);
	char* p = ret;
	it = navi_hash_iter(args);
	while ( (hent = navi_hash_iter_next(it))) {
		if ( p != ret ) {
			*(p++) = '&';
		}
		p += navi_escape_uri(p, hent->k, NAVI_ESCAPE_ARGS);
		*(p++) = '=';
		p += navi_escape_uri(p, (char*)hent->v, NAVI_ESCAPE_ARGS);
	}
	navi_hash_iter_destroy(it);

	*p = 0;
	return ret;
}

navi_hash_t* navi_parse_query(navi_pool_t* pool, const char* args)
{
	navi_hash_t* ret = NULL;
	char* p_pair, *ctx_pair, *p_key, *p_value, *ctx;
	uint32_t cnt = 0;
	char buf[1024];
	char* tmp = buf;
	int len = strlen(args);

	if (len > 1023) {
		tmp = (char*) malloc(len + 1);
		assert(tmp);
	}

	strcpy(tmp, args);
	p_pair = strtok_r(tmp, "&", &ctx_pair);
	while (p_pair) {
		p_key = strtok_r(p_pair, "=", &ctx);
		p_value = strtok_r(NULL, "=", &ctx);
		if (!p_key) {
			if (tmp != buf)
				free(tmp);
			return NULL;
		}

		navi_unescape_uri((u_char*) p_key, strlen(p_key), 0);
		if(p_value)
			navi_unescape_uri((u_char*) p_value, strlen(p_value), 0);

		if ( ret == NULL ) {
			ret = navi_hash_init(pool);
		}
		navi_hash_set(ret, p_key, p_value);
		p_pair = strtok_r(NULL, "&", &ctx_pair);
	};

	if (tmp != buf)
		free(tmp);

	return ret;
}

char* navi_build_uri(uint32_t comp_count, .../*各uri分量，必须是字符串参数*/)
{
	uint32_t i;
	va_list vl;
	const char* part = NULL;
	const char* pp, *pt;

	char* ret = (char*) malloc(1024);
	size_t cur_sz = 1023, comp_sz = 0;
	char* pr = ret;
	bool only_root = false;

	va_start(vl, comp_count);
	for ( i=0; i<comp_count; i++ ) {
		part = va_arg(vl, const char*);
		if ( part==NULL || strlen(part)==0 )
			continue;

		pp = part;
		pt = part + strlen(part) - 1;

		while ( *pp == '/' && pp != pt)
			pp++;

		while ( *pt == '/' && pt != pp)
			pt--;

		comp_sz = pt - pp + 1;

		if ( comp_sz == 1 && *pp == '/' ) {
			if ( i==0 ) {
				*pr++ = '/';
				cur_sz--;
				only_root = true;
				continue;
			}
			else
				continue;
		}
		else {
			if (!only_root)
				comp_sz += 1;
			if ( cur_sz < comp_sz ) {
				char* n = (char*) realloc (ret, pr - ret + comp_sz + 256);
				pr = n + (pr - ret);
				ret = n;
				cur_sz = comp_sz + 255;
			}

			if (only_root) {
				memcpy( pr, pp, comp_sz);
				only_root = false;
			}
			else {
				memcpy( pr+1, pp, comp_sz-1);
				*pr = '/';
			}
			cur_sz -= comp_sz;
			pr += comp_sz;
		}
	}
	va_end(vl);
	*pr = 0;
	return ret;
}

bool navi_is_symbol_word(const char* word)
{
	if(!word) return false;
	while(*word && (isdigit(*word) || isupper(*word) || islower(*word) || *word=='_')) {
		word++;
		continue;
	}

	if (*word) return false;
	return true;
}

void navi_addr_to_str(const struct sockaddr* peer, char* addr_str)
{
	switch( peer->sa_family) {
	case AF_INET: {
		const struct sockaddr_in* in = (const struct sockaddr_in*)peer;
		inet_ntop(AF_INET, (const void*)&(in->sin_addr), addr_str, 256);
		char buf[10];
		sprintf(buf,":%u", ntohs(in->sin_port));
		strcat(addr_str,buf);
		break;
	}
	case AF_INET6: {
		const struct sockaddr_in6* in6 = (const struct sockaddr_in6*)peer;
		inet_ntop(AF_INET6, (const void*)&(in6->sin6_addr), addr_str, 256);
		char buf[10];
		sprintf(buf,":%u", ntohs(in6->sin6_port));
		strcat(addr_str,buf);
		break;
	}
	case AF_UNIX:{
		const struct sockaddr_un* un = (const struct sockaddr_un*)peer;
		sprintf(addr_str, "UNIX:%s", un->sun_path);
		break;
	}
	}
}


static in_addr_t
my_inet_addr(u_char *text, size_t len)
{
    u_char      *p, c;
    in_addr_t    addr;
    uint32_t   octet, n;

    addr = 0;
    octet = 0;
    n = 0;

    for (p = text; p < text + len; p++) {

        c = *p;

        if (c >= '0' && c <= '9') {
            octet = octet * 10 + (c - '0');
            continue;
        }

        if (c == '.' && octet < 256) {
            addr = (addr << 8) + octet;
            octet = 0;
            n++;
            continue;
        }

        return INADDR_NONE;
    }

    if (n == 3 && octet < 256) {
        addr = (addr << 8) + octet;
        return htonl(addr);
    }

    return INADDR_NONE;
}

int navi_parse_url(const char* url, navi_url_parse_t* result)
{
	if (!url||!strlen(url)) return -1;
	if (result)
		memset(result, 0x00, offsetof(navi_url_parse_t,pool));

	enum {
		scheme_invalid,
		scheme_http,
		scheme_redis,
		scheme_rtmp
	};

	int scheme_type = scheme_http;

	off_t skip = 0;
	if ( 0 == strncasecmp(url,"http://", 7) ) {
		result->scheme = "http://";
		skip = strlen("http://");
		scheme_type = scheme_http;
	}
	else if ( 0 == strncasecmp(url, "redis://", 8)) {
		result->scheme = "redis://";
		skip = strlen("redis://");
		scheme_type = scheme_redis;
	}
	else if ( 0 == strncasecmp(url, "rtmp://", 7)) {
		result->scheme = "rtmp://";
		skip = strlen("rtmp://");
		scheme_type = scheme_rtmp;
	}

	enum {
		sw_host,
		sw_port_deli,
		sw_port,
		sw_uri_begin,
		sw_uri,
		sw_arg_begin,
		sw_arg,
		sw_end
	};

	int parse_status = sw_host;
	char *p = (char*)url + skip;

	char* p_host = p;
	char* p_port = NULL;
	char* p_uri = NULL;
	char* p_arg = NULL;
	int host_len = 0;
	int port_len = 0;
	int uri_len = 0;
	int arg_len = 0;
	char c;
	if (*p_host == 0)
		goto err;

	while(true) {
		c = *p;
		switch(parse_status) {
		case sw_host:
			if ( ( c >= 'a' && c <= 'z') || ( c >= 'A' && c <= 'Z')
				|| ( c >= '0' && c <= '9')
				||  ( c == '.') || (c == '-') ) {
				p++;
				continue;
			}
			else if ( c == ':' ) {
				parse_status = sw_port_deli;
				host_len = p - p_host;
			}
			else if ( c == '/' ) {
				parse_status = sw_uri_begin;
				p_uri = p;
				host_len = p - p_host;
			}
			else if ( c == '?' ) {
				parse_status = sw_arg_begin;
				host_len = p - p_host;
			}
			else if ( c == '\0') {
				parse_status = sw_end;
				host_len = p - p_host;
				goto done;
			}
			break;
		case sw_port_deli:
			if ( c >= '0' && c <= '9' ) {
				p_port = p;
				parse_status = sw_port;
			}
			else {
				goto err;
			}
			break;
		case sw_port:
			if ( c >= '0' && c <= '9' ) {
				p++;
				continue;
			}
			else if ( c == '/' ) {
				parse_status = sw_uri_begin;
				p_uri = p;
				port_len = p - p_port;
			}
			else if ( c == '?' ) {
				parse_status = sw_arg_begin;
				port_len = p - p_port;
			}
			else if ( c == '\0' ) {
				parse_status = sw_end;
				port_len = p - p_port;
				goto done;
			}
			else {
				goto err;
			}
			break;
		case sw_uri_begin:
			if ( c == '/') {
				p_uri = p;
			}
			else if ( c == '?' ) {
				parse_status = sw_arg_begin;
				uri_len = p - p_uri;
			}
			else if ( c == '\0' ) {
				parse_status = sw_end;
				uri_len = p - p_uri;
				goto done;
			}
			else {
				parse_status = sw_uri;
			}
			break;
		case sw_uri:
			if ( c == '?' ) {
				parse_status = sw_arg_begin;
				uri_len = p - p_uri;
			}
			else if ( c == '\0' ) {
				parse_status = sw_end;
				uri_len = p - p_uri;
				goto done;
			}
			else {
				p++;
				continue;
			}
			break;
		case sw_arg_begin:
			if ( c == '\0' ) {
				parse_status = sw_end;
				goto done;
			}
			else {
				p_arg = p;
				parse_status = sw_arg;
			}
			break;
		case sw_arg:
			if ( c == '\0' ) {
				parse_status = sw_end;
				arg_len = p - p_arg;
				goto done;
			}
			else {
				p++;
				continue;
			}
			break;
		default:
			break;
		}
		p++;
	}

done:
	if (!result && host_len) {
		return 0;
	}

	result->orig_text = navi_pool_strdup(result->pool, url);

	if (host_len==0)
		return -1;

	result->host_text = navi_pool_alloc(result->pool,host_len+1);
	memcpy(result->host_text,p_host,host_len);
	result->host_text[host_len] = 0;

	if (port_len) {
		result->port_text = navi_pool_alloc(result->pool,port_len+1);
		memcpy(result->port_text,p_port,port_len);
		result->port_text[port_len] = 0;
	}

	if ( uri_len ) {
		result->uri = navi_pool_alloc(result->pool,uri_len+1);
		memcpy(result->uri,p_uri,uri_len);
		result->uri[uri_len] = 0;
	}
	else {
		result->uri = "/";
	}

	if ( arg_len ) {
		result->query_args = navi_pool_alloc(result->pool,arg_len+1);
		memcpy(result->query_args,p_arg,arg_len);
		result->query_args[arg_len] = 0;
	}

	if ( port_len) {
		int iport = atoi(result->port_text);
		if (iport >= 65536 || iport == 0) {
			return -1;
		}
		result->port = (uint16_t)iport;
	}
	else {
		switch (scheme_type) {
		case scheme_http:
			result->port = 80;
			break;
		case scheme_redis:
			result->port = 6379;
			break;
		case scheme_rtmp:
			result->port = 1935;
			break;
		default:
			result->port = 0;
			break;
		}
	}

	result->addr.sin_family = AF_INET;
	result->addr.sin_port = htons(result->port);
	result->addr.sin_addr.s_addr = my_inet_addr(result->host_text,host_len);
	if (result->addr.sin_addr.s_addr != INADDR_NONE) {
		return 0;
	}
	else {
		struct hostent *h = gethostbyname(result->host_text);
		if (h == NULL || h->h_addr_list[0] == NULL) {
			result->addr.sin_addr.s_addr = INADDR_NONE;
			return -1;
		}

		if (h->h_addrtype != AF_INET) {
			result->addr.sin_addr.s_addr = INADDR_NONE;
			return -1;
		}

		int i;
		for (i=0; h->h_addr_list[i] != NULL; i++);

		result->resolve_hosts = (struct sockaddr_in*)navi_pool_calloc(result->pool,
			i, sizeof(struct sockaddr_in));
		struct sockaddr_in* p_resolve = result->resolve_hosts;
		for (i=0; h->h_addr_list[i] != NULL; i++) {
			p_resolve->sin_port = htons(result->port);
			p_resolve->sin_addr.s_addr =  *(in_addr_t *) (h->h_addr_list[i]);
			p_resolve->sin_family = AF_INET;
			p_resolve++;
		}

		result->resolve_size = p_resolve - result->resolve_hosts;
		if (result->resolve_size == 0 ) {
			result->addr.sin_addr.s_addr = INADDR_NONE;
			return -1;
		}
		else {
			result->addr.sin_addr.s_addr = result->resolve_hosts[0].sin_addr.s_addr;
		}

		return 0;
	}
err:
	return -1;
}

bool navi_check_dir_path(const char* path, mode_t mod, int check_access)
{
	char check_tmp[1024];
	char* e = check_tmp + snprintf(check_tmp,sizeof(check_tmp),"%s", path);
	char* p = check_tmp+1;
	char b;
	int invalid_pos = 1;
	char* pre_exist = check_tmp;

	for (; p < e ; ) {

		if ( *p != '/') {
			p++;
			if ( p != e)
				continue;
		}
		b = *p;
		*p = 0;

		struct stat stbuf;
		bool exist = false;
		int ret = stat(check_tmp, &stbuf);
		if ( ret == 0 ) {
			if (!S_ISDIR(stbuf.st_mode)) {
				return false;
			}
			pre_exist = p;
			*(p++) = b;
			invalid_pos = p - check_tmp;
		}
		else {
			char bp = *pre_exist;
			*pre_exist = 0;

			if ( access(check_tmp, R_OK|W_OK|X_OK) )
				return false;

			*pre_exist = bp;
			*p = b;

			if ( 0 == navi_create_dir(check_tmp, invalid_pos, mod) )
				return true;
			else
				return false;
		}
	}

	if (check_access) {
		int check_bits = check_access & (R_OK|W_OK|X_OK);
		if (access(path, check_bits))
			return false;
		else
			return true;
	}
	return true;
}

int navi_create_dir(const char* path, int start_try, mode_t mod)
{
	char tmp_path[1024];
	if (path[0] != '/')
		return -2;
	char* e = tmp_path + snprintf(tmp_path, sizeof(tmp_path), "%s", path);
	if ( start_try <= 0 || start_try >= e - tmp_path)
		start_try = e - tmp_path - 1;

	char* p = tmp_path + start_try;
	char b;
	for (; p < e; ) {

		if ( *p != '/' ) {
			p++;
			if (p != e)
				continue;
		}

		b = *p;
		*p = 0;
		int ret = mkdir(tmp_path, mod);
		if ( ret == -1) {
			if ( errno == EEXIST) {
				struct stat stbuf;
				if ( 0 == stat(tmp_path, &stbuf)) {
					if ( S_ISDIR(stbuf.st_mode)) {
						if ( access(tmp_path, R_OK|W_OK|X_OK)) {
							NAVI_FRAME_LOG_FL(NAVI_LOG_ERR,"create dir failed for:%s which permission is limited",
								tmp_path);
							return -1;
						}
						*(p++) = b;
						continue;
					}
					else {
						NAVI_FRAME_LOG_FL(NAVI_LOG_ERR,"create dir failed for:%s which not directory",
							tmp_path);
						return -1;
					}
				}
				else {
					NAVI_FRAME_LOG_FL(NAVI_LOG_ERR,"create dir failed for:%s %d %s",
						tmp_path, errno, strerror(errno));
					return -1;
				}
			}
			else if (errno == ENOENT) {
				if ( start_try == 1) {
					assert(0);
				}
				else  {
					*p = b;
					p = tmp_path + 1;
					continue;
				}
			}
			else {
				NAVI_FRAME_LOG_FL(NAVI_LOG_ERR,"create dir failed for:%s %d %s",
					tmp_path, errno, strerror(errno));
				return -1;
			}
		}
		else {
			assert(ret==0);
			*(p++) = b;
			continue;
		}
	}

	return 0;
}

static const char* http_status_lines[] =
    {
        ("200 OK"),
        ("201 Created"),
        ("202 Accepted"),
        NULL, /* "203 Non-Authoritative Information" */
        ("204 No Content"),
        NULL, /* "205 Reset Content" */
        ("206 Partial Content"),

        /* NULL, *//* "207 Multi-Status" */

#define NGX_HTTP_LAST_LEVEL_200  207
#define NGX_HTTP_LEVEL_200       (NGX_HTTP_LAST_LEVEL_200 - 200)

        NULL,  /*"300 Multiple Choices" */

        ("301 Moved Permanently"),
        ("302 Moved Temporarily"),
        ("303 See Other"),
        ("304 Not Modified"),

        /* NULL, *//* "305 Use Proxy" */
        /* NULL, *//* "306 unused" */
        /* NULL, *//* "307 Temporary Redirect" */

#define NGX_HTTP_LAST_LEVEL_300  305
#define NGX_HTTP_LEVEL_300       (NGX_HTTP_LAST_LEVEL_300 - 300)

        ("400 Bad Request"),
        ("401 Unauthorized"),
        ("402 Payment Required"),
        ("403 Forbidden"),
        ("404 Not Found"),
        ("405 Not Allowed"),
        ("406 Not Acceptable"),
        NULL, /* "407 Proxy Authentication Required" */
        ("408 Request Time-out"),
        ("409 Conflict"),
        ("410 Gone"),
        ("411 Length Required"),
        ("412 Precondition Failed"),
        ("413 Request Entity Too Large"),
        NULL, /* "414 Request-URI Too Large", but we never send it
         * because we treat such requests as the HTTP/0.9
         * requests and send only a body without a header
         */
        ("415 Unsupported Media Type"),
        ("416 Requested Range Not Satisfiable"),

        /* NULL, *//* "417 Expectation Failed" */
        /* NULL, *//* "418 unused" */
        /* NULL, *//* "419 unused" */
        /* NULL, *//* "420 unused" */
        /* NULL, *//* "421 unused" */
        /* NULL, *//* "422 Unprocessable Entity" */
        /* NULL, *//* "423 Locked" */
        /* NULL, *//* "424 Failed Dependency" */

#define NGX_HTTP_LAST_LEVEL_400  417
#define NGX_HTTP_LEVEL_400       (NGX_HTTP_LAST_LEVEL_400 - 400)

        ("500 Internal Server Error"),
        ("501 Method Not Implemented"),
        ("502 Bad Gateway"),
        ("503 Service Temporarily Unavailable"),
        ("504 Gateway Time-out"),

        NULL, /* "505 HTTP Version Not Supported" */
        NULL, /* "506 Variant Also Negotiates" */
        ("507 Insufficient Storage"),
    /* NULL, *//* "508 unused" */
    /* NULL, *//* "509 unused" */
    /* NULL, *//* "510 Not Extended" */

#define NGX_HTTP_LAST_LEVEL_500  508
    };

const char* http_status2line(int code) {
	if (code < 200)
		return NULL;
	//else if (code < 300)
	else if (code < NGX_HTTP_LAST_LEVEL_200)
			return http_status_lines[code - 200];
	//else if (code < 400)
	else if (code >=301 && code < NGX_HTTP_LAST_LEVEL_300)
			return http_status_lines[code - 300 + NGX_HTTP_LEVEL_200];
	//else if (code < 500)
	else if (code >= 400 && code < NGX_HTTP_LAST_LEVEL_400)
			return http_status_lines[code - 400 + NGX_HTTP_LEVEL_300
			                         + NGX_HTTP_LEVEL_200];
	else if (code >= 500 && code < NGX_HTTP_LAST_LEVEL_500)
		return http_status_lines[code - 500 + NGX_HTTP_LEVEL_400
		    + NGX_HTTP_LEVEL_300
		    + NGX_HTTP_LEVEL_200];

	return NULL;
}
