/*
 * navi_inner_util.h
 *
 *  Created on: 2013-9-23
 *      Author: li.lei
 */

#ifndef NAVI_INNER_UTIL_H_
#define NAVI_INNER_UTIL_H_
#include "navi_common_define.h"
#include "navi_simple_hash.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>

#define NAVI_ESCAPE_URI            0
#define NAVI_ESCAPE_ARGS           1
#define NAVI_ESCAPE_URI_COMPONENT  2
#define NAVI_ESCAPE_HTML           3
#define NAVI_ESCAPE_REFRESH        4
#define NAVI_ESCAPE_MEMCACHED      5
#define NAVI_ESCAPE_MAIL_AUTH      6

#define NAVI_UNESCAPE_URI       1
#define NAVI_UNESCAPE_REDIRECT  2

size_t navi_rpath_2abs(const char* path, char *abs, size_t abs_sz);

bool navi_check_dir_path(const char* path, mode_t mod, int check_access);
int navi_create_dir(const char* path, int start_try, mode_t mod);
size_t navi_escape_uri(u_char* dst, u_char* src, uint8_t type);
void navi_unescape_uri(u_char* dst, size_t size, uint8_t type);

char* navi_build_query(navi_pool_t* pool, navi_hash_t* args);
navi_hash_t* navi_parse_query(navi_pool_t* pool, const char* str);

#define base64_encoded_length(len)  (((len + 2) / 3) * 4)
size_t encode_base64(uint8_t *dst, const uint8_t *src, size_t src_sz);

char* navi_build_uri(uint32_t comp_sz, .../*各uri分量，必须是字符串参数*/);

typedef struct navi_url_parse_s
{
	struct sockaddr_in addr;
	uint16_t port;
	char* scheme;
	char* host_text;
	char* port_text;
	char* uri;
	char* query_args;
	char* orig_text;
	struct sockaddr_in* resolve_hosts;
	int resolve_size;
	navi_pool_t* pool;
}navi_url_parse_t;

int navi_parse_url(const char* url, navi_url_parse_t* result);

uint64_t cur_time_us();

bool navi_is_symbol_word(const char* word);

void navi_addr_to_str(const struct sockaddr* peer, char* addr_str);

const char* http_status2line(int code);

#endif /* NAVI_INNER_UTIL_H_ */
