/*
 * test_util.c
 *
 *  Created on: 2013-9-24
 *      Author: li.lei
 */

#include "navi_inner_util.h"
#include <assert.h>

int main(int argc, char* argv[]) {
	char path[1024];
	navi_rpath_2abs(".",path,1024);
	printf("%s\n",path);

	navi_rpath_2abs("./",path,1024);
	printf("%s\n",path);

	navi_rpath_2abs("./aa/",path,1024);
	printf("%s\n",path);

	navi_rpath_2abs("../aa/",path,1024);
	printf("%s\n",path);

	navi_rpath_2abs("/aa/bb/cc/./../dd/ee",path,1024);
	printf("%s\n",path);

	navi_rpath_2abs("/../../aa/bb",path,1024);
	printf("%s\n",path);

	navi_rpath_2abs("/.//a",path,1024);
	printf("%s\n",path);

	navi_rpath_2abs("/aa/bb/cc/..",path,1024);
	printf("%s\n",path);;

	navi_rpath_2abs("aa/bb/cc/dd/",path,1024);
	printf("%s\n",path);

	navi_rpath_2abs("aa/./bb/../cc/.",path,1024);
	printf("%s\n", path);

	char* u = navi_build_uri(3, "/", "", "aa");
	assert( 0 == strcmp( u, "/aa"));
	free(u);
	u = navi_build_uri(3, "/", "aa", "/");
	assert( 0 == strcmp( u, "/aa"));
	free(u);;
	u = navi_build_uri(4, "/", "/", "/","aa//");
	assert( 0 == strcmp( u, "/aa"));
	free(u);;

	u = navi_build_uri(3, "/", "aa", "aa");
	assert( 0 == strcmp( u, "/aa/aa"));
	free(u);;
	u = navi_build_uri(3, "/aa//", "/aa", "aa/");
	assert( 0 == strcmp( u, "/aa/aa/aa"));
	free(u);;

	if (argc == 2) {
		navi_pool_t* pool = navi_pool_create(1024);
		navi_url_parse_t u_parse;
		u_parse.pool = pool;

		if (0==navi_parse_url(argv[1], &u_parse)) {
			char ip_text[128];
			inet_ntop(AF_INET,&u_parse.addr.sin_addr, ip_text, 128 );
			printf("%s:%d %s %s %s", u_parse.host_text, u_parse.port, u_parse.uri, u_parse.query_args,
				ip_text);
		}
		else {
			printf("parse url failed");
		}
	}

	return 0;
}

