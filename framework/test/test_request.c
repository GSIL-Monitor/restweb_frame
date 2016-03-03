/*
 * test_request.c
 *
 *  Created on: 2013-9-22
 *      Author: li.lei
 */

#include <assert.h>
#include "navi_request_driver.h"

static void test_create() {
	navi_request_t* req = navi_request_init();
	navi_request_free(req);
}

static void test_set_uri() {
	navi_request_t* req = navi_request_init();

	char buf[1024];

	sprintf(buf,"/test");
	navi_http_request_set_uri(req,buf,1);
	assert( 5==navi_http_request_get_uri_query(req,NULL,0) );

	sprintf(buf,"/test%%20a/jjla/a-a");
	navi_http_request_set_uri(req,buf,1);
	const char* uri = navi_http_request_get_uri(req);

	assert(strcmp(uri,"/test a/jjla/a-a")==0);

	memcpy(buf,"/test%3fa/jj",strlen("/test%3fa/jj")+1);
	navi_http_request_set_uri(req,buf,1);
	uri = navi_http_request_get_uri(req);

	assert(strcmp(uri,"/test?a/jj")==0);

	memcpy(buf,"/test%3fa/jj?arg1=arg1value",strlen("/test%3fa/jj?arg1=arg1value")+1);
	navi_http_request_set_uri(req,buf,1);
	uri = navi_http_request_get_uri(req);

	assert(strcmp(uri,"/test?a/jj")==0);

	assert(strcmp("arg1value",navi_http_request_get_arg(req,"arg1") )==0 );

	navi_http_request_get_uri_query(req,buf,1024);
	printf("%s\n",buf);

	navi_request_free(req);
}

static void test_set_arg() {
	navi_request_t* req = navi_request_init();

	assert(NULL==navi_http_request_get_arg(req,"arg6"));
	const char* arg, *val;
	void* it = navi_http_request_arg_iter(req);
	assert(NULL == navi_http_request_arg_iter_next(it,NULL));
	navi_http_request_arg_iter_destroy(it);

	navi_http_request_set_uri(req,"/jjj jjj/aa?aa/dd?arg1=v1&arg2=v2",0);
	navi_http_request_set_args_raw(req,"arg1=v11&arg3=v%203&arg4=v4&arg5=v5");
	char buf[1024];
	size_t sz = navi_http_request_get_uri_query(req,buf,1024);
	printf("%s\n",buf);
	assert(sz==strlen(buf));

	assert(strcmp("v11",navi_http_request_get_arg(req,"arg1"))==0);
	assert(strcmp("v2",navi_http_request_get_arg(req,"arg2"))==0);
	assert(strcmp("v 3",navi_http_request_get_arg(req,"arg3"))==0);
	assert(strcmp("v4",navi_http_request_get_arg(req,"arg4"))==0);
	assert(strcmp("v5",navi_http_request_get_arg(req,"arg5"))==0);
	assert(NULL==navi_http_request_get_arg(req,"arg6"));

	navi_http_request_set_arg(req,"arg6",NULL);
	assert(strlen(navi_http_request_get_arg(req,"arg6"))==0);

	navi_http_request_set_arg(req,"arg=7","v&-= ?8");
	assert(strcmp("v&-= ?8",navi_http_request_get_arg(req,"arg=7"))==0);
	sz = navi_http_request_get_uri_query(req,buf,1024);
	printf("%s\n",buf);
	assert(sz==strlen(buf));

	navi_http_request_set_args_raw(req,"arg1=v11&arg3=v%203&arg4=v4&arg5=v5&arg6=&arg7=v7");
	assert(strcmp("v11",navi_http_request_get_arg(req,"arg1"))==0);
	assert(strcmp("v2",navi_http_request_get_arg(req,"arg2"))==0);
	assert(strcmp("v 3",navi_http_request_get_arg(req,"arg3"))==0);
	assert(strcmp("v4",navi_http_request_get_arg(req,"arg4"))==0);
	assert(strcmp("v5",navi_http_request_get_arg(req,"arg5"))==0);
	assert(strlen(navi_http_request_get_arg(req,"arg6"))==0);
	assert(strcmp("v7",navi_http_request_get_arg(req,"arg7"))==0);


	int i;
	for (i=0;i<2000;i++) {
		char arg[32],val[32];
		sprintf(arg,"arg%d",i);
		sprintf(val,"v%d",i);
		navi_http_request_set_arg(req,arg,val);
	}

	char big_buf[10240];
	navi_http_request_get_uri_query(req,big_buf,10240);
	printf("%s\n",big_buf);

	it = navi_http_request_arg_iter(req);

	i = 0;
	while (arg = navi_http_request_arg_iter_next(it,&val)) {
		i++;
		assert(strcmp(val,navi_http_request_get_arg(req,arg))==0);
	}
	navi_http_request_arg_iter_destroy(it);
	assert(i==2001);

	navi_http_request_set_args_raw(req,"a%3d1%26b%3d2%26c=3");
	assert(strcmp("3",navi_http_request_get_arg(req,"a=1&b=2&c"))==0);
	navi_http_request_set_args_raw(req,"a%=1");
	assert(strcmp("1",navi_http_request_get_arg(req,"a%"))==0);
	navi_http_request_set_args_raw(req,"a%a=1");
	assert(strcmp("1",navi_http_request_get_arg(req,"a%a"))==0);
	navi_http_request_set_args_raw(req,"a%q=1");
	assert(strcmp("1",navi_http_request_get_arg(req,"a%q"))==0);
	navi_http_request_set_args_raw(req,"a%20=1");
	assert(strcmp("1",navi_http_request_get_arg(req,"a "))==0);
	navi_http_request_set_args_raw(req,"a%2q=1");
	assert(strcmp("1",navi_http_request_get_arg(req,"a%2q"))==0);
	
	navi_http_request_set_args_raw(req,"a=1%&b=2%25&c=3%");
	assert(strcmp("1%",navi_http_request_get_arg(req,"a"))==0);
	assert(strcmp("2%",navi_http_request_get_arg(req,"b"))==0);
	assert(strcmp("3%",navi_http_request_get_arg(req,"c"))==0);

	navi_request_free(req);
}

static void test_set_header() {
	navi_request_t* req = navi_request_init();

	assert(NULL==navi_http_request_get_header(req,"arg6"));
	const char* arg, *val;
	void* it = navi_http_request_header_iter(req);
	assert(NULL == navi_http_request_header_iter_next(it,NULL));
	navi_http_request_header_iter_destroy(it);

	int i ;
	for (i=0; i<1000; i++) {
		char hnm[64];
		char hval[64];
		sprintf(hnm,"Header%d",i);
		sprintf(hval,"HeaderValue%d",i);
		navi_http_request_set_header(req,hnm,hval);
	}

	for (i=0; i<1000; i++) {
		char hnm[64];
		char hval[64];
		sprintf(hnm,"heAder%d",i);
		sprintf(hval,"HeaderValue%d",i);

		assert(strcmp(hval,navi_http_request_get_header(req,hnm))==0);
	}

	it = navi_http_request_header_iter(req);
	i = 0;
	while (arg = navi_http_request_header_iter_next(it,&val)) {
		i++;
		//printf("%s %s\n",arg,val);
		assert(strcmp(val,navi_http_request_get_header(req,arg))==0);
	}
	navi_http_request_header_iter_destroy(it);
	assert(i==1000);

	navi_http_request_set_header(req,"aheader","avalue");
	navi_http_request_set_header(req,"bheader","bvalue");

	//assert(NAVI_ARG_ERR == navi_http_request_set_header(req,"content-length","1010"));

	assert(strcmp(navi_http_request_get_header(req,"aheader"),"avalue")==0);
	assert(strcmp(navi_http_request_get_header(req,"bheader"),"bvalue")==0);
	assert(NULL==navi_http_request_get_header(req,"cheader"));
	//assert(NULL==navi_http_request_get_header(req,"content-length"));

	navi_request_free(req);
}

static void test_set_resp_header() {
	navi_request_t* req = navi_request_init();

	assert(NULL==navi_http_response_get_header(req,"arg6"));
	const char* arg, *val;
	void* it = navi_http_response_header_iter(req);
	assert(NULL == navi_http_response_header_iter_next(it,NULL));
	navi_http_response_header_iter_destroy(it);

	int i ;
	for (i=0; i<1000; i++) {
		char hnm[64];
		char hval[64];
		sprintf(hnm,"Header%d",i);
		sprintf(hval,"HeaderValue%d",i);
		navi_http_response_set_header(req,hnm,hval);
	}

	for (i=0; i<1000; i++) {
		char hnm[64];
		char hval[64];
		sprintf(hnm,"heAder%d",i);
		sprintf(hval,"HeaderValue%d",i);

		assert(strcmp(hval,navi_http_response_get_header(req,hnm))==0);
	}

	it = navi_http_response_header_iter(req);
	i = 0;
	while (arg = navi_http_response_header_iter_next(it,&val)) {
		i++;
		//printf("%s %s\n",arg,val);
		assert(strcmp(val,navi_http_response_get_header(req,arg))==0);
	}
	navi_http_response_header_iter_destroy(it);
	assert(i==1000);

	navi_http_response_set_header(req,"aheader","avalue");
	navi_http_response_set_header(req,"bheader","bvalue");

	//assert(NAVI_ARG_ERR == navi_http_response_set_header(req,"content-length","1010"));

	assert(strcmp(navi_http_response_get_header(req,"aheader"),"avalue")==0);
	assert(strcmp(navi_http_response_get_header(req,"bheader"),"bvalue")==0);
	assert(NULL==navi_http_response_get_header(req,"cheader"));
	//assert(NULL==navi_http_response_get_header(req,"content-length"));

	navi_request_free(req);
}

static void test_post() {
	navi_request_t* req = navi_request_init();

	assert(0==navi_http_request_get_post(req,NULL));

	int i;
	const uint8_t* post;
	size_t len;
	for (i=0; i<10; i++) {
		char buf[8192];

		navi_http_request_set_post(req,buf,8192);
		len = navi_http_request_get_post(req,&post);
		assert(len==8192 );
		assert(memcmp(post,buf,8192)==0);
	}

	int j;
	for (i=0; i<10; i++) {
		for (j=0; j<10; j++) {
			char buf2[128];
			navi_http_request_append_post(req,buf2,128);
		}
		len = navi_http_request_get_post(req,&post);
		assert(len==1280);
	}


	assert(0==navi_http_response_get_body(req,NULL));

	for (i=0; i<10; i++) {
		char buf[8192];
		navi_http_response_set_body(req,buf,8192);
		len = navi_http_response_get_body(req,&post);
		assert(len==8192 );
		assert(memcmp(post,buf,8192)==0);
	}

	for (i=0; i<10; i++) {
		for (j=0; j<10; j++) {
			char buf2[128];
			navi_http_response_append_body(req,buf2,128);
		}
		len = navi_http_response_get_body(req,&post);
		assert(len==1280);
	}

	navi_request_free(req);
}

int main() {
	test_create();
	test_set_uri();
	test_set_arg();
	test_set_header();
	test_set_resp_header();
	test_post();
}
