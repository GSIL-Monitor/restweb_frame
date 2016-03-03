/*
 * test_request_drive.c
 *
 *  Created on: 2013Äê10ÔÂ9ÈÕ
 *      Author: li.lei
 */

#include "navi_request_driver.h"
#include "navi_module_driver.h"
#include "navi_module_mgr.h"
#include "navi_simple_array.h"

#include <assert.h>

navi_module_mgr_t* mgr=NULL;

void single_drive() {

	navi_request_t* req = navi_request_init();
	assert(req);
	navi_http_request_set_uri(req,"/test_app1/method1",1);
	navi_request_parse_main_uri(req);
	navi_http_request_append_post(req,"post_part1",strlen("post_part1"));
	navi_http_request_append_post(req,"post_part2",strlen("post_part2")+1);

	navi_mgr_run_request(mgr,req);

	assert(navi_http_response_get_status(req) == 200 );
	navi_response_t* resp = navi_request_response_obj(req);
	char* body = navi_response_http_body(resp,0);
	printf("%s\n",body);

	navi_request_free(req);
}

void sub_normal_drive() {
	navi_request_t* req = navi_request_init();
	navi_request_t* sub;
	assert(req);
	navi_http_request_set_uri(req,"/test_app1/normal_sub",1);
	navi_request_parse_main_uri(req);
	navi_mgr_run_request(mgr,req);

	void* iter = navi_request_regist_iter(req);
	while((sub = navi_request_regist_iter_next(iter))) {
		navi_request_set_status(sub,NAVI_REQUEST_DRIVER_PROCESSING);
		navi_request_call_process(sub);
	}
	navi_request_regist_iter_destroy(iter);

	assert(navi_http_response_get_status(req) == 200 );
	navi_response_t* resp = navi_request_response_obj(req);
	char* body = navi_response_http_body(resp,0);
	printf("%s\n",body);

	navi_request_free(req);
}

void absub_normal_drive() {
	navi_request_t* req = navi_request_init();
	navi_request_t* sub;
	assert(req);
	navi_http_request_set_uri(req,"/test_app1/abnormal_sub",1);
	navi_request_parse_main_uri(req);
	navi_mgr_run_request(mgr,req);

	void* iter = navi_request_regist_iter(req);
	while((sub = navi_request_regist_iter_next(iter))) {
		navi_request_set_status(sub,NAVI_REQUEST_DRIVER_PROCESSING);
		navi_request_call_process(sub);
	}
	navi_request_regist_iter_destroy(iter);

	assert(navi_http_response_get_status(req) == 200 );
	navi_response_t* resp = navi_request_response_obj(req);
	char* body = navi_response_http_body(resp,0);
	printf("%s\n",body);

	navi_request_free(req);
}

void notexist_drive() {
	navi_request_t* req = navi_request_init();
		navi_request_t* sub;
		assert(req);
		navi_http_request_set_uri(req,"/test_app1",1);
		navi_request_parse_main_uri(req);
		navi_mgr_run_request(mgr,req);

		void* iter = navi_request_regist_iter(req);
		while((sub = navi_request_regist_iter_next(iter))) {
			navi_request_set_status(sub,NAVI_REQUEST_DRIVER_PROCESSING);
			navi_request_call_process(sub);
		}
		navi_request_regist_iter_destroy(iter);

		assert(navi_http_response_get_status(req) == 405 );
		navi_response_t* resp = navi_request_response_obj(req);
		char* body = navi_response_http_body(resp,0);
		printf("%s\n",body);

		navi_request_free(req);
}
void test_tree() {
	navi_request_t* req = navi_request_init();
	navi_request_t* sub;
	assert(req);
	navi_http_request_set_uri(req,"/test_app1/tree",1);
	navi_request_parse_main_uri(req);
	navi_mgr_run_request(mgr,req);
	navi_array_t *drivers = navi_array_create(navi_request_pool(req),10, sizeof(navi_request_t*));

	void* iter = navi_request_regist_iter(req);
	while((sub = navi_request_regist_iter_next(iter))) {
		navi_request_set_status(sub,NAVI_REQUEST_DRIVER_PROCESSING);
		navi_request_t** t = navi_array_push(drivers);
		*t = sub;
	}
	navi_request_regist_iter_destroy(iter);

	int i;
	for ( i=0; i< drivers->count; i++) {
		navi_request_t** t = navi_array_item(drivers, i);
		navi_request_call_process(*t);
	}

	 iter = navi_request_cancel_iter(req);
	while((sub = navi_request_cancel_iter_next(iter))) {
		navi_request_set_status(sub,NAVI_REQUEST_CANCELED);
	}
	navi_request_cancel_iter_destroy(iter);

	assert(navi_http_response_get_status(req) == 200 );
	navi_response_t* resp = navi_request_response_obj(req);
	char* body = navi_response_http_body(resp,0);
	printf("=======tree %s\n",body);

	navi_request_free(req);
}

int main() {
	mgr = navi_mgr_init("./conf");
	single_drive();
	sub_normal_drive();
	absub_normal_drive();
	notexist_drive();

	test_tree();

	navi_mgr_free(mgr);
	return 0;
}
