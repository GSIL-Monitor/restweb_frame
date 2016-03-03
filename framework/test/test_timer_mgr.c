/*
 * test_timer_mgr.c
 *
 *  Created on: 2013-9-17
 *      Author: li.lei
 */

#include "navi_timer_mgr.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

static void test_init() {
	navi_timer_mgr_t mgr;
	navi_timer_mgr_init(&mgr);
	assert(NULL == navi_timer_get(&mgr,NAVI_TIMER_RUNNING));
	assert(NULL == navi_timer_get(&mgr,NAVI_TIMER_CANCEL));
	assert(NULL == navi_timer_get(&mgr,NAVI_TIMER_REGISTED));
	navi_timer_mgr_clean(&mgr);
}

static int test_timer_handler(void* custom) {
	char* str = (char*)custom;
	printf("%s\n",str);
	return 0;
}

static int test_timer_destroyer(void* custom) {
	char* str = (char*)custom;
	printf("destroyer %s\n",str);
	return 0;
}

static void test_add() {
	navi_timer_mgr_t mgr;
	navi_timer_mgr_init(&mgr);

	navi_timer_h h = navi_timer_add(&mgr,NAVI_TIMER_ONCE,200,test_timer_handler,"test",NULL,NULL);
	navi_timer_h h2 = navi_timer_get(&mgr,NAVI_TIMER_REGISTED);
	assert( h==h2);

	navi_timer_timeout(h2);

	assert(NULL == navi_timer_get(&mgr,NAVI_TIMER_RUNNING));
	assert(NULL == navi_timer_get(&mgr,NAVI_TIMER_CANCEL));
	assert(NULL == navi_timer_get(&mgr,NAVI_TIMER_REGISTED));
	navi_timer_mgr_clean(&mgr);
	navi_timer_cleanup(h2);
}

static void test_interval() {
	navi_timer_mgr_t mgr;
	navi_timer_mgr_init(&mgr);

	navi_timer_h h = navi_timer_add(&mgr,NAVI_TIMER_INTERVAL,200,test_timer_handler,"test",test_timer_destroyer,(void*)1);
	navi_timer_h h2 = navi_timer_add(&mgr,NAVI_TIMER_INTERVAL,200,test_timer_handler,"test",test_timer_destroyer,(void*)1);
	navi_timer_h h3 = navi_timer_add(&mgr,NAVI_TIMER_INTERVAL,200,test_timer_handler,"test",test_timer_destroyer,(void*)1);

	navi_timer_h hh;
	int i=0;
	while( hh = navi_timer_get(&mgr, NAVI_TIMER_REGISTED) ) {
		assert( hh==h || i!=0 );
		assert( hh==h2 || i!=1 );
		assert( hh==h3 || i!=2 );
		i++;
		navi_timer_running(hh,NULL);
		navi_timer_timeout(hh);
	}

	navi_timer_mgr_clean_spec(&mgr, (void*)1);

	assert(navi_timer_is_zombie(h));
	assert(navi_timer_is_zombie(h2));
	assert(navi_timer_is_zombie(h3));
	navi_timer_timeout(h);
	navi_timer_timeout(h2);
	navi_timer_timeout(h3);
	navi_timer_cleanup(h);
	navi_timer_cleanup(h2);
	navi_timer_cleanup(h3);
}

static void test_cancel() {
	navi_timer_mgr_t mgr;
	navi_timer_mgr_init(&mgr);
	navi_timer_h h = navi_timer_add(&mgr,NAVI_TIMER_INTERVAL,200,test_timer_handler,"test",test_timer_destroyer,NULL);
	assert(h==navi_timer_get(&mgr,NAVI_TIMER_REGISTED));
	navi_timer_cancel(h);
	assert(NULL==navi_timer_get(&mgr,NAVI_TIMER_CANCEL));
	assert(NULL==navi_timer_get(&mgr,NAVI_TIMER_REGISTED));

	navi_timer_timeout(h);
	assert(navi_timer_is_zombie(h));
	assert(NULL==navi_timer_get(&mgr,NAVI_TIMER_CANCEL));
	navi_timer_cleanup(h);
	navi_timer_mgr_clean(&mgr);
}

int main()
{
	test_init();
	test_add();
	test_interval();
	test_cancel();
}

