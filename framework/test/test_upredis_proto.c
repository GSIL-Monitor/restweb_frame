/*
 * test_upredis_proto.c
 *
 *  Created on: 2014-1-13
 *      Author: li.lei
 */

#include "navi_upproto_redis.h"
#include <sys/time.h>
#include <assert.h>

void test_error_resp()
{
	navi_pool_t* pool = navi_pool_create(128);
	nvup_redis_proto_t proto;
	const char* resp = "-ERR: info\r\n";

	nvup_redis_proto_init(&proto,pool , 1024);
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	nvup_redis_proto_clean(&proto);


	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "-ERR: info";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "\r";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	nvup_redis_proto_clean(&proto);

	assert( proto.proto_type == redis_type_error_reply);
	assert( proto.pending_stage == redis_stage_done);
	assert( 0 == strcmp(proto.str_result, "ERR: info"));

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "-ERR: \r\ri\rnfo\r\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	nvup_redis_proto_clean(&proto);

	assert( proto.proto_type == redis_type_error_reply);
	assert( proto.pending_stage == redis_stage_done);
	assert( 0 == strcmp(proto.str_result, "ERR: \r\ri\rnfo\r"));

	navi_pool_destroy(pool);
}

void test_num_resp()
{
	navi_pool_t* pool = navi_pool_create(128);
	nvup_redis_proto_t proto;

	const char* resp = NULL;

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = ":1024\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_num);
	assert( proto.pending_stage == redis_stage_done);
	assert( proto.num_result==1024);
	nvup_redis_proto_clean(&proto);


	nvup_redis_proto_init(&proto,pool , 1024);
	resp = ":-1024\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_num);
	assert( proto.pending_stage == redis_stage_done);
	assert( proto.num_result==-1024);
	nvup_redis_proto_clean(&proto);


	nvup_redis_proto_init(&proto,pool , 1024);
	resp = ":-102";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "4";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));

	resp = "\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_num);
	assert( proto.pending_stage == redis_stage_done);
	assert( proto.num_result==-1024);
	nvup_redis_proto_clean(&proto);

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = ":-102a4\r\n";
	assert(NVUP_PARSE_PROTO_ERROR == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_proto_error);
	assert( proto.pending_stage == redis_stage_done);
	nvup_redis_proto_clean(&proto);

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = ":-1024\r\r\n";
	assert(NVUP_PARSE_PROTO_ERROR == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_proto_error);
	assert( proto.pending_stage == redis_stage_done);
	nvup_redis_proto_clean(&proto);

	navi_pool_destroy(pool);
}

void test_status_resp()
{
	navi_pool_t* pool = navi_pool_create(128);
	nvup_redis_proto_t proto;

	const char* resp = NULL;

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "+OK\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_status_reply);
	assert( proto.pending_stage == redis_stage_done);
	assert( 0==strcmp(proto.str_result, "OK"));
	nvup_redis_proto_clean(&proto);


	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "+O\rK\r\r\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_status_reply);
	assert( proto.pending_stage == redis_stage_done);
	assert( 0==strcmp(proto.str_result, "O\rK\r\r"));
	nvup_redis_proto_clean(&proto);


	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "+AAAA";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "A";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));

	assert( proto.proto_type == redis_type_status_reply);
	assert( proto.pending_stage == redis_stage_done);
	assert( 0==strcmp(proto.str_result, "AAAAA"));

	nvup_redis_proto_clean(&proto);
	navi_pool_destroy(pool);
}

void test_single_bulk_resp()
{
	navi_pool_t* pool = navi_pool_create(128);
	nvup_redis_proto_t proto;

	const char* resp = NULL;

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "$10";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "01234567";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "89";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_single_bulk);
	assert( proto.pending_stage == redis_stage_done);
	assert( proto.in_bulks && proto.in_bulks->count == 1);

	redis_bulk_t* bk = navi_array_item(proto.in_bulks, 0);
	assert (bk->bulk_type == redis_type_single_bulk);
	assert (0==strcmp(bk->s, "0123456789"));
	nvup_redis_proto_clean(&proto);

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "$10";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "01234567899\r\n";
	assert(NVUP_PARSE_PROTO_ERROR == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	nvup_redis_proto_clean(&proto);

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "$\r\n";
	assert(NVUP_PARSE_PROTO_ERROR == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	nvup_redis_proto_clean(&proto);

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "$-1\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_single_bulk);
	assert( proto.pending_stage == redis_stage_done);
	assert( proto.in_bulks == NULL);
	nvup_redis_proto_clean(&proto);

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "$0\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_single_bulk);
	assert( proto.pending_stage == redis_stage_done);
	assert( proto.in_bulks && proto.in_bulks->count == 1);

	bk = navi_array_item(proto.in_bulks, 0);
	assert (bk->bulk_type == redis_type_single_bulk);
	assert ( 0 == strlen(bk->s));
	nvup_redis_proto_clean(&proto);

	nvup_redis_proto_init(&proto,pool , 1024);
	resp = "$0\r\njj\n";
	assert(NVUP_PARSE_PROTO_ERROR == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	nvup_redis_proto_clean(&proto);

	navi_pool_destroy(pool);
}

void test_multi_str_bulk_resp()
{
	navi_pool_t* pool = navi_pool_create(128);
	nvup_redis_proto_t proto;

	const char* resp = NULL;

	nvup_redis_proto_init(&proto, pool , 1024);
	resp = "*2\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "$10\r\n0123456789\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "$5\r\n01234\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));

	assert( proto.proto_type == redis_type_multi_bulk);
	assert( proto.pending_stage == redis_stage_done);
	assert( proto.in_bulks && proto.in_bulks->count == 2);

	redis_bulk_t* bk = navi_array_item(proto.in_bulks, 0);
	assert (bk->bulk_type == redis_type_single_bulk);
	assert ( 0 == strcmp(bk->s, "0123456789"));
	bk = navi_array_item(proto.in_bulks, 1);
	assert (bk->bulk_type == redis_type_single_bulk);
	assert ( 0 == strcmp(bk->s, "01234"));
	nvup_redis_proto_clean(&proto);

	nvup_redis_proto_init(&proto, pool , 1024);
	resp = "*-1\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_multi_bulk);
	assert( proto.pending_stage == redis_stage_done);
	assert( proto.in_bulks == NULL );
	nvup_redis_proto_clean(&proto);

	nvup_redis_proto_init(&proto, pool , 1024);
	resp = "*0\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	assert( proto.proto_type == redis_type_multi_bulk);
	assert( proto.pending_stage == redis_stage_done);
	assert( proto.in_bulks && proto.in_bulks->count == 0 );
	nvup_redis_proto_clean(&proto);

	navi_pool_destroy(pool);
}

void test_multi_mixed_bulk_resp()
{
	navi_pool_t* pool = navi_pool_create(128);
	nvup_redis_proto_t proto;

	const char* resp = NULL;

	nvup_redis_proto_init(&proto, pool , 1024);

	resp = "*6\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = ":1024\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "-ERR: xx\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "+OK\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "$0\r\n\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "$-1\r\n";
	assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
	resp = "$10\r\n0123456789\r\n";
	assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));

	assert( proto.in_bulks && proto.in_bulks->count == 6);

	redis_bulk_t* bk = navi_array_item(proto.in_bulks, 0);
	assert( bk->bulk_type == redis_type_num && bk->i == 1024);

	bk = navi_array_item(proto.in_bulks, 1);
	assert (bk->bulk_type == redis_type_error_reply && strcmp(bk->s, "ERR: xx")==0);
	bk = navi_array_item(proto.in_bulks, 2);
	assert (bk->bulk_type == redis_type_status_reply && strcmp(bk->s, "OK")==0);
	bk = navi_array_item(proto.in_bulks, 3);
	assert (bk->bulk_type == redis_type_single_bulk && strcmp(bk->s, "")==0);
	bk = navi_array_item(proto.in_bulks, 4);
	assert (bk->bulk_type == redis_type_single_bulk && bk->s == NULL);
	bk = navi_array_item(proto.in_bulks, 5);
	assert (bk->bulk_type == redis_type_single_bulk && strcmp(bk->s, "0123456789")==0);
	nvup_redis_proto_clean(&proto);
	navi_pool_destroy(pool);
}

void print_elapse(struct timeval* start, struct timeval* end)
{
    if (start->tv_usec <= end->tv_usec)
    {
        fprintf(stderr, "elapse: %d sec %d usec\n", end->tv_sec - start->tv_sec, end->tv_usec - start->tv_usec);
    }
    else
    {
        fprintf(stderr, "elapse: %d sec %d usec\n", end->tv_sec - start->tv_sec - 1,
            1000000 - start->tv_usec + end->tv_usec);
    }
}

static void perftest_multi_bulk() {
	navi_pool_t* pool = navi_pool_create(1024);
	nvup_redis_proto_t proto;

	const char* resp = "*20\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		"$20\r\n01234567890123456789\r\n"
		;
	struct timeval start,end;
	gettimeofday(&start,NULL);
	nvup_redis_proto_init(&proto, pool , 1024);

	int i = 0;
	for (; i<1000000; i++) {
		assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp, strlen(resp)));
		nvup_redis_proto_reset(&proto);
	}
	printf("perftest_multibulk_parse:");
	gettimeofday(&end,NULL);
	print_elapse(&start,&end);
	nvup_redis_proto_clean(&proto);
	navi_pool_destroy(pool);
}

static void test_parse_buf() {
	navi_pool_t* pool = navi_pool_create(128);
	nvup_redis_proto_t proto;

	nvup_redis_proto_init(&proto, pool , 64);
	char resp1[4096], resp2[4096];
	char* p, *end;
	size_t sz;
	srand(time(NULL));
	int i = 0, j;
	for (; i<100000; i++) {
		p = resp1;
		end = resp1+sizeof(resp1);
		p+= snprintf( p, end-p, "*20\r\n", strlen("*20\r\n"));
		for (j=0; j<10; j++) {
			sz = rand()%20;
			if (sz)
				p += snprintf( p, end-p, "$%d\r\n%*c\r\n", sz, sz, 'c');
			else
				p += snprintf( p, end-p, "$1\r\nc\r\n");
		}

		assert(NVUP_PARSE_AGAIN == nvup_redis_proto_parse_in(&proto, resp1, strlen(resp1)));

		p = resp1;
		for (j=0; j<10; j++) {
			sz = rand()%20;
			if (sz)
				p += snprintf( p, end-p, "$%d\r\n%*c\r\n", sz, sz, 'c');
			else
				p += snprintf( p, end-p, "$1\r\nc\r\n");
		}
		assert(NVUP_PARSE_DONE == nvup_redis_proto_parse_in(&proto, resp1, strlen(resp1)));
		nvup_redis_proto_reset(&proto);
	}
	nvup_redis_proto_clean(&proto);
}

void test_skey_cmd()
{
	nvup_redis_cmd_t cmd;
	navi_pool_t* pool = navi_pool_create(128);
	navi_buf_chain_t *chain = navi_buf_chain_init(pool);
	char buf[1024];
	UPREDIS_SKEY_0ARG_CMD(&cmd, pool, "TEST", "KK", chain);
	size_t sz = navi_buf_chain_get_content(chain, buf, sizeof(buf));
	buf[sz] = 0;
	assert( 0 == strcmp(buf,"*2\r\n$4\r\nTEST\r\n$2\r\nKK\r\n" ) );

	chain = navi_buf_chain_init(pool);
	UPREDIS_SKEY_1ARG_CMD(&cmd, pool, "TEST", "KK", "JJ", chain);
	sz = navi_buf_chain_get_content(chain, buf, sizeof(buf));
	buf[sz] =0;
	assert( 0 == strcmp(buf,"*3\r\n$4\r\nTEST\r\n$2\r\nKK\r\n$2\r\nJJ\r\n" ) );

	chain = navi_buf_chain_init(pool);
	UPREDIS_SKEY_2ARG_CMD(&cmd, pool, "TEST", "KK", "JJ","KK", chain);
	sz = navi_buf_chain_get_content(chain, buf, sizeof(buf));
	buf[sz] =0;
	assert( 0 == strcmp(buf,"*4\r\n$4\r\nTEST\r\n$2\r\nKK\r\n$2\r\nJJ\r\n$2\r\nKK\r\n" ) );

	chain = navi_buf_chain_init(pool);
	UPREDIS_SKEY_MARG_CMD(&cmd, pool, "TEST", "KK", 4);
	char** parg = navi_array_push(cmd.s_key->margs);
	*parg = "JJ1";
	parg = navi_array_push(cmd.s_key->margs);
	*parg = "JJ2";
	parg = navi_array_push(cmd.s_key->margs);
	*parg = "JJ3";
	parg = navi_array_push(cmd.s_key->margs);
	*parg = "JJ4";
	nvup_redis_cmd_2outpack(&cmd, chain);
	sz = navi_buf_chain_get_content(chain, buf, sizeof(buf));
	buf[sz] = 0;
	assert( 0 == strcmp(buf,"*6\r\n$4\r\nTEST\r\n$2\r\nKK\r\n$3\r\nJJ1\r\n$3\r\nJJ2\r\n$3\r\nJJ3\r\n$3\r\nJJ4\r\n" ) );

	navi_pool_destroy(pool);
}

void test_mkey_cmd()
{
	nvup_redis_cmd_t cmd;
	navi_pool_t* pool = navi_pool_create(128);
	navi_buf_chain_t *chain = navi_buf_chain_init(pool);
	char buf[1024];
	size_t sz = 0;

	UPREDIS_MKEY_CMD(&cmd, pool, "TEST", 4);
	nvup_redis_cmd_key_t* ka = navi_array_push(cmd.m_keys);
	ka->arg_st = NVUP_REDIS_KEY_0ARG;
	ka->key = "key1";
	ka = navi_array_push(cmd.m_keys);
	ka->arg_st = NVUP_REDIS_KEY_1ARG;
	ka->key = "key2";
	ka->arg1 = "arg2";
	ka = navi_array_push(cmd.m_keys);
	ka->arg_st = NVUP_REDIS_KEY_2ARG;
	ka->key = "key3";
	ka->arg1 = "arg3_1";
	ka->arg2 = "arg3_2";
	nvup_redis_cmd_2outpack(&cmd, chain);
	sz = navi_buf_chain_get_content(chain, buf, sizeof(buf));
	buf[sz] = 0;

	assert( 0 == strcmp(buf,"*7\r\n$4\r\nTEST\r\n$4\r\nkey1\r\n$4\r\nkey2\r\n$4\r\narg2\r\n$4\r\nkey3\r\n"
		"$6\r\narg3_1\r\n$6\r\narg3_2\r\n" ) );

	navi_pool_destroy(pool);
}

void test_parg_cmd()
{
	nvup_redis_cmd_t cmd;
	navi_pool_t* pool = navi_pool_create(128);
	navi_buf_chain_t *chain = navi_buf_chain_init(pool);
	char buf[1024];
	size_t sz = 0;

	UPREDIS_PUR1ARG_CMD(&cmd, pool, "test", "arg", chain);
	sz = navi_buf_chain_get_content(chain, buf, sizeof(buf));
	buf[sz] = 0;

	assert( 0 == strcmp(buf,"*2\r\n$4\r\ntest\r\n$3\r\narg\r\n") );


	chain = navi_buf_chain_init(pool);
	UPREDIS_PURMARG_CMD(&cmd, pool, "test", 4);
	char** parg = navi_array_push(cmd.m_args);
	*parg = "arg1";
	parg = navi_array_push(cmd.m_args);
	*parg = "arg2";
parg = navi_array_push(cmd.m_args);
	*parg = "arg3";
	parg = navi_array_push(cmd.m_args);
	*parg = "arg4";
	nvup_redis_cmd_2outpack(&cmd, chain);
	sz = navi_buf_chain_get_content(chain, buf, sizeof(buf));
	buf[sz] = 0;
	assert( 0 == strcmp(buf,"*5\r\n$4\r\ntest\r\n$4\r\narg1\r\n$4\r\narg2\r\n$4\r\narg3\r\n$4\r\narg4\r\n") );
	navi_pool_destroy(pool);
}


void test_resp()
{
	test_error_resp();
	test_num_resp();
	test_status_resp();
	test_single_bulk_resp();
	test_multi_str_bulk_resp();
	test_multi_mixed_bulk_resp();
	test_parse_buf();
}

void test_cmd()
{
	test_skey_cmd();
	test_mkey_cmd();
	test_parg_cmd();
}

int main()
{
	test_resp();
	test_cmd();
	perftest_multi_bulk();
}

