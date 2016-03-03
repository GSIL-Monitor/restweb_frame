/*
 * test_redis_proxy_module.c
 *
 *  Created on: 2014-1-16
 *      Author: li.lei
 */

#include "navi_module.h"
#include "navi_request.h"
#include "navi_upredis.h"


NAVI_MODULE_INIT(test_redis_proxy,module)
{
	module->module_data = NULL;
	return NAVI_OK;
}

NAVI_MODULE_FREE(test_redis_proxy,module)
{

}

NAVI_MODULE_METHOD(test_redis_proxy,get,module,request)
{
	navi_request_t* sub = navi_request_new_sub(request);

	const char* key = navi_http_request_get_arg(request, "key");
	const char* group = navi_http_request_get_arg(request,"group");
	navi_upredis_t* redis = navi_request_bind_upredis(sub,group,NULL);
	navi_upredis_get(redis, key);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_redis_proxy,set,module,request)
{
	navi_request_t* sub = navi_request_new_sub(request);

	const char* key = navi_http_request_get_arg(request, "key");
	const char* group = navi_http_request_get_arg(request,"group");
	const char* value = navi_http_request_get_arg(request, "value");
	navi_upredis_t* redis = navi_request_bind_upredis(sub,group,NULL);
	navi_upredis_set(redis, key, value);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_redis_proxy,del,module,request)
{
	navi_request_t* sub = navi_request_new_sub(request);

	const char* key = navi_http_request_get_arg(request, "key");
	const char* group = navi_http_request_get_arg(request,"group");
	navi_upredis_t* redis = navi_request_bind_upredis(sub,group,NULL);
	navi_upredis_del(redis, key);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_redis_proxy,type,module,request)
{
	navi_request_t* sub = navi_request_new_sub(request);

	const char* key = navi_http_request_get_arg(request, "key");
	const char* group = navi_http_request_get_arg(request,"group");
	navi_upredis_t* redis = navi_request_bind_upredis(sub,group,NULL);
	navi_upredis_type(redis, key);
	return NAVI_OK;
}

typedef struct pull_list_data_s {
	navi_array_t* arr;
	const char* key;
	const char* group;
	const char* other_key;
	int other_cnt;
	int last_len;
	int lrange_count;
} pull_list_data_t;

void pulllist_after_llen(navi_upredis_t* redis, navi_upreq_result_t* result, void* x);

void pulllist_after_ltrim(navi_upredis_t* redis, navi_upreq_result_t* result, void* x)
{
	pull_list_data_t* data = (pull_list_data_t*)x;
	navi_request_t* root = navi_request_get_root(navi_upreq_channel(&redis->base));
	navi_pool_t* pool  =  navi_request_pool(root);
	if (result->code == NVUP_RESULT_SESSION_OK && result->content_type == NVUP_RESULT_DATA_STRING
		&& data->lrange_count < 5) {
		if ( 0==strcasecmp(result->s,"OK")) {
			navi_request_t* llen_req = navi_request_new_sub(root);
			navi_upredis_t* llen_redis = navi_request_bind_upredis_ctx(llen_req,
				data->group, pulllist_after_llen, data, NULL);
			navi_upredis_llen(llen_redis, data->key);
			navi_request_recycle_on_end(llen_req);
		}
	}
}

void pulllist_after_lrange(navi_upredis_t* redis, navi_upreq_result_t* result, void* x)
{
	pull_list_data_t* data = (pull_list_data_t*)x;
	navi_request_t* root = navi_request_get_root(navi_upreq_channel(&redis->base));
	navi_pool_t* pool  =  navi_request_pool(root);
	if (result->code == NVUP_RESULT_SESSION_OK && result->content_type == NVUP_RESULT_DATA_JSON) {
		int sz = json_array_size(result->js), i;
		for ( i=0; i<sz; i++) {
			json_t* je = json_array_get(result->js, i);
			if (json_is_string(je)) {
				char** se = navi_array_push(data->arr);
				*se = navi_pool_strdup(pool, json_string_value(je));
			}
		}

		navi_request_t* trim_req = navi_request_new_sub(root);
		navi_upredis_t* trim_redis = navi_request_bind_upredis_ctx(trim_req,
			data->group, pulllist_after_ltrim, data, NULL);
		navi_request_recycle_on_end(trim_req);
		navi_upredis_ltrim(trim_redis, data->key, data->last_len, -1);
		data->last_len = 0;
		data->lrange_count++;
	}
}

void pulllist_after_llen(navi_upredis_t* redis, navi_upreq_result_t* result, void* x)
{
	pull_list_data_t* data = (pull_list_data_t*)x;
	navi_request_t* root = navi_request_get_root(navi_upreq_channel(&redis->base));
	navi_pool_t* pool  =  navi_request_pool(root);
	if (result->code == NVUP_RESULT_SESSION_OK && result->content_type == NVUP_RESULT_DATA_INT) {
		if (result->i > 0) {
			navi_request_t* get_req = navi_request_new_sub(root);
			navi_upredis_t* get_redis = navi_request_bind_upredis_ctx(get_req,
				data->group, pulllist_after_lrange, data, NULL);
			navi_request_recycle_on_end(get_req);
			data->last_len = result->i;
			navi_upredis_lrange(get_redis, data->key, 0, result->i-1);
		}
	}
}

void pulllist_after_bpop(navi_upredis_t* redis, navi_upreq_result_t* result, void* x)
{
	pull_list_data_t* data = (pull_list_data_t*)x;
	navi_request_t* root = navi_request_get_root(navi_upreq_channel(&redis->base));
	navi_pool_t* pool  =  navi_request_pool(root);
	if (result->code == NVUP_RESULT_SESSION_OK) {
		if (result->content_type == NVUP_RESULT_DATA_PAIR) {
			char** e = navi_array_push(data->arr);
			*e = navi_pool_strdup(pool, result->pair.v);

			navi_request_recycle_on_end(navi_upreq_channel(&redis->base));

			navi_request_t* llen_req = navi_request_new_sub(root);
			navi_upredis_t* llen_redis = navi_request_bind_upredis_ctx(llen_req,
				data->group, pulllist_after_llen, data, NULL);
			navi_upredis_llen(llen_redis, data->key);
			navi_request_recycle_on_end(llen_req);
		}
	}
}

int process_list_data(navi_request_t* req, void* x) {
	pull_list_data_t* data = (pull_list_data_t*)x;
	if (data->arr->count == 0) {
		navi_http_response_append_body(req, "NULL", 4);
	}
	else {
		int i, j;
		char** pe;
		navi_array_part_t* part;
		char buf[256];
		for (i=0; i<data->arr->part_size; i++) {
			part = data->arr->parts[i];
			if (!part)
				break;

			pe = (char**)part->allocs;
			for (j=0; j<part->used; j++, pe++) {
				snprintf(buf, sizeof(buf), "%s\r\n", *pe);
				navi_http_response_append_body(req, buf, strlen(buf));
			}
		}
	}
	navi_http_response_set_status(req, 200);
	return NAVI_OK;
}

void get_other(navi_request_t* rt, navi_timer_h tmr, void* arg)
{
	pull_list_data_t* ctx = (const char*)arg;

	navi_request_t* sub = navi_request_new_sub(rt);
	navi_upredis_t* upredis = navi_request_bind_upredis_ctx(sub, ctx->group, NULL, NULL, NULL);
	navi_request_recycle_on_end(sub);
	navi_upredis_type(upredis, ctx->other_key);
	ctx->other_cnt++;

	if (ctx->other_cnt == 10)
		navi_request_cancel_timer(rt, tmr);
}

void exists_other(navi_request_t* rt, navi_timer_h tmr, void* arg)
{
	pull_list_data_t* ctx = (const char*)arg;

	navi_request_t* sub = navi_request_new_sub(rt);
	navi_upredis_t* upredis = navi_request_bind_upredis_ctx(sub, ctx->group, NULL, NULL, NULL);
	navi_request_recycle_on_end(sub);
	navi_upredis_exists(upredis, ctx->other_key);
}

NAVI_MODULE_METHOD(test_redis_proxy,blpop,module,request)
{
	navi_pool_t* pool = navi_request_pool(request);
	pull_list_data_t* ctx = navi_pool_calloc(pool, 1, sizeof(pull_list_data_t));
	navi_request_t* sub = navi_request_new_sub(request);

	ctx->key = navi_http_request_get_arg(request, "key");
	ctx->group = navi_http_request_get_arg(request,"group");
	ctx->other_key = navi_http_request_get_arg(request, "other_key");
	ctx->arr = navi_array_create(pool, 10, sizeof(char*));

	navi_request_set_custom_context(request, ctx);
	navi_request_set_process(request, process_list_data);
	navi_upredis_t* redis = navi_request_bind_upredis_ctx(sub,ctx->group,pulllist_after_bpop,ctx,NULL);
	navi_upredis_blpop(redis, ctx->key, 5);

	navi_request_add_timer(request, get_other, ctx, NULL, 1000, true);
	navi_request_add_timer(request, exists_other, ctx, NULL, 1000, false);
	return NAVI_OK;
}

NAVI_MODULE_METHOD(test_redis_proxy,rpush,module,request)
{
	navi_request_t* sub = navi_request_new_sub(request);

	const char* key = navi_http_request_get_arg(request, "key");
	const char* group = navi_http_request_get_arg(request,"group");
	const char* value = navi_http_request_get_arg(request, "value");
	const char** pvalue = &value;
	navi_upredis_t* redis = navi_request_bind_upredis(sub,group,NULL);
	navi_upredis_rpush(redis, key, pvalue, 1);
	return NAVI_OK;
}


