/*
 * navi_upredis.c
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#include "navi_upredis.h"
#include "navi_upgroup_mgr.h"
#include "navi_inner_util.h"
#include "navi_frame_log.h"
#include "navi_up_network.h"

static navi_upreq_parse_status_e nvup_redis_parse_in(navi_upreq_t* up,
    uint8_t* in, size_t sz);

static void nvup_redis_destroy(navi_upreq_t* up);

static void nvup_redis_build_result(navi_upreq_t* up, navi_upreq_result_t* result)
{
	navi_upredis_t* upredis = (navi_upredis_t*)((char*)up -
		offsetof(navi_upredis_t, base));
	if (result->code != NVUP_RESULT_UNSET) {
		if (upredis->process)upredis->process(upredis, result, upredis->ctx);
	}
	else {
		if (upredis->proto == NULL || upredis->proto->pending_stage != redis_stage_done) {
			upredis->base.result.code = NVUP_RESULT_UPIN_PROTO_ERROR;
		}
		else {
			upredis->base.result.code = NVUP_RESULT_SESSION_OK;

			if (upredis->proto2result)
				upredis->proto2result(upredis, &upredis->base.result);

			if (upredis->proto->proto_type == redis_type_error_reply) {
				// 写访问slave redis服务器
				if (strncasecmp(upredis->proto->str_result, "READONLY", 8) == 0 ) {
					upredis->base.result.code = NVUP_RESULT_RW_FAILED; //以读写错误对待
				}
			}
		}

		if (upredis->process)
			upredis->process(upredis, result, upredis->ctx);
	}
	return;
}

navi_upreq_proc_t g_nvup_redis_proc =
{
	nvup_redis_get_policy_key,
	nvup_redis_parse_in,
	nvup_redis_build_result,
	nvup_redis_destroy
};

static void default_proc_redis_result(navi_upredis_t* up, navi_upreq_result_t* res, void* ctx)
{
	navi_request_t* req = navi_upreq_channel(&up->base);
	char buf[1024];
	if (res->code == NVUP_RESULT_SESSION_OK) {
		switch (res->content_type) {
		case NVUP_RESULT_DATA_STRING :
			snprintf(buf, sizeof(buf), "str: %s", res->s);
			break;
		case NVUP_RESULT_DATA_NULL:
			snprintf(buf, sizeof(buf), "nil: nil", res->s);
			break;
		case NVUP_RESULT_DATA_DOUBLE:
			snprintf(buf, sizeof(buf), "double:%f", res->d);
			break;
		case NVUP_RESULT_DATA_ERR:
			snprintf(buf, sizeof(buf), "err:%s", res->s);
			break;
		case NVUP_RESULT_DATA_INT:
			snprintf(buf, sizeof(buf), "int:%lld", res->i);
			break;
		case NVUP_RESULT_DATA_JSON: {
			char* tmp = json_dumps(res->js, JSON_INDENT(2) | JSON_SORT_KEYS | JSON_ENSURE_ASCII );
			snprintf(buf, sizeof(buf), "json: %s", tmp);
			free(tmp);
			break;
		}
		case NVUP_RESULT_DATA_PAIR:
			snprintf(buf, sizeof(buf), "pair: key:%s value:%s", res->pair.k, res->pair.v);
			break;
		case NVUP_RESULT_DATA_HEAP_BIN:
		case NVUP_RESULT_DATA_POOL_BIN: {
			size_t bs64_sz = base64_encoded_length(res->bin.size);
			char* tmp = (char*) malloc(bs64_sz);
			encode_base64(tmp, res->bin.data, res->bin.size);
			snprintf( buf, sizeof(buf), "%s", tmp);
			free(tmp);
			break;
		}
		default:
			snprintf(buf, sizeof(buf), "result processing impl error");
			break;
		}
	}
	else {
		snprintf(buf, sizeof(buf), "session failed. code:%d desc:%s",
			res->code, res->session_err_desc);
	}
	navi_http_response_set_body(req,buf, strlen(buf));
	return;
}


navi_upredis_t* navi_request_bind_upredis_ctx(navi_request_t* binded,
    const char* srv_grp, navi_upredis_proc_result_fp proc, void* ctx,
    navi_upredis_cleanup_ctx_fp cleanup)
{
	navi_pool_t* pool = navi_request_pool(binded);
	navi_upredis_t* obj = (navi_upredis_t*) navi_pool_calloc(pool,1, sizeof(navi_upredis_t));
	if (!obj)
		return NULL;

	obj->base.group_name = navi_pool_strdup(pool, srv_grp);
	obj->base.procs = &g_nvup_redis_proc;
	obj->base.proto = NVUP_PROTO_REDIS;
	obj->base.out_pack = navi_buf_chain_init(pool);
	obj->process = proc?proc:default_proc_redis_result;
	obj->cleanup = cleanup;
	obj->ctx = ctx;

	navi_upgroup_mgr_t* mgr = navi_upgroup_mgr_instance(NULL);
	navi_http_request_set_uri(binded, mgr->gr_driver_path, 0);
	navi_request_bind_upreq(&obj->base, binded);
	return obj;
}

navi_upredis_t* navi_request_bind_upredis_ctx_ext(navi_request_t* binded,
    const char* srv_grp, const char* srv_name, navi_upredis_proc_result_fp proc, void* ctx,
    navi_upredis_cleanup_ctx_fp cleanup)
{
	navi_upredis_t* obj = navi_request_bind_upredis_ctx(binded, srv_grp, proc, ctx, cleanup);
	if (!obj)
		return NULL;

	if (srv_name){
		obj->base.srv_name = navi_request_strdup(binded,srv_name);
	}

	return obj;
}

static void nvup_redis_destroy(navi_upreq_t* up)
{
	navi_upredis_t* up_redis = (navi_upredis_t*) ((char*) up -
	    offsetof(navi_upredis_t, base));
	if (up_redis->cleanup)
		up_redis->cleanup(up_redis, up_redis->ctx);
	if (up_redis->proto)
		nvup_redis_proto_clean(up_redis->proto);
	return;
}

const char* nvup_redis_get_policy_key(navi_upreq_t* up, const char* key)
{
	navi_upredis_t* up_redis = (navi_upredis_t*) ((char*) up -
	    offsetof(navi_upredis_t, base));
	if (0 == strcmp(key, "key")) {
		if (up_redis->cmd.cmd_st == NVUP_REDIS_CMDST_1KEY)
			return up_redis->cmd.s_key->key;
		else if (up_redis->cmd.cmd_st == NVUP_REDIS_CMDST_PUR_MARGS &&
			(0==strcasecmp(up_redis->cmd.cmd, "EVAL") || 0==strcasecmp(up_redis->cmd.cmd, "EVALSHA") )) {
			char** keyspace = navi_array_item(up_redis->cmd.m_args, 2);
			if (keyspace)
				return *keyspace;
			else
				return NULL;
		}
		else
			return NULL;
	}

	return NULL;
}

static navi_upreq_parse_status_e nvup_redis_parse_in(navi_upreq_t* up,
    uint8_t *in, size_t sz)
{
	navi_upredis_t* up_redis = (navi_upredis_t*) ((char*) up -
	    offsetof(navi_upredis_t, base));

	if (up_redis->proto == NULL) {
		up_redis->proto = navi_pool_calloc(up->pool, 1, sizeof(nvup_redis_proto_t));

		if (up_redis->proto == NULL)
			return NVUP_PARSE_STATUS_INVALID;

		if (NAVI_OK != nvup_redis_proto_init(up_redis->proto, up->pool,
		    up->policy.in_proto_buf_sz))
			return NVUP_PARSE_STATUS_INVALID;
	}

	return nvup_redis_proto_parse_in(up_redis->proto, in, sz);
}

void redisproto_get_int_result(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
{
	if (proto->proto_type == redis_type_error_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = proto->str_result;
		result->ess_logic_code = -1;
		return ;
	}
	else if (proto->proto_type != redis_type_num) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not :<NUM> redis integer reply";
		result->ess_logic_code = -1;
		return ;
	}

	result->ess_logic_code = 0;
	result->content_type = NVUP_RESULT_DATA_INT;
	result->i = proto->num_result;
	return ;
}

void redisproto_get_float_from_bulk(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
{
	if (proto->proto_type == redis_type_error_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = proto->str_result;
		result->ess_logic_code = -1;
		return ;
	}
	else if (proto->proto_type != redis_type_single_bulk) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not redis single bulk reply";
		result->ess_logic_code = -1;
		return ;
	}

	if (proto->in_bulks==NULL) { /*$-1*/
		result->ess_logic_code = 0;
		result->content_type = NVUP_RESULT_DATA_NULL;
		return ;
	}

	redis_bulk_t* bk = navi_array_item(proto->in_bulks,0);

	result->ess_logic_code = 0;
	result->content_type = NVUP_RESULT_DATA_DOUBLE;
	result->d = atof(bk->s);
	return ;
}

void upredis_sum2parent_int_result(navi_upredis_t* child, navi_upreq_result_t* noused)
{
	if (child->proto->proto_type != redis_type_num)
		return ;

	navi_request_t* pr_nv = navi_request_get_parent(child->base.bind_channel);
	navi_upreq_result_t* pr_rslt = &(((navi_upreq_t*)pr_nv->ctx_own)->result);

	pr_rslt->content_type = NVUP_RESULT_DATA_INT;
	pr_rslt->i += child->proto->num_result;
	return;
}

void redisproto_get_ok_result_from_status(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
{
	if (proto->proto_type == redis_type_error_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = proto->str_result;
		result->ess_logic_code = -1;
		return ;
	}
	else if (proto->proto_type != redis_type_status_reply){
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not +OK redis status reply";
		result->ess_logic_code = -1;
		return ;
	}

	if (!strcasecmp("OK",proto->str_result))
		result->ess_logic_code = 0;
	else
		result->ess_logic_code = -1;
	result->content_type = NVUP_RESULT_DATA_STRING;
	result->s = proto->str_result;
	return ;
}

void redisproto_get_str_result_from_status(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
{
	if (proto->proto_type == redis_type_error_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = proto->str_result;
		result->ess_logic_code = -1;
		return ;
	}
	else if (proto->proto_type != redis_type_status_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not +<STRING> redis status reply";
		result->ess_logic_code = -1;
		return ;
	}

	result->ess_logic_code = 0;
	result->content_type = NVUP_RESULT_DATA_STRING;
	result->s = proto->str_result;
	return ;
}

void redisproto_get_str_result_from_error(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
{
	if (proto->proto_type == redis_type_error_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = proto->str_result;
		result->ess_logic_code = -1;
		return ;
	}
	else {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not -<STRING> redis error reply";
		result->ess_logic_code = -1;
		return ;
	}

	return ;
}

void redisproto_get_str_result_from_bulk(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
{
	if (proto->proto_type == redis_type_error_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = proto->str_result;
		result->ess_logic_code = -1;
		return ;
	}
	else if (proto->proto_type != redis_type_single_bulk) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not redis single bulk reply";
		result->ess_logic_code = -1;
		return ;
	}

	if (proto->in_bulks==NULL) { /*$-1*/
		result->ess_logic_code = 0;
		result->content_type = NVUP_RESULT_DATA_NULL;
		return ;
	}

	redis_bulk_t* bk = navi_array_item(proto->in_bulks,0);

	result->ess_logic_code = 0;
	result->content_type = NVUP_RESULT_DATA_STRING;
	result->s = bk->s;
	return ;
}

void redisproto_get_pair_from_mbulk(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
{
	if (proto->proto_type == redis_type_error_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = proto->str_result;
		result->ess_logic_code = -1;
		return ;
	}
	else if (proto->proto_type != redis_type_multi_bulk) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not redis multi bulk reply";
		result->ess_logic_code = -1;
		return ;
	}

	if (proto->in_bulks == NULL) /*-1*/
	{
		result->ess_logic_code = 0;
		result->content_type = NVUP_RESULT_DATA_NULL;
		return ;
	}

	if (proto->in_bulks->count != 2) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not redis multi-bulk reply which contains pair";
		result->ess_logic_code = -1;
		return ;
	}

	redis_bulk_t* bk1 = navi_array_item(proto->in_bulks, 0);
	redis_bulk_t* bk2 = navi_array_item(proto->in_bulks, 1);
	if (bk1->bulk_type != redis_type_single_bulk ||
		bk2->bulk_type != redis_type_single_bulk) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not redis multi-bulk reply which contains pair";
		result->ess_logic_code = -1;
		return ;
	}

	result->ess_logic_code = 0;
	result->content_type = NVUP_RESULT_DATA_PAIR;
	result->pair.k = bk1->s;
	result->pair.v = bk2->s;
	return ;
}

void redisproto_get_strs_from_mbulk(nvup_redis_proto_t* proto, navi_upreq_result_t* result)
{
	if (proto->proto_type == redis_type_error_reply) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = proto->str_result;
		result->ess_logic_code = -1;
		return ;
	}
	else if (proto->proto_type != redis_type_multi_bulk) {
		result->content_type = NVUP_RESULT_DATA_ERR;
		result->err = "not redis multi bulk reply";
		result->ess_logic_code = -1;
		return ;
	}

	if (proto->in_bulks == NULL) /*-1*/
	{
		result->ess_logic_code = 0;
		result->content_type = NVUP_RESULT_DATA_NULL;
		return ;
	}

	int pt, i;
	navi_array_part_t* part;
	json_t* js_obj = json_array();
	for (pt=0; pt<proto->in_bulks->part_size; pt++) {
		part = proto->in_bulks->parts[pt];
		if (!part)
			break;

		redis_bulk_t* bulk = (redis_bulk_t*)part->allocs;
		for (i=0; i<part->used; i++,bulk++) {
			if (bulk->bulk_type == redis_type_single_bulk) {
				if (bulk->s)
					json_array_append_new(js_obj, json_string(bulk->s));
				else
					json_array_append_new(js_obj, json_null());
			}
		}
	}

	result->ess_logic_code = 0;
	result->content_type = NVUP_RESULT_DATA_JSON;
	result->js = js_obj;
	return ;
}

void upredis_add2parent_strs_from_mbulk(navi_upredis_t* child, navi_upreq_result_t* noused)
{
	if (child->proto->proto_type != redis_type_multi_bulk)
			return ;

	nvup_redis_proto_t *proto = child->proto;
	navi_request_t* pr_nv = navi_request_get_parent(child->base.bind_channel);
	navi_upreq_result_t* pr_rslt = &(((navi_upreq_t*)pr_nv->ctx_own)->result);

	if (proto->in_bulks == NULL) /*-1*/
	{
		return ;
	}

	json_t* js_obj = NULL;
	if (pr_rslt->content_type != NVUP_RESULT_DATA_JSON) {
		js_obj = json_array();
		pr_rslt->ess_logic_code = 0;
		pr_rslt->content_type = NVUP_RESULT_DATA_JSON;
		pr_rslt->js = js_obj;
	}
	else {
		js_obj = pr_rslt->js;
	}

	int pt, i;
	navi_array_part_t* part;
	for (pt=0; pt<proto->in_bulks->part_size; pt++) {
		part = proto->in_bulks->parts[pt];
		if (!part)
			break;

		redis_bulk_t* bulk = (redis_bulk_t*)part->allocs;
		for (i=0; i<part->used; i++,bulk++) {
			if (bulk->bulk_type == redis_type_single_bulk) {
				if (bulk->s)
					json_array_append_new(js_obj, json_string(bulk->s));
				else
					json_array_append_new(js_obj, json_null());
			}
		}
	}

	return;
}

typedef struct upredis_usr_proc_redirect_s {
	navi_request_process_fp user_process;
	navi_request_process_fp user_cleanup;
	void* user_ctx;
	navi_upredis_proc_result_fp user_proc_result;
} upredis_usr_proc_redirect_t;

static int upredis_reduce_and_process(navi_request_t* nvreq, void* rd_ctx)
{
	navi_upreq_t* upreq = (navi_upreq_t*)nvreq->ctx_own;
	navi_upredis_t* upredis = (navi_upredis_t*)((char*)upreq -
		offsetof(navi_upredis_t, base));

	upredis_usr_proc_redirect_t* redi_ctx = (upredis_usr_proc_redirect_t*)rd_ctx;

	int ret = 0;
	if (redi_ctx->user_proc_result)
		redi_ctx->user_proc_result(upredis, &upredis->base.result, upredis->ctx);

	if (redi_ctx->user_process)
		ret = redi_ctx->user_process(nvreq, redi_ctx->user_ctx);

	return ret;
}

static int upredis_multied_cleanup(navi_request_t* parent, void* rd_ctx)
{
	upredis_usr_proc_redirect_t* redi_ctx = (upredis_usr_proc_redirect_t*)rd_ctx;
	if (redi_ctx->user_cleanup)
		return redi_ctx->user_cleanup(parent, redi_ctx->user_ctx);
	return NAVI_OK;
}

void upredis_result_mr_proc(navi_upredis_t* upredis)
{
	upredis_usr_proc_redirect_t* rdctx = navi_pool_calloc(upredis->base.pool, 1,
		sizeof(upredis_usr_proc_redirect_t));

	rdctx->user_process = upredis->base.bind_channel->process_request;
	rdctx->user_ctx = upredis->base.bind_channel->custom_ctx;
	rdctx->user_cleanup = upredis->base.bind_channel->clean_up;
	rdctx->user_proc_result = upredis->process;

	upredis->process = NULL;

	upredis->base.bind_channel->process_request = upredis_reduce_and_process;
	upredis->base.bind_channel->custom_ctx = rdctx;
	upredis->base.bind_channel->clean_up = upredis_multied_cleanup;
}

int navi_upredis_lua_eval(navi_upredis_t* upreq, const char* keyspace, const navi_upredis_script_t* script)
{
	UPREDIS_PURMARG_CMD(&upreq->cmd, upreq->base.pool, "EVAL", 3 /*script 1 keyspace*/+ script->args_sz);
	char** parg = navi_array_push(upreq->cmd.m_args);
	*parg = script->script;
	parg = navi_array_push(upreq->cmd.m_args);
	*parg = "1";
	parg = navi_array_push(upreq->cmd.m_args);
	*parg = (char*)keyspace;

	int i;
	for (i=0; i<script->args_sz; i++) {
		parg = navi_array_push(upreq->cmd.m_args);
		*parg = script->args[i];
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	return navi_upreq_init(&upreq->base);
}

int navi_upredis_lua_evalsha(navi_upredis_t* upreq, const char* keyspace, const navi_upredis_script_t* script)
{
	UPREDIS_PURMARG_CMD(&upreq->cmd, upreq->base.pool, "EVALSHA", 3 /*script 1 keyspace*/+ script->args_sz);
	char** parg = navi_array_push(upreq->cmd.m_args);
	*parg = script->script_sha;
	parg = navi_array_push(upreq->cmd.m_args);
	*parg = "1";
	parg = navi_array_push(upreq->cmd.m_args);
	*parg = (char*)keyspace;

	int i;
	for (i=0; i<script->args_sz; i++) {
		parg = navi_array_push(upreq->cmd.m_args);
		*parg = script->args[i];
	}

	nvup_redis_cmd_2outpack(&upreq->cmd, upreq->base.out_pack);
	return navi_upreq_init(&upreq->base);
}

//在group的server的address可获取时，将脚本load到服务端，并返回脚本的标记sha
int navi_upredis_lua_load(const char* group, const char* script, char** sha)
{
	navi_upgroup_mgr_t* mgr = navi_upgroup_mgr_instance(NULL);
	if (!mgr) return -1;
	navi_upgroup_t* grp = navi_upgroup_mgr_get_group(mgr, group);
	if (!grp){
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s notexist when lua-load",
			group);
		return -1;
	}

	navi_upserver_t* servers[100];
	navi_upserver_t** psers = servers;
	size_t server_sz = navi_upgroup_get_servers(grp, NULL, 100);
	if (server_sz > 100) {
		psers = (navi_upserver_t**)malloc(sizeof(navi_upserver_t*)*server_sz);
	}
	navi_upgroup_get_servers(grp, psers, server_sz);
	navi_pool_t* pool = navi_pool_create(4096);

	navi_upserver_t* pser;
	nvup_redis_proto_t proto;
	char recv_buf[1024];
	nvup_redis_proto_init(&proto, pool, 512);
	int i,ret;
	char* ret_sha = NULL;
	for (i=0; i<server_sz; i++) {
		pser = psers[i];
		ret = -1;
		struct sockaddr_storage addr;
		if (pser->procs->get_addr) {
			ret = pser->procs->get_addr(&pser->impl, &addr);
		}
		if ( ret != NAVI_OK) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s getaddress failed when lua-load",
				group, pser->server_name);
			nvup_redis_proto_clean(&proto);
			navi_pool_destroy(pool);
			if (psers != servers) free(psers);
			if (ret_sha)free(ret_sha);
			return NAVI_FAILED;
		}

		nvup_redis_cmd_t cmd;
		navi_buf_chain_t* chain = navi_buf_chain_init(pool);
		UPREDIS_PURMARG_CMD(&cmd, pool, "SCRIPT", 2);
		char** pp = navi_array_push(cmd.m_args);
		*pp = "LOAD";
		pp = navi_array_push(cmd.m_args);
		*pp = (char*)script;
		nvup_redis_cmd_2outpack((&cmd), (chain));

		int fd = navi_up_socket_create((struct sockaddr*)&addr);
		if ( fd == -1) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s create_socket when lua-load",
				group, pser->server_name);
			nvup_redis_proto_clean(&proto);
			navi_pool_destroy(pool);
			if (psers != servers) free(psers);
			if (ret_sha)free(ret_sha);
			return NAVI_FAILED;
		}

		navi_buf_node_t* buf_node = chain->head;
		while( buf_node ) {
			ret = navi_up_send(fd, buf_node->buf, buf_node->size);
			if ( ret != buf_node->size ) {
				navi_up_socket_close(fd);
				nvup_redis_proto_clean(&proto);
				navi_pool_destroy(pool);
				if (psers != servers) free(psers);
				if (ret_sha)free(ret_sha);
				NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s send request failed when lua-load",
					group, pser->server_name);
				return NAVI_FAILED;
			}
			buf_node = buf_node->next;
		}

		nvup_redis_proto_reset(&proto);

		ret = 0;
		do {
			ret = navi_up_recv(fd, recv_buf, sizeof(recv_buf));
			if ( ret > 0 ) {
				nvup_redis_proto_parse_in(&proto, (uint8_t*)recv_buf, ret);
			}
		} while(ret!=0 && ret!=-1 && proto.pending_stage!=redis_stage_done);

		navi_up_socket_close(fd);

		const char* check_sha = NULL;
		if ( proto.pending_stage == redis_stage_done) {
			if ( proto.proto_type == redis_type_single_bulk ) {
				redis_bulk_t* bk = navi_array_item(proto.in_bulks,0);
				check_sha = bk->s;
			}
		}

		if (check_sha == NULL) {
			nvup_redis_proto_clean(&proto);
			navi_pool_destroy(pool);
			if (psers != servers) free(psers);
			if (ret_sha)free(ret_sha);
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s read response failed when lua-load",
				group, pser->server_name);
			return NAVI_FAILED;
		}

		if ( ret_sha == NULL) {
			ret_sha = strdup(check_sha);
		}
		else {
			if ( strcasecmp(ret_sha, check_sha) ) {
				nvup_redis_proto_clean(&proto);
				navi_pool_destroy(pool);
				if (psers != servers) free(psers);
				if (ret_sha)free(ret_sha);
				NAVI_FRAME_LOG(NAVI_LOG_ERR, "group:%s server:%s getaddress failed when lua-load",
					group, pser->server_name);
				return NAVI_FAILED;
			}
		}
	}

	nvup_redis_proto_clean(&proto);
	navi_pool_destroy(pool);
	if (psers != servers)free(psers);


	if (sha)
		*sha = ret_sha;
	else if (ret_sha)
		free(ret_sha);

	return NAVI_OK;
}

int navi_redis_instance_lua_load(const struct sockaddr* addr, const char* script, char** sha)
{
	nvup_redis_cmd_t cmd;
	navi_pool_t* pool = navi_pool_create(4096);

	nvup_redis_proto_t proto;
	char recv_buf[1024];
	nvup_redis_proto_init(&proto, pool, 512);
	int i,ret;
	navi_buf_chain_t* chain = navi_buf_chain_init(pool);
	UPREDIS_PURMARG_CMD(&cmd, pool, "SCRIPT", 2);
	char** pp = navi_array_push(cmd.m_args);
	*pp = "LOAD";
	pp = navi_array_push(cmd.m_args);
	*pp = (char*)script;
	nvup_redis_cmd_2outpack((&cmd), (chain));

	int fd = navi_up_socket_create(addr);
	if ( fd == -1) {
		nvup_redis_proto_clean(&proto);
		navi_pool_destroy(pool);
		return NAVI_FAILED;
	}

	navi_buf_node_t* buf_node = chain->head;
	while( buf_node ) {
		ret = navi_up_send(fd, buf_node->buf, buf_node->size);
		if ( ret != buf_node->size ) {
			navi_up_socket_close(fd);
			nvup_redis_proto_clean(&proto);
			navi_pool_destroy(pool);
			return NAVI_FAILED;
		}
		buf_node = buf_node->next;
	}

	ret = 0;
	do {
		ret = navi_up_recv(fd, recv_buf, sizeof(recv_buf));
		if ( ret > 0 ) {
			nvup_redis_proto_parse_in(&proto, (uint8_t*)recv_buf, ret);
		}
	} while(ret!=0 && ret!=-1 && proto.pending_stage!=redis_stage_done);

	navi_up_socket_close(fd);

	const char* check_sha = NULL;
	if ( proto.pending_stage == redis_stage_done) {
		if ( proto.proto_type == redis_type_single_bulk ) {
			redis_bulk_t* bk = navi_array_item(proto.in_bulks,0);
			check_sha = bk->s;
		}
	}

	if (check_sha)
		*sha = strdup(check_sha);
	else
		*sha = NULL;

	nvup_redis_proto_clean(&proto);
	navi_pool_destroy(pool);
	return check_sha!= NULL ? 0 : -1;
}
