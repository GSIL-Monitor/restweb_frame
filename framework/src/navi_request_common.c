/*
 * navi_iter_impl.c
 *
 *  Created on: 2013-9-5
 *      Author: li.lei
 */
#include <stdlib.h>
#include <unistd.h>
#include "navi_request_impl.h"
#include "navi_list.h"
#include <jansson.h>
#include "navi_inner_util.h"
#include "navi_frame_log.h"

static void quit_reg_chain(navi_request_impl_t* prev_reg)
{
	navi_request_impl_t* main = prev_reg->main;
	navi_griter_mgr_t* mgr = &main->main_data->iter_mgr;
	navi_griter_t* it;
	chain_node_t* link = mgr->using_iter.next;
	chain_node_t* quiting = &prev_reg->cmd_link;
	while(link != &mgr->using_iter) {
		it = (navi_griter_t*)navi_list_data(link,navi_griter_t,link);
		if ( it->ctx == &main->main_data->reg_chain && it->cur == quiting ) {
			it->cur = quiting->next;
		}
		link = link->next;
	}
	navi_list_remove2(quiting);
}

static void quit_reg_tree(navi_request_impl_t* parent) {
	quit_reg_chain(parent);
	navi_request_impl_t* next = parent->child;
	while ( next ) {
		quit_reg_tree(next);
		next = next->next;
	}
}

static void quit_cancel_chain(navi_request_impl_t* prev_cancel)
{
	navi_request_impl_t* main = prev_cancel->main;
	navi_griter_mgr_t* mgr = &main->main_data->iter_mgr;
	navi_griter_t* it;
	chain_node_t* link = mgr->using_iter.next;
	chain_node_t* quiting = &prev_cancel->cmd_link;
	while(link != &mgr->using_iter) {
		it = (navi_griter_t*)navi_list_data(link,navi_griter_t,link);
		if ( it->ctx == &main->main_data->cancel_chain && it->cur == quiting ) {
			it->cur = quiting->next;
		}
		link = link->next;
	}
	navi_list_remove2(quiting);
}

static void recycle_sub(navi_request_impl_t* ri)
{
	navi_request_impl_t* main = ri->main;

	// 处理迭代器
	navi_griter_mgr_t* mgr = &main->main_data->iter_mgr;
	navi_griter_t* it;
	chain_node_t* link = mgr->using_iter.next;
	while(link != &mgr->using_iter) {
		it = (navi_griter_t*)navi_list_data(link,navi_griter_t,link);
		if (  it->cur == ri ) {
			it->cur = ri->next;
		}
		link = link->next;
	}

	// 从父请求的子请求链表中退出
	navi_request_impl_t** pp = NULL;
	navi_request_impl_t* pr = ri->parent;
	if (pr) {
		ri->parent = NULL;

		pp = &pr->child;
		while(*pp != ri) {
			pp = &((*pp)->next);
		}
		*pp = ri->next;
		ri->next = NULL;
	}

	// 回收子请求
	navi_request_impl_t* next = ri->child, *o;
	while (next) {
		o = next;
		next = next->next;
		recycle_sub(o);
	}

	navi_pool_t* sv = ri->cld_dp;
	navi_pool_reset(sv);
	memset(ri, 0x00, sizeof(navi_request_impl_t));
	ri->handle._magic = NAVI_HANDLE_MAGIC;
	ri->main = main;
	ri->cld_dp = sv;
	ri->navi_status = NAVI_REQUEST_STATUS_INVALID;

	navi_list_insert_tail(&main->main_data->recycle_chain,&ri->cmd_link);
}

static json_t* build_default_sub_response(navi_request_t* handle) {
	if (!check_req_h(handle))
		return NULL;

	json_t* ret_js = json_object();
	if (!ret_js) {
		NAVI_SYSERR_LOG();
		return NULL;
	}

	navi_request_impl_t* ri = navi_req_h2i(handle);
	navi_request_impl_t* sub_ri;
	json_t* sub_js = NULL;
	navi_pool_t* pool = ri->cld_dp;

	if (ri->navi_status==NAVI_REQUEST_REGISTED)
		return NULL;

	json_object_set_new(ret_js, "uri", json_string(ri->uri));
	json_t* args_js = NULL;
	void* it = navi_http_request_arg_iter(handle);
	const char* arg_v = NULL;
	const char* arg_k;
	while (it && (arg_k = navi_http_request_arg_iter_next(it, &arg_v))) {
		if (args_js == NULL) {
			args_js = json_object();
			if (!args_js) {
				NAVI_SYSERR_LOG();
				json_decref(ret_js);
				return NULL;
			}
			json_object_set_new(ret_js, "args", args_js);
		}
		json_object_set_new(args_js, arg_k, json_string(arg_v));
	}

	char tm_buf[32];
	snprintf(tm_buf,sizeof(tm_buf),"%.6f",ri->cost_us/(double)1000000);
	json_object_set_new(ret_js, "cost", json_string(tm_buf));

	int httpcode = navi_http_response_get_status(handle);
	const char* status_line = http_status2line( httpcode );
	if ( status_line == NULL) {
		snprintf(tm_buf,sizeof(tm_buf),"%d",httpcode);
		status_line = tm_buf;
	}
	json_object_set_new(ret_js, "http_resp_status",json_string(status_line));

	args_js = NULL;
	it = navi_http_response_header_iter(handle);
	while (it && (arg_k = navi_http_response_header_iter_next(it, &arg_v))) {
		if (args_js == NULL) {
			args_js = json_object();
			if (!args_js) {
				NAVI_SYSERR_LOG();
				json_decref(ret_js);
				return NULL;
			}
			json_object_set_new(ret_js, "http_resp_headers", args_js);
		}
		json_object_set_new(args_js, arg_k, json_string(arg_v));
	}

	const uint8_t* http_body = NULL;
	size_t body_size =navi_http_response_get_body(handle, &http_body);
	bool is_bin = false;

	int i;
	if (!http_body)
		goto ret_children;
	//检查是以字符串文本处理，还是当做二进制数据的base64编码处理

	for (i = 0; i < body_size - 1; i++) {
		if (http_body[i] == 0) {
			is_bin = true;
			break;
		}
	}
	//if (http_body[body_size - 1] != 0)
	//	is_bin = true;

	if (!is_bin) {
		json_object_set_new(ret_js, "http_resp_body",json_string((char*) http_body));
	}
	else {
		char buf[4096];
		char* bs64_buf = buf;
		if (base64_encoded_length(body_size) > 4096) {
			bs64_buf = navi_pool_alloc(pool,base64_encoded_length(body_size));
		}
		if (bs64_buf) {
			body_size = encode_base64((uint8_t*) bs64_buf, http_body,body_size);
			json_object_set_new(ret_js, "http_resp_body_base64",json_string(bs64_buf));
			if (bs64_buf != buf)
				navi_pool_free(pool, bs64_buf);
		}
	}

ret_children:
{
	args_js=NULL;
	sub_ri = ri->child;
	while(sub_ri) {
		sub_js = build_default_sub_response(&sub_ri->handle);
		if (sub_js) {
			if( args_js==NULL )
				args_js = json_array();
			if (args_js)
				json_array_append_new(args_js,sub_js);
		}
		sub_ri = sub_ri->next;
	}
	if (args_js) {
		json_object_set_new(ret_js,"subrequests",args_js);
	}
}
	return ret_js;
}

static void build_default_body(navi_request_t* handle) {
	navi_response_t* resp = navi_request_response_obj(handle);
	navi_request_impl_t* ri = navi_req_h2i(handle);
	json_t* def_js = NULL;
	json_t* sub_arr_js = NULL;
	navi_request_impl_t* sub_ri = ri->child;

	while (sub_ri) {
		json_t* sub_resp_js = build_default_sub_response(&sub_ri->handle);
		if (!sub_resp_js) {
			sub_ri = sub_ri->next;
			continue;
		}

		if (sub_arr_js == NULL)
			sub_arr_js = json_array();
		if (sub_arr_js)
			json_array_append_new(sub_arr_js, sub_resp_js);
		else
			NAVI_SYSERR_LOG();

		sub_ri = sub_ri->next;
	}

	if (sub_arr_js) {
		def_js = json_object();
		if (def_js) {
			json_object_set_new(def_js, "subrequests", sub_arr_js);
			navi_response_set_content(resp, def_js, 0);
		}
		else
			NAVI_SYSERR_LOG();
	}
}

static int build_default_main_response(navi_request_t* handle, void* ctx)
{
	navi_respbody_type_e body_type = navi_request_respbody_type(handle);
	if (body_type == NAVI_RESP_STREAM)
		return NAVI_OK;
	//TODO:返回时类型未设导致500错误，暂时注掉
#if 0
	else if (body_type == NAVI_RESP_UNKNOWN_TYPE) {
		navi_http_response_set_status(handle,500);
		return NAVI_OK;
	}
#endif
	int http_code = navi_http_response_get_status(handle);
	navi_response_t* resp = navi_request_response_obj(handle);
	navi_request_impl_t* ri = navi_req_h2i(handle);
	navi_request_cost_ns(handle);

	if (!resp) {
		navi_http_response_set_status(handle,500);
		return NAVI_OK;
	}
	resp->cost = ri->cost_us / (double) 1000000;

	if (0 != http_code ) {
		if (resp && resp->error.code == NULL_CODE && http_code!=200) {
			char tmp[32];
			const char* sl = http_status2line(http_code);
			if (sl==NULL) {
				snprintf(tmp,sizeof(tmp),"%d",http_code);
				sl = tmp;
			}
			navi_response_set_desc(resp, http_code, "navi frame",sl);
			build_default_body(handle);
		}
	}
	else {
		navi_http_response_set_status(handle, 200);
	}

	if (body_type == NAVI_RESP_BIN)
		return NAVI_OK;
	else if (body_type == NAVI_RESP_FILE)
		return NAVI_OK;

	char* http_resp_body;
	//size_t body_size = navi_http_response_get_body(handle,(const uint8_t**)&http_resp_body);
	//if (body_size) {
	//	return NAVI_OK;
	//}

	// 还未设置navi resp，设置默认响应
	if (resp->error.code == NULL_CODE) {
		navi_response_set_desc(resp, 0, "navi frame", "default navi response");
		build_default_body(handle);
	}

	http_resp_body = navi_response_http_body(resp, 1);
	navi_http_response_set_body(handle, http_resp_body,
	    strlen(http_resp_body) );
	ri->main_data->outbody_navi = 1;
	ri->main_data->outbody_bin = 0;
	ri->main_data->outbody_stream = 0;
	ri->main_data->outbody_file = 0;
	free(http_resp_body);
	return NAVI_OK;
}

