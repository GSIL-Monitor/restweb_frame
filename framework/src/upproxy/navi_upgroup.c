/*
 * navi_upgroup.c
 *
 *  Created on: 2013-12-11
 *      Author: li.lei
 */

#include "navi_common_define.h"
#include "navi_upgroup.h"
#include "navi_upgroup_mgr.h"
#include "navi_frame_log.h"
#include "navi_list.h"
#include "navi_upgroup_policy_rest.h"
#include <jansson.h>
#include <dlfcn.h>

#define NVUP_CONF_GNAME "group_name"
#define NVUP_CONF_GTYPE "group_policy"
#define NVUP_CONF_GPROTO "group_protocol"
#define NVUP_CONF_GSO_NAME "group_policy_so_name"
#define NVUP_CONF_GSETTING_CNN_TO "connect_timeout_ms"
#define NVUP_CONF_GSETTING_RW_TO "rw_timeout_ms"
#define NVUP_CONF_GSETTING_POOL_SZ "idle_pool_max"
#define NVUP_CONF_GSETTING_POOL_IDLE_TO "idle_timeout_ms"
#define NVUP_CONF_GSERVERS "servers"

#define NVUP_GROUP_OBJ_SIZE (sizeof(navi_upgroup_t)+0x1000)

navi_upgroup_t* navi_upgroup_init(const char* config_path, void* mgr)
{
	if (!config_path || !mgr)
		return NULL;

	navi_upgroup_mgr_t* grp_mgr = (navi_upgroup_mgr_t*)mgr;

	json_error_t js_err;
	void* js_it;
	const char* conf_sv;
	char tmp_path[1024];
	json_t* js_config = json_load_file(config_path, &js_err);
	if (!js_config) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "load upgroup json failed:%s line:%d. %s", config_path, js_err.line, js_err.text);
		return NULL;
	}
	json_t* je = json_object_get(js_config, NVUP_CONF_GNAME);
	if (!je || !json_is_string(je) || strlen(json_string_value(je)) == 0) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
			"upgroup config: %s is absent. Conf:%s.", NVUP_CONF_GNAME, config_path);
		json_decref(js_config);
		return NULL;
	}

	const char* grp_name = json_string_value(je);

	if (grp_mgr->groups) {
		if (navi_hash_get_gr(grp_mgr->groups, grp_name)) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR,
				"upgroup name duplicated: %s . Conf:%s.", grp_name, config_path);
			json_decref(js_config);
			return NULL;
		}
	}

	struct stat stbuf;
	stat(config_path, &stbuf);

	navi_upgroup_t* obj = (navi_upgroup_t*) malloc(NVUP_GROUP_OBJ_SIZE);
	if (!obj)
		return NULL;
	memset(obj, 0x00, sizeof(navi_upgroup_t));
	navi_pool_init(obj->pool, obj, 0x1000);
	obj->mgr = grp_mgr;
	obj->c.config = js_config;
	obj->c.last_modify = stbuf.st_mtime;
	if (0 < navi_rpath_2abs(config_path, tmp_path, sizeof(tmp_path))) {
		obj->c.config_path = navi_pool_strdup(obj->pool, tmp_path);
	}
	else
		obj->c.config_path = navi_pool_strdup(obj->pool, config_path);
	obj->i.impl.group = obj;
	obj->group_name = navi_pool_strdup(obj->pool, grp_name);

	je = json_object_get(js_config, NVUP_CONF_GPROTO);
	if (!je || !json_is_string(je) || strlen(json_string_value(je)) == 0) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "upgroup config: %s is absent. Conf:%s.", NVUP_CONF_GPROTO, config_path);
		goto failed;
	}
	conf_sv = json_string_value(je);
	if (0 == strcasecmp(conf_sv, "http")) {
		obj->proto = NVUP_PROTO_HTTP;
	}
	else if (0 == strcasecmp(conf_sv, "navi")) {
		obj->proto = NVUP_PROTO_NAVI;
	}
	else if (0 == strcasecmp(conf_sv, "redis")) {
		obj->proto = NVUP_PROTO_REDIS;
	}
	else {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "upgroup config: %s. Unknown protocol. Conf:%s.", NVUP_CONF_GPROTO, config_path);
		goto failed;
	}

	je = json_object_get(js_config, NVUP_CONF_GTYPE);
	if (!je || !json_is_string(je) || strlen(json_string_value(je)) == 0) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "upgroup config: %s is absent. Conf:%s.", NVUP_CONF_GTYPE, config_path);
		goto failed;
	}

	obj->policy_name = navi_pool_strdup(obj->pool, json_string_value(je));

	je = json_object_get(js_config, NVUP_CONF_GSO_NAME);
	if (je && json_is_string(je) && strlen(json_string_value(je))) {
		const char* so_nm = json_string_value(je);
		if (grp_mgr && grp_mgr->policy_so_dir && !strchr(so_nm, '/')) {
			snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
			    grp_mgr->policy_so_dir, so_nm);
		}
		else if (strchr(so_nm, '/')) { //是一个路径
			if (0 >= navi_rpath_2abs(so_nm, tmp_path, sizeof(tmp_path))) {
				tmp_path[0] = 0;
				strncat(tmp_path, so_nm, sizeof(tmp_path) - 1);
			}
		}
		else { //只是一个动态库名字
			tmp_path[0] = 0;
			strncat(tmp_path, so_nm, sizeof(tmp_path) - 1);
		}
	}

	if (strlen(tmp_path) == 0) {
		if (grp_mgr && grp_mgr->policy_so_dir) {
			snprintf(tmp_path, sizeof(tmp_path), "%s/lib%s.so",
			    grp_mgr->policy_so_dir, obj->policy_name);
		}
		else {
			snprintf(tmp_path, sizeof(tmp_path), "lib%s.so", obj->policy_name);
		}
	}

	void* so_handle = dlopen(tmp_path, RTLD_LAZY);
	if (!so_handle) {
		//NAVI_SYSERR_LOG("load so failed:");
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "load upgroup policy so failed:%s", dlerror());
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "load upgroup policy so: %s failed. Conf:%s", tmp_path, config_path);
		goto failed;
	}
	obj->i.so_handle = so_handle;

	snprintf(tmp_path, sizeof(tmp_path), "navi_upgroup_policy_%s_init",
	    obj->policy_name);
	obj->i.procs.init = dlsym(obj->i.so_handle, tmp_path);
	if (!obj->i.procs.init) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "Policy group:%s's %s function is null. Conf:%s", obj->group_name,
		    tmp_path, obj->c.config_path);
		goto failed;
	}

	snprintf(tmp_path, sizeof(tmp_path), "navi_upgroup_policy_%s_rebuild",
		    obj->policy_name);
	obj->i.procs.rebuild = dlsym(obj->i.so_handle, tmp_path);

	snprintf(tmp_path, sizeof(tmp_path), "navi_upgroup_policy_%s_resolve",
	    obj->policy_name);
	obj->i.procs.resolve_server = dlsym(obj->i.so_handle, tmp_path);
	if (!obj->i.procs.resolve_server) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "Policy group:%s's %s function is null. Conf:%s", obj->group_name,
		    tmp_path, obj->c.config_path);
		goto failed;
	}

	snprintf(tmp_path, sizeof(tmp_path), "navi_upgroup_policy_%s_query",
	    obj->policy_name);
	obj->i.procs.query = dlsym(obj->i.so_handle, tmp_path);
	if (!obj->i.procs.query) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO,
		    "Policy group:%s's %s function is null. Conf:%s", obj->group_name,
		    tmp_path, obj->c.config_path);
	}

	snprintf(tmp_path, sizeof(tmp_path), "navi_upgroup_policy_%s_destroy",
	    obj->policy_name);
	obj->i.procs.destroy = dlsym(obj->i.so_handle, tmp_path);
	if (!obj->i.procs.destroy) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "Policy group:%s's %s function is null. Conf:%s", obj->group_name,
		    tmp_path, obj->c.config_path);
		goto failed;
	}

	// server policy init可以为空，表示该group不需要upserver持有策略相关数据
	snprintf(tmp_path, sizeof(tmp_path), "navi_upserver_policy_%s_init",
	    obj->policy_name);
	obj->i.procs.server_policy_init = dlsym(obj->i.so_handle, tmp_path);
	if (obj->i.procs.server_policy_init) {
		// 只有在upserver policy init非空时，才需要有对应的destroy，且destroy还是可以为空
		snprintf(tmp_path, sizeof(tmp_path), "navi_upserver_policy_%s_destroy",
		    obj->policy_name);
		obj->i.procs.server_policy_destroy = dlsym(obj->i.so_handle, tmp_path);
	}

	obj->settings.conn_timeout_ms = 200;
	obj->settings.rw_timeout_ms = 200;
	je = json_object_get(js_config, NVUP_CONF_GSETTING_CNN_TO);
	if (je && json_is_integer(je)) {
		int v = json_integer_value(je);
		if (v > 0) {
			if (v > 30000)
				v = 30000;
			obj->settings.conn_timeout_ms = v;
		}
		else if (v == 0)
			obj->settings.conn_timeout_ms = 0xffffffff;
	}

	je = json_object_get(js_config, NVUP_CONF_GSETTING_RW_TO);
	if (je && json_is_integer(je)) {
		int v = json_integer_value(je);
		if (v > 0) {
			if (v > 30000)
				v = 30000;
			obj->settings.rw_timeout_ms = v;
		}
		else if (v == 0)
			obj->settings.rw_timeout_ms = 0xffffffff;
	}

	je = json_object_get(js_config, NVUP_CONF_GSETTING_POOL_SZ);
	if (je && json_is_integer(je)) {
		int v = json_integer_value(je);
		if (v > 0) {
			if (v > 1024)
				v = 1024;
			obj->settings.idle_pool_size = v;
			obj->settings.max_idle_ms = 300000; //5 minutes
		}
	}

	je = json_object_get(js_config, NVUP_CONF_GSETTING_POOL_IDLE_TO);
	if (je && json_is_integer(je) && obj->settings.idle_pool_size > 0) {
		int v = json_integer_value(je);
		if (v > 0) {
			if (v < 1000)
				v = 1000;
			obj->settings.max_idle_ms = v;
		}
	}

	je = json_object_get(js_config, NVUP_CONF_GSERVERS);
	if (!je || !json_is_object(je)) {
		// 可以是不通过servers配置来增加upserver，而是在policy的init调用中，
		// 会create upserver
		goto final;
	}

	js_it = json_object_iter(je);
	while (js_it) {
		const char* srv_name = json_object_iter_key(js_it);
		json_t* js_srv = json_object_iter_value(js_it);
		if (json_is_object(js_srv)) {
			navi_upserver_t* srv_obj = navi_upserver_create(obj, srv_name,js_srv);
			if (!srv_obj) {
				goto failed;
			}
		}
		js_it = json_object_iter_next(je, js_it);
	}

final:
	//初始化policy group
	{
		int ret = (obj->i.procs.init)(&obj->i.impl, obj->c.config);
		if (ret != NAVI_OK) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR,
			    "policy group:%s init failed.policy name:%s",
			    obj->group_name, obj->policy_name);
			goto failed;
		}
	}

	return obj;

failed:
	navi_upgroup_destroy(obj);
	return NULL;
}

navi_upgroup_t* navi_upgroup_create(const char* grp_name, navi_upreq_proto_type_e proto, 
	int connect_timeout_ms,   int rw_timeout_ms, int idle_pool_max, int idle_timeout_ms){
	if (!grp_name)
		return NULL;

	navi_upgroup_mgr_t* grp_mgr = navi_upgroup_mgr_instance(NULL);
	navi_upgroup_t*  obj = navi_upgroup_mgr_get_group(grp_mgr, grp_name);

	if (obj != NULL){
		return obj;
	}
	
	obj = (navi_upgroup_t*) malloc(NVUP_GROUP_OBJ_SIZE);
	if (!obj)
		return NULL;
	memset(obj, 0x00, sizeof(navi_upgroup_t));
	navi_pool_init(obj->pool, obj, 0x1000);
	obj->mgr = grp_mgr;
	obj->i.impl.group = obj;
	obj->group_name = navi_pool_strdup(obj->pool, grp_name);
	obj->proto = proto;

	obj->policy_name = "rest";

	obj->i.procs.init = navi_upgroup_policy_rest_init;

	obj->i.procs.resolve_server = navi_upgroup_policy_rest_resolve;

	/*obj->i.procs.query = navi_upgroup_policy_rest_query;*/

	obj->i.procs.destroy = navi_upgroup_policy_rest_destroy;

/*	obj->i.procs.server_policy_init =navi_upserver_policy_rest_init;
	obj->i.procs.server_policy_init =navi_upserver_policy_rest_destroy;*/

	obj->settings.conn_timeout_ms = 200;
	obj->settings.rw_timeout_ms = 200;
	if (connect_timeout_ms > 0) {
		if (connect_timeout_ms > 30000)
			connect_timeout_ms = 30000;
		obj->settings.conn_timeout_ms = connect_timeout_ms;
	}
	else if (connect_timeout_ms== 0){
			obj->settings.conn_timeout_ms = 0xffffffff;
	}

	if (rw_timeout_ms > 0) {
		if (rw_timeout_ms > 30000)
			rw_timeout_ms = 30000;
		obj->settings.rw_timeout_ms = rw_timeout_ms;
	}
	else if (rw_timeout_ms == 0){
		obj->settings.rw_timeout_ms = 0xffffffff;
	}

	if (idle_pool_max > 0) {
		if (idle_pool_max > 1024)
			idle_pool_max = 1024;
		obj->settings.idle_pool_size = idle_pool_max;
		obj->settings.max_idle_ms = 300000; //5 minutes
	}

	if (obj->settings.idle_pool_size > 0) {
		if (idle_timeout_ms > 0) {
			if (idle_timeout_ms < 1000)
				idle_timeout_ms = 1000;
			obj->settings.max_idle_ms = idle_timeout_ms;
		}
	}

final:
	//初始化policy group
	{
		int ret = (obj->i.procs.init)(&obj->i.impl, obj->c.config);
		if (ret != NAVI_OK) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR,
			    "policy group:%s init failed.policy name:%s",
			    obj->group_name, obj->policy_name);
			goto failed;
		}
	}

	navi_hash_set_gr(grp_mgr->groups, obj->group_name, obj);
		
	return obj;

	failed:
	navi_upgroup_destroy(obj);
	return NULL;
}

void navi_upgroup_destroy(navi_upgroup_t* grp)
{
	if (grp->i.procs.destroy)
		(grp->i.procs.destroy)(&grp->i.impl);

	if (grp->s.hash) {
		void* it = navi_hash_iter(grp->s.hash);
		navi_hent_t* e;
		while ((e=navi_hash_iter_next(it))) {
			navi_upserver_t* srv_obj = (navi_upserver_t*)e->v;
			e->v = NULL;
			navi_upserver_destroy(srv_obj);
		}
		navi_hash_iter_destroy(it);
	}

	if (grp->c.config)
		json_decref(grp->c.config);

	navi_pool_destroy(grp->pool);
}

navi_upserver_t* navi_upgroup_get_server(navi_upgroup_t* grp, const char* nm)
{
	if (!grp || grp->s.hash == NULL) return NULL;
	return (navi_upserver_t*)navi_hash_get_gr(grp->s.hash, nm);
}

size_t navi_upgroup_get_servers(navi_upgroup_t* grp, navi_upserver_t** srv, size_t sz)
{
	if (!grp) return 0;
	if (!srv)
		return grp->s.hash->used;

	sz = grp->s.hash->used > sz ? sz : grp->s.hash->used;
	int i;
	chain_node_t* nd = grp->s.hash->list_link.next;
	for (i=0; i<sz && nd!=&grp->s.hash->list_link;  i++,nd=nd->next) {
		navi_hent_t* e = (navi_hent_t*)navi_list_data(nd,navi_hent_t,list_link);
		srv[i] = (navi_upserver_t*)e->v;
	}
	return grp->s.hash->used;
}

int navi_upgroup_resolve_upreq(navi_upgroup_t* grp, navi_upreq_t* req,
    navi_upreq_policy_t* policy)
{
	if (req->proto != grp->proto) {
		navi_upreq_error_lt(req, NVUP_RESULT_CLI_ERROR, -1,
			"upgroup protocol unmatched");
		return NAVI_INNER_ERR;
	}

	navi_upserver_t* hit_srv = (grp->i.procs.resolve_server)(&grp->i.impl, req);
	if (!hit_srv) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "upgroup:%s resolve server failed",
			grp->group_name);
		req->result.code = NVUP_RESULT_POLICY_UNRESOLVE;
		return NAVI_INNER_ERR;
	}

	if (0 != (hit_srv->procs->get_addr)(&hit_srv->impl, (struct sockaddr_storage*)&policy->peer_addr)) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "upserver:%s of group:%s unresolved or unreachable",
			grp->group_name,hit_srv->server_name);
		navi_upreq_error_lt(req, NVUP_RESULT_POLICY_UNRESOLVE, -1,
			"selected server's address is undetermind");
		return NAVI_INNER_ERR;
	}
	else {
		//req处理期间，可能发生配置刷新
		policy->server_name = navi_pool_strdup(req->pool, hit_srv->server_name);
		policy->cnn_timeout_ms = hit_srv->settings.conn_timeout_ms;
		policy->rw_timeout_ms = hit_srv->settings.rw_timeout_ms;
		policy->in_proto_buf_sz = 1024;
		return 0;
	}

}

int navi_upgroup_policy_query(navi_upgroup_t* grp, nvup_policy_inkeys_t* inkeys,
	navi_upreq_policy_t* result)
{
	if ( !grp || !inkeys || !result)
		return NAVI_ARG_ERR;
	if ( grp->i.procs.query == NULL ) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "group:%s do not have query handler");
		return NAVI_INNER_ERR;
	}
	navi_upserver_t* hit_srv = (grp->i.procs.query)(&grp->i.impl,inkeys,result);
	if (!hit_srv) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "upgroup:%s resolve server failed",
			grp->group_name);
		return NAVI_INNER_ERR;
	}

	if (0 != (hit_srv->procs->get_addr)(&hit_srv->impl, (struct sockaddr_storage*)&result->peer_addr)) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "upserver:%s of group:%s unresolved or unreachable",
			grp->group_name,hit_srv->server_name);
		return NAVI_INNER_ERR;
	}
	else {
		result->server_name = hit_srv->server_name;
		result->cnn_timeout_ms = hit_srv->settings.conn_timeout_ms;
		result->rw_timeout_ms = hit_srv->settings.rw_timeout_ms;
		result->in_proto_buf_sz = 1024;
		return 0;
	}
	return 0;
}
