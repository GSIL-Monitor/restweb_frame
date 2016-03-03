/*
 * navi_upserver.c
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#include "navi_upserver.h"
#include "navi_upgroup.h"
#include "navi_upgroup_mgr.h"
#include "navi_frame_log.h"
#include "navi_upserver_single.h"
#include "navi_upserver_redis_rs.h"
#include "navi_upserver_local.h"

static navi_upserver_procs_t* nvup_srv_type2procs(const char* name);

#define NVUP_SRV_OBJ_SIZE (sizeof(navi_upserver_t)+0x1000)

#define NVUP_CONF_GSETTING_CNN_TO "connect_timeout_ms"
#define NVUP_CONF_GSETTING_RW_TO "rw_timeout_ms"
#define NVUP_CONF_GSETTING_POOL_SZ "idle_pool_max"
#define NVUP_CONF_GSETTING_POOL_IDLE_TO "idle_timeout_ms"

#define NVUP_CONF_GSRV_TYPE "server_type"

navi_upserver_t* navi_upserver_create(void* grp, const char* srv_name, json_t* cfg)
{
	navi_upgroup_t* upgroup = (navi_upgroup_t*) grp;
	navi_upserver_t* obj = (navi_upserver_t*) malloc(NVUP_SRV_OBJ_SIZE);
	json_t* je;
	if (!obj) {
		NAVI_SYSERR_LOG();
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "memory error when create upserver:%s of group:%s",
		    srv_name, upgroup->group_name);
		return NULL;
	}


	const char* type = NULL;
	navi_pool_init(obj->pool, obj, 0x1000);
	memset(obj, 0x00, sizeof(navi_upserver_t));


	obj->server_name = navi_pool_strdup(obj->pool, srv_name);
	obj->settings = upgroup->settings;
	obj->group = upgroup;
	obj->impl.upserver = obj;
	obj->config = json_deep_copy(cfg);
	obj->policy_settings.init = upgroup->i.procs.server_policy_init;
	obj->policy_settings.destroy = upgroup->i.procs.server_policy_destroy;

	je = json_object_get(cfg, NVUP_CONF_GSRV_TYPE);
	if ( json_is_string(je) ) {
		type = json_string_value(je);
	}

	if ( !type || strlen(type)==0 ) {
		NAVI_FRAME_LOG(NAVI_LOG_NOTICE,
			"empty server_type:%s of upserver:%s of group:%s",
			type, srv_name, upgroup->group_name);
		type = NULL;
	}
	obj->procs = nvup_srv_type2procs(type);

	if (obj->procs == NULL) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "invalid server_type:%s of upserver:%s of group:%s",
		    type, srv_name, upgroup->group_name);
		goto failed;
	}

	je = json_object_get(cfg, NVUP_CONF_GSETTING_CNN_TO);
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

	je = json_object_get(cfg, NVUP_CONF_GSETTING_RW_TO);
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

	je = json_object_get(cfg, NVUP_CONF_GSETTING_POOL_SZ);
	if (je && json_is_integer(je)) {
		int v = json_integer_value(je);
		if (v > 0) {
			if (v > 1024)
				v = 1024;
			obj->settings.idle_pool_size = v;
			obj->settings.max_idle_ms = 300000; //5 minutes
		}
	}

	je = json_object_get(cfg, NVUP_CONF_GSETTING_POOL_IDLE_TO);
	if (je && json_is_integer(je) && obj->settings.idle_pool_size > 0) {
		int v = json_integer_value(je);
		if (v > 0) {
			if (v < 1000)
				v = 1000;
			obj->settings.max_idle_ms = v;
		}
	}

	if (0 != (obj->procs->init)(&obj->impl, cfg)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "init upserver:%s of group:%s failed",
		    type, srv_name, upgroup->group_name);
		goto failed;
	}

	if (0 != obj->policy_settings.init(obj, obj->config)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "policy data init for upserver:%s of group:%s failed",
		    type, srv_name, upgroup->group_name);
		goto failed;
	}

	if (upgroup->s.hash == NULL) {
		upgroup->s.hash = navi_hash_init(upgroup->pool);
	}

	if (!upgroup->s.hash) {
		NAVI_SYSERR_LOG();
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "memory error when create upserver:%s of group:%s",
		    srv_name, upgroup->group_name);
		goto failed;
	}

	if (navi_hash_get_gr(upgroup->s.hash, srv_name)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "upserver:%s of group:%s already exists",
		    srv_name, upgroup->group_name);
		goto failed;
	}

	if (0 > navi_hash_set_gr(upgroup->s.hash, srv_name, obj)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "memory error when create upserver:%s of group:%s",
		    srv_name, upgroup->group_name);
		goto failed;
	}

	return obj;

failed:
	navi_upserver_destroy(obj);
	return NULL;
}

navi_upserver_t* navi_upserver_add(const char * grp_name, const char* host, uint16_t port)
{
	if (grp_name == NULL || host == NULL){
		return NULL;
	}
	char srv_name[128] ={0};
	snprintf(srv_name, sizeof(srv_name), "%s:%d", host, port);
	
	navi_upgroup_mgr_t* grp_mgr = navi_upgroup_mgr_instance(NULL);
	navi_upgroup_t*  upgroup = navi_upgroup_mgr_get_group(grp_mgr, grp_name);
	if (upgroup == NULL){
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "group:%s not exist when add upserver:%s ",
		    grp_name, srv_name);
		return NULL;
	}

	navi_upserver_t* obj = navi_upgroup_get_server(upgroup, srv_name);
	if (obj) {
		return obj; 
	}

	obj = (navi_upserver_t*) malloc(NVUP_SRV_OBJ_SIZE);
	if (!obj) {
		NAVI_SYSERR_LOG();
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "memory error when create upserver:%s of group:%s",
		    srv_name, upgroup->group_name);
		return NULL;
	}

	const char* type = NULL;
	navi_pool_init(obj->pool, obj, 0x1000);
	memset(obj, 0x00, sizeof(navi_upserver_t));

	obj->server_name = navi_pool_strdup(obj->pool, srv_name);
	obj->settings = upgroup->settings;
	obj->group = upgroup;
	obj->impl.upserver = obj;
	obj->policy_settings.init = upgroup->i.procs.server_policy_init;
	obj->policy_settings.destroy = upgroup->i.procs.server_policy_destroy;

	obj->procs = nvup_srv_type2procs(NULL);

	json_t* cfg = json_object();
	json_object_set_new(cfg, "host", json_string(host));
	json_object_set_new(cfg, "port", json_integer(port));
	if (0 != (obj->procs->init)(&obj->impl, cfg)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "init upserver:%s of group:%s failed",
		    srv_name, upgroup->group_name);
		goto failed;
	}

	json_decref(cfg);
	
	/*if (0 != obj->policy_settings.init(obj, obj->config)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "policy data init for upserver:%s of group:%s failed",
		     srv_name, upgroup->group_name);
		goto failed;
	}*/

	if (upgroup->s.hash == NULL) {
		upgroup->s.hash = navi_hash_init(upgroup->pool);
	}

	if (!upgroup->s.hash) {
		NAVI_SYSERR_LOG();
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "memory error when create upserver:%s of group:%s",
		    srv_name, upgroup->group_name);
		goto failed;
	}

	if (0 > navi_hash_set_gr(upgroup->s.hash, srv_name, obj)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "memory error when create upserver:%s of group:%s",
		    srv_name, upgroup->group_name);
		goto failed;
	}

	return obj;

failed:
	navi_upserver_destroy(obj);
	return NULL;
}

void navi_upserver_destroy(navi_upserver_t* obj)
{
	if (!obj)
		return;
	navi_upgroup_t* grp = (navi_upgroup_t*) obj->group;
	if (grp) {
		navi_hash_del(grp->s.hash, obj->server_name);
		obj->group = NULL;
	}

	if (obj->policy_settings.destroy) {
		obj->policy_settings.destroy(obj->policy_settings.data);
	}
	if (obj->procs && obj->procs->destroy)
		obj->procs->destroy(&obj->impl);

	if (obj->config)
		json_decref(obj->config);

	if (g_rs_servers != NULL){
		char srv_key[256] = {0};
		char *p = srv_key;
		size_t sz = snprintf(p, sizeof(srv_key), "%s:%s",grp->group_name, obj->server_name);
		if (sz > sizeof(srv_key)){
			p = (char*)malloc(sz+1);
			sprintf(p, "%s:%s",grp->group_name, obj->server_name);
		}
		navi_hash_del(g_rs_servers->hash, p);
		if (p != srv_key){
			free(p);
		}
	}
	navi_pool_destroy(obj->pool);
}

static navi_upserver_procs_t* nvup_srv_type2procs(const char* name)
{
	if (!name)
		return g_upsrv_single_procs;

	if (0 == strcasecmp(name, "single")) {
		return g_upsrv_single_procs;
	}
	else if (0 == strcasecmp(name, "redis_rs")) {
		return g_upsrv_redis_rs_procs;
	}
	else if (0 == strcasecmp(name, "local")) {
		return g_upsrv_local_procs;
	}
	else
		return NULL;
}
