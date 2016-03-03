/*
 * navi_upgroup_mgr.c
 *
 *  Created on: 2013-12-10
 *      Author: li.lei
 */

#include "navi_upgroup_mgr.h"
#include "navi_frame_log.h"
#include "navi_inner_util.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#define NVUP_MGR_GLOBAL_CONF	"common.json"
#define NVUP_MGR_DEFAULT_CONF_DIR  "/etc/cnavi/server_groups/"

#define NVUP_MGR_CONF_SO_DIR "policy_so_dir"
#define NVUP_MGR_HTTP_DRIVER_PATH "http_driver_path"
#define NVUP_MGR_GR_DRIVER_PATH "gr_driver_path"

#define NVUP_MGR_OBJ_INIT_SZ (sizeof(navi_upgroup_mgr_t)+0x2000)

static navi_upgroup_mgr_t* s_grp_mgr = NULL;

static void navi_upgroup_mgr_destroy(navi_upgroup_mgr_t* mgr);

static int navi_upgroup_common_cfg_init(navi_upgroup_mgr_t* mgr, json_t* file_js_conf)
{
	json_t* je;
	const char* jv_s;
	char tmp_path[1024];
	je = json_object_get(file_js_conf, NVUP_MGR_HTTP_DRIVER_PATH);
	if (!je || !json_is_string(je) || strlen(json_string_value(je)) == 0) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "%s is absent from upgroup mgr common.json.", NVUP_MGR_HTTP_DRIVER_PATH);
		return -1;
	}
	jv_s = json_string_value(je);
	if (jv_s[0] != '/') {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "%s is invalid in upgroup mgr common.json.", NVUP_MGR_HTTP_DRIVER_PATH);
		return -1;
	}

	mgr->http_driver_path = jv_s;

	je = json_object_get(file_js_conf, NVUP_MGR_GR_DRIVER_PATH);
	if (!je || !json_is_string(je) || strlen(json_string_value(je)) == 0) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "%s is absent from upgroup mgr common.json.", NVUP_MGR_GR_DRIVER_PATH);
		return -1;
	}
	jv_s = json_string_value(je);
	if (jv_s[0] != '/') {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "%s is invalid in upgroup mgr common.json.", NVUP_MGR_GR_DRIVER_PATH);
		return -1;
	}

	mgr->gr_driver_path = jv_s;

	je = json_object_get(file_js_conf, NVUP_MGR_CONF_SO_DIR);
	if (!je || !json_is_string(je) || strlen(json_string_value(je)) == 0) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "%s is absent from upgroup mgr common.json.", NVUP_MGR_CONF_SO_DIR);
		return -1;
	}
	jv_s = json_string_value(je);

	if (0 >= navi_rpath_2abs(jv_s, tmp_path, sizeof(tmp_path))) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "%s is inavlid dir path in upgroup mgr common.json.", jv_s);
		return -1;
	}

	struct stat stbuf;
	if (-1 == stat(tmp_path, &stbuf)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "PATH: %s does not exist.", tmp_path);
		return -1;
	}

	if (!S_ISDIR(stbuf.st_mode)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "PATH: %s is not dir.", tmp_path);
		return -1;
	}

	mgr->policy_so_dir = navi_pool_strdup(mgr->pool, tmp_path);
	return 0;
}

static navi_upgroup_mgr_t* navi_upgroup_mgr_init(const char* conf_dir)
{
	struct stat stbuf;
	char tmp_path[1024];
	if (conf_dir == NULL) {
		conf_dir = NVUP_MGR_DEFAULT_CONF_DIR;
	}

	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "Using config dir path:%s", conf_dir);

	if (-1 == stat(conf_dir, &stbuf)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "%s don't exists. %s", conf_dir, strerror(errno));
		return NULL;
	}

	if (!S_ISDIR(stbuf.st_mode)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "%s isn't a dir.", conf_dir);
		return NULL;
	}

	navi_upgroup_mgr_t* mgr = (navi_upgroup_mgr_t*) malloc(NVUP_MGR_OBJ_INIT_SZ);
	if (!mgr) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "memory err when init upgroup_mgr");
		return NULL;
	}

	navi_pool_init(mgr->pool, mgr, 0x2000);
	memset(mgr, 0x00, sizeof(navi_upgroup_mgr_t));

	if (0 < navi_rpath_2abs(conf_dir, tmp_path, sizeof(tmp_path)))
		mgr->root_dir = navi_pool_strdup(mgr->pool, tmp_path);
	else
		mgr->root_dir = navi_pool_strdup(mgr->pool, conf_dir);

	snprintf(tmp_path, sizeof(tmp_path), "%s/%s", mgr->root_dir, NVUP_MGR_GLOBAL_CONF);
	json_error_t js_err;
	json_t* file_js_conf = json_load_file(tmp_path, &js_err);

	if (!file_js_conf) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "load json:%s failed:%s line:%s",
		    tmp_path, js_err.text, js_err.line);
		goto failed;
	}
	stat(tmp_path, &stbuf);
	mgr->common_cfg_last = stbuf.st_mtime;
	mgr->common_cfg = file_js_conf;

	if (0 != navi_upgroup_common_cfg_init(mgr, file_js_conf)) {
		goto failed;
	}

	mgr->groups = navi_hash_init(mgr->pool);
	if (mgr->groups == NULL) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "memory err when init upgroup_mgr");
		navi_pool_destroy(mgr->pool);
		return NULL;
	}

	DIR* dir = opendir(conf_dir);
	struct dirent* file_dirent = NULL;
	if (!dir) {
		NAVI_SYSERR_LOG("opendir failed");
		goto failed;
	}

	while ((file_dirent = readdir(dir))) {
		if (strlen(file_dirent->d_name) <= strlen(".json"))
			continue;
		if (strcmp(".json",
		    file_dirent->d_name + strlen(file_dirent->d_name) - strlen(".json"))
		    != 0)
			continue;
		if (strcmp(NVUP_MGR_GLOBAL_CONF, file_dirent->d_name) == 0)
			continue;

		snprintf(tmp_path, sizeof(tmp_path), "%s/%s", mgr->root_dir,
		    file_dirent->d_name);
		if (-1 == stat(tmp_path, &stbuf))
			continue;

		if (!S_ISREG(stbuf.st_mode))
			continue;

		navi_upgroup_t* grp = navi_upgroup_init(tmp_path, mgr);
		if (!grp) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING,
			    "upgroup loaded failed from config:%s", tmp_path);
			continue;
		}

		navi_hash_set_gr(mgr->groups, grp->group_name, grp);
		NAVI_FRAME_LOG(NAVI_LOG_NOTICE,
		    "upgroup:%s has loaded and inited", grp->group_name);
	}

	closedir(dir);
	return mgr;

failed:
	navi_upgroup_mgr_destroy(mgr);
	return NULL;
}

static void navi_upgroup_mgr_destroy(navi_upgroup_mgr_t* mgr)
{
	if (!mgr)
		return;

	if (mgr->groups) {
		void* it = navi_hash_iter(mgr->groups);
		navi_hent_t* he;
		while ((he=navi_hash_iter_next(it))) {
			navi_upgroup_t* grp = (navi_upgroup_t*) he->v;
			he->v = NULL;
			if (grp)
				navi_upgroup_destroy(grp);
		}
		navi_hash_iter_destroy(it);
	}

	if (mgr->common_cfg)
		json_decref(mgr->common_cfg);

	navi_pool_destroy(mgr->pool);
}

void navi_upgroup_mgr_refresh(navi_upgroup_mgr_t* mgr)
{
	struct stat stbuf;
	char tmp_path[1024];
	snprintf(tmp_path, sizeof(tmp_path), "%s/%s", mgr->root_dir, NVUP_MGR_GLOBAL_CONF);
	stat(tmp_path, &stbuf);

	if (stbuf.st_mtime > mgr->common_cfg_last) {
		json_error_t js_err;
		json_t* file_js_conf = json_load_file(tmp_path, &js_err);
		json_t* je, *ae;
		const char* jv_s;
		if (!file_js_conf) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "load json:%s failed:%s line:%s",
			    tmp_path, js_err.text, js_err.line);
		}
		else {
			navi_upgroup_common_cfg_init(mgr, file_js_conf);
			json_decref(mgr->common_cfg);
			mgr->common_cfg = file_js_conf;
			mgr->common_cfg_last = stbuf.st_mtime;
		}
	}

	if (mgr->groups == NULL)
		return;

	navi_hent_t* he;
	navi_upgroup_t* grp;
	navi_upgroup_t* ngrp;

	void* it_grp = navi_hash_iter(mgr->groups);
	while ((he=navi_hash_iter_next(it_grp))) {
		grp = (navi_upgroup_t*) he->v;
		if (grp->c.config_path == NULL){
			/*调用接口添加的组无配置文件*/
			continue;
		}
		if (-1 == stat(grp->c.config_path, &stbuf) || stbuf.st_mtime > grp->c.last_modify) {
			navi_hash_del(mgr->groups, grp->group_name);
			navi_upgroup_destroy(grp);
		}
	}
	navi_hash_iter_destroy(it_grp);

	DIR* dir = opendir(mgr->root_dir);
	struct dirent* file_dirent = NULL;
	if (!dir) {
		NAVI_SYSERR_LOG("opendir failed");
		return;
	}

	while ((file_dirent = readdir(dir))) {
		if (strlen(file_dirent->d_name) <= strlen(".json"))
			continue;
		if (strcmp(".json",
		    file_dirent->d_name + strlen(file_dirent->d_name) - strlen(".json"))
		    != 0)
			continue;
		if (strcmp(NVUP_MGR_GLOBAL_CONF, file_dirent->d_name) == 0)
			continue;

		snprintf(tmp_path, sizeof(tmp_path), "%s/%s", mgr->root_dir,
		    file_dirent->d_name);
		if (-1 == stat(tmp_path, &stbuf))
			continue;

		if (!S_ISREG(stbuf.st_mode))
			continue;

		json_error_t js_err;
		json_t* grp_cfg = json_load_file(tmp_path, &js_err);
		if (grp_cfg == NULL)
			continue;
		json_t* je = json_object_get(grp_cfg, "group_name");
		if (!je || !json_is_string(je) || 0 == strlen(json_string_value(je))) {
			json_decref(grp_cfg);
			continue;
		}

		if (navi_hash_get_gr(mgr->groups, json_string_value(je))) {
			json_decref(grp_cfg);
			continue;
		}

		json_decref(grp_cfg);

		navi_upgroup_t* grp = navi_upgroup_init(tmp_path, mgr);
		if (!grp) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING,
			    "upgroup loaded failed from config:%s", tmp_path);
			continue;
		}

		navi_hash_set_gr(mgr->groups, grp->group_name, grp);
		NAVI_FRAME_LOG(NAVI_LOG_NOTICE,
		    "upgroup:%s has loaded and inited", grp->group_name);
	}

	closedir(dir);
}

navi_upgroup_mgr_t* navi_upgroup_mgr_instance(const char* root_path)
{
	if (s_grp_mgr == NULL) {
		s_grp_mgr = navi_upgroup_mgr_init(root_path);
	}
	return s_grp_mgr;
}

void navi_upgroup_mgr_instance_destroy()
{
	if (s_grp_mgr) {
		navi_upgroup_mgr_destroy(s_grp_mgr);
		s_grp_mgr = NULL;
	}
}

int navi_upreq_resolve_policy(navi_upgroup_mgr_t* mgr, navi_upreq_t* req,
    navi_upreq_policy_t* policy)
{
	if (!mgr || !mgr->groups) {
		return NAVI_ARG_ERR;
	}

	navi_upgroup_t* grp = (navi_upgroup_t*) navi_hash_get_gr(mgr->groups, req->group_name);
	if (!grp) {
		NAVI_FRAME_LOG(NAVI_LOG_INFO, "unknown upgroup name:%s for upreq", req->group_name);
		navi_upreq_error_lt(req, NVUP_RESULT_CLI_ERROR, -1, "upgroup not found");
		return NAVI_INNER_ERR;
	}

	return navi_upgroup_resolve_upreq(grp, req, policy);
}

navi_upserver_t* navi_upgroup_mgr_get_server(navi_upgroup_mgr_t* mgr, const char* grp_nm,
	const char* srv_nm)
{
	if (!mgr || mgr->groups == NULL) return NULL;
	navi_upgroup_t* grp = (navi_upgroup_t*)navi_hash_get_gr(mgr->groups, grp_nm);
	return navi_upgroup_get_server(grp, srv_nm);
}

navi_upgroup_t* navi_upgroup_mgr_get_group(navi_upgroup_mgr_t* mgr, const char* grp_nm)
{
	if (!mgr || mgr->groups == NULL) return NULL;
	return (navi_upgroup_t*)navi_hash_get_gr(mgr->groups, grp_nm);
}
