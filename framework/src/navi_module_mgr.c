/*
 * navi_modulemgr.c
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 */
#include "navi_module_driver.h"
#include "navi_request_driver.h"
#include "navi_module_mgr.h"
#include "navi_request.h"
#include "navi_request_impl.h"
#include "navi_module_impl.h"
#include "navi_inner_util.h"
#include "navi_frame_log.h"
#include "navi_static_content.h"
//#include "navi_work_queue.h"
#include "navi_list.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <assert.h>

#include "navi_request_common.c"

#define NOUSED(x)

#define NAVI_CONF_MAIN "navi.json"
//#define NAVI_SCFILE_DIR_CONFFILE "scfile_dir.json"
//#define NAVI_MONO_CTRL_CONFFILE "module_mono_init_ctrl.json"
#define NAVI_CONF_SCFILE_MGRS "scfile_mgrs"
#define NAVI_CONF_MONO_MODULES "mono_modules"
//#define NAVI_CONF_WORK_QUEUE_DOMAIN "work_queue_domains"
#define NAVI_CONF_LOCAL_REDISGRP "local_cache_group"
#define NAVI_CONF_LOCAL_LEVELDBGRP "local_leveldb_group"

#define NAVI_CONF_SERVICE_NAME "service_name"

#define NAVI_CONF_PREV_BASIC_CHAIN "prev_basic_chain"
#define NAVI_CONF_POST_BASIC_CHAIN "post_basic_chain"

#define NAVI_CONF_LOG_LEVEL "log_level"
#define NAVI_CONF_SO_DIR "module_so_dir"

#define NAVI_DEFAULT_CONF_DIR "/etc/cnavi/"

static bool build_module_so_dir(navi_module_mgr_t* mgr, const char* dir);

static void build_ic_chain(navi_module_mgr_t* mgr);
static void navi_ic_module_chain_decref(navi_ic_module_chain_t* chain);

static void navi_mono_ctrl_clean(void* obj)
{
	navi_module_mono_ctrl_t* ctrl = (navi_module_mono_ctrl_t*)obj;
	if (ctrl->lock_fd != -1) {
		close(ctrl->lock_fd);
		ctrl->lock_fd = -1;
	}
}
static void navi_mgr_init_mono_ctrl(navi_module_mgr_t* mgr, const json_t* cfg)
{
	if ( !json_is_array(cfg) || !json_array_size(cfg) ) {
		return;
	}
	int i = 0;
	json_t* ae = NULL;
	int sz = json_array_size(cfg);
	for( ; i<sz; i++) {
		ae = json_array_get(cfg, i);
		if (!ae || !json_is_string(ae) )
			continue;
		const char* s = json_string_value(ae);
		if (!strlen(s) || !navi_is_symbol_word(s) )
			continue;

		if (mgr->mono_ctrl == NULL)
			mgr->mono_ctrl = navi_hash_init(mgr->pool);

		navi_module_mono_ctrl_t* ctrl = navi_pool_calloc(mgr->pool, 1,
			sizeof(navi_module_mono_ctrl_t));

		ctrl->module_name = navi_pool_strdup(mgr->pool, s);
		ctrl->lock_fd = -1;
		navi_hash_set_gr2(mgr->mono_ctrl, s, ctrl, navi_mono_ctrl_clean);

		char tmp_path[1024];
		snprintf(tmp_path,sizeof(tmp_path), "/tmp/%s_mono_run.lock", s);
		ctrl->lock_fd = open(tmp_path, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);
		if (ctrl->lock_fd == -1) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "try lock mono for module:%s failed. %s",
				s, strerror(errno));
			continue;
		}

		struct flock lk;
		lk.l_type = F_WRLCK;
		lk.l_start = 0;
		lk.l_whence = SEEK_SET;
		lk.l_len = 0;
		lk.l_pid = 0;

		if ( 0 > fcntl(ctrl->lock_fd, F_GETLK,&lk) ) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "try lock mono for module:%s failed. %s",
				s, strerror(errno));
			close(ctrl->lock_fd);
			ctrl->lock_fd = -1;
			continue;
		}

		if ( lk.l_type == F_UNLCK ) {
			lk.l_type = F_WRLCK;
			int ret = fcntl(ctrl->lock_fd, F_SETLK, &lk);
			if (ret == 0) {
				NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "mono lock success module:%s", s);
				ctrl->mono_run = 1;
			}
			else if (ret == EAGAIN || errno == EAGAIN ) {
				ctrl->mono_run = 0;
				close(ctrl->lock_fd);
				ctrl->lock_fd = -1;
			}
			else {
				NAVI_FRAME_LOG(NAVI_LOG_WARNING, "try lock mono for module:%s failed. %s",
						s, strerror(errno));
				close(ctrl->lock_fd);
				ctrl->lock_fd = -1;
				continue;
			}
		}
		else {
			ctrl->mono_run = 0;
			close(ctrl->lock_fd);
			ctrl->lock_fd = -1;
		}
	}
}

navi_module_mgr_t* navi_mgr_init(const char* conf_path) {
	if (navi_frame_log == NULL) {
		navi_frame_log = navi_log_init(NAVI_LOG_NOTICE, "[cnavi frame]", 512);
	}

	struct stat stbuf;
	if (conf_path == NULL) {
		conf_path = NAVI_DEFAULT_CONF_DIR;
	}

	NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "Using config dir path:%s", conf_path);

	if (-1 == stat(conf_path, &stbuf)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "%s don't exists. %s", conf_path, strerror(errno));
		return NULL;
	}

	if (!S_ISDIR(stbuf.st_mode)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "%s isn't a dir.", conf_path);
		return NULL;
	}

	navi_module_mgr_t* mgr = (navi_module_mgr_t*)malloc(sizeof(navi_module_mgr_t));
	if (!mgr) {
		NAVI_SYSERR_LOG();
		return NULL;
	}

	memset(mgr, 0x00, sizeof(navi_module_mgr_t));
	navi_timer_mgr_init(&mgr->timer_mgr);

	mgr->pool = navi_pool_create(0x1000);
	if (!mgr->pool) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "pool create failed");
		navi_mgr_free(mgr);
		return NULL;
	}
	mgr->module_map = navi_hash_init(mgr->pool);
	if (!mgr->module_map) {
		NAVI_SYSERR_LOG("init module map hash failed");
		navi_mgr_free(mgr);
		return NULL;
	}

	/*
	 * 检查navi.json配置
	 */

	char tmp_path[1024];
	json_error_t js_err;
	snprintf(tmp_path, sizeof(tmp_path), "%s/%s", conf_path, NAVI_CONF_MAIN);

	DIR* dir = NULL;
	struct dirent* file_dirent;
	int ret;

	navi_module_t* mod = NULL, *check_mod = NULL;
	int mod_idx;
	const char* mod_idx_str;

	json_t* file_js_conf = json_load_file(tmp_path, &js_err);
	json_t* je, *ae;
	if (!file_js_conf) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "load json:%s failed:%s line:%d",
		    tmp_path, js_err.text, js_err.line);
		goto failed;
	}
	mgr->rmm_conf = file_js_conf;
	stat(tmp_path, &stbuf);
	mgr->rmm_conf_last = stbuf.st_mtime;

	je = json_object_get(file_js_conf, NAVI_CONF_SERVICE_NAME);
	if (!je || !json_is_string(je)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "%s is absent from navi.json.", NAVI_CONF_SERVICE_NAME);
		goto failed;
	}

	mgr->service_name = strdup(json_string_value(je));
	if (strlen(mgr->service_name) == 0) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,
		    "%s is absent from navi.json.", NAVI_CONF_SERVICE_NAME);
		goto failed;
	}

	je = json_object_get(file_js_conf, NAVI_CONF_SO_DIR);
	if (je && json_is_string(je) && strlen(json_string_value(je))) {
		const char* so_dir = json_string_value(je);
		if ( ! build_module_so_dir( mgr, so_dir ) )
			goto failed;
	}

	je = json_object_get(file_js_conf, "debug");
	if (je && json_is_true(je)) {
		mgr->debug = true;
	}

	je = json_object_get(file_js_conf, "enable_bigpost");
	if ( je && json_is_true(je) ) {
		mgr->enable_bigpost = true;
	}

	/**
	snprintf(tmp_path, sizeof(tmp_path), "%s/%s", conf_path, NAVI_SCFILE_DIR_CONFFILE);
	file_js_conf = json_load_file(tmp_path,&js_err);
	if ( file_js_conf ) {
		mgr->scfile_conf = file_js_conf;
		stat(tmp_path,&stbuf);
		mgr->scfile_conf_last = stbuf.st_mtime;
		navi_scfile_mgrs_init(file_js_conf);
	}
	else {
		NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "scfile_dir config from %s empty or load failed:%s %d",
		    tmp_path, js_err.text, js_err.line);
	}**/

	//snprintf(tmp_path, sizeof(tmp_path), "%s/%s", conf_path, NAVI_MONO_CTRL_CONFFILE);
	//file_js_conf = json_load_file(tmp_path, &js_err);
	{
		const json_t* mono_cfg = json_object_get(file_js_conf, NAVI_CONF_MONO_MODULES);
		if ( mono_cfg ) {
			navi_mgr_init_mono_ctrl(mgr, mono_cfg);
		}
		else {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "No mono_modules defined.");
		}
	}

	{
		const json_t* sc_mgrs = json_object_get(file_js_conf, NAVI_CONF_SCFILE_MGRS);
		if ( sc_mgrs ) {
			navi_scfile_mgrs_init(sc_mgrs);
		}
		else {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "no scfile_mgrs defined");
		}
	}

	/**{
		const json_t* work_domains = json_object_get(file_js_conf, NAVI_CONF_WORK_QUEUE_DOMAIN);
		if ( work_domains ) {
			nvworkq_config_init(work_domains);
		}
		else {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "no work_queue_domains defined");
		}
	}**/

	{
		const char* cache_grp = NULL;
		const char* leveldb_grp = NULL;
		const json_t* se = json_object_get(file_js_conf, NAVI_CONF_LOCAL_REDISGRP);
		if ( !se || !json_is_string(se) ) {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "no local_cache_group defined");
		}
		else {
			cache_grp = json_string_value(se);
			if ( !strlen(cache_grp) ) {
				NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "no local_cache_group defined");
			}
		}

		se = json_object_get(file_js_conf, NAVI_CONF_LOCAL_LEVELDBGRP);
		if ( !se || !json_is_string(se) ) {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "no local_leveldb_group defined");
		}
		else {
			leveldb_grp = json_string_value(se);
			if ( !strlen(leveldb_grp) ) {
				NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "no local_leveldb_group defined");
			}
		}

		if ( cache_grp || leveldb_grp ) {
			navi_local_redis_cfg_init(cache_grp, leveldb_grp);
		}
	}


	/*
	 * 遍历配置目录，扫描并加载模块
	 */
	dir = opendir(conf_path);
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
		if ( strcmp(NAVI_CONF_MAIN, file_dirent->d_name)==0 )
			continue;
		//if ( strcmp(NAVI_SCFILE_DIR_CONFFILE, file_dirent->d_name)==0 )
		//	continue;
		//if ( strcmp(NAVI_MONO_CTRL_CONFFILE, file_dirent->d_name)==0 )
		//	continue;

		snprintf(tmp_path, sizeof(tmp_path), "%s/%s", conf_path,
		    file_dirent->d_name);
		if (-1 == stat(tmp_path, &stbuf))
			continue;

		if (!S_ISREG(stbuf.st_mode))
			continue;

		json_error_t js_err;
		json_t* cf = json_load_file(tmp_path,&js_err);
		je = json_object_get(cf, CONF_MODULE_NAME);
		char *mod_nm = NULL;
		if (je && json_is_string(je) && strlen(json_string_value(je))) {
			mod_nm = strdup(json_string_value(je));
		}
		json_decref(cf);
		if (mod_nm==NULL || !navi_is_symbol_word(mod_nm)) {
			if (mod_nm)free(mod_nm);
			continue;
		}

		if (navi_hash_get_gr(mgr->module_map, mod_nm)) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING,
				"Module:%s already loaded. dup conf:%s",
				mod_nm, tmp_path);
			free(mod_nm);
			continue;
		}
		free(mod_nm);

		mod = navi_module_init(tmp_path, mgr);
		if (!mod)
			continue;

		if (NAVI_INNER_ERR
		    == navi_hash_set_gr(mgr->module_map, mod->mod_name, mod)) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR,
			    "hash set failed when adding module to map.");
			navi_module_decref(mod);
			continue;
		}

		NAVI_FRAME_LOG(NAVI_LOG_NOTICE,
		    "Module:%s has loaded and inited.Conf path:%s", mod->mod_name,
		    navi_module_conf_path(mod));
	}

	closedir(dir);

	/*
	 * 读取navi.json calling_chain配置选项，组织事前事后基础模块列表
	 */
	build_ic_chain(mgr);
	/*
	 * 框架内部日志级别设置
	 */
	je = json_object_get(mgr->rmm_conf, NAVI_CONF_LOG_LEVEL);
	if (je && json_is_string(je)) {
		const char* level = json_string_value(je);

		if (0 == strcmp(level, "debug")) {
			navi_log_set_minlevel(navi_frame_log, NAVI_LOG_DEBUG);
		}
		else if (0 == strcmp(level, "info")) {
			navi_log_set_minlevel(navi_frame_log, NAVI_LOG_INFO);
		}
		else if (0 == strcmp(level, "notice")) {
			navi_log_set_minlevel(navi_frame_log, NAVI_LOG_NOTICE);
		}
		else if (0 == strcmp(level, "warning")) {
			navi_log_set_minlevel(navi_frame_log, NAVI_LOG_WARNING);
		}
		else if (0 == strcmp(level, "error")) {
			navi_log_set_minlevel(navi_frame_log, NAVI_LOG_ERR);
		}
		else if (0 == strcmp(level, "emerge")) {
			navi_log_set_minlevel(navi_frame_log, NAVI_LOG_EMERG);
		}
	}

	if ( 0 < navi_rpath_2abs(conf_path,tmp_path,sizeof(tmp_path)) )
		mgr->conf_dir = strdup(tmp_path);
	else
		mgr->conf_dir = strdup(conf_path);

	return mgr;

failed:
	navi_mgr_free(mgr);
	return NULL;
}

void navi_mgr_free(navi_module_mgr_t* mgr) {
	if (!mgr)
		return;

	if (mgr->prev_ic)
		navi_ic_module_chain_decref(mgr->prev_ic);

	if (mgr->post_ic)
		navi_ic_module_chain_decref(mgr->post_ic);

	void* it = navi_hash_iter(mgr->module_map);
	navi_hent_t* he = NULL;
	while ((he=navi_hash_iter_next(it))) {
		navi_module_t* mod = (navi_module_t*)he->v;
		navi_module_decref(mod);
	}
	navi_hash_iter_destroy(it);

	if (mgr->mono_ctrl){
		navi_hash_reset(mgr->mono_ctrl);
		mgr->mono_ctrl = NULL;
	}

	navi_timer_mgr_clean(&mgr->timer_mgr);

	if (mgr->pool) {
		navi_pool_destroy(mgr->pool);
		mgr->pool = NULL;
	}

	if (mgr->service_name)
		free(mgr->service_name);

	if (mgr->module_so_dir)
		free(mgr->module_so_dir);

	if (mgr->conf_dir)
		free(mgr->conf_dir);

	if (mgr->rmm_conf)
		json_decref(mgr->rmm_conf);

	free(mgr);

	if (navi_frame_log) {
		navi_log_destroy(navi_frame_log);
		navi_frame_log = NULL;
	}
}

void navi_mgr_check_modules(navi_module_mgr_t* mgr) {
	char tmp_path[1024];
	bool need_build_chain = false;
	bool navi_main_changed = false;
	struct stat stbuf;
	json_t* file_js_conf = NULL;
	json_t* cf, *je;
	json_error_t js_err;

	NAVI_FRAME_LOG(NAVI_LOG_DEBUG,"checking module mgr");

	snprintf(tmp_path, sizeof(tmp_path), "%s/%s", mgr->conf_dir,
	    NAVI_CONF_MAIN);

	if (-1 == stat(tmp_path, &stbuf)) {
		NAVI_FRAME_LOG(NAVI_LOG_WARNING, "%s lost.", tmp_path);
	}
	else if (stbuf.st_mtime > mgr->rmm_conf_last) {
		file_js_conf = json_load_file(tmp_path, &js_err);
		if (!file_js_conf) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "%s json load failed:%s line:%d.",
			    tmp_path, js_err.text, js_err.line);
		}
		else {
			navi_main_changed = true;

			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "%s config is changed",tmp_path);

			je = json_object_get(file_js_conf, NAVI_CONF_SO_DIR);
			if (je && json_is_string(je)) {
				const char* dir_path = json_string_value(je);
				if ( !build_module_so_dir(mgr, dir_path) ) {
					NAVI_FRAME_LOG(NAVI_LOG_WARNING,"module_so_dir:%s invalid, using previous:%s",
						dir_path, mgr->module_so_dir);
				}
			}

			mgr->debug = false;
			je = json_object_get(file_js_conf, "debug");
			if (je && json_is_true(je)) {
				mgr->debug = true;
			}

			je = json_object_get(file_js_conf, NAVI_CONF_SERVICE_NAME);
			if (je && json_is_string(je)) {
				const char* tmp_srv = json_string_value(je);
				if (strlen(tmp_srv) == 0) {
					NAVI_FRAME_LOG(NAVI_LOG_WARNING,
					    "service_name in navi.json is empty");
				}
				else {
					if (mgr->service_name)
						free(mgr->service_name);
					mgr->service_name = strdup(tmp_srv);
				}
			}

			je = json_object_get(mgr->rmm_conf, NAVI_CONF_LOG_LEVEL);
			if (je && json_is_string(je)) {
				const char* level = json_string_value(je);

				if (0 == strcmp(level, "debug")) {
					navi_log_set_minlevel(navi_frame_log, NAVI_LOG_DEBUG);
				}
				else if (0 == strcmp(level, "info")) {
					navi_log_set_minlevel(navi_frame_log, NAVI_LOG_INFO);
				}
				else if (0 == strcmp(level, "notice")) {
					navi_log_set_minlevel(navi_frame_log, NAVI_LOG_NOTICE);
				}
				else if (0 == strcmp(level, "warning")) {
					navi_log_set_minlevel(navi_frame_log, NAVI_LOG_WARNING);
				}
				else if (0 == strcmp(level, "error")) {
					navi_log_set_minlevel(navi_frame_log, NAVI_LOG_ERR);
				}
				else if (0 == strcmp(level, "emerge")) {
					navi_log_set_minlevel(navi_frame_log, NAVI_LOG_EMERG);
				}
			}

			mgr->rmm_conf_last = stbuf.st_mtime;
			if (mgr->rmm_conf)
				json_decref(mgr->rmm_conf);
			mgr->rmm_conf = file_js_conf;
		}
	}

	navi_hash_t* ic_keys = navi_hash_init_with_heap();
	size_t i=0, arr_sz = 0;
	json_t* ae = NULL;
	const char* key;
	je = json_object_get(mgr->rmm_conf, NAVI_CONF_PREV_BASIC_CHAIN);
	if (je && json_is_array(je)) {
		arr_sz = json_array_size(je);
		for (i = 0; i < arr_sz; i++) {
			ae = json_array_get(je, i);
			if (json_is_string(ae) && strlen(key=json_string_value(ae))
				&& navi_is_symbol_word(key)) {
				navi_hash_set_gr(ic_keys, key, (void*)key);
			}
		}
	}
	je = json_object_get(mgr->rmm_conf, NAVI_CONF_POST_BASIC_CHAIN);
	if (je && json_is_array(je)) {
		arr_sz = json_array_size(je);
		for (i = 0; i < arr_sz; i++) {
			ae = json_array_get(je, i);
			if (json_is_string(ae) && strlen(key=json_string_value(ae))
				&& navi_is_symbol_word(key)) {
				navi_hash_set_gr(ic_keys, key, (void*)key);
			}
		}
	}

	/*
	 * 对已加载模块刷新
	 */
	void* it = navi_hash_iter(mgr->module_map);
	navi_hent_t* he = NULL;
	navi_module_t* module = NULL, *rf_module;
	const char* conf_path = NULL;
	while ((he=navi_hash_iter_next(it))) {
		module = (navi_module_t*)he->v;
		assert(module->_magic==NAVI_MOD_HANDLE_MAGIC);
		if (!navi_module_conf_changed(module))
			continue;
		conf_path = navi_module_conf_path(module);
		rf_module = navi_module_init(conf_path, mgr);
		if (!rf_module) {
			continue;
		}
		if ( strcmp(rf_module->mod_name, he->k) ) {
			navi_module_decref(rf_module);
			NAVI_FRAME_LOG(NAVI_LOG_WARNING,"config_path:%s module name change not allowed.",
				conf_path);
			continue;
		}
		navi_module_decref(module);
		navi_hash_set_gr(mgr->module_map, rf_module->mod_name, rf_module);
		if (!navi_module_conf_disabled(rf_module)) {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "Module:%s conf changed. Reloading success.",
				rf_module->mod_name);
		}
		else {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "Module:%s conf changed. Disabled.",
				rf_module->mod_name);
			navi_module_impl_t* mi = navi_mod_h2i(rf_module);
			navi_module_mgr_t* mgr = (navi_module_mgr_t*) mi->navi_mgr;
			navi_timer_mgr_clean_spec(&mgr->timer_mgr, mi);
		}
		if (navi_hash_get_gr(ic_keys, rf_module->mod_name)) {
			need_build_chain = true;
		}
	}
	navi_hash_iter_destroy(it);

	/*
	 * 扫描配置文件丢失的模块并尝试卸载。
	 */
	it = navi_hash_iter(mgr->module_map);
	while ((he=navi_hash_iter_next(it))) {
		module = (navi_module_t*)he->v;
		conf_path = navi_module_conf_path(module);
		if ( (-1 == stat(conf_path, &stbuf) || !S_ISREG(stbuf.st_mode)) ) {
			if (navi_hash_get_gr(ic_keys, module->mod_name)) {
				need_build_chain = true;
			}
			navi_hash_del(mgr->module_map, module->mod_name);
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE,"Module:%s deleted", module->mod_name);
			navi_module_decref(module);
		}
	}
	navi_hash_iter_destroy(it);

	/*
	 * 扫描新增模块并加载
	 */
	DIR* dir = opendir(mgr->conf_dir);
	struct dirent *de;
	char* mod_nm;
	if (!dir) {
		NAVI_SYSERR_LOG("open config dir failed");
	}

	while (dir && (de = readdir(dir)) ) {
		if (strlen(de->d_name) <= strlen(".json"))
			continue;
		if (strcmp(".json", de->d_name + strlen(de->d_name) - strlen(".json"))
		    != 0)
			continue;
		if ( strcmp(NAVI_CONF_MAIN, de->d_name)==0 )
			continue;

		snprintf(tmp_path, sizeof(tmp_path), "%s/%s", mgr->conf_dir,
		    de->d_name);
		if (-1 == stat(tmp_path, &stbuf))
			continue;

		if (!S_ISREG(stbuf.st_mode))
			continue;

		cf = json_load_file(tmp_path, &js_err);
		if (!cf) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "%s json load failed:%s line:%d.",
			    tmp_path, js_err.text, js_err.line);
			continue;
		}

		je = json_object_get(cf, CONF_MODULE_NAME);
		mod_nm = NULL;
		if (je && json_is_string(je)) {
			mod_nm = strdup(json_string_value(je));
		}
		json_decref(cf);
		if (mod_nm==NULL || !navi_is_symbol_word(mod_nm))
			continue;

		if (navi_hash_get_gr(mgr->module_map, mod_nm)) {
			free(mod_nm);
			continue;
		}
		free(mod_nm);

		module = navi_module_init(tmp_path, mgr);
		if (!module) {
			continue;
		}

		NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "Module:%s discovered.Conf:%s",
			module->mod_name, tmp_path);

		if (NAVI_INNER_ERR == navi_hash_set_gr(mgr->module_map, module->mod_name, module)) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR,
			    "Add module to map failed:hash set failed");
			navi_module_decref(module);
			continue;
		}

		if (navi_hash_get_gr(ic_keys, module->mod_name)) {
			need_build_chain = true;
		}
	}

	navi_hash_destroy(ic_keys);

	if (dir)
		closedir(dir);

	if (need_build_chain || navi_main_changed) {
		build_ic_chain(mgr);
	}
}

static void build_ic_chain(navi_module_mgr_t* mgr) {
	json_t* ae;
	navi_module_t* mod;
	json_t* je = NULL;
	int i;
	const char* mod_nm;

	navi_ic_module_chain_t* prev_chain = (navi_ic_module_chain_t*)
		calloc(1,sizeof(navi_ic_module_chain_t)+0x100);
	prev_chain->ref_count = 1;
	navi_list_init(&prev_chain->head.link);
	navi_pool_init(prev_chain->pool,prev_chain,0x100);

	je = json_object_get(mgr->rmm_conf, NAVI_CONF_PREV_BASIC_CHAIN);
	if (je && json_is_array(je)) {
		for (i = 0; i < json_array_size(je); i++) {
			ae = json_array_get(je, i);
			if (json_is_string(ae) && strlen(mod_nm=json_string_value(ae))
				&& navi_is_symbol_word(mod_nm)) {
				mod = (navi_module_t*)navi_hash_get_gr(mgr->module_map, mod_nm);
				if (mod == NULL) {
					NAVI_FRAME_LOG(NAVI_LOG_WARNING, "PREV_BASIC_MODULE:%s not exists",
						mod_nm);
					continue;
				}
				uint32_t mod_type = navi_module_type(mod);
				if (mod_type & NAVI_MODULE_TYPE_PRE_APP) {
					navi_ic_link_t* lk_nd = navi_pool_calloc(prev_chain->pool,1,sizeof(navi_ic_link_t));
					lk_nd->module = mod;
					navi_module_incref(mod);
					navi_list_insert_tail(&prev_chain->head.link,&lk_nd->link);
					NAVI_FRAME_LOG(NAVI_LOG_NOTICE,"PREV_BASIC_MODULE:%s joined", mod_nm);
				}
				else {
					NAVI_FRAME_LOG(NAVI_LOG_WARNING,"%s is not PREV_BASIC_MODULE",  mod_nm);
				}
			}
		}

		if (prev_chain->head.link.next == &prev_chain->head.link) {
			navi_ic_module_chain_decref(prev_chain);
			prev_chain = NULL;
		}
	}

	navi_ic_module_chain_t* post_chain = (navi_ic_module_chain_t*)
			calloc(1,sizeof(navi_ic_module_chain_t)+0x100);
	post_chain->ref_count = 1;
	navi_list_init(&post_chain->head.link);
	navi_pool_init(post_chain->pool,post_chain,0x100);

	je = json_object_get(mgr->rmm_conf, NAVI_CONF_POST_BASIC_CHAIN);
	if (je && json_is_array(je)) {
		for (i = 0; i < json_array_size(je); i++) {
			ae = json_array_get(je, i);
			if (json_is_string(ae) && strlen(mod_nm=json_string_value(ae))
				&& navi_is_symbol_word(mod_nm)) {
				mod = (navi_module_t*)navi_hash_get_gr(mgr->module_map, mod_nm);
				if (mod == NULL){
					NAVI_FRAME_LOG(NAVI_LOG_WARNING, "POST_BASIC_MODULE:%s not exists",
						mod_nm);
					continue;
				}
				uint32_t mod_type = navi_module_type(mod);
				if (mod_type & NAVI_MODULE_TYPE_POST_APP) {
					navi_ic_link_t* lk_nd = navi_pool_calloc(post_chain->pool,1,sizeof(navi_ic_link_t));
					lk_nd->module = mod;
					navi_module_incref(mod);
					navi_list_insert_tail(&post_chain->head.link,&lk_nd->link);
					NAVI_FRAME_LOG(NAVI_LOG_NOTICE,"POST_BASIC_MODULE:%s joined", mod_nm);
				}
				else {
					NAVI_FRAME_LOG(NAVI_LOG_WARNING,"%s is not POST_BASIC_MODULE",  mod_nm);
				}
			}
		}

		if (post_chain->head.link.next == &post_chain->head.link) {
			navi_ic_module_chain_decref(post_chain);
			post_chain = NULL;
		}
	}

	if (mgr->prev_ic)
		navi_ic_module_chain_decref(mgr->prev_ic);
	if (mgr->post_ic)
		navi_ic_module_chain_decref(mgr->post_ic);

	mgr->prev_ic = prev_chain;
	mgr->post_ic = post_chain;
}

static void navi_ic_module_chain_decref(navi_ic_module_chain_t* chain)
{
	if (!chain) return;
	if (--chain->ref_count == 0) {
		chain_node_t* lk = chain->head.link.next;
		while (lk != &chain->head.link) {
			navi_ic_link_t* node = (navi_ic_link_t*)navi_list_data(lk,navi_ic_link_t,link);
			lk = lk->next;
			navi_module_decref(node->module);
		}
		navi_pool_destroy(chain->pool);
	}
}

static bool build_module_so_dir(navi_module_mgr_t* mgr, const char* so_dir)
{
	char tmp_path[1024];
	char* p = NULL;
	size_t left = sizeof(tmp_path);
	if ( 0 >= navi_rpath_2abs(so_dir, tmp_path, sizeof(tmp_path) ) ) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"module_so_dir: %s is too long.", so_dir);
		return false;
	}

	struct stat stbuf;
	if ( -1 == stat(tmp_path,&stbuf) || !S_ISDIR(stbuf.st_mode) ) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"module_so_dir: %s is not a direnctory.", tmp_path);
		return false;
	}

	p = tmp_path + strlen(tmp_path);
	left -= strlen(tmp_path);

	if (left < strlen("/cnavimodules/")+1 ) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"module_so_dir: %s is too long.", tmp_path);
		return false;
	}

	memcpy(p, "/cnavimodules/", strlen("/cnavimodules/")+1 );

	if ( -1 == stat(tmp_path, &stbuf) || !S_ISDIR(stbuf.st_mode)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR,"module_so_dir: %s is not a direnctory.",
			tmp_path);
		return false;
	}

	if ( mgr->module_so_dir )
		free( mgr->module_so_dir );
	mgr->module_so_dir = strdup( tmp_path );
	return true;
}

int navi_mgr_run_request(navi_module_mgr_t* mgr, navi_request_t* r) {
	if (!mgr)
		return NAVI_ARG_ERR;

	if (!check_req_h(r))
		return NAVI_ARG_ERR;

	navi_request_impl_t* req = navi_req_h2i(r);
	if (req->main != req)
		return NAVI_ARG_ERR;

	req->navi_status = NAVI_REQUEST_FRAME_PROCESSING;
	navi_request_cost_ns(r);
	req->main_data->service = mgr->service_name;
	req->main_data->navi_mgr = mgr;
	req->main_data->cur_stage = NAVI_ROOT_STAGE_PREV_APP;
	req->ic_mod = NULL;

	int i;
	navi_module_impl_t* ic_mi;
	navi_ic_link_t* ic_link = NULL;
	int ic_ret = 0;

	chain_node_t* mod_lk = NULL;
	if (mgr->prev_ic) {
		mod_lk = mgr->prev_ic->head.link.next;
		if (mod_lk == &mgr->prev_ic->head.link) {
			mod_lk = NULL;
			navi_ic_module_chain_decref(mgr->prev_ic);
			mgr->prev_ic = NULL;
		}
		else {
			mgr->prev_ic->ref_count++;
			ic_link =(navi_ic_link_t*)navi_list_data(mod_lk,navi_ic_link_t,link);
			req->ic_mod = ic_link;
			req->ic_chain = mgr->prev_ic;
		}
	}

	if (mod_lk) {
		ic_ret = navi_module_run_request(ic_link->module, r);
		ic_mi = navi_mod_h2i(ic_link->module);
		if (ic_ret!=NAVI_OK) {
			if (ic_ret == NAVI_DENY ) {
				if (ic_mi->ret_ctrl_mask|NAVI_IC_ALLOW_DENEY) {
					req->main_data->cur_ctrl = NAVI_ROOT_DENYED;
				}
				goto drive;
			}
			else if (ic_ret == NAVI_CONCLUDED ) {
				if (ic_mi->ret_ctrl_mask|NAVI_IC_ALLOW_CONCLUDE) {
					req->main_data->cur_ctrl = NAVI_ROOT_CONCLUDE;
				}
				goto drive;
			}

			navi_http_request_abort_bigpost(r);

			if (req->resp_http_code==0||req->resp_http_code==200)
				req->resp_http_code = 500;
			navi_response_t* resp = navi_request_response_obj(r);
			if (resp->error.code==NULL_CODE)
				navi_response_set_desc(resp,-1,"navi frame", "ic module impl failed");

			navi_request_cancel(r);
			//此处不可能有子请求、定时器、虚事件被安装，直接封装响应退出
			mgr->prev_ic->ref_count--;
			navi_module_decref(ic_link->module);
			req->ic_mod = NULL;
			req->ic_chain = NULL;
			req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
			navi_mgr_step_request(r,NULL);
			return NAVI_OK;
		}
		goto drive;
	}

	req->ic_mod = NULL;
	req->ic_chain = NULL;
	req->main_data->cur_stage = NAVI_ROOT_STAGE_APP;
	navi_mgr_step_request(r,NULL);
	return NAVI_OK;

drive:
	navi_request_call_process(r);
	return NAVI_OK;
}

#define RESP_HEADER_MODULE "Module"

int navi_mgr_step_request(navi_request_t* r, void* ctx) {
	if (!check_req_h(r)) return NAVI_ARG_ERR;

	navi_request_impl_t* req = navi_req_h2i(r);
	if (req->main != req) return NAVI_ARG_ERR;

	navi_module_mgr_t* mgr = (navi_module_mgr_t*)req->main_data->navi_mgr;
	navi_module_t* cur_mod ;
	navi_module_impl_t* cur_mi = NULL;
next_step:
	cur_mod = NULL;
	switch(req->main_data->cur_stage) {
	case NAVI_ROOT_STAGE_PREV_APP:{
		cur_mod = req->ic_mod->module;

		if (req->main_data->cur_ctrl == NAVI_ROOT_DENYED) {
			if (req->resp_http_code==0 || req->resp_http_code==200) {
				req->resp_http_code = 405;
			}
			navi_response_t* resp = navi_request_response_obj(r);
			if (resp->error.code == NULL_CODE)
				navi_response_set_desc(resp, 405, cur_mod->mod_name, "DENYED");

			navi_module_decref(cur_mod);
			navi_ic_module_chain_decref(req->ic_chain);
			req->ic_chain = NULL;
			req->ic_mod = NULL;
			req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
			req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
			goto next_step;
		}
		else if (req->main_data->cur_ctrl == NAVI_ROOT_CONCLUDE) {
			navi_response_t* resp = navi_request_response_obj(r);
			if (resp->error.code == NULL_CODE)
				navi_response_set_desc(resp, 0, cur_mod->mod_name, "CONCLUDED");

			navi_module_decref(cur_mod);
			navi_ic_module_chain_decref(req->ic_chain);
			req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
			req->main_data->cur_stage = NAVI_ROOT_STAGE_POST_APP;
			req->ic_chain = NULL;
			req->ic_mod = NULL;
			goto next_step;
		}

		navi_ic_link_t* next_ic = (navi_ic_link_t*)navi_list_data(req->ic_mod->link.next,
			navi_ic_link_t,link);
		navi_module_decref(cur_mod);
		if (next_ic->module) {
			req->ic_mod = next_ic;
			cur_mod = next_ic->module;
			int ic_ret = navi_module_run_request(cur_mod, r);
			if (ic_ret!=NAVI_OK) {
				navi_module_impl_t* ic_mi = navi_mod_h2i(cur_mod);
				if (ic_ret == NAVI_DENY ) {
					if (ic_mi->ret_ctrl_mask|NAVI_IC_ALLOW_DENEY) {
						req->main_data->cur_ctrl = NAVI_ROOT_DENYED;
					}
					//有可能有子请求及其他
					goto drive;
				}
				else if (ic_ret == NAVI_CONCLUDED ) {
					if (ic_mi->ret_ctrl_mask|NAVI_IC_ALLOW_CONCLUDE) {
						req->main_data->cur_ctrl = NAVI_ROOT_CONCLUDE;
					}
					goto drive;
				}

				if (req->resp_http_code==0||req->resp_http_code==200)
					req->resp_http_code = 500;
				navi_response_t* resp = navi_request_response_obj(r);
				if (resp->error.code==NULL_CODE)
					navi_response_set_desc(resp,-1,cur_mod->mod_name, "ic module impl failed");

				navi_request_cancel(r);
				navi_ic_module_chain_decref(req->ic_chain);
				navi_module_decref(req->ic_mod->module);
				req->ic_mod = NULL;
				req->ic_chain = NULL;
				req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
				req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
				goto next_step;
			}
			goto drive;
		}

		navi_ic_module_chain_decref(req->ic_chain);
		req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
		req->main_data->cur_stage = NAVI_ROOT_STAGE_APP;
		req->ic_chain = NULL;
		req->ic_mod = NULL;
		goto next_step;
	}
	break;
	case NAVI_ROOT_STAGE_APP:{
		if (req->app_mod == NULL) {
			cur_mod = (navi_module_t*)navi_hash_get_gr(mgr->module_map,req->main_data->module);
			if (!cur_mod) {
				char tmp_buf[256];
				snprintf(tmp_buf, sizeof(tmp_buf), "Module:%s not found",
					req->main_data->module);
				navi_http_request_abort_bigpost(r);
				navi_http_response_set_status(r, 405);
				navi_http_response_set_header(r, RESP_HEADER_MODULE, tmp_buf);
				navi_response_set_desc( navi_request_response_obj(r),405, "navi frame", tmp_buf );
				req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
				goto next_step;
			}

			navi_module_impl_t* mi = navi_mod_h2i(cur_mod);
			if (mi->enable == 0) {
				char tmp_buf[256];
				snprintf(tmp_buf, sizeof(tmp_buf), "Module:%s is disabled",
					req->main_data->module);
				navi_http_request_abort_bigpost(r);
				navi_http_response_set_status(r, 405);
				navi_http_response_set_header(r, RESP_HEADER_MODULE, tmp_buf);
				navi_response_set_desc( navi_request_response_obj(r),405, "navi frame", tmp_buf );
				req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
				goto next_step;
			}

			if (mi->module_type != NAVI_MODULE_TYPE_APP) {
				char tmp_buf[256];
				snprintf(tmp_buf, sizeof(tmp_buf), "Module:%s not found",
					req->main_data->module);
				navi_http_request_abort_bigpost(r);
				navi_http_response_set_status(r, 405);
				navi_http_response_set_header(r, RESP_HEADER_MODULE, tmp_buf);
				navi_response_set_desc( navi_request_response_obj(r),405, "navi frame", tmp_buf );
				req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
				goto next_step;
			}

			req->app_mod = cur_mod;
			int mod_ret = navi_module_run_request(cur_mod, r);
			if (mod_ret != NAVI_OK) {
				navi_module_impl_t* ic_mi = navi_mod_h2i(cur_mod);
				if (mod_ret == NAVI_DENY ) {
					if (ic_mi->ret_ctrl_mask|NAVI_IC_ALLOW_DENEY) {
						req->main_data->cur_ctrl = NAVI_ROOT_DENYED;
					}
					//有可能有子请求及其他
					goto drive;
				}
				else if (mod_ret == NAVI_CONCLUDED ) {
					req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
					goto drive;
				}

				navi_http_request_abort_bigpost(r);

				if (req->resp_http_code==0||req->resp_http_code==200)
					req->resp_http_code = 500;
				navi_response_t* resp = navi_request_response_obj(r);
				if (resp->error.code==NULL_CODE)
					navi_response_set_desc(resp,-1,cur_mod->mod_name, "app module impl failed");

				navi_request_cancel(r);
				navi_module_decref(cur_mod);
				req->app_mod = NULL;
				req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
				req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
				goto next_step;
			}

			if ( req->main_data->bigpost_file ) {
				if ( req->main_data->bigpost_complete && !req->main_data->bigpost_abort ) {
					//不等待子请求定时器虚事件结束，即可进入bigpost的处理
					req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
					req->main_data->cur_stage = NAVI_ROOT_STAGE_APP_BIGPOST;
					goto next_step;
				}
				if ( req->main_data->bigpost_abort ) {
					if ( req->resp_http_code == 0 || req->resp_http_code == 200) {
						req->resp_http_code = 503;
					}

					navi_response_t* resp = navi_request_response_obj(r);
					if (resp->error.code == NULL_CODE)
						navi_response_set_desc(resp, 503, cur_mod->mod_name, "aborted by server");
				}
			}
			goto drive;
		}

		cur_mod = req->app_mod;
		if (req->main_data->cur_ctrl == NAVI_ROOT_DENYED) {
			if (req->resp_http_code==0 || req->resp_http_code==200) {
				req->resp_http_code = 405;
			}

			navi_http_request_abort_bigpost(r);

			navi_response_t* resp = navi_request_response_obj(r);
			if (resp->error.code == NULL_CODE)
				navi_response_set_desc(resp, 405, cur_mod->mod_name, "DENYED");

			navi_module_decref(cur_mod);

			req->app_mod = NULL;
			req->main_data->cur_stage = NAVI_ROOT_STAGE_POST_APP;
			req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
			goto next_step;
		}

		if (req->main_data->bigpost_file ) {
			if ( req->main_data->bigpost_complete ) {
				req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
				req->main_data->cur_stage = NAVI_ROOT_STAGE_APP_BIGPOST;
				goto next_step;
			}
			else if (req->main_data->bigpost_abort ) {
				if ( req->resp_http_code == 0 || req->resp_http_code == 200) {
					req->resp_http_code = 503;
				}

				navi_response_t* resp = navi_request_response_obj(r);
				if (resp->error.code == NULL_CODE)
					navi_response_set_desc(resp, 503, cur_mod->mod_name, "aborted by server");

				navi_module_decref(cur_mod);

				req->app_mod = NULL;
				req->main_data->cur_stage = NAVI_ROOT_STAGE_POST_APP;
				req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
				goto next_step;
			}
		}

		if ( navi_request_can_step(&req->handle) ) {
			navi_module_decref(cur_mod);
			req->main_data->cur_stage=NAVI_ROOT_STAGE_POST_APP;
			req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
			req->app_mod = NULL;
			goto next_step;
		}
		else
			return NAVI_OK;
	}
	break;
	case NAVI_ROOT_STAGE_APP_BIGPOST:{
		cur_mod = req->app_mod;
		if ( req->main_data->bigpost_temp_file ) {
			const navi_method_proc_t* procs = navi_module_get_method(cur_mod,req->main_data->method);
			int mod_ret = procs->bigpost_step(cur_mod, r, req->main_data->bigpost_temp_file);
			req->main_data->bigpost_temp_file = NULL;

			if ( mod_ret != NAVI_OK ) {
				navi_module_impl_t* ic_mi = navi_mod_h2i(cur_mod);
				if (mod_ret == NAVI_DENY ) {
					if (ic_mi->ret_ctrl_mask|NAVI_IC_ALLOW_DENEY) {
						req->main_data->cur_ctrl = NAVI_ROOT_DENYED;
					}
					//有可能有子请求及其他
					goto drive;
				}
				else if (mod_ret == NAVI_CONCLUDED ) {
					req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
					goto drive;
				}

				if (req->resp_http_code==0||req->resp_http_code==200)
					req->resp_http_code = 500;
				navi_response_t* resp = navi_request_response_obj(r);
				if (resp->error.code==NULL_CODE)
					navi_response_set_desc(resp,-1,cur_mod->mod_name, "app module impl failed");

				navi_request_cancel(r);
				navi_module_decref(cur_mod);
				req->app_mod = NULL;
				req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
				req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
				goto next_step;
			}
			goto drive;
		}

		if (req->main_data->cur_ctrl == NAVI_ROOT_DENYED) {
			if (req->resp_http_code==0 || req->resp_http_code==200) {
				req->resp_http_code = 405;
			}

			navi_response_t* resp = navi_request_response_obj(r);
			if (resp->error.code == NULL_CODE)
				navi_response_set_desc(resp, 405, cur_mod->mod_name, "DENYED");

			navi_module_decref(cur_mod);

			req->app_mod = NULL;
			req->main_data->cur_stage = NAVI_ROOT_STAGE_POST_APP;
			req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
			goto next_step;
		}

		if ( navi_request_can_step(&req->handle)) {
			navi_module_decref(cur_mod);
			req->main_data->cur_stage=NAVI_ROOT_STAGE_POST_APP;
			req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
			req->app_mod = NULL;
			goto next_step;
		}
		else
			return NAVI_OK;
	}
	break;
	case NAVI_ROOT_STAGE_POST_APP:{
		chain_node_t* mod_lk = NULL;
		navi_ic_link_t* ic_link = NULL;
		if (req->ic_chain==NULL) {
			if (mgr->post_ic) {
				mod_lk = mgr->post_ic->head.link.next;
				if (mod_lk == &mgr->post_ic->head.link) {
					mod_lk = NULL;
					navi_ic_module_chain_decref(mgr->post_ic);
					mgr->post_ic = NULL;
				}
			}
			if (mod_lk) {
				req->ic_chain = mgr->post_ic;
				req->ic_chain->ref_count++;
				ic_link =(navi_ic_link_t*)navi_list_data(mod_lk,navi_ic_link_t,link);
				req->ic_mod = ic_link;
			}
			else {
				req->ic_chain = NULL;
				req->ic_mod = NULL;
				req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
				req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
				goto next_step;
			}
		}
		else {
			cur_mod = req->ic_mod->module;
			if (req->main_data->cur_ctrl == NAVI_ROOT_DENYED) {
				if (req->resp_http_code==0 || req->resp_http_code==200) {
					req->resp_http_code = 405;
				}
				navi_response_t* resp = navi_request_response_obj(r);
				if (resp->error.code == NULL_CODE)
					navi_response_set_desc(resp, 405, cur_mod->mod_name, "DENYED");

				navi_module_decref(cur_mod);
				navi_ic_module_chain_decref(req->ic_chain);
				req->ic_chain = NULL;
				req->ic_mod = NULL;
				req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
				req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
				goto next_step;
			}
			navi_module_decref(cur_mod);
			navi_ic_link_t* next_ic = (navi_ic_link_t*)navi_list_data(req->ic_mod->link.next,
				navi_ic_link_t,link);
			if (next_ic->module) {
				req->ic_mod = next_ic;
			}
			else {
				navi_ic_module_chain_decref(req->ic_chain);
				req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
				req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
				req->ic_chain = NULL;
				req->ic_mod = NULL;
				goto next_step;
			}
		}

		cur_mod = req->ic_mod->module;
		int ic_ret = navi_module_run_request(cur_mod, r);
		if (ic_ret!=NAVI_OK) {
			navi_module_impl_t* ic_mi = navi_mod_h2i(cur_mod);
			if (ic_ret == NAVI_DENY ) {
				if (ic_mi->ret_ctrl_mask|NAVI_IC_ALLOW_DENEY) {
					req->main_data->cur_ctrl = NAVI_ROOT_DENYED;
				}
				//有可能有子请求及其他
				goto drive;
			}
			else if (ic_ret == NAVI_CONCLUDED ) {
				req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
				goto drive;
			}

			if (req->resp_http_code==0||req->resp_http_code==200)
				req->resp_http_code = 500;
			navi_response_t* resp = navi_request_response_obj(r);
			if (resp->error.code==NULL_CODE)
				navi_response_set_desc(resp,-1,cur_mod->mod_name, "ic module impl failed");

			navi_request_cancel(r);
			navi_module_decref(cur_mod);
			navi_ic_module_chain_decref(req->ic_chain);
			req->ic_mod = NULL;
			req->ic_chain = NULL;
			req->main_data->cur_ctrl = NAVI_ROOT_NO_CTRL;
			req->main_data->cur_stage = NAVI_ROOT_STAGE_FINALIZED;
			goto next_step;
		}
		goto drive;
	}
	break;
	case NAVI_ROOT_STAGE_FINALIZED:{
		navi_request_set_status(r, NAVI_REQUEST_COMPLETE);
		build_default_main_response(r, NULL);
		return NAVI_OK;
	}
	break;
	default:
		return NAVI_INNER_ERR;
	}
drive:
	//if (req->pending_subs == 0 && !navi_request_has_timers(r) && !navi_request_has_vh(r) ) {
	//	goto next_step;
	//}
	if ( navi_request_can_step(r))
		goto next_step;

	return NAVI_OK;
}

bool navi_mgr_judge_bigpost(navi_module_mgr_t* mgr, navi_request_t* r)
{
	if ( !mgr || mgr->enable_bigpost==false )
		return false;

	if (!check_req_h(r))
		return false;

	navi_request_impl_t* req = navi_req_h2i(r);
	if (req->main != req)
		return false;

	const char* post_len_str = navi_http_request_get_header(r, "content-length");
	if (!post_len_str || strlen(post_len_str)==0)
		return false;

	size_t post_len = strtol(post_len_str, NULL, 10);
	if (post_len <= 0)
		return false;

	navi_module_t* mod ;
	if ( NULL == (mod= navi_hash_get_gr(mgr->module_map, navi_request_module(r)))) {
		return false;
	}

	const navi_method_proc_t* method_attr = navi_module_get_method(mod, navi_request_method(r));
	if ( method_attr == NULL)
		return false;

	if ( method_attr->bigpost && post_len >= method_attr->bigpost_threshold ) {
		req->main_data->bigpost_file = 1;
		return true;
	}

	return false;
}

void* navi_mgr_get_bigpost_filemgr(navi_module_mgr_t* mgr, navi_request_t* r)
{
    void *fmgr = NULL;
	if(!mgr)
		return fmgr;

	if (!check_req_h(r))
		return fmgr;

	navi_request_impl_t* req = navi_req_h2i(r);
	if (req->main != req)
		return fmgr;

	navi_module_t* mod ;
	if ( NULL == (mod= navi_hash_get_gr(mgr->module_map, navi_request_module(r)))) {
		return fmgr;
	}

	const navi_method_proc_t* method_attr = navi_module_get_method(mod, navi_request_method(r));
	if (method_attr)
        fmgr = method_attr->bigpost_filemgr;
		
	return fmgr;
}

navi_module_t* navi_mgr_get_module(navi_module_mgr_t* mgr, const char* mod_name)
{
	navi_module_t* ret = NULL;
	if (!mgr) return ret;

	return (navi_module_t*)navi_hash_get_gr(mgr->module_map, mod_name);
}
