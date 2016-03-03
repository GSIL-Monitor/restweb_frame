/*
 * navi_module_impl.c
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 */

#include "navi_module_impl.h"
#include "navi_module_driver.h"
#include "navi_frame_log.h"
#include "navi_module_mgr.h"
#include "navi_timer_mgr.h"
#include "navi_static_content.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dlfcn.h>

#define NAVI_MODULE_POOL_INIT (sizeof(navi_module_impl_t)+0x1000)
static void navi_module_free(navi_module_t* mod);

void navi_module_incref(navi_module_t* mod)
{
	if (!check_navi_mod_h(mod))
			return;

	navi_module_impl_t* mi = navi_mod_h2i(mod);
	mi->ref_count++;
}

void navi_module_decref(navi_module_t* mod)
{
	if (!check_navi_mod_h(mod))
		return;

	navi_module_impl_t* mi = navi_mod_h2i(mod);
	if (--mi->ref_count==0) {
		navi_module_free(&mi->handle);
	}
}

int navi_module_run_request(navi_module_t* mod, navi_request_t* root)
{
	navi_module_impl_t* mi = navi_mod_h2i(mod);
	navi_module_incref(mod);
	if (mi->process==NULL)return NAVI_OK;
	return mi->process(mod, root);
}

#define ALIGN_SIZE_1M(sz) (((sz)+ 0xfffff ) & 0x7ff00000 )

navi_module_t* navi_module_init(const char* config_path, void* mgr) {
	if (!config_path)
		return NULL;

	json_error_t js_err;
	json_t* js_config = json_load_file(config_path, &js_err);
	if (!js_config) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "load module json failed:%s line:%d. %s",
		    config_path, js_err.line, js_err.text);
		return NULL;
	}

	struct stat stbuf;
	stat(config_path, &stbuf);

	json_t* e = json_object_get(js_config, CONF_MODULE_NAME);
	if (!e || !json_is_string(e)) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "module config: %s is absent. Conf:%s.",
			CONF_MODULE_NAME,config_path);
		json_decref(js_config);
		return NULL;
	}

	const char* mod_name = json_string_value(e);
	if (strlen(mod_name) == 0) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "module config: %s is absent. Conf:%s",
			CONF_MODULE_NAME, config_path);
		json_decref(js_config);
		return NULL;
	}

	char tmp_path[1024];
	tmp_path[0] = 0;
	navi_module_mgr_t* navi_mgr = (navi_module_mgr_t*) mgr;

	void* so_handle = NULL;
	bool so_new = false;
	if (navi_mgr->so_map) {
		so_handle = navi_hash_get_gr(navi_mgr->so_map, mod_name);
	}
	if (so_handle == NULL) {
		/*
		 * so_name 配置项是可选的。如果存在
		 *  * 如果是绝对路径，则使用绝对路径
		 *  * 如果navi.json中有module_so_dir配置，则在该目录下查找so_name指定的动态库并加载
		 *  * 如果navi.json没有module_so_dir，则在系统运行的动态库查找路径列表上寻找so_name指定的动态库
		 *
		 *  * 如果so_name未指定或者指定为空，那么默认使用的so_name是： libxxx.so，其中的xxx是module名字
		 */
		e = json_object_get(js_config, CONF_MODULE_SO_NAME);
		if (e && json_is_string(e)) {
			const char* so_nm = json_string_value(e);
			if (strlen(so_nm)) {
				if (navi_mgr && navi_mgr->module_so_dir && !strchr(so_nm,'/') ) {
					snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
						navi_mgr->module_so_dir, so_nm);
				}
				else if( strchr(so_nm,'/') ) { //是一个路径
					if ( 0 >= navi_rpath_2abs(so_nm,tmp_path,sizeof(tmp_path)) ) {
						tmp_path[0] = 0;
						strncat(tmp_path, so_nm, sizeof(tmp_path)-1);
					}
				}
				else { //只是一个动态库名字
					tmp_path[0] = 0;
					strncat(tmp_path, so_nm, sizeof(tmp_path)-1 );
				}
			}
		}

		if (strlen(tmp_path) == 0) {
			if (navi_mgr && navi_mgr->module_so_dir) {
				snprintf(tmp_path, sizeof(tmp_path), "%s/lib%s.so",
					navi_mgr->module_so_dir, mod_name);
			}
			else {
				snprintf(tmp_path, sizeof(tmp_path), "lib%s.so", mod_name);
			}
		}
		so_handle = dlopen(tmp_path, RTLD_LAZY);
		if (!so_handle) {
			//NAVI_SYSERR_LOG("load so failed:");
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "load so failed:%s",dlerror());
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "load so: %s failed. Conf:%s", tmp_path, config_path);
			json_decref(js_config);
			return NULL;
		}
		so_new = true;
	}

	navi_module_impl_t* mod = (navi_module_impl_t*)malloc(NAVI_MODULE_POOL_INIT);
	if (!mod) {
		NAVI_SYSERR_LOG();
		json_decref(js_config);
		return NULL;
	}

	memset(mod, 0x00, sizeof(navi_module_impl_t) + sizeof(navi_pool_t));
	mod->handle._magic = NAVI_MOD_HANDLE_MAGIC;
	navi_pool_init(mod->pool, mod, 0x1000);

	mod->so_handle = so_handle;
	mod->handle.js_conf = js_config;
	mod->handle.mod_name = navi_pool_strdup(mod->pool, mod_name);

	mod->conf_last_modify = stbuf.st_mtime;

	if ( 0 < navi_rpath_2abs(config_path, tmp_path, sizeof(tmp_path))) {
		mod->conf_path = navi_pool_strdup(mod->pool, tmp_path);
	}
	else
		mod->conf_path = navi_pool_strdup(mod->pool, config_path);

	if (mod->conf_path == NULL) {
		NAVI_SYSERR_LOG();
		goto failed_ret;
	}

	mod->enable = 1;
	e = json_object_get(mod->handle.js_conf, CONF_ENABLE);
	if (e) {
		if (json_is_integer(e) && json_integer_value(e) == 0)
			mod->enable = 0;
		if (json_is_false(e))
			mod->enable = 0;
	}

	mod->module_type = NAVI_MODULE_TYPE_APP;
	e = json_object_get(mod->handle.js_conf, CONF_MODULE_TYPE);
	if (e && json_is_integer(e)) {
		switch (json_integer_value(e))
		{
		case 0:
			break;
		case 1:
			mod->module_type = NAVI_MODULE_TYPE_PRE_APP;
			break;
		case 2:
			mod->module_type = NAVI_MODULE_TYPE_POST_APP;
			break;
		default:
			NAVI_FRAME_LOG(NAVI_LOG_WARNING,
				"module %s config:%s is invalid, 0 is used as default.",
				mod->handle.mod_name, CONF_MODULE_TYPE);
			break;
		}
	}
	else if (e && json_is_string(e)) {
		const char* mod_type = json_string_value(e);
		if (strcmp(mod_type, CONF_MODULE_TYPE_RRE_APP) == 0) {
			mod->module_type = NAVI_MODULE_TYPE_PRE_APP;
		}
		else if (strcmp(mod_type, CONF_MODULE_TYPE_POST_APP) == 0) {
			mod->module_type = NAVI_MODULE_TYPE_POST_APP;
		}
		else if (strcmp(mod_type, CONF_MODULE_TYPE_APP)) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING,
				"module %s config:%s is invalid, \"app\" is used as default.",
				mod->handle.mod_name, CONF_MODULE_TYPE);
		}
	}


	mod->ret_ctrl_mask = NAVI_IC_NO_CTRL|NAVI_IC_ALLOW_DENEY|NAVI_IC_ALLOW_CONCLUDE;
	e = json_object_get(mod->handle.js_conf, CONF_MODULE_ALLOW_DENY);
	if (e ){
		if ((json_is_integer(e) && json_integer_value(e)==0)||json_is_false(e) ) {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE,
				"module %s not allow deny request.",
				mod->handle.mod_name);
			mod->ret_ctrl_mask &= ~NAVI_IC_ALLOW_DENEY;
		}
	}

	e = json_object_get(mod->handle.js_conf, CONF_MODULE_ALLOW_CONCLUDE);
	if (e ){
		if ((json_is_integer(e) && json_integer_value(e)==0)||json_is_false(e) ) {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE,
				"module %s not allow conclude request.",
				mod->handle.mod_name);
			mod->ret_ctrl_mask &= ~NAVI_IC_ALLOW_CONCLUDE;
		}
	}

	e = json_object_get(mod->handle.js_conf, CONF_MODULE_TRACE);
	if (e) {
		if (json_is_true(e) || (json_is_integer(e)&&json_integer_value(e)!=0) )
			mod->enable_trace = 1;
	}

	snprintf(tmp_path, sizeof(tmp_path), "module_%s_init", mod->handle.mod_name);
	module_init_fp fp = dlsym(mod->so_handle, tmp_path);
	if (fp) {
		mod->init = fp;
	}
	else {
		NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "function %s is null", tmp_path);
	}

	snprintf(tmp_path, sizeof(tmp_path), "module_%s_free", mod->handle.mod_name);
	module_free_fp free_fp = dlsym(mod->so_handle, tmp_path);
	if (free_fp) {
		mod->free = free_fp;
	}
	else {
		NAVI_FRAME_LOG(NAVI_LOG_NOTICE, "function %s is null", tmp_path);
	}

	snprintf(tmp_path, sizeof(tmp_path), "module_%s_process_request",
		mod->handle.mod_name);
	module_process_fp pro_fp = dlsym(mod->so_handle, tmp_path);
	if (pro_fp) {
		mod->process = pro_fp;
	}
	else {
		if (mod->module_type==NAVI_MODULE_TYPE_APP) {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE,
				"Module:%s using default method processing", mod->handle.mod_name);
			mod->process = navi_module_default_process;

			e = json_object_get(mod->handle.js_conf, CONF_METHODS);
			const json_t* bigpost_cfg = json_object_get(mod->handle.js_conf, CONF_BIGPOST_METHODS);
			const json_t* bigpost_method_cfg;
			if (e && !json_is_array(e)) {
				NAVI_FRAME_LOG(NAVI_LOG_ERR, "module config:%s exists but not array. Conf:%s",
					CONF_METHODS, config_path);
				goto failed_ret;
			}

			unsigned int mc = 0, i;
			if (e && (mc = json_array_size(e))) {

				json_t* ae;
				for (i = 0; i < mc; i++) {
					ae = json_array_get(e, i);

					const char* m_nm;
					if (!ae || !json_is_string(ae))
						continue;

					m_nm = json_string_value(ae);

					if (strlen(m_nm) == 0 || !navi_is_symbol_word(m_nm))
						continue;

					snprintf(tmp_path, sizeof(tmp_path), "module_%s_method_%s",
						mod->handle.mod_name, m_nm);
					module_method_fp m_fp = dlsym(mod->so_handle, tmp_path);
					if (!m_fp) {
						NAVI_FRAME_LOG(NAVI_LOG_ERR, "%s method not exists. Conf:%s",
							tmp_path, config_path);
						goto failed_ret;
					}

					if (!mod->methods) {
						mod->methods = navi_hash_init(mod->pool);
						if (!mod->methods) {
							NAVI_SYSERR_LOG();
							goto failed_ret;
						}
					}

					navi_method_proc_t* method_attr = navi_pool_calloc(mod->pool,1,
						sizeof(navi_method_proc_t));
					method_attr->method = m_fp;

					bigpost_method_cfg = NULL;
					if (bigpost_cfg) {
						bigpost_method_cfg = json_object_get(bigpost_cfg, m_nm);
					}

					json_t* je;
					void* scfile_mgr;
					module_method_bigpost_fp bigpost_step_fp;
					if ( !bigpost_method_cfg || !json_is_object(bigpost_method_cfg))
						goto method_reg;

					je = json_object_get(bigpost_method_cfg, "root_path");
					if ( !je || !json_is_string(je) || 0==strlen(json_string_value(je)))
						goto method_reg;

					scfile_mgr = navi_scfile_mgr_get(json_string_value(je));
					if ( scfile_mgr == NULL ) {
						NAVI_FRAME_LOG(NAVI_LOG_ERR, "%s method bigpost scfile_mgr not exists. Conf:%s",
							m_nm, config_path);
						goto failed_ret;
					}

					snprintf(tmp_path, sizeof(tmp_path), "module_%s_bigpost_%s",
						mod->handle.mod_name, m_nm);
					bigpost_step_fp = dlsym(mod->so_handle, tmp_path);
					if (!bigpost_step_fp) {
						NAVI_FRAME_LOG(NAVI_LOG_ERR, "%s bigpost method not exists. Conf:%s",
							tmp_path, config_path);
						goto failed_ret;
					}
					method_attr->bigpost_step = bigpost_step_fp;
					method_attr->bigpost_filemgr = scfile_mgr;
					method_attr->bigpost = 1;

					je = json_object_get(bigpost_method_cfg, "bigpost_threshold");
					if ( je && json_is_integer(je) ) {
						int i = json_integer_value(je);
						if ( i <= 0 ) {
							i = 4194304;
						}
						else {
							i = ALIGN_SIZE_1M(i);
						}
						method_attr->bigpost_threshold = i;
					}
					else
						method_attr->bigpost_threshold = 4194304;
method_reg:
					if (NAVI_INNER_ERR == navi_hash_set_gr(mod->methods, m_nm, method_attr/*m_fp*/)) {
						NAVI_SYSERR_LOG();
						goto failed_ret;
					}
				}
			}
		}
		else {
			NAVI_FRAME_LOG(NAVI_LOG_NOTICE,
				"IC_Module:%s has no process handler", mod->handle.mod_name);
		}
	}

	// 调用模块初始化函数
	mod->navi_mgr = mgr;
	if (mod->init) {
		int ret = (mod->init)(&mod->handle);
		if (ret != NAVI_OK) {
			NAVI_FRAME_LOG(NAVI_LOG_ERR, "module:%s init_fp calling failed.",
			    mod->handle.mod_name);
			goto failed_ret;
		}
	}

	if (navi_mgr->so_map == NULL)
		navi_mgr->so_map = navi_hash_init(navi_mgr->pool);

	if ( navi_hash_get_gr(navi_mgr->so_map, mod->handle.mod_name) == NULL ) {
		navi_hash_set_gr(navi_mgr->so_map, mod->handle.mod_name, mod->so_handle);
	}

	mod->ref_count++;
	return &mod->handle;
failed_ret:
	navi_module_free(&mod->handle);
	if ( so_new && so_handle ) {
		dlclose(so_handle);
	}
	return NULL;
}

static void navi_module_free(navi_module_t* mod) {
	if (!check_navi_mod_h(mod))
		return;

	navi_module_impl_t* mi = navi_mod_h2i(mod);

	navi_module_mgr_t* mgr = (navi_module_mgr_t*) mi->navi_mgr;
	if (mgr)
		navi_timer_mgr_clean_spec(&mgr->timer_mgr, mi);

	if (mi->free && !mi->free_called) {
		(mi->free)(mod);
	}

	if (mi->handle.js_conf)
		json_decref(mi->handle.js_conf);

	navi_pool_destroy(mi->pool);
	return;
}

bool navi_module_is_enable(navi_module_t* mod) {
	if (!check_navi_mod_h(mod))
		return false;

	navi_module_impl_t* mi = navi_mod_h2i(mod);
	return mi->enable;
}

uint32_t navi_module_type(navi_module_t* mod) {
	if (!check_navi_mod_h(mod))
		return false;

	navi_module_impl_t* mi = navi_mod_h2i(mod);
	return mi->module_type;
}

void navi_module_set_enable(navi_module_t* mod, uint8_t enable) {
	if (!check_navi_mod_h(mod))
		return;

	navi_module_impl_t* mi = navi_mod_h2i(mod);
	mi->enable = enable;
}

bool navi_module_conf_changed(navi_module_t* mod) {
	if (!check_navi_mod_h(mod))
		return false;

	navi_module_impl_t* mi = navi_mod_h2i(mod);

	struct stat stbuf;
	if (-1 == stat(mi->conf_path, &stbuf))
		return false;

	if (mi->conf_last_modify < stbuf.st_mtime)
		return true;

	return false;
}

bool navi_module_conf_disabled(navi_module_t* mod) {
	if (!check_navi_mod_h(mod))
		return false;

	navi_module_impl_t* mi = navi_mod_h2i(mod);

	struct stat stbuf;
	if (-1 == stat(mi->conf_path, &stbuf))
		return false;

	json_error_t js_err;
	json_t* js = json_load_file(mi->conf_path, &js_err);
	if (!js)
		return false;

	json_t* je = json_object_get(js, CONF_ENABLE);
	if (je && json_is_integer(je) && json_integer_value(je) == 0) {
		json_decref(js);
		return true;
	}
	if (je && json_is_false(je)) {
		json_decref(js);
		return true;
	}

	json_decref(js);
	return false;
}

const char* navi_module_conf_path(navi_module_t* mod) {
	if (!check_navi_mod_h(mod))
		return NULL;

	navi_module_impl_t* mi = navi_mod_h2i(mod);
	return mi->conf_path;
}

const navi_method_proc_t* navi_module_get_method(navi_module_t* mod, const char* method)
{
	if (!check_navi_mod_h(mod))
		return NULL;

	navi_module_impl_t* mi = navi_mod_h2i(mod);
	return (navi_method_proc_t*)navi_hash_get_gr(mi->methods, method);
}
