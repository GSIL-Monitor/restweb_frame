/*
 * navi_module_impl.h
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 */

#ifndef NAVI_MODULE_IMPL_H_
#define NAVI_MODULE_IMPL_H_

#include "navi_simple_hash.h"
#include "navi_module.h"

#define NAVI_MOD_HANDLE_MAGIC 0x786acdf1

#define CONF_MODULE_NAME "module_name"
#define CONF_ENABLE "enable"

#define CONF_METHODS "methods"
#define CONF_BIGPOST_METHODS "bigpost_methods"

#define CONF_MODULE_TYPE "module_type"
#define CONF_MODULE_TYPE_APP "app"
#define CONF_MODULE_TYPE_RRE_APP "prev_app"
#define CONF_MODULE_TYPE_POST_APP "post_app"

#define CONF_MODULE_ALLOW_DENY "allow_deny_request"
#define CONF_MODULE_ALLOW_CONCLUDE "allow_conclude_request"

#define CONF_MODULE_TRACE "enable_trace"

#define CONF_MODULE_SO_NAME "so_name"

typedef enum navi_ic_module_ctrl_e
{
	NAVI_IC_NO_CTRL = 0x0,
	NAVI_IC_ALLOW_DENEY = 0x1,
	NAVI_IC_ALLOW_CONCLUDE = 0x2
} navi_ic_ctrl_type;

typedef struct navi_method_proc_s
{
	module_method_fp method;
	module_method_bigpost_fp bigpost_step;
	void* bigpost_filemgr; //!< 控制body文件的目录路径
	size_t bigpost_threshold; //!< 以文件形式提供的门限，大于等于时以文件上传
	int bigpost:1;
} navi_method_proc_t;

typedef struct navi_module_impl_s{
	navi_module_t handle;
	void* so_handle;

	navi_hash_t* methods; //!< navi_request_proc_t类型

	module_init_fp init;
	module_free_fp free;
	bool free_called;
	module_process_fp process;

	//一些通用控制及状态成员
	uint8_t enable;
	uint32_t module_type;
	uint32_t ret_ctrl_mask;

	char* conf_path;
	time_t conf_last_modify;

	void* navi_mgr;

	//模块可以被request引用，也可以被内部组件模块链表引用
	//还会被模块hash表引用(模块hash表是当前配置初始化的模块，
	//可能和之前配置初始化的模块同时存在)
	uint32_t ref_count;
	int enable_trace:1;
	navi_pool_t pool[0];
}navi_module_impl_t;

int navi_module_run_request(navi_module_t* mod, navi_request_t* root);
const navi_method_proc_t* navi_module_get_method(navi_module_t* mod, const char* method);
void navi_module_incref(navi_module_t* mod);

#define navi_mod_h2i(h) ((navi_module_impl_t*)((char*)(h) - offsetof(navi_module_impl_t,handle)))
#define check_navi_mod_h(h) ((h) && (h)->_magic==NAVI_MOD_HANDLE_MAGIC)

#endif /* NAVI_MODULE_IMPL_H_ */
