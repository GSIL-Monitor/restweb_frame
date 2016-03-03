/*
 * restmodule.h
 *
 *  Created on: 2013-8-28
 *      Author: li.lei
 *      Desc:
 *      	提供给业务模块使用的接口。
 *      	* module_xxx_init 类型定义
 *      	* module_xxx_free 类型定义
 *      	* module_xxx_process_request 类型定义
 *      	* module_xxx_method_yyy 类型定义
 *      	* 模块级定时器接口
 */

#ifndef NAVI_MODULE_H_
#define NAVI_MODULE_H_

#include "navi_request.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct navi_module_s
{
	uint32_t _magic;
	char* mod_name;
	json_t* js_conf; //模块配置，暴露给应用。应用应该只读使用
	void* module_data; //模块自定义的模块全局的数据,有业务模块自己管理
} navi_module_t;

#define NAVI_MODULE_INIT(mod_nm,mod) int module_##mod_nm##_init(navi_module_t* mod)
#define NAVI_MODULE_FREE(mod_nm,mod) void module_##mod_nm##_free(navi_module_t* mod)
#define NAVI_MODULE_REQUEST_PROC(mod_nm,mod,req) int module_##mod_nm##_process_request(navi_module_t* mod,navi_request_t* req)
#define NAVI_MODULE_METHOD(mod_nm,mt_nm,mod,req) int module_##mod_nm##_method_##mt_nm(navi_module_t* mod,navi_request_t* req)
#define NAVI_MODULE_BIGPOST(mod_nm,mt_nm,mod,req,posted_path) int module_##mod_nm##_bigpost_##mt_nm(navi_module_t* mod,navi_request_t* req,\
	const char* posted_path)

typedef void (*module_free_fp)(navi_module_t* module);
typedef int (*module_method_fp)(navi_module_t* module, navi_request_t* request);
typedef int (*module_method_bigpost_fp)(navi_module_t* module, navi_request_t* request, const char* posted_path);
typedef int (*module_process_fp)(navi_module_t* module, navi_request_t* request);
typedef int (*module_init_fp)(navi_module_t* module);

/*
 * 	@func navi_module_default_process
 * 	@desc:
 *		模块内方法查找，如果存在则调用。否则返回405 not allowed.
 *		可以作为业务模块默认的process_request实现。
 *		如果业务模块不提供process_request，则中间层使用该默认行为。
 *		业务模块也可以在自己的process_request中调用该接口。
 */
int navi_module_default_process(navi_module_t* module, navi_request_t* request);

/*
 *	@func navi_module_add_interval_timer
 *	@args
 *		mod: 定时器所在的语境。在init/process/method等回调中使用该接口时，传递模块mod参数
 *		tm_ms: 定时器时间间隔
 *		fun: 定时器回调
 *		args: 回调参数
 *		destroyer: 定时器销毁时的dtor, 如果不需要，指定NULL
 *	@desc
 *		增加一个周期性定时器。
 *		当模块卸载时，同时会卸载所有在该模块语境下增加的定时器。如果定时器有destroyer，
 *		这些destroyer会被调用。
 */
navi_timer_h navi_module_add_interval_timer(navi_module_t* mod, uint32_t tm_ms,
    timer_handler_fp fun, void* args, timer_handler_fp destroy);
/*
 *	@func navi_module_add_once_timer
 *	@desc
 *		与周期性参数意义相同，但增加的是一次性的定时器。超时后，调用fun，如果有destroyer，
 *		还是调用destroyer
 */
navi_timer_h navi_module_add_once_timer(navi_module_t* mod, uint32_t tm_ms,
    timer_handler_fp fun, void* args, timer_handler_fp destroy);
/*
 * 	@func navi_module_cancel_timer
 * 	@desc
 * 		注销定时器的接口
 */
void navi_module_cancel_timer(navi_timer_h h);

navi_module_t* navi_request_current_module(navi_request_t* root);

typedef enum navi_module_mono_mode_E
{
	NOT_MONO_MOD,
	MONO_LEADER,
	MONO_FOLLOWER
} navi_module_mono_mode_e;

navi_module_mono_mode_e navi_module_mono_mode(navi_module_t* module);

navi_pool_t* navi_module_pool(navi_module_t* module);

#ifdef __cplusplus
}
#endif

#endif /* RESTMODULE_H_ */
