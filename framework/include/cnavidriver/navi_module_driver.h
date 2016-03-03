/*
 * navi_module_driver.h
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 *      Desc: navi框架驱动层专用接口。业务模块开发者不关心。
 */

#ifndef NAVI_MODULE_HOOK_H_
#define NAVI_MODULE_HOOK_H_
#include "navi_module.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum navi_module_type_e
{
	NAVI_MODULE_TYPE_APP = 0x0,
	NAVI_MODULE_TYPE_PRE_APP = 0x1,
	NAVI_MODULE_TYPE_POST_APP = 0x2
} navi_module_type_t;

/*
 * 	@func: navi_module_init
 * 	@args:
 * 		config_path  配置文件路径
 * 		module_mgr 全局的module_mgr
 * 	@return value
 * 		初始化模块成功时，返回模块的句柄
 * 		否则返回空。
 * 	@desc
 *		过程： 检查配置合法性，加载业务模块动态库，绑定业务模块的
 *		module_example_init,
 *		module_example_process_request,
 *		module_example_free以及各
 *		module_example_method_examplemethod方法函数。
 *		并调用module_example_init回调。
 *		过程中的任何错误，导致模块加载失败，并在syslog中记录日志
 */
navi_module_t* navi_module_init(const char* config_path,void* module_mgr);

void navi_module_decref(navi_module_t* mod);

bool navi_module_is_enable(navi_module_t* mod);
void navi_module_set_enable(navi_module_t* mod,uint8_t enable);

uint32_t navi_module_type(navi_module_t* mod);
const char* navi_module_conf_path(navi_module_t* mod);

/*
 * 	@func: navi_module_conf_changed
 * 	@desc:
 * 		看当前模块初始化时的配置文件是否发生了改变。删除不算改变。
 */
bool navi_module_conf_changed(navi_module_t* mod);
/*
 * 	@func:navi_module_conf_disabled
 * 	@desc:
 * 		当前模块初始化时使用的配置文件的enable是否设置为0/false。
 * 		当navi_module_conf_changed()为真，且navi_module_conf_disabled()
 * 		为真,仅仅disable该模块，而不是刷新(卸载再加载)模块。
 */
bool navi_module_conf_disabled(navi_module_t* mod);


#ifdef __cplusplus
}
#endif

#endif /* NAVI_MODULE_HOOK_H_ */
