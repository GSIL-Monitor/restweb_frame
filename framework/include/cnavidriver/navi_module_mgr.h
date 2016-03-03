/*
 * restmodulemgr.h
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 *      Desc:
 *      	模块管理器。管理模块的加载、刷新，请求的驱动出入口，定时器的管理等。
 *      	业务模块不需要关心该接口
 */

#ifndef NAVI_MODULE_MGR_H_
#define NAVI_MODULE_MGR_H_
#include "navi_module.h"
#include "navi_timer_mgr.h"
#include "navi_simple_hash.h"
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct navi_module_mgr_s navi_module_mgr_t;

//每个link有一个对module的引用计数
typedef struct navi_ic_link_s {
	navi_module_t* module;
	chain_node_t link;
}navi_ic_link_t;

typedef struct navi_ic_module_chain_s {
	uint32_t ref_count; //请求引用计数
	navi_ic_link_t head;//head module为空
	navi_pool_t pool[0]; //pool空间
}navi_ic_module_chain_t;

typedef struct navi_module_mono_ctrl_s
{
	char* module_name;
	int lock_fd; //用于抢占运行的写文件锁。
	int mono_run; //标记当前worker下的mgr，是否持有该模块的运行锁
} navi_module_mono_ctrl_t;

struct navi_module_mgr_s
{
	navi_pool_t* pool;
	navi_hash_t* module_map; //持有当前配置初始化模块。
	navi_hash_t* so_map; //独立管理动态加载的so的句柄。退出时不释放

	//navi_module_mono_ctrl_t成员
	navi_hash_t* mono_ctrl; //单实例运行模块的控制结构, 某些模块限制只在一个worker进程下运行。

	char* service_name;
	char* module_so_dir;
	bool debug;
	json_t* rmm_conf; //rest module manager全局配置对象
	time_t rmm_conf_last;

	bool enable_bigpost;

	//json_t* scfile_conf;
	//time_t scfile_conf_last;

	char* conf_dir;

	navi_ic_module_chain_t* prev_ic;
	navi_ic_module_chain_t* post_ic;

	navi_timer_mgr_t timer_mgr;
};

/*
 * 	@func: navi_mgr_init
 * 	@args:
 * 		conf_path: 初始化使用的配置文件目录。如果为NULL,使用默认值/etc/restmodule。
 * 	@desc:
 * 		初始化中间层日志全局对象。
 *		扫描指定配置目录下的所有.json文件，以及主配置navi.json文件。
 *		对每个.json配置，尝试加载对应的navi module，如果加载成功，则将其加入
 *		module map。
 *
 *		根据navi.json中的calling_chain配置，组织事前事后基础模块链。(已成功加载的模块才会加入
 *		基础模块调用链表中)
 *
 *		根据navi.json配置，设置中间层框架日志的日志级别。
 *		初始化定时器管理器
 */
navi_module_mgr_t* navi_mgr_init(const char* conf_path);
void navi_mgr_free(navi_module_mgr_t* pprmm);

/*
 *	@func: navi_mgr_check_modules
 *	@desc:
 *		1: 对已加载模块，如果原初始化配置文件有修改，则刷新(如果配置文件enable设置为0，则仅disable)
 *		2: 扫描配置目录，对新出现的配置文件，尝试新增对应模块。
 *		3：对那些初始化配置文件不存在的模块，进行卸载。
 *		4： 检查navi.json是否有刷新，有则更新相关配置。
 *		5： 重构基础模块调用链表。
 */
void navi_mgr_check_modules(navi_module_mgr_t* prmm);

/*
 * 	@func: navi_mgr_run_request
 * 	@args:
 * 		prmm  module manager
 * 		r	主请求句柄。主请求的navi请求参数需要drvier进行设置。参考navi_request_driver.h
 * 	@desc
 * 		事前基础模块调用。
 * 		模块查找-> module_example_process_request调用。
 */
int navi_mgr_run_request(navi_module_mgr_t* prmm, navi_request_t* r);

bool navi_mgr_judge_bigpost(navi_module_mgr_t* prmm, navi_request_t* r);

void* navi_mgr_get_bigpost_filemgr(navi_module_mgr_t* mgr, navi_request_t* r);

navi_module_t* navi_mgr_get_module(navi_module_mgr_t* mgr, const char* module_name);

#ifdef __cplusplus
}
#endif

#endif /* RESTMODULEMGR_H_ */
