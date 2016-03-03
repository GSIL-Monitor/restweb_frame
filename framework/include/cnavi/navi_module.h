/*
 * restmodule.h
 *
 *  Created on: 2013-8-28
 *      Author: li.lei
 *      Desc:
 *      	�ṩ��ҵ��ģ��ʹ�õĽӿڡ�
 *      	* module_xxx_init ���Ͷ���
 *      	* module_xxx_free ���Ͷ���
 *      	* module_xxx_process_request ���Ͷ���
 *      	* module_xxx_method_yyy ���Ͷ���
 *      	* ģ�鼶��ʱ���ӿ�
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
	json_t* js_conf; //ģ�����ã���¶��Ӧ�á�Ӧ��Ӧ��ֻ��ʹ��
	void* module_data; //ģ���Զ����ģ��ȫ�ֵ�����,��ҵ��ģ���Լ�����
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
 *		ģ���ڷ������ң������������á����򷵻�405 not allowed.
 *		������Ϊҵ��ģ��Ĭ�ϵ�process_requestʵ�֡�
 *		���ҵ��ģ�鲻�ṩprocess_request�����м��ʹ�ø�Ĭ����Ϊ��
 *		ҵ��ģ��Ҳ�������Լ���process_request�е��øýӿڡ�
 */
int navi_module_default_process(navi_module_t* module, navi_request_t* request);

/*
 *	@func navi_module_add_interval_timer
 *	@args
 *		mod: ��ʱ�����ڵ��ﾳ����init/process/method�Ȼص���ʹ�øýӿ�ʱ������ģ��mod����
 *		tm_ms: ��ʱ��ʱ����
 *		fun: ��ʱ���ص�
 *		args: �ص�����
 *		destroyer: ��ʱ������ʱ��dtor, �������Ҫ��ָ��NULL
 *	@desc
 *		����һ�������Զ�ʱ����
 *		��ģ��ж��ʱ��ͬʱ��ж�������ڸ�ģ���ﾳ�����ӵĶ�ʱ���������ʱ����destroyer��
 *		��Щdestroyer�ᱻ���á�
 */
navi_timer_h navi_module_add_interval_timer(navi_module_t* mod, uint32_t tm_ms,
    timer_handler_fp fun, void* args, timer_handler_fp destroy);
/*
 *	@func navi_module_add_once_timer
 *	@desc
 *		�������Բ���������ͬ�������ӵ���һ���ԵĶ�ʱ������ʱ�󣬵���fun�������destroyer��
 *		���ǵ���destroyer
 */
navi_timer_h navi_module_add_once_timer(navi_module_t* mod, uint32_t tm_ms,
    timer_handler_fp fun, void* args, timer_handler_fp destroy);
/*
 * 	@func navi_module_cancel_timer
 * 	@desc
 * 		ע����ʱ���Ľӿ�
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
