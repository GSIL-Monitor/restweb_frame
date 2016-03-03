/*
 * navi_module_driver.h
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 *      Desc: navi���������ר�ýӿڡ�ҵ��ģ�鿪���߲����ġ�
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
 * 		config_path  �����ļ�·��
 * 		module_mgr ȫ�ֵ�module_mgr
 * 	@return value
 * 		��ʼ��ģ��ɹ�ʱ������ģ��ľ��
 * 		���򷵻ؿա�
 * 	@desc
 *		���̣� ������úϷ��ԣ�����ҵ��ģ�鶯̬�⣬��ҵ��ģ���
 *		module_example_init,
 *		module_example_process_request,
 *		module_example_free�Լ���
 *		module_example_method_examplemethod����������
 *		������module_example_init�ص���
 *		�����е��κδ��󣬵���ģ�����ʧ�ܣ�����syslog�м�¼��־
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
 * 		����ǰģ���ʼ��ʱ�������ļ��Ƿ����˸ı䡣ɾ������ı䡣
 */
bool navi_module_conf_changed(navi_module_t* mod);
/*
 * 	@func:navi_module_conf_disabled
 * 	@desc:
 * 		��ǰģ���ʼ��ʱʹ�õ������ļ���enable�Ƿ�����Ϊ0/false��
 * 		��navi_module_conf_changed()Ϊ�棬��navi_module_conf_disabled()
 * 		Ϊ��,����disable��ģ�飬������ˢ��(ж���ټ���)ģ�顣
 */
bool navi_module_conf_disabled(navi_module_t* mod);


#ifdef __cplusplus
}
#endif

#endif /* NAVI_MODULE_HOOK_H_ */
