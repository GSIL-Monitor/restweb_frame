/*
 * restmodulemgr.h
 *
 *  Created on: 2013-8-29
 *      Author: li.lei
 *      Desc:
 *      	ģ�������������ģ��ļ��ء�ˢ�£��������������ڣ���ʱ���Ĺ���ȡ�
 *      	ҵ��ģ�鲻��Ҫ���ĸýӿ�
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

//ÿ��link��һ����module�����ü���
typedef struct navi_ic_link_s {
	navi_module_t* module;
	chain_node_t link;
}navi_ic_link_t;

typedef struct navi_ic_module_chain_s {
	uint32_t ref_count; //�������ü���
	navi_ic_link_t head;//head moduleΪ��
	navi_pool_t pool[0]; //pool�ռ�
}navi_ic_module_chain_t;

typedef struct navi_module_mono_ctrl_s
{
	char* module_name;
	int lock_fd; //������ռ���е�д�ļ�����
	int mono_run; //��ǵ�ǰworker�µ�mgr���Ƿ���и�ģ���������
} navi_module_mono_ctrl_t;

struct navi_module_mgr_s
{
	navi_pool_t* pool;
	navi_hash_t* module_map; //���е�ǰ���ó�ʼ��ģ�顣
	navi_hash_t* so_map; //��������̬���ص�so�ľ�����˳�ʱ���ͷ�

	//navi_module_mono_ctrl_t��Ա
	navi_hash_t* mono_ctrl; //��ʵ������ģ��Ŀ��ƽṹ, ĳЩģ������ֻ��һ��worker���������С�

	char* service_name;
	char* module_so_dir;
	bool debug;
	json_t* rmm_conf; //rest module managerȫ�����ö���
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
 * 		conf_path: ��ʼ��ʹ�õ������ļ�Ŀ¼�����ΪNULL,ʹ��Ĭ��ֵ/etc/restmodule��
 * 	@desc:
 * 		��ʼ���м����־ȫ�ֶ���
 *		ɨ��ָ������Ŀ¼�µ�����.json�ļ����Լ�������navi.json�ļ���
 *		��ÿ��.json���ã����Լ��ض�Ӧ��navi module��������سɹ����������
 *		module map��
 *
 *		����navi.json�е�calling_chain���ã���֯��ǰ�º����ģ������(�ѳɹ����ص�ģ��Ż����
 *		����ģ�����������)
 *
 *		����navi.json���ã������м������־����־����
 *		��ʼ����ʱ��������
 */
navi_module_mgr_t* navi_mgr_init(const char* conf_path);
void navi_mgr_free(navi_module_mgr_t* pprmm);

/*
 *	@func: navi_mgr_check_modules
 *	@desc:
 *		1: ���Ѽ���ģ�飬���ԭ��ʼ�������ļ����޸ģ���ˢ��(��������ļ�enable����Ϊ0�����disable)
 *		2: ɨ������Ŀ¼�����³��ֵ������ļ�������������Ӧģ�顣
 *		3������Щ��ʼ�������ļ������ڵ�ģ�飬����ж�ء�
 *		4�� ���navi.json�Ƿ���ˢ�£��������������á�
 *		5�� �ع�����ģ���������
 */
void navi_mgr_check_modules(navi_module_mgr_t* prmm);

/*
 * 	@func: navi_mgr_run_request
 * 	@args:
 * 		prmm  module manager
 * 		r	�����������������navi���������Ҫdrvier�������á��ο�navi_request_driver.h
 * 	@desc
 * 		��ǰ����ģ����á�
 * 		ģ�����-> module_example_process_request���á�
 */
int navi_mgr_run_request(navi_module_mgr_t* prmm, navi_request_t* r);

bool navi_mgr_judge_bigpost(navi_module_mgr_t* prmm, navi_request_t* r);

void* navi_mgr_get_bigpost_filemgr(navi_module_mgr_t* mgr, navi_request_t* r);

navi_module_t* navi_mgr_get_module(navi_module_mgr_t* mgr, const char* module_name);

#ifdef __cplusplus
}
#endif

#endif /* RESTMODULEMGR_H_ */
