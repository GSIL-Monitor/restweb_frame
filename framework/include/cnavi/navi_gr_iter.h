/*
 * navi_gr_iter.h
 *
 *  Created on: 2014-4-25
 *      Author: li.lei
 */

#ifndef NAVI_GR_ITER_H_
#define NAVI_GR_ITER_H_

#include "navi_common_define.h"
#include "navi_pool.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct navi_griter_s {
	//�α�����ڲ�ʹ��
	uint32_t _magic;
	chain_node_t link; //it_mgrʹ�á�using_iter/iter_pool������
	void* mgr;

	//iter�α����
	union {
		void* cur;
		struct {
			uint32_t i;
			uint32_t j;
		};
	};
	void* ctx;
}navi_griter_t;

typedef struct navi_griter_mgr_s {
	chain_node_t using_iter;
	chain_node_t iter_pool;
	navi_pool_t* pool; //���Ϊ�գ�it�Զѹ���������pool����
} navi_griter_mgr_t;

void navi_griter_mgr_init(navi_griter_mgr_t* mgr, navi_pool_t* pool/*����Ϊ�գ��ѷ��������*/);
void navi_griter_mgr_clean(navi_griter_mgr_t* mgr);

navi_griter_t* navi_griter_get(navi_griter_mgr_t* mgr);
void navi_griter_recycle(navi_griter_t* iter);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_GR_ITER_H_ */
