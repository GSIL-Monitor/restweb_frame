/** \brief 
 * playlog_handler.h
 *  Created on: 2015-3-26
 *      Author: zoudaobing
 *  brief: �ṩ�ļ����ż�¼���ܣ�ͳ����Ϣ����LRU ɾ��
 */

#ifndef _PLAYLOG_HANDLER_H_
#define _PLAYLOG_HANDLER_H_

#include <navi_task.h>
#include <nvcli_redis.h>

typedef struct playlog_s {
    char *fileid;
	char *count;
} playlog_t;

//����lua�ű�����������ֱ��ʹ��shaֵ
int playlog_init(navi_task_t* task, const struct sockaddr* peer_addr);

//playlog_listΪplaylog_t��������
int playlog_report(nvcli_redis_t* redis, navi_pool_t* pool, navi_array_t *playlog_list);

//maxn ����������ٲ����ļ����������
int playlog_lru_get(nvcli_redis_t* redis, unsigned int maxn, navi_pool_t* pool);

//����ͳ������
int playlog_lru_update(nvcli_redis_t* redis);

#endif

