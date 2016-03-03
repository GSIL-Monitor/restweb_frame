/** \brief 
 * playlog_handler.h
 *  Created on: 2015-3-26
 *      Author: zoudaobing
 *  brief: 提供文件播放记录功能，统计信息用于LRU 删除
 */

#ifndef _PLAYLOG_HANDLER_H_
#define _PLAYLOG_HANDLER_H_

#include <navi_task.h>
#include <nvcli_redis.h>

typedef struct playlog_s {
    char *fileid;
	char *count;
} playlog_t;

//加载lua脚本，后续调用直接使用sha值
int playlog_init(navi_task_t* task, const struct sockaddr* peer_addr);

//playlog_list为playlog_t类型数组
int playlog_report(nvcli_redis_t* redis, navi_pool_t* pool, navi_array_t *playlog_list);

//maxn 返回最近最少播放文件的最大条数
int playlog_lru_get(nvcli_redis_t* redis, unsigned int maxn, navi_pool_t* pool);

//更新统计周期
int playlog_lru_update(nvcli_redis_t* redis);

#endif

