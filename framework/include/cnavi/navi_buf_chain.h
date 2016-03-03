/*
 * navi_buf_chain.h
 *
 *  Created on: 2013-9-23
 *      Author: li.lei
 *      Desc: navi框架内部用来缓存驱动层给出的数据流。一般是http post的内容或者http响应体
 */

#ifndef NAVI_BUF_CHAIN_H_
#define NAVI_BUF_CHAIN_H_

#include "navi_pool.h"

typedef struct navi_buf_node_s
{
	size_t capacity;
	size_t size;
	void* buf;
	int fd;
	size_t filepos;
	struct navi_buf_node_s *next;
	unsigned infile:1;
	unsigned read:1;
}navi_buf_node_t;

typedef struct navi_buf_chain_s
{
	size_t sum;
	navi_buf_node_t* head;
	navi_buf_node_t** tail;

	navi_buf_node_t** read_node;

	navi_buf_node_t* recycle;
	navi_pool_t *pool; //cnavi0.3.0优化，chain使用request的pool，不独立建立pool
}navi_buf_chain_t;

navi_buf_chain_t* navi_buf_chain_init(navi_pool_t* pool);

int navi_buf_chain_append(navi_buf_chain_t* chain, const uint8_t* part, size_t sz);
int navi_buf_chain_insert_head(navi_buf_chain_t* chain, const uint8_t* part, size_t sz);
size_t navi_buf_chain_get_content(navi_buf_chain_t* chain, uint8_t* buf, size_t sz);

int navi_buf_chain_append_file(navi_buf_chain_t* chain,int fd, size_t pos);
int navi_buf_chain_append_part_file(navi_buf_chain_t* chain, int fd, size_t pos_begin,
	size_t content_size);
int navi_buf_chain_insert_head_file(navi_buf_chain_t* chain, int fd, size_t pos,
	size_t content_size);



size_t navi_buf_chain_read_part(navi_buf_chain_t* chain, uint8_t** buf);

/*
 *	@func navi_buf_chain_recycle
 *	@args
 *		chain: 待回收的navi_buf_chain_t
 *		newpos: 剩余的有效内容所在buf起始地址
 *    offset: 有效内容起始pos
 *	@desc
 *		回收buffer，加入recycle链表，如一块buffer中部分有效，将有效内容移至buffer头
 */

void navi_buf_chain_recycle(navi_buf_chain_t* chain, void *busy_part/*, size_t *offset*/);
void navi_buf_chain_recycle_readed(navi_buf_chain_t* chain);


#endif /* NAVI_BUF_CHAIN_H_ */
