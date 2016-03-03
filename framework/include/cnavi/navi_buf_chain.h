/*
 * navi_buf_chain.h
 *
 *  Created on: 2013-9-23
 *      Author: li.lei
 *      Desc: navi����ڲ����������������������������һ����http post�����ݻ���http��Ӧ��
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
	navi_pool_t *pool; //cnavi0.3.0�Ż���chainʹ��request��pool������������pool
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
 *		chain: �����յ�navi_buf_chain_t
 *		newpos: ʣ�����Ч��������buf��ʼ��ַ
 *    offset: ��Ч������ʼpos
 *	@desc
 *		����buffer������recycle������һ��buffer�в�����Ч������Ч��������bufferͷ
 */

void navi_buf_chain_recycle(navi_buf_chain_t* chain, void *busy_part/*, size_t *offset*/);
void navi_buf_chain_recycle_readed(navi_buf_chain_t* chain);


#endif /* NAVI_BUF_CHAIN_H_ */
