/*
 * test_buf_chain.c
 *
 *  Created on: 2015Äê5ÔÂ8ÈÕ
 *      Author: L-F000000-PC
 */

#include "navi_buf_chain.h"

int main()
{
	navi_pool_t* pool = navi_pool_create(1024);

	navi_buf_chain_t* chain = navi_buf_chain_init(pool);

	int i;
	char buf[20];
	for(i=0; i<10; i++) {
		sprintf(buf,"%d ", i);
		navi_buf_chain_append(chain, buf, strlen(buf));
	}

	char* part;
	size_t part_sz;
	while ((part_sz=navi_buf_chain_read_part(chain,(uint8_t**)&part))) {
		printf("%.*s\n", part_sz, part);
	}

	navi_buf_chain_recycle_readed(chain);

	int j;
	uint8_t* busy = NULL;
	for ( j=0; j<10000; j++) {
		int k = i+20;
		for (; i<k; i++) {
			sprintf(buf,"%d xxxxxxxx ", i);
			navi_buf_chain_append(chain, buf, strlen(buf));
		}
		printf("after append=======\n");
		navi_buf_chain_print(chain);

		while ((part_sz=navi_buf_chain_read_part(chain,(uint8_t**)&part))) {
			printf("%.*s\n", part_sz, part);
			if (busy == NULL) busy = part;
		}
		printf("after read=======\n");
		navi_buf_chain_print(chain);

		if ( j % 100 ) {
			navi_buf_chain_recycle(chain, busy);
			busy = NULL;
			printf("after recycle=======\n");
			navi_buf_chain_print(chain);
		}
	}

	return 0;
}

