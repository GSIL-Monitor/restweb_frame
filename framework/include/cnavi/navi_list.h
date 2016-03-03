/*
 * navi_list.h
 *
 *  Created on: 2014-04-08
 *      Author: yanguotao@youku.com
 */

#ifndef NAVI_LIST_H_
#define NAVI_LIST_H_

#include "navi_common_define.h"

#ifdef __cplusplus
extern "C"
{
#endif


#define navi_list_init(l)       do {                                          \
    (l)->prev = l;                                                            \
    (l)->next = l; \
}while(0)


#define navi_list_empty(h)    (h == (h)->prev)


#define navi_list_insert_head(h, x)        do {                         \
    (x)->next = (h)->next;                                               \
    (x)->prev = (h);	\
    (h)->next->prev = (x);\
    (h)->next = (x);\
}while(0)

#define navi_list_insert_after   navi_list_insert_head

#define navi_list_insert_tail(h, x)     do{                                   \
    (x)->prev = (h)->prev;                                                    \
    (x)->next = (h); \
    (h)->prev->next = (x); \
    (h)->prev = (x);\
}while(0)

#define navi_list_head(h)   (h)->next

#define navi_list_last(h)     (h)->prev

#define navi_list_next(q)    (q)->next

#define navi_list_prev(q)    (q)->prev

#define navi_list_remove(x)    do{                                             \
    (x)->next->prev = (x)->prev;                                           \
    (x)->prev->next = (x)->next;	\
	(x)->prev = (x)->next = (x); \
}while(0)

#define navi_list_remove2(x)    do{                                             \
    (x)->next->prev = (x)->prev;                                           \
    (x)->prev->next = (x)->next;	\
	(x)->prev = (x)->next = NULL; \
}while(0)

#define navi_list_add(h, n)  do{                                                 \
    (h)->prev->next = (n)->next;                                          \
    (n)->next->prev = (h)->prev;                                          \
    (h)->prev = (n)->prev;                                                    \
    (h)->prev->next = (h);\
}while(0)

#define navi_list_data(l, type, link)                                        \
    (type *) ((u_char *) l - offsetof(type, link))

#define navi_list_give(src,dst) do {\
	(dst)->prev->next = (src)->next;\
	(src)->next->prev = (dst)->prev;\
	(dst)->prev = (src)->prev;\
	(dst)->prev->next = (dst);\
	(src)->next = (src)->prev = src;\
}while(0)


#ifdef __cplusplus
}
#endif

#endif /* NAVI_LIST_H_ */

