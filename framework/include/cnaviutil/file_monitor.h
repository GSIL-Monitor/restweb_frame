/** \brief 
 * file_monitor.h
 *  Created on: 2015-3-17
 *      Author: zoudaobing
 *  brief: ����inotify �ṩ�ļ���ع��ܣ�Ŀǰֻ��ش�����д��ɡ�
              ͬһ�ļ�/Ŀ¼�Ķ�μ�������һ������Ϊ׼
 */

#ifndef _FILE_MONITOR_H_
#define _FILE_MONITOR_H_

#include "../cnavi/navi_simple_hash.h"

typedef struct navi_file_mon_s {
	int              notifyfd;
	navi_hash_t     *path_confs;
	navi_hash_t     *wd_confs;
	void            *driver;
} navi_file_mon_t;

typedef int (*file_event_handler_fp)(char *path, char *filename);

typedef struct navi_file_mon_conf_s {
	char 	               *path;
	int 	                wd;
	file_event_handler_fp   create_handler;
	file_event_handler_fp   closew_handler;//close write
} navi_file_mon_conf_t;


int file_mon_init(navi_file_mon_t *s);
int file_add_monitor(navi_file_mon_t *s, navi_file_mon_conf_t *conf);
int file_del_monitor(navi_file_mon_t *s, navi_file_mon_conf_t *conf);
int file_mon_destroy(navi_file_mon_t *s);



//�����Ǹ��ڲ��������õĽӿ�

typedef void * (*file_mon_install_fp)(navi_file_mon_t *s);
typedef void (*file_mon_uninstall_fp)(navi_file_mon_t *s);

void file_mon_set(file_mon_install_fp install, file_mon_uninstall_fp uninstall);
void file_event_dispatch(navi_file_mon_t *s, void *buf, int n);


#endif
