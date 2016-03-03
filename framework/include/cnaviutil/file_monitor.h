/** \brief 
 * file_monitor.h
 *  Created on: 2015-3-17
 *      Author: zoudaobing
 *  brief: 利用inotify 提供文件监控功能，目前只监控创建和写完成。
              同一文件/目录的多次监控以最后一次设置为准
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



//下面是给内部驱动调用的接口

typedef void * (*file_mon_install_fp)(navi_file_mon_t *s);
typedef void (*file_mon_uninstall_fp)(navi_file_mon_t *s);

void file_mon_set(file_mon_install_fp install, file_mon_uninstall_fp uninstall);
void file_event_dispatch(navi_file_mon_t *s, void *buf, int n);


#endif
