/** \brief 
 * file_monitor.c
 *  Created on: 2015-3-17
 *      Author: zoudaobing
 *  brief: 利用inotify 提供文件监控功能，目前只监控创建和写完成
 */

#include <sys/inotify.h>
#include "file_monitor.h"
#include "../navi_frame_log.h"

static file_mon_install_fp s_install;
static file_mon_uninstall_fp s_uninstall;
char wdstr[32];

void file_mon_set(file_mon_install_fp install, file_mon_uninstall_fp uninstall)
{
	s_install = install;
	s_uninstall = uninstall;
}


int file_mon_init(navi_file_mon_t *s)
{
	s->notifyfd = inotify_init();
	s->path_confs = navi_hash_init_with_heap();
	s->wd_confs = navi_hash_init_with_heap();
	s->driver = s_install(s);
	return 0;
}

void file_event_dispatch(navi_file_mon_t *s, void *buf, int n)
{
	int i;
	
	for (i = 0; i < n; ) {
		struct inotify_event *event = (struct inotify_event *) ((char*)buf+i);
		NAVI_FRAME_LOG(NAVI_LOG_DEBUG, "file mon: event %d on %d happened",event->mask, s->notifyfd);
		
		sprintf(wdstr,"%d",event->wd);
		navi_file_mon_conf_t *conf = navi_hash_get_gr(s->wd_confs,wdstr);
		if (conf == NULL) {
			i += sizeof(struct inotify_event) + event->len;
			continue;
		}
		
		char *filename = strndup(event->name,event->len);
		if (event->mask & IN_CLOSE_WRITE) {
			if (conf->closew_handler)
				conf->closew_handler(conf->path,filename);
		}
		else if (event->mask & IN_CREATE) {
			if (conf->create_handler)
				conf->create_handler(conf->path,filename);
		}
		free(filename);
		
		i += sizeof(struct inotify_event) + event->len;
	}
}

int file_add_monitor(navi_file_mon_t *s, navi_file_mon_conf_t *conf)
{
	if (s->notifyfd == -1)
		return NAVI_FAILED;
	navi_file_mon_conf_t *oldconf = navi_hash_get_gr(s->path_confs,conf->path);
	char wdstr[32] = {0};
	if (oldconf != NULL) {
		sprintf(wdstr,"%d",oldconf->wd);
		navi_hash_del(s->wd_confs,wdstr);
		free(oldconf);
	}
	int wd = inotify_add_watch(s->notifyfd, conf->path, IN_CREATE | IN_CLOSE_WRITE);//目前只关注创建和写完成
	
	conf->wd = wd;
	navi_hash_set_gr(s->path_confs,conf->path,conf);
	sprintf(wdstr,"%d",wd);
	navi_hash_set_gr(s->wd_confs,wdstr,conf);

	if (s->driver == NULL) {
		s->driver = s_install(s);
	}
	return NAVI_OK;
}

int file_del_monitor(navi_file_mon_t *s, navi_file_mon_conf_t *conf)
{
	navi_file_mon_conf_t *oldconf = navi_hash_get_gr(s->path_confs,conf->path);
	if (oldconf == NULL) {
		return NAVI_OK;
	}

	if (inotify_rm_watch(s->notifyfd, conf->wd) == -1) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "file mon: failed to rm watch");
		return NAVI_FAILED;
	}
	
	char wdstr[32] = {0};
	sprintf(wdstr,"%d",conf->wd);
	navi_hash_del(s->path_confs,conf->path);
	navi_hash_del(s->wd_confs,wdstr);

	return NAVI_OK;
}

int file_mon_destroy(navi_file_mon_t *s)
{
	s_uninstall(s);
	if (s->notifyfd != -1) {
		close(s->notifyfd);
	}
	navi_hash_destroy(s->path_confs);
	navi_hash_destroy(s->wd_confs);
	s->driver == NULL;
	return NAVI_OK;
}

