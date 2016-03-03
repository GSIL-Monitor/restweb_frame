/** \brief cnavi��ܾ�̬�����м��
 *
 * ��̬�����м����������ؾ�̬��Դ��д������ɾ�����⡣
 * Ҫ��̬������Ψһ��ǡ�
 * ��̬���ݣ�����С����Ϊ�ļ�ϵͳ�洢���ڴ�洢��
 * �ļ��洢������M�������ݣ��ڴ�洢������K����С���ݡ�
 *
 * �ļ���̬�����м��֮�£���װ���»��ƣ�
 * * �ļ����첽д���ơ��첽д������navi_bgjob_t�½��С�
 * * ��ԴĿ¼�Զ�������ԴĿ¼�����в��ԣ�������������ԴID���������Դ��ȫ·����
 * * �ļ���д����д��ʱ�ļ���д����ɺ�renameΪ��ʽ�ļ���д�����ʱ��ִ�и�
 * 	��Դ������task��õ��첽��֪ͨ��
 *
 * * ��Դ�Ķ����棬�м��ά��һ�� �ļ�������ļ���Ϣ�Ļ��档��ȡ��Դʱ������
 *   ��Դ��fd����fd���԰�ȫ��ʹ�ã���������ļ��������ط���ɾ����rename�Ȳ�����
 *   �û����Զ������仺����Ŀ�������õ���fd���԰�ȫ���������ݵĴ��䡣���罻��
 *   nginx http��Ӧ����sendfile��
 * * ��Դ��ɾ�������Ǽ򵥵��ļ�ɾ������Ϊ��ֻ���ļ��������Ĵ��ڣ�ɾ����Ӱ�����ڱ�ʹ�õ��ļ�
 *
 * �ڴ漶���м��֮�£���װ���»��ƣ�
 * * ���Դ洢�ڱ���redisdb�������Դ��Ҫ����ʧ�ġ�
 * * ���Դ洢�ڱ���redis�������Դ�������Զ�LRUʽ����ġ������ڻ������
 * * ��Դ�Ķ�����ͨ���첽��nvcli_redis_t�����á�����ɺ�ִ�ж���task�õ���������ݡ�
 * * ��Դ��д����ͨ���첽��nvcli_redis_t����ִ�С�д��ɺ�ִ��д��task�õ��첽��֪ͨ��
 * * ��Դ��ɾ����ͨ���첽��nvcli_redis_t������С�
 *
 * ��̬�����м�����ṩ���Ľӿڣ�������Դ�����ӡ�ɾ������ȡ���Լ��м���ĳ�ʼ�������ٽӿڡ�
 *
 * navi_static_content.h
 *  Created on: 2015-1-29
 *      Author: li.lei
 *  brief: 
 */

#ifndef NAVI_STATIC_CONTENT_H_
#define NAVI_STATIC_CONTENT_H_

#include "navi_common_define.h"
#include "navi_task.h"
#include "navi_bg_job.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _navi_scfd_t
{
	char* scid;
	char* path;
	int fd;
	int is_temp:1;
} navi_scfd_t;

typedef void* (*navi_scfile_path_strategy_config_fp)(const json_t* conf);
typedef bool (*navi_scfile_path_resolve_fp)(void* strategy, const char* scid, char* path, size_t sz);
typedef void (*navi_scfile_path_strategy_clean_fp)(void* strategy);

#define NAVI_SCFILE_PATH_STRATEGY_INIT(strategy_name,conf) void* navi_scfile_##strategy_nm##_strategy_init(const json_t* conf)
#define NAVI_SCFILE_PATH_STRATEGY_RESOLVE(strategy_name,stra_obj,scid,path,sz) bool navi_scfile_##strategy_nm##_strategy_resolve(\
	void* stra_obj, const char* scid, char* path, size_t sz)
#define NAVI_SCFILE_PATH_STRATEGY_CLEAN(strategy_name,stra_obj) int navi_scfile_##strategy_nm##_strategy_clean(\
	void* stra_obj)
/**
void* navi_scfile_mgr_init(
	const char* root_path,
	const json_t* config,
	navi_scfile_path_strategy_config_fp path_strategy_create,
	navi_scfile_path_resolve_fp path_strategy_resolve,
	navi_scfile_path_strategy_clean_fp path_strategy_clean);**/

typedef enum _navi_scfile_error_e
{
	NV_SCFILE_EXISTS = 0x1,
	NV_SCFILE_WRITING = 0x2,
	NV_SCFILE_NOT_EXISTS = 0x4,
	NV_SCFILE_DISK_FULL = 0x8,
	NV_SCFILE_IO_PROBLEM = 0x10,
	NV_SCFILE_DIR_PROBLEM = 0x20,
	NV_SCFILE_PERM_PROBLEM = 0x40,
	NV_SCFILE_PROCESS_LIMIT = 0x80,
	NV_SCFILE_NOT_REGULAR = 0x100,
	NV_SCFILE_OTHER_ERROR = 0x200,
	NV_SCFILE_STRATEGY_ERROR = 0x400,
	NV_SCFILE_PATH_TOO_LONG = 0x800
}navi_scfile_error_e;

void* navi_scfile_mgr_get(const char* root_path);

void navi_scfile_mgrs_init(const json_t* config);

//void navi_scfile_mgrs_clean();

navi_scfd_t* navi_request_get_scfile_readfd(navi_request_t* main_req,void* mgr, const char* id, int* err);
navi_scfd_t* navi_task_get_scfile_readfd(navi_task_t* task, void* mgr, const char* id, int* err);

typedef void* (*navi_scfile_rfdcache_init_fp)(void* mgr, int fd_max, int min_uses, int valid_time);
typedef void (*navi_scfile_rfdchace_clean_fp)(void* mgr, void* cache);
typedef int (*navi_scfile_rfdcache_getfd_fp)(void* cache, const char* path, void* driver_pool);
typedef void (*navi_scfile_rfdcache_delfd_fp)(void* cache, const char* path, void* driver_pool);
typedef bool (*navi_scfile_rfdcache_checkdir_fp)(void* cache, const char* path);

void navi_scfile_mgr_rfd_cache_driver(
	navi_scfile_rfdcache_init_fp cache_init,
	navi_scfile_rfdchace_clean_fp cache_clean,
	navi_scfile_rfdcache_getfd_fp get_entry,
	navi_scfile_rfdcache_delfd_fp del_entry,
	navi_scfile_rfdcache_checkdir_fp dir_check);

navi_scfd_t* navi_scfile_openw_temp(void* mgr,int *err);
navi_scfd_t* navi_scfile_openw_resource(void* mgr, const char* id, int* err);

const char* navi_scfile_last_error(int *errno);

int navi_scfile_write_abort(navi_scfd_t* fd);
int navi_scfile_write_comfirm(navi_scfd_t* fd);

void navi_scfd_clean(navi_scfd_t* fd);

int navi_scfile_rename(void* src_mgr, const char* src_id, void* dst_mgr, const char* dst_id);
int navi_scfile_rename_path(const char* src_path, void* dst_mgr, const char* dst_id);

int navi_scfile_get_path(void* mgr, const char* source_id, char *path, size_t path_bufsz);

typedef void (*navi_scfile_bgwrite_end_fp)(navi_task_t* task, navi_bgjob_t* job, navi_scfd_t* fd);
typedef void (*navi_scfile_bgwrite_failed_fp)(navi_task_t* task, navi_bgjob_t* job, navi_scfd_t* fd,
	const char* err);
navi_bgjob_t* navi_scfile_bgwrite_start(void* mgr, navi_scfd_t* wfd,
	navi_task_t* task,
	navi_scfile_bgwrite_end_fp completer,
	navi_scfile_bgwrite_failed_fp error_handler,
	int size_threshold,
	int time_threshold);

void navi_scfile_bgwrite(navi_bgjob_t* job, void* data, size_t sz);
void navi_scfile_bgwrite_fin(navi_bgjob_t* job);
void navi_scfile_bgwrite_abort(navi_bgjob_t* job);

ssize_t navi_scfile_writev(navi_scfd_t* fd, const struct iovec *iov, int iovcnt);

int navi_scfile_remove(void* mgr, const char* id, navi_request_t *main_req);
bool navi_scfile_exists(void* mgr, const char* id, int* err);

void* navi_scmem_mgr_init(const char* groupname,
	int conn_timeout,
	int resp_waiting, int input_max_interval); //!< cnavi0.5.0 ��֧��IPv4����

void navi_scmem_mgr_clean();

nvcli_redis_t* navi_scmem_get(const char* group, const char* scid, navi_task_t* task,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler);

nvcli_redis_t* navi_scmem_set_ifnx(const char* group, const char* scid, navi_task_t* task,
	void* data,
	size_t size,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler);

nvcli_redis_t* navi_scmem_remove(const char* group, const char* scid, navi_task_t* task,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_STATIC_CONTENT_H_ */
