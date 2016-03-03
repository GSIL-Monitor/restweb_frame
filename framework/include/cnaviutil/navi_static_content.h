/** \brief cnavi框架静态内容中间件
 *
 * 静态内容中间件，解决本地静态资源的写、读、删的问题。
 * 要求静态内容有唯一标记。
 * 静态内容，按大小，分为文件系统存储和内存存储。
 * 文件存储适用于M级别内容，内存存储适用于K级别小内容。
 *
 * 文件静态内容中间件之下，封装如下机制：
 * * 文件的异步写机制。异步写动作在navi_bgjob_t下进行。
 * * 资源目录自动管理。资源目录管理有策略，策略输入是资源ID，输出是资源的全路径。
 * * 文件的写，先写临时文件，写入完成后，rename为正式文件。写入完成时，执行该
 * 	资源操作的task会得到异步的通知。
 *
 * * 资源的读方面，中间件维持一个 文件句柄及文件信息的缓存。读取资源时，会获得
 *   资源的fd，该fd可以安全的使用，无需关心文件在其他地方被删除、rename等操作。
 *   该缓存自动管理其缓存项目的清理。得到的fd可以安全的用于数据的传输。比如交给
 *   nginx http响应进行sendfile。
 * * 资源的删除，就是简单的文件删除。因为有只读文件句柄缓存的存在，删除不影响正在被使用的文件
 *
 * 内存级别中间件之下，封装如下机制：
 * * 可以存储于本地redisdb，如果资源是要求不易失的。
 * * 可以存储于本地redis，如果资源是允许自动LRU式清理的。适用于缓存服务。
 * * 资源的读，是通过异步的nvcli_redis_t命令获得。读完成后，执行读的task得到整体的内容。
 * * 资源的写，是通过异步的nvcli_redis_t命令执行。写完成后，执行写的task得到异步的通知。
 * * 资源的删除，通过异步的nvcli_redis_t命令进行。
 *
 * 静态内容中间件，提供简便的接口，就是资源的增加、删除、获取，以及中间件的初始化和销毁接口。
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
	int resp_waiting, int input_max_interval); //!< cnavi0.5.0 仅支持IPv4分组

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
