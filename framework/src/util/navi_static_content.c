/** \brief 
 * navi_static_content.c
 *  Created on: 2015-1-29
 *      Author: li.lei
 *  brief: 
 */

#include "navi_static_content.h"
#include "navi_uppolicy_query.h"
#include "navi_upgroup_mgr.h"
#include "navi_inner_util.h"
#include "../navi_frame_log.h"
#include "../navi_request_impl.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

static navi_scfile_rfdcache_init_fp s_rfdcache_init = NULL;
static navi_scfile_rfdchace_clean_fp s_rfdcache_clean = NULL;
static navi_scfile_rfdcache_getfd_fp s_rfdcache_getfd = NULL;
static navi_scfile_rfdcache_delfd_fp s_rfdcache_delfd = NULL;
static navi_scfile_rfdcache_checkdir_fp s_rfdcache_checkdir = NULL;

void navi_scfile_mgr_rfd_cache_driver(
	navi_scfile_rfdcache_init_fp cache_init,
	navi_scfile_rfdchace_clean_fp cache_clean,
	navi_scfile_rfdcache_getfd_fp get_entry,
	navi_scfile_rfdcache_delfd_fp del_entry,
	navi_scfile_rfdcache_checkdir_fp dir_check)
{
	s_rfdcache_init = cache_init;
	s_rfdcache_clean = cache_clean;
	s_rfdcache_getfd = get_entry;
	s_rfdcache_delfd = del_entry;
	s_rfdcache_checkdir = dir_check;
}

static navi_hash_t* s_scfile_mgrs = NULL;

typedef struct _navi_scfile_path_strategy_t
{
	void* strategy;
	navi_scfile_path_strategy_config_fp configer;
	navi_scfile_path_resolve_fp resolver;
	navi_scfile_path_strategy_clean_fp cleaner;
} navi_scfile_path_strategy_t;

typedef struct _scfile_mgr_t
{
	navi_scfile_path_strategy_t path_strategy;
	void* cache;
	char path[1024];
	uint32_t rand_seed;
} scfile_mgr_t;

typedef struct _scfile_simple_strategy_t
{
	int top_level_max;
	int top_level_width;
	int middle_level_max;
	int middle_level_width;
	int leaf_level_max;
	int leaf_level_width;
}scfile_simple_strategy_t;

static void* default_scfile_path_strategy_create(const json_t* conf)
{
	scfile_simple_strategy_t* ret = (scfile_simple_strategy_t*)
		calloc(1,sizeof(scfile_simple_strategy_t));
	const json_t* top_cfg = json_object_get(conf, "top_level_max");
	const json_t* mid_cfg = json_object_get(conf, "middle_level_max");
	const json_t* leaf_cfg = json_object_get(conf, "leaf_level_max");

	if ( !top_cfg || !json_is_integer(top_cfg) ) {
		ret->top_level_width = 2;
		ret->top_level_max = 100;
		ret->leaf_level_width = 2;
		ret->leaf_level_max = 100;
	}
	else {
		int level_max = 0;
		int level_width = 0;
		level_max = json_integer_value(top_cfg);

		if ( level_max > 1000) {
			level_max = 1000;
			level_width = 3;
		}
		else if (level_max <= 10 ) {
			level_max = 10;
			level_width = 1;
		}
		else {
			if ( level_max > 100)
				level_width = 3;
			else
				level_width = 2;
		}

		ret->top_level_max = level_max;
		ret->top_level_width = level_width;

		if ( mid_cfg && json_is_integer(mid_cfg) ) {
			level_max = json_integer_value(mid_cfg);
		}
		else {
			goto leaf;
		}

		if ( level_max > 1000) {
			level_max = 1000;
			level_width = 3;
		}
		else if (level_max <= 10 ) {
			level_max = 10;
			level_width = 1;
		}
		else {
			if ( level_max > 100)
				level_width = 3;
			else
				level_width = 2;
		}

		ret->middle_level_max = level_max;
		ret->middle_level_width = level_width;

leaf:
		if (leaf_cfg && json_is_integer(leaf_cfg)) {
			level_max = json_integer_value(leaf_cfg);
		}
		else {
			if ( ret->middle_level_max == 0 )
				level_max = 10000 / ret->top_level_max;
			else {
				if ( ret->top_level_max * ret->middle_level_max > 50000) {
					ret->leaf_level_max = ret->middle_level_max;
					ret->leaf_level_width = ret->middle_level_width;
					ret->middle_level_max = 0;
					ret->middle_level_width = 0;
					goto done;
				}
				else {
					level_max = 50000 / (ret->top_level_max * ret->middle_level_max);
				}
			}
		}

		if ( level_max > 1000) {
			level_max = 1000;
			level_width = 3;
		}
		else if (level_max <= 10 ) {
			level_max = 10;
			level_width = 1;
		}
		else {
			if ( level_max > 100) {
				level_width = 3;
			}
			else {
				level_width = 2;
			}
		}
		ret->leaf_level_max = level_max;
		ret->leaf_level_width = level_width;
	}
done:
	return ret;
}

static uint64_t hash_str(const void *ptr)
{
    const char *str = (const char *)ptr;

    uint64_t hash = 5381;
    uint64_t c;

    while((c = (uint64_t)*str))
    {
        hash = ((hash << 5) + hash) + c;
        str++;
    }

    return hash;
}

static bool default_scfile_path_get(void* strategy, const char* scid, char* path, size_t sz)
{
	scfile_simple_strategy_t* strat = (scfile_simple_strategy_t*)strategy;
	char buf[30];
	char dir_buf[30];
	char* p = dir_buf;
	snprintf(buf, sizeof(buf), "%020llu", hash_str(scid)); //?

	int pos = 20 - strat->top_level_width;

	char tmp_token[4] = {0};
	strncat(tmp_token, buf + pos, strat->top_level_width);
	p += sprintf( p, "%0*d/", strat->top_level_width, atoi(tmp_token) % strat->top_level_max);

	if ( strat->middle_level_max == 0)
		goto leaf;

	pos -= strat->middle_level_width;
	memcpy(tmp_token, buf + pos, strat->middle_level_width);
	tmp_token[strat->middle_level_width] = 0;
	p += sprintf( p, "%0*d/", strat->middle_level_max ,atoi(tmp_token) % strat->middle_level_max);

leaf:
	pos -= strat->leaf_level_width;
	memcpy(tmp_token, buf + pos, strat->leaf_level_width);
	tmp_token[strat->leaf_level_width] = 0;
	sprintf(p, "%0*d/", strat->leaf_level_width, atoi(tmp_token) % strat->leaf_level_max);

	snprintf( path, sz, "%s%s",dir_buf, scid);
	return true;
}

static void default_scfile_path_strategy_clean(void* strategy)
{
	scfile_simple_strategy_t* obj = (scfile_simple_strategy_t*)strategy;
	free(obj);
}

#define SCFILE_CONF_READ_FD_MAX "open_file_cache_max"
#define SCFILE_CONF_READ_FD_MINUSE "open_file_cache_min_uses"
#define SCFILE_CONF_READ_FD_VALID "open_file_cache_valid"

static void navi_scfile_mgr_destroy(void* mgr)
{
	scfile_mgr_t* obj = (scfile_mgr_t*)mgr;
	obj->path_strategy.cleaner(obj->path_strategy.strategy);
	s_rfdcache_clean(obj, obj->cache);
	free(obj);
}

static void* navi_scfile_mgr_init(
	const char* root_path,
	const json_t* config,
	navi_scfile_path_strategy_config_fp path_strategy_create,
	navi_scfile_path_resolve_fp path_strategy_resolve,
	navi_scfile_path_strategy_clean_fp path_strategy_clean)
{
	scfile_mgr_t tmp_mgr;
	memset(&tmp_mgr, 0x00, sizeof(scfile_mgr_t));

	if ( root_path[0] != '/' )
		return NULL;

	navi_rpath_2abs(root_path, tmp_mgr.path, sizeof(tmp_mgr.path));
	if ( !navi_check_dir_path(tmp_mgr.path, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH, R_OK|W_OK|X_OK)) {
		NAVI_FRAME_LOG(NAVI_LOG_WARNING, "scfile_mgrs.%s dir permission problem or entry not dir",tmp_mgr.path);
		return NULL;
	}
	/****
	if ( access(tmp_mgr.path, R_OK|W_OK|X_OK) == -1) {
		//todo: log
		return NULL;
	}

	struct stat stbuf;
	if ( -1 == stat(tmp_mgr.path,&stbuf) || !S_ISDIR(stbuf.st_mode)) {
		//todo: log
		return NULL;
	}****/

	scfile_mgr_t* mgr = NULL;
	if (s_scfile_mgrs) {
		mgr = (void*)navi_hash_get_gr(s_scfile_mgrs, tmp_mgr.path);
	}

	if ( path_strategy_create == NULL) {
		path_strategy_create = default_scfile_path_strategy_create;
		path_strategy_clean = default_scfile_path_strategy_clean;
		path_strategy_resolve = default_scfile_path_get;
	}

	tmp_mgr.path_strategy.strategy = path_strategy_create(config);
	tmp_mgr.path_strategy.configer = path_strategy_create;
	tmp_mgr.path_strategy.resolver = path_strategy_resolve;
	tmp_mgr.path_strategy.cleaner = path_strategy_clean;

	if (tmp_mgr.path_strategy.strategy == NULL)
		return mgr;

	if ( mgr == NULL ) {
		mgr = (scfile_mgr_t*)malloc(sizeof(scfile_mgr_t));
		memcpy(mgr, &tmp_mgr, sizeof(scfile_mgr_t));

		const json_t* jse = json_object_get(config, SCFILE_CONF_READ_FD_MAX);
		int cache_max = 512;
		if ( jse && json_is_integer(jse) ) {
			cache_max = json_integer_value(jse);
			if ( cache_max < 32)
				cache_max = 32;
			if ( cache_max > 10240)
				cache_max = 10240;
		}

		jse = json_object_get(config, SCFILE_CONF_READ_FD_MINUSE);
		int min_uses = 1;
		if ( jse && json_is_integer(jse) ) {
			min_uses = json_integer_value(jse);
			if (min_uses > 1024)
				min_uses = 1024;
			if (min_uses < 0)
				min_uses = 0;
		}

		jse = json_object_get(config, SCFILE_CONF_READ_FD_VALID);
		int cache_entry_valid = 60;
		if ( jse && json_is_integer(jse)) {
			cache_entry_valid = json_integer_value(jse);
			if (cache_entry_valid < 5)
				cache_entry_valid = 5;
			if (cache_entry_valid > 3600)
				cache_entry_valid = 3600;
		}

		mgr->cache = s_rfdcache_init(mgr, cache_max, min_uses, cache_entry_valid);
		if (!s_scfile_mgrs) {
			s_scfile_mgrs = navi_hash_init_with_heap();
		}
		navi_hash_set_gr2(s_scfile_mgrs, mgr->path, mgr,navi_scfile_mgr_destroy);
		mgr->rand_seed = time(NULL);
	}
	else {
		if ( mgr->path_strategy.strategy ) {
			mgr->path_strategy.cleaner(mgr->path_strategy.strategy);
		}
		memcpy(&mgr->path_strategy, &tmp_mgr.path_strategy,sizeof(navi_scfile_path_strategy_t));
	}

	return mgr;
}

void* navi_scfile_mgr_get(const char* root_path)
{
	if (s_scfile_mgrs) {
		return (void*)navi_hash_get_gr(s_scfile_mgrs, root_path);
	}
	return NULL;
}

static navi_hash_t* s_rsrc_writing = NULL;

static void navi_scfile_mgrs_clean()
{
	if (!s_scfile_mgrs)return;
	navi_hash_destroy(s_scfile_mgrs);
	s_scfile_mgrs = NULL;
	if ( s_rsrc_writing ) {
		void* it = navi_hash_iter(s_rsrc_writing);
		navi_hent_t* hent;
		while ((hent = navi_hash_iter_next(it))) {
			unlink(hent->k);
		}
		navi_hash_iter_destroy(it);
		navi_hash_destroy(s_rsrc_writing);
		s_rsrc_writing = NULL;
	}
}

navi_scfd_t* navi_request_get_scfile_readfd(navi_request_t* main_req,void* mgr,
	const char* id, int* err)
{
	void* driver_pool = navi_request_get_driver_pool(main_req);
	scfile_mgr_t* _mgr = (scfile_mgr_t*)mgr;
	char path[1024];
	off_t off = snprintf(path, sizeof(path), "%s/", _mgr->path);
	_mgr->path_strategy.resolver(_mgr->path_strategy.strategy, id, path + off,sizeof(path) - off);
	int fd = s_rfdcache_getfd(_mgr->cache,path,driver_pool);
	if ( fd == -1 ) {
		if ( err )
			*err = NV_SCFILE_NOT_EXISTS;
		return NULL;
	}
	navi_scfd_t* ret = (navi_scfd_t*)calloc(1,sizeof(navi_scfd_t));
	ret->fd = fd;
	ret->path = strdup(path);
	ret->scid = strdup(id);
	return ret;
}

//从rfdcache缓存中检查目录的存在性, 找到路径上已经存在的目录在全路径中的位置
static bool check_dir_path(void* cache, const char* path, mode_t mod)
{
	char check_tmp[1024];
	char* e = check_tmp + snprintf(check_tmp,sizeof(check_tmp),"%s", path);
	char* p = check_tmp+1;
	char b;
	int invalid_pos = 1;

	for (; p < e ; ) {

		if ( *p != '/') {
			p++;
			if ( p != e)
				continue;
		}
		b = *p;
		*p = 0;
		bool exists = s_rfdcache_checkdir(cache, check_tmp);
		if ( exists ) {
			*(p++) = b;
			invalid_pos = p - check_tmp;
			continue;
		}
		else {
			*p = b;
			if (0 == navi_create_dir(check_tmp, invalid_pos, mod) )
				return true ;
			else {
				return false;
			}
		}
	}

	return true;
}

navi_scfd_t* navi_task_get_scfile_readfd(navi_task_t* task, void* mgr, const char* id, int* err)
{
	void* driver_pool = nvtask_get_driver_pool(task);
	scfile_mgr_t* _mgr = (scfile_mgr_t*)mgr;
	char path[1024];
	off_t off = snprintf(path, sizeof(path), "%s/", _mgr->path);
	_mgr->path_strategy.resolver(_mgr->path_strategy.strategy, id, path + off,sizeof(path) - off);
	int fd = s_rfdcache_getfd(_mgr->cache,path,driver_pool);
	if ( fd == -1 ) {
		if ( err )
			*err = NV_SCFILE_NOT_EXISTS;
		return NULL;
	}
	navi_scfd_t* ret = (navi_scfd_t*)calloc(1,sizeof(navi_scfd_t));
	ret->fd = fd;
	ret->path = strdup(path);
	ret->scid = strdup(id);
	return ret;
}

navi_scfd_t* navi_scfile_openw_temp(void* mgr, int* err)
{
	scfile_mgr_t* _mgr = (scfile_mgr_t*)mgr;
	int _err;
	while(1) {
		uint32_t temp_v = rand_r(&_mgr->rand_seed);
		time_t epoch = time(NULL);
		char path[1024];
		off_t off = snprintf(path, sizeof(path), "%s/", _mgr->path);
		char id[50];
		snprintf(id, sizeof(id), "%llu_%u", epoch, temp_v);
		if ( ! _mgr->path_strategy.resolver(_mgr->path_strategy.strategy, id, path + off,sizeof(path) - off) ) {
			_err = NV_SCFILE_STRATEGY_ERROR;
			goto failed;
		}
		struct stat st;
		if ( 0==stat(path,&st) ) {
			continue;
		}
		else {
			int fd = -1;
			int check_pos = 0;
			bool dir_exists = false;
recreate:
			fd =  open(path, O_CREAT|O_EXCL|O_WRONLY, S_IRWXU|S_IRWXG);
			if ( fd < 0 ) {
				if ( errno == EACCES ) {
					_err = NV_SCFILE_PERM_PROBLEM;
					goto failed;
				}
				else if ( errno == EEXIST ) {
					continue;
				}
				else if ( errno == ENOENT ) {
					goto dir_try;
				}
				else if ( errno == EMFILE ) {
					_err = NV_SCFILE_PROCESS_LIMIT;
					goto failed;
				}
				else if ( errno == ENOSPC ) {
					_err = NV_SCFILE_DISK_FULL;
					goto failed;
				}
				else if ( errno == EPERM ) {
					_err = NV_SCFILE_PERM_PROBLEM;
					goto failed;
				}
				else {
					_err = NV_SCFILE_OTHER_ERROR;
					goto failed;
				}

				if ( dir_exists ) {
					_err = NV_SCFILE_OTHER_ERROR;
					goto failed;
				}
				dir_try:{
					char* last_dir = rindex(path,'/');
					*last_dir = 0;
					dir_exists = check_dir_path(_mgr->cache, path, S_IRWXU|S_IRWXG);
					*last_dir = '/';
				}
				if ( !dir_exists ) {
					if ( errno == EACCES ) {
						_err = NV_SCFILE_PERM_PROBLEM;
						goto failed;
					}
					else if ( errno == ENOSPC ) {
						_err = NV_SCFILE_DISK_FULL;
						goto failed;
					}
					else if ( errno == EPERM ) {
						_err = NV_SCFILE_PERM_PROBLEM;
						goto failed;
					}
					else {
						_err = NV_SCFILE_OTHER_ERROR;
						goto failed;
					}
				}
				else {
					goto recreate;
				}
			}
			else {
				navi_scfd_t* ret = (navi_scfd_t*)calloc(1,sizeof(navi_scfd_t));
				ret->fd = fd;
				ret->is_temp = 1;
				ret->scid = strdup(id);
				ret->path = strdup(path);
				return ret;
			}

			break;
		}
	}
failed:
	if ( err )
		*err = _err;
	return NULL;
}

static int try_lock_wtemp(int fd, const char* path)
{
	if ( s_rsrc_writing) {
		if (navi_hash_get_gr(s_rsrc_writing, path))
			return 1;
	}
	struct flock lk;
	lk.l_type = F_WRLCK;
	lk.l_start = 0;
	lk.l_whence = SEEK_SET;
	lk.l_len = 0;
	lk.l_pid = 0;

	if ( 0 > fcntl(fd, F_GETLK,&lk) ) {
		NAVI_SYSERR_LOG("fcntl F_GETLK failed");
		return -1;
	}

	if ( lk.l_type == F_UNLCK ) {
		lk.l_type = F_WRLCK;
		int ret = fcntl(fd, F_SETLK, &lk);
		if (ret == 0) {
			ftruncate(fd, 0);
			navi_hash_set_gr(s_rsrc_writing, path, (void*)1);
			return 0;
		}
		else if (ret == EAGAIN || errno == EAGAIN ) {
			return 1;
		}
	}
	else {
		return 1;
	}

	return -1;
}

static void unlock_wtemp(int fd, const char* path)
{
	if ( s_rsrc_writing )
		navi_hash_del(s_rsrc_writing, path);

	struct flock lk;
	lk.l_type = F_WRLCK;
	lk.l_start = 0;
	lk.l_whence = SEEK_SET;
	lk.l_len = 0;
	lk.l_pid = 0;
	fcntl(fd, F_SETLK, &lk);
}

navi_scfd_t* navi_scfile_openw_resource(void* mgr, const char* id, int* err)
{
	scfile_mgr_t* _mgr = (scfile_mgr_t*)mgr;
	char path[1024];
	int _err;
	off_t off = snprintf(path, sizeof(path), "%s/", _mgr->path);
	if ( off >= sizeof(path) ) {
		_err = NV_SCFILE_PATH_TOO_LONG;
		goto failed;
	}
	if ( !_mgr->path_strategy.resolver(_mgr->path_strategy.strategy, id,
		path + off,sizeof(path) - off) ) {
		_err =NV_SCFILE_STRATEGY_ERROR;
		goto failed;
	}

	char *p = path + off;
	while ( *p++ );
	p--;
	struct stat stbuf;

	if ( 0==stat(path,&stbuf)) {
		if (S_ISREG(stbuf.st_mode)) {
			_err = NV_SCFILE_EXISTS;
			goto failed;
		}
		else {
			_err = NV_SCFILE_NOT_REGULAR;
			goto failed;
		}
	}

	if ( p - path >= 1024 - strlen(".wtmp") ) {
		_err =NV_SCFILE_PATH_TOO_LONG;
		goto failed;
	}

	sprintf(p, ".wtmp");

	int fd = -1;
	int check_pos = 0;
	bool dir_exists = false;
	int lk_status = 0;
recreate:
	fd =  open(path, O_CREAT|O_WRONLY, S_IRWXU|S_IRWXG);
	if ( fd < 0 ) {
		if ( errno == EACCES ) {
			if(err) *err = NV_SCFILE_PERM_PROBLEM;
			return NULL;
		}
		else if ( errno == EEXIST ) {
			if ( 0 == stat(path,&stbuf) ) {
				if ( S_ISREG(stbuf.st_mode) ) {
					_err = NV_SCFILE_WRITING;
					goto failed;
				}
				else {
					_err = NV_SCFILE_NOT_REGULAR;
					goto failed;
				}
			}
			else {
				goto recreate;
			}
		}
		else if ( errno == ENOENT ) {
			goto dir_try;
		}
		else if ( errno == EMFILE ) {
			if(err)*err = NV_SCFILE_PROCESS_LIMIT;
			return NULL;
		}
		else if ( errno == ENOSPC ) {
			if(err)*err = NV_SCFILE_DISK_FULL;
			return NULL;
		}
		else if ( errno == EPERM ) {
			if(err)*err = NV_SCFILE_PERM_PROBLEM;
			return NULL;
		}
		else {
			if(err)*err = NV_SCFILE_OTHER_ERROR;
			return NULL;
		}

		if ( dir_exists ) {
			if(err)*err = NV_SCFILE_OTHER_ERROR;
			return NULL;
		}
		dir_try:{
			char* last_dir = rindex(path,'/');
			*last_dir = 0;
			dir_exists = check_dir_path(_mgr->cache, path, S_IRWXU|S_IRWXG);
			*last_dir = '/';
		}
		if ( !dir_exists ) {
			if ( errno == EACCES ) {
				if(err)*err = NV_SCFILE_PERM_PROBLEM;
				return NULL;
			}
			else if ( errno == ENOSPC ) {
				if(err)*err = NV_SCFILE_DISK_FULL;
				return NULL;
			}
			else if ( errno == EPERM ) {
				if(err)*err = NV_SCFILE_PERM_PROBLEM;
				return NULL;
			}
			else {
				if(err)*err = NV_SCFILE_OTHER_ERROR;
				return NULL;
			}
		}
		else {
			goto recreate;
		}
	}
    else {
        lk_status = try_lock_wtemp(fd, path);
        if ( lk_status == 1) {
            _err = NV_SCFILE_WRITING;
            close(fd);
            goto failed;
        }
        else if (lk_status == -1) {
            _err = NV_SCFILE_OTHER_ERROR;
            close(fd);
            goto failed;
        }

        navi_scfd_t* ret = (navi_scfd_t*)calloc(1,sizeof(navi_scfd_t));
        ret->fd = fd;
        ret->is_temp = 0;
        ret->scid = strdup(id);
        //*p = 0;
        ret->path = strdup(path);
        return ret;
    }

failed:
	if ( err )
		*err = _err;
	return NULL;
}

void navi_scfd_clean(navi_scfd_t* fd)
{
	if (!fd)return;
	if (fd->fd != -1) {
		close(fd->fd);
		fd->fd = -1;
	}
	free(fd->path);
	free(fd->scid);
	free(fd);
}

int navi_scfile_write_abort(navi_scfd_t* fd)
{
	if (!fd)
		return 0;
	int _err = 0;

	if ( fd->fd != -1) {
		if ( -1 == unlink(fd->path) ) {
			if ( errno == EACCES || errno == EPERM)
				_err = NV_SCFILE_PERM_PROBLEM;
			else if (errno == ENOENT  || errno == ENOTDIR)
				_err = NV_SCFILE_DIR_PROBLEM;
			else
				_err = NV_SCFILE_OTHER_ERROR;

			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "unlink failed for:%s %d %s",
				fd->path, errno, strerror(errno));
			return _err;
		}
		close(fd->fd);
		fd->fd = -1;
	}
	if ( fd->is_temp == 0) {
		navi_hash_del(s_rsrc_writing, fd->path);
	}

	return 0;
}

int navi_scfile_write_comfirm(navi_scfd_t* fd)
{
	if (!fd)
		return 0;
	if ( fd->is_temp ) {
		close(fd->fd);
		fd->fd = -1;
		return 0;
	}

	if ( fd->fd != -1) {
		char tmp_path[1024];
		int _err = 0;
		int len = strlen(fd->path) - 5;
		memcpy(tmp_path,fd->path, len);
		tmp_path[len] = 0;
		if ( 0 != rename(fd->path, tmp_path)) {
			if ( errno == EACCES || errno == EPERM)
				_err = NV_SCFILE_PERM_PROBLEM;
			else if (errno == ENOENT  || errno == ENOTDIR)
				_err = NV_SCFILE_DIR_PROBLEM;
			else
				_err = NV_SCFILE_OTHER_ERROR;
			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "confirm static content failed for:%s %d %s",
				fd->path, errno, strerror(errno));
			return _err;
		}
		unlock_wtemp(fd->fd, fd->path);
	}
	return 0;
}

int navi_scfile_rename_path(const char* src_path, void* dst_mgr, const char* dst_id)
{
	char id_path[1024];
	bool iddir_try = false;
	scfile_mgr_t* _mgr = (scfile_mgr_t*)dst_mgr;
	off_t off = strlen(_mgr->path);
	memcpy(id_path, _mgr->path, off+1);
	id_path[off++] = '/';
	int _err = 0;

	_mgr = (scfile_mgr_t*)dst_mgr;
	if ( !_mgr->path_strategy.resolver(_mgr->path_strategy.strategy, dst_id,
		id_path + off,sizeof(id_path) - off) ) {
		return NV_SCFILE_STRATEGY_ERROR;
	}

	struct stat stbuf;
	if ( 0==stat(src_path,&stbuf)) {
		if ( !S_ISREG(stbuf.st_mode) ) {
			return NV_SCFILE_NOT_REGULAR;
		}
	}
	else {
		return NV_SCFILE_NOT_EXISTS;
	}

	if ( 0==stat(id_path,&stbuf)) {
		if (S_ISREG(stbuf.st_mode)) {
			return NV_SCFILE_EXISTS;
		}
		else {
			return NV_SCFILE_NOT_REGULAR;
		}
	}

redo:
	if ( 0 != rename(src_path, id_path) ) {
		if (errno == EACCES || errno == EPERM) {
			return NV_SCFILE_PERM_PROBLEM;
		}
		else if (errno == ENOENT ) {
			if (!iddir_try) {
				char* last_dir = rindex(id_path,'/');
				*last_dir = 0;
				bool dir_try = check_dir_path(_mgr->cache, id_path, S_IRWXU|S_IRWXG);
				*last_dir = '/';
				iddir_try = true;
				if ( dir_try) {
					goto redo;
				}
			}
			return NV_SCFILE_NOT_EXISTS;
		}
		else if (errno == ENOSPC) {
			return NV_SCFILE_DISK_FULL;
		}
		else {
			return NV_SCFILE_OTHER_ERROR;
		}
	}

	return 0;
}

int navi_scfile_rename(void* src_mgr, const char* src_id, void* dst_mgr, const char* dst_id)
{
	char tmp_path[1024];
	char id_path[1024];
	bool iddir_try = false;
	scfile_mgr_t* _mgr = (scfile_mgr_t*)src_mgr;
	off_t off = strlen(_mgr->path);
	memcpy(tmp_path, _mgr->path, off+1);
	memcpy(id_path, _mgr->path, off+1);
	int _err = 0;

	if ( !_mgr->path_strategy.resolver(_mgr->path_strategy.strategy,src_id,
		tmp_path + off,sizeof(tmp_path) - off) ) {
		return NV_SCFILE_STRATEGY_ERROR;
	}

	_mgr = (scfile_mgr_t*)dst_mgr;
	if ( !_mgr->path_strategy.resolver(_mgr->path_strategy.strategy, dst_id,
		id_path + off,sizeof(id_path) - off) ) {
		return NV_SCFILE_STRATEGY_ERROR;
	}

	struct stat stbuf;
	if ( 0==stat(tmp_path,&stbuf)) {
		if ( !S_ISREG(stbuf.st_mode) ) {
			return NV_SCFILE_NOT_REGULAR;
		}
	}
	else {
		return NV_SCFILE_NOT_EXISTS;
	}

	if ( 0==stat(id_path,&stbuf)) {
		if (S_ISREG(stbuf.st_mode)) {
			return NV_SCFILE_EXISTS;
		}
		else {
			return NV_SCFILE_NOT_REGULAR;
		}
	}

redo:
	if ( 0 != rename(tmp_path, id_path) ) {
		if (errno == EACCES || errno == EPERM) {
			return NV_SCFILE_PERM_PROBLEM;
		}
		else if (errno == ENOENT ) {
			if (!iddir_try) {
				char* last_dir = rindex(id_path,'/');
				*last_dir = 0;
				bool dir_try = check_dir_path(_mgr->cache, id_path, S_IRWXU|S_IRWXG);
				*last_dir = '/';
				iddir_try = true;
				if ( dir_try) {
					goto redo;
				}
			}
			return NV_SCFILE_NOT_EXISTS;
		}
		else if (errno == ENOSPC) {
			return NV_SCFILE_DISK_FULL;
		}
		else {
			return NV_SCFILE_OTHER_ERROR;
		}
	}

	return 0;
}

int navi_scfile_get_path(void* mgr, const char* id, char *arg_path, size_t path_bufsz)
{
	scfile_mgr_t* _mgr = (scfile_mgr_t*)mgr;
	char path[1024];
	int _err;
	off_t off = snprintf(path, sizeof(path), "%s/", _mgr->path);
	if ( off >= sizeof(path) ) {
		_err = NV_SCFILE_PATH_TOO_LONG;
		return -1;
	}
	if ( !_mgr->path_strategy.resolver(_mgr->path_strategy.strategy, id,
		path + off,sizeof(path) - off) ) {
		_err =NV_SCFILE_STRATEGY_ERROR;
		return -1;
	}

	size_t len = strlen(path);
	if ( len + 1 <= path_bufsz ) {
		memcpy(arg_path, path, len+1);
	}
	else {
		memcpy(arg_path, path, path_bufsz-1);
		arg_path[path_bufsz - 1] = '\0';
	}
	return 0;
}

#define BGWRITE_MAGIC 0x8761acdf

typedef struct _bgwrite_ctx_t
{
	uint32_t _magic;
	navi_scfd_t* scfd;
	navi_timer_h timer;
	navi_scfile_bgwrite_end_fp completer;
	navi_scfile_bgwrite_failed_fp error_handler;

	int size_threshold;

	//job线程可以访问，以及销毁的部分。
	pthread_rwlock_t wlock;
	int fd; //duped
	navi_buf_chain_t* write_chain;
	navi_pool_t* write_pool;
	navi_buf_chain_t* buf_chain;
	navi_pool_t* buf_pool;
} bgwrite_ctx_t;

static void bgwrite_ctx_cleanup(bgwrite_ctx_t* bgctx)
{
	if ( bgctx->write_chain) {
		navi_pool_destroy(bgctx->write_pool);
		bgctx->write_chain = NULL;
	}
	if (bgctx->buf_chain ) {
		navi_pool_destroy(bgctx->buf_pool);
		bgctx->buf_chain = NULL;
	}
	pthread_rwlock_destroy(&bgctx->wlock);
	if (bgctx->fd != -1) {
		close(bgctx->fd);
		bgctx->fd = -1;
	}
	free(bgctx);
}

static void bgwrite_jobcleanup(navi_bgjob_t* job,void* job_data)
{
	bgwrite_ctx_cleanup((bgwrite_ctx_t*)job_data);
}

static void bgwrite_stream_handler(navi_bgjob_t* job, void* data, size_t dummy)
{
	bgwrite_ctx_t* ctx = (bgwrite_ctx_t*)data;
	pthread_rwlock_wrlock(&ctx->wlock);
	navi_pool_t* tmpp = ctx->buf_pool;
	ctx->buf_pool = ctx->write_pool;
	ctx->write_pool = tmpp;

	navi_buf_chain_t* tmpc = ctx->buf_chain;
	ctx->buf_chain = ctx->write_chain;
	ctx->write_chain = tmpc;
	pthread_rwlock_unlock(&ctx->wlock);

	struct iovec vecs[128];
	int i = 0;
	size_t part_sz;
	bool failed= false;
	int _tmp_err;
	while(1) {
		for ( i=0; i<128; ) {
			part_sz = navi_buf_chain_read_part(ctx->write_chain, (uint8_t**)&(vecs[i].iov_base));
			if ( part_sz > 0) {
				i++;
			}
			else
				break;
		}

		if ( i == 128 ) {
			if ( -1 == writev(ctx->fd, vecs, i) ) {
				failed = true;
				_tmp_err = errno;
			}
		}
		else {
			if ( i==0 )
				break;

			if ( -1 == writev(ctx->fd, vecs, i) ) {
				failed = true;
				_tmp_err = errno;
			}
		}
	}

	navi_buf_chain_recycle_readed(ctx->write_chain);
	if (failed ) {
		navi_bgjob_failed(job, "writev syserr:%d %s", _tmp_err, strerror(_tmp_err));
	}
}

static void bgwrite_timer(navi_task_t* task, void* timer_data)
{
	navi_bgjob_t* job = (navi_bgjob_t*)timer_data;
	bgwrite_ctx_t* ctx = (bgwrite_ctx_t*)job->job_start_data;
	pthread_rwlock_rdlock(&ctx->wlock);
	if ( navi_buf_chain_get_content(ctx->buf_chain, NULL, 0) > 0 ) {
		navi_streamed_bgjob_push(job, (void*)1, 1, NULL);
	}
	pthread_rwlock_unlock(&ctx->wlock);
}

static void bgwrite_completer(navi_task_t* task, navi_bgjob_t* job,void* job_data)
{
	bgwrite_ctx_t* ctx = (bgwrite_ctx_t*)job_data;
	navi_scfile_write_comfirm(ctx->scfd);
	ctx->completer(task,job, ctx->scfd);
}

static void bgwrite_error_handler(navi_task_t* task, navi_bgjob_t* job, void* job_data, const char* err)
{
	bgwrite_ctx_t* ctx = (bgwrite_ctx_t*)job_data;
	navi_scfile_write_abort(ctx->scfd);
	ctx->error_handler(task, job, ctx->scfd, err);
}

navi_bgjob_t* navi_scfile_bgwrite_start(void* mgr, navi_scfd_t* wfd,
	navi_task_t* task,
	navi_scfile_bgwrite_end_fp completer,
	navi_scfile_bgwrite_failed_fp error_handler,
	int size_threshold,
	int time_threshold)
{
	if (!wfd || wfd->fd==-1 || wfd->is_temp) {
		return NULL;
	}

	int off =0;
	bgwrite_ctx_t* bgctx = (bgwrite_ctx_t*)calloc(1,sizeof(bgwrite_ctx_t));
	char job_name[1500];
	char* p = job_name;
	bgctx->fd = dup(wfd->fd);
	if (bgctx->fd == -1) {
		NAVI_SYSERR_LOG("dup fd failed for bgwrite");
		goto failed;
	}

	bgctx->completer = completer;
	bgctx->error_handler = error_handler;
	if (size_threshold <= 0) {
		size_threshold = 4096;
	}
	else if (size_threshold >= 4096*1024) {
		size_threshold = 4096*1024;
	}
	bgctx->size_threshold = size_threshold;

	if ( time_threshold > 1000 )
		time_threshold = 1000;
	if ( time_threshold <= 0)
		time_threshold = 4;

	bgctx->write_pool = navi_pool_create(4096);
	bgctx->buf_pool = navi_pool_create(4096);
	bgctx->write_chain = navi_buf_chain_init(bgctx->write_pool);
	bgctx->buf_chain = navi_buf_chain_init(bgctx->buf_pool);

	pthread_rwlock_init(&bgctx->wlock,NULL);

	off = snprintf(job_name,sizeof(job_name),"bgwrite-%s", wfd->path);
	if ( off >= sizeof(job_name) ) {
		p = (char*)malloc(off + 1);
		sprintf(p, "bgwrite-%s", wfd->path);
	}
	navi_bgjob_t* ret = navi_streamed_bgjob_create(task, p, bgctx, NULL,bgwrite_jobcleanup,
		bgwrite_stream_handler,bgwrite_completer,bgwrite_error_handler);

	if ( ret == NULL) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "create scfile bgwrite failed:%s", job_name);
		if ( p != job_name)
			free(p);
		goto failed;
	}
	if ( p != job_name)
		free(p);

	bgctx->scfd = wfd;
	bgctx->timer = nvtask_new_timer(task,ret,time_threshold, NAVI_TIMER_INTERVAL, bgwrite_timer,NULL);

failed:
	bgwrite_ctx_cleanup(bgctx);
	return NULL;
}

void navi_scfile_bgwrite(navi_bgjob_t* job, void* data, size_t sz)
{
	if (!job || !data || sz==0)
		return;
	bgwrite_ctx_t* ctx = (bgwrite_ctx_t*)job->job_start_data;
	if ( ctx->_magic != BGWRITE_MAGIC )
		return;
	pthread_rwlock_rdlock(&ctx->wlock);
	navi_buf_chain_append(ctx->buf_chain, (const uint8_t*)data, sz);
	size_t total = navi_buf_chain_get_content(ctx->buf_chain, NULL, 0);
	if ( total >= ctx->size_threshold) {
		navi_streamed_bgjob_push(job, (void*)1, 1, NULL);
	}
	pthread_rwlock_unlock(&ctx->wlock);
}

void navi_scfile_bgwrite_fin(navi_bgjob_t* job)
{
	if (!job)
		return;
	bgwrite_ctx_t* ctx = (bgwrite_ctx_t*)job->job_start_data;
	if ( ctx->_magic != BGWRITE_MAGIC )
		return;

	pthread_rwlock_rdlock(&ctx->wlock);
	if ( navi_buf_chain_get_content(ctx->buf_chain, NULL, 0) > 0)
		navi_streamed_bgjob_push(job, (void*)1, 1, NULL);
	pthread_rwlock_unlock(&ctx->wlock);

	navi_streamed_bgjob_input_done(job);

	navi_task_t* task = navi_bgjob_get_task(job);
	if (task ) {
		nvtask_cancel_timer(task, ctx->timer);
		ctx->timer = NULL;
	}
}

void navi_scfile_bgwrite_abort(navi_bgjob_t* job)
{
	if (!job)
		return;
	bgwrite_ctx_t* ctx = (bgwrite_ctx_t*)job->job_start_data;
	if ( ctx->_magic != BGWRITE_MAGIC )
		return;

	navi_task_t* task = navi_bgjob_get_task(job);
	if (task ) {
		nvtask_cancel_timer(task, ctx->timer);
		ctx->timer = NULL;
	}
	navi_scfile_write_abort(ctx->scfd);
	navi_streamed_bgjob_cancel(job);
}

ssize_t navi_scfile_writev(navi_scfd_t* fd, const struct iovec *iov, int iovcnt)
{
	return writev(fd->fd, iov,iovcnt);
}

int navi_scfile_remove(void* mgr, const char* id, navi_request_t *main_req)
{
	scfile_mgr_t* _mgr = (scfile_mgr_t*)mgr;
    void* driver_pool = NULL;
	char path[1024];
	off_t off = snprintf(path, sizeof(path), "%s/", _mgr->path);
	if ( off >= sizeof(path) ) {
		return NV_SCFILE_PATH_TOO_LONG;
	}
	if ( !_mgr->path_strategy.resolver(_mgr->path_strategy.strategy, id,
		path + off,sizeof(path) - off) ) {
		return NV_SCFILE_STRATEGY_ERROR;
	}
	int _err =0;

	if ( -1 == unlink(path) ) {
		if ( errno == EACCES || errno == EPERM)
			_err = NV_SCFILE_PERM_PROBLEM;
		else if (errno == ENOENT  || errno == ENOTDIR)
			_err = NV_SCFILE_DIR_PROBLEM;
		else
			_err = NV_SCFILE_OTHER_ERROR;

		NAVI_FRAME_LOG(NAVI_LOG_WARNING, "unlink failed for:%s %d %s",
			path, errno, strerror(errno));
		return _err;
	}
    if(main_req){
        driver_pool = navi_request_get_driver_pool(main_req);
        if(driver_pool)
            s_rfdcache_delfd(_mgr->cache, path, driver_pool);
    }
	return 0;
}

bool navi_scfile_exists(void* mgr, const char* id, int* err)
{
	scfile_mgr_t* _mgr = (scfile_mgr_t*)mgr;
	char path[1024];
	int _err = 0;
	off_t off = snprintf(path, sizeof(path), "%s/", _mgr->path);
	if ( off >= sizeof(path) ) {
		_err = NV_SCFILE_PATH_TOO_LONG;
		goto failed;
	}
	if ( !_mgr->path_strategy.resolver(_mgr->path_strategy.strategy, id,
		path + off,sizeof(path) - off) ) {
		_err =  NV_SCFILE_STRATEGY_ERROR;
		goto failed;
	}

	struct stat stbuf;
	if ( 0 == stat(path, &stbuf) ) {
		if (S_ISREG(stbuf.st_mode))
			return true;
		else {
			_err = NV_SCFILE_NOT_REGULAR;
			goto failed;
		}
	}
	else {
		return false;
	}

failed:
	if (err)
		*err = _err;
	return false;
}

typedef struct _scmem_mgr_t
{
	char *group_name;
	int cnn_timeout;
	int resp_waiting;
	int input_max_interval;
} scmem_mgr_t;

static navi_hash_t* s_scmem_mgrs = NULL;

static void scmem_mgr_clean(void* obj)
{
	scmem_mgr_t* mgr = (scmem_mgr_t*)obj;
	free(mgr->group_name);
	free(mgr);
}

void* navi_scmem_mgr_init(const char* groupname,
	int conn_timeout,
	int resp_waiting, int input_max_interval) //!< cnavi0.5.0 仅支持IPv4分组
{
	navi_upgroup_t* group = navi_upgroup_mgr_get_group(navi_upgroup_mgr_instance(NULL), groupname);
	if (group == NULL) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "scmem_mgr init failed: upgroup not exists", groupname);
		return NULL;
	}

	if ( s_scmem_mgrs == NULL)
		s_scmem_mgrs = navi_hash_init_with_heap();

	scmem_mgr_t* mgr = (scmem_mgr_t*)navi_hash_get_gr(s_scmem_mgrs,groupname);
	if (mgr == NULL) {
		mgr = (scmem_mgr_t*)calloc(1,sizeof(scmem_mgr_t));
		mgr->group_name = strdup(groupname);
		navi_hash_set_gr2(s_scmem_mgrs, groupname, mgr, scmem_mgr_clean);
	}
	if ( conn_timeout <= 0) {
		conn_timeout = 500;
	}
	else if (conn_timeout >= 10000) {
		conn_timeout = 10000;
	}
	mgr->cnn_timeout = conn_timeout;

	if ( resp_waiting <= 0) {
		resp_waiting = 2000;
	}
	else if (resp_waiting >= 20000) {
		resp_waiting = 20000;
	}
	mgr->resp_waiting = resp_waiting;
	if (input_max_interval <= 0) {
		input_max_interval = 1000;
	}
	else if (input_max_interval >= 20000) {
		input_max_interval = 20000;
	}
	mgr->input_max_interval = input_max_interval;

	return mgr;
}

void navi_scmem_mgr_clean()
{
	navi_hash_destroy(s_scmem_mgrs);
	s_scmem_mgrs=NULL;
}

nvcli_redis_t* navi_scmem_get(const char* group, const char* scid, navi_task_t* task,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler)
{
	if (!group || 0==strlen(group) ||
		!scid || 0==strlen(scid) ||
		!task )
		return NULL;
	scmem_mgr_t* mgr = NULL;
	if ( s_scmem_mgrs ) {
		mgr = navi_hash_get_gr(s_scmem_mgrs, group);
	}
	if ( mgr == NULL) {
		if ( NULL == (mgr = navi_scmem_mgr_init(group, 1000, 2000, 1000))) {
			return NULL;
		}
	}

	navi_uppolicy_squery_t* policy_query =  navi_uppolicy_squery_create();
	navi_uppolicy_squery_add_inkey(policy_query, "key", scid);
	if ( 0 != navi_uppolicy_squery_resolve(policy_query, group) ) {
		navi_uppolicy_squery_destroy(policy_query);
		return NULL;
	}

	nvcli_redis_t* ret = nvtask_new_redis_session(task, (const struct sockaddr*)&policy_query->policy.peer_addr,
		result_handler, error_handler, NULL, mgr->cnn_timeout, mgr->resp_waiting, mgr->input_max_interval);

	nvcli_redis_get(ret, scid); //todo: getbin
	return ret;
}

nvcli_redis_t* navi_scmem_set_ifnx(const char* group, const char* scid, navi_task_t* task,
	void* data,
	size_t size,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler)
{
	if (!group || 0==strlen(group) ||
		!scid || 0==strlen(scid) ||
		!task || !data || !size)
		return NULL;

	scmem_mgr_t* mgr = NULL;
	if ( s_scmem_mgrs ) {
		mgr = navi_hash_get_gr(s_scmem_mgrs, group);
	}
	if ( mgr == NULL) {
		if ( NULL == (mgr = navi_scmem_mgr_init(group, 1000, 2000, 1000))) {
			return NULL;
		}
	}

	navi_uppolicy_squery_t* policy_query =  navi_uppolicy_squery_create();
	navi_uppolicy_squery_add_inkey(policy_query, "key", scid);
	if ( 0 != navi_uppolicy_squery_resolve(policy_query, group) ) {
		navi_uppolicy_squery_destroy(policy_query);
		return NULL;
	}

	nvcli_redis_t* ret = nvtask_new_redis_session(task, (const struct sockaddr*)&policy_query->policy.peer_addr,
		result_handler, error_handler, NULL, mgr->cnn_timeout, mgr->resp_waiting, mgr->input_max_interval);

	nvcli_redis_setnx(ret, scid,(const char*)data); //todo: setnx bin
	return ret;
}

nvcli_redis_t* navi_scmem_remove(const char* group, const char* scid, navi_task_t* task,
	nvredis_result_proc_fp result_handler,
	nvredis_error_proc_fp error_handler)
{
	if (!group || 0==strlen(group) ||
		!scid || 0==strlen(scid) ||
		!task)
		return NULL;

	scmem_mgr_t* mgr = NULL;
	if ( s_scmem_mgrs ) {
		mgr = navi_hash_get_gr(s_scmem_mgrs, group);
	}
	if ( mgr == NULL) {
		if ( NULL == (mgr = navi_scmem_mgr_init(group, 1000, 2000, 1000))) {
			return NULL;
		}
	}

	navi_uppolicy_squery_t* policy_query =  navi_uppolicy_squery_create();
	navi_uppolicy_squery_add_inkey(policy_query, "key", scid);
	if ( 0 != navi_uppolicy_squery_resolve(policy_query, group) ) {
		navi_uppolicy_squery_destroy(policy_query);
		return NULL;
	}

	nvcli_redis_t* ret = nvtask_new_redis_session(task, (const struct sockaddr*)&policy_query->policy.peer_addr,
		result_handler, error_handler, NULL, mgr->cnn_timeout, mgr->resp_waiting, mgr->input_max_interval);

	nvcli_redis_del(ret, scid); //todo: setnx bin
	return ret;
}

#define NAVI_SCFILE_DIR_CONFFILE "scfile_dir.json"
#define NAVI_SCFILE_DIR_STRATEGY_SO_DIR "scfile_path_strategy_so_dir"
#define NAVI_SCFILE_DEFAULT_STRATEGY_SO_DIR "scfile_path_so"

static navi_hash_t* scfile_strategy_so_handles = NULL;

//todo:
void navi_scfile_mgrs_init(const json_t* config)
{
	if (!config || !json_is_object(config))
		return;

	void* it = json_object_iter((json_t*)config);
	const char* root;
	json_t* cfg;
	while ( it ) {
		root = json_object_iter_key(it);
		cfg = json_object_iter_value(it);

		if ( !json_is_object(cfg) )
			continue;
        navi_scfile_mgr_init(root, cfg, NULL, NULL, NULL);
		it = json_object_iter_next((json_t*)config, it);
	}
	atexit(navi_scfile_mgrs_clean);
}


