/*
 * ngx_http_navi_module.h
 *
 *  Created on: 2013-9-23
 *      Author: yanguotao@youku.com
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_channel.h>


#define NGX_HTTP_NAVI_DEFAULT_CHECK_INTERVAL 5

#define NGX_HTTP_BUF_ALLOC_SIZE(buf)                                          \
    (sizeof(*buf) +                                                           \
	 (((buf)->temporary || (buf)->memory) ? ngx_buf_size(buf) : 0) +          \
	 (((buf)->file!=NULL) ? (sizeof(*(buf)->file) + (buf)->file->name.len + 1) : 0))

ngx_int_t   ngx_http_navi_worker_processes;

typedef struct {
    navi_request_t *navi_req;
    //void *data;
    ngx_event_t* req_timeout_ev; //请求超时定时器对应的event
    ngx_int_t  processed;
    unsigned run_in_entrance:1;
} ngx_http_navi_ctx_t;

typedef struct ngx_http_navi_header_val_s ngx_http_navi_header_val_t;
typedef ngx_int_t (*ngx_http_navi_set_header_pt)(ngx_http_request_t *r,
    ngx_http_navi_header_val_t *hv, ngx_str_t *value);

struct ngx_http_navi_header_val_s {
    ngx_uint_t                              hash;
    ngx_str_t                               key;
    ngx_http_navi_set_header_pt              handler;
    ngx_uint_t                              offset;
};

typedef struct {
    ngx_str_t                               name;
    ngx_uint_t                              offset;
    ngx_http_navi_set_header_pt              handler;
} ngx_http_navi_set_header_t;

typedef struct ngx_nvds_main_conf_s {
	ngx_str_t conf_root;
	ngx_int_t check_interval;
	ngx_str_t enable_nvds_location;
	void* srv_conf;
}ngx_http_navi_up_main_conf_t;

typedef struct {
	ngx_int_t   check_interval;
	ngx_flag_t  client_check;
	ngx_str_t  navi_directory;
	ngx_str_t task_ctrl;//用于task控制，目前为redis的unix domain地址
	ngx_http_navi_up_main_conf_t up_main_conf;
} ngx_http_navi_main_conf_t;

static ngx_http_output_header_filter_pt next_header_filter;
static ngx_http_output_body_filter_pt next_body_filter;
static ngx_int_t ngx_http_navi_header_filter(ngx_http_request_t *r);
static ngx_int_t ngx_http_navi_body_filter(ngx_http_request_t * r, ngx_chain_t * in);
static ngx_int_t ngx_http_navi_post_config(ngx_conf_t *cf);
static ngx_int_t ngx_http_navi_sr_end_handler(ngx_http_request_t *r, void *data, ngx_int_t rc);
static ngx_int_t ngx_http_navi_main_end_handler_common(ngx_http_request_t * r);
static void ngx_http_navi_main_end_handler(ngx_http_request_t* r) ;
static ngx_int_t ngx_http_navi_add_subrequest(ngx_http_request_t *r, navi_request_t *sub, ngx_uint_t flags);
static void  ngx_http_navi_global_timer_process();
static void ngx_http_navi_module_check(ngx_event_t *ev);
static ngx_http_request_t * ngx_http_navi_get_root_req(navi_request_t *req);
static void ngx_http_navi_reqtimer_process(navi_request_t* root);
static void ngx_http_navi_ve_process(navi_request_t*);
	
static  ngx_int_t ngx_http_navi_add_header_in(ngx_http_request_t* r, const ngx_str_t* key, const ngx_str_t* value);
static ngx_int_t ngx_http_navi_add_header_out(ngx_http_request_t *r, const ngx_str_t * key, const ngx_str_t* value);
static ngx_int_t ngx_http_navi_respond_header(ngx_http_request_t *r, ngx_str_t* content_type,
        ngx_int_t  content_len, ngx_int_t  status_code, const ngx_str_t *status_line);

static ngx_int_t  ngx_http_navi_init_handler(ngx_http_request_t* r);

static ngx_int_t  ngx_http_navi_process_request(ngx_http_request_t* r);

static navi_request_t * ngx_http_navi_build_request(ngx_http_request_t* r);

const ngx_str_t NGX_HTTP_NAVI_HEADER_ALLOW = ngx_string("Allow");

const ngx_str_t NGX_HTTP_NAVI_ALLOW_METHOD = ngx_string("Only allow GET,POST");

const ngx_str_t NGX_HTTP_NAVI_HEADER_ACCESS_CTRL = ngx_string("Access-Control-Allow-Origin");

const ngx_str_t NGX_HTTP_NAVI_HEADER_ACCESS_CTRL_VALUE = ngx_string("*");

/*navi upstream*/
typedef struct ngx_navi_up_conn_pool_s
{
    ngx_queue_t cache;
    ngx_uint_t max_caches;
    ngx_uint_t cur_cached;
    ngx_msec_t max_idle_to;
} ngx_navi_up_conn_pool_t;

typedef struct ngx_navi_up_data_s
{
    navi_hash_t* grp_conn_pools;
    navi_pool_t* hash_mem;    
    ngx_queue_t free_cache_ents;
} ngx_navi_up_data_t;

typedef struct ngx_navi_up_conn_cache_ent_s
{
    ngx_navi_up_data_t* policy;
    ngx_navi_up_conn_pool_t *pool;
    ngx_queue_t queue;
    ngx_connection_t *connection;
} ngx_navi_up_conn_cache_ent_t;

typedef struct ngx_navi_up_request_peer_data_s {
    ngx_navi_up_data_t *policy;
    ngx_http_navi_ctx_t *req_ctx;
    ngx_http_request_t *req;
}ngx_navi_up_request_peer_data_t;

typedef enum navi_root_run_E {
	NAVI_ROOT_RUN_COMPLETE,
	NAVI_ROOT_RUN_NEW_SUBS,
	NAVI_ROOT_RUN_WAITING
}navi_root_run_e;

static ngx_int_t ngx_http_navi_upstream_init_request(ngx_http_request_t *r,
        ngx_http_upstream_srv_conf_t *us);
static ngx_int_t ngx_http_navi_upstream_get_peer(ngx_peer_connection_t *pc, void *data);
static void ngx_http_navi_upstream_free_peer(ngx_peer_connection_t *pc,
        void *data, ngx_uint_t state);
static ngx_int_t ngx_http_navi_upstream_add_srv_grp(ngx_conf_t* cf);
static char *ngx_http_navi_upstream_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_navi_upstream_module_check(ngx_event_t *ev);
static void ngx_http_navi_pipe_process(void);
static void ngx_http_navi_pipe_mgr_destroy(void);
static void *ngx_http_navi_open_file_cache_init(void *mgr, int max_uses, int min_uses, int valid_time);
static int ngx_http_navi_get_cached_open_file(void* cache, const char* path, void* pool);
static void ngx_http_navi_delete_cached_open_file(void* cache, const char* path, void* pool);
static bool ngx_http_navi_check_dir(void* cache, const char* path);
static void navi_http_navi_open_file_cache_clean(void *mgr, void* cache);
static void ngx_http_navi_root_run(navi_request_t* root, bool trig_ve, bool trig_app);
static void ngx_http_navi_root_rest_run(navi_request_t* root);
static void ngx_http_navi_request_rest_driver_trigger();
