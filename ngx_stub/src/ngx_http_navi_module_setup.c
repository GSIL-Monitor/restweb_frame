/*
 * ngx_http_navi_module_setup.c
 *
 *  Created on: 2013-9-23
 *      Author: yanguotao@youku.com
 */

#include <cnaviutil/navi_static_content.h>

ngx_module_t  ngx_http_navi_module;
navi_module_mgr_t* navi_module_mgr = NULL;
ngx_event_t* ev_check_time = NULL;
ngx_event_t* ev_upstream_check_time = NULL;
ngx_cycle_t* pcycle = NULL;
ngx_queue_t ngx_pipe_mgr;
static ngx_pool_t *navi_open_file_cache_pool = NULL;

/*
extern void navi_task_mgr_init(const struct sockaddr_un* ctrl_redis);
extern void* navi_timer_driver_install(navi_timer_t* timer);
extern void navi_timer_driver_cancel(navi_timer_t* timer);
extern void* nvacnn_driver_install(navi_aconn_t* conn);
extern void nvacnn_driver_close(navi_aconn_t* conn);
extern void nvacnn_driver_set_idle(navi_aconn_t* conn, int idle_timeout_ms);
extern void nvacnn_driver_quit_idle(navi_aconn_t* conn);
extern void nvacnn_driver_process(navi_aconn_t* conn);

typedef void* (*navi_timer_driver_install_fp)(navi_timer_t* timer);
typedef void (*navi_timer_driver_cancel_fp)(navi_timer_t* driver);
typedef void* (*nvacnn_driver_install_fp)(navi_aconn_t* conn);
typedef void (*nvacnn_driver_close_fp)(navi_aconn_t* conn);
typedef void (*nvacnn_driver_set_idle_fp)(navi_aconn_t* conn, int idle_timeout_ms);
typedef void (*nvacnn_driver_quit_idle_fp)(navi_aconn_t* conn);
typedef void (*nvacnn_driver_process_fp)(navi_aconn_t* conn);

extern void nvcli_parent_driver_regist(navi_timer_driver_install_fp timer_installer,
	navi_timer_driver_cancel_fp timer_cancler,
	nvacnn_driver_install_fp aconn_installer,
	nvacnn_driver_process_fp aconn_processor,
	nvacnn_driver_close_fp aconn_closer,
	nvacnn_driver_set_idle_fp aconn_set_idle,
	nvacnn_driver_quit_idle_fp aconn_quit_idle);
*/

static ngx_int_t ngx_http_navi_init_worker(ngx_cycle_t *cycle) 
{
    navi_upgroup_mgr_t *up_mgr;
    ngx_http_navi_main_conf_t* mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_navi_module);


    navi_scfile_mgr_rfd_cache_driver(ngx_http_navi_open_file_cache_init,
                                     navi_http_navi_open_file_cache_clean,
                                     ngx_http_navi_get_cached_open_file,
                                     ngx_http_navi_delete_cached_open_file,
                                     ngx_http_navi_check_dir);

    navi_request_driver_rest_hook(ngx_http_navi_request_rest_driver_trigger,
    		ngx_http_navi_root_rest_run);

	//set driver handler
	nvcli_parent_driver_regist(navi_timer_driver_install, navi_timer_driver_cancel,
							nvacnn_driver_install, nvacnn_driver_process,
							nvacnn_driver_close, nvacnn_driver_set_idle,
							nvacnn_driver_quit_idle, nvcli_parent_create_driver,
							nvcli_parent_get_driverpool, nvcli_parent_cleanup_driver,navi_driver_setup);
	//set util handler
	ngx_http_navi_init_util();

	//init task mgr
	ngx_url_t url;
	url.url = mcf->task_ctrl;//unix:xxpath
	url.uri_part = 0;
	if ( NGX_OK != ngx_parse_url(cycle->pool,&url)) {
		ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "Init navi task ctrl failed: %s",url.err);
        return NGX_ERROR;
	}

	if (url.naddrs != 1 || url.family != AF_UNIX) {
		ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "navi task ctrl must be unix domain addr.");
        return NGX_ERROR;
	}
	navi_task_mgr_init((const struct sockaddr_un*)(url.addrs[0].sockaddr));


    if (mcf->client_check == NGX_CONF_UNSET){
        mcf->client_check = 1;
    }

    if (mcf->up_main_conf.conf_root.len == 0){
        up_mgr = navi_upgroup_mgr_instance(NULL);
    }
    else{
        up_mgr = navi_upgroup_mgr_instance((const char *)(mcf->up_main_conf.conf_root.data));
    }
    if (up_mgr == NULL){
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "Init navi upgroup manager failed ");
        return NGX_ERROR;
    }

    pcycle = cycle;


	//check task ctrl conf
	if (mcf->task_ctrl.len == 0) {
		ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "Init navi task ctrl failed: task ctrl unset.");
        return NGX_ERROR;
	}

    if (navi_module_mgr == NULL){
        if (mcf->navi_directory.len == 0){
            navi_module_mgr = navi_mgr_init(NULL);
        }
        else{
            navi_module_mgr = navi_mgr_init((const char *)(mcf->navi_directory.data));
        }
    }

    if (navi_module_mgr == NULL){
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "Init navi module manager failed ");
        return NGX_ERROR;
    }

    ngx_http_navi_global_timer_process();

    if (mcf->check_interval == NGX_CONF_UNSET){
        mcf->check_interval  = NGX_HTTP_NAVI_DEFAULT_CHECK_INTERVAL;
    }
    if (ev_check_time == NULL && mcf->check_interval > 0){
        ev_check_time = ngx_pcalloc(cycle->pool,sizeof(ngx_event_t));
        ev_check_time->handler = ngx_http_navi_module_check;
        ev_check_time->data = (void *)(mcf->check_interval);
		ev_check_time->log = cycle->log;
        ngx_add_timer(ev_check_time, (mcf->check_interval)*1000);
    }

    if (mcf->up_main_conf.check_interval  == NGX_CONF_UNSET){
        mcf->up_main_conf.check_interval   = NGX_HTTP_NAVI_DEFAULT_CHECK_INTERVAL;
    }
    if (ev_upstream_check_time == NULL && mcf->up_main_conf.check_interval > 0){
        ev_upstream_check_time = ngx_pcalloc(cycle->pool,sizeof(ngx_event_t));
        ev_upstream_check_time->handler = ngx_http_navi_upstream_module_check;
        ev_upstream_check_time->data = (void *)(mcf->up_main_conf.check_interval );
		ev_upstream_check_time->log = cycle->log;
        ngx_add_timer(ev_upstream_check_time, (mcf->up_main_conf.check_interval )*1000);
    }

    ngx_queue_init(&ngx_pipe_mgr);

    return NGX_OK;
}

static void ngx_http_navi_exit_worker(ngx_cycle_t *cycle) 
{
	navi_task_mgr_clean();
    nvacnn_clean_global_pool();

    if (!ngx_queue_empty(&ngx_pipe_mgr)){
        ngx_http_navi_pipe_mgr_destroy();
    }
    navi_vevent_mgr_destroy();
    nvup_pipe_mgr_destroy();

    navi_upgroup_mgr_instance_destroy();

    if (navi_module_mgr != NULL){
        navi_mgr_free(navi_module_mgr);
        navi_module_mgr = NULL;
    }
}

static char* ngx_http_navi_setup_handler(ngx_conf_t *cf, void * conf, ngx_int_t (*handler)(ngx_http_request_t *))
{
    ngx_http_core_loc_conf_t* clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = handler;
    clcf->if_modified_since = NGX_HTTP_IMS_OFF;
    return NGX_CONF_OK;
}

static char* ngx_http_navi_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) 
{
    return ngx_http_navi_setup_handler(cf,conf,&ngx_http_navi_init_handler);
}

static void* ngx_http_navi_create_main_conf(ngx_conf_t *cf) 
{
    ngx_http_navi_main_conf_t* mcf = ngx_pcalloc(cf->pool, sizeof(*mcf));
    if(mcf == NULL) {
        return NGX_CONF_ERROR;
    }
    mcf->check_interval = NGX_CONF_UNSET;
    mcf->client_check = NGX_CONF_UNSET;
    mcf->up_main_conf.check_interval = NGX_CONF_UNSET;
    ngx_str_set(&mcf->task_ctrl,"unix:/tmp/cnavi_task.sock");
    return mcf;
}

static ngx_command_t  ngx_http_navi_commands[] = {
    { ngx_string("navi_check_interval"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_navi_main_conf_t, check_interval),
      NULL },
    { ngx_string("navi_client_check"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_navi_main_conf_t, client_check),
      NULL },
    { ngx_string("navi_directory"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_navi_main_conf_t, navi_directory),
      NULL },
    { ngx_string("navi_task_ctrl"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_navi_main_conf_t, task_ctrl),
      NULL },
    { ngx_string("navi_init"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_navi_init,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*navi upstream*/
    { ngx_string("navi_ds_config"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_navi_main_conf_t, up_main_conf.conf_root),
      NULL },
    
    { ngx_string("nvds_check_interval"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_navi_main_conf_t, up_main_conf.check_interval),
      NULL },
    
    { ngx_string("navi_ds_pass"),
      NGX_HTTP_LOC_CONF| NGX_CONF_NOARGS,
      ngx_http_navi_upstream_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    ngx_null_command
};

static ngx_http_module_t  ngx_http_navi_module_ctx = {
    ngx_http_navi_upstream_add_srv_grp,                                     /* preconfiguration */
    ngx_http_navi_post_config,     /* postconfiguration */
    ngx_http_navi_create_main_conf,    /* create main configuration */
    NULL,        /* init main configuration */
    NULL,                                     /* create server configuration */
    NULL,                                     /* merge server configuration */
    NULL,                                     /* create location configuration */
    NULL,                                     /* merge location configuration */
};

ngx_module_t  ngx_http_navi_module = {
    NGX_MODULE_V1,
    &ngx_http_navi_module_ctx,             /* module context */
    ngx_http_navi_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                 /* init module */
    ngx_http_navi_init_worker,             /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_navi_exit_worker,             /* exit process */
    NULL,             /* exit master */
    NGX_MODULE_V1_PADDING
};


