/** \brief 
 * navi_grcli.h
 *  Created on: 2015-1-7
 *      Author: li.lei
 *  brief: 一次往复式远程会话。
 */

#ifndef NAVI_GRCLI_H_
#define NAVI_GRCLI_H_

#include "navi_common_define.h"
#include "navi_list.h"
#include "navi_async_conn.h"
#include "navi_timer_mgr.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef enum _nvcli_proto_e
{
	NVCLI_HTTP,
	NVCLI_REDIS,
	NVCLI_DUMMY
} nvcli_proto_e;

/*!	\struct nvcli_parent_t
 * \brief	封装通用客户端所运行的语境，统一通用客户端在driver层的处理
 */
typedef struct _navi_grcli_parent_s
{
	chain_node_t clients;	//!< 当前语境下，发起的客户端会话
	int client_cnt;
	navi_timer_mgr_t timer_mgr;
	navi_pool_t* pool;	//!< navi_task_t或者主navi_request_t的内存池
	chain_node_t active_aconns;

	chain_node_t drive_link;

	chain_node_t client_pool[NVCLI_DUMMY];

	void (*parent_idle_handler)(void* parent);
	void* parent; //!< navi_task_t或者navi_request_t,必须是主请求

	void* driver;
	void* (*get_driver_pool)(void* driver);
	void (*driver_cleanup)(void* driver);
} nvcli_parent_t;

/*!< 响应头部解析回调。返回为0时表示未完，返回1时表示header已完，且不期望body，如果size和调用前不同，则
 * 认为是协议错误。
 * 返回2头部完整，还表示需要等待body的到达， size参数返回header占用的量。 返回-1表示协议错误*/
typedef int (*nvcli_iheader_parse_fp)(void* obj, const unsigned char* content, size_t* size);
/*!< 响应body的解析回调，返回为0表示未完，返回1表示完成。返回-1表示协议错误*/
typedef int (*nvcli_ibody_parse_fp)(void* obj, const unsigned char* content, size_t* size);
typedef void (*nvcli_cleanup_fp)(void* obj);

typedef void (*nvcli_error_fp)(void* cli_parent, void* cli, nvcli_error_e e);
/*!< 输出body回调函数。 返回0表示输出未完，返回1表示输出结束，返回-1表示错误，不能完整输出内容*/
typedef int (*nvcli_output_goon_fp)(void* cli_parent, void* cli);
typedef void (*nvcli_complete_fp)(void* cli_parent, void* cli);

typedef struct _navi_grcli_proto_proc_s
{
	nvcli_proto_e proto;
	size_t proto_obj_size;
	nvcli_iheader_parse_fp iheader_parser;
	nvcli_ibody_parse_fp ibody_parser;
	nvcli_cleanup_fp proto_cleanup;
} nvcli_proto_proc_t;

typedef struct _navi_grcli_app_proc_t
{
	nvcli_error_fp session_error_handler;
	nvcli_complete_fp session_complete_handler;
	nvcli_output_goon_fp obody_goon_handler;
}navi_grcli_app_proc_t;

typedef struct _navi_grcli_s
{
	chain_node_t parent_link;
	nvcli_parent_t* parent;

	navi_aconn_t* conn;

	const nvcli_proto_proc_t* proto_procs;
	navi_grcli_app_proc_t app_procs;
    void* app_data;//用户数据
    void (*app_data_cleanup)(void* app_data);

	navi_timer_t* input_timer;
	navi_timer_t* output_timer;
	navi_pool_t* private_pool;
    

	int input_max_interval;
	int resp_max_waiting;

	union {
		uint8_t flags;
		struct {
			int has_output:1;//是否有过输出
			int oheader_done:1;
			int output_done:1;
			int resp_reading:1;
			int iheader_done:1;
			int input_done:1;
			int recycled:1;
		};
	};
} navi_grcli_t;

/*************************************
 * ... 供parent子类的定时器操作调用
 *************************************/
typedef void (*nvcli_parent_timer_fp)(void* parent, void* timer_arg);

navi_timer_h nvcli_parent_add_timer(nvcli_parent_t* parent, int timeout_ms,
	navi_timer_type_e type,
	void* timer_arg,
	nvcli_parent_timer_fp timer_handler,
	nvcli_parent_timer_fp timer_cleanup);

void nvcli_parent_cancel_timer(nvcli_parent_t* parent, navi_timer_h timer);

void nvcli_parent_init(nvcli_parent_t* parent, navi_pool_t* pool, void* parent_obj,
	void (*parent_idle_handler)(void*));

void nvcli_parent_cleanup(nvcli_parent_t* parent);

void nvcli_parent_check_idle(nvcli_parent_t* parent);

void* nvcli_init( nvcli_parent_t* parent,
	const nvcli_proto_proc_t* in_procs,
	const navi_grcli_app_proc_t* app_procs,
	void* app_data,
	int conn_timeout,
	int resp_max_waiting,
	int input_max_interval,
	const struct sockaddr* peer);

/*************************************
 * ... 供不同会话子类调用
 *************************************/

void nvcli_set_obody_handler(navi_grcli_t* cli, nvcli_output_goon_fp body_handler);
void nvcli_set_complete_handler(navi_grcli_t* cli, nvcli_complete_fp body_handler);
void nvcli_set_error_handler(navi_grcli_t* cli, nvcli_error_fp body_handler);

void nvcli_clean(navi_grcli_t* cli);

void nvcli_send_header(navi_grcli_t* cli, const unsigned char* content, size_t size,
	bool start_reading);

void nvcli_send_body(navi_grcli_t* cli, const unsigned char* content, size_t size,
	bool start_reading);

void nvcli_prepare_file_body(navi_grcli_t* cli, int fd, size_t pos, size_t size);
void nvcli_prepare_body(navi_grcli_t* cli, const unsigned char* content, size_t size);

void nvcli_sendfile(navi_grcli_t* cli, int fd, size_t pos, size_t size, bool start_reading);

/**************************************
 * ... 驱动调用接口。驱动通用客户端的执行
 **************************************/
typedef void* (*nvcli_parent_create_driver_fp)(nvcli_parent_t* parent);
typedef void* (*nvcli_parent_get_driverpool_fp)(void* driver);
typedef void (*nvcli_parent_cleanup_driver_fp)(void* driver);
typedef void (*navi_driver_setup_fp)(void);


void nvcli_parent_driver_regist(navi_timer_driver_install_fp timer_installer,
	navi_timer_driver_cancel_fp timer_cancler,
	nvacnn_driver_install_fp aconn_installer,
	nvacnn_driver_process_fp join_rev,
	nvacnn_driver_close_fp aconn_closer,
	nvacnn_driver_set_idle_fp aconn_set_idle,
	nvacnn_driver_quit_idle_fp aconn_quit_idle,
	nvcli_parent_create_driver_fp parent_driver_creater,
	nvcli_parent_get_driverpool_fp parent_dirvepool_getter,
	nvcli_parent_cleanup_driver_fp parent_driver_cleaner,
	navi_driver_setup_fp driver_setup);

void nvcli_parents_drive(nvcli_parent_create_driver_fp create_driver, nvcli_parent_get_driverpool_fp get_driver_pool,
	nvcli_parent_cleanup_driver_fp cleanup_driver);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_GRCLI_H_ */
