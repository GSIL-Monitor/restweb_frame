/** \brief 
 * navi_async_network.h
 *  Created on: 2015-1-15
 *      Author: li.lei
 *  brief: 
 */

#ifndef NAVI_ASYNC_NETWORK_H_
#define NAVI_ASYNC_NETWORK_H_

#include "navi_common_define.h"
#include "navi_list.h"
#include "navi_simple_hash.h"
#include "navi_buf_chain.h"
#include "nvcli_common.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>

#ifdef __cplusplus
extern "C"
{
#endif

/*!
 * \struct	navi_async_conn_t
 * \brief	cnavi异步连接对象
 */
typedef struct _navi_async_conn_s
{
	void* driver;	/*!< 驱动层对应实体，如果为NULL，则驱动层需要发起连接*/
	void (*driver_close_handler)(struct _navi_async_conn_s*);	/*!< 驱动层对应实体的回收函数 */
	void (*driver_set_idle_handler)(struct _navi_async_conn_s*, int);
	void (*driver_quit_idle_handler)(struct _navi_async_conn_s*);
	void (*driver_process_handler)(struct _navi_async_conn_s*);

	void* app;	/*!< 应用层数据发送者，或者数据读取者*/

	void (*app_unbind_handler)(void*);

	/*!< parse_in_handler回调函数。驱动层在有数据时调用
	 * 	返回0，表示继续等待数据。
	 * 	返回1，表示读取完整。不期望其他数据的读入。
	 * 	返回-1，表示协议错误。连接需要断开。
	 */
	int (*app_input_handler)(void* app, const unsigned char* content, size_t size);

	/*!< output_goon回调函数。驱动层在发送完一批数据时后，如果上次调用output_goon
	 * 返回值是0，那么再次调用output_goon函数。如果上次返回为1，则发送完毕后，不再进行
	 * 发送的检查。
	 * 如果设置为空，那么只是发送out_buf一次。
	 * 如果返回值为1，则表示当前out_buf的内容是最后要发送的内容。
	 */
	int (*app_output_goon_handler)(void* app);

	void (*app_error_handler)(void* app, nvcli_error_e e);

	chain_node_t link;

	navi_buf_chain_t* out_buf;
	//write ctx
	void * busy_outbuf;
	void ** busy_outbuflast;
	
	navi_pool_t* pool;

	int conn_timeout_ms;

	union {
		struct sockaddr peer_addr;
		struct sockaddr_in peer_addr_in;
		struct sockaddr_in6 peer_addr_in6;
		struct sockaddr_un peer_addr_un;
	};

	union {
		uint32_t flags;
		struct {
			int use_once:1;
			/*!< \var app_write_status
			 * 0x00 nothing
			 * 0x01 有，并且还有
			 * 0x02 有，只有这些
			 * 0x03 已经结束
			 */
			unsigned int app_write_status:2;
			int has_output:1;

			/*!< \var app_reading_status
			 *	0x00 不需要读
			 *	0x01 需要读，且没有读完
			 *	0x02 已经读完，要求不能再有。
			 *	0x03 协议解析错误
			 */
			unsigned int app_reading_status:2;
			int idle:1;
			int ready:1;
			int err:1;
			int zombie:1;
		};
	};

	int used_cnt;	/*!< 被使用的次数*/
} navi_aconn_t;

/**************************************************
 * ... 异步连接的使用者调用的接口部分
 **************************************************/

/*!< parse_in_handler回调函数。驱动层在有数据时调用
 * 	返回0，表示继续等待数据。
 * 	返回1，表示读取完整。不期望其他数据的读入。
 * 	返回-1，表示协议错误。连接需要断开。
 */
typedef int (*nvacnn_parse_in_fp)(void* app, const unsigned char* content, size_t size);

/*!< output_goon回调函数。驱动层在发送完一批数据时后，如果上次调用output_goon
 * 返回值是0，那么再次调用output_goon函数。如果上次返回为1，则发送完毕后，不再进行
 * 发送的检查。
 * 如果设置为空，那么只是发送out_buf一次。
 * 如果返回值为1，则表示当前out_buf的内容是最后要发送的内容。
 */
typedef int (*nvacnn_output_goon_fp)(void* app);

/*!
 * \fn	navi_aconn_t* nvacnn_get_conn(const struct sockaddr* peer, void* app);
 * \brief	获得一个新的tcp连接，或者从连接池中取出。
 * \param peer	对端地址
 * \param app	连接上承载的上层对象
 */
typedef void (*nvacnn_app_unbind_fp)(void* app);
navi_aconn_t* nvacnn_get_conn(const struct sockaddr* peer, void* app,
	nvacnn_app_unbind_fp unbind_handler, int conn_timeout_ms);

/*!	\fn	void nvacnn_set_short(bool short_conn);
 * 	\brief	设置短连接或者长连接。默认是长连接。
 * 		连接再没有数据要输出，并且不再期望输入到达时，如果设置为短连接，则连接关闭。
 */
void nvacnn_set_short(navi_aconn_t* cnn, bool short_conn);

/*! \fn  bool nvacnn_is_idle(navi_aconn_t* conn);
 *	\brief	检查连接是否是idle的。连接再没有数据要输出，并且不再期望输入到达时是idle的。
 */
bool nvacnn_is_idle(navi_aconn_t* conn);

static inline bool nvacnn_is_ready(navi_aconn_t* conn)
{
	return conn->ready;
}

static inline void nvacnn_set_ready(navi_aconn_t* conn)
{
	conn->ready = 1;
}

/*! \fn void nvacnn_write(navi_aconn_t* conn, const unsigned char* content, size_t size,
	nvacnn_output_goon_fp goon);
	\brief	输出内容。如果goon为空，表示不再有输出。如果非空，表示异步发送完成后，需要继续发送。
	\param conn
	\param content	内容
	\param size	内容大小
	\param goon	如果此次内容发送完毕后，还有内容需要发送，那么设置goon handler
*/
void nvacnn_write(navi_aconn_t* conn, const unsigned char* content, size_t size,
	nvacnn_output_goon_fp goon, bool pre);

/*! \fn void nvacnn_sendfile(navi_aconn_t* conn, int fd, size_t pos, nvacnn_output_goon_fp goon, bool pre);
	\brief	输出文件内容。如果goon为空，表示不再有输出。如果非空，表示异步发送完成后，需要继续发送。
	\param conn
	\param fd	打开的文件句柄
	\param pos	发送的文件起始位置
	\param goon	如果此次内容发送完毕后，还有内容需要发送，那么设置goon handler
*/
void nvacnn_sendfile(navi_aconn_t* conn, int fd, size_t pos,size_t size, nvacnn_output_goon_fp goon, bool pre);


/*! \fn void nvacnn_set_reading(navi_aconn_t* conn, nvacnn_parse_in_fp handler);
 * 	\brief	表示开始等待输入。或者修改输入的处理handler
 * 	\param conn
 * 	\param handler
 *
 */
void nvacnn_set_reading(navi_aconn_t* conn, nvacnn_parse_in_fp handler);

/*!	\fn void nvacnn_close(navi_aconn_t* conn);
 *	\brief	应用层关闭连接。
 */
void nvacnn_close(navi_aconn_t* conn);

typedef struct _navi_peer_aconn_pool_s
{
	chain_node_t idles; //!< 处于idle状态的navi_async_conn_t
	int cur_idle_count;
	int idle_pool_size;	//!< 连接池最大idle连接数
	int idle_timeout; //!< 连接处于IDLE的时限，超过时限则关闭
	int	conn_used_limit; //!< 连接被使用的次数限制，超过限制则关闭
} navi_peer_aconn_pool_t;

typedef struct _navi_aconn_pool_mgr_s
{
	int idle_total_limit;	//!< 全局最大idle连接数。如果超过限制，则按超过比例，清理各peer的连接池中的连接。
	int idle_total; 	//!< 当前连接池最大连接数
	navi_hash_t* peer_idle_idx; //!< key是地址的字符串表示，value是navi_peer_aconn_pool_t

} nvacnn_pool_mgr_t;

/*!	\fn	void nvacnn_set_peer_pool(const struct sockaddr* peer, int idle_pool_size,
		int idle_timeout_ms, int conn_used_max);
	\brief	设置某个对端的连接池参数
 *	\param peer	对端地址
 *	\param idle_pool_size	连接池大小。设置为0，表示全部使用短连接，并且清理之前已经存在的idle连接。
 *	\param idle_timeout_ms	在idle状态的连接的最大时长。如果为0，表示可以一直持有
 *	\param conn_used_max	表示连接被使用的上限。超过上限时，连接idle时，会被关闭。
 */
void nvacnn_set_peer_pool(const struct sockaddr* peer, int idle_pool_size,
	int idle_timeout_ms, int conn_used_max);
void nvacnn_set_global_pool(int max_idle_conn);

void nvacnn_add_idle(navi_aconn_t* idle);
navi_aconn_t* nvacnn_get_idle(const struct sockaddr* peer);
void nvacnn_check_global_pool();
void nvacnn_clean_global_pool();

/************************
 *  ... 驱动层调用的接口
 ************************/

/*!	\fn void nvacnn_input_arrive(navi_aconn_t* conn, const unsigned char* in, size_t size);
 *	\brief	驱动层读取到数据时，调用该函数。
 */
void nvacnn_input_arrive(navi_aconn_t* conn, const unsigned char* in, size_t size);

/*! \fn void nvacnn_output_gone(navi_aconn_t* conn);
 *	\brief 驱动层在发送完当前数据后，调用该函数。
 */
void nvacnn_output_gone(navi_aconn_t* conn);

/*! \fn void nvacnn_has_problem(navi_aconn_t* conn, nvacnn_error_e e);
 * 	\brief	驱动层在发现连接有问题时，调用该函数。
 */
void nvacnn_has_problem(navi_aconn_t* conn, nvcli_error_e e);

void nvacnn_idle_timedout(navi_aconn_t* conn);

typedef void* (*nvacnn_driver_install_fp)(navi_aconn_t* conn);
typedef void (*nvacnn_driver_close_fp)(navi_aconn_t* conn);
typedef void (*nvacnn_driver_set_idle_fp)(navi_aconn_t* conn, int idle_timeout_ms);
typedef void (*nvacnn_driver_quit_idle_fp)(navi_aconn_t* conn);
typedef void (*nvacnn_driver_process_fp)(navi_aconn_t* conn);

/*!< \fn void nvacnn_set_driver(navi_aconn_t* conn, void* driver, nvacnn_driver_close_fp closer);
 *	\brief	驱动层创建新的连接和navi_aconn_t绑定时，使用该函数。
 *	\param conn
 *	\param driver 驱动层给出的连接实体
 *	\param process 驱动层给出的对navi_aconn_t进行处理的回调函数，主要是根据navi_aconn_t的信息进行读写事件的安排
 *	\param closer  驱动层给出的连接实体关闭的回调函数。
 *	\param set_idle	驱动层给出的在navi_aconn_t idle时的处理回调
 *	\param quit_idle 驱动层给出的在navi_aconn_t从idle pool被取出时的处理回调
 */
void nvacnn_set_driver(navi_aconn_t* conn, void* driver,
	nvacnn_driver_process_fp join_rev,
	nvacnn_driver_close_fp closer,
	nvacnn_driver_set_idle_fp set_idle,
	nvacnn_driver_quit_idle_fp quit_idle);

void nvacnn_process_driver(navi_aconn_t* conn);

#ifdef __cplusplus
}
#endif

#endif /* NAVI_ASYNC_NETWORK_H_ */
