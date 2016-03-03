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
 * \brief	cnavi�첽���Ӷ���
 */
typedef struct _navi_async_conn_s
{
	void* driver;	/*!< �������Ӧʵ�壬���ΪNULL������������Ҫ��������*/
	void (*driver_close_handler)(struct _navi_async_conn_s*);	/*!< �������Ӧʵ��Ļ��պ��� */
	void (*driver_set_idle_handler)(struct _navi_async_conn_s*, int);
	void (*driver_quit_idle_handler)(struct _navi_async_conn_s*);
	void (*driver_process_handler)(struct _navi_async_conn_s*);

	void* app;	/*!< Ӧ�ò����ݷ����ߣ��������ݶ�ȡ��*/

	void (*app_unbind_handler)(void*);

	/*!< parse_in_handler�ص���������������������ʱ����
	 * 	����0����ʾ�����ȴ����ݡ�
	 * 	����1����ʾ��ȡ�������������������ݵĶ��롣
	 * 	����-1����ʾЭ�����������Ҫ�Ͽ���
	 */
	int (*app_input_handler)(void* app, const unsigned char* content, size_t size);

	/*!< output_goon�ص��������������ڷ�����һ������ʱ������ϴε���output_goon
	 * ����ֵ��0����ô�ٴε���output_goon����������ϴη���Ϊ1��������Ϻ󣬲��ٽ���
	 * ���͵ļ�顣
	 * �������Ϊ�գ���ôֻ�Ƿ���out_bufһ�Ρ�
	 * �������ֵΪ1�����ʾ��ǰout_buf�����������Ҫ���͵����ݡ�
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
			 * 0x01 �У����һ���
			 * 0x02 �У�ֻ����Щ
			 * 0x03 �Ѿ�����
			 */
			unsigned int app_write_status:2;
			int has_output:1;

			/*!< \var app_reading_status
			 *	0x00 ����Ҫ��
			 *	0x01 ��Ҫ������û�ж���
			 *	0x02 �Ѿ����꣬Ҫ�������С�
			 *	0x03 Э���������
			 */
			unsigned int app_reading_status:2;
			int idle:1;
			int ready:1;
			int err:1;
			int zombie:1;
		};
	};

	int used_cnt;	/*!< ��ʹ�õĴ���*/
} navi_aconn_t;

/**************************************************
 * ... �첽���ӵ�ʹ���ߵ��õĽӿڲ���
 **************************************************/

/*!< parse_in_handler�ص���������������������ʱ����
 * 	����0����ʾ�����ȴ����ݡ�
 * 	����1����ʾ��ȡ�������������������ݵĶ��롣
 * 	����-1����ʾЭ�����������Ҫ�Ͽ���
 */
typedef int (*nvacnn_parse_in_fp)(void* app, const unsigned char* content, size_t size);

/*!< output_goon�ص��������������ڷ�����һ������ʱ������ϴε���output_goon
 * ����ֵ��0����ô�ٴε���output_goon����������ϴη���Ϊ1��������Ϻ󣬲��ٽ���
 * ���͵ļ�顣
 * �������Ϊ�գ���ôֻ�Ƿ���out_bufһ�Ρ�
 * �������ֵΪ1�����ʾ��ǰout_buf�����������Ҫ���͵����ݡ�
 */
typedef int (*nvacnn_output_goon_fp)(void* app);

/*!
 * \fn	navi_aconn_t* nvacnn_get_conn(const struct sockaddr* peer, void* app);
 * \brief	���һ���µ�tcp���ӣ����ߴ����ӳ���ȡ����
 * \param peer	�Զ˵�ַ
 * \param app	�����ϳ��ص��ϲ����
 */
typedef void (*nvacnn_app_unbind_fp)(void* app);
navi_aconn_t* nvacnn_get_conn(const struct sockaddr* peer, void* app,
	nvacnn_app_unbind_fp unbind_handler, int conn_timeout_ms);

/*!	\fn	void nvacnn_set_short(bool short_conn);
 * 	\brief	���ö����ӻ��߳����ӡ�Ĭ���ǳ����ӡ�
 * 		������û������Ҫ��������Ҳ����������뵽��ʱ���������Ϊ�����ӣ������ӹرա�
 */
void nvacnn_set_short(navi_aconn_t* cnn, bool short_conn);

/*! \fn  bool nvacnn_is_idle(navi_aconn_t* conn);
 *	\brief	��������Ƿ���idle�ġ�������û������Ҫ��������Ҳ����������뵽��ʱ��idle�ġ�
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
	\brief	������ݡ����goonΪ�գ���ʾ���������������ǿգ���ʾ�첽������ɺ���Ҫ�������͡�
	\param conn
	\param content	����
	\param size	���ݴ�С
	\param goon	����˴����ݷ�����Ϻ󣬻���������Ҫ���ͣ���ô����goon handler
*/
void nvacnn_write(navi_aconn_t* conn, const unsigned char* content, size_t size,
	nvacnn_output_goon_fp goon, bool pre);

/*! \fn void nvacnn_sendfile(navi_aconn_t* conn, int fd, size_t pos, nvacnn_output_goon_fp goon, bool pre);
	\brief	����ļ����ݡ����goonΪ�գ���ʾ���������������ǿգ���ʾ�첽������ɺ���Ҫ�������͡�
	\param conn
	\param fd	�򿪵��ļ����
	\param pos	���͵��ļ���ʼλ��
	\param goon	����˴����ݷ�����Ϻ󣬻���������Ҫ���ͣ���ô����goon handler
*/
void nvacnn_sendfile(navi_aconn_t* conn, int fd, size_t pos,size_t size, nvacnn_output_goon_fp goon, bool pre);


/*! \fn void nvacnn_set_reading(navi_aconn_t* conn, nvacnn_parse_in_fp handler);
 * 	\brief	��ʾ��ʼ�ȴ����롣�����޸�����Ĵ���handler
 * 	\param conn
 * 	\param handler
 *
 */
void nvacnn_set_reading(navi_aconn_t* conn, nvacnn_parse_in_fp handler);

/*!	\fn void nvacnn_close(navi_aconn_t* conn);
 *	\brief	Ӧ�ò�ر����ӡ�
 */
void nvacnn_close(navi_aconn_t* conn);

typedef struct _navi_peer_aconn_pool_s
{
	chain_node_t idles; //!< ����idle״̬��navi_async_conn_t
	int cur_idle_count;
	int idle_pool_size;	//!< ���ӳ����idle������
	int idle_timeout; //!< ���Ӵ���IDLE��ʱ�ޣ�����ʱ����ر�
	int	conn_used_limit; //!< ���ӱ�ʹ�õĴ������ƣ�����������ر�
} navi_peer_aconn_pool_t;

typedef struct _navi_aconn_pool_mgr_s
{
	int idle_total_limit;	//!< ȫ�����idle������������������ƣ��򰴳��������������peer�����ӳ��е����ӡ�
	int idle_total; 	//!< ��ǰ���ӳ����������
	navi_hash_t* peer_idle_idx; //!< key�ǵ�ַ���ַ�����ʾ��value��navi_peer_aconn_pool_t

} nvacnn_pool_mgr_t;

/*!	\fn	void nvacnn_set_peer_pool(const struct sockaddr* peer, int idle_pool_size,
		int idle_timeout_ms, int conn_used_max);
	\brief	����ĳ���Զ˵����ӳز���
 *	\param peer	�Զ˵�ַ
 *	\param idle_pool_size	���ӳش�С������Ϊ0����ʾȫ��ʹ�ö����ӣ���������֮ǰ�Ѿ����ڵ�idle���ӡ�
 *	\param idle_timeout_ms	��idle״̬�����ӵ����ʱ�������Ϊ0����ʾ����һֱ����
 *	\param conn_used_max	��ʾ���ӱ�ʹ�õ����ޡ���������ʱ������idleʱ���ᱻ�رա�
 */
void nvacnn_set_peer_pool(const struct sockaddr* peer, int idle_pool_size,
	int idle_timeout_ms, int conn_used_max);
void nvacnn_set_global_pool(int max_idle_conn);

void nvacnn_add_idle(navi_aconn_t* idle);
navi_aconn_t* nvacnn_get_idle(const struct sockaddr* peer);
void nvacnn_check_global_pool();
void nvacnn_clean_global_pool();

/************************
 *  ... ��������õĽӿ�
 ************************/

/*!	\fn void nvacnn_input_arrive(navi_aconn_t* conn, const unsigned char* in, size_t size);
 *	\brief	�������ȡ������ʱ�����øú�����
 */
void nvacnn_input_arrive(navi_aconn_t* conn, const unsigned char* in, size_t size);

/*! \fn void nvacnn_output_gone(navi_aconn_t* conn);
 *	\brief �������ڷ����굱ǰ���ݺ󣬵��øú�����
 */
void nvacnn_output_gone(navi_aconn_t* conn);

/*! \fn void nvacnn_has_problem(navi_aconn_t* conn, nvacnn_error_e e);
 * 	\brief	�������ڷ�������������ʱ�����øú�����
 */
void nvacnn_has_problem(navi_aconn_t* conn, nvcli_error_e e);

void nvacnn_idle_timedout(navi_aconn_t* conn);

typedef void* (*nvacnn_driver_install_fp)(navi_aconn_t* conn);
typedef void (*nvacnn_driver_close_fp)(navi_aconn_t* conn);
typedef void (*nvacnn_driver_set_idle_fp)(navi_aconn_t* conn, int idle_timeout_ms);
typedef void (*nvacnn_driver_quit_idle_fp)(navi_aconn_t* conn);
typedef void (*nvacnn_driver_process_fp)(navi_aconn_t* conn);

/*!< \fn void nvacnn_set_driver(navi_aconn_t* conn, void* driver, nvacnn_driver_close_fp closer);
 *	\brief	�����㴴���µ����Ӻ�navi_aconn_t��ʱ��ʹ�øú�����
 *	\param conn
 *	\param driver ���������������ʵ��
 *	\param process ����������Ķ�navi_aconn_t���д���Ļص���������Ҫ�Ǹ���navi_aconn_t����Ϣ���ж�д�¼��İ���
 *	\param closer  ���������������ʵ��رյĻص�������
 *	\param set_idle	�������������navi_aconn_t idleʱ�Ĵ���ص�
 *	\param quit_idle �������������navi_aconn_t��idle pool��ȡ��ʱ�Ĵ���ص�
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
