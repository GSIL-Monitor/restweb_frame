/*
 * navi_bsession.c
 *
 *  Created on: 2015年6月10日
 *      Author: li.lei
 */

#include "navi_bsession.h"
#include "navi_frame_log.h"
#include <fcntl.h>
#include <errno.h>
#include "navi_inner_util.h"
#include "navi_list.h"
#include "navi_simple_hash.h"

static chain_node_t s_cnn_pool_queue = {&s_cnn_pool_queue, &s_cnn_pool_queue};
static navi_hash_t* s_cnn_pool_hash = NULL;

typedef enum navi_bsession_stage_E {
	BSESSION_INIT,
	BSESSION_CONNECTED,
	BSESSION_REQUESTING,
	BSESSION_RESPONDING,
	BSESSION_COMPLETE,
	BSESSION_IDLE
} navi_bsession_stage_e;

typedef struct navi_bsession_s {
	int socket;
	struct timeval idle_tm;
	navi_bsession_stage_e stage;
	struct sockaddr_storage addr;
	char* addr_text;
	char recv_buf[4096];
	chain_node_t queue_link;
	navi_pool_t pool[0];
} navi_bsession_t;

static void clean_bss_idles()
{
	navi_bsession_check_idle(true);
}

void navi_bsession_util_init()
{
	atexit(clean_bss_idles);
}

static int64_t time_elapse(struct timeval* start, struct timeval* end)
{
    if (start->tv_usec <= end->tv_usec)
    {
    	return ((int64_t)(end->tv_sec - start->tv_sec)*1000 +
    			(end->tv_usec - start->tv_usec)/1000 );
    }
    else
    {
    	return ((int64_t)(end->tv_sec - start->tv_sec - 1)*1000 +
    			(1000000 - start->tv_usec + end->tv_usec)/1000 );
    }
}

static void ss_cleanup(navi_bsession_t* ss);
void navi_bsession_check_idle(bool closeall)
{
	if (s_cnn_pool_hash==NULL) return;
	if ( closeall ) {
		void *it = navi_hash_iter(s_cnn_pool_hash);
		navi_hent_t* he ;
		while ( (he = navi_hash_iter_next(it))) {
			ss_cleanup((navi_bsession_t*)he->v);
		}
		navi_hash_iter_destroy(it);
		navi_hash_destroy(s_cnn_pool_hash);
		s_cnn_pool_hash = NULL;
		return;
	}

	chain_node_t* lk = s_cnn_pool_queue.next;
	navi_bsession_t* obj = NULL;
	struct timeval tv;
	int cleancnt = 0;
	gettimeofday(&tv,NULL);
	while ( lk != &s_cnn_pool_queue ) {
		obj = (navi_bsession_t*)navi_list_data(lk, navi_bsession_t, queue_link);
		if ( time_elapse(&obj->idle_tm, &tv) < 60000 )
			break;
		lk = lk->next;
		navi_hash_del(s_cnn_pool_hash, obj->addr_text);
		ss_cleanup(obj);
		if (cleancnt++ >= 200) {
			break;
		}
	}
}

/*!
 * \brief 异步连接对端。
 * \param sa  对端地址
 * \param conn_toms  连接超时，毫秒
 * \retval >=0 连接fd  -1 其它错误  -2 连接超时 -3 连接失败
 */
static int conn_peer(const struct sockaddr* sa, int *conn_toms)
{
	int set = 1;
	int sock_buf_len= BSESSION_DEFAULT_SOCK_BUF;
	struct timeval timeout;
	int sock_fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (sock_fd < 0){
		NAVI_SYSERR_LOG("create socket");
		return -1;
	}

	if (sa->sa_family != AF_UNIX) {
		if (setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR,(void*)&set,sizeof(set)) == -1 ||
				setsockopt(sock_fd,IPPROTO_TCP,TCP_NODELAY, (void *)&set, sizeof(set)) == -1 ||
				setsockopt(sock_fd,SOL_SOCKET,SO_RCVBUF,(void*)&sock_buf_len,sizeof(int)) == -1 ||
				setsockopt(sock_fd,SOL_SOCKET,SO_SNDBUF,(void*)&sock_buf_len,sizeof(int)) == -1 ){
			close(sock_fd);
			NAVI_SYSERR_LOG("setsockopt");
			return -1;
		}
	}
	else {
		if(setsockopt(sock_fd,SOL_SOCKET,SO_RCVBUF,(void*)&sock_buf_len,sizeof(int)) == -1 ||
				setsockopt(sock_fd,SOL_SOCKET,SO_SNDBUF,(void*)&sock_buf_len,sizeof(int)) == -1){
			close(sock_fd);
			NAVI_SYSERR_LOG("setsockopt");
			return -1;
		}
	}

	int flag = fcntl(sock_fd, F_GETFL, 0);
	if (flag < 0) {
		NAVI_SYSERR_LOG("fcntl F_GETFL");
		close(sock_fd);
		return -1;
	}
	flag |= O_NONBLOCK;
	if ( 0 > fcntl(sock_fd, F_SETFL, flag) ) {
		NAVI_SYSERR_LOG("fnctl F_SETFL");
		close(sock_fd);
		return -1;
	}

	size_t addrsz = 0;
	switch(sa->sa_family){
	case AF_INET:
		addrsz = sizeof(struct sockaddr_in);
		break;
	case AF_INET6:
		addrsz = sizeof(struct sockaddr_in6);
		break;
	case AF_UNIX:
		addrsz = sizeof(struct sockaddr_un);
		break;
	}
	if (connect(sock_fd, (struct sockaddr *)sa, addrsz) != 0){
		if (errno != EINPROGRESS) {
			NAVI_SYSERR_LOG("connect");
			close(sock_fd);
			return -3;
		}
	}

	fd_set rset;
	fd_set wset;

	FD_SET(sock_fd, &rset);
	FD_SET(sock_fd, &wset);

	int _cnn_to = *conn_toms;
	if (_cnn_to <= 0)
		_cnn_to = BSESSION_DEFAULT_CONN_TIMEOUT;
	else if (_cnn_to >= 20000 )
		_cnn_to = 20000;

	struct timeval tv;
	tv.tv_sec = _cnn_to/1000;
	tv.tv_usec = (_cnn_to%1000)*1000;
	int sel_ret = select(sock_fd+1,&rset,&wset,NULL, &tv);
	if (sel_ret == 0) {
		close(sock_fd);
		return -2;
	}
	else if(sel_ret > 0) {
		if ( FD_ISSET(sock_fd,&rset) && FD_ISSET(sock_fd,&wset) ) {
			close(sock_fd);
			return -3;
		}
		else if (FD_ISSET(sock_fd, &wset) ) {
			*conn_toms = tv.tv_sec*1000 + tv.tv_usec/1000;
			if (*conn_toms==0)*conn_toms = 10;
			return sock_fd;
		}
	}
	else {
		close(sock_fd);
		NAVI_SYSERR_LOG("select");
		return -1;
	}

	return -1;
}

/*
 * \brief 发送请求
 * \retval -1 sys err
 * \retval >0 发送成功
 * \retval -2 超时
 * \retval -3 broken
 */
static int send_request(int fd, const uint8_t* raw, size_t sz, int *toms)
{
	int pos = 0, ret = -1;
	fd_set wset, eset, rset;
	struct timeval tv = {*toms/1000, ((*toms)%1000)*1000};
	do {
		//此处，send往tcp wbuf写数据，消耗时间认为为0.
		ret = send(fd, raw+pos, sz-pos, 0);
		if ( ret == -1 ) {
			if (errno == EAGAIN) {
				FD_SET(fd,&wset);
				FD_SET(fd,&eset);
				FD_SET(fd,&rset);

				ret = select(fd+1,&rset,&wset,&eset,&tv);
				if (ret == 0) {
					return -2;
				}
				else if (ret == 1) {
					if (FD_ISSET(fd, &rset) || FD_ISSET(fd,&eset)) {
						return -3;
					}
					else if (FD_ISSET(fd,&wset)) {
						continue;
					}
				}
				else {
					if (errno == EINTR) {
						continue;
					}
					else {
						NAVI_SYSERR_LOG("select");
						return -1;
					}
				}
			}
			else if (errno == EINTR) {
				continue;
			}
			else {
				NAVI_SYSERR_LOG("send_request");
				return -3;
			}
		}
		else if ( ret >= 0 ) {
			pos += ret;
			if ( pos >= sz) {
				*toms = tv.tv_sec*1000 + tv.tv_usec/1000;
				if (*toms == 0) *toms = 10;
				return sz;
			}
			else {
				continue;
			}
		}
	} while (1);
	return ret;
}

static int check_idle_conn(int fd)
{
	fd_set rset;
	fd_set eset;
	struct timeval tv = {0,0};
	FD_SET(fd, &rset);
	FD_SET(fd, &eset);
	int sel_ret = select(fd+1,&rset,NULL,&eset,&tv);
	if (sel_ret == 0) {
		return 0;
	}
	else {
		return -1;
	}
}

#define BSS_SIZE (sizeof(navi_bsession_t)+1024)
static navi_bsession_t* ss_create(const struct sockaddr* sa,int fd)
{
	if (!sa || fd==-1) return NULL;
	navi_bsession_t* obj = (navi_bsession_t*)calloc(1, BSS_SIZE);
	navi_pool_init(obj->pool, obj, 1024);
	switch(sa->sa_family) {
	case AF_INET:
		memcpy(&obj->addr, sa, sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		memcpy(&obj->addr, sa, sizeof(struct sockaddr_in6));
		break;
	case AF_UNIX:
		memcpy(&obj->addr, sa, sizeof(struct sockaddr_un));
		break;
	default:
		assert(0);
	}
	char tmp[256];
	navi_addr_to_str(sa, tmp);
	obj->addr_text = navi_pool_strdup(obj->pool, tmp);
	navi_list_init(&obj->queue_link);
	return obj;
}

static void ss_cleanup(navi_bsession_t* ss)
{
	if ( !ss) return;
	if (ss->socket!=-1) {
		close(ss->socket);
		ss->socket = -1;
	}
	navi_list_remove(&ss->queue_link);

	//if (ss->stage == BSESSION_IDLE) {
	//	navi_hash_del(s_cnn_pool_hash, ss->addr_text);
	//	navi_list_remove(&ss->queue_link);
	//}

	navi_pool_destroy(ss->pool);
}

static navi_bsession_t* get_recycle_ss(const struct sockaddr* sa)
{
	if (s_cnn_pool_hash == NULL) return NULL;
	char addr_text[256];
	navi_addr_to_str(sa, addr_text);
	navi_bsession_t* pe = (navi_bsession_t*)navi_hash_get_gr(s_cnn_pool_hash, addr_text);
	if (!pe) return NULL;
	if ( -1 == check_idle_conn(pe->socket) ) {
		ss_cleanup(pe);
		pe = NULL;
	}
	else {
		navi_list_remove(&pe->queue_link);
	}
	navi_hash_del(s_cnn_pool_hash, addr_text);
	return pe;
}

static void recycle_ss(navi_bsession_t* ss)
{
	ss->stage = BSESSION_IDLE;
	gettimeofday(&ss->idle_tm,NULL);
	navi_list_insert_tail(&s_cnn_pool_queue, &ss->queue_link);
	if (!s_cnn_pool_hash)s_cnn_pool_hash = navi_hash_init_with_heap();
	navi_hash_set_gr(s_cnn_pool_hash, ss->addr_text, ss);
}

static navi_bsession_t* navi_bsession_get(const struct sockaddr* sa, int* conn_toms, navi_bsession_code_e* err)
{
	navi_bsession_t* obj = get_recycle_ss(sa);
	if (obj) {
		obj->stage = BSESSION_CONNECTED;
		return obj;
	}
	int fd = conn_peer(sa, conn_toms);
	if (fd < 0 ) {
		if ( fd == -1 ) {
			if (err) *err = BSESSION_SYSERR;
		}
		else if (fd == -2) {
			if (err) *err = BSESSION_CONN_TIMEDOUT;
		}
		else if (fd == -3) {
			if (err) *err = BSESSION_CONN_FAILED;
		}
		return NULL;
	}

	obj = ss_create(sa, fd);
	obj->stage = BSESSION_CONNECTED;
	return obj;
}

static void navi_bsession_release(navi_bsession_t* ss)
{
	if (!ss) return;
	if ( ss->socket == -1 ) {
		ss_cleanup(ss);
		return;
	}
	if ( ss->stage != BSESSION_COMPLETE ) {
		ss_cleanup(ss);
	}
	else {
		if (0 == check_idle_conn(ss->socket)) {
			recycle_ss(ss);
		}
		else {
			ss_cleanup(ss);
		}
	}
}

navi_bsession_code_e navi_bsession_request(const struct sockaddr* sa,
		int session_toms,
		int keepalive,
		const uint8_t* req_raw, size_t len,
		bsession_resp_parser_fp parser, void* ctx)
{
	if (!sa || !req_raw || !len || !parser) return BSESSION_ABUSED;
	if (session_toms <= 0) {
		session_toms = 60000;
	}
	navi_bsession_code_e ret = BSESSION_OK;
	navi_bsession_t* obj = navi_bsession_get(sa, &session_toms, &ret);
	if (!obj) return ret;

	obj->stage = BSESSION_REQUESTING;
	int iret = send_request(obj->socket, req_raw, len , &session_toms);
	if (iret < 0) {
		ss_cleanup(obj);
		if (iret == -1) {
			return BSESSION_SYSERR;
		}
		else if (iret == -2) {
			return BSESSION_REQ_TIMEDOUT;
		}
		else if (iret == -3) {
			return BSESSION_BROKEN;
		}
	}

	obj->stage = BSESSION_RESPONDING;
	bool resp_waiting = true;
	struct timeval tv = {session_toms/1000, (session_toms%1000)*1000};
	do {
		fd_set rset;
		fd_set eset;
		FD_SET(obj->socket,&rset);
		FD_SET(obj->socket,&eset);

		if (resp_waiting == false) {
			//在有响应内容之后，后续每次可读最多等待500ms
			tv.tv_sec = 0;
			tv.tv_usec = 500000;
		}
		iret = select(obj->socket+1,&rset,NULL,&eset, &tv);

		if ( iret == 0) {
			ss_cleanup(obj);
			return BSESSION_RESP_TIMEDOUT;
		}
		else if (iret == -1) {
			if (errno == EINTR) {
				continue;
			}
			else {
				ss_cleanup(obj);
				NAVI_SYSERR_LOG("select");
				return BSESSION_SYSERR;
			}
		}
		else {
			if (FD_ISSET(obj->socket,&eset)) {
				ss_cleanup(obj);
				NAVI_SYSERR_LOG("socket in err set");
				return BSESSION_SYSERR;
			}
			else if (FD_ISSET(obj->socket,&rset)) {
				resp_waiting = false;
				do {
					iret = recv(obj->socket,obj->recv_buf,sizeof(obj->recv_buf),0);
					if (iret == 0) {
						ss_cleanup(obj);
						return BSESSION_BROKEN;
					}
					else if (iret < 0) {
						if (errno == EINTR) {
							continue; //to recv
						}
						else if (errno == EAGAIN || errno == EWOULDBLOCK) {
							break; //to select
						}
						else {
							ss_cleanup(obj);
							NAVI_SYSERR_LOG("recv");
							return BSESSION_BROKEN;
						}
					}
					else {
						iret = parser(ctx,obj->recv_buf, iret);
						if ( iret < 0 ) {
							ss_cleanup(obj);
							return BSESSION_PROTO_ERR;
						}
						else if ( iret == 0) {
							continue; //continue recv
						}
						else if ( iret == 1) {
							obj->stage = BSESSION_COMPLETE;
							if(keepalive) {
								navi_bsession_release(obj);
							}
							else {
								ss_cleanup(obj);
							}
							return BSESSION_OK;
						}
					}
				}while(1); //recv while
			}
		}
	}while(1); //select while
	return BSESSION_SYSERR;
}

