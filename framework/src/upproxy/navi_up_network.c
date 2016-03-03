/*
 * navi_up_network.c
 *
 *  Created on: 2014-01-26
 *      Author: yanguotao@youku.com
 */
#include "navi_up_network.h"

int navi_up_socket_create(const struct sockaddr *sa)
{
	int set = 1;
	int sock_buf_len= DEFAULT_SOCK_BUF;
	struct timeval timeout;  
	int sock_fd = socket(sa->sa_family, SOCK_STREAM, 0);
	if (sock_fd < 0){
		return -1;
	}

	timeout.tv_sec = 0;
	timeout.tv_usec = DEFAULT_TIMEOUT*1000;
	if (sa->sa_family != AF_UNIX) {
		if (setsockopt(sock_fd,SOL_SOCKET,SO_REUSEADDR,(void*)&set,sizeof(set)) == -1 ||
				setsockopt(sock_fd,IPPROTO_TCP,TCP_NODELAY, (void *)&set, sizeof(set)) == -1 ||
				setsockopt(sock_fd,SOL_SOCKET,SO_RCVBUF,(void*)&sock_buf_len,sizeof(int)) == -1 ||
				setsockopt(sock_fd,SOL_SOCKET,SO_SNDBUF,(void*)&sock_buf_len,sizeof(int)) == -1 ||
				setsockopt(sock_fd,SOL_SOCKET,SO_RCVTIMEO,(void*)&timeout,sizeof(timeout)) == -1 ||
				setsockopt(sock_fd,SOL_SOCKET,SO_SNDTIMEO,(void*)&timeout,sizeof(timeout)) == -1){
			close(sock_fd);
			return -1;
		}
	}
	else {
		if(setsockopt(sock_fd,SOL_SOCKET,SO_RCVBUF,(void*)&sock_buf_len,sizeof(int)) == -1 ||
				setsockopt(sock_fd,SOL_SOCKET,SO_SNDBUF,(void*)&sock_buf_len,sizeof(int)) == -1 ||
				setsockopt(sock_fd,SOL_SOCKET,SO_RCVTIMEO,(void*)&timeout,sizeof(timeout)) == -1 ||
				setsockopt(sock_fd,SOL_SOCKET,SO_SNDTIMEO,(void*)&timeout,sizeof(timeout)) == -1){
			close(sock_fd);
			return -1;
		}
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
		close(sock_fd);
		return -1;
	}

	return sock_fd;
}

int navi_up_send(int sock_fd, char* buf, int len)
{
	int sent=0, rc;
	
	while (sent < len){
		rc = send(sock_fd, buf+sent, len-sent,0);
		if (rc >0){
			sent += rc;
		}
		else {
			return -1;
		}
	}

	return sent;	
}

int navi_up_recv(int sock_fd, char* buf, int len)
{
	int rc;
	rc = recv(sock_fd, buf, len, 0);

	return rc;
}

void navi_up_socket_close(int sock_fd)
{
	if (sock_fd > 0){
		close(sock_fd);
	}
}

