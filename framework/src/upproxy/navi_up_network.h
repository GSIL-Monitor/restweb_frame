/*
 * navi_up_network.h
 *
 *  Created on: 2014-01-26
 *      Author: yanguotao@youku.com
 */

#ifndef NAVI_UPS_NETWORK_H_
#define NAVI_UPS_NETWORK_H_

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_SOCK_BUF 8*1024
#define DEFAULT_TIMEOUT 200

int navi_up_socket_create(const struct sockaddr *sa);

int navi_up_send(int sock_fd, char* buf, int len);

int navi_up_recv(int sock_fd, char* buf, int len);

void navi_up_socket_close(int sock_fd);
#endif

