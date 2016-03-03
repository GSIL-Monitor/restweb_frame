/** \brief 
 * exec_util.h
 *  Created on: 2015-3-17
 *      Author: zoudaobing
 *  brief: 提供自动重启结束的 子进程以及父进程异常结束时向子进程发送信号的功能
              根据子进程退出的状态调用相应的回调函数
 */

#ifndef _EXEC_UTIL_H_
#define _EXEC_UTIL_H_

#ifdef __cplusplus
extern "C"{
#endif

#include "navi_pool.h"
#include "navi_simple_array.h"
#include "navi_buf_chain.h"
#include <signal.h>

typedef struct navi_exec_mon_s {
	char                   *cmd_human;
	char                   *program;
	char                   *directory;
	navi_array_t           *args;
    pid_t                   pid;
    pid_t                  *save_pid;
    int                     pipefd;
	void                   *driver;
    int                     parent_quit_signal;
	int                     status;
	navi_buf_chain_t*       child_output_buf;
	int                    (*exit_success)(struct navi_exec_mon_s* cmd, void*, int,
								const unsigned char*,size_t);
	int                    (*exit_abnormal)(struct navi_exec_mon_s* cmd, void*, int,
								const unsigned char*,size_t);
	void                   *ctx;
	unsigned				occupy_dir:1;
	unsigned				output_collect:1;
	unsigned                active:1;
	unsigned                stick:1;
	unsigned                zombie:1;
	unsigned                aborted:1;
	navi_pool_t             pool[0];
} navi_exec_mon_t;

typedef int (*exec_event_handler_fp)(navi_exec_mon_t *cmd, void* context, int status,
	const unsigned char* child_out, size_t sz);

/*!
 * \brief 准备一个命令行陈旭
 *	\param program 程序名称，绝对路径和程序名称均可
 *	\param run_directory 子进程运行目录
 *	\param parent_quit_signal 表示本进程退出时，给还在运行的子进程的信号。为0时，使用默认值SIG_TERM
 *	\param context 子进程关联的调用方的应用语境
 *	\param success_proc 子进程正常结束时的回调。回调调用结束后，调用方再访问navi_exec_mon_t句柄是非法的
 *	\param failed_proc 子进程异常结束时的回调。回调结束后，调用方再访问navi_exec_mon_t句柄非法
 */
navi_exec_mon_t* navi_exec_prepare(const char* program, const char* run_directory, bool occupy_dir,
		bool output_collect,
		int parent_quit_signal, void* context, exec_event_handler_fp success_proc,
		exec_event_handler_fp failed_proc);

typedef enum exec_opt_type_E
{
	EXEC_OPT_SHORT, //标准命令行选项 单破折号，单字符选项
	EXEC_OPT_LONG, //标准命令行选项 双破折号，多字符长选项
	EXEC_OPT_LONG_SINGLE_DASH,	//非常规单破折号长选项
	EXEC_OPT_ASIS	//如参数所指(参数中给出选项前缀)，给出选项
}exec_opt_type_e;

/*!
 * \brief 为命令行准备选项。 被调用的顺序即选项出现的顺序
 * 	\param type 选项类型
 * 	\param optname 选项名称
 * 	\param optvalue 可以为空。选项值。可以是format字符串
 * 	\param ... 可变参数部分，如果optvalue是格式串，可以有可变参数
 */
int navi_exec_append_option(navi_exec_mon_t* mon, exec_opt_type_e type, const char* optname,
		const char* optvalue, ...);

/*!
 * \brief 为命令行指定内容。被调用的顺序即内容出现的顺序
 *  \param count 参数个数
 * 	\param ... 可变参数列表。
 */
int navi_exec_append_arguments(navi_exec_mon_t* mon, int count, ...);

int navi_exec_append_argument(navi_exec_mon_t* mon, const char* fmt, ...);

int navi_exec_run(navi_exec_mon_t *e);

bool navi_exec_running(navi_exec_mon_t* e);

/*!
 * \brief 取消子进程。调用方调用之后，再使用e句柄是非法的。
 * \param e
 * \param kill_signal kill进程的信号。为0时，默认使用SIGTERM
 *
 */
void navi_exec_abort(navi_exec_mon_t* e, int kill_signal);

//int exec_kill(navi_exec_mon_t *e, int kill_signal);

//下面是给内部驱动调用的接口

typedef void * (*exec_mon_install_fp)(navi_exec_mon_t *e);

void navi_exec_mon_set(exec_mon_install_fp einstall);
void navi_exec_child_output(navi_exec_mon_t* e, const unsigned char* content,size_t sz);
void navi_exec_child_dead(navi_exec_mon_t *e);

#ifdef __cplusplus
}
#endif

#endif
