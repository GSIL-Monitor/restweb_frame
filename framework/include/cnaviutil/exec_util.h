/** \brief 
 * exec_util.h
 *  Created on: 2015-3-17
 *      Author: zoudaobing
 *  brief: �ṩ�Զ����������� �ӽ����Լ��������쳣����ʱ���ӽ��̷����źŵĹ���
              �����ӽ����˳���״̬������Ӧ�Ļص�����
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
 * \brief ׼��һ�������г���
 *	\param program �������ƣ�����·���ͳ������ƾ���
 *	\param run_directory �ӽ�������Ŀ¼
 *	\param parent_quit_signal ��ʾ�������˳�ʱ�����������е��ӽ��̵��źš�Ϊ0ʱ��ʹ��Ĭ��ֵSIG_TERM
 *	\param context �ӽ��̹����ĵ��÷���Ӧ���ﾳ
 *	\param success_proc �ӽ�����������ʱ�Ļص����ص����ý����󣬵��÷��ٷ���navi_exec_mon_t����ǷǷ���
 *	\param failed_proc �ӽ����쳣����ʱ�Ļص����ص������󣬵��÷��ٷ���navi_exec_mon_t����Ƿ�
 */
navi_exec_mon_t* navi_exec_prepare(const char* program, const char* run_directory, bool occupy_dir,
		bool output_collect,
		int parent_quit_signal, void* context, exec_event_handler_fp success_proc,
		exec_event_handler_fp failed_proc);

typedef enum exec_opt_type_E
{
	EXEC_OPT_SHORT, //��׼������ѡ�� �����ۺţ����ַ�ѡ��
	EXEC_OPT_LONG, //��׼������ѡ�� ˫���ۺţ����ַ���ѡ��
	EXEC_OPT_LONG_SINGLE_DASH,	//�ǳ��浥���ۺų�ѡ��
	EXEC_OPT_ASIS	//�������ָ(�����и���ѡ��ǰ׺)������ѡ��
}exec_opt_type_e;

/*!
 * \brief Ϊ������׼��ѡ� �����õ�˳��ѡ����ֵ�˳��
 * 	\param type ѡ������
 * 	\param optname ѡ������
 * 	\param optvalue ����Ϊ�ա�ѡ��ֵ��������format�ַ���
 * 	\param ... �ɱ�������֣����optvalue�Ǹ�ʽ���������пɱ����
 */
int navi_exec_append_option(navi_exec_mon_t* mon, exec_opt_type_e type, const char* optname,
		const char* optvalue, ...);

/*!
 * \brief Ϊ������ָ�����ݡ������õ�˳�����ݳ��ֵ�˳��
 *  \param count ��������
 * 	\param ... �ɱ�����б�
 */
int navi_exec_append_arguments(navi_exec_mon_t* mon, int count, ...);

int navi_exec_append_argument(navi_exec_mon_t* mon, const char* fmt, ...);

int navi_exec_run(navi_exec_mon_t *e);

bool navi_exec_running(navi_exec_mon_t* e);

/*!
 * \brief ȡ���ӽ��̡����÷�����֮����ʹ��e����ǷǷ��ġ�
 * \param e
 * \param kill_signal kill���̵��źš�Ϊ0ʱ��Ĭ��ʹ��SIGTERM
 *
 */
void navi_exec_abort(navi_exec_mon_t* e, int kill_signal);

//int exec_kill(navi_exec_mon_t *e, int kill_signal);

//�����Ǹ��ڲ��������õĽӿ�

typedef void * (*exec_mon_install_fp)(navi_exec_mon_t *e);

void navi_exec_mon_set(exec_mon_install_fp einstall);
void navi_exec_child_output(navi_exec_mon_t* e, const unsigned char* content,size_t sz);
void navi_exec_child_dead(navi_exec_mon_t *e);

#ifdef __cplusplus
}
#endif

#endif
