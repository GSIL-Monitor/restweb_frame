/** \brief 
 * exec_util.c
 *  Created on: 2015-3-17
 *      Author: zoudaobing
 *  brief: 提供自动重启结束的 子进程以及父进程异常结束时向子进程发送信号的功能
 */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/prctl.h>

#include "exec_util.h"
#include "../cnavi/navi_common_define.h"
#include "../navi_frame_log.h"

static exec_mon_install_fp s_einstall;

static void exec_mon_cleanup(navi_exec_mon_t* mon)
{
	if (mon->zombie) {
		if (mon->stick)
			return;
		else {
			navi_pool_destroy(mon->pool);
		}
	}

	mon->zombie = 1;
	if (mon->stick) {
		return;
	}
	else {
		navi_pool_destroy(mon->pool);
	}
}

void navi_exec_mon_set(exec_mon_install_fp einstall)
{
	s_einstall = einstall;
}

void navi_exec_child_output(navi_exec_mon_t* e, const unsigned char* content,size_t sz)
{
	if (sz == 0 || content == NULL)
		return;
	if (e->child_output_buf==NULL)
		e->child_output_buf = navi_buf_chain_init(e->pool);

	navi_buf_chain_append(e->child_output_buf, content, sz);
	return;
}

void
navi_exec_child_dead(navi_exec_mon_t *e)
{
	NAVI_FRAME_LOG(NAVI_LOG_INFO, "exec: child '%s'[%u] exited with %d", e->cmd_human,e->pid, e->status);

	int status = e->status;
	e->active = 0;

	unsigned char* tmp_buf = NULL;
	size_t buf_sz = 0;
	if ( e->child_output_buf ) {
		buf_sz = navi_buf_chain_get_content(e->child_output_buf, NULL, 0);
		if (buf_sz > 0 ) {
			tmp_buf = navi_pool_nalloc(e->pool, buf_sz+1);
			navi_buf_chain_get_content(e->child_output_buf, tmp_buf, buf_sz);
			tmp_buf[buf_sz] = 0;
		}
	}

	if (!status) {
		NAVI_FRAME_LOG(NAVI_LOG_DEBUG, "exec: child '%s'[%u] exited with 0", e->cmd_human, e->pid);
		e->stick = 1;
		if (e->exit_success) {
			e->exit_success(e, e->ctx, status, tmp_buf, buf_sz);
			e->exit_success = NULL;
		}

		e->stick = 0;
		exec_mon_cleanup(e);
		return;
	}
	else {
		if (WIFEXITED(status)) {
			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "exec: child '%s'[%u] exited with %d",
					e->cmd_human, e->pid, WEXITSTATUS(status));
		}
		else if (WIFSIGNALED(status)){
			NAVI_FRAME_LOG(NAVI_LOG_WARNING, "exec: child '%s'[%u] exited with signal %d",
					e->cmd_human, e->pid, WTERMSIG(status));
		}
	}

	e->stick = 1;

	if ( e->exit_abnormal) {
		e->exit_abnormal(e, e->ctx, status, tmp_buf, buf_sz);
		e->exit_abnormal = NULL;
	}
	e->stick = 0;
	exec_mon_cleanup(e);
	return;
}

bool navi_exec_running(navi_exec_mon_t* e)
{
	if (e->active==0)
		return false;

	if (kill(e->pid, 0)==0)
		return true;

	return false;
}

void navi_exec_abort(navi_exec_mon_t* e, int kill_sig)
{
	if (kill_sig==0)
		kill_sig = SIGTERM;

	if (e->zombie == 1 || e->active == 0) {
		e->stick = 0;
		exec_mon_cleanup(e);
		return;
	}

	e->exit_abnormal = NULL;
	e->exit_success = NULL;
	e->aborted = 1;

	if (kill(e->pid,0) == 0) {
		kill(e->pid, kill_sig);
		return;
	}
}

int navi_exec_run(navi_exec_mon_t *e)
{
	int 					fd, ret, maxfd, pipefd[2];
	pid_t				    pid;

	if (!e || e->zombie)
		return -1;

	if (e->active) {
		NAVI_FRAME_LOG(NAVI_LOG_DEBUG, "exec: already active '%s'", e->cmd_human);
		return NAVI_OK;
	}

	size_t cmd_len = strlen(e->program);
	if (e->args) {
		void* it = navi_array_iter(e->args);
		char** arg;
		while ( (arg = (char**)navi_array_iter_next(it))) {
			cmd_len++;
			cmd_len += strlen(*arg);
		}
		navi_array_iter_destroy(it);
	}

	e->cmd_human = navi_pool_alloc(e->pool,cmd_len+1);
	char* p = e->cmd_human;
	memcpy(p, e->program, strlen(e->program));
	p += strlen(e->program);

	char** exec_argv = navi_pool_calloc(e->pool, 2 + navi_array_size(e->args), sizeof(char*));
	exec_argv[0] = e->program;
	int i = 1;

	if (e->args) {
		void* it = navi_array_iter(e->args);
		char** arg;
		while ( (arg = (char**)navi_array_iter_next(it))) {
			*(p++) = ' ';
			memcpy(p, *arg, strlen(*arg));
			p += strlen(*arg);
			exec_argv[i] = *arg;
			i++;
		}
		navi_array_iter_destroy(it);
	}

	exec_argv[i] = NULL;
	*p = '\0';

	NAVI_FRAME_LOG(NAVI_LOG_INFO, "exec: starting child '%s'", e->cmd_human);

	pipefd[0] = -1;
	pipefd[1] = -1;

	if (pipe(pipefd) == -1) {
		NAVI_FRAME_LOG(NAVI_LOG_ERR, "exec: pipe failed '%s'", e->cmd_human);
		exec_mon_cleanup(e);
		return NAVI_FAILED;
	}

	/* make pipe write end survive through exec */

	ret = fcntl(pipefd[1], F_GETFD);

	if (ret != -1) {
		ret &= ~FD_CLOEXEC;
		ret = fcntl(pipefd[1], F_SETFD, ret);
	}

	if (ret == -1) {

		close(pipefd[0]);
		close(pipefd[1]);

		NAVI_FRAME_LOG(NAVI_LOG_ERR, "exec: fcntl failed.'%s'", e->cmd_human);
		exec_mon_cleanup(e);
		return NAVI_FAILED;
	}

	pid = fork();

	switch (pid) {

		case -1:

			/* failure */

			if (pipefd[0] != -1) {
				close(pipefd[0]);
			}

			if (pipefd[1] != -1) {
				close(pipefd[1]);
			}

			NAVI_FRAME_LOG(NAVI_LOG_ERR, "exec: fork failed '%s'", e->cmd_human);
			exec_mon_cleanup(e);
			return NAVI_FAILED;

		case 0:

			/* child */

			prctl(PR_SET_PDEATHSIG, e->parent_quit_signal, 0, 0, 0);

			/* close all descriptors but pipe write end */

			maxfd = sysconf(_SC_OPEN_MAX);
			for (fd = 0; fd < maxfd; ++fd) {
				if (fd == pipefd[1]) {
					continue;
				}
				close(fd);
			}

			int nil_fd = open("/dev/null", O_RDWR);
			dup2(nil_fd, STDIN_FILENO);
			dup2(pipefd[1], STDOUT_FILENO);
			dup2(pipefd[1], STDERR_FILENO);

			if (e->directory &&  -1 == chdir(e->directory) ) {
				char	*msg;
				msg = strerror(errno);
				write(STDERR_FILENO, "change cwd failed: ", strlen("change cwd failed: "));
				write(STDERR_FILENO, msg, strlen(msg));
				write(STDERR_FILENO, "\n", 1);
				exit(3);
			}

			if (e->occupy_dir) {
				fd = open("occpy.lock", O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR);
				if (fd == -1) {
					char	*msg;
					msg = strerror(errno);
					write(STDERR_FILENO, "occpy run dir failed:", strlen("occpy run dir failed:"));
					write(STDERR_FILENO, msg, strlen(msg));
					exit(4);
				}

				int ret = fcntl(fd, F_GETFD);

				if (ret != -1) {
					ret &= ~FD_CLOEXEC;
					ret = fcntl(fd, F_SETFD, ret);
				}
				else {
					char	*msg;
					msg = strerror(errno);
					write(STDERR_FILENO, "occpy run dir failed:", strlen("occpy run dir failed:"));
					write(STDERR_FILENO, msg, strlen(msg));
					exit(4);
				}

				struct flock lk;
				lk.l_type = F_WRLCK;
				lk.l_start = 0;
				lk.l_whence = SEEK_SET;
				lk.l_len = 0;
				lk.l_pid = 0;

				if ( 0 > fcntl(fd, F_GETLK,&lk) ) {
					char	*msg;
					msg = strerror(errno);
					write(STDERR_FILENO, "occpy run dir failed:", strlen("occpy run dir failed:"));
					write(STDERR_FILENO, msg, strlen(msg));
					exit(4);
				}

				if ( lk.l_type == F_UNLCK ) {
					lk.l_type = F_WRLCK;
					int ret = fcntl(fd, F_SETLK, &lk);
					if (ret == 0) {
					}
					else if (ret == EAGAIN || errno == EAGAIN ) {
						write(STDERR_FILENO, "occpy run dir failed: already occpied by other process",
								strlen("occpy run dir failed: already occpied by other process"));
						exit(4);
					}
					else {
						char	*msg;
						msg = strerror(errno);
						write(STDERR_FILENO, "occpy run dir failed:", strlen("occpy run dir failed:"));
						write(STDERR_FILENO, msg, strlen(msg));
						exit(4);
					}
				}
				else {
					write(STDERR_FILENO, "occpy run dir failed: already occpied by other process",
						strlen("occpy run dir failed: already occpied by other process"));
					exit(4);
				}
			}

			if ( e->output_collect == 0 ) {
				dup2(nil_fd, STDOUT_FILENO);
				dup2(nil_fd, STDERR_FILENO);
			}

			if (execvp(e->program, exec_argv) == -1) {
				char	*msg;

				msg = strerror(errno);

				write(pipefd[1], "execvp error: ", 14);
				write(pipefd[1], msg, strlen(msg));
				write(pipefd[1], "\n", 1);

				exit(2);
			}

			break;

		default:

			/* parent */

			if (pipefd[1] != -1) {
				close(pipefd[1]);
			}

			if (pipefd[0] != -1) {

				e->active = 1;
				e->pid = pid;
				e->pipefd = pipefd[0];

				if (e->save_pid) {
					*e->save_pid = pid;
				}

				e->driver = s_einstall(e);
			}
			else {
				NAVI_FRAME_LOG(NAVI_LOG_ERR, "exec: parent error: pipefd[0] = -1");
			}

			NAVI_FRAME_LOG(NAVI_LOG_DEBUG, "exec: child '%s' started pid=%i", e->cmd_human,pid);
			break;
	}

	return NAVI_OK;
}

#define EXEC_MON_SIZE (sizeof(navi_exec_mon_t)+0x200)

navi_exec_mon_t* navi_exec_prepare(const char* program, const char* run_directory, bool occpy_dir,
		bool output_collect,
		int parent_quit_signal, void* context, exec_event_handler_fp success_proc,
		exec_event_handler_fp failed_proc)
{
	if ( !program || !strlen(program) || !run_directory || !strlen(run_directory))
		return NULL;

	navi_exec_mon_t* ret = (navi_exec_mon_t*)calloc(1,EXEC_MON_SIZE);
	navi_pool_init(ret->pool, ret, 0x200);

	ret->program = navi_pool_strdup(ret->pool, program);

	ret->parent_quit_signal = SIGTERM;
	if ( parent_quit_signal != 0 && parent_quit_signal <= SIGUSR2) {
		ret->parent_quit_signal = parent_quit_signal;
	}

	if (run_directory) {
		ret->directory = navi_pool_strdup(ret->pool, run_directory);
		ret->occupy_dir = occpy_dir?1:0;
	}

	ret->output_collect = output_collect?1:0;

	ret->ctx = context;
	ret->exit_success = success_proc;
	ret->exit_abnormal = failed_proc;
	return ret;
}

int navi_exec_append_option(navi_exec_mon_t* mon, exec_opt_type_e type, const char* optname,
		const char* optvalue, ...)
{
	size_t optname_len = 0;
	if (!mon || !optname || !(optname_len=strlen(optname)) )
		return -1;

	switch(type) {
	case EXEC_OPT_SHORT:
		if ( optname_len > 1)
			return -1;
		break;
	case EXEC_OPT_LONG:
		if ( optname_len == 1)
			return -1;
		break;
	}

	if ( mon->args == NULL) {
		mon->args = navi_array_create(mon->pool, 10, sizeof(char*));
	}

	char** parg = navi_array_push(mon->args);
	char* arg = NULL;
	switch(type) {
	case EXEC_OPT_SHORT:
	case EXEC_OPT_LONG_SINGLE_DASH:
		arg = navi_pool_alloc(mon->pool, optname_len+2);
		*parg = arg;
		*(arg++) = '-';
		break;
	case EXEC_OPT_LONG:
		arg = navi_pool_alloc(mon->pool, optname_len+3);
		*parg = arg;
		*(arg++) = '-';
		*(arg++) = '-';
		break;
	case EXEC_OPT_ASIS:
		arg = navi_pool_alloc(mon->pool, optname_len+1);
		*parg = arg;
		break;
	}
	memcpy(arg, optname, optname_len+1);

	if (optvalue == NULL)
		return 0;

	parg = navi_array_push(mon->args);

	char buf[1024];
	int arg_len;
	va_list vl;
	va_start(vl, optvalue);
	arg_len = vsnprintf(buf,sizeof(buf),optvalue, vl);
	arg = navi_pool_alloc(mon->pool, arg_len+1);
	*parg = arg;
	if (arg_len >= sizeof(buf) ) {
		vsprintf(arg, optvalue, vl);
	}
	else {
		memcpy(arg, buf, arg_len+1);
	}
	va_end(vl);
	return 0;
}

int navi_exec_append_arguments(navi_exec_mon_t* mon, int count,  ...)
{
	if ( !mon )
		return -1;
	va_list vl;
	char** parg;
	char* arg;
	va_start(vl,count);
	while(count--) {
		const char* v = va_arg(vl,const char*);
		if ( !v || !strlen(v) )
			continue;

		if ( mon->args == NULL)
			mon->args = navi_array_create(mon->pool, 10, sizeof(const char*));

		parg = navi_array_push(mon->args);
		arg = navi_pool_strdup(mon->pool, v);
		*parg = arg;
	}
	va_end(vl);
	return 0;
}

int navi_exec_append_argument(navi_exec_mon_t* mon, const char* fmt, ...)
{
	if (!mon)
		return -1;
	char tmp[256];
	char** parg;
	char* arg;

	if ( mon->args == NULL) {
		mon->args = navi_array_create(mon->pool, 10, sizeof(char*));
	}
	parg = (char**)navi_array_push(mon->args);

	va_list vl;
	va_start(vl,fmt);
	off_t off = vsnprintf(tmp,sizeof(tmp),fmt,vl);
	if ( off >= sizeof(tmp) ) {
		arg = (char*)navi_pool_alloc(mon->pool,off+1);
		vsprintf(arg, fmt, vl);
		*parg = arg;
	}
	else {
		arg = navi_pool_strdup(mon->pool, tmp);
		*parg = arg;
	}
	va_end(vl);
	return 0;
}
