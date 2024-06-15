#ifndef __LINUX_ESF_HOOKS_PROCESS_H
#define __LINUX_ESF_HOOKS_PROCESS_H

#include <linux/sched.h>
#include <linux/binfmts.h>
#include <linux/uuid.h>

int esf_on_process_ptrace(struct task_struct *p, unsigned int mode);

int esf_on_process_kill(struct task_struct *p, struct kernel_siginfo *info,
			int sig, const struct cred *cred);

int esf_on_process_exec(struct task_struct *task, struct linux_binprm *bprm);

void esf_on_process_exited(struct task_struct *task);

#endif //__LINUX_ESF_HOOKS_PROCESS_H