#ifndef LINUX_ESF_H
#define LINUX_ESF_H

int esf_on_execve(struct task_struct *task, struct linux_binprm* bprm);

#endif //LINUX_ESF_H
