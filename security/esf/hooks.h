#ifndef __LINUX_ESF_HOOKS_H
#define __LINUX_ESF_HOOKS_H

#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>

void __init esf_hooks_init(void);

#endif /* __LINUX_ESF_HOOKS_H */
