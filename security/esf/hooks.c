#include "hooks/process.h"
#include "hooks/file.h"

#include "hooks.h"
#include "esf.h"
#include "log.h"

static int _esf_bprm_check_security(struct linux_binprm *bprm)
{
	return esf_on_process_exec(current, bprm);
}

static struct security_hook_list _esf_hooks[] __ro_after_init = {
	/* process hooks */
	LSM_HOOK_INIT(bprm_check_security, _esf_bprm_check_security),
	// todo: find a better place for this event (maybe with probe on do_exit)
	LSM_HOOK_INIT(task_free, esf_on_process_exited),
	LSM_HOOK_INIT(task_kill, esf_on_process_kill),
	LSM_HOOK_INIT(ptrace_access_check, esf_on_process_ptrace),

	/* file hooks */
	LSM_HOOK_INIT(inode_permission, esf_on_check_inode_permission),
	LSM_HOOK_INIT(file_open, esf_on_file_open),
	LSM_HOOK_INIT(file_truncate, esf_on_file_truncate),

	/* fs hooks */
	// todo: implement

	/* net hooks */
	// todo: implement

	/* dev hooks */
	// todo: implement

	/* kern hooks */
	// todo: implement
};

void __init esf_hooks_init(void)
{
	esf_log_info("Initializing hooks");
	security_add_hooks(_esf_hooks, ARRAY_SIZE(_esf_hooks), "esf");
}