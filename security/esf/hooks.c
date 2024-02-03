#include "hooks.h"
#include "esf.h"
#include "log.h"

#include <linux/ipc_namespace.h>
#include <linux/mnt_namespace.h>
#include <net/net_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/time_namespace.h>
#include <linux/cgroup.h>
#include <linux/utsname.h>
#include <linux/mount.h>

void _fill_ns_from_task(esf_ns_info_t *ns, struct task_struct *task)
{
	ns->uts_ns = task->nsproxy->uts_ns->ns.inum;
	ns->ipc_ns = task->nsproxy->ipc_ns->ns.inum;
	ns->mnt_ns = from_mnt_ns(task->nsproxy->mnt_ns)->inum;
	ns->pid_ns_for_children = task->nsproxy->pid_ns_for_children->ns.inum;
	ns->net_ns = task->nsproxy->net_ns->ns.inum;
	ns->time_ns = task->nsproxy->time_ns->ns.inum;
	ns->time_ns_for_children = task->nsproxy->time_ns_for_children->ns.inum;
}

void _fill_creds_from_task(esf_creds_info_t *creds, struct task_struct *task)
{
	creds->uid = task_cred_xxx(task, uid).val;
	creds->euid = task_cred_xxx(task, euid).val;
	creds->suid = task_cred_xxx(task, suid).val;
	creds->fsuid = task_cred_xxx(task, fsuid).val;

	creds->gid = task_cred_xxx(task, gid).val;
	creds->egid = task_cred_xxx(task, egid).val;
	creds->sgid = task_cred_xxx(task, sgid).val;
	creds->fsgid = task_cred_xxx(task, fsgid).val;
}

typedef struct fill_task_info {
	struct task_struct *task;
	struct mm_struct *mm;
	char *__will_be_moved argp;
	size_t arg_len;
	char *__will_be_moved envp;
	size_t env_len;
	char *__will_be_moved filename;
	size_t filename_len;
} fill_task_info_t;

void _fill_process_from_task_info(esf_raw_event_t *raw_event,
				  esf_process_info_t *process,
				  fill_task_info_t *task_fill_info, gfp_t gfp)
{
	BUG_ON(!task_fill_info);
	BUG_ON(!task_fill_info->task);

	get_task_struct(task_fill_info->task);

	struct mm_struct *mm = NULL;

	if (task_fill_info->mm) {
		mmget(task_fill_info->mm);
		mm = task_fill_info->mm;
	} else {
		mm = get_task_mm(task_fill_info->task);
	}

	if (task_fill_info->argp) {
		esf_raw_event_add_item_ex(
			raw_event, &process->args, ESF_ITEM_TYPE_STRING_ARR,
			task_fill_info->argp, task_fill_info->arg_len, gfp,
			ESF_ADD_ITEM_KERNMEM | ESF_ADD_ITEM_MOVEMEM);

	} else if (mm && mm->arg_start) {
		esf_raw_event_add_item_ex(raw_event, &process->args,
					  ESF_ITEM_TYPE_STRING_ARR,
					  (void *)mm->arg_start,
					  mm->arg_end - mm->arg_start, gfp,
					  ESF_ADD_ITEM_USERMEM);
	}

	if (task_fill_info->envp) {
		esf_raw_event_add_item_ex(
			raw_event, &process->env, ESF_ITEM_TYPE_STRING_ARR,
			task_fill_info->envp, task_fill_info->env_len, gfp,
			ESF_ADD_ITEM_KERNMEM | ESF_ADD_ITEM_MOVEMEM);

	} else if (mm && mm->arg_start) {
		esf_raw_event_add_item_ex(raw_event, &process->env,
					  ESF_ITEM_TYPE_STRING_ARR,
					  (void *)mm->env_start,
					  mm->env_end - mm->env_start, gfp,
					  ESF_ADD_ITEM_USERMEM);
	}

	if (task_fill_info->filename) {
		esf_raw_event_add_item_ex(
			raw_event, &process->exe, ESF_ITEM_TYPE_STRING,
			task_fill_info->filename,
			strlen(task_fill_info->filename), gfp,
			ESF_ADD_ITEM_KERNMEM | ESF_ADD_ITEM_MOVEMEM);

	} else if (mm && mm->exe_file) {
		char *path_buffer = kmalloc(PATH_MAX, gfp);

		if (!path_buffer) {
			goto fill_integral;
		}

		char *fpath = file_path(mm->exe_file, path_buffer, PATH_MAX);

		if (IS_ERR_OR_NULL(fpath)) {
			esf_log_err("Unable to fill process path, err: %ld",
				    PTR_ERR(fpath));

			esf_raw_event_add_item_type(
				raw_event, &process->exe, ESF_ITEM_TYPE_STRING,
				task_fill_info->task->comm,
				strlen(task_fill_info->task->comm), gfp);

		} else {
			esf_raw_event_add_item_type(raw_event, &process->exe,
						    ESF_ITEM_TYPE_STRING, fpath,
						    strlen(fpath), gfp);
		}

		kfree(path_buffer);
	}

fill_integral:
	process->pid = task_fill_info->task->pid;
	process->tgid = task_fill_info->task->tgid;

	_fill_creds_from_task(&process->creds, task_fill_info->task);
	_fill_ns_from_task(&process->namespace, task_fill_info->task);

	put_task_struct(task_fill_info->task);

	if (mm) {
		mmput(mm);
	}
}

/*!
 * _get_flat_strings_from_stack() copies string array from process stack to kernel space
 * @p[in,out] : is a pointer to saved stack variable
 * @argc[in] : count of elements in array
 * @len[out] : total length of array
 * @return pointer to copied data
 *
 * @a p will be advanced to @a len in case it's possible to calculate one, even if failure due
 * data copying has occured, in any other cases @a p will be equal to its start value
 */
static char *_get_flat_strings_from_stack(unsigned long *p, uint32_t argc,
					  size_t *len)
{
	BUG_ON(!len);
	BUG_ON(!p);

	unsigned int ulen = 0;
	const void __user *top = (void __user *)(*p);
	char *strs_arr = NULL;

	if (!top || !argc) {
		goto out;
	}

	for (int i = 0; i < argc; i++) {
		ulong l = strnlen_user((char *)(*p), MAX_ARG_STRLEN);
		ulen += l;
		*p += l;
	}

	if (!ulen) {
		return NULL;
	}

	strs_arr = memdup_user(top, ulen);

	if (IS_ERR_OR_NULL(strs_arr)) {
		ulen = 0;
		goto out;
	}

out:
	*len = ulen;

	return strs_arr;
}

int esf_on_execve(struct task_struct *task, struct linux_binprm *bprm)
{
	ulong task_stack = 0;
	int ret = 0;

	if (!esf_anyone_subscribed_to(ESF_EVENT_TYPE_PROCESS_EXECUTION)) {
		return 0;
	}

	esf_raw_event_t *raw_event = esf_raw_event_create(
		ESF_EVENT_TYPE_PROCESS_EXECUTION, ESF_EVENT_SIMPLE, GFP_KERNEL);

	if (!raw_event) {
		return 0;
	}

	fill_task_info_t fill_task_info;
	memset(&fill_task_info, 0, sizeof(fill_task_info));

	task_stack = bprm->p;
	fill_task_info.task = task;

	fill_task_info.argp = _get_flat_strings_from_stack(
		&task_stack, bprm->argc, &fill_task_info.arg_len);

	fill_task_info.envp = _get_flat_strings_from_stack(
		&task_stack, bprm->envc, &fill_task_info.env_len);

	fill_task_info.filename = kstrdup(bprm->filename, GFP_KERNEL);
	fill_task_info.filename_len = strlen(bprm->filename);

	_fill_process_from_task_info(raw_event,
				     &raw_event->event.header.process,
				     &fill_task_info, GFP_KERNEL);

	ret = esf_submit_raw_event(raw_event, GFP_KERNEL);

	esf_raw_event_put(raw_event);

	return ret;
}

static struct security_hook_list _esf_hooks[] __ro_after_init = {};

void __init esf_hooks_init(void)
{
	esf_log_info("Initializing hooks");
	security_add_hooks(_esf_hooks, ARRAY_SIZE(_esf_hooks), "esf");
}