#include "fillers.h"

#include <linux/ipc_namespace.h>
#include <linux/mnt_namespace.h>
#include <net/net_namespace.h>
#include <linux/pid_namespace.h>
#include <linux/time_namespace.h>
#include <linux/cgroup.h>
#include <linux/utsname.h>
#include <linux/mount.h>
#include <linux/binfmts.h>
#include <linux/fs_struct.h>

#include "log.h"
#include "blobs.h"

void esf_fill_ns_from_task(esf_ns_info_t *ns, struct task_struct *task,
			   esf_raw_event_filter_data_payload_t *init_filter)
{
	ns->uts_ns = _ACCESSIBLE(task, nsproxy, uts_ns) ?
			     task->nsproxy->uts_ns->ns.inum :
			     init_nsproxy.uts_ns->ns.inum;

	ns->ipc_ns = _ACCESSIBLE(task, nsproxy, ipc_ns) ?
			     task->nsproxy->ipc_ns->ns.inum :
			     init_nsproxy.ipc_ns->ns.inum;

	ns->mnt_ns = _ACCESSIBLE(task, nsproxy, mnt_ns) ?
			     from_mnt_ns(task->nsproxy->mnt_ns)->inum :
			     from_mnt_ns(init_nsproxy.mnt_ns)->inum;

	ns->pid_ns_for_children =
		_ACCESSIBLE(task, nsproxy, pid_ns_for_children) ?
			task->nsproxy->pid_ns_for_children->ns.inum :
			init_nsproxy.pid_ns_for_children->ns.inum;

	ns->net_ns = _ACCESSIBLE(task, nsproxy, net_ns) ?
			     task->nsproxy->net_ns->ns.inum :
			     init_nsproxy.net_ns->ns.inum;

	ns->time_ns = _ACCESSIBLE(task, nsproxy, time_ns) ?
			      task->nsproxy->time_ns->ns.inum :
			      init_nsproxy.time_ns->ns.inum;

	ns->time_ns_for_children =
		_ACCESSIBLE(task, nsproxy, time_ns_for_children) ?
			task->nsproxy->time_ns_for_children->ns.inum :
			init_nsproxy.time_ns_for_children->ns.inum;
}

void esf_fill_creds_from_task(esf_creds_info_t *creds, struct task_struct *task,
			      esf_raw_event_filter_data_payload_t *init_filter)
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

void esf_fill_process_from_fill_data(
	esf_raw_event_t *raw_event, esf_process_info_t *process,
	esf_process_fill_data_t *task_fill_info,
	esf_raw_event_filter_data_payload_t *init_filter, gfp_t gfp)
{
	BUG_ON(!task_fill_info);
	BUG_ON(!task_fill_info->task);

	export_uuid(process->uuid.b,
		    &esf_get_task_lsb(task_fill_info->task)->unique_id);

	struct mm_struct *mm = NULL;

	if (task_fill_info->mm) {
		mmget(task_fill_info->mm);
		mm = task_fill_info->mm;
	} else {
		mm = task_fill_info->task->mm;
		if (mm) {
			mmget(mm);
		}
	}

	if (!IS_ERR_OR_NULL(task_fill_info->argp)) {
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

	if (!IS_ERR_OR_NULL(task_fill_info->envp)) {
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

	if (task_fill_info->exe_info) {
		if (!task_fill_info->exe_info->fs_info) {
			task_fill_info->exe_info->fs_info =
				task_fill_info->task->fs;
		}

		esf_fill_file_from_fill_data(raw_event, &process->exe,
					     task_fill_info->exe_info,
					     init_filter, gfp);

	} else if (mm && mm->exe_file) {
		esf_file_fill_data_t exe_info = { 0 };
		char *path_buffer = kmalloc(PATH_MAX, gfp);

		if (!path_buffer) {
			goto fill_integral;
		}

		exe_info.fs_info = task_fill_info->task->fs;
		exe_info.inode = file_inode(mm->exe_file);

		char *fpath = file_path(mm->exe_file, path_buffer, PATH_MAX);

		if (IS_ERR_OR_NULL(fpath)) {
			esf_log_err("Unable to fill process path, err: %ld",
				    PTR_ERR(fpath));

			// copy and set size (including NUL terminator)
			exe_info.filename =
				kstrdup(task_fill_info->task->comm, gfp);
			exe_info.filename_len =
				strmovelen(task_fill_info->task->comm);

			esf_fill_file_from_fill_data(raw_event, &process->exe,
						     &exe_info, init_filter,
						     gfp);

		} else {
			// copy and set size (including NUL terminator)
			exe_info.filename = kstrdup(fpath, gfp);
			exe_info.filename_len = strmovelen(fpath);

			esf_fill_file_from_fill_data(raw_event, &process->exe,
						     &exe_info, init_filter,
						     gfp);
		}

		kfree(path_buffer);

	} else if (!mm && task_fill_info->task->flags & PF_KTHREAD) {
		esf_file_fill_data_t exe_info = { 0 };

		// copy and set size (including NUL terminator)
		exe_info.filename = kstrdup("kthread", gfp);
		exe_info.filename_len = sizeof("kthread");

		esf_fill_file_from_fill_data(raw_event, &process->exe,
					     &exe_info, init_filter, gfp);
	}

fill_integral:
	process->pid = task_fill_info->task->pid;
	process->tgid = task_fill_info->task->tgid;
	process->ppid = task_fill_info->task->parent ?
				task_fill_info->task->parent->pid :
				0;

	esf_fill_creds_from_task(&process->creds, task_fill_info->task,
				 init_filter);
	esf_fill_ns_from_task(&process->namespace, task_fill_info->task,
			      init_filter);

	if (mm) {
		mmput(mm);
	}
}

typedef struct _lookup_inode_vmfmount_struct {
	struct inode *inode;
	struct fs_struct *fs_info;
	char *buffer;
	size_t buffer_size;
	gfp_t gfp;

	char *__will_be_moved found_mount_path;
} _lookup_inode_vmfmount;

static int _lookup_inode_mount_path(struct vfsmount *mnt, void *arg)
{
	_lookup_inode_vmfmount *lookup = arg;

	BUG_ON(!lookup);
	BUG_ON(!lookup->inode);
	BUG_ON(!lookup->buffer);
	BUG_ON(!lookup->fs_info);

	if (!mnt->mnt_root || !mnt->mnt_sb) {
		return -EFAULT;
	}

	struct path p = { .dentry = mnt->mnt_root, .mnt = mnt };

	if (lookup->inode->i_sb == mnt->mnt_sb) {
		char *path = d_absolute_path(&p, lookup->buffer,
					     lookup->buffer_size);

		lookup->found_mount_path = kstrdup(path, lookup->gfp);

		return true; // stop iterating
	}

	return false;
}

void esf_fill_file_from_fill_data(
	esf_raw_event_t *raw_event, esf_file_info_t *file,
	esf_file_fill_data_t *file_fill_info,
	esf_raw_event_filter_data_payload_t *init_filter, gfp_t gfp)
{
	BUG_ON(!file_fill_info);

	const esf_raw_item_t *file_path_item = NULL;

	if (file_fill_info->filename) {
		file_path_item = esf_raw_event_add_item_ex(
			raw_event, &file->path, ESF_ITEM_TYPE_STRING,
			file_fill_info->filename, file_fill_info->filename_len,
			gfp, ESF_ADD_ITEM_KERNMEM | ESF_ADD_ITEM_MOVEMEM);

	} else if (file_fill_info->file) {
		char *path_buffer = kmalloc(PATH_MAX, gfp);

		if (!path_buffer) {
			goto skip_path_filling;
		}

		char *fpath =
			file_path(file_fill_info->file, path_buffer, PATH_MAX);

		file_path_item = esf_raw_event_add_item_ex(
			raw_event, &file->path, ESF_ITEM_TYPE_STRING, fpath,
			strlen(fpath), gfp, ESF_ADD_ITEM_KERNMEM);

		kfree(path_buffer);
	}

	if (!IS_ERR_OR_NULL(file_path_item) && init_filter) {
		init_filter->path = file_path_item->data;
	}

	if (!file_fill_info->inode && file_fill_info->file) {
		file_fill_info->inode = file_inode(file_fill_info->file);
	}

skip_path_filling:
	if (file_fill_info->inode) {
		file->inode = file_fill_info->inode->i_ino;

		file->ctime = timespec64_to_ktime(
			inode_get_ctime(file_fill_info->inode));
		file->atime = timespec64_to_ktime(
			inode_get_atime(file_fill_info->inode));
		file->mtime = timespec64_to_ktime(
			inode_get_mtime(file_fill_info->inode));

		file->gid =
			from_kgid(&init_user_ns, file_fill_info->inode->i_gid);

		file->uid =
			from_kuid(&init_user_ns, file_fill_info->inode->i_uid);

		file->mode = file_fill_info->inode->i_mode;
		file->size = file_fill_info->inode->i_size;

		if (file_fill_info->inode->i_sb) {
			struct super_block *sb = file_fill_info->inode->i_sb;

			strncpy(file->fs.id, sb->s_id, sizeof(file->fs.id));
			export_uuid(file->fs.uuid.b, &sb->s_uuid);
			file->fs.magic = sb->s_magic;
		}
	}

	if (file_fill_info->fs_info && file_fill_info->inode) {
		char *buffer = kmalloc(PATH_MAX, gfp);

		if (!buffer) {
			goto out;
		}

		_lookup_inode_vmfmount lookup = {
			.inode = file_fill_info->inode,
			.fs_info = file_fill_info->fs_info,
			.buffer = buffer,
			.buffer_size = PATH_MAX,
			.gfp = gfp,
			.found_mount_path = NULL,
		};

		if (iterate_mounts(_lookup_inode_mount_path, &lookup,
				   file_fill_info->fs_info->root.mnt)) {
			if (lookup.found_mount_path) {
				esf_raw_event_add_item_ex(
					raw_event, &file->fs.mount_point,
					ESF_ITEM_TYPE_STRING,
					lookup.found_mount_path,
					strmovelen(lookup.found_mount_path),
					gfp,
					ESF_ADD_ITEM_KERNMEM |
						ESF_ADD_ITEM_MOVEMEM);
			} else {
				esf_raw_event_add_item_ex(raw_event,
							  &file->fs.mount_point,
							  ESF_ITEM_TYPE_STRING,
							  "?/", sizeof("?/"),
							  gfp,
							  ESF_ADD_ITEM_KERNMEM);
			}
		}

		kfree(buffer);
	}

out:
	return;
}