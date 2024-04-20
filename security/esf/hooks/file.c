#include <linux/esf/defs.h>
#include <linux/fs_struct.h>

#include "esf.h"
#include "log.h"
#include "file.h"
#include "fillers.h"

static int _lookup_inode_vfsmount(struct vfsmount *mnt, void *arg)
{
	esf_file_fill_data_t *file_fill_data = arg;

	if (!mnt->mnt_root || !mnt->mnt_sb) {
		return -EFAULT;
	}

	char *path_buffer = kzalloc(PATH_MAX, GFP_KERNEL);

	if (!path_buffer) {
		return -ENOMEM;
	}

	struct path p = { .dentry = mnt->mnt_root, .mnt = mnt };

	if (file_fill_data->inode->i_sb == mnt->mnt_sb) {
		file_fill_data->fs_mnt_point = mnt;

		char *path =
			__d_path(&p, &current->fs->root, path_buffer, PATH_MAX);
		esf_log_debug("Mount path: %s", path);
		return 1; // stop iterating
	}

	kfree(path_buffer);
	return 0;
}

int esf_on_check_inode_permission(struct inode *inode, int mask)
{
	int ret = 0;
	char *path_buffer = NULL;
	esf_raw_event_t *raw_event = NULL;

	struct dentry *real_dentry = NULL;
	struct dentry *dentry = NULL;

	if (!(mask & MAY_OPEN)) {
		goto out;
	}

	if (!esf_anyone_subscribed_to(ESF_EVENT_TYPE_FILE_OPEN)) {
		goto out;
	}

	path_buffer = kzalloc(PATH_MAX, GFP_KERNEL);

	if (!path_buffer) {
		goto out;
	}

	esf_process_fill_data_t process_fill_data = { 0 };
	process_fill_data.task = current;

	esf_file_fill_data_t file_fill_data = { 0 };
	file_fill_data.inode = inode;

	dentry = d_find_any_alias(inode);

	if (!dentry) {
		goto out;
	}

	real_dentry = d_real(dentry, inode);

	char *filepath = dentry_path_raw(real_dentry, path_buffer, PATH_MAX);

	iterate_mounts(_lookup_inode_vfsmount, &file_fill_data,
		       current->fs->root.mnt);

	lockref_put_not_zero(&dentry->d_lockref);

	if (filepath) {
		file_fill_data.filename = kstrdup(filepath, GFP_KERNEL);

		if (!file_fill_data.filename) {
			goto out;
		}

		file_fill_data.filename_len =
			strmovelen(file_fill_data.filename);
	}

	raw_event = esf_raw_event_create(
		ESF_EVENT_TYPE_FILE_OPEN,
		ESF_EVENT_SIMPLE | ESF_EVENT_CAN_CONTROL, GFP_KERNEL);

	if (!raw_event) {
		goto out;
	}

	esf_fill_process_from_fill_data(raw_event, &raw_event->event.process,
					&process_fill_data,
					&raw_event->filter_data.process,
					GFP_KERNEL);

	esf_fill_file_from_fill_data(
		raw_event, &raw_event->event.file_open.file, &file_fill_data,
		&raw_event->filter_data.target, GFP_KERNEL);

	ret = esf_submit_raw_event_ex(raw_event, GFP_KERNEL,
				      ESF_SUBMIT_WAIT_FOR_DECISION);
out:
	if (raw_event) {
		esf_raw_event_put(raw_event);
	}

	if (path_buffer) {
		kfree(path_buffer);
	}

	return ret;
}

int esf_on_file_open(struct file *file)
{
	int ret = 0;

	if (!esf_anyone_subscribed_to(ESF_EVENT_TYPE_FILE_OPEN)) {
		goto out;
	}

	get_file(file);

	esf_raw_event_t *raw_event = esf_raw_event_create(
		ESF_EVENT_TYPE_FILE_OPEN,
		ESF_EVENT_SIMPLE | ESF_EVENT_CAN_CONTROL, GFP_KERNEL);

	if (!raw_event) {
		goto out_put;
	}

	esf_process_fill_data_t process_fill_data = { 0 };
	process_fill_data.task = current;

	esf_file_fill_data_t file_fill_data = { 0 };
	file_fill_data.file = file;

	esf_fill_process_from_fill_data(raw_event, &raw_event->event.process,
					&process_fill_data,
					&raw_event->filter_data.process,
					GFP_KERNEL);

	esf_fill_file_from_fill_data(
		raw_event, &raw_event->event.file_open.file, &file_fill_data,
		&raw_event->filter_data.target, GFP_KERNEL);

	raw_event->event.file_open.flags = file->f_flags;

	ret = esf_submit_raw_event_ex(raw_event, GFP_KERNEL,
				      ESF_SUBMIT_WAIT_FOR_DECISION);

out_put:
	if (raw_event) {
		esf_raw_event_put(raw_event);
	}

	fput(file);
out:
	return ret;
}

int esf_on_file_truncate(struct file *file)
{
	int ret = 0;

	if (!esf_anyone_subscribed_to(ESF_EVENT_TYPE_FILE_TRUNCATE)) {
		goto out;
	}

	get_file(file);

	esf_raw_event_t *raw_event = esf_raw_event_create(
		ESF_EVENT_TYPE_FILE_TRUNCATE,
		ESF_EVENT_SIMPLE | ESF_EVENT_CAN_CONTROL, GFP_KERNEL);

	if (!raw_event) {
		goto out_put;
	}

	esf_process_fill_data_t process_fill_data = { 0 };
	process_fill_data.task = current;

	esf_file_fill_data_t file_fill_data = { 0 };
	file_fill_data.file = file;

	esf_fill_process_from_fill_data(raw_event, &raw_event->event.process,
					&process_fill_data,
					&raw_event->filter_data.process,
					GFP_KERNEL);

	esf_fill_file_from_fill_data(
		raw_event, &raw_event->event.file_truncate.file,
		&file_fill_data, &raw_event->filter_data.target, GFP_KERNEL);

	ret = esf_submit_raw_event_ex(raw_event, GFP_KERNEL,
				      ESF_SUBMIT_WAIT_FOR_DECISION);

out_put:
	if (raw_event) {
		esf_raw_event_put(raw_event);
	}

	fput(file);
out:
	return ret;
}

int esf_on_file_write(struct file *file)
{
	return 0;
}
