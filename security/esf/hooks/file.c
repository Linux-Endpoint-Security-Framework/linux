#include <linux/esf/defs.h>
#include <linux/fs_struct.h>

#include "esf.h"
#include "log.h"
#include "file.h"
#include "fillers.h"

esf_raw_event_t *_inode_event(struct inode *inode, esf_event_type_t event_type,
			      esf_event_flags_t event_flags)
{
	char *path_buffer = NULL;
	esf_raw_event_t *raw_event = NULL;

	struct dentry *real_dentry = NULL;
	struct dentry *dentry = NULL;

	if (!esf_anyone_subscribed_to(event_type)) {
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
	file_fill_data.fs_info = current->fs;

	dentry = d_find_any_alias(inode);

	if (!dentry) {
		goto out;
	}

	real_dentry = d_real(dentry, inode);

	char *filepath = dentry_path_raw(real_dentry, path_buffer, PATH_MAX);

	lockref_put_not_zero(&dentry->d_lockref);

	if (filepath) {
		file_fill_data.filename = kstrdup(filepath, GFP_KERNEL);

		if (!file_fill_data.filename) {
			goto out;
		}

		file_fill_data.filename_len =
			strmovelen(file_fill_data.filename);
	}

	raw_event = esf_raw_event_create(event_type, event_flags, GFP_KERNEL);

	if (!raw_event) {
		goto out;
	}

	esf_fill_process_from_fill_data(raw_event, &raw_event->event.process,
					&process_fill_data,
					&raw_event->filter_data.process,
					GFP_KERNEL);

	esf_fill_file_from_fill_data(raw_event, &raw_event->event.__file,
				     &file_fill_data,
				     &raw_event->filter_data.target,
				     GFP_KERNEL);

out:
	if (path_buffer) {
		kfree(path_buffer);
	}

	return raw_event;
}

int esf_on_check_inode_permission(struct inode *inode, int mask)
{
	int ret = 0;
	esf_raw_event_t *raw_event = NULL;

	raw_event = _inode_event(inode, ESF_EVENT_TYPE_FILE_INODE_CHECK_PERM,
				 ESF_EVENT_SIMPLE | ESF_EVENT_CAN_CONTROL);

	if (!raw_event) {
		goto out;
	}

	ret = esf_submit_raw_event_ex(raw_event, GFP_KERNEL,
				      ESF_SUBMIT_SIMPLE |
					      ESF_SUBMIT_WAIT_FOR_DECISION);

out:
	if (raw_event) {
		esf_raw_event_put(raw_event);
	}

	return ret;
}

int esf_on_file_open(struct file *file)
{
	int ret = 0;
	esf_raw_event_t *raw_event = NULL;
	struct inode *inode = file_inode(file);

	if (!inode) {
		goto out;
	}

	raw_event = _inode_event(inode, ESF_EVENT_TYPE_FILE_OPEN,
				 ESF_EVENT_SIMPLE | ESF_EVENT_CAN_CONTROL);

	if (!raw_event) {
		goto out;
	}

	raw_event->event.file_open.flags = file->f_flags;

	ret = esf_submit_raw_event_ex(raw_event, GFP_KERNEL,
				      ESF_SUBMIT_SIMPLE |
					      ESF_SUBMIT_WAIT_FOR_DECISION);

out:
	if (raw_event) {
		esf_raw_event_put(raw_event);
	}

	return ret;
}

int esf_on_file_truncate(struct file *file)
{
	int ret = 0;
	esf_raw_event_t *raw_event = NULL;
	struct inode *inode = file_inode(file);

	if (!inode) {
		goto out;
	}

	raw_event = _inode_event(inode, ESF_EVENT_TYPE_FILE_TRUNCATE,
				 ESF_EVENT_SIMPLE | ESF_EVENT_CAN_CONTROL);

	if (!raw_event) {
		goto out;
	}

	ret = esf_submit_raw_event_ex(raw_event, GFP_KERNEL,
				      ESF_SUBMIT_SIMPLE |
					      ESF_SUBMIT_WAIT_FOR_DECISION);

out:
	if (raw_event) {
		esf_raw_event_put(raw_event);
	}

	return ret;
}

int esf_on_file_write(struct file *file)
{
	return 0;
}
