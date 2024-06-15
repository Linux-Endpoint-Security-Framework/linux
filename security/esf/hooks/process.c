#include "process.h"

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mman.h>
#include <linux/mmap_lock.h>
#include <linux/uaccess.h>
#include <linux/highmem.h>

#include "esf.h"
#include "fillers.h"
#include "event.h"
#include "blobs.h"

static noinline int _dump_user_page(struct linux_binprm *bprm, void *buffer,
				    ulong pos)
{
	struct page *page;
#ifdef CONFIG_MMU
	long ret;

	mmap_read_lock(bprm->mm);
	ret = get_user_pages_remote(bprm->mm, pos, 1, FOLL_FORCE, &page, NULL);
	mmap_read_unlock(bprm->mm);

	if (ret <= 0) {
		return 0;
	}
#else
	page = bprm->page[pos / PAGE_SIZE];
#endif
	const ulong offset = pos % PAGE_SIZE;
	char *kaddr = kmap_atomic(page);

	memcpy(buffer, kaddr + offset, PAGE_SIZE - offset);
	kunmap_atomic(kaddr);

#ifdef CONFIG_MMU
	put_page(page);
#endif

	return PAGE_SIZE - offset;
}

static noinline void *_dump_user_pages(struct linux_binprm *bprm,
				       void *__user userp, size_t size,
				       gfp_t gfp)
{
	uint64_t upages_count = (size + PAGE_SIZE - 1) / PAGE_SIZE;
	uint64_t upages_size = upages_count * PAGE_SIZE;

	ulong pos = (ulong)userp;
	ulong koff = 0;

	void *pages_dump = kzalloc(upages_size, gfp);

	if (!pages_dump) {
		goto fail;
	}

	for (int page_num = 0; page_num < upages_count; page_num++) {
		int copied = _dump_user_page(bprm, pages_dump + koff, pos);

		if (!copied) {
			goto fail;
		}

		pos += copied;
		koff += copied;
	}

	return pages_dump;

fail:
	if (pages_dump) {
		kfree(pages_dump);
	}

	return NULL;
}

/*!
 * _get_flat_strings_from_stack() copies string array from process stack to kernel space
 * @p: is a pointer to saved stack variable
 * @argc: count of elements in array
 * @len: total length of array
 * @return pointer to copied data
 *
 * @a p will be advanced to @a len in case it's possible to calculate one, even if failure due
 * data copying has occured, in any other cases @a p will be equal to its start value
 */
static noinline char *_get_flat_strings_from_stack(void **p, uint32_t argc,
						   size_t *len)
{
	BUG_ON(!len);
	BUG_ON(!p);

	const void *top = *p;
	char *strs_arr = NULL;
	size_t ulen = 0;

	if (!top || !argc) {
		goto out;
	}

	for (int i = 0; i < argc; i++) {
		size_t l = strnlen((char *)*p, MAX_ARG_STRLEN);

		if (l) { // escape '\0'
			l++;
		}

		ulen += l;
		*p += l;
	}

	if (!ulen) {
		goto out;
	}

	strs_arr = kmemdup(top, ulen, GFP_KERNEL);

	if (IS_ERR_OR_NULL(strs_arr)) {
		ulen = 0;
		goto out;
	}

out:
	*len = ulen;

	return strs_arr;
}

int esf_on_process_exec(struct task_struct *task, struct linux_binprm *bprm)
{
	int ret = 0;
	struct task_struct *parent_task = NULL;
	esf_raw_event_t *raw_event = NULL;

	if (!esf_anyone_subscribed_to(ESF_EVENT_TYPE_PROCESS_EXECUTION)) {
		goto out;
	}

	raw_event = esf_raw_event_create(
		ESF_EVENT_TYPE_PROCESS_EXECUTION,
		ESF_EVENT_SIMPLE | ESF_EVENT_CAN_CONTROL, GFP_KERNEL);

	if (!raw_event) {
		goto out;
	}

	parent_task = task->parent ? get_task_struct(task->parent) :
				     get_task_struct(task);

	esf_process_fill_data_t fill_child_task_info = { 0 };
	esf_file_fill_data_t fill_task_file_info = { 0 };
	fill_child_task_info.exe_info = &fill_task_file_info;

	esf_process_fill_data_t fill_parent_task_info = { 0 };

	fill_child_task_info.task = task;
	fill_parent_task_info.task = parent_task;

	uint32_t uarr_size = bprm->exec - bprm->p;
	void *environ_dump = _dump_user_pages(bprm, (void *__user)bprm->p,
					      uarr_size, GFP_KERNEL);

	if (environ_dump) {
		void *stack_ptr = environ_dump;

		fill_child_task_info.argp = _get_flat_strings_from_stack(
			&stack_ptr, bprm->argc, &fill_child_task_info.arg_len);

		fill_child_task_info.envp = _get_flat_strings_from_stack(
			&stack_ptr, bprm->envc, &fill_child_task_info.env_len);

		kfree(environ_dump);
	}

	// preprare information about file is going to be executed
	struct fd file_to_exec = fdget(bprm->execfd);
	struct inode *inode_to_exec = NULL;

	if (file_to_exec.file) {
		inode_to_exec = file_inode(file_to_exec.file);
	} else if (bprm->file) {
		inode_to_exec = file_inode(bprm->file);
	}

	fill_child_task_info.exe_info->inode = inode_to_exec;
	fill_child_task_info.exe_info->filename =
		kstrdup(bprm->filename, GFP_KERNEL);
	fill_child_task_info.exe_info->filename_len =
		bprm->filename ? strmovelen(bprm->filename) : 0;
	fdput(file_to_exec);

	// fill header with parent information
	esf_fill_process_from_fill_data(raw_event, &raw_event->event.process,
					&fill_parent_task_info,
					&raw_event->filter_data.process,
					GFP_KERNEL);

	// fill event payload process
	esf_fill_process_from_fill_data(
		raw_event, &raw_event->event.process_execution.process,
		&fill_child_task_info, &raw_event->filter_data.target,
		GFP_KERNEL);

	if (bprm->interp) {
		esf_raw_event_add_item(
			raw_event,
			&raw_event->event.process_execution.interpreter,
			(void *)bprm->interp, strmovelen(bprm->interp),
			GFP_KERNEL);
	}

	ret = esf_submit_raw_event_ex(raw_event, GFP_KERNEL,
				      ESF_SUBMIT_WAIT_FOR_DECISION);

out:
	if (raw_event) {
		esf_raw_event_put(raw_event);
	}

	if (parent_task) {
		put_task_struct(parent_task);
	}

	if (ret == 0) {
		esf_process_lsb_t *esf_task = esf_get_task_lsb(task);
		uuid_gen(&esf_task->unique_id);
	}

	return ret;
}

int esf_on_process_ptrace(struct task_struct *p, unsigned int mode)
{
	int ret = 0;
	esf_raw_event_t *raw_event = NULL;

	if (!esf_anyone_subscribed_to(ESF_EVENT_TYPE_PROCESS_TRACE)) {
		goto out;
	}

	raw_event = esf_raw_event_create(
		ESF_EVENT_TYPE_PROCESS_TRACE,
		ESF_EVENT_SIMPLE | ESF_EVENT_CAN_CONTROL, GFP_KERNEL);

	if (!raw_event) {
		goto out;
	}

	esf_process_fill_data_t fill_sender_task_info = { 0 };
	fill_sender_task_info.task = current;

	esf_fill_process_from_fill_data(raw_event, &raw_event->event.process,
					&fill_sender_task_info,
					&raw_event->filter_data.process,
					GFP_KERNEL);

	esf_process_fill_data_t fill_receiver_task_info = { 0 };
	fill_receiver_task_info.task = p;

	esf_fill_process_from_fill_data(raw_event,
					&raw_event->event.process_ptrace.target,
					&fill_receiver_task_info,
					&raw_event->filter_data.target,
					GFP_KERNEL);

	raw_event->event.process_ptrace.mode = mode;

	ret = esf_submit_raw_event_ex(raw_event, GFP_KERNEL,
				      ESF_SUBMIT_WAIT_FOR_DECISION);

out:
	if (raw_event) {
		esf_raw_event_put(raw_event);
	}

	return ret;
}

int esf_on_process_kill(struct task_struct *p, struct kernel_siginfo *info,
			int sig, const struct cred *cred)
{
	int ret = 0;
	esf_raw_event_t *raw_event = NULL;

	if (!esf_anyone_subscribed_to(ESF_EVENT_TYPE_PROCESS_SIGNAL)) {
		goto out;
	}

	raw_event = esf_raw_event_create(
		ESF_EVENT_TYPE_PROCESS_SIGNAL,
		ESF_EVENT_SIMPLE | ESF_EVENT_CAN_CONTROL, GFP_KERNEL);

	if (!raw_event) {
		goto out;
	}

	esf_process_fill_data_t fill_sender_task_info = { 0 };
	fill_sender_task_info.task = current;

	esf_fill_process_from_fill_data(raw_event, &raw_event->event.process,
					&fill_sender_task_info,
					&raw_event->filter_data.process,
					GFP_KERNEL);

	esf_process_fill_data_t fill_receiver_task_info = { 0 };
	fill_receiver_task_info.task = p;

	esf_fill_process_from_fill_data(raw_event,
					&raw_event->event.process_signal.target,
					&fill_receiver_task_info,
					&raw_event->filter_data.target,
					GFP_KERNEL);

	raw_event->event.process_signal.signal = sig;

	ret = esf_submit_raw_event_ex(raw_event, GFP_KERNEL,
				      ESF_SUBMIT_WAIT_FOR_DECISION);

out:
	if (raw_event) {
		esf_raw_event_put(raw_event);
	}

	return ret;
}

void esf_on_process_exited(struct task_struct *task)
{
	if (task->pid != task->tgid) {
		return;
	}

	if (!esf_anyone_subscribed_to(ESF_EVENT_TYPE_PROCESS_EXITED)) {
		return;
	}

	esf_raw_event_t *raw_event = esf_raw_event_create(
		ESF_EVENT_TYPE_PROCESS_EXITED, ESF_EVENT_SIMPLE, GFP_KERNEL);

	if (!raw_event) {
		return;
	}

	esf_process_fill_data_t fill_task_info = { 0 };
	fill_task_info.task = task;

	esf_fill_process_from_fill_data(raw_event, &raw_event->event.process,
					&fill_task_info,
					&raw_event->filter_data.target,
					GFP_KERNEL);

	raw_event->event.process_exit.code = task->exit_code;
	raw_event->event.process_exit.signal = task->exit_signal;

	esf_submit_raw_event(raw_event, GFP_KERNEL);
	esf_raw_event_put(raw_event);
}