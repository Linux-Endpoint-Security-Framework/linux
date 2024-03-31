#include <linux/esf/defs.h>
#include <linux/fsnotify.h>
#include <esf.h>

#include "file.h"
#include "fillers.h"

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
