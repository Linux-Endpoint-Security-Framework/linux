#include "events_channel.h"

#include <linux/anon_inodes.h>
#include <linux/esf/ctl.h>
#include <linux/glob.h>

#include "log.h"

static int _events_chann_fd_release(struct inode *inode, struct file *filp);
static long _events_chann_ioctl(struct file *, unsigned int, unsigned long);
static __poll_t _events_chann_fd_poll(struct file *,
				      struct poll_table_struct *);
static ssize_t _events_chann_fd_read(struct file *, char __user *, size_t,
				     loff_t *);

static struct file_operations _events_chann_fd_fops = {
	.owner = THIS_MODULE,
	.release = _events_chann_fd_release,
	.read = _events_chann_fd_read,
	.poll = _events_chann_fd_poll,
	.unlocked_ioctl = _events_chann_ioctl,
};

static void _esf_events_channel_destroy(esf_events_channel_t *channel)
{
	esf_log_debug("Destroying event channel, " ESF_EVENTS_CHAN_FMT_STR,
		      ESF_EVENTS_CHAN_FMT(channel));

	esf_events_queue_deinit(&channel->events_queue);

	esf_events_channel_filter_t *tmp = NULL;
	esf_events_channel_filter_t *filter = NULL;

	write_lock(&channel->filters_lock);

	for (int i = 0; i < __ESF_FILTER_TYPE_NUM; i++) {
		struct list_head *filters_list = &channel->filters[i];

		list_for_each_entry_safe(filter, tmp, filters_list, _node) {
			list_del(&filter->_node);
			kfree(filter);
		}
	}

	write_unlock(&channel->filters_lock);

	kfree(channel);
}

static long _do_events_chan_add_filter_ioctl(
	esf_events_channel_t *channel,
	const esf_events_chan_ctl_add_filter_t *add_filter_cmd)
{
	long err = 0;

	esf_events_channel_filter_t *new_filter =
		kmalloc(sizeof(esf_events_channel_filter_t), GFP_KERNEL);

	if (!new_filter) {
		err = -ENOMEM;
		goto out;
	}

	INIT_LIST_HEAD(&new_filter->_node);
	long non_copied = copy_from_user(&new_filter->filter,
					 add_filter_cmd->filter,
					 sizeof(*add_filter_cmd->filter));

	if (non_copied) {
		kfree(new_filter);
		err = -EINVAL;
		goto out;
	}

	if (new_filter->filter.type > __ESF_FILTER_TYPE_NUM ||
	    new_filter->filter.type < 0) {
		kfree(new_filter);
		esf_log_err("Bad filter type %d", new_filter->filter.type);
		err = -EINVAL;
		goto out;
	}

	if (new_filter->filter.process.path[ESF_FILTER_PATH_MAX - 1] != '\0') {
		new_filter->filter.process.path[ESF_FILTER_PATH_MAX - 1] = '\0';
	}

	if (new_filter->filter.target.path[ESF_FILTER_PATH_MAX - 1] != '\0') {
		new_filter->filter.target.path[ESF_FILTER_PATH_MAX - 1] = '\0';
	}

	write_lock(&channel->filters_lock);

	list_add_tail(&new_filter->_node,
		      &channel->filters[new_filter->filter.type]);
	channel->filters_count[new_filter->filter.type]++;

	write_unlock(&channel->filters_lock);
out:
	return err;
}

static long _do_events_chan_subscribe_ioctl(
	esf_events_channel_t *channel,
	const esf_events_chan_ctl_subscribe_t *subscribe_cmd)
{
	esf_event_category_t category =
		ESF_EVENT_CATEGORY_NR(subscribe_cmd->event_type);
	uint64_t event_mask = ESF_EVENT_TYPE_MASK(subscribe_cmd->event_type);

	if (category >= _ESF_EVENT_CATEGORY_MAX) {
		esf_log_err("Unknown ESF event category: %u", category);
		return -ENOPARAM;
	}

	esf_log_debug(
		"Agent %d is listening for nr:%d, chan: " ESF_EVENTS_CHAN_FMT_STR,
		current->tgid, subscribe_cmd->event_type,
		ESF_EVENTS_CHAN_FMT(channel));

	channel->subscriptions[category] |= event_mask;

	return 0;
}

static long _events_chann_ioctl(struct file *f, unsigned int cmd,
				unsigned long arg)
{
	long res = 0;
	switch (cmd) {
	case ESF_EVENTS_CHAN_CTL_SUBSCRIBE: {
		esf_events_chan_ctl_subscribe_t subscribe_cmd;
		if (copy_from_user(&subscribe_cmd, (const void *)arg,
				   sizeof(subscribe_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}

		res = _do_events_chan_subscribe_ioctl(f->private_data,
						      &subscribe_cmd);
	} break;
	case ESF_EVENTS_CHAN_CTL_ADD_FILTER: {
		esf_events_chan_ctl_add_filter_t add_filter_cmd;

		if (copy_from_user(&add_filter_cmd, (const void *)arg,
				   sizeof(add_filter_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}

		res = _do_events_chan_add_filter_ioctl(f->private_data,
						       &add_filter_cmd);
	} break;
	default:
		res = -ENOIOCTLCMD;
	}

out:
	return res;
}

static int _events_chann_fd_release(struct inode *inode, struct file *filp)
{
	esf_events_channel_t *channel = filp->private_data;

	if (channel->ctl && channel->ctl->release) {
		channel->ctl->release(channel);
	}

	esf_events_channel_put(channel);
	return 0;
}

static __poll_t _events_chann_fd_poll(struct file *filp,
				      struct poll_table_struct *pollt)
{
	__poll_t poll_mask = 0;
	esf_events_channel_t *channel = filp->private_data;

	if (filp->f_op != &_events_chann_fd_fops) {
		return -EBADFD;
	}

	poll_wait(filp, &channel->wq, pollt);

	size_t queue_size = esf_events_queue_size(&channel->events_queue);

	if (queue_size > 0) {
		esf_log_debug("Polled %zu events from %d", queue_size,
			      channel->fd);
		poll_mask |= (POLLIN | POLLRDNORM);
	}

	return poll_mask;
}

static inline int
_send_event_to_user(char *buffer, size_t buffer_size,
		    const esf_raw_event_holder_t *event_holder, loff_t *offset)
{
	ulong non_copied = 0;
	esf_event_t *event_buffer = (esf_event_t *)(buffer + *offset);
	void *items_data_buffer = &event_buffer->data;
	esf_raw_event_t *raw_event = esf_raw_event_holder_deref(event_holder);
	int err = 0;

	BUG_ON(((char *)items_data_buffer - (char *)event_buffer) !=
	       sizeof(esf_event_t));

	// if event iteself + whole items data > buffer size
	if (*offset + sizeof(raw_event->event) + raw_event->items_data_size >
	    buffer_size) {
		// return not enough memory
		return -ENOMEM;
	}

	esf_raw_item_t *raw_item = NULL;
	uint64_t total_copied = 0;

	// serialize all items
	list_for_each_entry(raw_item, &raw_event->raw_items, _node) {
		BUG_ON(!raw_item);

		esf_raw_item_get(raw_item);

#ifdef CONFIG_DEBUG_TRACE_LOG_EVENTS
		void *item_data_dst =
			items_data_buffer + raw_item->item->offset;

		esf_log_debug(
			"Serializing item, type: %d, size: %u, offset: %llu, src: 0x%llx, dst: 0x%llx",
			raw_item->item->item_type, raw_item->item->size,
			raw_item->item->offset, (uint64_t)raw_item->data,
			(uint64_t)item_data_dst);
#endif

		non_copied =
			copy_to_user(items_data_buffer + raw_item->item->offset,
				     raw_item->data, raw_item->item->size);

		if (non_copied) {
			esf_raw_item_put(raw_item);
			esf_log_err(
				"Unable to serialize raw item, %lu bytes not copied",
				non_copied);
			err = -EFAULT;
			goto out;
		}

		total_copied += raw_item->item->size;
		esf_raw_item_put(raw_item);
	}

	// copy event with prepared data
	non_copied = copy_to_user(event_buffer, &raw_event->event,
				  sizeof(raw_event->event));

	if (non_copied) {
		esf_log_err("Unable to copy %lu bytes to user", non_copied);
	}

out:
	if (!err) {
		*offset +=
			sizeof(raw_event->event) + raw_event->items_data_size;
	}

	return err;
}

noinline static ssize_t _events_chann_fd_read(struct file *filp,
					      char __user *buffer,
					      size_t buffer_size,
					      loff_t *offset)
{
	esf_events_channel_t *channel = filp->private_data;
	esf_raw_event_holder_t *event_holder = NULL;

	if (filp->f_op != &_events_chann_fd_fops) {
		return -EBADFD;
	}

	int send_err = 0;
	loff_t cur_buff_offset = 0;

	uint64_t max_events_to_send =
		esf_events_queue_size(&channel->events_queue);

	esf_events_t *__user events_arr = (esf_events_t *)buffer;
	void *__user serialized_events_arr = events_arr->events;
	size_t serialized_events_arr_size = buffer_size - sizeof(*events_arr);

	esf_events_queue_t sent_events_list;
	esf_events_queue_init(&sent_events_list);

	while (max_events_to_send > 0) {
		event_holder = esf_events_queue_hold(&channel->events_queue);

		if (!event_holder) {
			return -EPIPE;
		}

		send_err = _send_event_to_user(serialized_events_arr,
					       serialized_events_arr_size,
					       event_holder, &cur_buff_offset);

		if (send_err) {
			esf_events_queue_release_held(event_holder);
			break;
		}

		max_events_to_send--;
		esf_events_queue_dequeue_held(event_holder);
		esf_events_queue_enqueue_move(&sent_events_list, event_holder);
		esf_put_raw_event_holder(event_holder);
	}

	size_t events_sent = esf_events_queue_size(&sent_events_list);
	int non_copied = copy_to_user(&events_arr->count, &events_sent,
				      sizeof(events_arr));

	if (non_copied) {
		return -EFAULT;
	}

	if (channel->ctl && channel->ctl->on_events_were_read) {
		channel->ctl->on_events_were_read(channel, &sent_events_list);
	}

	// notify that all events were read by this agent
	for (esf_events_queue_iter_t it =
		     esf_events_queue_make_iter(&sent_events_list);
	     !esf_events_queue_iter_is_end(it);
	     it = esf_events_queue_iter_next(it)) {
		esf_raw_event_t *ev = esf_events_queue_iter_deref(it);
		esf_raw_event_notify_read(ev);
	}

	esf_events_queue_deinit(&sent_events_list);

	return cur_buff_offset + sizeof(*events_arr);
}

esf_events_channel_t *
esf_events_channel_create(struct task_struct *owner, const char *name,
			  const esf_events_channel_ctl_t *ctl, void *private)
{
	esf_events_channel_t *chan =
		kzalloc(sizeof(esf_events_channel_t), GFP_KERNEL);

	if (!chan) {
		return ERR_PTR(-ENOMEM);
	}

	int fd = anon_inode_getfd(name, &_events_chann_fd_fops, chan,
				  O_NONBLOCK | O_CLOEXEC | O_RDWR);

	if (fd < 0) {
		esf_log_err("Unable to create esf inode, err: %d", fd);
		return ERR_PTR(fd);
	}

	chan->fd = fd;
	chan->private = private;
	chan->ctl = ctl;

	atomic_set(&chan->refc, 0);
	atomic64_set(&chan->event_nr, 0);

	chan->owner.tgid = owner->tgid;

	init_waitqueue_head(&chan->wq);
	esf_events_queue_init(&chan->events_queue);

	rwlock_init(&chan->filters_lock);
	for (int i = 0; i < __ESF_FILTER_TYPE_NUM; i++) {
		INIT_LIST_HEAD(&chan->filters[i]);
	}

	esf_log_debug("Created event channel " ESF_EVENTS_CHAN_FMT_STR,
		      ESF_EVENTS_CHAN_FMT(chan));

	return esf_events_channel_get(chan);
}

esf_events_channel_t *esf_events_channel_get(esf_events_channel_t *channel)
{
	atomic_inc(&channel->refc);
	return channel;
}

void esf_events_channel_put(esf_events_channel_t *channel)
{
	if (atomic_dec_and_test(&channel->refc)) {
		_esf_events_channel_destroy(channel);
	}
}

int esf_events_channel_wakeup(esf_events_channel_t *channel)
{
	esf_log_debug("Waking up channel " ESF_EVENTS_CHAN_FMT_STR,
		      ESF_EVENTS_CHAN_FMT(channel));

	int woken_up = wake_up_all(&channel->wq);
	esf_log_debug("%d tasks woken up", woken_up);

	return 0;
}

static noinline bool _filter_matches(const esf_raw_event_t *event,
				     const esf_filter_t *filter)
{
	esf_filter_match_mask_t matched = 0;

	if (filter->match & ESF_FILTER_EVENT_TYPE) {
		if (filter->event_type == event->event.header.type) {
			matched |= ESF_FILTER_EVENT_TYPE;
		}
	}

	if (filter->match & ESF_FILTER_PROCESS_PATH) {
		if (glob_match(filter->process.path,
			       event->filter_data.process.path)) {
			matched |= ESF_FILTER_PROCESS_PATH;
		}
	}

	if (filter->match & ESF_FILTER_TARGET_PATH) {
		if (glob_match(filter->target.path,
			       event->filter_data.target.path)) {
			matched |= ESF_FILTER_TARGET_PATH;
		}
	}

	if (!matched) {
		return false;
	}

	// at least one matched
	if (filter->match_mode == ESF_FILTER_MATCH_MODE_OR) {
		esf_log_debug("Filter matches (OR) flags %d", matched);
		return true;
	}

	esf_log_debug("Filter matches (AND) flags %d", matched);
	return matched == filter->match;
}

int esf_events_channel_send(esf_events_channel_t *channel,
			    esf_raw_event_t *event, gfp_t gfp)
{
	esf_raw_event_get(event);
	bool should_enqueue_event = false;

	esf_events_channel_filter_t *f = NULL;
	read_lock(&channel->filters_lock);

	// check drop rules first
	if (channel->filters_count[ESF_FILTER_TYPE_DROP] > 0) {
		list_for_each_entry(f, &channel->filters[ESF_FILTER_TYPE_DROP],
				    _node) {
			if (!_filter_matches(event, &f->filter)) {
				continue;
			}

			if (channel->ctl && channel->ctl->event_filtered) {
				should_enqueue_event =
					channel->ctl->event_filtered(
						channel, event, &f->filter);
			} else {
				should_enqueue_event = false;
			}

			// event must be dropped anyway
			goto filters_processed;
		}

		// no one filter drops this event
		if (channel->ctl && channel->ctl->event_passed_filters) {
			should_enqueue_event = channel->ctl->event_passed_filters(
				channel, event, ESF_FILTER_TYPE_DROP,
				channel->filters_count[ESF_FILTER_TYPE_DROP]);

			if (!should_enqueue_event) {
				goto filters_processed;
			}
		}
	}

	// and then check allow filters
	// If there is at list one allow filter and event didn't match to it
	// drop event
	if (channel->filters_count[ESF_FILTER_TYPE_ALLOW] > 0) {
		list_for_each_entry(f, &channel->filters[ESF_FILTER_TYPE_ALLOW],
				    _node) {
			if (!_filter_matches(event, &f->filter)) {
				continue;
			}

			if (channel->ctl && channel->ctl->event_filtered) {
				should_enqueue_event =
					channel->ctl->event_filtered(
						channel, event, &f->filter);
			} else {
				should_enqueue_event = true;
			}

			goto filters_processed;
		}

		// no one filter allows this event
		if (channel->ctl && channel->ctl->event_passed_filters) {
			// so we should ask for agent logic in this case
			should_enqueue_event = channel->ctl->event_passed_filters(
				channel, event, ESF_FILTER_TYPE_ALLOW,
				channel->filters_count[ESF_FILTER_TYPE_ALLOW]);
		} else {
			// ctl is not setup, drop this event
			should_enqueue_event = false;
		}

	} else { // there are no allow filters, so we should allow all events
		should_enqueue_event = true;
	}

filters_processed:
	read_unlock(&channel->filters_lock);

	if (!should_enqueue_event) {
		goto out;
	} else {
		// mark event as read to avoid any
		esf_raw_event_notify_read(event);
	}

	esf_raw_event_holder_t *holder =
		esf_events_queue_enqueue(&channel->events_queue, event, gfp);

	if (!holder) {
		return -ENOMEM;
	}

	int64_t event_nr = atomic64_inc_return(&channel->event_nr);

	if (channel->ctl && channel->ctl->want_wakeup) {
		if (channel->ctl->want_wakeup(channel, event_nr)) {
			esf_events_channel_wakeup(channel);
		}
	} else {
		esf_events_channel_wakeup(channel);
	}

out:
	esf_raw_event_put(event);
	return 0;
}

uint64_t esf_events_channel_size(esf_events_channel_t *channel)
{
	return esf_events_queue_size(&channel->events_queue);
}
