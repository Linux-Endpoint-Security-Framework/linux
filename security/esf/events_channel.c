#include "events_channel.h"

#include <linux/anon_inodes.h>
#include <linux/esf/ctl.h>

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
	esf_log_debug("Destroying event channel, fd: %d", channel->fd);
	esf_event_queue_deinit(&channel->events_queue);
	kfree(channel);
}

static long
_do_agent_subscribe_ioctl(esf_events_channel_t *channel,
			  const esf_agent_ctl_subscribe_t *subscribe_cmd)
{
	esf_event_category_t category =
		ESF_EVENT_CATEGORY_NR(subscribe_cmd->event_type);
	uint64_t event_mask = ESF_EVENT_TYPE_MASK(subscribe_cmd->event_type);

	if (category >= _ESF_EVENT_CATEGORY_MAX) {
		esf_log_err("Unknown ESF event category: %u", category);
		return -ENOPARAM;
	}

	esf_log_debug("Agent %d is listening for nr:%d, chan: %d",
		      current->tgid, subscribe_cmd->event_type, channel->fd);
	channel->subscriptions[category] |= event_mask;

	return 0;
}

static long _events_chann_ioctl(struct file *f, unsigned int cmd,
				unsigned long arg)
{
	long res = 0;
	switch (cmd) {
	case ESF_AGENT_CTL_SUBSCRIBE: {
		esf_agent_ctl_subscribe_t subscribe_cmd;
		if (copy_from_user(&subscribe_cmd, (const void *)arg,
				   sizeof(subscribe_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}

		res = _do_agent_subscribe_ioctl(f->private_data,
						&subscribe_cmd);
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

	if (channel->ops && channel->ops->release) {
		channel->ops->release(channel);
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

	size_t queue_size = esf_event_queue_size(&channel->events_queue);

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

static ssize_t _events_chann_fd_read(struct file *filp, char __user *buffer,
				     size_t buffer_size, loff_t *offset)
{
	esf_events_channel_t *channel = filp->private_data;
	esf_raw_event_holder_t *event_holder = NULL;

	if (filp->f_op != &_events_chann_fd_fops) {
		return -EBADFD;
	}

	int send_err = 0;
	loff_t cur_buff_offset = 0;
	ssize_t events_sent = 0;

	uint64_t max_events_to_send =
		esf_event_queue_size(&channel->events_queue);

	esf_events_t *__user events_arr = (esf_events_t *)buffer;
	void *__user serialized_events_arr = events_arr->events;
	size_t serialized_events_arr_size = buffer_size - sizeof(*events_arr);

	while (max_events_to_send > 0) {
		event_holder = esf_event_queue_hold(&channel->events_queue);

		if (!event_holder) {
			return -EPIPE;
		}

		send_err = _send_event_to_user(serialized_events_arr,
					       serialized_events_arr_size,
					       event_holder, &cur_buff_offset);

		if (send_err) {
			esf_event_queue_release_held(event_holder);
			break;
		}

		events_sent++;
		max_events_to_send--;
		esf_event_queue_dequeue_held(event_holder);
		esf_put_raw_event_holder(event_holder);
	}

	int non_copied = copy_to_user(&events_arr->count, &events_sent,
				      sizeof(events_arr));

	if (non_copied) {
		return -EFAULT;
	}

	return cur_buff_offset + sizeof(*events_arr);
}

esf_events_channel_t *esf_events_channel_create(const char *name,
						esf_events_channel_fops_t *ops,
						void *private)
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

	esf_log_debug("Created event channel, fd: %d", fd);

	chan->fd = fd;
	chan->private = private;
	atomic_set(&chan->refc, 0);
	atomic64_set(&chan->event_nr, 0);

	init_waitqueue_head(&chan->wq);
	esf_event_queue_init(&chan->events_queue);

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
	esf_log_debug("Waking up channel %d", channel->fd);
	wake_up(&channel->wq);
	return 0;
}

int esf_events_channel_send(esf_events_channel_t *channel,
			    esf_raw_event_t *event, gfp_t gfp)
{
	esf_raw_event_get(event);
	esf_raw_event_holder_t *holder =
		esf_event_queue_enqueue(&channel->events_queue, event, gfp);

	if (!holder) {
		return -ENOMEM;
	}

	int64_t event_nr = atomic64_inc_return(&channel->event_nr);

	if (channel->ops && channel->ops->want_wakeup) {
		if (channel->ops->want_wakeup(channel, event_nr)) {
			esf_events_channel_wakeup(channel);
		}
	} else {
		esf_events_channel_wakeup(channel);
	}

	return 0;
}

uint64_t esf_events_channel_size(esf_events_channel_t *channel)
{
	return esf_event_queue_size(&channel->events_queue);
}
