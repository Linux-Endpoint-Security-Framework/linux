#include "agent.h"
#include "log.h"
#include "esf.h"

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/poll.h>
#include <linux/esf/ctl.h>

static esf_raw_event_holder_t *_create_event_holder(esf_raw_event_t *for_event,
						    gfp_t gfp)
{
	BUG_ON(!for_event);

	esf_raw_event_holder_t *item =
		kmalloc(sizeof(esf_raw_event_holder_t), gfp);

	if (!item) {
		return NULL;
	}

	INIT_LIST_HEAD(&item->_node);
	item->raw_event = for_event;

	esf_raw_event_get(for_event);

	return item;
}

static void _destroy_event_holder(esf_raw_event_holder_t *holder)
{
	esf_raw_event_put(holder->raw_event);
	kfree(holder);
}

static void _esf_agent_destroy(esf_agent_t *agent)
{
	agent->flags = 0;

	esf_raw_event_holder_t *tmp = NULL;
	esf_raw_event_holder_t *event_item = NULL;

	write_lock(&agent->event_queue_lock);

	list_for_each_entry_safe(event_item, tmp, &agent->events_queue, _node) {
		agent->events_count--;
		list_del(&event_item->_node);
		_destroy_event_holder(event_item);
	}

	write_unlock(&agent->event_queue_lock);

	put_task_struct(agent->task);
	kfree(agent);
}

static int _agent_fd_release(struct inode *inode, struct file *filp);
static __poll_t _agent_fd_poll(struct file *, struct poll_table_struct *);
static ssize_t _agent_fd_read(struct file *, char __user *, size_t, loff_t *);
static long _agent_fd_ioctl(struct file *, unsigned int, unsigned long);

static struct file_operations _agent_fd_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = _agent_fd_ioctl,
	.release = _agent_fd_release,
	.read = _agent_fd_read,
	.poll = _agent_fd_poll,
};

static long
_do_agent_activate_ioctl(esf_agent_t *agent,
			 const esf_agent_ctl_activate_t *activate_cmd)
{
	esf_log_info("Activating agent %d", agent->task->tgid);
	esf_bitmask_buff_64_t mask_buff = { 0 };

	for (int i = 0; i < _ESF_EVENT_CATEGORY_MAX; ++i) {
		esf_print_bitmask_64(agent->subscriptions[i], mask_buff);
		esf_log_debug("\tsub mask %d: %s", i, mask_buff);
		esf_print_bitmask_64(agent->want_control_subscriptions[i],
				     mask_buff);
		esf_log_debug("\tctl mask %d: %s", i, mask_buff);
	}

	agent->flags |= ESF_AGENT_ACTIVE;

	esf_update_active_subscriptions_mask();

	return 0;
}

static long
_do_agent_subscribe_ioctl(esf_agent_t *agent,
			  const esf_agent_ctl_subscribe_t *subscribe_cmd)
{
	esf_event_category_t category =
		ESF_EVENT_CATEGORY_NR(subscribe_cmd->event_type);
	uint64_t event_mask = ESF_EVENT_TYPE_MASK(subscribe_cmd->event_type);

	if (category >= _ESF_EVENT_CATEGORY_MAX) {
		esf_log_err("Unknown ESF event category: %u", category);
		return -ENOPARAM;
	}

	agent->subscriptions[category] |= event_mask;

	if (subscribe_cmd->flags & ESF_SUBSCRIBE_AS_CONTROLLER) {
		agent->want_control_subscriptions[category] |= event_mask;
	}

	return 0;
}

static long _do_agent_decide_ioctl(__maybe_unused esf_agent_t *agent,
				   const esf_agent_ctl_decide_t *decide_cmd)
{
	return esf_event_id_make_decision(decide_cmd->event_id,
					  decide_cmd->decision);
}

static long _agent_fd_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	long res = 0;
	esf_agent_t *agent = filp->private_data;

	if (filp->f_op != &_agent_fd_fops) {
		res = -EBADFD;
		goto out;
	}

	switch (cmd) {
	case ESF_AGENT_CTL_ACTIVATE: {
		esf_agent_ctl_activate_t activate_cmd;
		if (copy_from_user(&activate_cmd, (const void *)arg,
				   sizeof(activate_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}

		res = _do_agent_activate_ioctl(agent, &activate_cmd);
	} break;
	case ESF_AGENT_CTL_SUBSCRIBE: {
		esf_agent_ctl_subscribe_t subscribe_cmd;
		if (copy_from_user(&subscribe_cmd, (const void *)arg,
				   sizeof(subscribe_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}

		res = _do_agent_subscribe_ioctl(agent, &subscribe_cmd);
	} break;
	case ESF_AGENT_CTL_DECIDE: {
		esf_agent_ctl_decide_t decide_cmd;
		if (copy_from_user(&decide_cmd, (const void *)arg,
				   sizeof(decide_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}

		res = _do_agent_decide_ioctl(agent, &decide_cmd);
	} break;
	default:
		res = -ENOIOCTLCMD;
	}

out:
	return res;
}

static __poll_t _agent_fd_poll(struct file *filp,
			       struct poll_table_struct *pollt)
{
	__poll_t poll_mask = 0;
	esf_agent_t *agent = filp->private_data;

	if (filp->f_op != &_agent_fd_fops) {
		return -EBADFD;
	}

	esf_agent_get(agent);

	read_lock(&agent->event_queue_lock);

	if (agent->events_count > 0) {
		poll_mask |= (POLLIN | POLLRDNORM);
	}

	read_unlock(&agent->event_queue_lock);

	if (poll_mask) {
		goto out;
	}

	poll_wait(filp, &agent->events_queue_wq, pollt);

out:
	esf_agent_put(agent);

	return poll_mask;
}

static inline int
_send_event_to_user(char *buffer, size_t buffer_size,
		    const esf_raw_event_holder_t *event_holder, loff_t *offset)
{
	ulong non_copied = 0;
	esf_event_t *event_buffer = (esf_event_t *)(buffer + *offset);
	void *items_data_buffer = &event_buffer->data;
	int err = 0;

	BUG_ON(((char *)items_data_buffer - (char *)event_buffer) !=
	       sizeof(esf_event_t));

	// if event iteself + whole items data > buffer size
	if (*offset + sizeof(event_holder->raw_event->event) +
		    event_holder->raw_event->items_data_size >
	    buffer_size) {
		// return not enough memory
		return -ENOMEM;
	}

	esf_raw_item_t *raw_item = NULL;
	uint64_t total_copied = 0;

	// serialize all items
	list_for_each_entry(raw_item, &event_holder->raw_event->raw_items,
			    _node) {
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
	non_copied = copy_to_user(event_buffer, &event_holder->raw_event->event,
				  sizeof(event_holder->raw_event->event));

	if (non_copied) {
		esf_log_err("Unable to copy %lu bytes to user", non_copied);
	}

out:
	if (!err) {
		*offset += sizeof(event_holder->raw_event->event) +
			   event_holder->raw_event->items_data_size;
	}

	return err;
}

static ssize_t _agent_fd_read(struct file *filp, char __user *buffer,
			      size_t buffer_size, loff_t *offset)
{
	esf_agent_t *agent = filp->private_data;
	esf_raw_event_holder_t *event_holder = NULL;
	ssize_t result = 0;

	if (filp->f_op != &_agent_fd_fops) {
		return -EBADFD;
	}

	esf_agent_get(agent);

	int send_err = 0;
	loff_t cur_buff_offset = 0;
	ssize_t events_sent = 0;

	read_lock(&agent->event_queue_lock);
	uint64_t max_events_to_send = agent->events_count;
	read_unlock(&agent->event_queue_lock);

	while (max_events_to_send > 0) {
		write_lock(&agent->event_queue_lock);
		event_holder = list_first_entry(&agent->events_queue,
						esf_raw_event_holder_t, _node);
		list_del(&event_holder->_node);
		agent->events_count--;
		write_unlock(&agent->event_queue_lock);

		BUG_ON(!event_holder->raw_event);

		send_err = _send_event_to_user(buffer, buffer_size,
					       event_holder, &cur_buff_offset);

		if (send_err) {
			write_lock(&agent->event_queue_lock);
			list_add(&event_holder->_node, &agent->events_queue);
			agent->events_count++;
			write_unlock(&agent->event_queue_lock);

			break;
		}

		events_sent++;
		max_events_to_send--;
		_destroy_event_holder(event_holder);
	}

	result = events_sent;

	esf_agent_put(agent);

	return result;
}

static int _agent_fd_release(struct inode *inode, struct file *filp)
{
	if (filp->f_op != &_agent_fd_fops) {
		return -EBADFD;
	}

	esf_agent_t *agent = filp->private_data;

	if (agent->flags & ESF_AGENT_REGISTERED) {
		esf_unregister_agent(agent);
	}

	return 0;
}

esf_agent_t *esf_agent_create(struct task_struct *security_agent_task,
			      gfp_t gfp)
{
	BUG_ON(!security_agent_task);
	BUG_ON(security_agent_task != current);

	esf_agent_t *agent = kzalloc(sizeof(esf_agent_t), gfp);

	if (!agent) {
		return ERR_PTR(-ENOMEM);
	}

	int fd = anon_inode_getfd("[esf]", &_agent_fd_fops, agent,
				  O_NONBLOCK | O_CLOEXEC | O_RDWR);

	if (fd < 0) {
		esf_log_err("Unable to create esf inode, err: %d", fd);
		kfree(agent);
		return ERR_PTR(fd);
	}

	get_task_struct(security_agent_task);

	atomic_set(&agent->refs, 0);

	rwlock_init(&agent->lock);
	INIT_LIST_HEAD(&agent->_node);

	rwlock_init(&agent->event_queue_lock);
	init_waitqueue_head(&agent->events_queue_wq);
	INIT_LIST_HEAD(&agent->events_queue);

	agent->task = security_agent_task;
	agent->fd = fd;

	return esf_agent_get(agent);
}

int esf_agent_enqueue_event(esf_agent_t *agent, esf_raw_event_t *raw_event,
			    gfp_t gfp)
{
	BUG_ON(!raw_event);

	esf_raw_event_get(raw_event);

	esf_raw_event_holder_t *holder = _create_event_holder(raw_event, gfp);

	esf_raw_event_put(raw_event);

	if (!holder) {
		return -ENOMEM;
	}

	BUG_ON(!holder->raw_event);

	write_lock(&agent->event_queue_lock);

	list_add_tail(&holder->_node, &agent->events_queue);
	agent->events_count++;

	write_unlock(&agent->event_queue_lock);

	wake_up_interruptible(&agent->events_queue_wq);

	return 0;
}

bool esf_agent_want_control(const esf_agent_t *agent,
			    esf_event_type_t event_type)
{
	esf_event_category_t category = ESF_EVENT_CATEGORY_NR(event_type);
	uint64_t event_mask = ESF_EVENT_TYPE_MASK(event_type);

	BUG_ON(category >= _ESF_EVENT_CATEGORY_MAX);
	return (agent->want_control_subscriptions[category] & event_mask);
}

bool esf_agent_is_subscribed_to(const esf_agent_t *agent,
				esf_event_type_t event_type)
{
	esf_event_category_t category = ESF_EVENT_CATEGORY_NR(event_type);
	uint64_t event_mask = ESF_EVENT_TYPE_MASK(event_type);

	BUG_ON(category >= _ESF_EVENT_CATEGORY_MAX);
	return (agent->subscriptions[category] & event_mask);
}

esf_agent_t *esf_agent_get(esf_agent_t *agent)
{
	BUG_ON(!agent);

	atomic_inc(&agent->refs);
	return agent;
}

void esf_agent_put(esf_agent_t *agent)
{
	BUG_ON(!agent);

	if (atomic_dec_and_test(&agent->refs)) {
		_esf_agent_destroy(agent);
	}
}