#include "agent.h"
#include "log.h"
#include "esf.h"

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/anon_inodes.h>
#include <linux/esf/ctl.h>
#include <linux/kthread.h>
#include <linux/delay.h>

typedef enum {
	AGENT_LISTEN_CHANNEL_BEHAVIOUR_POLICY,
	AGENT_AUTH_CHANNEL_BEHAVIOUR_POLICY,
} _agent_channel_behaviour_policy;

typedef struct _agent_channel_private_data {
	esf_events_channel_t **agent_channel_ptr;
	esf_agent_t *agent;
	_agent_channel_behaviour_policy policy;

	/* data for policies */
	union {
		struct {
			uint64_t wake_up_period;
			uint64_t wake_up_period_ms;
			struct task_struct *channel_alarm;
		} listen;
		struct {
		} auth;
	} behaviour;
} _agent_channel_private_data_t;

static bool _agent_chan_wakeup(struct esf_events_channel *chan,
			       int64_t event_nr)
{
	_agent_channel_private_data_t *dat = chan->private;

	switch (dat->policy) {
	case AGENT_LISTEN_CHANNEL_BEHAVIOUR_POLICY: {
		return (event_nr % dat->behaviour.listen.wake_up_period) == 0;
	}
	case AGENT_AUTH_CHANNEL_BEHAVIOUR_POLICY: {
		return true;
	}
	}

	return true;
}

static bool _agent_chan_event_passed_filters(struct esf_events_channel *chan,
					     esf_raw_event_t *event,
					     esf_filter_type_t filters_type,
					     size_t filters_count)
{
	_agent_channel_private_data_t *dat = chan->private;

	switch (dat->policy) {
	case AGENT_LISTEN_CHANNEL_BEHAVIOUR_POLICY: {
		switch (filters_type) {
		case ESF_FILTER_TYPE_ALLOW:
			// event passed allow filters on listen channel
			// drop event, because no one filter allows it
			return false;
		default:
		case ESF_FILTER_TYPE_DROP:
			// event passed drop filters on listen channel
			// allow event, because no one filter drops it
			return true;
		}
	} break;
	case AGENT_AUTH_CHANNEL_BEHAVIOUR_POLICY: {
		// send this event anyway to ask agent for decision
		return true;
	} break;
	}

	return true;
}

static bool _agent_chan_event_filtered(struct esf_events_channel *chan,
				       esf_raw_event_t *raw_event,
				       esf_filter_t *filter)
{
	_agent_channel_private_data_t *dat = chan->private;

	switch (dat->policy) {
	case AGENT_LISTEN_CHANNEL_BEHAVIOUR_POLICY: {
		switch (filter->type) {
		case ESF_FILTER_TYPE_ALLOW:
			return true;
		default:
		case ESF_FILTER_TYPE_DROP:
			esf_log_debug(RAW_EVENT_FMT_STR " filtered",
				      RAW_EVENT_FMT(raw_event));
			return false;
		}
	} break;
	case AGENT_AUTH_CHANNEL_BEHAVIOUR_POLICY: {
		switch (filter->type) {
		case ESF_FILTER_TYPE_ALLOW:
			esf_raw_event_make_decision(raw_event,
						    ESF_ACTION_DECISION_ALLOW);
			esf_log_debug(RAW_EVENT_FMT_STR " allowed by filter",
				      RAW_EVENT_FMT(raw_event));

			return false;
		default:
		case ESF_FILTER_TYPE_DROP:
			esf_raw_event_make_decision(raw_event,
						    ESF_ACTION_DECISION_DENY);
			esf_log_debug(RAW_EVENT_FMT_STR " declined by filter",
				      RAW_EVENT_FMT(raw_event));

			return false;
		}
	} break;
	}

	return true;
}

static int _agent_chan_release(struct esf_events_channel *chan)
{
	_agent_channel_private_data_t *data = chan->private;

	BUG_ON(!data);
	BUG_ON(!data->agent_channel_ptr);

	if (data->policy == AGENT_LISTEN_CHANNEL_BEHAVIOUR_POLICY &&
	    data->behaviour.listen.channel_alarm) {
		kthread_stop(data->behaviour.listen.channel_alarm);
	}

	// just zero field at agent holder, channel will deinitialize self
	*data->agent_channel_ptr = NULL;

	kfree(data);
	return 0;
}

static const esf_events_channel_ctl_t _agent_events_chan_fops = {
	.want_wakeup = _agent_chan_wakeup,
	.event_passed_filters = _agent_chan_event_passed_filters,
	.event_filtered = _agent_chan_event_filtered,
	.release = _agent_chan_release,
};

static int _agent_fd_release(struct inode *inode, struct file *filp);
static long _agent_fd_ioctl(struct file *, unsigned int, unsigned long);

static struct file_operations _agent_fd_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = _agent_fd_ioctl,
	.release = _agent_fd_release,
};

static long _do_agent_open_auth_channel_ioctl(
	struct esf_agent *agent,
	esf_agent_ctl_open_auth_channel_t *open_auth_channel)
{
	if (agent->_auth_channel != NULL) {
		return -EALREADY;
	}

	_agent_channel_private_data_t *dat =
		kzalloc(sizeof(_agent_channel_private_data_t), GFP_KERNEL);

	if (!dat) {
		return -ENOMEM;
	}

	dat->policy = AGENT_AUTH_CHANNEL_BEHAVIOUR_POLICY;
	dat->agent = agent;
	dat->agent_channel_ptr = &agent->_auth_channel;

	esf_events_channel_t *chan = esf_events_channel_create(
		agent->task, "[esf:auth]", &_agent_events_chan_fops, dat);

	if (IS_ERR_OR_NULL(chan)) {
		kfree(dat);
		return PTR_ERR(chan);
	}

	agent->_auth_channel = chan;
	open_auth_channel->channel_fd = chan->fd;

	return 0;
}

static int _events_flusher(void *data)
{
	_agent_channel_private_data_t *dat = data;

	while (!kthread_should_stop()) {
		esf_events_channel_t *chan = *dat->agent_channel_ptr;

		// not valid channel
		if (!chan) {
			esf_log_warn("Events channel is NULL");
			break;
		}

		uint64_t events_in_chan = esf_events_channel_size(chan);

		if (events_in_chan > 0) {
			esf_log_debug("Alarming channel due it has %llu events",
				      events_in_chan);
			esf_events_channel_wakeup(chan);
		}

		msleep_interruptible(100);
	}

	esf_log_warn("Flusher stopped");

	return 0;
}

static long _do_agent_open_listen_channel_ioctl(
	struct esf_agent *agent,
	esf_agent_ctl_open_listen_channel_t *open_listen_channel)
{
	if (agent->_listen_channel != NULL) {
		return -EALREADY;
	}

	_agent_channel_private_data_t *dat =
		kzalloc(sizeof(_agent_channel_private_data_t), GFP_KERNEL);

	if (!dat) {
		return -ENOMEM;
	}

	dat->policy = AGENT_LISTEN_CHANNEL_BEHAVIOUR_POLICY;
	dat->agent = agent;
	dat->agent_channel_ptr = &agent->_listen_channel;
	dat->behaviour.listen.wake_up_period = 100;
	dat->behaviour.listen.wake_up_period_ms = 100;

	esf_events_channel_t *chan = esf_events_channel_create(
		agent->task, "[esf:listen]", &_agent_events_chan_fops, dat);

	if (IS_ERR_OR_NULL(chan)) {
		return PTR_ERR(chan);
	}

	agent->_listen_channel = chan;
	open_listen_channel->channel_fd = chan->fd;

	dat->behaviour.listen.channel_alarm =
		kthread_run(_events_flusher, dat, "esf_alarm[%d:%d]",
			    agent->task->tgid, chan->fd);

	return 0;
}

static long
_do_agent_activate_ioctl(esf_agent_t *agent,
			 const esf_agent_ctl_activate_t *activate_cmd)
{
	esf_log_info("Activating agent %d", agent->task->tgid);
	esf_bitmask_buff_64_t mask_buff = { 0 };

	if (agent->_auth_channel) {
		esf_log_debug("Auth channel %d:%d", agent->task->tgid,
			      agent->_auth_channel->fd);

		for (int i = 0; i < _ESF_EVENT_CATEGORY_MAX; ++i) {
			esf_print_bitmask_64(
				agent->_auth_channel->subscriptions[i],
				mask_buff);
			esf_log_debug("\tsub mask %d: %s", i, mask_buff);
		}
	} else {
		esf_log_debug("Auth channel is not registered for agent %d",
			      agent->task->tgid);
	}

	if (agent->_listen_channel) {
		esf_log_debug("Listen channel %d:%d", agent->task->tgid,
			      agent->_listen_channel->fd);

		for (int i = 0; i < _ESF_EVENT_CATEGORY_MAX; ++i) {
			esf_print_bitmask_64(
				agent->_listen_channel->subscriptions[i],
				mask_buff);
			esf_log_debug("\tsub mask %d: %s", i, mask_buff);
		}
	} else {
		esf_log_debug("Listen channel is not registered for agent %d",
			      agent->task->tgid);
	}

	agent->flags |= ESF_AGENT_ACTIVE;

	esf_update_active_subscriptions_mask();

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
	case ESF_AGENT_CTL_OPEN_AUTH_CHANNEL: {
		esf_agent_ctl_open_auth_channel_t open_auth_chan_cmd;
		if (copy_from_user(&open_auth_chan_cmd, (const void *)arg,
				   sizeof(open_auth_chan_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}

		res = _do_agent_open_auth_channel_ioctl(agent,
							&open_auth_chan_cmd);

		if (copy_to_user((void *)arg, &open_auth_chan_cmd,
				 sizeof(open_auth_chan_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}
	} break;
	case ESF_AGENT_CTL_OPEN_LISTEN_CHANNEL: {
		esf_agent_ctl_open_listen_channel_t open_listen_chan_cmd;
		if (copy_from_user(&open_listen_chan_cmd, (const void *)arg,
				   sizeof(open_listen_chan_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}

		res = _do_agent_open_listen_channel_ioctl(
			agent, &open_listen_chan_cmd);

		if (copy_to_user((void *)arg, &open_listen_chan_cmd,
				 sizeof(open_listen_chan_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}
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

	agent->task = security_agent_task;
	agent->control_fd = fd;

	return esf_agent_get(agent);
}

int esf_agent_enqueue_event(esf_agent_t *agent, esf_raw_event_t *raw_event,
			    gfp_t gfp)
{
	BUG_ON(!raw_event);

	if (!(agent->flags & ESF_AGENT_ACTIVE)) {
		return -EAGAIN;
	}

	esf_raw_event_get(raw_event);

	bool event_controllable =
		(raw_event->event.header.flags & ESF_EVENT_CAN_CONTROL);
	bool agent_controls_event =
		esf_agent_authorizes(agent, raw_event->event.header.type);

	if (event_controllable && agent_controls_event) {
		esf_events_channel_send(agent->_auth_channel, raw_event, gfp);
	} else if (agent->_listen_channel) {
		esf_events_channel_send(agent->_listen_channel, raw_event, gfp);
	}

	esf_raw_event_put(raw_event);

	return 0;
}

static bool _is_subscribed(esf_agent_subscriptions_mask_t mask,
			   esf_event_type_t event_type)
{
	esf_event_category_t category = ESF_EVENT_CATEGORY_NR(event_type);
	uint64_t event_mask = ESF_EVENT_TYPE_MASK(event_type);
	BUG_ON(category >= _ESF_EVENT_CATEGORY_MAX);
	return (mask[category] & event_mask);
}

noinline bool esf_agent_authorizes(const esf_agent_t *agent,
				   esf_event_type_t event_type)
{
	if (!agent->_auth_channel) {
		return false;
	}

	return _is_subscribed(agent->_auth_channel->subscriptions, event_type);
}

noinline bool esf_agent_listens_to(const esf_agent_t *agent,
				   esf_event_type_t event_type)
{
	if (!agent->_listen_channel) {
		return false;
	}

	return _is_subscribed(agent->_listen_channel->subscriptions,
			      event_type);
}

void esf_agent_get_subscriptions(const esf_agent_t *agent,
				 esf_agent_subscriptions_mask_t *out)
{
	memset(*out, 0, sizeof(*out));
	esf_agent_combine_subscriptions(agent, out);
}

void esf_agent_combine_subscriptions(const esf_agent_t *agent,
				     esf_agent_subscriptions_mask_t *out)
{
	if (agent->_auth_channel) {
		for (int i = 0; i < _ESF_EVENT_CATEGORY_MAX; ++i) {
			(*out)[i] |= agent->_auth_channel->subscriptions[i];
		}
	}

	if (agent->_listen_channel) {
		for (int i = 0; i < _ESF_EVENT_CATEGORY_MAX; ++i) {
			(*out)[i] |= agent->_listen_channel->subscriptions[i];
		}
	}
}

esf_agent_t *esf_agent_get(esf_agent_t *agent)
{
	BUG_ON(!agent);

	atomic_inc(&agent->refs);
	return agent;
}

static void _esf_agent_destroy(esf_agent_t *agent)
{
	agent->flags = 0;
	put_task_struct(agent->task);
	kfree(agent);
}

void esf_agent_put(esf_agent_t *agent)
{
	BUG_ON(!agent);

	if (atomic_dec_and_test(&agent->refs)) {
		_esf_agent_destroy(agent);
	}
}