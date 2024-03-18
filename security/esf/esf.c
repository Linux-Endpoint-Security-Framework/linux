#include <linux/module.h>
#include <linux/kconfig.h>
#include <linux/lsm_hooks.h>
#include <linux/netlink.h>
#include <linux/miscdevice.h>
#include <linux/hashtable.h>

#include <uapi/linux/esf/defs.h>
#include <uapi/linux/esf/ctl.h>

#include "agent.h"
#include "esf.h"
#include "log.h"
#include "hooks.h"

static bool verify_sig = IS_ENABLED(CONFIG_SECURITY_CHECK_SIGNATURE);
module_param(verify_sig, bool, 0600);
MODULE_PARM_DESC(verify_sig, "Enable agent signature verification");

static int max_agents = CONFIG_SECURITY_ESF_MAX_AGENTS;
module_param(max_agents, int, 0600);
MODULE_PARM_DESC(max_agents,
		 "Specify maximum agents can be registered, (<" esf_str(
			 CONFIG_SECURITY_MAX_AGENTS) ")");

static struct {
	rwlock_t agents_lock;
	uint32_t agents_count;
	struct list_head agents;
	// summary mask for all subscriptions, can be updated via esf_update_active_subscriptions_mask
	esf_agent_subscriptions_mask agents_subscriptions;
} __randomize_layout _context;

void esf_update_active_subscriptions_mask(void)
{
	ulong irq_flags = 0;
	esf_agent_t *agent = NULL;

	read_lock_irqsave(&_context.agents_lock, irq_flags);

	esf_log_debug("Updating active subscriptions summary");

	// zero all masks
	memset(_context.agents_subscriptions, 0,
	       sizeof(_context.agents_subscriptions));

	list_for_each_entry(agent, &_context.agents, _node) {
		// we're not interested in non-active agents
		if (!(agent->flags & ESF_AGENT_ACTIVE)) {
			continue;
		}

		for (int i = 0; i < _ESF_EVENT_CATEGORY_MAX; ++i) {
			_context.agents_subscriptions[i] |=
				agent->subscriptions[i];
		}
	}

	esf_bitmask_buff_64_t mask_buff = { 0 };

	for (int i = 0; i < _ESF_EVENT_CATEGORY_MAX; ++i) {
		esf_print_bitmask_64(_context.agents_subscriptions[i],
				     mask_buff);
		esf_log_debug("\tsummary mask %d: %s", i, mask_buff);
	}

	read_unlock_irqrestore(&_context.agents_lock, irq_flags);
}

bool esf_anyone_subscribed_to(esf_event_type_t type)
{
	ulong irq_flags = 0;
	bool subscribed = false;

	esf_event_category_t category = ESF_EVENT_CATEGORY_NR(type);
	uint64_t event_mask = ESF_EVENT_TYPE_MASK(type);

	read_lock_irqsave(&_context.agents_lock, irq_flags);
	subscribed = _context.agents_subscriptions[category] & event_mask;
	read_unlock_irqrestore(&_context.agents_lock, irq_flags);

	return subscribed;
}

int esf_unregister_agent(esf_agent_t *agent)
{
	BUG_ON(!agent);
	BUG_ON(!(agent->flags & ESF_AGENT_REGISTERED));

	ulong irq_flags = 0;

	agent->flags &= ~ESF_AGENT_REGISTERED;
	agent->flags &= ~ESF_AGENT_ACTIVE;

	esf_log_info("Unregistering agent %d (%d)", agent->task->tgid,
		     agent->fd);

	write_lock_irqsave(&_context.agents_lock, irq_flags);
	list_del(&agent->_node);
	_context.agents_count--;
	write_unlock_irqrestore(&_context.agents_lock, irq_flags);

	esf_update_active_subscriptions_mask();

	esf_agent_put(agent);
	return 0;
}

int esf_register_agent(esf_agent_t *agent)
{
	BUG_ON(!agent);

	ulong irq_flags = 0;
	int err = 0;

	if (agent->flags & ESF_AGENT_REGISTERED) {
		return -EISCONN;
	}

	esf_agent_get(agent);

	write_lock_irqsave(&_context.agents_lock, irq_flags);

	if (_context.agents_count >= max_agents) {
		err = -EACCES;
		goto out;
	}

	esf_log_info("Registering agent %d", agent->task->tgid);

	list_add_tail(&agent->_node, &_context.agents);
	// grab the reference until agent will get unregistered
	esf_agent_get(agent);
	_context.agents_count++;
	agent->flags |= ESF_AGENT_REGISTERED;

out:
	write_unlock_irqrestore(&_context.agents_lock, irq_flags);

	if (err) {
		esf_log_err(
			"Maximum agents count (%d) reached, rejecting registration for new one",
			max_agents);
	}

	esf_agent_put(agent);

	return err;
}

uint32_t esf_get_agents_count(void)
{
	uint32_t agent_count = 0;
	ulong irq_flags = 0;

	read_lock_irqsave(&_context.agents_lock, irq_flags);
	agent_count = _context.agents_count;
	read_unlock_irqrestore(&_context.agents_lock, irq_flags);

	return agent_count;
}

int esf_submit_raw_event_ex(esf_raw_event_t *raw_event, gfp_t gfp,
			    esf_submit_flags_t flags)
{
	esf_agent_t *agent = NULL;
	int agents_want_control = 0;
	esf_action_decision_t decision = ESF_ACTION_DECISION_ALLOW;

	BUG_ON(!raw_event);

	esf_raw_event_get(raw_event);

	int receivers_num = 0;
	esf_agent_t *receiver_agents[CONFIG_SECURITY_ESF_MAX_AGENTS];
	memset(receiver_agents, 0, sizeof(receiver_agents));

	read_lock(&_context.agents_lock);

	list_for_each_entry(agent, &_context.agents, _node) {
		esf_agent_get(agent);

		// agent is not active, do not send event to this one
		if (!(agent->flags & ESF_AGENT_ACTIVE)) {
			goto put_agent;
		}

		// agent is not subscribed to this event type, do not send event to this one
		if (!esf_agent_is_subscribed_to(agent,
						raw_event->event.header.type)) {
			goto put_agent;
		}

		// agent active and subscribed to this event type, write to broadcast
		// table ref up (will be putted after sending event)
		receiver_agents[receivers_num] = agent;
		receivers_num++;
		esf_agent_get(agent);

		// if this event can be controlled by this agent and agent
		// also wants to control this event increment want control counter
		if ((raw_event->event.header.flags & ESF_EVENT_CAN_CONTROL) &&
		    esf_agent_want_control(agent,
					   raw_event->event.header.type)) {
			agents_want_control++;
		}

put_agent:
		esf_agent_put(agent);
	}

	read_unlock(&_context.agents_lock);

	// broadcast event to all agents want to receive this one
	for (int i = 0; i < receivers_num; i++) {
		esf_agent_t *receiver_agent = receiver_agents[i];
		esf_agent_enqueue_event(receiver_agent, raw_event, gfp);
		esf_agent_put(receiver_agent);
	}

	if (agents_want_control == 0 &&
	    raw_event->event.header.flags & ESF_EVENT_CAN_CONTROL) {
#ifdef CONFIG_DEBUG_TRACE_LOG_DECISIONS
		esf_log_debug("Nobody want control " RAW_EVENT_FMT_STR,
			      RAW_EVENT_FMT(raw_event));
#endif
	}

	// if any at least one agent want to control this event, we should
	// wait for decision from all agents
	if (agents_want_control > 0 && (flags & ESF_SUBMIT_WAIT_FOR_DECISION)) {
#ifdef CONFIG_DEBUG_TRACE_LOG_DECISIONS
		esf_log_debug("%d agents want control " RAW_EVENT_FMT_STR,
			      agents_want_control, RAW_EVENT_FMT(raw_event));
#endif

		// add this event to wait table with calculated
		// amount of agents which will make decision
		esf_raw_event_add_to_decision_wait_table(raw_event,
							 agents_want_control);

		// and finally wait for decision
		decision = esf_raw_event_wait_for_decision(raw_event);
	}

	esf_raw_event_put(raw_event);

	return decision == ESF_ACTION_DECISION_ALLOW ? 0 : -EPERM;
}

int esf_submit_raw_event(esf_raw_event_t *raw_event, gfp_t gfp)
{
	return esf_submit_raw_event_ex(raw_event, gfp, ESF_SUBMIT_SIMPLE);
}

static long _esf_signature_verify(struct task_struct *agent_task,
				  esf_ctl_register_agent_t *register_cmd)
{
	// todo: implement signature versification
	esf_log_warn("Agent signature verification is currently unsupported");
	return 0;
}

static long _do_esf_register_agent_ioctl(struct task_struct *agent_task,
					 esf_ctl_register_agent_t *register_cmd)
{
	long err = 0;
	esf_agent_t *new_agent = NULL;

	if (register_cmd->api_version != ESF_VERSION) {
		esf_log_err(
			"Agent %d registration avoided because of incompatible API version",
			agent_task->tgid);
		err = -EFAULT;
		goto out;
	}

	if (verify_sig) {
		err = _esf_signature_verify(agent_task, register_cmd);

		if (err) {
			goto out;
		}
	}

	new_agent = esf_agent_create(agent_task, GFP_KERNEL);

	if (IS_ERR(new_agent)) {
		err = PTR_ERR(new_agent);
		goto out;
	}

	err = esf_register_agent(new_agent);

out:
	if (new_agent) {
		esf_agent_put(new_agent);
	}

	// error or file descriptor
	return err ? err : new_agent->fd;
}

long _esf_dev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long res = -ENOTSUPP;

	switch (cmd) {
	case ESF_CTL_GET_SUBSYSTEM_INFO: {
		goto out;
	} break;
	case ESF_CTL_REGISTER_AGENT: {
		esf_ctl_register_agent_t register_cmd;
		if (copy_from_user(&register_cmd, (const void *)arg,
				   sizeof(register_cmd)) > 0) {
			res = -EFAULT;
			goto out;
		}
		res = _do_esf_register_agent_ioctl(current, &register_cmd);
	} break;
	default: {
		res = -ENOIOCTLCMD;
	} break;
	}

out:
	return res;
}

static struct file_operations _chdev_fops = {
	.owner = THIS_MODULE,
	.llseek = no_llseek,
	.unlocked_ioctl = _esf_dev_ioctl,
};

static struct miscdevice _dev = {
	MISC_DYNAMIC_MINOR,
	"esf",
	&_chdev_fops,
};

int _esf_device_init(void)
{
	int err = 0;

	esf_log_info("Creating '%s' device", _dev.name);

	err = misc_register(&_dev);

	if (err) {
		esf_log_err("Unable to register misc device");
	}

	return err;
}

device_initcall(_esf_device_init);

static int __init _esf_init(void)
{
	int err = 0;

	memset(&_context, 0, sizeof(_context));
	rwlock_init(&_context.agents_lock);
	INIT_LIST_HEAD(&_context.agents);

	esf_hooks_init();

	esf_log_info("Initializing ESF subsystem");
	esf_log_info(
		"\tMax agents: %d/" esf_str(CONFIG_SECURITY_ESF_MAX_AGENTS),
		max_agents);
	esf_log_info("\tSignature verification: %s",
		     verify_sig ? "enabled" : "disabled");

	if (!verify_sig) {
		esf_log_warn("Agent signature verification disabled!");
	}

	return err;
}

static int __exit _esf_exit(void)
{
	return 0;
}

static struct lsm_blob_sizes _esf_blobs = {
	.lbs_task = sizeof(esf_process_lsb_t),
	.lbs_cred = 0,
	.lbs_file = 0,
	.lbs_inode = 0,
	.lbs_superblock = 0,
	.lbs_ipc = 0,
	.lbs_msg_msg = 0,
	.lbs_xattr_count = 0,
};

DEFINE_LSM(esf) = {
	.name = "esf",
	.init = _esf_init,
	.blobs = &_esf_blobs,
};