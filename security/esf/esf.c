#include <linux/module.h>
#include <linux/kconfig.h>
#include <linux/lsm_hooks.h>
#include <linux/netlink.h>
#include <linux/miscdevice.h>
#include <linux/hashtable.h>
#include <linux/digsig.h>
#include <linux/esf.h>

#include <linux/module_signature.h>
#include <linux/verification.h>
#include <linux/security.h>
#include <crypto/public_key.h>

#include <uapi/linux/esf/defs.h>
#include <uapi/linux/esf/ctl.h>
#include <linux/key-type.h>

#include "agent.h"
#include "esf.h"
#include "log.h"
#include "hooks.h"
#include "blobs.h"

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
	esf_agent_subscriptions_mask_t agents_subscriptions;
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

		esf_agent_combine_subscriptions(agent,
						&_context.agents_subscriptions);
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
		     agent->control_fd);

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
	esf_action_decision_t decision = ESF_ACTION_DECISION_ALLOW;

	BUG_ON(!raw_event);

	esf_raw_event_get(raw_event);

	int listeners_num = 0;
	esf_agent_t *listener_agents[CONFIG_SECURITY_ESF_MAX_AGENTS];
	memset(listener_agents, 0, sizeof(listener_agents));

	int authorizers_num = 0;
	esf_agent_t *auth_agents[CONFIG_SECURITY_ESF_MAX_AGENTS];
	memset(auth_agents, 0, sizeof(listener_agents));

	read_lock(&_context.agents_lock);

	// collecting info about agents
	list_for_each_entry(agent, &_context.agents, _node) {
		esf_agent_get(agent);

		// agent is not active, do not send event to this one
		if (!(agent->flags & ESF_AGENT_ACTIVE)) {
			goto put_agent;
		}

		// agent is not subscribed to this event type, do not send event to this one
		if (esf_agent_listens_to(agent, raw_event->event.header.type)) {
			// agent active and subscribed to this event type, write to broadcast
			// table and ref up agent (will be putted after sending event)
			listener_agents[listeners_num] = agent;
			listeners_num++;
			esf_agent_get(agent);
		}

		if (esf_agent_authorizes(agent, raw_event->event.header.type) &&
		    (raw_event->event.header.flags & ESF_EVENT_CAN_CONTROL)) {
			// agent active and can authorize this event
			auth_agents[authorizers_num] = agent;
			authorizers_num++;
			esf_agent_get(agent);
		}

put_agent:
		esf_agent_put(agent);
	}

	read_unlock(&_context.agents_lock);

	// authorizers more than 0, set waits to auth flag to event
	if (authorizers_num > 0) {
		raw_event->event.header.flags |= ESF_EVENT_WAITS_FOR_AUTH;

		if (flags & ESF_SUBMIT_WAIT_FOR_DECISION) {
			// add this event to wait table with calculated
			// amount of agents which will make decision
			esf_raw_event_add_to_decision_wait_table(
				raw_event, authorizers_num);
		}
	}

	// broadcast event to all agents want to authorize this one
	for (int i = 0; i < authorizers_num; i++) {
		esf_agent_t *auth_agent = auth_agents[i];
		esf_agent_enqueue_event(auth_agent, raw_event, gfp);
		esf_agent_put(auth_agent);
	}

#ifdef CONFIG_DEBUG_TRACE_LOG_DECISIONS
	if (authorizers_num == 0 &&
	    raw_event->event.header.flags & ESF_EVENT_CAN_CONTROL) {
		esf_log_debug("Nobody want control " RAW_EVENT_FMT_STR,
			      RAW_EVENT_FMT(raw_event));
	}
#endif

	// if any (at least one) agent want to control this event, we should
	// wait for decision from all agents
	if (authorizers_num > 0 && (flags & ESF_SUBMIT_WAIT_FOR_DECISION)) {
#ifdef CONFIG_DEBUG_TRACE_LOG_DECISIONS
		esf_log_debug("%d agents want control " RAW_EVENT_FMT_STR,
			      authorizers_num, RAW_EVENT_FMT(raw_event));
#endif
		// and finally wait for decision
		decision = esf_raw_event_wait_for_decision(raw_event);

		// decision made at this point, unset waits for auth flag
		raw_event->event.header.flags &= ~ESF_EVENT_WAITS_FOR_AUTH;
		raw_event->event.header.flags &= ~ESF_EVENT_CAN_CONTROL;

		// and set corresponding decision flag
		if (decision == ESF_ACTION_DECISION_ALLOW) {
			raw_event->event.header.flags |= ESF_EVENT_AUTHORIZED;
		} else {
			raw_event->event.header.flags |= ESF_EVENT_DENIED;
		}
	} else {
		raw_event->event.header.flags &= ~ESF_EVENT_CAN_CONTROL;
		raw_event->event.header.flags |= ESF_EVENT_AUTHORIZED;
	}

	// broadcast event to all agents want to listen to this one
	for (int i = 0; i < listeners_num; i++) {
		esf_agent_t *listener_agent = listener_agents[i];
		esf_agent_enqueue_event(listener_agent, raw_event, gfp);
		esf_agent_put(listener_agent);
	}

	esf_raw_event_put(raw_event);

	return decision == ESF_ACTION_DECISION_ALLOW ? 0 : -EPERM;
}

int esf_submit_raw_event(esf_raw_event_t *raw_event, gfp_t gfp)
{
	return esf_submit_raw_event_ex(raw_event, gfp, ESF_SUBMIT_SIMPLE);
}

static int _esf_signature_verify(struct task_struct *agent_task)
{
	const unsigned long marker_len = sizeof(MODULE_SIG_STRING) - 1;
	int err = 0;
	uint8_t *file_data = NULL;
	size_t file_len = 0, sig_len = 0;

	struct mm_struct *mm = agent_task->mm;

	if (!mm) {
		err = -EFAULT;
		goto out;
	}
	ssize_t read = kernel_read_file(mm->exe_file, 0, (void **)&file_data,
					INT_MAX, &file_len, READING_MODULE);

	if (read < 0) {
		err = (int)read;
		goto out;
	}

	if (file_data == NULL) {
		err = -EFAULT;
		goto out;
	}

	/* We truncate the file data to discard the signature */
	if (file_len > marker_len &&
	    memcmp(file_data + file_len - marker_len, MODULE_SIG_STRING,
		   marker_len) == 0) {
		file_len -= marker_len;
	}

	if (file_len <= sizeof(struct module_signature)) {
		err = -EBADMSG;
		goto out;
	}

	struct module_signature *ms =
		(void *)(file_data + (file_len - sizeof(*ms)));

	err = mod_check_sig(ms, file_len, "ESF agent");

	if (err) {
		goto out;
	}

	sig_len = be32_to_cpu(ms->sig_len);
	file_len -= sig_len + sizeof(*ms);

	err = verify_pkcs7_signature(file_data, file_len, file_data + file_len,
				     sig_len, VERIFY_USE_SECONDARY_KEYRING,
				     VERIFYING_MODULE_SIGNATURE, NULL, NULL);

out:
	if (file_data != NULL) {
		kvfree(file_data);
	}

	return err;
}

int _do_esf_register_agent_ioctl(struct task_struct *agent_task,
				 esf_ctl_register_agent_t *register_cmd)
{
	esf_agent_t *new_agent = NULL;
	int err;

	err = _esf_signature_verify(agent_task);

	if (err) {
		const char *reason = "unknown";

		switch (err) {
		case -ENODATA:
			reason = "unsigned agent";
			break;
		case -ENOPKG:
			reason = "agent with unsupported crypto";
			break;
		case -ENOKEY:
			reason = "agent with unavailable key";
			break;
		default:
			break;
		}

		esf_log_err("Agent signature verification failed, error: %s %d",
			    reason, err);

		return err;
	}

	esf_log_info("Signature verified");

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
	return err ? err : new_agent->control_fd;
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

DEFINE_LSM(esf) = {
	.name = "esf",
	.init = _esf_init,
	.blobs = &esf_blobs,
};