#ifndef __LINUX_ESF_AGENT_H
#define __LINUX_ESF_AGENT_H

#include <uapi/linux/esf/defs.h>

#include <linux/sched/task.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/list.h>

#include "events_channel.h"
#include "event.h"

typedef enum esf_agent_flags {
	ESF_AGENT_REGISTERED = 1 << 0,
	ESF_AGENT_ACTIVE = 1 << 1,
} esf_agent_flags_t;

typedef struct esf_agent {
	struct list_head _node;
	struct task_struct *task;
	atomic_t refs;
	rwlock_t lock;
	int control_fd;
	esf_agent_flags_t flags;

	esf_events_channel_t *_auth_channel;
	esf_events_channel_t *_listen_channel;
} __randomize_layout esf_agent_t;

esf_agent_t *esf_agent_create(struct task_struct *security_agent_task,
			      gfp_t gfp);

bool esf_agent_authorizes(const esf_agent_t *agent,
			    esf_event_type_t event_type);

void esf_agent_get_subscriptions(const esf_agent_t *agent,
				 esf_agent_subscriptions_mask_t *out);

void esf_agent_combine_subscriptions(const esf_agent_t *agent,
				     esf_agent_subscriptions_mask_t *out);

bool esf_agent_listens_to(const esf_agent_t *agent,
			  esf_event_type_t event_type);

int esf_agent_enqueue_event(esf_agent_t *agent, esf_raw_event_t *event,
			    gfp_t gfp);

esf_agent_t *esf_agent_get(esf_agent_t *agent);

void esf_agent_put(esf_agent_t *agent);

#endif /* __LINUX_ESF_AGENT_H */
