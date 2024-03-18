#ifndef __LINUX_ESF_AGENT_H
#define __LINUX_ESF_AGENT_H

#include <uapi/linux/esf/defs.h>

#include <linux/sched/task.h>
#include <linux/atomic.h>
#include <linux/slab.h>
#include <linux/list.h>

#include "event.h"

typedef enum esf_agent_flags {
	ESF_AGENT_REGISTERED = 1 << 0,
	ESF_AGENT_ACTIVE = 1 << 1,
} esf_agent_flags_t;

typedef uint64_t esf_agent_subscriptions_mask[_ESF_EVENT_CATEGORY_MAX + 1];

typedef struct esf_raw_event_holder {
	struct list_head _node;
	esf_raw_event_t *raw_event;
	atomic_t refc;
} esf_raw_event_holder_t;

typedef struct esf_agent {
	struct list_head _node;
	struct task_struct *task;
	atomic_t refs;
	rwlock_t lock;
	int fd;
	esf_agent_flags_t flags;
	esf_agent_subscriptions_mask subscriptions;
	esf_agent_subscriptions_mask want_control_subscriptions;

	wait_queue_head_t events_queue_wq;
	rwlock_t event_queue_lock;
	uint64_t events_count;
	uint64_t events_notify_count;
	uint64_t events_last_notify;
	struct list_head events_queue; // esf_agent_raw_item_holder_t
} __randomize_layout esf_agent_t;

esf_agent_t* esf_agent_create(struct task_struct *security_agent_task, gfp_t gfp);

bool esf_agent_want_control(const esf_agent_t *agent,
			    esf_event_type_t event_type);

bool esf_agent_is_subscribed_to(const esf_agent_t* agent, esf_event_type_t event_type);

int esf_agent_enqueue_event(esf_agent_t* agent, esf_raw_event_t* event, gfp_t gfp);

esf_agent_t* esf_agent_get(esf_agent_t* agent);

void esf_agent_put(esf_agent_t* agent);

#endif /* __LINUX_ESF_AGENT_H */
