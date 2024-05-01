#ifndef __LINUX_ESF_EVENTS_CHANNEL_H
#define __LINUX_ESF_EVENTS_CHANNEL_H

#include <linux/wait.h>
#include <linux/types.h>
#include <linux/esf/filters.h>

#include "events_queue.h"

struct esf_events_channel;

typedef struct esf_events_channel_ctl {
	void (*on_events_were_read)(struct esf_events_channel *chan,
				    const esf_events_queue_t *queue);
	// tells should event be actually be sent
	bool (*event_filtered)(struct esf_events_channel *chan,
			       esf_raw_event_t *event, esf_filter_t *filter);
	// tells should event be actually be sent
	bool (*event_passed_filters)(struct esf_events_channel *chan,
				     esf_raw_event_t *event,
				     esf_filter_type_t filters_type,
				     size_t filters_count);
	bool (*want_wakeup)(struct esf_events_channel *chan, int64_t event_nr);
	int (*release)(struct esf_events_channel *chan);
} esf_events_channel_ctl_t;

typedef struct esf_events_chan_owner {
	pid_t tgid;
} esf_events_chan_owner_t;

#define ESF_EVENTS_CHAN_FMT_STR "{%d:%d [%lld]}"
#define ESF_EVENTS_CHAN_FMT(chan) \
	(chan)->owner.tgid, (chan)->fd, esf_events_channel_size(chan)

typedef struct esf_events_channel_filter {
	struct list_head _node;
	esf_filter_t filter;
} esf_events_channel_filter_t;

typedef struct esf_events_channel {
	int fd;
	atomic_t refc;
	esf_agent_subscriptions_mask_t subscriptions;
	wait_queue_head_t wq;
	esf_events_queue_t events_queue;
	const esf_events_channel_ctl_t *ctl;
	void *private;
	atomic64_t event_nr;
	esf_events_chan_owner_t owner;

	rwlock_t filters_lock;
	struct list_head filters[__ESF_FILTER_TYPE_NUM];
	size_t filters_count[__ESF_FILTER_TYPE_NUM];
} __randomize_layout esf_events_channel_t;

esf_events_channel_t *esf_events_channel_get(esf_events_channel_t *channel);

void esf_events_channel_put(esf_events_channel_t *channel);

esf_events_channel_t *
esf_events_channel_create(struct task_struct *owner, const char *name,
			  const esf_events_channel_ctl_t *ops, void *private);

int esf_events_channel_send(esf_events_channel_t *channel,
			    esf_raw_event_t *event, gfp_t gfp);

int esf_events_channel_wakeup(esf_events_channel_t *channel);

uint64_t esf_events_channel_size(esf_events_channel_t *channel);

#endif //__LINUX_ESF_EVENTS_CHANNEL_H
