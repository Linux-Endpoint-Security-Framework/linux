#ifndef __LINUX_ESF_EVENTS_QUEUE_H
#define __LINUX_ESF_EVENTS_QUEUE_H

#include <linux/poll.h>
#include <linux/list.h>
#include <linux/types.h>
#include <linux/rwlock.h>
#include "event.h"

typedef struct esf_raw_event_holder esf_raw_event_holder_t;

void esf_put_raw_event_holder(esf_raw_event_holder_t *holder);

esf_raw_event_holder_t *
esf_get_raw_event_holder(esf_raw_event_holder_t *holder);

esf_raw_event_t *esf_raw_event_holder_deref(const esf_raw_event_holder_t *holder);

typedef struct esf_events_queue {
	rwlock_t _event_queue_lock;
	uint64_t _events_count;
	struct list_head _events_queue; // esf_agent_raw_item_holder_t
} esf_events_queue_t;

void esf_event_queue_init(esf_events_queue_t *queue);

void esf_event_queue_deinit(esf_events_queue_t *queue);

size_t esf_event_queue_size(esf_events_queue_t *queue);

esf_raw_event_holder_t *esf_event_queue_enqueue_back(esf_events_queue_t *queue,
						     esf_raw_event_t *event,
						     gfp_t gfp);

esf_raw_event_holder_t *esf_event_queue_enqueue(esf_events_queue_t *queue,
						esf_raw_event_t *event,
						gfp_t gfp);

esf_raw_event_holder_t *esf_event_queue_dequeue(esf_events_queue_t *queue);

esf_raw_event_holder_t *esf_event_queue_hold(esf_events_queue_t *queue);

void esf_event_queue_release_held(esf_raw_event_holder_t *held_holder);

void esf_event_queue_dequeue_held(esf_raw_event_holder_t *held_holder);

#endif //__LINUX_ESF_EVENTS_QUEUE_H
