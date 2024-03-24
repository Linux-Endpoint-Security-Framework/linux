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

esf_raw_event_t *
esf_raw_event_holder_deref(const esf_raw_event_holder_t *holder);

typedef struct esf_events_queue {
	rwlock_t __lock;
	uint64_t __count;
	struct list_head __queue; // esf_agent_raw_item_holder_t
} esf_events_queue_t;

void esf_events_queue_init(esf_events_queue_t *queue);

void esf_events_queue_deinit(esf_events_queue_t *queue);

size_t esf_events_queue_size(esf_events_queue_t *queue);

esf_raw_event_holder_t *esf_events_queue_enqueue_back(esf_events_queue_t *queue,
						      esf_raw_event_t *event,
						      gfp_t gfp);

esf_raw_event_holder_t *esf_events_queue_enqueue(esf_events_queue_t *queue,
						 esf_raw_event_t *event,
						 gfp_t gfp);

esf_raw_event_holder_t *
esf_events_queue_enqueue_and_hold(esf_events_queue_t *queue,
				  esf_raw_event_t *event, gfp_t gfp);

esf_raw_event_holder_t *esf_events_queue_dequeue(esf_events_queue_t *queue);

esf_raw_event_holder_t *esf_events_queue_hold(esf_events_queue_t *queue);

esf_raw_event_holder_t *
esf_events_queue_enqueue_move(esf_events_queue_t *queue,
			      esf_raw_event_holder_t *holder_to_move);

void esf_events_queue_release_held(esf_raw_event_holder_t *held_holder);

void esf_events_queue_dequeue_held(esf_raw_event_holder_t *held_holder);

typedef struct esf_events_queue_iter {
	const esf_events_queue_t *__queue;
	esf_raw_event_holder_t *__holder;
} esf_events_queue_iter_t;

esf_events_queue_iter_t
esf_events_queue_make_iter(const esf_events_queue_t *queue);

esf_events_queue_iter_t
esf_events_queue_iter_next(esf_events_queue_iter_t iter);

bool esf_events_queue_iter_is_end(esf_events_queue_iter_t iter);

esf_raw_event_t *esf_events_queue_iter_deref(esf_events_queue_iter_t iter);

#endif //__LINUX_ESF_EVENTS_QUEUE_H
