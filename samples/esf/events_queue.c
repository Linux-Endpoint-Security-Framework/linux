#include "events_queue.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

static inline size_t _esf_event_size(const esf_event_t *event)
{
	return sizeof(*event) + event->data_size;
}

static inline esf_event_t *_esf_event_copy(const esf_event_t *event)
{
	size_t event_size = _esf_event_size(event);
	esf_event_t *dup = malloc(_esf_event_size(event));
	return memcpy(dup, event, event_size);
}

void events_queue_push_event(events_queue_t *pq, const esf_event_t *event, esf_action_decision_t d)
{
	event_elem_t *el = malloc(sizeof(event_elem_t));
	el->event = _esf_event_copy(event);
	el->decision = d;

	pthread_mutex_lock(&pq->mtx);

	el->next = pq->elems;
	pq->elems = el;

	pq->elems_count++;

	pthread_mutex_unlock(&pq->mtx);
}

event_elem_t *events_queue_pop(events_queue_t *pq)
{
	event_elem_t *elem = NULL;
	pthread_mutex_lock(&pq->mtx);

	if (pq->elems_count == 0) {
		goto out_unlock;
	}

	elem = pq->elems;

	if (elem) {
		pq->elems = elem->next;
	} else {
		pq->elems = NULL;
	}

	pq->elems_count--;

out_unlock:
	pthread_mutex_unlock(&pq->mtx);

	return elem;
}