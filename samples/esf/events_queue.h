#ifndef ESF_EVENTS_QUEUE_H
#define ESF_EVENTS_QUEUE_H

#include <stddef.h>
#include <bits/pthreadtypes.h>
#include <linux/esf/defs.h>

typedef struct event_elem {
    struct event_elem *next;

    esf_event_t *event;
    esf_action_decision_t decision;
} event_elem_t;

typedef struct {
    event_elem_t *elems;
    size_t elems_count;
    pthread_mutex_t mtx;
} events_queue_t;

void events_queue_push_event(events_queue_t *pq, const esf_event_t *event, esf_action_decision_t d);

event_elem_t *events_queue_pop(events_queue_t *pq);

#endif // ESF_EVENTS_QUEUE_H
