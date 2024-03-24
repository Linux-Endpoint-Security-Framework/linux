#include "events_queue.h"
#include "log.h"

struct esf_raw_event_holder {
	esf_events_queue_t *held_at;
	struct list_head _node;
	esf_raw_event_t *raw_event;
	atomic_t refc;
};

static esf_raw_event_holder_t *_create_event_holder(esf_raw_event_t *for_event,
						    gfp_t gfp)
{
	BUG_ON(!for_event);

	esf_raw_event_holder_t *holder =
		kmalloc(sizeof(esf_raw_event_holder_t), gfp);

	if (!holder) {
		return NULL;
	}

	INIT_LIST_HEAD(&holder->_node);
	holder->raw_event = for_event;
	holder->held_at = NULL;
	atomic_set(&holder->refc, 0);

	esf_raw_event_get(for_event);

	return esf_get_raw_event_holder(holder);
}

static void _destroy_event_holder(esf_raw_event_holder_t *holder)
{
	esf_raw_event_put(holder->raw_event);
	kfree(holder);
}

static int _esf_events_queue_enqueue_lockless(esf_events_queue_t *queue,
					      esf_raw_event_holder_t *holder)
{
	list_add_tail(&holder->_node, &queue->__queue);
	queue->__count++;
	return 0;
}

static esf_raw_event_holder_t *
_esf_events_queue_get_first_not_held_lockless(esf_events_queue_t *queue)
{
	esf_raw_event_holder_t *holder = NULL;

	if (queue->__count == 0) {
		goto out;
	}

	holder = list_first_entry(&queue->__queue, esf_raw_event_holder_t,
				  _node);

	int i = 0;

	while (holder->held_at && i < queue->__count) {
		holder = list_next_entry(holder, _node);
		i++;
	}

	if (list_is_last(&holder->_node, &queue->__queue) &&
	    holder->held_at != NULL) {
		return NULL;
	}
out:
	return holder;
}

static esf_raw_event_holder_t *
_esf_events_queue_dequeue_lockless(esf_events_queue_t *queue)
{
	esf_raw_event_holder_t *holder =
		_esf_events_queue_get_first_not_held_lockless(queue);

	if (!holder) {
		goto out;
	}

	list_del_init(&holder->_node);
	queue->__count--;

out:
	return holder;
}

static esf_raw_event_holder_t *
_esf_events_queue_hold_lockless(esf_events_queue_t *queue)
{
	esf_raw_event_holder_t *holder =
		_esf_events_queue_get_first_not_held_lockless(queue);

	if (!holder) {
		goto out;
	}

	holder->held_at = queue;
	queue->__count--;

out:
	return holder;
}

esf_raw_event_holder_t *esf_get_raw_event_holder(esf_raw_event_holder_t *holder)
{
	atomic_inc(&holder->refc);
	return holder;
}

void esf_put_raw_event_holder(esf_raw_event_holder_t *holder)
{
	if (atomic_dec_and_test(&holder->refc)) {
		_destroy_event_holder(holder);
	}
}

esf_raw_event_t *
esf_raw_event_holder_deref(const esf_raw_event_holder_t *holder)
{
	BUG_ON(!holder->raw_event);
	return holder->raw_event;
}

void esf_events_queue_init(esf_events_queue_t *queue)
{
	BUG_ON(!queue);
	memset(queue, 0, sizeof(*queue));
	rwlock_init(&queue->__lock);
	INIT_LIST_HEAD(&queue->__queue);

	esf_log_debug("Events queue initialized");
}

void esf_events_queue_deinit(esf_events_queue_t *queue)
{
	ulong irq_flags;

	write_lock_irqsave(&queue->__lock, irq_flags);

	esf_log_debug("Cleaning up events queue, events to delete: %llu",
		      queue->__count);

	while (queue->__count > 0) {
		esf_raw_event_holder_t *holder =
			_esf_events_queue_dequeue_lockless(queue);

		if (holder) {
			esf_put_raw_event_holder(holder);
		}
	}
	write_unlock_irqrestore(&queue->__lock, irq_flags);
}

size_t esf_events_queue_size(esf_events_queue_t *queue)
{
	ulong irq_flags;
	size_t size = 0;
	read_lock_irqsave(&queue->__lock, irq_flags);
	size = queue->__count;
	read_unlock_irqrestore(&queue->__lock, irq_flags);
	return size;
}

esf_raw_event_holder_t *esf_events_queue_enqueue(esf_events_queue_t *queue,
						 esf_raw_event_t *event,
						 gfp_t gfp)
{
	esf_raw_event_holder_t *holder = NULL;
	esf_raw_event_get(event);

	holder = _create_event_holder(event, gfp);

	if (holder == NULL) {
		goto out;
	}

	ulong irq_flags;

	write_lock_irqsave(&queue->__lock, irq_flags);
	_esf_events_queue_enqueue_lockless(queue, holder);
	write_unlock_irqrestore(&queue->__lock, irq_flags);

out:
	esf_raw_event_put(event);
	return holder;
}

esf_raw_event_holder_t *
esf_events_queue_enqueue_and_hold(esf_events_queue_t *queue,
				  esf_raw_event_t *event, gfp_t gfp)
{
	esf_raw_event_holder_t *holder = NULL;
	esf_raw_event_get(event);

	holder = _create_event_holder(event, gfp);

	if (holder == NULL) {
		goto out;
	}

	ulong irq_flags;

	write_lock_irqsave(&queue->__lock, irq_flags);
	_esf_events_queue_enqueue_lockless(queue, holder);
	holder->held_at = queue;
	queue->__count--;
	write_unlock_irqrestore(&queue->__lock, irq_flags);

out:
	esf_raw_event_put(event);
	return holder;
}

esf_raw_event_holder_t *esf_events_queue_dequeue(esf_events_queue_t *queue)
{
	esf_raw_event_holder_t *holder = NULL;
	ulong irq_flags;
	write_lock_irqsave(&queue->__lock, irq_flags);
	holder = _esf_events_queue_dequeue_lockless(queue);
	write_unlock_irqrestore(&queue->__lock, irq_flags);
	return holder;
}

struct esf_raw_event_holder *esf_events_queue_hold(esf_events_queue_t *queue)
{
	esf_raw_event_holder_t *holder = NULL;
	ulong irq_flags;
	write_lock_irqsave(&queue->__lock, irq_flags);
	holder = _esf_events_queue_hold_lockless(queue);
	write_unlock_irqrestore(&queue->__lock, irq_flags);
	return holder;
}

void esf_events_queue_release_held(struct esf_raw_event_holder *held_holder)
{
	BUG_ON(!held_holder->held_at);

	esf_events_queue_t *q = held_holder->held_at;

	ulong irq_flags;
	write_lock_irqsave(&q->__lock, irq_flags);
	held_holder->held_at->__count++;
	held_holder->held_at = NULL;
	write_unlock_irqrestore(&q->__lock, irq_flags);
}

void esf_events_queue_dequeue_held(struct esf_raw_event_holder *held_holder)
{
	BUG_ON(!held_holder->held_at);

	esf_events_queue_t *q = held_holder->held_at;

	ulong irq_flags;
	write_lock_irqsave(&q->__lock, irq_flags);
	list_del_init(&held_holder->_node);
	held_holder->held_at = NULL;
	write_unlock_irqrestore(&q->__lock, irq_flags);
}

esf_raw_event_holder_t *
esf_events_queue_enqueue_move(esf_events_queue_t *queue,
			      esf_raw_event_holder_t *holder_to_move)
{
	ulong irq_flags;
	esf_get_raw_event_holder(holder_to_move);
	write_lock_irqsave(&queue->__lock, irq_flags);
	_esf_events_queue_enqueue_lockless(queue, holder_to_move);
	write_unlock_irqrestore(&queue->__lock, irq_flags);
	return holder_to_move;
}

esf_events_queue_iter_t
esf_events_queue_make_iter(const esf_events_queue_t *queue)
{
	ulong irq_flags;
	esf_events_queue_t *mut_queue = (esf_events_queue_t *)queue;

	read_lock_irqsave(&mut_queue->__lock, irq_flags);

	esf_events_queue_iter_t it = {
		.__queue = queue,
		.__holder = _esf_events_queue_get_first_not_held_lockless(
			mut_queue),
	};

	read_unlock_irqrestore(&mut_queue->__lock, irq_flags);

	return it;
}

esf_events_queue_iter_t esf_events_queue_iter_next(esf_events_queue_iter_t iter)
{
	ulong irq_flags;
	esf_events_queue_t *mut_queue = (esf_events_queue_t *)iter.__queue;

	read_lock_irqsave(&mut_queue->__lock, irq_flags);

	esf_events_queue_iter_t new_it = iter;

	if (list_is_last(&iter.__holder->_node, &iter.__queue->__queue)) {
		new_it.__holder = NULL;
	} else {
		new_it.__holder = list_next_entry(iter.__holder, _node);
	}

	read_unlock_irqrestore(&mut_queue->__lock, irq_flags);

	return new_it;
}

bool esf_events_queue_iter_is_end(esf_events_queue_iter_t iter)
{
	return iter.__holder == NULL;
}

esf_raw_event_t *esf_events_queue_iter_deref(esf_events_queue_iter_t iter)
{
	if (esf_events_queue_iter_is_end(iter)) {
		return NULL;
	}

	return esf_raw_event_holder_deref(iter.__holder);
}