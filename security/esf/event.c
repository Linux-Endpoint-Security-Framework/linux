#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/hashtable.h>

#include "event.h"
#include "log.h"

#define ASSERT_ITEM_IS_OWNED_BY(event_ptr, item_ptr)              \
	BUG_ON((((uint8_t *)(event_ptr) + sizeof(*(event_ptr))) < \
		((uint8_t *)(item_ptr))) ||                       \
	       (((uint8_t *)(item_ptr)) < ((uint8_t *)(event_ptr))))

esf_raw_item_t *_esf_raw_item_alloc(gfp_t gfp)
{
	return kzalloc(sizeof(esf_raw_item_t), gfp);
}

void _efs_raw_item_free(esf_raw_item_t *raw_item)
{
	kfree(raw_item);
}

typedef ulong (*_copy_func_t)(void *, const void *, size_t);

static ulong _esf_raw_item_init_data(void *dst, const void *src, size_t size)
{
	memcpy(dst, src, size);
	return 0;
}

static ulong _esf_raw_item_init_data_user(void *dst, const void *src,
					  size_t size)
{
	return copy_from_user(dst, src, size);
}

esf_raw_item_t *_esf_raw_item_create(esf_item_t *__owned item, void *data,
				     size_t data_size, gfp_t gfp,
				     _copy_func_t copy_func)
{
	esf_raw_item_t *raw_item = _esf_raw_item_alloc(gfp);
	size_t item_size = data_size;

	if (!raw_item || !data_size) {
		return NULL;
	}

	if (copy_func) {
		// with zero at end
		item_size += 1;

		raw_item->data = kzalloc(item_size, gfp);

		if (!raw_item->data) {
			_efs_raw_item_free(raw_item);
			return NULL;
		}

		if (copy_func(raw_item->data, data, data_size) != 0) {
			_efs_raw_item_free(raw_item);
			return NULL;
		}
	} else {
		// memory will be just moved, so keep data size as passed to func
		raw_item->data = data;

		// assert that moved item also ends with zero
		BUG_ON(((char *)raw_item->data)[item_size - 1] != 0x0);
	}

	atomic_set(&raw_item->refs, 0);
	INIT_LIST_HEAD(&raw_item->_node);
	raw_item->item = item;
	raw_item->item->size = item_size;

#ifdef CONFIG_DEBUG_TRACE_LOG_EVENTS
	esf_log_debug("Created raw item 0x%llx, size: %zu", (uint64_t)raw_item,
		      data_size);
#endif

	return esf_raw_item_get(raw_item);
}

void _efs_raw_item_destroy(esf_raw_item_t *raw_item)
{
	BUG_ON(!raw_item);

#ifdef CONFIG_DEBUG_TRACE_LOG_EVENTS
	esf_log_debug("Destroying raw item 0x%llx", (uint64_t)raw_item);
#endif

	if (raw_item->item) {
		raw_item->item->offset = 0;
		raw_item->item->size = 0;
	}

	if (raw_item->data) {
		kfree(raw_item->data);
	}

	list_del(&raw_item->_node);

	_efs_raw_item_free(raw_item);
}

esf_raw_event_t *_esf_raw_event_alloc(gfp_t gfp)
{
	return kzalloc(sizeof(esf_raw_event_t), gfp);
}

void _esf_raw_event_free(esf_raw_event_t *esf_event)
{
	kfree(esf_event);
}

static atomic64_t _raw_event_id = ATOMIC64_INIT(0);

esf_raw_event_t *esf_raw_event_create(esf_event_type_t type,
				      esf_event_flags_t flags, gfp_t gfp)
{
	esf_raw_event_t *raw_event = _esf_raw_event_alloc(gfp);

	if (!raw_event) {
		return NULL;
	}

	raw_event->event.header.version = ESF_VERSION;
	raw_event->event.header.timestamp = ktime_to_ms(ktime_get());
	raw_event->event.header.type = type;
	raw_event->event.header.flags = flags;
	raw_event->event.header.id = atomic64_inc_return(&_raw_event_id);

	INIT_HLIST_NODE(&raw_event->_hnode);
	raw_event->decision = ESF_ACTION_DECISION_ALLOW;
	init_completion(&raw_event->__read_completion);
	atomic_set(&raw_event->__reads_left, 0);
	init_completion(&raw_event->decisions_completion);
	atomic_set(&raw_event->decisions_left, 0);
	INIT_LIST_HEAD(&raw_event->raw_items);
	atomic_set(&raw_event->refs, 0);

#ifdef CONFIG_DEBUG_TRACE_LOG_EVENTS
	esf_log_debug("Created raw event 0x%llx from %lld", (uint64_t)raw_event,
		      raw_event->event.header.timestamp);
#endif

	return esf_raw_event_get(raw_event);
}

void _esf_raw_event_destroy(esf_raw_event_t *raw_event)
{
	esf_raw_event_remove_to_decision_wait_table(raw_event);

	esf_raw_item_t *raw_item = NULL;
	esf_raw_item_t *raw_item_tmp = NULL;

#ifdef CONFIG_DEBUG_TRACE_LOG_EVENTS
	esf_log_debug("Destroying raw event 0x%llx from %lld",
		      (uint64_t)raw_event, raw_event->event.header.timestamp);
#endif

	list_for_each_entry_safe(raw_item, raw_item_tmp, &raw_event->raw_items,
				 _node) {
		esf_raw_item_put(raw_item);
	}

	_esf_raw_event_free(raw_event);
}

const esf_raw_item_t *esf_raw_event_add_item_ex(
	esf_raw_event_t *raw_event, esf_item_t *item, esf_item_type_t item_type,
	void *data, size_t data_size, gfp_t gfp, esf_add_item_flags_t flags)
{
	ASSERT_ITEM_IS_OWNED_BY(&raw_event->event, item);

	bool should_not_copy = (flags & ESF_ADD_ITEM_MOVEMEM) &&
			       ((flags & ESF_ADD_ITEM_USERMEM) == 0);

	_copy_func_t copy_func = flags & ESF_ADD_ITEM_USERMEM ?
					 _esf_raw_item_init_data_user :
					 _esf_raw_item_init_data;

	if (should_not_copy) {
		copy_func = NULL;
	}

	esf_raw_item_t *raw_item =
		_esf_raw_item_create(item, data, data_size, gfp, copy_func);

	if (!raw_item) {
#ifdef CONFIG_DEBUG_TRACE_LOG_EVENTS
		esf_log_debug("Unable to create raw item for 0x%llx",
			      (uint64_t)raw_event);
#endif

		return ERR_PTR(-ENOMEM);
	}

	list_add(&raw_item->_node, &raw_event->raw_items);
	raw_item->item->item_type = item_type;
	raw_item->item->offset = raw_event->items_data_size;

#ifdef CONFIG_DEBUG_TRACE_LOG_EVENTS
	esf_log_debug("Added raw item at 0x%llx, size: %u, offset: %llu",
		      (uint64_t)raw_event, raw_item->item->size,
		      raw_item->item->offset);
#endif

	raw_event->items_data_size += raw_item->item->size;
	raw_event->event.data_size = raw_event->items_data_size;

	return raw_item;
}

const esf_raw_item_t *esf_raw_event_add_item(esf_raw_event_t *raw_event,
					     esf_item_t *__owned item,
					     void *data, size_t data_size,
					     gfp_t gfp)
{
	return esf_raw_event_add_item_ex(raw_event, item, ESF_ITEM_TYPE_STRING,
					 data, data_size, gfp,
					 ESF_ADD_ITEM_KERNMEM);
}

const esf_raw_item_t *esf_raw_event_add_item_type(esf_raw_event_t *raw_event,
						  esf_item_t *__owned item,
						  esf_item_type_t item_type,
						  void *data, size_t data_size,
						  gfp_t gfp)
{
	return esf_raw_event_add_item_ex(raw_event, item, item_type, data,
					 data_size, gfp, ESF_ADD_ITEM_KERNMEM);
}

esf_raw_item_t *esf_raw_item_get(esf_raw_item_t *raw_item)
{
	atomic_inc(&raw_item->refs);
	return raw_item;
}

void esf_raw_item_put(esf_raw_item_t *raw_item)
{
	if (atomic_dec_and_test(&raw_item->refs)) {
		_efs_raw_item_destroy(raw_item);
	}
}

esf_raw_event_t *esf_raw_event_get(esf_raw_event_t *raw_event)
{
	BUG_ON(!raw_event);
	atomic_inc(&raw_event->refs);
	return raw_event;
}

void esf_raw_event_put(esf_raw_event_t *raw_event)
{
	if (atomic_dec_and_test(&raw_event->refs)) {
		_esf_raw_event_destroy(raw_event);
	}
}

static DEFINE_MUTEX(_wait_decision_tbl_mtx);
static DECLARE_HASHTABLE(_wait_decision_tbl, 12);

int esf_raw_event_make_decision(esf_raw_event_t *raw_event,
				esf_action_decision_t decision)
{
	return esf_event_id_make_decision(raw_event->event.header.id, decision);
}

int esf_event_id_make_decision(esf_event_id event_id,
			       esf_action_decision_t decision)
{
	esf_raw_event_t *raw_event = NULL;
	bool found = false;

	mutex_lock(&_wait_decision_tbl_mtx);

	hash_for_each_possible(_wait_decision_tbl, raw_event, _hnode,
			       event_id) {
		found = true;

#ifdef CONFIG_DEBUG_TRACE_LOG_DECISIONS
		esf_log_debug(RAW_EVENT_FMT_STR " - %s by agent %d",
			      RAW_EVENT_FMT(raw_event),
			      decision == ESF_ACTION_DECISION_ALLOW ?
				      "allowed" :
				      "denied",
			      current->pid);

		if (decision == ESF_ACTION_DECISION_DENY) {
			esf_log_warn("Action %d denied by security agent %d",
				     raw_event->event.header.type,
				     current->pid);
		}
#endif

		// if not denied, write new decision
		if (raw_event->decision != ESF_ACTION_DECISION_DENY) {
			raw_event->decision = decision;
		}

		if (atomic_dec_and_test(&raw_event->decisions_left)) {
			complete_all(&raw_event->decisions_completion);
		}
	}

	mutex_unlock(&_wait_decision_tbl_mtx);

	return found ? 0 : -ENOENT;
}

int esf_raw_event_notify_read(esf_raw_event_t *raw_event)
{
	// notify on each read until
	if (!atomic_dec_and_test(&raw_event->__reads_left)) {
		complete_all(&raw_event->__read_completion);
	}

	return 0;
}

#define _ESF_EVENT_READ_TIMEOUT_MS 2000
#define _ESF_EVENT_DECISION_TIMEOUT_MS 500

static int _esf_raw_event_wait_for_one_read(esf_raw_event_t *raw_event,
					    int reads_count)
{
	atomic_set(&raw_event->__reads_left, reads_count);

	uint64_t read_timeout = msecs_to_jiffies(_ESF_EVENT_READ_TIMEOUT_MS);

	uint64_t till_read_timeout = wait_for_completion_interruptible_timeout(
		&raw_event->__read_completion, read_timeout);

#ifdef CONFIG_DEBUG_TRACE_LOG_DECISIONS
	if (till_read_timeout == 0) {
		esf_log_debug_err("Waiting for " RAW_EVENT_FMT_STR
				  " read timed out",
				  RAW_EVENT_FMT(raw_event));
	} else {
		esf_log_debug(RAW_EVENT_FMT_STR " maked as read",
			      RAW_EVENT_FMT(raw_event));
	}
#endif

	return till_read_timeout;
}

void esf_raw_event_add_to_decision_wait_table(esf_raw_event_t *raw_event,
					      int waiters_count)
{
	BUG_ON(waiters_count <= 0);

	esf_raw_event_get(raw_event);
	atomic_set(&raw_event->decisions_left, waiters_count);

	mutex_lock(&_wait_decision_tbl_mtx);
	hash_add(_wait_decision_tbl, &raw_event->_hnode,
		 raw_event->event.header.id);
	mutex_unlock(&_wait_decision_tbl_mtx);
}

void esf_raw_event_remove_to_decision_wait_table(esf_raw_event_t *raw_event)
{
	atomic_set(&raw_event->decisions_left, 0);
	complete_all(&raw_event->decisions_completion);

	mutex_lock(&_wait_decision_tbl_mtx);
	hash_del(&raw_event->_hnode);
	mutex_unlock(&_wait_decision_tbl_mtx);

	esf_raw_event_put(raw_event);
}

/*!
 * esf_raw_event_wait_for_decision() waits for event decision
 * and removes raw_event from wait table
 * @raw_event : event to wait
 * @return a decision has made
 */
esf_action_decision_t
esf_raw_event_wait_for_decision(esf_raw_event_t *raw_event)
{
	esf_action_decision_t final_decision = ESF_ACTION_DECISION_ALLOW;

	esf_raw_event_get(raw_event);

	if (!hash_hashed(&raw_event->_hnode)) {
		esf_log_err(
			"Attempt to wait for decision on non-hashed " RAW_EVENT_FMT_STR,
			RAW_EVENT_FMT(raw_event));

		goto out;
	}

	uint64_t till_read_timeout = _esf_raw_event_wait_for_one_read(
		raw_event, atomic_read(&raw_event->decisions_left));

	if (till_read_timeout <= 0) {
		goto out_remove_from_table;
	}

	uint64_t decision_timeout =
		msecs_to_jiffies(_ESF_EVENT_DECISION_TIMEOUT_MS);
	uint64_t till_decision_timeout =
		wait_for_completion_interruptible_timeout(
			&raw_event->decisions_completion, decision_timeout);

	final_decision = raw_event->decision;

#ifdef CONFIG_DEBUG_TRACE_LOG_DECISIONS
	if (till_decision_timeout == 0) {
		esf_log_debug_err("Waiting for " RAW_EVENT_FMT_STR
				  " decision timed out",
				  RAW_EVENT_FMT(raw_event));
	} else {
		esf_log_debug(
			"Decision for " RAW_EVENT_FMT_STR ": %s made in %d ms",
			RAW_EVENT_FMT(raw_event),
			final_decision == ESF_ACTION_DECISION_ALLOW ? "allow" :
								      "deny",
			jiffies_to_msecs(decision_timeout -
					 till_decision_timeout));
	}
#endif

out_remove_from_table:
	esf_raw_event_remove_to_decision_wait_table(raw_event);

out:
	esf_raw_event_put(raw_event);

	return final_decision;
}
