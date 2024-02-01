#include <linux/slab.h>
#include <linux/uaccess.h>

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

	if (!raw_item) {
		return NULL;
	}

	if (copy_func) {
		raw_item->data = kmalloc(data_size, gfp);

		if (!raw_item->data) {
			_efs_raw_item_free(raw_item);
			return NULL;
		}

		if (copy_func(raw_item->data, data, data_size) != 0) {
			_efs_raw_item_free(raw_item);
			return NULL;
		}
	} else {
		raw_item->data = data;
	}

	atomic_set(&raw_item->refs, 0);
	INIT_LIST_HEAD(&raw_item->_node);
	raw_item->item = item;

	esf_log_debug("Created raw item 0x%llx, size: %zu", (uint64_t)raw_item,
		      data_size);

	return esf_raw_item_get(raw_item);
}

void _efs_raw_item_destroy(esf_raw_item_t *raw_item)
{
	BUG_ON(!raw_item);

	esf_log_debug("Destroying raw item 0x%llx", (uint64_t)raw_item);

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

	INIT_LIST_HEAD(&raw_event->raw_items);
	atomic_set(&raw_event->refs, 0);

	esf_log_debug("Created raw event 0x%llx from %lld", (uint64_t)raw_event,
		      raw_event->event.header.timestamp);

	return esf_raw_event_get(raw_event);
}

void _esf_raw_event_destroy(esf_raw_event_t *raw_event)
{
	esf_raw_item_t *raw_item = NULL;
	esf_raw_item_t *raw_item_tmp = NULL;

	esf_log_debug("Destroying raw event 0x%llx from %lld",
		      (uint64_t)raw_event, raw_event->event.header.timestamp);

	list_for_each_entry_safe(raw_item, raw_item_tmp, &raw_event->raw_items,
				 _node) {
		esf_raw_item_put(raw_item);
	}

	_esf_raw_event_free(raw_event);
}

int esf_raw_event_add_item_ex(esf_raw_event_t *raw_event, esf_item_t *item,
			      esf_item_type_t item_type, void *data,
			      size_t data_size, gfp_t gfp,
			      esf_add_item_flags_t flags)
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
		esf_log_debug("Unable to create raw item for 0x%llx",
			      (uint64_t)raw_event);

		return -ENOMEM;
	}

	list_add(&raw_item->_node, &raw_event->raw_items);
	raw_item->item->item_type = item_type;
	raw_item->item->size = data_size;
	raw_item->item->offset = raw_event->items_data_size;

	esf_log_debug("Added raw item at 0x%llx, size: %u, offset: %llu",
		      (uint64_t)raw_event, raw_item->item->size,
		      raw_item->item->offset);

	raw_event->items_data_size += data_size;
	raw_event->event.data_size = raw_event->items_data_size;

	return 0;
}

int esf_raw_event_add_item(esf_raw_event_t *raw_event, esf_item_t *__owned item,
			   void *data, size_t data_size, gfp_t gfp)
{
	return esf_raw_event_add_item_ex(raw_event, item, ESF_ITEM_TYPE_STRING,
					 data, data_size, gfp,
					 ESF_ADD_ITEM_KERNMEM);
}

int esf_raw_event_add_item_type(esf_raw_event_t *raw_event,
				esf_item_t *__owned item,
				esf_item_type_t item_type, void *data,
				size_t data_size, gfp_t gfp)
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
