#ifndef __LINUX_ESF_EVENT_H
#define __LINUX_ESF_EVENT_H

#include <uapi/linux/esf/defs.h>
#include <linux/list.h>

#define __owned
#define __will_be_moved

typedef struct esf_raw_event_item {
	struct list_head _node;
	atomic_t refs;
	esf_item_t *__owned item;
	void *data;
} esf_raw_item_t;

typedef struct esf_raw_event {
	struct list_head raw_items; // list of esf_raw_event_item_t
	atomic_t refs;
	size_t items_data_size;
	esf_event_t event;
} esf_raw_event_t;

esf_raw_item_t *esf_raw_item_get(esf_raw_item_t *raw_item);

void esf_raw_item_put(esf_raw_item_t *raw_item);

esf_raw_event_t *esf_raw_event_get(esf_raw_event_t *raw_event);

void esf_raw_event_put(esf_raw_event_t *raw_event);

esf_raw_event_t *esf_raw_event_create(esf_event_type_t type,
				      esf_event_flags_t flags, gfp_t gfp);

typedef enum esf_add_item_flags {
	ESF_ADD_ITEM_KERNMEM = 0,
	ESF_ADD_ITEM_USERMEM = 1 << 0,
	ESF_ADD_ITEM_MOVEMEM = 1 << 1
} esf_add_item_flags_t;

int esf_raw_event_add_item_ex(esf_raw_event_t *raw_event,
			      esf_item_t *__owned item,
			      esf_item_type_t item_type, void *data,
			      size_t data_size, gfp_t gfp,
			      esf_add_item_flags_t flags);

int esf_raw_event_add_item(esf_raw_event_t *raw_event, esf_item_t *__owned item,
			   void *data, size_t data_size, gfp_t gfp);

int esf_raw_event_add_item_type(esf_raw_event_t *raw_event,
				esf_item_t *__owned item,
				esf_item_type_t item_type, void *data,
				size_t data_size, gfp_t gfp);

#endif /* __LINUX_ESF_EVENT_H */
