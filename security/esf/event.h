#ifndef __LINUX_ESF_EVENT_H
#define __LINUX_ESF_EVENT_H

#include <uapi/linux/esf/defs.h>
#include <linux/string.h>
#include <linux/list.h>

#define __owned

typedef struct esf_raw_event_filter_data_payload {
	const char *path;
} esf_raw_event_filter_data_payload_t;

typedef struct esf_raw_event_filter_data {
	esf_raw_event_filter_data_payload_t process;
	esf_raw_event_filter_data_payload_t target;
} __randomize_layout esf_raw_event_filter_data_t;

typedef struct esf_raw_event_item {
	struct list_head _node;
	atomic_t refs;
	esf_item_t *__owned item;
	void *data;
} __randomize_layout esf_raw_item_t;

typedef struct esf_raw_event {
	// control table data
	struct hlist_node _hnode;

	atomic_t __reads_left;
	struct completion __read_completion;
	atomic_t decisions_left;
	struct completion decisions_completion;
	esf_action_decision_t decision;

	struct list_head raw_items; // list of esf_raw_event_item_t
	atomic_t refs;
	size_t items_data_size;
	esf_event_t event;

	esf_raw_event_filter_data_t filter_data;
} __randomize_layout esf_raw_event_t;

#define RAW_EVENT_FMT_STR \
	"event[0x%llx]: { id:%lld, type: %d, decision: %d, decisions_left: %d }"

#define RAW_EVENT_FMT(raw_event)                                       \
	(uint64_t)(raw_event), (raw_event)->event.header.id,           \
		(raw_event)->event.header.type, (raw_event)->decision, \
		atomic_read(&(raw_event)->decisions_left)

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

// get string lengh for storing in buffer. Strings stored with zero
#define strmovelen(str) (strlen(str) + 1)

const esf_raw_item_t *esf_raw_event_add_item_ex(esf_raw_event_t *raw_event,
						esf_item_t *__owned item,
						esf_item_type_t item_type,
						void *data, size_t data_size,
						gfp_t gfp,
						esf_add_item_flags_t flags);

const esf_raw_item_t *esf_raw_event_add_item(esf_raw_event_t *raw_event,
					     esf_item_t *__owned item,
					     void *data, size_t data_size,
					     gfp_t gfp);

const esf_raw_item_t *esf_raw_event_add_item_type(esf_raw_event_t *raw_event,
						  esf_item_t *__owned item,
						  esf_item_type_t item_type,
						  void *data, size_t data_size,
						  gfp_t gfp);

int esf_raw_event_make_decision(esf_raw_event_t *raw_event,
				esf_action_decision_t decision);

int esf_event_id_make_decision(esf_event_id event_id,
			       esf_action_decision_t decision);

int esf_raw_event_notify_read(esf_raw_event_t *raw_event);

void esf_raw_event_add_to_decision_wait_table(esf_raw_event_t *raw_event,
					      int waiters_count);

void esf_raw_event_remove_to_decision_wait_table(esf_raw_event_t *raw_event);

esf_action_decision_t
esf_raw_event_wait_for_decision(esf_raw_event_t *raw_event);

typedef uint64_t esf_agent_subscriptions_mask_t[_ESF_EVENT_CATEGORY_MAX + 1];

#endif /* __LINUX_ESF_EVENT_H */
