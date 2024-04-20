#ifndef __LINUX_ESF_H
#define __LINUX_ESF_H

#include <linux/spinlock.h>

#include "agent.h"

int esf_unregister_agent(esf_agent_t* agent);

int esf_register_agent(esf_agent_t* agent);

uint32_t esf_get_agents_count(void);

void esf_update_active_subscriptions_mask(void);

bool esf_anyone_subscribed_to(esf_event_type_t type);

typedef enum esf_submit_flags {
	ESF_SUBMIT_SIMPLE = 0,
	ESF_SUBMIT_WAIT_FOR_DECISION = 1 << 0,
} esf_submit_flags_t;

int esf_submit_raw_event_ex(esf_raw_event_t *raw_event, gfp_t gfp, esf_submit_flags_t flags);

int esf_submit_raw_event(esf_raw_event_t* event, gfp_t gfp);

#endif /* __LINUX_ESF_H */
