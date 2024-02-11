/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Endpoint securitu framework types
 *
 * Author: Timur Chernykh <tim.cherry.co@gmail.com>
 *
 * Copyright (C) 2024 Timur Chernykh <tim.cherry.co@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation.
 */

#ifndef _LINUX_ESF_CTL_H
#define _LINUX_ESF_CTL_H

#include <linux/ioctl.h>

#include "defs.h"

typedef enum esf_agent_ctl_subscribe_flags {
	ESF_SUBSCRIBE_NONE = 0,
	ESF_SUBSCRIBE_AS_CONTROLLER = 1 << 0
} esf_agent_ctl_subscribe_flags_t;

typedef struct esf_agent_ctl_subscribe {
	esf_event_type_t event_type;
	esf_agent_ctl_subscribe_flags_t flags;
} esf_agent_ctl_subscribe_t;

typedef struct esf_agent_ctl_activate {
} esf_agent_ctl_activate_t;

typedef struct esf_agent_ctl_decide {
	esf_event_id event_id;
	esf_action_decision_t decision;
} esf_agent_ctl_decide_t;

#define ESF_AGENT_CTL_SUBSCRIBE _IOR('a', 0x0, esf_agent_ctl_subscribe_t)
#define ESF_AGENT_CTL_ACTIVATE _IOR('a', 0x5, esf_agent_ctl_activate_t)
#define ESF_AGENT_CTL_DECIDE _IOR('a', 0x10, esf_agent_ctl_decide_t)

typedef struct esf_ctl_get_subsystem_info {
	esf_version api_version;
} esf_ctl_get_subsystem_info_t;

typedef struct esf_ctl_register_agent {
	esf_version api_version;
} esf_ctl_register_agent_t;

#define ESF_CTL_GET_SUBSYSTEM_INFO _IOR('a', 0x40, esf_ctl_get_subsystem_info_t)
#define ESF_CTL_REGISTER_AGENT _IOR('a', 0x41, esf_ctl_register_agent_t)

#endif /* _LINUX_ESF_CTL_H */