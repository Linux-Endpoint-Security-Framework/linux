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

#include "filters.h"
#include "defs.h"

typedef struct esf_events_chan_ctl_subscribe {
	esf_event_type_t event_type;
} esf_events_chan_ctl_subscribe_t;

typedef struct esf_events_chan_ctl_add_filter {
	esf_filter_t *filter;
} esf_events_chan_ctl_add_filter_t;

#define ESF_EVENTS_CHAN_CTL_SUBSCRIBE _IOW('a', 0x0, esf_events_chan_ctl_subscribe_t)
#define ESF_EVENTS_CHAN_CTL_ADD_FILTER _IOW('a', 0x1, esf_events_chan_ctl_add_filter_t)

typedef struct esf_agent_ctl_activate {
} esf_agent_ctl_activate_t;

typedef struct esf_agent_ctl_decide {
	esf_event_id event_id;
	esf_action_decision_t decision;
} esf_agent_ctl_decide_t;

typedef struct esf_agent_ctl_open_listen_channel {
	esf_version api_version;
	int channel_fd;
} esf_agent_ctl_open_listen_channel_t;

typedef struct esf_agent_ctl_open_auth_channel {
	esf_version api_version;
	int channel_fd;
} esf_agent_ctl_open_auth_channel_t;

#define ESF_AGENT_CTL_ACTIVATE _IOW('a', 0x5, esf_agent_ctl_activate_t)
#define ESF_AGENT_CTL_DECIDE _IOW('a', 0x10, esf_agent_ctl_decide_t)
#define ESF_AGENT_CTL_OPEN_LISTEN_CHANNEL \
	_IOWR('a', 0x11, esf_agent_ctl_open_listen_channel_t)
#define ESF_AGENT_CTL_OPEN_AUTH_CHANNEL \
	_IOWR('a', 0x12, esf_agent_ctl_open_auth_channel_t)

typedef struct esf_ctl_get_subsystem_info {
	esf_version api_version;
} esf_ctl_get_subsystem_info_t;

typedef struct esf_ctl_register_agent {
	esf_version api_version;
} esf_ctl_register_agent_t;

#define ESF_CTL_GET_SUBSYSTEM_INFO _IOR('a', 0x40, esf_ctl_get_subsystem_info_t)
#define ESF_CTL_REGISTER_AGENT _IOR('a', 0x42, esf_ctl_register_agent_t)

#endif /* _LINUX_ESF_CTL_H */