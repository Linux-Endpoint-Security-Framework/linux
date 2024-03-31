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

#ifndef _LINUX_ESF_FILTERS_H
#define _LINUX_ESF_FILTERS_H

#include "defs.h"

typedef enum esf_filter_match_mode {
	ESF_FILTER_MATCH_MODE_AND = 0,
	ESF_FILTER_MATCH_MODE_OR = 1,
} esf_filter_match_mode_t;

/* note: use only sequence order for filters mode enumeration
 * because it uses in array to access corresponding filter type */
typedef enum esf_filter_type {
	ESF_FILTER_TYPE_ALLOW = 0,
	ESF_FILTER_TYPE_DROP = 1,
	__ESF_FILTER_TYPE_NUM,
} esf_filter_type_t;

typedef enum esf_filter_match_mask {
	ESF_FILTER_EVENT_TYPE = __ESF_BIT_FIELD(0),

	/* emitter process filters - event.process */
	ESF_FILTER_PROCESS_PATH = __ESF_BIT_FIELD(10),
	ESF_FILTER_PROCESS_PID = __ESF_BIT_FIELD(11),
	ESF_FILTER_PROCESS_TGID = __ESF_BIT_FIELD(12),
	ESF_FILTER_PROCESS_UID = __ESF_BIT_FIELD(13),
	ESF_FILTER_PROCESS_GID = __ESF_BIT_FIELD(14),

	/* event data filters */
	ESF_FILTER_TARGET_PATH = __ESF_BIT_FIELD(30),
} esf_filter_match_mask_t;

#define ESF_FILTER_PATH_MAX PATH_MAX + 1

typedef struct esf_process_filter {
	__kernel_uid_t uid;
	__kernel_uid_t gid;
	__kernel_pid_t pid;
	__kernel_pid_t tgid;
	char path[ESF_FILTER_PATH_MAX];
} esf_process_filter_t;

typedef struct esf_target_filter {
	char path[ESF_FILTER_PATH_MAX];
} esf_target_filter_t;

typedef struct esf_filter {
	/* filter configuration */
	esf_filter_type_t type;
	esf_filter_match_mode_t match_mode;
	esf_filter_match_mask_t match;

	/* filter payload */
	esf_event_type_t event_type;
	esf_process_filter_t process;
	esf_target_filter_t target;
} esf_filter_t;

#endif
