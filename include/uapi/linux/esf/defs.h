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

#ifndef _LINUX_ESF_DEFS_H
#define _LINUX_ESF_DEFS_H

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/limits.h>
#include <linux/uuid.h>

#define ESV_V1 1
#define ESF_VERSION ESV_V1

typedef int esf_version;
typedef __u64 esf_event_id;

typedef enum esf_action_decision {
	ESF_ACTION_DECISION_ALLOW = 0,
	ESF_ACTION_DECISION_DENY = 1
} esf_action_decision_t;

typedef enum esf_transport {
	ESF_TRANSPORT_EPOLL = 1 << 0,
	ESF_TRANSPORT_IO_URING = 1 << 1,
} esf_transport_t;

typedef enum esf_item_type {
	ESF_ITEM_TYPE_STRING = 0,
	ESF_ITEM_TYPE_STRING_ARR = 1,
} esf_item_type_t;

typedef struct esf_item {
	__u64 offset;
	__u32 size;
	esf_item_type_t item_type;
} esf_item_t;

#define __ESF_BIT_FIELD(n) (1 << n)
#define __ESF_UUID_LEN 16

typedef enum esf_event_flags {
	ESF_EVENT_SIMPLE = 0,
	ESF_EVENT_CAN_CONTROL = __ESF_BIT_FIELD(0),
	ESF_EVENT_QUERYABLE = __ESF_BIT_FIELD(1),
	ESF_EVENT_WAITS_FOR_AUTH = __ESF_BIT_FIELD(2),
	ESF_EVENT_AUTHORIZED = __ESF_BIT_FIELD(3),
	ESF_EVENT_DENIED = __ESF_BIT_FIELD(4),
} esf_event_flags_t;

#define __ESF_EVENT_CATEGORY_BASE 100ULL
#define __ESF_EVENT_CATEGORY_EVENT_TYPE_NR(n) \
	(n##ULL * __ESF_EVENT_CATEGORY_BASE)
#define __ESF_BEGIN_CATEGORY(n, name) \
	_ESF_EVENT_TYPE_##name##_BEG = __ESF_EVENT_CATEGORY_EVENT_TYPE_NR(n)
#define __ESF_END_CATEGORY(name) _ESF_EVENT_TYPE_##name##_END
#define __ESF_EVENT_CATEGORY_NR(name) \
	((_ESF_EVENT_TYPE_##name##_BEG / __ESF_EVENT_CATEGORY_BASE))

/*!
 * Each category may have 64 events maximum
 */
typedef enum esf_event_type {
	__ESF_BEGIN_CATEGORY(0, PROCESS),
	ESF_EVENT_TYPE_PROCESS_TRACE,
	ESF_EVENT_TYPE_PROCESS_SIGNAL,
	ESF_EVENT_TYPE_PROCESS_MAP_EXEC,
	ESF_EVENT_TYPE_PROCESS_EXITED,
	ESF_EVENT_TYPE_PROCESS_EXECUTION,
	ESF_EVENT_TYPE_PROCESS_CREATED,
	ESF_EVENT_TYPE_PROCESS_CRASHED,
	ESF_EVENT_TYPE_PROCESS_CHUID,
	ESF_EVENT_TYPE_PROCESS_CHGID,
	__ESF_END_CATEGORY(PROCESS),

	__ESF_BEGIN_CATEGORY(1, FILE),
	ESF_EVENT_TYPE_FILE_CREATE,
	ESF_EVENT_TYPE_FILE_REMOVE,
	ESF_EVENT_TYPE_FILE_MOVE,
	ESF_EVENT_TYPE_FILE_OPEN,
	ESF_EVENT_TYPE_FILE_MODIFY,
	ESF_EVENT_TYPE_FILE_EXEC,
	ESF_EVENT_TYPE_FILE_TRUNCATE,
	ESF_EVENT_TYPE_FILE_READ,
	ESF_EVENT_TYPE_FILE_ACCESS,
	ESF_EVENT_TYPE_FILE_CLOSED,
	ESF_EVENT_TYPE_FILE_INODE_CHECK_PERM,
	__ESF_END_CATEGORY(FILE),

	__ESF_BEGIN_CATEGORY(2, FS),
	ESF_EVENT_TYPE_FS_MOUNT,
	ESF_EVENT_TYPE_FS_UMOUNT,
	ESF_EVENT_TYPE_FS_LINK_CREATE,
	ESF_EVENT_TYPE_FS_LINK_REMOVE,
	ESF_EVENT_TYPE_FS_FILE_CHOWN,
	ESF_EVENT_TYPE_FS_FILE_CHATTR,
	ESF_EVENT_TYPE_FS_FILE_CHXATTR,
	__ESF_END_CATEGORY(FS),

	__ESF_BEGIN_CATEGORY(3, NET),
	ESF_EVENT_TYPE_NET_CONN_ESTABLISHED,
	ESF_EVENT_TYPE_NET_DOMAIN_RESOLVED,
	ESF_EVENT_TYPE_NET_SOCKET_CREATED,
	ESF_EVENT_TYPE_NET_SOCKET_RECV,
	ESF_EVENT_TYPE_NET_SOCKET_SEND,
	ESF_EVENT_TYPE_NET_TUN_CREATE,
	ESF_EVENT_TYPE_NET_TUN_CLOSE,
	ESF_EVENT_TYPE_NET_NF_CONF_CHANGED,
	ESF_EVENT_TYPE_NET_NF_CONF_RULE_ADD,
	ESF_EVENT_TYPE_NET_NF_CONF_RULE_REMOVE,
	__ESF_END_CATEGORY(NET),

	/* 4 is reserved for further possible network subcategory */

	__ESF_BEGIN_CATEGORY(5, HW_DEVICE),
	ESF_EVENT_TYPE_HW_DEVICE_ADD,
	ESF_EVENT_TYPE_HW_DEVICE_REMOVE,
	ESF_EVENT_TYPE_HW_DEVICE_SOFT_REMOVE,
	__ESF_END_CATEGORY(HW_DEVICE),

	__ESF_BEGIN_CATEGORY(6, KERN),
	ESF_EVENT_TYPE_KERN_BPF_PROG_LOAD,
	ESF_EVENT_TYPE_KERN_BPF_PROG_UNLOAD,
	ESF_EVENT_TYPE_KERN_BPF_MAP_LOOKUP_ELEM,
	ESF_EVENT_TYPE_KERN_BPF_MAP_UPDATE_ELEM,
	ESF_EVENT_TYPE_KERN_BPF_MAP_REMOVE_ELEM,
	ESF_EVENT_TYPE_KERN_MOD_LOAD,
	ESF_EVENT_TYPE_KERN_MOD_UNLOAD,
	ESF_EVENT_TYPE_KERN_SHUTDOWN,
	ESF_EVENT_TYPE_KERN_REBOOT,
	__ESF_END_CATEGORY(KERN),

	_ESF_EVENT_TYPE_MAX
} esf_event_type_t;

typedef enum esf_event_category {
	ESF_EVENT_CATEGORY_PROCESS = __ESF_EVENT_CATEGORY_NR(PROCESS),
	ESF_EVENT_CATEGORY_FILE = __ESF_EVENT_CATEGORY_NR(FILE),
	ESF_EVENT_CATEGORY_FS = __ESF_EVENT_CATEGORY_NR(FS),
	ESF_EVENT_CATEGORY_NET = __ESF_EVENT_CATEGORY_NR(NET),
	ESF_EVENT_CATEGORY_HW_DEVICE = __ESF_EVENT_CATEGORY_NR(HW_DEVICE),
	ESF_EVENT_CATEGORY_KERN = __ESF_EVENT_CATEGORY_NR(KERN),
	_ESF_EVENT_CATEGORY_MAX
} esf_event_category_t;

#define ESF_EVENT_TYPE_NR(event) ((event - 1) % __ESF_EVENT_CATEGORY_BASE)
#define ESF_EVENT_TYPE_MASK(event) (1 << ESF_EVENT_TYPE_NR(event))
#define ESF_EVENT_CATEGORY_NR(event) \
	(esf_event_category_t)(event / __ESF_EVENT_CATEGORY_BASE)

#define ESF_EVENT_IS_IN_CATEGORY(category, event_nr)                \
	(((int)event_nr > 0) &&                                     \
	 ((int)event_nr > (int)_ESF_EVENT_TYPE_##category##_BEG) && \
	 ((int)event_nr < (int)_ESF_EVENT_TYPE_##category##_END))

typedef struct esf_ns_info {
	__u32 uts_ns;
	__u32 ipc_ns;
	__u32 mnt_ns;
	__u32 pid_ns_for_children;
	__u32 net_ns;
	__u32 time_ns;
	__u32 time_ns_for_children;
	__u32 cgroup_ns;
} esf_ns_info_t;

typedef struct esf_creds_info {
	__kernel_uid32_t uid;
	__kernel_uid32_t euid;
	__kernel_uid32_t suid;
	__kernel_uid32_t fsuid;
	__kernel_gid32_t gid;
	__kernel_gid32_t egid;
	__kernel_gid32_t sgid;
	__kernel_gid32_t fsgid;
} esf_creds_info_t;

typedef struct esf_uuid {
	__u8 b[__ESF_UUID_LEN];
} esf_uuid_t;

typedef struct esf_fs_info {
	char id[32];
	esf_uuid_t uuid;
	__kernel_ulong_t magic;
	esf_item_t mount_point;
} esf_fs_info_t;

typedef struct esf_file_info {
	__kernel_ino_t inode;
	__kernel_mode_t mode;
	__kernel_size_t size;
	__kernel_uid_t uid;
	__kernel_gid_t gid;
	__s64 ctime;
	__s64 mtime;
	__s64 atime;
	esf_item_t path;
	esf_fs_info_t fs;
} esf_file_info_t;

typedef struct esf_process_info {
	__kernel_pid_t pid;
	__kernel_pid_t tgid;
	__kernel_pid_t ppid;
	esf_creds_info_t creds;
	esf_file_info_t exe;
	esf_item_t args;
	esf_item_t env;
	esf_ns_info_t namespace;
	esf_file_info_t file_info;
	esf_uuid_t uuid;
} esf_process_info_t;

typedef struct esf_event_header {
	esf_event_id id;
	esf_event_type_t type;
	esf_version version;
	esf_event_flags_t flags;
	__kernel_time64_t timestamp;
} esf_event_header_t;

typedef struct esf_process_execution {
	esf_item_t interpreter;
	esf_process_info_t process;
} esf_process_execution_t;

typedef struct esf_process_exit {
	int signal;
	int code;
} esf_process_exit_t;

typedef struct esf_process_signal {
	esf_process_info_t target;
	int signal;
} esf_process_signal_t;

typedef struct esf_process_ptrace {
	esf_process_info_t target;
	__u32 mode;
} esf_process_ptrace_t;

typedef struct esf_file_open {
	esf_file_info_t file; /* esf_file_info_t must be first */
	__u32 flags;
} esf_file_open_t;

typedef struct esf_file_truncate {
	esf_file_info_t file; /* esf_file_info_t must be first */
} esf_file_truncate_t;

typedef struct esf_file_inode_check_perm {
	esf_file_info_t file; /* esf_file_info_t must be first */
	__kernel_ulong_t mask; /* mask is MAY_* kernel flags */
} esf_file_inode_check_perm_t;

typedef struct esf_event {
	esf_event_header_t header;
	esf_process_info_t process;

	union {
		esf_process_execution_t process_execution;
		esf_process_exit_t process_exit;
		esf_process_signal_t process_signal;
		esf_process_ptrace_t process_ptrace;

		esf_file_info_t __file; /* basic esf_file_* event */
		esf_file_open_t file_open;
		esf_file_truncate_t file_truncate;
		esf_file_inode_check_perm_t file_inode_check_perm;
	};

	__u64 data_size;
	char data[];
} esf_event_t;

typedef struct esf_events {
	__u64 count;
	esf_event_t events[];
} esf_events_t;

#endif /* _LINUX_ESF_DEFS_H */
