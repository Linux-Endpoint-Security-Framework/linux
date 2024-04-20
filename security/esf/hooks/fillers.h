#ifndef __LINUX_ESF_HOOKS_FILLERS_H
#define __LINUX_ESF_HOOKS_FILLERS_H

#include <linux/sched.h>
#include <linux/security.h>
#include <uapi/linux/esf/defs.h>
#include "event.h"

#define _VA_ARGS_SEQ(_1, _2, _3, _4, _5, _6, _7, _8, _9, N, ...) N
#define _VA_ARGS_LEN(...) _VA_ARGS_SEQ(__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1)
#define _CAT(a, b) a##b

#define _FIELD_REF_1(v1) (v1)
#define _FIELD_REF_2(v1, v2) (v1)->v2
#define _FIELD_REF_3(v1, v2, v3) (v1)->v2->v3
#define _FIELD_REF_4(v1, v2, v3, v4) (v1)->v2->v3->v4
#define _FIELD_REF_5(v1, v2, v3, v4, v5) (v1)->v2->v3->v4->v5
#define _FIELD_REF_6(v1, v2, v3, v4, v5, v6) (v1)->v2->v3->v4->v5
#define _FIELD_REF_N(_nargs, ...) _CAT(_FIELD_REF_, _nargs)(__VA_ARGS__)
#define _FIELD_REF(...) _FIELD_REF_N(_VA_ARGS_LEN(__VA_ARGS__), __VA_ARGS__)

#define _CHECK_NULL_FIELD_1(v1) _FIELD_REF_1(v1)

#define _CHECK_NULL_FIELD_2(v1, v2) \
	_CHECK_NULL_FIELD_1(v1) && _FIELD_REF_2(v1, v2)

#define _CHECK_NULL_FIELD_3(v1, v2, v3) \
	_CHECK_NULL_FIELD_2(v1, v2) && _FIELD_REF_3(v1, v2, v3)

#define _CHECK_NULL_FIELD_4(v1, v2, v3, v4) \
	_CHECK_NULL_FIELD_3(v1, v2, v3) && _FIELD_REF_4(v1, v2, v3, v4)

#define _CHECK_NULL_FIELD_5(v1, v2, v3, v4, v5) \
	_CHECK_NULL_FIELD_4(v1, v2, v3, v4) && _FIELD_REF_5(v1, v2, v3, v4, v5)

#define _CHECK_NULL_FIELD_6(v1, v2, v3, v4, v5, v6) \
	_CHECK_NULL_FIELD_5(v1, v2, v3, v4, v5) &&  \
		_FIELD_REF_6(v1, v2, v3, v4, v5, v6)

#define _CHECK_NULL_FIELD_N(_nargs, ...) \
	_CAT(_CHECK_NULL_FIELD_, _nargs)(__VA_ARGS__)

#define _ACCESSIBLE(...) \
	(_CHECK_NULL_FIELD_N(_VA_ARGS_LEN(__VA_ARGS__), __VA_ARGS__))

#define __will_be_moved
#define __required

typedef struct esf_file_fill_data {
	struct file *file;
	struct inode *inode;
	char *__will_be_moved filename;
	size_t filename_len;
	struct vfsmount *fs_mnt_point;
} esf_file_fill_data_t;

typedef struct esf_process_fill_data {
	struct task_struct *__required task;
	struct mm_struct *mm;
	char *__will_be_moved argp;
	size_t arg_len;
	char *__will_be_moved envp;
	size_t env_len;
	esf_file_fill_data_t *exe_info;
} esf_process_fill_data_t;

void esf_fill_ns_from_task(esf_ns_info_t *ns, struct task_struct *task,
			   esf_raw_event_filter_data_payload_t *init_filter);

void esf_fill_creds_from_task(esf_creds_info_t *creds, struct task_struct *task,
			      esf_raw_event_filter_data_payload_t *init_filter);

void esf_fill_file_from_fill_data(
	esf_raw_event_t *raw_event, esf_file_info_t *file,
	esf_file_fill_data_t *file_fill_info,
	esf_raw_event_filter_data_payload_t *init_filter, gfp_t gfp);

void esf_fill_process_from_fill_data(
	esf_raw_event_t *raw_event, esf_process_info_t *process,
	esf_process_fill_data_t *task_fill_info,
	esf_raw_event_filter_data_payload_t *init_filter, gfp_t gfp);

#endif //__LINUX_ESF_HOOKS_FILLERS_H
