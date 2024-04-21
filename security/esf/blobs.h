#ifndef __LINUX_ESF_BLOBS_H
#define __LINUX_ESF_BLOBS_H

#include <linux/uuid.h>
#include <linux/atomic.h>
#include <linux/lsm_hooks.h>

typedef struct esf_inode_lsb {
	atomic64_t w_count;
} esf_inode_lsb_t;

typedef struct esf_process_lsb {
	uuid_t unique_id;
} esf_process_lsb_t;

extern struct lsm_blob_sizes esf_blobs;

static inline esf_inode_lsb_t *esf_get_inode_lsb(const struct inode *inode)
{
	if (unlikely(!inode->i_security)) {
		return NULL;
	}

	return inode->i_security + esf_blobs.lbs_inode;
}

static inline esf_process_lsb_t *esf_get_task_lsb(const struct task_struct *task)
{
	if (unlikely(!task->security)) {
		return NULL;
	}

	return task->security + esf_blobs.lbs_task;
}

#endif //__LINUX_ESF_BLOBS_H
