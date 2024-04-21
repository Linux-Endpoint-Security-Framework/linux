#include "blobs.h"

struct lsm_blob_sizes esf_blobs __ro_after_init = {
	.lbs_task = sizeof(esf_process_lsb_t),
	.lbs_cred = 0,
	.lbs_file = 0,
	.lbs_inode = sizeof(esf_inode_lsb_t),
	.lbs_superblock = 0,
	.lbs_ipc = 0,
	.lbs_msg_msg = 0,
	.lbs_xattr_count = 0,
};
