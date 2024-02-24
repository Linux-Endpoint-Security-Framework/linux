#ifndef __LINUX_ESF_HOOKS_FILE_H
#define __LINUX_ESF_HOOKS_FILE_H

#include <linux/file.h>

int esf_on_file_open(struct file* file);

int esf_on_file_truncate(struct file* file);

int esf_on_file_write(struct file* file);

#endif // __LINUX_ESF_HOOKS_FILE_H