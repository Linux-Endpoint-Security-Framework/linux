#ifndef __LINUX_ESF_LOG_H
#define __LINUX_ESF_LOG_H

#include <linux/printk.h>

#define _str(x) #x
#define esf_str(x) _str(x)

#if !defined(__BASE_FILE__)
#define __BASE_FILE__ "masked"
#endif

#define esf_log_debug(fmt, ...) \
	pr_info("esf: [debug:" __BASE_FILE__ "] " fmt "\n", ##__VA_ARGS__)

#define esf_log_debug_err(fmt, ...) \
	pr_err("esf: [debug:" __BASE_FILE__ "] " fmt "\n", ##__VA_ARGS__)

#define esf_log_info(fmt, ...) pr_info("esf: " fmt "\n", ##__VA_ARGS__)
#define esf_log_warn(fmt, ...) pr_warn("esf: " fmt "\n", ##__VA_ARGS__)
#define esf_log_err(fmt, ...) pr_err("esf: " fmt "\n", ##__VA_ARGS__)

typedef char esf_bitmask_buff_64_t[65];

static inline void esf_print_bitmask_64(uint64_t bitmask,
					esf_bitmask_buff_64_t buffer)
{
	buffer[64] = 0;

	for (int i = (sizeof(bitmask) * 8); i > 0; i--) {
		uint64_t bit = (sizeof(bitmask) * 8) - i;
		buffer[i - 1] = (bitmask & ((uint64_t)1 << bit)) ? '1' : '0';
	}
}

#endif /* __LINUX_ESF_LOG_H */
