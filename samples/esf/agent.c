#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/user.h>

#include <linux/esf/ctl.h>
#include <sys/epoll.h>

#include "events_queue.h"
#include "strdefs.h"

#include <signal.h>

#define RED "\x1B[31m"
#define GRN "\x1B[32m"
#define YEL "\x1B[33m"
#define BLU "\x1B[34m"
#define MAG "\x1B[35m"
#define CYN "\x1B[36m"
#define WHT "\x1B[37m"
#define RESET "\x1B[0m"

#define POLL_SIZE 256
#define POLL_MAX_EVENTS 20

#define WIN_WIDTH_RES 30
static int32_t _win_width = 80;

#define ARRAY_SIZE(x) ((sizeof(x) / sizeof(0 [x])) / ((size_t)(!(sizeof(x) % sizeof(0 [x])))))
#define MAX_PW (_win_width - WIN_WIDTH_RES)
#define NULL_STR "(null)"

#define esf_item_as_string(event_ptr, item_field) esf_event_item_copy((event_ptr), &((event_ptr)->item_field))
#define esf_item_as_ref(event_ptr, item_field) esf_event_item_data((event_ptr), &((event_ptr)->item_field))

#define esf_agent_err(fmt, ...) fprintf(stderr, "[sample]: " fmt ": %s\n", ##__VA_ARGS__, strerror(errno))
#define esf_agent_log(fmt, ...) fprintf(stdout, "[sample]: " fmt "\n", ##__VA_ARGS__)
#define esf_agent_logi(ident, fmt, ...) fprintf(stdout, "[sample]: %*s" fmt "\n", ident * 2, "", ##__VA_ARGS__)
#define esf_agent_logni_field(ident, name, type, field, ...) esf_agent_logi(ident, name ": %" type, field)
#define esf_agent_logni_field_str(ident, name, field, len, ...) \
	esf_agent_logi(ident, name ": %.*s%s (%d)", MAX_PW, field, (len) > MAX_PW ? "..." : "", (len))

typedef struct esf_event_iterator {
	uint32_t _i;
	uint32_t _total;
	const char *_buffer;
} esf_event_iterator_t;

static esf_event_iterator_t esf_new_event_iterator(const esf_events_t *events_buffer)
{
	esf_event_iterator_t it = {
		._i = 0,
		._buffer = (void *)events_buffer->events,
		._total = events_buffer->count,
	};

	return it;
}

static bool esf_event_iterator_is_end(esf_event_iterator_t it)
{
	return it._i >= it._total;
}

static const esf_event_t *esf_event_iterator_get_event(esf_event_iterator_t it)
{
	if (esf_event_iterator_is_end(it)) {
		return NULL;
	}

	return (esf_event_t *)it._buffer;
}

static esf_event_iterator_t esf_event_iterator_next(esf_event_iterator_t it)
{
	if (esf_event_iterator_is_end(it)) {
		return it;
	}

	const esf_event_t *event = esf_event_iterator_get_event(it);

	if (event == NULL) {
		return it;
	}

	it._i++;
	it._buffer += sizeof(*event) + event->data_size;

	return it;
}

#define for_each_esf_event(buff, it)                                                                                   \
	for (esf_event_iterator_t it = esf_new_event_iterator(((esf_events_t *)buff)); !esf_event_iterator_is_end(it); \
	     it = esf_event_iterator_next(it))

typedef struct esf_agent {
	int fd;
} esf_agent_t;

typedef struct esf_events_channel {
	const esf_agent_t *agent;
	int fd;
} esf_events_channel_t;

int esf_register_agent(int esf_fd, esf_agent_t *esf_agent)
{
	esf_ctl_register_agent_t register_agent = {
		.api_version = ESF_VERSION,
	};

	esf_agent_log("registering with API version: %d", ESF_VERSION);

	int agent_fd = ioctl(esf_fd, ESF_CTL_REGISTER_AGENT, &register_agent);

	if (agent_fd < 0) {
		return agent_fd;
	}

	esf_agent->fd = agent_fd;

	return 0;
}

int esf_agent_open_listen_channel(const esf_agent_t *agent, esf_events_channel_t *chan)
{
	esf_agent_ctl_open_listen_channel_t open_listen_chan_cmd = { .api_version = ESF_VERSION };

	int err = ioctl(agent->fd, ESF_AGENT_CTL_OPEN_LISTEN_CHANNEL, &open_listen_chan_cmd);

	if (err) {
		return -1;
	}

	chan->agent = agent;
	chan->fd = open_listen_chan_cmd.channel_fd;

	return 0;
}

int esf_agent_open_auth_channel(const esf_agent_t *agent, esf_events_channel_t *chan)
{
	esf_agent_ctl_open_auth_channel_t open_auth_chan_cmd = { .api_version = ESF_VERSION };

	int err = ioctl(agent->fd, ESF_AGENT_CTL_OPEN_AUTH_CHANNEL, &open_auth_chan_cmd);

	if (err) {
		return -1;
	}

	chan->agent = agent;
	chan->fd = open_auth_chan_cmd.channel_fd;

	return 0;
}

int esf_event_subscribe(const esf_events_channel_t *chan, esf_event_type_t event_type)
{
	esf_agent_log("subscribing to event type %d (chan: %d)...", event_type, chan->fd);
	esf_events_chan_ctl_subscribe_t subscribe_cmd = {
		.event_type = event_type,
	};

	return ioctl(chan->fd, ESF_EVENTS_CHAN_CTL_SUBSCRIBE, &subscribe_cmd);
}

int esf_event_add_filter(esf_events_channel_t *chan, const esf_filter_t *filter)
{
	esf_agent_log("adding %s filter (chan: %d)...", filter->type == ESF_FILTER_TYPE_ALLOW ? "allow" : "drop",
		      chan->fd);
	esf_events_chan_ctl_add_filter_t add_filter_t = {
		.filter = (esf_filter_t *)filter,
	};

	return ioctl(chan->fd, ESF_EVENTS_CHAN_CTL_ADD_FILTER, &add_filter_t);
}

void esf_filter_init(esf_filter_t *filter, esf_filter_type_t type, esf_filter_match_mode_t mode)
{
	memset(filter, 0, sizeof(*filter));
	filter->match_mode = mode;
	filter->type = type;
}

int esf_filter_add_rule(esf_filter_t *filter, esf_filter_match_mask_t match, const void *data, size_t data_size)
{
#define __STR_CHECK_AND_SET(target, val, size, max) \
	if (size > max - 1) {                       \
		return E2BIG;                       \
	}                                           \
	memcpy(target, val, size);                  \
	filter->match |= match;                     \
	break

#define __VAL_CHECK_AND_SET(target, val, size) \
	if (size != sizeof(target)) {          \
		return EINVAL;                 \
	}                                      \
	memcpy(&target, val, size);            \
	filter->match |= match;                \
	break

	switch (match) {
	case ESF_FILTER_EVENT_TYPE:
		__VAL_CHECK_AND_SET(filter->event_type, data, data_size);
	case ESF_FILTER_PROCESS_PATH:
		__STR_CHECK_AND_SET(filter->process.path, data, data_size, ESF_FILTER_PATH_MAX);
	case ESF_FILTER_PROCESS_PID:
		__VAL_CHECK_AND_SET(filter->process.pid, data, data_size);
	case ESF_FILTER_PROCESS_TGID:
		__VAL_CHECK_AND_SET(filter->process.tgid, data, data_size);
	case ESF_FILTER_PROCESS_UID:
		__VAL_CHECK_AND_SET(filter->process.uid, data, data_size);
	case ESF_FILTER_PROCESS_GID:
		__VAL_CHECK_AND_SET(filter->process.gid, data, data_size);
	case ESF_FILTER_TARGET_PATH:
		__STR_CHECK_AND_SET(filter->target.path, data, data_size, ESF_FILTER_PATH_MAX);
	}

	return EINVAL;
}

int esf_agent_activate(const esf_agent_t *agent)
{
	esf_agent_ctl_activate_t activate_cmd = {};
	esf_agent_log("activating agent...");
	return ioctl(agent->fd, ESF_AGENT_CTL_ACTIVATE, &activate_cmd);
}

int esf_event_make_decision(const esf_agent_t *agent, const esf_event_t *event, esf_action_decision_t decision)
{
	esf_agent_ctl_decide_t decide_cmd = {
		.event_id = event->header.id,
		.decision = decision,
	};
	esf_agent_log("%s event %llu", decision == ESF_ACTION_DECISION_ALLOW ? "allow" : "deny", event->header.id);
	return ioctl(agent->fd, ESF_AGENT_CTL_DECIDE, &decide_cmd);
}

const void *esf_event_item_data(const esf_event_t *event, const esf_item_t *item)
{
	return event->data + item->offset;
}

void *esf_event_item_copy(const esf_event_t *event, const esf_item_t *item)
{
	if (item->size == 0) {
		return NULL;
	}

	const void *item_data = esf_event_item_data(event, item);
	char *dup = malloc(item->size + 1);
	memcpy(dup, item_data, item->size);
	dup[item->size] = 0;

	if (item->item_type == ESF_ITEM_TYPE_STRING_ARR) {
		for (int i = 0; i < item->size - 1; i++) {
			if (dup[i] == '\0') {
				dup[i] = ' ';
			}
		}
	}

	return dup;
}

const char *_basename(char const *path, uint32_t pathlen)
{
	if (pathlen == 1) {
		return path;
	}

	while (pathlen > 0) {
		if (path[pathlen] == '/') {
			break;
		}

		pathlen--;
	}

	// not found
	if (pathlen == 0) {
		return path;
	}

	return path + pathlen + 1;
}

bool _is_program(const char *p, const char *e, uint32_t pathlen)
{
	const char *base = _basename(p, pathlen);
	return strcmp(base, e) == 0;
}

typedef void (*on_event_callback)(const esf_events_channel_t *channel, const esf_event_t *event, void *data);

static int _read_all_events(const esf_events_channel_t *channel, esf_events_t *events_buffer,
			    const size_t events_buffer_size, const on_event_callback callback, void *data)
{
	int err = 0;

	while (true) {
		const long bytes_read = read(channel->fd, events_buffer, events_buffer_size);

		if (bytes_read < 0) {
			err = errno;
			goto out;
		}

		if (bytes_read == 0 || events_buffer->count == 0) {
			goto out;
		}

		esf_agent_log("accepted %llu events on events chan %d (read: %ld bytes)", events_buffer->count,
			      channel->fd, bytes_read);

		for_each_esf_event(events_buffer, it)
		{
			const esf_event_t *event = esf_event_iterator_get_event(it);
			callback(channel, event, data);
		}
	}

out:
	return err;
}

static bool _print_thread_should_run = true;
static bool _auth_thread_should_run = true;
static bool _listen_thread_should_run = true;

typedef char uuid_string[37];

static void _uuid_to_str(uuid_string uuid_str, const esf_uuid_t uuid)
{
	sprintf(uuid_str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", uuid.b[0], uuid.b[1],
		uuid.b[2], uuid.b[3], uuid.b[4], uuid.b[5], uuid.b[6], uuid.b[7], uuid.b[8], uuid.b[9], uuid.b[10],
		uuid.b[11], uuid.b[12], uuid.b[13], uuid.b[14], uuid.b[15]);
}

static void *_print_routine(void *arg)
{
	events_queue_t *print_queue = arg;

	while (_print_thread_should_run) {
		event_elem_t *el = events_queue_pop(print_queue);
		if (el == NULL) {
			continue;
		}
		const esf_event_t *event = el->event;
		const esf_action_decision_t decision = el->decision;

		char *parent_exe = esf_item_as_string(event, process.exe.path);
		char *parent_args = esf_item_as_string(event, process.args);
		char *parent_env = esf_item_as_string(event, process.env);
		uuid_string process_uuid = { 0 };
		_uuid_to_str(process_uuid, event->process.uuid);

		esf_event_flags_str_t flags = esf_event_flags_str(event->header.flags);

		if (event->header.flags & ESF_EVENT_DENIED) {
			esf_agent_log(YEL);
		} else {
			switch (decision) {
			case ESF_ACTION_DECISION_DENY:
				esf_agent_log(RED);
				break;
			case ESF_ACTION_DECISION_ALLOW:
				esf_agent_log(GRN);
				break;
			default:
				esf_agent_log(BLU);
				break;
			}
		}

		esf_agent_logi(0, "[%llu] %s:%d [%s], data size: %llu {", event->header.id,
			       esf_event_type_name(event->header.type), event->header.type, flags.str,
			       event->data_size);

		esf_agent_logi(1, "process { ");
		esf_agent_logni_field(2, "pid", "d", event->process.pid);
		esf_agent_logni_field_str(2, "uuid", process_uuid, (int)sizeof(process_uuid) - 1);
		esf_agent_logni_field_str(2, "exe", parent_exe, event->process.exe.path.size);
		esf_agent_logni_field_str(2, "args", parent_args, event->process.args.size);
		esf_agent_logni_field_str(2, "env", parent_env, event->process.env.size);
		esf_agent_logi(1, "}");

		if (event->header.type == ESF_EVENT_TYPE_PROCESS_EXECUTION) {
			_uuid_to_str(process_uuid, event->process_execution.process.uuid);

			char *interpreter = esf_item_as_string(event, process_execution.interpreter);
			char *child_exe = esf_item_as_string(event, process_execution.process.exe.path);
			char *child_args = esf_item_as_string(event, process_execution.process.args);
			char *child_env = esf_item_as_string(event, process_execution.process.env);

			esf_agent_logi(1, "child { ");
			esf_agent_logni_field_str(2, "interpreter", interpreter,
						  event->process_execution.interpreter.size);
			esf_agent_logni_field(2, "pid", "d", event->process_execution.process.pid);
			esf_agent_logni_field(2, "ppid", "d", event->process_execution.process.ppid);
			esf_agent_logni_field_str(2, "uuid", process_uuid, (int)sizeof(process_uuid) - 1);
			esf_agent_logni_field_str(2, "exe", child_exe, event->process_execution.process.exe.path.size);
			esf_agent_logni_field_str(2, "args", child_args, event->process_execution.process.args.size);
			esf_agent_logni_field_str(2, "env", child_env, event->process_execution.process.env.size);
			esf_agent_logi(1, "}");

			if (interpreter) {
				free(interpreter);
			}
			if (child_exe) {
				free(child_exe);
			}
			if (child_args) {
				free(child_args);
			}
			if (child_env) {
				free(child_env);
			}
		} else if (event->header.type == ESF_EVENT_TYPE_PROCESS_SIGNAL) {
			_uuid_to_str(process_uuid, event->process_signal.target.uuid);

			char *child_exe = esf_item_as_string(event, process_signal.target.exe.path);
			char *child_args = esf_item_as_string(event, process_signal.target.args);
			char *child_env = esf_item_as_string(event, process_signal.target.env);

			esf_agent_logi(1, "child { ");
			esf_agent_logni_field(2, "pid", "d", event->process_signal.target.pid);
			esf_agent_logni_field(2, "ppid", "d", event->process_signal.target.ppid);
			esf_agent_logni_field_str(2, "uuid", process_uuid, (int)sizeof(process_uuid) - 1);
			esf_agent_logni_field_str(2, "exe", child_exe, event->process_signal.target.exe.path.size);
			esf_agent_logni_field_str(2, "args", child_args, event->process_signal.target.args.size);
			esf_agent_logni_field_str(2, "env", child_env, event->process_signal.target.env.size);
			esf_agent_logi(1, "}");
			esf_agent_logni_field(1, "signal", "d", event->process_signal.signal);

			if (child_exe) {
				free(child_exe);
			}
			if (child_args) {
				free(child_args);
			}
			if (child_env) {
				free(child_env);
			}
		} else if (event->header.type == ESF_EVENT_TYPE_PROCESS_TRACE) {
			_uuid_to_str(process_uuid, event->process_ptrace.target.uuid);

			char *child_exe = esf_item_as_string(event, process_ptrace.target.exe.path);
			char *child_args = esf_item_as_string(event, process_ptrace.target.args);
			char *child_env = esf_item_as_string(event, process_ptrace.target.env);

			esf_agent_logi(1, "child { ");
			esf_agent_logni_field(2, "pid", "d", event->process_ptrace.target.pid);
			esf_agent_logni_field(2, "ppid", "d", event->process_ptrace.target.ppid);
			esf_agent_logni_field_str(2, "uuid", process_uuid, (int)sizeof(process_uuid) - 1);
			esf_agent_logni_field_str(2, "exe", child_exe, event->process_ptrace.target.exe.path.size);
			esf_agent_logni_field_str(2, "args", child_args, event->process_ptrace.target.args.size);
			esf_agent_logni_field_str(2, "env", child_env, event->process_ptrace.target.env.size);
			esf_agent_logi(1, "}");
			esf_agent_logni_field(1, "mode", "d", event->process_ptrace.mode);

			if (child_exe) {
				free(child_exe);
			}
			if (child_args) {
				free(child_args);
			}
			if (child_env) {
				free(child_env);
			}
		} else if (ESF_EVENT_IS_IN_CATEGORY(FILE, event->header.type)) {
			/* all file events has file_info at top of struct */
			const char *fname = esf_item_as_ref(event, file_open.file.path);
			const char *mnt_point = esf_item_as_ref(event, file_open.file.fs.mount_point);

			uuid_string fs_uuid = { 0 };
			_uuid_to_str(fs_uuid, event->file_open.file.fs.uuid);

			esf_agent_logi(1, "file { ");
			esf_agent_logi(2, "fs { ");
			esf_agent_logni_field(3, "magic", "lx", event->file_open.file.fs.magic);
			esf_agent_logni_field_str(3, "uuid", fs_uuid, (int)sizeof(fs_uuid) - 1);
			esf_agent_logni_field_str(3, "mount_point", mnt_point,
						  event->file_open.file.fs.mount_point.size);
			esf_agent_logni_field_str(3, "id", event->file_open.file.fs.id,
						  (int)sizeof(event->file_open.file.fs.id));
			esf_agent_logi(2, "}");
			esf_agent_logni_field_str(2, "path", fname, event->file_open.file.path.size);
			esf_agent_logi(1, "}");
		}

		switch (decision) {
		case ESF_ACTION_DECISION_DENY:
			esf_agent_logi(0, "} -> deny" RESET);
			break;
		case ESF_ACTION_DECISION_ALLOW:
			esf_agent_logi(0, "} -> allow" RESET);
			break;
		default:
			esf_agent_logi(0, "}" RESET);
			break;
		}

		if (parent_exe) {
			free(parent_exe);
		}
		if (parent_args) {
			free(parent_args);
		}
		if (parent_env) {
			free(parent_env);
		}

		free(el);
	}

	return NULL;
}

typedef struct {
	const esf_events_channel_t *chan;
	events_queue_t *print_queue;
	on_event_callback callback;
	bool *should_run_flag;
} events_thread_args_t;

void _auth_callback(const esf_events_channel_t *channel, const esf_event_t *event, void *data)
{
	esf_action_decision_t decision = ESF_ACTION_DECISION_ALLOW;
	events_queue_t *print_queue = data;

	if (event->header.flags & ESF_EVENT_CAN_CONTROL) {
		if (event->header.type == ESF_EVENT_TYPE_PROCESS_EXECUTION) {
			const char *exe_path = esf_item_as_ref(event, process_execution.interpreter);

			decision = _is_program(exe_path, "python", event->process_execution.interpreter.size) ?
					   ESF_ACTION_DECISION_DENY :
					   ESF_ACTION_DECISION_ALLOW;
		}

		esf_event_make_decision(channel->agent, event, decision);
	}

	events_queue_push_event(print_queue, event, decision);
}

void _print_callback(__attribute_maybe_unused__ const esf_events_channel_t *channel, const esf_event_t *event,
		     void *data)
{
	events_queue_t *print_queue = data;
	events_queue_push_event(print_queue, event, -1);
}

static void *_accept_events_routine(void *arg)
{
	int err = 0;
	const events_thread_args_t *args = arg;

	const size_t buffer_size = PAGE_SIZE * 4096;
	esf_events_t *esf_events_buff = malloc(buffer_size);

	if (esf_events_buff == NULL) {
		esf_agent_err("malloc");
		err = ENOMEM;
		goto out;
	}

	const int polling_fd = epoll_create(0xABBA);

	if (polling_fd < 0) {
		esf_agent_err("epoll_create");
		err = errno;
		goto out;
	}

	struct epoll_event chan_poll_event = { 0 };

	chan_poll_event.data.fd = args->chan->fd;
	chan_poll_event.events = EPOLLIN;

	if (epoll_ctl(polling_fd, EPOLL_CTL_ADD, args->chan->fd, &chan_poll_event) != 0) {
		esf_agent_err("epoll_ctl");
		err = errno;
		goto out;
	}

	while (*args->should_run_flag) {
		struct epoll_event poll_events[POLL_MAX_EVENTS];
		const int wait_result = epoll_wait(polling_fd, poll_events, POLL_MAX_EVENTS, 1000);

		if (wait_result < 0) {
			err = errno;
			goto out;
		}

		if (wait_result == 0) {
			esf_agent_log("waiting for new events at channel %d...", args->chan->fd);
		}

		for (int i = 0; i < wait_result; ++i) {
			const struct epoll_event poll_event = poll_events[i];

			if (!(poll_event.events & POLLIN)) {
				continue;
			}

			err = _read_all_events(args->chan, esf_events_buff, buffer_size, args->callback,
					       args->print_queue);

			if (err) {
				goto out;
			}
		}
	}

out:
	if (err) {
		esf_agent_err("accepting routine failed");
	}

	return NULL;
}

typedef struct {
	const char *parent;
	const char *child;
} _auth_exec_filter;

static int _init_auth_channel(const esf_agent_t *agent, esf_events_channel_t *chan)
{
	int err = esf_agent_open_auth_channel(agent, chan);

	static _auth_exec_filter _auth_exec_filters[] = { { .parent = "*/bash", .child = "*/ping" } };

	if (err) {
		esf_agent_err("esf_agent_open_auth_channel");
		return err;
	}

	err = esf_event_subscribe(chan, ESF_EVENT_TYPE_PROCESS_EXECUTION);

	if (err) {
		esf_agent_err("esf_event_subscribe");
		return err;
	}

	for (int i = 0; i < ARRAY_SIZE(_auth_exec_filters); i++) {
		_auth_exec_filter exec_filter = _auth_exec_filters[i];
		esf_filter_t filter;
		esf_event_type_t proc_exec_type = ESF_EVENT_TYPE_PROCESS_EXECUTION;
		esf_filter_init(&filter, ESF_FILTER_TYPE_DROP, ESF_FILTER_MATCH_MODE_AND);
		esf_filter_add_rule(&filter, ESF_FILTER_EVENT_TYPE, &proc_exec_type, sizeof(proc_exec_type));
		esf_filter_add_rule(&filter, ESF_FILTER_PROCESS_PATH, exec_filter.parent, strlen(exec_filter.parent));
		esf_filter_add_rule(&filter, ESF_FILTER_TARGET_PATH, exec_filter.child, strlen(exec_filter.child));
		err = esf_event_add_filter(chan, &filter);

		if (err) {
			esf_agent_log("unable to add filter to chan %d, error: %s", err, strerror(errno));
			return err;
		}
	}

	esf_filter_t filter;
	esf_event_type_t proc_exec_type = ESF_EVENT_TYPE_PROCESS_EXECUTION;
	esf_filter_init(&filter, ESF_FILTER_TYPE_ALLOW, ESF_FILTER_MATCH_MODE_AND);
	esf_filter_add_rule(&filter, ESF_FILTER_EVENT_TYPE, &proc_exec_type, sizeof(proc_exec_type));
	esf_filter_add_rule(&filter, ESF_FILTER_PROCESS_PATH, "/usr/bin/*", strlen("/usr/bin/*"));
	esf_filter_add_rule(&filter, ESF_FILTER_TARGET_PATH, "/usr/bin/*", strlen("/usr/bin/*"));
	err = esf_event_add_filter(chan, &filter);

	if (err) {
		esf_agent_log("unable to add filter to chan %d, error: %s", err, strerror(errno));
		return err;
	}

out:
	return 0;
}

static int _init_listen_channel(const esf_agent_t *agent, esf_events_channel_t *chan)
{
	int err = esf_agent_open_listen_channel(agent, chan);

	if (err) {
		esf_agent_err("esf_agent_open_listen_channel");
		return err;
	}

	err = esf_event_subscribe(chan, ESF_EVENT_TYPE_PROCESS_EXECUTION);
	err |= esf_event_subscribe(chan, ESF_EVENT_TYPE_PROCESS_EXITED);
	err |= esf_event_subscribe(chan, ESF_EVENT_TYPE_PROCESS_TRACE);
	err |= esf_event_subscribe(chan, ESF_EVENT_TYPE_PROCESS_SIGNAL);

	// err |= esf_event_subscribe(chan, ESF_EVENT_TYPE_FILE_OPEN);

	if (err) {
		esf_agent_err("esf_event_subscribe");
		return err;
	}

out:
	return err;
}

static void _signal_hanlder(const int sig)
{
	esf_agent_log("got signal %d", sig);
	_print_thread_should_run = false;
	_listen_thread_should_run = false;
	_auth_thread_should_run = false;
}

int main(const int argc, const char **argv)
{
	int esf_fd = 0, err = 0;

	bool controller = false;
	bool listener = false;

	signal(SIGTERM, _signal_hanlder);
	signal(SIGINT, _signal_hanlder);

	for (int i = 0; i < argc; ++i) {
		if (!strcmp(argv[i], "--controller") || !strcmp(argv[i], "-c")) {
			esf_agent_log("running agent as controller");
			controller = true;
		}

		if (!strcmp(argv[i], "--listener") || !strcmp(argv[i], "-l")) {
			esf_agent_log("running agent as controller");
			listener = true;
		}
	}

	esf_agent_t agent = { 0 };
	pthread_t print_thread = 0, auth_thread = 0, listen_thread = 0;
	events_queue_t print_queue = { 0 };

	pthread_mutex_init(&print_queue.mtx, NULL);
	err = pthread_create(&print_thread, NULL, _print_routine, &print_queue);

	if (err) {
		goto out_join;
	}

	struct winsize w;
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	_win_width = w.ws_col > WIN_WIDTH_RES + 1 ? w.ws_col : WIN_WIDTH_RES;

	esf_fd = open("/dev/esf", O_RDWR);

	if (esf_fd < 0) {
		esf_agent_err("esf device");
		err = esf_fd;
		goto out_join;
	}

	err = esf_register_agent(esf_fd, &agent);

	if (err) {
		esf_agent_err("esf_register_agent");
		goto out_join;
	}

	esf_events_channel_t auth_chan;
	events_thread_args_t auth_args;

	esf_events_channel_t listen_chan;
	events_thread_args_t listen_args;

	if (controller) {
		err = _init_auth_channel(&agent, &auth_chan);

		if (err) {
			esf_agent_err("init_auth_channel");
			goto out_join;
		}

		auth_args.chan = &auth_chan;
		auth_args.print_queue = &print_queue;
		auth_args.callback = _auth_callback;
		auth_args.should_run_flag = &_auth_thread_should_run;

		err = pthread_create(&auth_thread, NULL, _accept_events_routine, &auth_args);

		if (err) {
			esf_agent_err("pthread_create");
			goto out_join;
		}

		_auth_thread_should_run = true;
	}

	if (listener) {
		err = _init_listen_channel(&agent, &listen_chan);

		if (err) {
			goto out_join;
		}

		if (err) {
			esf_agent_err("init_listen_channel");
			goto out_join;
		}

		listen_args.chan = &listen_chan;
		listen_args.print_queue = &print_queue;
		listen_args.callback = _print_callback;
		listen_args.should_run_flag = &_listen_thread_should_run;

		err = pthread_create(&listen_thread, NULL, _accept_events_routine, &listen_args);

		if (err) {
			esf_agent_err("pthread_create");
			goto out_join;
		}

		_listen_thread_should_run = true;
	}

	err = esf_agent_activate(&agent);

	if (err) {
		esf_agent_err("activating");
	}

out_join:
	if (controller && auth_thread) {
		pthread_join(auth_thread, NULL);
		close(auth_chan.fd);
	}

	if (listener && listen_thread) {
		pthread_join(listen_thread, NULL);
		close(listen_chan.fd);
	}

	_print_thread_should_run = false;
	_listen_thread_should_run = false;
	_auth_thread_should_run = false;

	pthread_join(print_thread, NULL);
	pthread_mutex_destroy(&print_queue.mtx);

	close(agent.fd);

	return err;
}