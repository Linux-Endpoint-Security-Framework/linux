#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/user.h>

#include <linux/esf/ctl.h>

#define EPOLL_SIZE 256
#define EPOLL_MAX_EVENTS 20

static const uint16_t _win_width_res = 30;
static uint16_t _win_width = 80;
#define _max_pw (_win_width - _win_width_res)
#define _null_str "(null)"

#define esf_item_as_string(event_ptr, item_field) esf_event_item_copy((event_ptr), &((event_ptr)->item_field))
#define esf_item_as_ref(event_ptr, item_field) esf_event_item_data((event_ptr), &((event_ptr)->item_field))

#define esf_agent_err(fmt, ...) fprintf(stderr, "[sample]: "fmt": %s\n", ##__VA_ARGS__, strerror(errno))
#define esf_agent_log(fmt, ...) fprintf(stdout, "[sample]: "fmt"\n", ##__VA_ARGS__)
#define esf_agent_logn_field_str(name, field, len, ...) \
        esf_agent_log("\t"name": %.*s%s (%d)", _max_pw, field, (len) > _max_pw ? "..." : "", (len))
#define esf_agent_log_field_str(name, field, ...) \
        esf_agent_logn_field_str(name, field ? field : _null_str, field ? strlen(field) : sizeof(_null_str), ##__VA_ARGS__)

typedef struct esf_event_iterator {
    uint32_t _i;
    uint32_t _total;
    const char *_buffer;
} esf_event_iterator_t;

static inline esf_event_iterator_t esf_new_event_iterator(const void *buffer, uint64_t events_count) {
    esf_event_iterator_t it = {
            ._i = 0,
            ._buffer = buffer,
            ._total = events_count,
    };

    return it;
}

static inline bool esf_event_iterator_is_end(esf_event_iterator_t it) {
    return it._i >= it._total;
}

static inline const esf_event_t *esf_event_iterator_get_event(esf_event_iterator_t it) {
    if (esf_event_iterator_is_end(it)) {
        return NULL;
    }

    return (esf_event_t *) it._buffer;
}

static inline size_t esf_event_size(const esf_event_t *event) {
    return sizeof(*event) + event->data_size;
}

static inline esf_event_t *esf_event_copy(const esf_event_t *event) {
    size_t event_size = esf_event_size(event);
    esf_event_t *dup = malloc(esf_event_size(event));
    return memcpy(dup, event, event_size);
}

static inline esf_event_iterator_t esf_event_iterator_next(esf_event_iterator_t it) {
    if (esf_event_iterator_is_end(it)) {
        return it;
    }

    const esf_event_t *event = esf_event_iterator_get_event(it);

    if (!event) {
        return it;
    }

    it._i++;
    it._buffer += sizeof(*event) + event->data_size;

    return it;
}

#define for_each_esf_event(buff, max, it)\
            for (esf_event_iterator_t it = esf_new_event_iterator(buff, max);\
                 !esf_event_iterator_is_end(it);\
                 it = esf_event_iterator_next(it))\


int esf_register_agent(int esf_fd) {
    esf_ctl_register_agent_t register_agent = {
            .api_version = ESF_VERSION,
    };

    esf_agent_log("registering with API version: %d", ESF_VERSION);

    int agent_fd = ioctl(esf_fd, ESF_CTL_REGISTER_AGENT, &register_agent);
    return agent_fd;
}

int esf_agent_subscribe(int agent_fd, esf_event_type_t event_type, esf_agent_ctl_subscribe_flags_t flags) {
    esf_agent_log("subscribing to event type %d...", event_type);
    esf_agent_ctl_subscribe_t subscribe_cmd = {
            .event_type = event_type,
            .flags = flags,
    };

    return ioctl(agent_fd, ESF_AGENT_CTL_SUBSCRIBE, &subscribe_cmd);
}

int esf_agent_activate(int agent_fd) {
    esf_agent_ctl_activate_t activate_cmd = {};
    esf_agent_log("activating agent...");
    return ioctl(agent_fd, ESF_AGENT_CTL_ACTIVATE, &activate_cmd);
}

int esf_event_make_decision(int agent_fd, const esf_event_t *event, esf_action_decision_t decision) {
    esf_agent_ctl_decide_t decide_cmd = {
            .event_id = event->header.id,
            .decision = decision,
    };
    esf_agent_log("%s event %llu", decision == ESF_ACTION_DECISION_ALLOW ? "allow" : "deny", event->header.id);
    return ioctl(agent_fd, ESF_AGENT_CTL_DECIDE, &decide_cmd);
}

const void *esf_event_item_data(const esf_event_t *event, const esf_item_t *item) {
    return event->data + item->offset;
}

void *esf_event_item_copy(const esf_event_t *event, const esf_item_t *item) {
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

const char *_basename(char const *path, uint32_t pathlen) {
    while (pathlen > 0) {
        if (path[pathlen] != '/') {
            break;
        }

        pathlen--;
    }

    return path + pathlen;
}

bool _is_program(const char *p, const char *e, uint32_t pathlen) {
    const char *base = _basename(p, pathlen);
    return strcmp(base, e) == 0;
}

typedef struct print_elem {
    struct print_elem *next;

    esf_event_t *event;
    esf_action_decision_t decision;
} print_elem_t;

typedef struct {
    print_elem_t *elems;
    size_t elems_count;
    pthread_mutex_t mtx;
} print_queue_t;

void print_queue_push_event(print_queue_t *pq, const esf_event_t *event, esf_action_decision_t d) {
    print_elem_t *el = malloc(sizeof(print_elem_t));
    el->event = esf_event_copy(event);
    el->decision = d;

    pthread_mutex_lock(&pq->mtx);

    el->next = pq->elems;
    pq->elems = el;

    pq->elems_count++;

    pthread_mutex_unlock(&pq->mtx);
}

print_elem_t *print_queue_pop(print_queue_t *pq) {
    print_elem_t *elem = NULL;
    pthread_mutex_lock(&pq->mtx);

    if (pq->elems_count == 0) {
        goto out_unlock;
    }

    elem = pq->elems;

    if (elem) {
        pq->elems = elem->next;
    } else {
        pq->elems = NULL;
    }

    pq->elems_count--;

    out_unlock:
    pthread_mutex_unlock(&pq->mtx);

    return elem;
}

_Noreturn void *_print_routine(void *arg) {
    print_queue_t *print_queue = arg;

    while (true) {
        print_elem_t *el = print_queue_pop(print_queue);
        if (!el) { continue; }
        const esf_event_t *event = el->event;
        esf_action_decision_t decision = el->decision;

        char *parent_exe = esf_item_as_string(event, header.process.exe.path);
        char *parent_args = esf_item_as_string(event, header.process.args);
        char *parent_env = esf_item_as_string(event, header.process.env);

        esf_agent_log("event [%llu] type: %d, data size: %llu {", event->header.id, event->header.type,
                      event->data_size);

        esf_agent_log("\tparent { ");
        esf_agent_logn_field_str("\texe", parent_exe, event->header.process.exe.path.size);
        esf_agent_logn_field_str("\targs", parent_args, event->header.process.args.size);
        esf_agent_logn_field_str("\tenv", parent_env, event->header.process.env.size);
        esf_agent_log("\t}");

        if (event->header.type == ESF_EVENT_TYPE_PROCESS_EXECUTION) {
            char *interpreter = esf_item_as_string(event, process_execution.interpreter);
            char *child_exe = esf_item_as_string(event, process_execution.process.exe.path);
            char *child_args = esf_item_as_string(event, process_execution.process.args);
            char *child_env = esf_item_as_string(event, process_execution.process.env);

            esf_agent_log("\tchild { ");
            esf_agent_logn_field_str("\tinterpreter", interpreter, event->process_execution.interpreter.size);
            esf_agent_logn_field_str("\texe", child_exe, event->process_execution.process.exe.path.size);
            esf_agent_logn_field_str("\targs", child_args, event->process_execution.process.args.size);
            esf_agent_logn_field_str("\tenv", child_env, event->process_execution.process.env.size);
            esf_agent_log("\t}");

            if (interpreter) { free(interpreter); }
            if (child_exe) { free(child_exe); }
            if (child_args) { free(child_args); }
            if (child_env) { free(child_env); }

        } else if (ESF_EVENT_IS_IN_CATEGORY(FILE, event->header.type)) {
            /* all file events has file_info at top of struct */
            const char *fname = esf_item_as_ref(event, file_open.file.path);

            esf_agent_log("\tfile { ");
            esf_agent_logn_field_str("\tfile: ", fname, event->file_open.file.path.size);
            esf_agent_log("\t}");
        }

        esf_agent_log("} -> %s", decision == ESF_ACTION_DECISION_ALLOW ? "allow" : "deny");

        if (parent_exe) { free(parent_exe); }
        if (parent_args) { free(parent_args); }
        if (parent_env) { free(parent_env); }

        free(el);
    }
}

int main(int argc, char **argv) {
    int epoll_fd = 0, esf_fd = 0, agent_fd = 0;
    size_t buffer_size = PAGE_SIZE * 4096;
    esf_event_t *esf_events_buff = malloc(buffer_size);
    mprotect(esf_events_buff, buffer_size, PROT_WRITE | PROT_READ);

    pthread_t print_thread;
    print_queue_t print_queue;
    memset(&print_queue, 0, sizeof(print_queue));

    pthread_mutex_init(&print_queue.mtx, NULL);
    pthread_create(&print_thread, NULL, _print_routine, &print_queue);

    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);

    _win_width = w.ws_col > _win_width_res + 1 ? w.ws_col : _win_width_res;

    esf_fd = open("/dev/esf", O_RDWR);
    struct epoll_event ev, events[EPOLL_MAX_EVENTS];
    int error;

    if (esf_fd < 0) {
        esf_agent_err("esf device");
        error = esf_fd;
        goto out;
    }

    agent_fd = esf_register_agent(esf_fd);

    if (agent_fd < 0) {
        esf_agent_err("esf_register_agent");
        error = agent_fd;
        goto out;
    }

    epoll_fd = epoll_create(EPOLL_SIZE);

    if (epoll_fd < 0) {
        esf_agent_err("epoll_create");
        error = epoll_fd;
        goto out;
    }

    ev.data.fd = agent_fd;
    ev.events = EPOLLIN;

    error = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, agent_fd, &ev);

    if (error) {
        esf_agent_err("epoll_ctl");
        goto out;
    }

    error |= esf_agent_subscribe(agent_fd, ESF_EVENT_TYPE_PROCESS_EXECUTION, ESF_SUBSCRIBE_AS_CONTROLLER);
    error |= esf_agent_subscribe(agent_fd, ESF_EVENT_TYPE_PROCESS_EXITED, ESF_SUBSCRIBE_NONE);
    error |= esf_agent_subscribe(agent_fd, ESF_EVENT_TYPE_FILE_OPEN, ESF_SUBSCRIBE_NONE);
    error |= esf_agent_subscribe(agent_fd, ESF_EVENT_TYPE_FILE_TRUNCATE, ESF_SUBSCRIBE_NONE);

    if (error) {
        esf_agent_err("esf_agent_subscribe");
        goto out;
    }

    error = esf_agent_activate(agent_fd);

    if (error) {
        esf_agent_err("esf_agent_activate");
        goto out;
    }

    while (true) {
        int wait_result = epoll_wait(epoll_fd, events, EPOLL_MAX_EVENTS, 1000);

        if (wait_result < 0) {
            esf_agent_err("epoll_wait");
            error = wait_result;
            goto out;
        }

        if (wait_result == 0) {
            esf_agent_log("waiting for new events...");
        }

        for (int i = 0; i < wait_result; ++i) {
            if ((events[i].events & EPOLLIN) != EPOLLIN) {
                continue;
            }

            long events_count = read(events[i].data.fd, esf_events_buff, buffer_size);

            if (events_count <= 0) {
                continue;
            }

            esf_agent_log("accepted %ld events", events_count);

            for_each_esf_event(esf_events_buff, events_count, it) {
                const esf_event_t *event = esf_event_iterator_get_event(it);
                esf_action_decision_t decision = ESF_ACTION_DECISION_ALLOW;

                if (event->header.flags & ESF_EVENT_CAN_CONTROL) {
                    if (event->header.type == ESF_EVENT_TYPE_PROCESS_EXECUTION) {
                        const char *exe_path = esf_item_as_ref(event, header.process.exe.path);
                        decision = _is_program(exe_path, "python", event->header.process.exe.path.size)
                                   ? ESF_ACTION_DECISION_DENY : ESF_ACTION_DECISION_ALLOW;
                    }

                    esf_event_make_decision(agent_fd, event, decision);
                }

                print_queue_push_event(&print_queue, event, decision);
            }
        }
    }

    out:
    pthread_mutex_destroy(&print_queue.mtx);

    if (agent_fd > 0) { close(agent_fd); }
    if (epoll_fd > 0) { close(agent_fd); }

    return error;
}