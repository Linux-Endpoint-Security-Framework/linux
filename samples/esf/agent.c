#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/user.h>

#include <linux/esf/ctl.h>

#define EPOLL_SIZE 256
#define EPOLL_MAX_EVENTS 20

static const uint16_t _win_width_res = 25;
static uint16_t _win_width = 80;
#define _max_pw (_win_width - _win_width_res)
#define _null_str "(null)"

#define esf_item_as_string(event_ptr, item_field) esf_event_item_copy((event_ptr), &((event_ptr)->item_field))

#define esf_agent_err(fmt, ...) fprintf(stderr, "[sample]: "fmt": %s\n", ##__VA_ARGS__, strerror(errno))
#define esf_agent_log(fmt, ...) fprintf(stdout, "[sample]: "fmt"\n", ##__VA_ARGS__)
#define esf_agent_logn_field_str(name, field, len, ...) \
        esf_agent_log("\t"name": %.*s%s", _max_pw, field, (len) > _max_pw ? "..." : "")
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

int esf_agent_subscribe(int agent_fd, esf_event_type_t event_type) {
    esf_agent_log("subscribing to event type %d...", event_type);
    esf_agent_ctl_subscribe_t subscribe_cmd = {
            .event_type = event_type,
    };

    return ioctl(agent_fd, ESF_AGENT_CTL_SUBSCRIBE, &subscribe_cmd);
}

int esf_agent_activate(int agent_fd) {
    esf_agent_ctl_activate_t activate_cmd = {};
    esf_agent_log("activating agent...");
    return ioctl(agent_fd, ESF_AGENT_CTL_ACTIVATE, &activate_cmd);
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


int main(int argc, char **argv) {
    int epoll_fd = 0, esf_fd = 0, agent_fd = 0;
    size_t buffer_size = PAGE_SIZE * 4096;
    esf_event_t *esf_events_buff = malloc(buffer_size);
    mprotect(esf_events_buff, buffer_size, PROT_WRITE | PROT_READ);

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

    error = esf_agent_subscribe(agent_fd, ESF_EVENT_TYPE_PROCESS_EXECUTION);

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

                char *exe = esf_item_as_string(event, header.process.exe);
                char *args = esf_item_as_string(event, header.process.args);
                char *env = esf_item_as_string(event, header.process.env);

                esf_agent_log("event %d (data size: %llu)", event->header.type, event->data_size);
                esf_agent_log_field_str("process", exe, event->header.process.exe.size);
                esf_agent_log_field_str("args", args, event->header.process.args.size);
                esf_agent_log_field_str("env", env, event->header.process.env.size);

                if (args) { free(args); }
                if (env) { free(env); }
            }
        }
    }

    out:
    if (agent_fd > 0) { close(agent_fd); }
    if (epoll_fd > 0) { close(agent_fd); }

    return error;
}