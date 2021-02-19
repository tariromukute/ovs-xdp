#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/wait.h> 
#include <sys/epoll.h>
#include <signal.h>
#include "ctl_upcall.h"
#include "xdp_user_helpers.h"
#include "dynamic-string.h"
#include "flow.h"
#include "xf.h"
#include "datapath.h"

#define TRACEFS_PIPE "/sys/kernel/debug/tracing/trace_pipe"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// #define SAMPLE_SIZE sizeof(struct xdp_flow_key)

static const char *upcall_pin_basedir = "/sys/fs/bpf/ovs-xdp";
static const char *_upcall_map = "_upcall_map";
static struct perf_buffer *pb = NULL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"


int upcall_cmd(int argc, char **argv, void *params)
{
    char *description = "Manage upcall";
    char *use = "xdp-ctl upcall [command]";
    int error = 1;

    const struct command *cmd;
    for (cmd = upcall_cmds; cmd->name != NULL; cmd++)
    {
        if (!strcmp(cmd->name, argv[1]))
        {
            printf("%s - \n", cmd->name);
            error = cmd->cmd(argc - 1, &argv[1], params);
            printf("%d \n", error);
            break;
        }
    }

    if (error)
    {
        if (error == 1)
            print_cmd_usage(description, use, upcall_cmds, NULL);

        return error;
    }
    return 0;
}

struct level
{
    int info;
    int error;
    int debug;
};

static void sig_handler(int signo)
{
    perf_buffer__free(pb);
    exit(0);
}

static void print_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    struct {
        __u16 cookie;
        __u16 pkt_len;
        __u8  pkt_data[MAX_FRAME_SIZE];
    } __attribute__((packed)) *e = data;

    
    if (e->cookie == UPCALL_COOKIE) {

        if (true) {
            printf("pkt len: %-5d bytes. hdr: ", e->pkt_len);
            for (int i = 0; i < e->pkt_len; i++)
                printf("%02x ", e->pkt_data[i]);
            printf("\n");
        }
    }

}

static void copy_bpf_output(void *ctx, int cpu, void *data, __u32 size)
{
    struct {
        __u16 cookie;
        __u16 pkt_len;
        __u8  pkt_data[MAX_FRAME_SIZE];
    } __attribute__((packed)) *e = data;

    memcpy(ctx, data, size);

    if (e->cookie == UPCALL_COOKIE) {

        if (true) {
            printf("%s pkt len: %-5d bytes. hdr: ", __func__, e->pkt_len);
            // for (int i = 0; i < e->pkt_len; i++)
            //     printf("%02x ", e->pkt_data[i]);
            // printf("\n");
        }
    }

}

struct option_wrapper list_upcall_options[] = {
    {{"help", no_argument, 0, 'h'}, "Show help", ""},
    {{"all", no_argument, 0, 'a'}, "Show all upcall", ""},
    {{"info", no_argument, 0, 'i'}, "Show information upcall", ""},
    {{"debug", no_argument, 0, 'd'}, "Show debug upcall", ""},
    {{"error", no_argument, 0, 'e'}, "Show error upcall", ""},
    {{0, 0, 0, 0}, "", ""}};

static int parse_list_upcall_options(int argc, char **argv, struct level *level)
{
    int error = 0;
    struct option *long_options;

    if (option_wrappers_to_optionsx(list_upcall_options, &long_options))
    {
        error = -1;
        printf("Unable to convert wrappers to options\n");
        goto out;
    }

    optind = 0; // reset getopt
    int c, cnt = 0;
    for (;;)
    {

        int option_index = 0;
        c = getopt_long(argc, argv, "",
                        long_options, &option_index);

        if (c == -1)
        {
            break;
        }
        printf("option %s", long_options[option_index].name);
        if (optarg)
            printf(" with arg %s", optarg);
        printf("\n");
        switch (c)
        {
        case 'h':
            error = EINVAL;
            goto out;
        case 'd':
            level->debug = 1;
            cnt++;
            break;
        case 'e':
            level->error = 1;
            cnt++;
            break;
        case 'i':
            level->info = 1;
            cnt++;
            break;
        case 'a':
            level->debug = 1;
            level->error = 1;
            level->info = 1;
            cnt++;
            break;
        case '?':
            error = EINVAL;
            goto out;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }
    if (!cnt)
    {
        printf("cnt not 0 %d\n",cnt);
        level->debug = 1;
        level->error = 1;
        level->info = 1;
    }
out:
    return error;
}

struct handler {
    int pmu_fds[MAX_CPUS];
    struct perf_event_mmap_page *headers[MAX_CPUS];
};

struct perf_cpu_buf {
	struct perf_buffer *pb;
	void *base; /* mmap()'ed memory */
	void *buf; /* for reconstructing segmented data */
	size_t buf_size;
	int fd;
	int cpu;
	int map_key;
};

struct perf_buffer {
	perf_buffer_event_fn event_cb;
	perf_buffer_sample_fn sample_cb;
	perf_buffer_lost_fn lost_cb;
	void *ctx; /* passed into callbacks */

	size_t page_size;
	size_t mmap_size;
	struct perf_cpu_buf **cpu_bufs;
	struct epoll_event *events;
	int cpu_cnt; /* number of allocated CPU buffers */
	int epoll_fd; /* perf event FD */
	int map_fd; /* BPF_MAP_TYPE_PERF_EVENT_ARRAY BPF map FD */
};

struct level level;
int list_upcall_cmd(int argc, char **argv, void *params)
{
    printf("Here\n");
    char *description = "Prints out the upcall from the datapath. It can print all upcall\n\
                        or filter by log level: debug, error, info.";
    char *use = "xdp-ctl upcall list [flags]";
    int error = 0;

    printf("------------------------------------\n");
    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s", upcall_pin_basedir, _upcall_map);
    if (len < 0) {
        error = -EINVAL;
        goto out;
    } else if(len >= PATH_MAX) {
        error = ENAMETOOLONG;
        goto out;
    }

    int map_fd = bpf_obj_get(buf);
    if (map_fd < 0) {
        error = ENOENT;
        
        goto out;
    }
    struct perf_buffer_opts pb_opts = {};

    if (signal(SIGINT, sig_handler) ||
        signal(SIGHUP, sig_handler) ||
        signal(SIGTERM, sig_handler)) {
        printf("signal\n");
        return 1;
    }

    pb_opts.sample_cb = copy_bpf_output;
    pb = perf_buffer__new(map_fd, 8, &pb_opts);
    error = libbpf_get_error(pb);
    if (error) {
        printf("perf_buffer setup failed\n");
        return 1;
    }
 
    int offset = 0;
    int n_events = 0;

    while (true) {

        char ofbuf[1522];

        if (offset >= n_events) {
            int retval;

            offset = n_events = 0;

            do {
                retval = epoll_wait(pb->epoll_fd, pb->events,
                                    pb->cpu_cnt, 1000);
            } while (retval < 0 && errno == EINTR);

            if (retval < 0) {
                printf("epoll_wait failed (%d)\n", errno);
            } else if (retval >= 0) {
                printf("retval %d \n", retval);
                n_events = retval;
            }
        }

        while (offset < n_events) {
        
            size_t buf_idx = pb->events[offset].data.u32;
            pb->ctx = &ofbuf;
            offset++;

            int err = perf_buffer__consume_buffer(pb, buf_idx);
            if (err) {
                pr_warn("error while processing records: %d\n", err);
                continue;
            }

            struct {
                __u16 cookie;
                __u16 pkt_len;
                __u8  pkt_data[MAX_FRAME_SIZE];
            } __attribute__((packed)) *e = &ofbuf;

            // print packet
            printf("pkt len: %-5d bytes. hdr: ", e->pkt_len);
            for (int i = 0; i < e->pkt_len; i++)
                printf("%02x ", e->pkt_data[i]);
            printf("\n");
            free(ofbuf);
            break;
        }
    }
    // while ((error = perf_buffer__poll(pb, 1000)) >= 0) {
    //     wait(1000);
    // }

    kill(0, SIGINT);
    
out:
    if (map_fd && map_fd >= 0)
        close(map_fd);
    if (error == EINVAL)
        print_cmd_usage(description, use, NULL, list_upcall_options);
    return error;
}
#pragma GCC diagnostic pop