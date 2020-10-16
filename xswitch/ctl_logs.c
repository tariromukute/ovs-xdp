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
#include <signal.h>
#include "ctl_logs.h"
#include "xdp_user_helpers.h"
#include "dynamic-string.h"
#include "flow.h"
#include "xf.h"
#include "datapath.h"

#define TRACEFS_PIPE "/sys/kernel/debug/tracing/trace_pipe"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define SAMPLE_SIZE 64ul
// #define SAMPLE_SIZE sizeof(struct xdp_flow_key)

static const char *perf_pin_basedir = "/sys/fs/bpf/ovs-xdp";
static const char *_perf_map = "_perf_map";
static struct perf_buffer *pb = NULL;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

static int list_map_keys() 
{
    int error = 0;
    int if_index = -1;
    if_index = if_nametoindex("vxdp0");
    if (if_index < 0)
    {
        error = ENONET;
        goto out;
    }

    int MAX_FLOWS = 30;
    int cnt = 0;
    struct xf_key key;
    memset(&key, 0, sizeof(struct xf_key));
    struct xf *flow = NULL;
    printf("----Printing list of keys in map ----\n");
    while (!error && cnt < MAX_FLOWS)
    {
        error = xswitch_br__flow_next("ovs-xdp", &key, &flow);
        if (!error)
        {
            memcpy(&key, &flow->key, sizeof(struct xf_key));
            struct ds ds = DS_EMPTY_INITIALIZER;
            xdp_flow_key_format(&ds, &key);
            printf("%s \n", ds_cstr(&ds));
            ds_destroy(&ds);

            struct ds dsx = DS_EMPTY_INITIALIZER;
            ds_put_hex(&dsx, &key, sizeof(struct xf_key));
            printf("%s \n", ds_cstr(&dsx));
            ds_destroy(&dsx);
            cnt++;
        }
        else
        {
            break;
        }
    }
    printf("-----------------------------------\n");

out:
    return error;
}

int logs_cmd(int argc, char **argv, void *params)
{
    char *description = "Manage logs";
    char *use = "xdp-ctl logs [command]";
    int error = 1;

    const struct command *cmd;
    for (cmd = logs_cmds; cmd->name != NULL; cmd++)
    {
        if (!strcmp(cmd->name, argv[1]))
        {
            error = cmd->cmd(argc - 1, &argv[1], params);
            break;
        }
    }

    if (error)
    {
        if (error == 1)
            print_cmd_usage(description, use, logs_cmds, NULL);

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
        __u16 data_len; // the length of the data
        __u8 data[XFA_BUF_MAX_SIZE]; // the data being sent via perf
        __u8  pkt_data[SAMPLE_SIZE];
    } __attribute__((packed)) *e = data;

    list_map_keys();
    if (e->cookie == LOG_XF_KEY) {
        printf("========== Logging xf key ============\n");
        struct xf_key key;
        memcpy(&key, &e->data, sizeof(struct xf_key));
        struct ds ds = DS_EMPTY_INITIALIZER;
        xdp_flow_key_format(&ds, &key);
        printf("%s \n", ds_cstr(&ds));
        ds_destroy(&ds);

        struct ds dsx = DS_EMPTY_INITIALIZER;
        ds_put_hex(&dsx, &key, sizeof(struct xf_key));
        printf("%s \n", ds_cstr(&dsx));
        ds_destroy(&dsx);
        printf("=================================================\n");
    } else if (e->cookie == LOG_XF_ACT) {
        printf("========== Logging xf action ============\n");
        struct xf_act act;
        memcpy(&act, &e->data, sizeof(struct xf_act));
        // struct ds ds = DS_EMPTY_INITIALIZER;
        // xdp_flow_key_format(&ds, &key);
        // printf("%s \n", ds_cstr(&ds));
        printf("=================================================\n");
    } else if (e->cookie == LOG_DEBUG) {
        printf("%s\n", e->data);
        return;
    } else if (e->cookie == LOG_INFO) {
        printf("%s\n", e->data);
        return;
    } else if (e->cookie == LOG_WARN) {
        printf("%s\n", e->data);
        return;
    } else if (e->cookie == LOG_ERR) {
        printf("%s\n", e->data);
        return;
    }

    printf("level %d\n", e->cookie);
}

struct option_wrapper list_logs_options[] = {
    {{"help", no_argument, 0, 'h'}, "Show help", ""},
    {{"all", no_argument, 0, 'a'}, "Show all logs", ""},
    {{"info", no_argument, 0, 'i'}, "Show information logs", ""},
    {{"debug", no_argument, 0, 'd'}, "Show debug logs", ""},
    {{"error", no_argument, 0, 'e'}, "Show error logs", ""},
    {{0, 0, 0, 0}, "", ""}};

static int parse_list_logs_options(int argc, char **argv, struct level *level)
{
    int error = 0;
    struct option *long_options;

    if (option_wrappers_to_optionsx(list_logs_options, &long_options))
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

struct level level;
int list_logs_cmd(int argc, char **argv, void *params)
{
    char *description = "Prints out the logs from the datapath. It can print all logs\n\
                        or filter by log level: debug, error, info.";
    char *use = "xdp-ctl logs list [flags]";
    int error = 0;

    printf("------------------------------------\n");
    char buf[PATH_MAX];
    int len = snprintf(buf, PATH_MAX, "%s/%s", perf_pin_basedir, _perf_map);
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

    pb_opts.sample_cb = print_bpf_output;
    pb = perf_buffer__new(map_fd, 8, &pb_opts);
    error = libbpf_get_error(pb);
    if (error) {
        printf("perf_buffer setup failed\n");
        return 1;
    }

    while ((error = perf_buffer__poll(pb, 1000)) >= 0) {
    }

    kill(0, SIGINT);
    
out:
    if (map_fd >= 0)
        close(map_fd);
    if (error == EINVAL)
        print_cmd_usage(description, use, NULL, list_logs_options);
    return error;
}
#pragma GCC diagnostic pop