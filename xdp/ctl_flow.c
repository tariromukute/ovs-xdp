#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include "ctl_flow.h"
#include "datapath.h"
#include "flow.h"
#include "xdp_user_helpers.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

int flow_cmd(int argc, char **argv, void *params)
{
    char *description = "Manage flows";
    char *use = "xdp-ctl flow [command]";
    int error = 1;

    const struct command *cmd;
    for (cmd = flow_cmds; cmd->name != NULL; cmd++)
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
            print_cmd_usage(description, use, flow_cmds, NULL);
    }
    return error;
}

enum flow_format
{
    OPENFLOW,
    JSON,
    XML
};
struct flow_arguments
{
    char dp_name[NAME_MAX];
    char if_name[NAME_MAX];
    char file_name[PATH_MAX];
    int format;
    int version;
};

struct option_wrapper list_flows_options[] = {
    {{"help", no_argument, 0, 'h'}, "Show help", ""},
    {{"dp", required_argument, 0, 'd'}, "Show flows install on datapath", ""},
    {{"ifname", required_argument, 0, 'i'}, "Show flows install on a specific interface", ""},
    {{"file", required_argument, 0, 'f'}, "File to output or read flows", ""},
    {{"format", required_argument, 0, 't'}, "Displays the output in the specified format", ""},
    {{"protocol", required_argument, 0, 'p'}, "Allowed protocol version", ""},
    {{0, 0, 0, 0}, "", ""}};

static int parse_list_flows_options(int argc, char **argv, struct flow_arguments *args)
{
    int error = 0;
    struct option *long_options;

    if (option_wrappers_to_optionsx(list_flows_options, &long_options))
    {
        error = -1;
        printf("Unable to convert wrappers to options\n");
        goto out;
    }

    optind = 0; // reset getopt
    int c;
    for (;;)
    {

        int option_index = 0;
        c = getopt_long(argc, argv, "",
                        long_options, &option_index);

        if (c == -1)
        {
            break;
        }
        
        switch (c)
        {
        case 'h':
            error = EINVAL;
            goto out;
        case 'd':
            strcpy(args->dp_name, optarg);
            break;
        case 'i':
            strcpy(args->if_name, optarg);
            break;
        case 'f':
            strcpy(args->file_name, optarg);
            break;
        /* TODO: implement option */
        case 't':
        case 'p':
            break;
        case '?':
            error = EINVAL;
            goto out;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }
out:
    return error;
}

int list_flow_cmd(int argc, char **argv, void *params)
{
    char *description = "Prints out the logs from the datapath. It can print all logs\n\
                        or filter by log level: debug, error, info.";
    char *use = "xdp-ctl logs list [flags]";
    int MAX_FLOWS = 10;
    int error = 0;
    struct flow_arguments args;
    memset(&args, 0, sizeof(struct flow_arguments));
    error = parse_list_flows_options(argc, argv, &args);
    if (error)
        goto out;

    struct xdp_flow *flow = NULL;
    struct xdp_flow_key *key = NULL;
    struct xdp_flow **list_flow;
    list_flow = malloc(MAX_FLOWS * sizeof(struct xdp_flow_key));
    int cnt = 0;
    if (strcmp(args.dp_name, ""))
    {
        struct xdp_datapath dp = {
            .name = args.dp_name
        };
        while (!error && cnt < MAX_FLOWS)
        {
            error = xdp_dp_flow_next(&dp, key, flow);
            if (!error)
            {
                memcpy(key, &flow->key, sizeof(struct xdp_flow_key));
                memcpy(&list_flow[cnt], flow, sizeof(struct xdp_flow));
                cnt++;
            }
            else
            {
                goto print;
            }
        }
    }
    else if (strcmp(args.if_name, ""))
    {
        int if_index = -1;
        if_index = if_nametoindex(args.if_name);
        if (if_index < 0)
        {
            error = ENONET;
            goto out;
        }

        while (!error && cnt < MAX_FLOWS)
        {
            error = xdp_if_flow_next(if_index, key, flow);
            if (!error)
            {
                memcpy(key, &flow->key, sizeof(struct xdp_flow_key));
                memcpy(&list_flow[cnt], flow, sizeof(struct xdp_flow));
                cnt++;
            }
            else
            {
                goto print;
            }
        }
    } else {
        /* TODO: implement default action for list flows. Either iterate all datapaths */
        printf("Provide either datapath name (--dp <datapath_name>) or interface name (--ifname <if_name>)\n");
        goto out;
    }

print:
    if (cnt == 0)
    {
        printf("No flows found\n");
        goto out;
    }
    for (size_t i = 0; i < cnt; i++)
    {
        char buf[4096];
        error = format_xdp_key(&list_flow[i]->key, buf);
        if (error)
        {
            goto out;
        }
        printf("%s\n", buf);
    }

out:
    if (error == EINVAL) {
        print_cmd_usage(description, use, NULL, list_flows_options);
    }
    return error;
}

int add_flow_cmd(int argc, char **argv, void *params)
{
    char *description = "Adds a flow to the specified datapath";
    char *use = "xdp-ctl flow add <flow> [flags]";
    int error = 0;
    struct flow_arguments *args = NULL;
    error = parse_list_flows_options(argc, argv, args);
    if (error)
        goto out;

    /* TODO: implement method */
    printf("Work in progress\n");

out:
    if (error == EINVAL)
        print_cmd_usage(description, use, NULL, list_flows_options);
    return error;
}

int edit_flow_cmd(int argc, char **argv, void *params)
{
    char *description = "Edits a flow flow on the given datapath";
    char *use = "xdp-ctl flow edit <flow> [flags]";
    int error = 0;
    struct flow_arguments *args = NULL;
    error = parse_list_flows_options(argc, argv, args);
    if (error)
        goto out;

    /* TODO: implement method */
    printf("Work in progress\n");
    
out:
    if (error == EINVAL)
        print_cmd_usage(description, use, NULL, list_flows_options);
    return error;
}
#pragma GCC diagnostic pop