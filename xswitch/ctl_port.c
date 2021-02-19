#include <stdio.h>
#include <string.h>
#include "ctl_port.h"
#include "net_utils.h"
#include "datapath.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

struct port_arguments {
    int version;
};

struct option_wrapper port_options[] = {
    {{"help", no_argument, 0, 'h'}, "Show help", ""},
    {{"version", required_argument, 0, 'v'}, "The version to be used", ""},
    {{0, 0, 0, 0}, "", ""}};

static int parse_port_options(int argc, char **argv, struct port_arguments *args)
{
    int error = 0;
    struct option *long_options;

    if (option_wrappers_to_optionsx(port_options, &long_options))
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
        case 'v':
            args->version = atoi(optarg);
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

int port_cmd(int argc, char **argv,  void *params)
{
    char *description = "Manage port";
    char *use = "xdp-ctl port [command]";
    int error = 1;

    const struct command *cmd;
    for (cmd = port_cmds; cmd->name != NULL; cmd++)
    {
        if (!strcmp(cmd->name, argv[1]))
        {
            error = cmd->cmd(argc - 1, &argv[1], params);
            break;
        }
    }

    if (error) {
        if (error == 1)
            print_cmd_usage(description, use, port_cmds, NULL);
    }
    return error;
}

int list_port_cmd(int argc, char **argv,  void *params)
{
    printf("Work in progress\n");
    return 0;
}

int add_port_cmd(int argc, char **argv,  void *params)
{
    char *description = "Adds a port to a data path";
    char *use = "xdp-ctl port add <datapath name> <port name> [flags]";
    int error = 0;

    struct port_arguments *args = NULL;
    error = parse_port_options(argc, argv, args);
    if (error)
        goto out;

    if (argc != 3) {
        error = EINVAL;
        goto out;
    }

    char brname[IFNAMSIZ] = {'\0'};
    strncpy(brname, argv[1], IFNAMSIZ-1);

    char ifname[IFNAMSIZ] = {'\0'};
    strncpy(ifname, argv[2], IFNAMSIZ-1);

    error = net_bridge__add_port(brname, ifname);
    if (error == EINVAL)
        error = -EINVAL;

    if (error)
        goto out;

    // load program
    struct xdp_ep xdp_ep;
    memset(&xdp_ep, 0, sizeof(struct xdp_ep));

    struct xs_cfg cfg = {
        .path = ".",
        // .ifname = devname,
        // .brname = dp->name,
        .filenames = NULL,
        .mode = XDP_MODE_UNSPEC,
        .xsk_if_queue = 0
    };
    cfg.ifname = (char *)&cfg.ifname_buf;
    strncpy(cfg.ifname, ifname, IF_NAMESIZE);
    cfg.brname = (char *)&cfg.brname_buf;
    strncpy(cfg.brname, brname, IF_NAMESIZE);

    error = xdp_prog_default_load(&xdp_ep, &cfg);
    if (error) {
        printf("Failed to load xdp program");
        if (error == EINVAL)
            error = -EINVAL;
    }

out:
    if (error == EINVAL)
        print_cmd_usage(description, use, NULL, port_options);
    return error;
}

int remove_port_cmd(int argc, char **argv,  void *params)
{
    char *description = "Removes a port to a data path";
    char *use = "xdp-ctl port remoce <datapath name> <port name> [flags]";
    int error = 0;

    struct port_arguments *args = NULL;
    error = parse_port_options(argc, argv, args);
    if (error)
        goto out;

    if (argc != 3) {
        error = EINVAL;
        goto out;
    }

    char brname[IFNAMSIZ] = {'\0'};
    strncpy(brname, argv[1], IFNAMSIZ-1);

    char ifname[IFNAMSIZ] = {'\0'};
    strncpy(ifname, argv[2], IFNAMSIZ-1);

    error = net_bridge__remove_port(brname, ifname);
    if (error == EINVAL)
        error = -EINVAL;

    if (error)
        goto out;

    // unload program and clean up

out:
    if (error == EINVAL)
        print_cmd_usage(description, use, NULL, port_options);
    return error;
}

int edit_port_cmd(int argc, char **argv,  void *params)
{
    printf("Work in progress\n");
    return 0;
}
#pragma GCC diagnostic pop