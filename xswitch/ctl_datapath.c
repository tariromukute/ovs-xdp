#include <stdio.h>
#include <string.h>
#include "ctl_datapath.h"
#include "xf_netdev.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

struct dp_arguments {
    int version;
};

struct option_wrapper dp_options[] = {
    {{"help", no_argument, 0, 'h'}, "Show help", ""},
    {{"version", required_argument, 0, 'v'}, "The version to be used", ""},
    {{0, 0, 0, 0}, "", ""}};

static int parse_dp_options(int argc, char **argv, struct dp_arguments *args)
{
    int error = 0;
    struct option *long_options;

    if (option_wrappers_to_optionsx(dp_options, &long_options))
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

int dp_cmd(int argc, char **argv,  void *params)
{
    char *description = "Manage datapath";
    char *use = "xdp-ctl dp [command]";
    int error = 1;

    const struct command *cmd;
    for (cmd = dp_cmds; cmd->name != NULL; cmd++)
    {
        if (!strcmp(cmd->name, argv[1]))
        {
            error = cmd->cmd(argc - 1, &argv[1], params);
            break;
        }
    }

    if (error) {
        if (error == 1)
            print_cmd_usage(description, use, dp_cmds, NULL);
    }
    return error;
}

int list_dp_cmd(int argc, char **argv,  void *params)
{
    printf("Work in progress\n");
    return 0;
}

int add_dp_cmd(int argc, char **argv,  void *params)
{
    char *description = "Adds a flow to the specified datapath";
    char *use = "xdp-ctl dp add <datapath name> [flags]";
    int error = 0;

    struct dp_arguments *args = NULL;
    error = parse_dp_options(argc, argv, args);
    if (error)
        goto out;

    char brname[IFNAMSIZ] = {'\0'};
    strncpy(brname, argv[1], IFNAMSIZ-1);

    error = bridge__create(brname);
    if (error == EINVAL)
        error = -EINVAL;

out:
    if (error == EINVAL)
        print_cmd_usage(description, use, NULL, dp_options);
    return error;
}

int del_dp_cmd(int argc, char **argv,  void *params)
{
    char *description = "Delete a datapath";
    char *use = "xdp-ctl dp del <datapath name> [flags]";
    int error = 0;

    struct dp_arguments *args = NULL;
    error = parse_dp_options(argc, argv, args);
    if (error)
        goto out;

    char brname[IFNAMSIZ] = {'\0'};
    strncpy(brname, argv[1], IFNAMSIZ-1);

    error = bridge__delete(brname);
    if (error == EINVAL)
        error = -EINVAL;

out:
    if (error == EINVAL)
        print_cmd_usage(description, use, NULL, dp_options);
    return error;
}

int edit_dp_cmd(int argc, char **argv,  void *params)
{
    printf("Work in progress\n");
    return 0;
}
#pragma GCC diagnostic pop