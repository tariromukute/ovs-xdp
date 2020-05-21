#include <stdio.h>
#include <string.h>
#include "ctl_datapath.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
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
    printf("Work in progress\n");
    return 0;
}

int edit_dp_cmd(int argc, char **argv,  void *params)
{
    printf("Work in progress\n");
    return 0;
}
#pragma GCC diagnostic pop