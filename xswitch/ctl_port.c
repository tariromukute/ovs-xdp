#include <stdio.h>
#include <string.h>
#include "ctl_port.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
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
    printf("Work in progress\n");
    return 0;
}

int edit_port_cmd(int argc, char **argv,  void *params)
{
    printf("Work in progress\n");
    return 0;
}
#pragma GCC diagnostic pop