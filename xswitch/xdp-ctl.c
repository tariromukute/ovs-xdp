
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <string.h>
#include <errno.h>
#include "ctl_flow.h"
#include "ctl_datapath.h"
#include "ctl_logs.h"
#include "ctl_port.h"
#include "command.h"

static struct global_flags flags = {
    .verbose = 0};

struct command main_cmds[] = {
    {"dp", "dp [command]", dp_cmd},
    {"flow", "flow [command]", flow_cmd},
    {"port", "port [command]", port_cmd},
    {"logs", "logs [command]", logs_cmd},
    {0, 0, 0}
};

int main(int argc, char **argv)
{
    char *description = "Manage xdp datapath and flows";
    char *use = "xdp-ctl [command]";
    int error = EAGAIN;
    int c;
    struct option_wrapper wrappers[] = {
    {{"help", no_argument, 0, 'h'}, "Show help", ""},
    {{"verbose", no_argument, 0, 'v'}, "Show all information messages", ""},
    {{0, 0, 0, 0}, "", ""}};
    struct option *long_options;

    if (option_wrappers_to_optionsx(wrappers, &long_options))
    {
        error = -1;
        printf("Unable to convert wrappers to options\n");
        goto out;
    }

    for (;;)
    {
        int option_index = 0;

        c = getopt_long(argc, argv, "+",
                        long_options, &option_index);
        if (c == -1)
        {
            break;
        }

        switch (c)
        {
        case 'v':
            flags.verbose = 1;
            break;
        case 'h':
            error = EAGAIN;
            goto out;
        case '?':
            error = EINVAL;
            goto out;

        default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }

    if (argc <= 1)
        goto out;
        
    struct command *cmd;
    for (cmd = main_cmds; cmd->name != NULL; cmd++)
    {
        if (!strcmp(cmd->name, argv[optind]))
        {   
            error = cmd->cmd(argc - optind, &argv[optind], &flags);
            break;
        }
    }
   
out:
    if (error)
    {
        if (error == EAGAIN) {
            print_cmd_usage(description, use, main_cmds, NULL);
        }
        if (error == EAGAIN || error == EINVAL) {
            printf("Global flags: \n\n");
            print_flags(wrappers);
        }
        exit(EXIT_FAILURE);
    }
    exit(EXIT_SUCCESS);
}