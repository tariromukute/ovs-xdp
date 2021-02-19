#ifndef XDP_CMD_UPCALL_H
#define XDP_CMD_UPCALL_H 1
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <getopt.h>
#include "command.h"

int upcall_cmd(int argc, char **argv, void *params);

int list_upcall_cmd(int argc, char **argv, void *params);

static const struct command upcall_cmds[] = {
    {"list", "list [flags]", list_upcall_cmd},
    {0, 0, 0}};

// int cmd(int argc, char **argv, struct globalFlags *flags, char *usage[]);
#endif /* XDP_CMD_LOGS_H */