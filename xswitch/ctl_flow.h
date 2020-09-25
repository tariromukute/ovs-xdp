#ifndef XDP_CMD_FLOW_H
#define XDP_CMD_FLOW_H 1
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <getopt.h>
#include "command.h"

int flow_cmd(int argc, char **argv, void *params);

int list_flow_cmd(int argc, char **argv, void *params);
int add_flow_cmd(int argc, char **argv, void *params);
int edit_flow_cmd(int argc, char **argv, void *params);

static const struct command flow_cmds[] = {
    {"list", "list [flags]", list_flow_cmd},
    {"add", "add <flow> [flags]", add_flow_cmd},
    {"edit", "edit <flow> [flags]", edit_flow_cmd},
    {0, 0, 0}};
// int cmd(int argc, char **argv, struct globalFlags *flags, char *usage[]);
#endif /* XDP_CMD_FLOW_H */