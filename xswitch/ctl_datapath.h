#ifndef XDP_CMD_DP_H
#define XDP_CMD_DP_H 1
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <getopt.h>
#include "command.h"

int dp_cmd(int argc, char **argv, void *params);

int list_dp_cmd(int argc, char **argv, void *params);
int add_dp_cmd(int argc, char **argv, void *params);
int del_dp_cmd(int argc, char **argv, void *params);
int edit_dp_cmd(int argc, char **argv, void *params);

static const struct command dp_cmds[] = {
    {"list", "list [flags]", list_dp_cmd},
    {"add", "add <datapath name> [flags]", add_dp_cmd},
    {"del", "del <datapath name> [flags]", del_dp_cmd},
    {"edit", "edit <datapath name> [flags]", edit_dp_cmd},
    {0, 0, 0}}; /* NOTE: important to have the 0 as the closing value. */
// int cmd(int argc, char **argv, struct globalFlags *flags, char *usage[]);
#endif /* XDP_CMD_DP_H */