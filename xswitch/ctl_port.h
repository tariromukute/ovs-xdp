#ifndef XDP_CMD_PORT_H
#define XDP_CMD_PORT_H 1
#include <stdio.h>  /* for printf */
#include <stdlib.h> /* for exit */
#include <getopt.h>
#include "command.h"

int port_cmd(int argc, char **argv, void *params);

int list_port_cmd(int argc, char **argv, void *params);
int add_port_cmd(int argc, char **argv, void *params);
int remove_port_cmd(int argc, char **argv, void *params);
int edit_port_cmd(int argc, char **argv, void *params);

static const struct command port_cmds[] = {
    {"list", "list <datapath name> [flags]", list_port_cmd},
    {"add", "add <datapath name> <port_name> [flags]", add_port_cmd},
    {"remove", "remove <datapath name> <port_name> [flags]", remove_port_cmd},
    {"edit", "edit <flow> [flags]", edit_port_cmd},
    {0, 0, 0}};
// int cmd(int argc, char **argv, struct globalFlags *flags, char *usage[]);
#endif /* XDP_CMD_PORT_H */