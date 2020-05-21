#ifndef XDP_CMD_H
#define XDP_CMD_H 1

#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef NAME_MAX
#define NAME_MAX 1096
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct global_flags
{
	int verbose;
	int debug;
};

struct option_wrapper
{
	struct option option;
	char *help;
	char *metavar;
};

struct usage
{
	char *description;
	char *use;
	char *args;
	char *flags;
};

typedef int cmd(int argc, char **argv, void *params);

struct command
{
	const char *name;
	const char *usage;
	cmd *cmd;
};

#pragma GCC diagnostic ignored "-Wunused-function"
static int option_wrappers_to_optionsx(const struct option_wrapper *wrapper,
									   struct option **options)
{
	int i, num;
	struct option *new_options;
	for (i = 0; wrapper[i].option.name != 0; i++)
	{
	}
	num = i;

	new_options = malloc(sizeof(struct option) * num);
	if (!new_options)
		return -1;
	for (i = 0; i < num; i++)
	{
		memcpy(&new_options[i], &wrapper[i], sizeof(struct option));
	}

	*options = new_options;
	return 0;
}

static void print_flags(struct option_wrapper *wrapper)
{
	struct option_wrapper *w;
	for (w = wrapper; w->help != NULL; w++)
	{
		printf("--%s \t %s\n", w->option.name, w->help);
	}
}

static void print_command(const struct command *args)
{
	const struct command *arg;
	for (arg = args; arg->name != NULL; arg++)
	{
		printf("%s\n", arg->usage);
	}
}

static void print_cmd_usage(char *description, char *use, const struct command *command, struct option_wrapper *flags)
{
	if (description)
		printf("Decription: \n\n%s\n\n", description);

	if (use)
		printf("Usage: \n\n%s \n\n", use);

	if (command) {
		printf("Commands: \n\n");
		print_command(command);
		printf("\n");
	}

	if (flags) {
		printf("Flags: \n\n");
		print_flags(flags);
		printf("\n");
	}
}



#endif /* XDP_CMD_H */
