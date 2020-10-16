/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include "libxdp.h"
#include "dynamic-string.h"
#include "logging.h"

static enum logging_print_level log_level = LOG_INFO;
static int log_fd = -1;


static int print_func(enum logging_print_level level, const char *format,
              va_list args)
{
    if (level > log_level)
        return 0;

    return vfprintf(stderr, format, args);
}

static int print_to_file(enum logging_print_level level, const char *format,
              va_list args)
{
    if (level > log_level)
        return 0;

    if (log_fd < 0)
        init_logging();

    struct ds ds = DS_EMPTY_INITIALIZER;
    ds_put_format_valist(&ds, format, args);
    ds_put_char(&ds, '\n');
    return write(log_fd, ds.string, ds.length);
}

static int libbpf_print_func(enum libbpf_print_level level, const char *format,
                 va_list args)
{
    return print_func(level + 1, format, args);
}

static int libbpf_silent_func(enum libbpf_print_level level, const char *format,
                  va_list args)
{
    return 0;
}

static int libxdp_print_func(enum libxdp_print_level level, const char *format,
                 va_list args)
{
    return print_func(level + 1, format, args);
}

#define __printf(a, b) __attribute__((format(printf, a, b)))

__printf(2, 3) void logging_print(enum logging_print_level level,
                  const char *format, ...)
{
    va_list args;

    va_start(args, format);
    // print_func(level, format, args);
    print_to_file(level, format, args);
    va_end(args);
}

void init_logging()
{
    char *file = "/var/log/xswitch/xswitchd.log";
    log_fd = open(file, O_WRONLY | O_CREAT | O_APPEND, 0660);
}

void init_lib_logging()
{
    libbpf_set_print(libbpf_print_func);
    // libxdp_set_print(libxdp_print_func);
}

void silence_libbpf_logging()
{
    if (log_level < LOG_VERBOSE)
        libbpf_set_print(libbpf_silent_func);
}

enum logging_print_level set_log_level(enum logging_print_level level)
{
    enum logging_print_level old_level = log_level;

    log_level = level;
    return old_level;
}

enum logging_print_level increase_log_level()
{
    if (log_level < LOG_VERBOSE)
        log_level++;
    return log_level;
}
