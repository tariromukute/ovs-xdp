$(info "================ RUNNING =======================")

# xdp_sources = \
# 	xdp/actions.c \
# 	xdp/entry-point.c \
# 	xdp/datapath.c \
# 	xdp/flow.c \
# 	xdp/xlate.c \
# 	xdp/flow_table.c \
# 	xdp/loader.c

# xdp_headers = \
# 	xdp/datapath.h \
# 	xdp/flow.h \
# 	xdp/xlate.h \
# 	xdp/flow_table.h \
# 	xdp/nsh.h \
# 	xdp/loader.h

# # Regardless of configuration with GCC, we must compile the BPF with clang
# # since GCC doesn't have a BPF backend.  Clang dones't support these flags,
# # so we filter them out.

# xdp_FILTER_FLAGS := $(filter-out -Wbool-compare, $(AM_XCFLAGS))
# xdp_FILTER_FLAGS2 := $(filter-out -Wduplicated-cond, $(xdp_FILTER_FLAGS))
# xdp_FILTER_FLAGS3 := $(filter-out --coverage, $(xdp_FILTER_FLAGS2))
# xdp_XCFLAGS := $(xdp_FILTER_FLAGS3)
# xdp_XCFLAGS += -D__NR_CPUS__=$(shell nproc) -O2 -Wall -Werror -emit-llvm
# xdp_XCFLAGS += -I$(top_builddir)/include -I$(top_srcdir)/include
# # xdp_XCFLAGS += -Wno-error=pointer-arith  # Allow skb->data arithmetic
# xdp_XCFLAGS += -I${IPROUTE2_SRC_PATH}/include/uapi/
# # FIXME:
# #bpf_XCFLAGS += -D__KERNEL__

# dist_sources = $(xdp_sources)
# dist_headers = $(xdp_headers)
# build_sources = $(dist_sources)
# build_headers = $(dist_headers)
# build_objects = $(patsubst %.c,%.o,$(build_sources))

# LLC ?=  llc-3.8
# CLANG ?= clang-3.8

# xdp: $(build_objects)
# xdp/datapath.o: $(xdp_sources) $(xdp_headers)
# 	$(MKDIR_P) $(dir $@)
# 	@which $(CLANG) >/dev/null 2>&1 || \
# 		(echo "Unable to find clang, Install clang (>=3.7) package"; exit 1)
# 	$(AM_V_CC) $(CLANG) $(xdp_XCFLAGS) -c $< -o - | \
# 	$(LLC) -march=bpf -filetype=obj -o $@

# xdp/datapath_dbg.o: $(xdp_sources) $(xdp_headers)
# 	@which clang-4.0 > /dev/null 2>&1 || \
# 		(echo "Unable to find clang-4.0 for debugging"; exit 1)
# 	clang-4.0 $(xdp_XCFLAGS) -g -c $< -o -| llc-4.0 -march=bpf -filetype=obj -o $@_dbg
# 	llvm-objdump-4.0 -S -no-show-raw-insn $@_dbg > $@_dbg.objdump

# EXTRA_DIST += $(dist_sources) $(dist_headers) $(xdp_extra)
# if HAVE_XDP
# dist_xdp_DATA += $(build_objects)
# endif

# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS and USER_TARGETS
# as a space-separated list
#

# XDP_TARGETS = \
# 	lib/xdp/actions \
# 	lib/xdp/entry-point

# USER_TARGETS = \
# 	lib/xdp/datapath \
# 	lib/xdp/flow \
# 	lib/xdp/flow-table \
# 	lib/xdp/loader

# xdp_headers = \
# 	lib/xdp/datapath.h \
# 	lib/xdp/flow.h \
# 	lib/xdp/flow-table.h \
# 	lib/xdp/tail_actions.h \
# 	lib/xdp/loader.h

# helpers_headers = \
# 	lib/xdp/headers/bpf_endian.h \
# 	lib/xdp/headers/bpf_helpers.h \
# 	lib/xdp/headers/bpf_util.h \
# 	lib/xdp/headers/common_helpers.h \
# 	lib/xdp/headers/jhash.h \
# 	lib/xdp/headers/nsh.h \
# 	lib/xdp/headers/parsing_helpers.h \
# 	lib/xdp/headers/perf-sys.h \
# 	lib/xdp/headers/rewrite_helpers.h \
# 	lib/xdp/headers/linux/bpf.h \
# 	lib/xdp/headers/linux/err.h \
# 	lib/xdp/headers/linux/if_link.h

# LLC ?= llc
# CLANG ?= clang
# CC ?= gcc

# EXTRA_DEPS =
# XDP_C = ${XDP_TARGETS:=.c}
# XDP_OBJ = ${XDP_C:.c=.o}
# USER_C := ${USER_TARGETS:=.c}
# USER_OBJ := ${USER_C:.c=.o}

# # Expect this is defined by including Makefile, but define if not

# OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a

# EXTRA_DEPS +=

# XCFLAGS =
# # XCFLAGS ?= -I$(LIBBPF_DIR)/root/usr/include/ -g
# # Extra include for Ubuntu issue #44
# # XCFLAGS += -I/usr/include/x86_64-linux-gnu
# XCFLAGS += -Ilib/xdp/headers/
# LDFLAGS ?= -L$(LIBBPF_DIR)

# XLIBS = -lbpf -lelf $(USER_LIBS)

# all: llvm-check $(USER_OBJ) $(XDP_OBJ) $(COPY_LOADER) $(COPY_STATS)

# .PHONY: clean $(CLANG) $(LLC)

# # $(MAKE) -C $(LIBBPF_DIR) clean
# clean:
# 	rm -f $(XDP_OBJ) $(USER_OBJ)
# 	rm -f *.ll
# 	rm -f *~


# llvm-check: $(CLANG) $(LLC)
# 	@for TOOL in $^ ; do \
# 		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
# 			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
# 			exit 1; \
# 		else true; fi; \
# 	done

# $(OBJECT_LIBBPF):
# 	@if [ ! -d $(LIBBPF_DIR) ]; then \
# 		echo "Error: Need libbpf submodule"; \
# 		echo "May need to run git submodule update --init"; \
# 		exit 1; \
# 	else \
# 		cd $(LIBBPF_DIR) && $(MAKE) all; \
# 		mkdir -p root; DESTDIR=root $(MAKE) install_headers; \
# 	fi

# Makefile $(EXTRA_DEPS)

# $(USER_OBJ): %.o: %.c %.h 
# 	$(CC) $(XCFLAGS) -c -o $@ $<

# $(XDP_OBJ): %.o: %.c  Makefile $(EXTRA_DEPS)
# 	$(CLANG) -S \
# 	    -target bpf \
# 	    -D __BPF_TRACING__ \
# 	    $(XCFLAGS) \
# 	    -Wall \
# 	    -Wno-unused-value \
# 	    -Wno-pointer-sign \
# 	    -Wno-compare-distinct-pointer-types \
# 	    -Werror \
# 	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
# 	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

# libxdp.${SHARED_LIBRARY_EXTENSION}: ${USER_OBJ}
# 	$(CC) ${SHARED_LIBRARY_FLAG} -o $@ $^

# EXTRA_DIST += $(USER_C) $(XDP_C) $(xdp_headers) $(helpers_headers)

# if HAVE_XDP
# dist_xdp_DATA += $(USER_OBJ)
# endif

# CFLAGS += -Ixdp/

# CFLAGS += -Ixdp/headers/

# lib_LTLIBRARIES += xdp/libxdp.la

# libxdp_la_LIBADD = $(LIBBPF_LDADD)

# libxdp_la_SOURCES = \
# 	xdp/datapath.c \
# 	xdp/datapath.h \
# 	xdp/flow.c \
# 	xdp/flow.h \
# 	xdp/xlate.c \
# 	xdp/xlate.h \
# 	xdp/flow-table.c \
# 	xdp/flow-table.h \
# 	xdp/loader.c \
# 	xdp/loader.h

# include_HEADERS = \
# 	xdp/loader.h

# noinst_LTLIBRARIES = xdp/libxdp.la

# libxdp_la_SOURCES = \
# 	xdp/datapath.c \
# 	xdp/datapath.h \
# 	xdp/flow.c \
# 	xdp/flow.h \
# 	xdp/xlate.c \
# 	xdp/xlate.h \
# 	xdp/flow-table.c \
# 	xdp/flow-table.h \
# 	xdp/loader.c \
# 	xdp/loader.h
bin_PROGRAMS += xdp/xdp_logger
xdp_xdp_logger_SOURCES = xdp/xdp_logger.c

bin_PROGRAMS += xdp/xdp-ctl

xdp_xdp_ctl_SOURCES = \
	xdp/command.h \
	xdp/xdp-ctl.c \
	xdp/ctl_datapath.c \
	xdp/ctl_datapath.h \
	xdp/ctl_flow.c \
	xdp/ctl_flow.h \
	xdp/ctl_logs.c \
	xdp/ctl_logs.h \
	xdp/ctl_port.c \
	xdp/ctl_port.h

xdp_xdp_ctl_LDADD = xdp/libxdpuser.la

lib_LTLIBRARIES += xdp/libxdp.la
xdp_libxdp_la_SOURCES =

xdp_libxdp_la_LIBADD = \
    xdp/libxdpuser.la \
	xdp/tail_prog.o \
    xdp/entry-point.o

lib_LTLIBRARIES += xdp/libxdpuser.la

xdp_libxdpuser_la_SOURCES = \
	xdp/dynamic-string.h \
	xdp/dynamic-string.c \
	xdp/xdp_user_helpers.h \
	xdp/xf.h \
    xdp/datapath.c \
	xdp/datapath.h \
    xdp/flow-table.c \
	xdp/flow-table.h \
    xdp/flow.c \
	xdp/flow.h \
    xdp/loader.c \
	xdp/loader.h

xdp_libxdpuser_la_LIBADD = $(LIBBPF_LDADD)

xdp_libxdpuser_la_LDFLAGS = \
        $(OVS_LTINFO) \
        $(AM_LDFLAGS)
	
XDP_TARGETS = \
	xdp/tail_prog \
	xdp/entry-point

LLC ?= llc
CLANG ?= clang

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}

all: $(XDP_OBJ)

llvm-check: $(CC) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(XDP_OBJ): %.o: %.c  Makefile $(EXTRA_DEPS)
	$(CC) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(XCFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

EXTRA_DIST += \
	xdp/README \
	xdp/nsh.h \
	xdp/parsing_xdp_key_helpers.h \
	xdp/parsing_helpers.h \
	xdp/rewrite_helpers.h \
	xdp/xf_kern.h \
	xdp/xdp_kern_helpers.h \
	$(XDP_C)

dist_xdp_DATA += \
	xdp/tail_prog.o \
	xdp/entry-point.o

CLEANFILES += \
	xdp/tail_prog.ll \
	xdp/entry-point.ll