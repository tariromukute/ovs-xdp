$(info "================ RUNNING =======================")

# xdp_sources = \
#	 xswitch/actions.c \
#	 xswitch/entry-point.c \
#	 xswitch/datapath.c \
#	 xswitch/flow.c \
#	 xswitch/xlate.c \
#	 xswitch/flow_table.c \
#	 xswitch/loader.c

# xdp_headers = \
#	 xswitch/datapath.h \
#	 xswitch/flow.h \
#	 xswitch/xlate.h \
#	 xswitch/flow_table.h \
#	 xswitch/nsh.h \
#	 xswitch/loader.h

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
# xswitch/datapath.o: $(xdp_sources) $(xdp_headers)
#	 $(MKDIR_P) $(dir $@)
#	 @which $(CLANG) >/dev/null 2>&1 || \
#		 (echo "Unable to find clang, Install clang (>=3.7) package"; exit 1)
#	 $(AM_V_CC) $(CLANG) $(xdp_XCFLAGS) -c $< -o - | \
#	 $(LLC) -march=bpf -filetype=obj -o $@

# xswitch/datapath_dbg.o: $(xdp_sources) $(xdp_headers)
#	 @which clang-4.0 > /dev/null 2>&1 || \
#		 (echo "Unable to find clang-4.0 for debugging"; exit 1)
#	 clang-4.0 $(xdp_XCFLAGS) -g -c $< -o -| llc-4.0 -march=bpf -filetype=obj -o $@_dbg
#	 llvm-objdump-4.0 -S -no-show-raw-insn $@_dbg > $@_dbg.objdump

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
#	 lib/xswitch/actions \
#	 lib/xswitch/entry-point

# USER_TARGETS = \
#	 lib/xswitch/datapath \
#	 lib/xswitch/flow \
#	 lib/xswitch/flow-table \
#	 lib/xswitch/loader

# xdp_headers = \
#	 lib/xswitch/datapath.h \
#	 lib/xswitch/flow.h \
#	 lib/xswitch/flow-table.h \
#	 lib/xswitch/tail_actions.h \
#	 lib/xswitch/loader.h

# helpers_headers = \
#	 lib/xswitch/headers/bpf_endian.h \
#	 lib/xswitch/headers/bpf_helpers.h \
#	 lib/xswitch/headers/bpf_util.h \
#	 lib/xswitch/headers/common_helpers.h \
#	 lib/xswitch/headers/jhash.h \
#	 lib/xswitch/headers/nsh.h \
#	 lib/xswitch/headers/parsing_helpers.h \
#	 lib/xswitch/headers/perf-sys.h \
#	 lib/xswitch/headers/rewrite_helpers.h \
#	 lib/xswitch/headers/linux/bpf.h \
#	 lib/xswitch/headers/linux/err.h \
#	 lib/xswitch/headers/linux/if_link.h

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
# XCFLAGS += -Ilib/xswitch/headers/
# LDFLAGS ?= -L$(LIBBPF_DIR)

# XLIBS = -lbpf -lelf $(USER_LIBS)

# all: llvm-check $(USER_OBJ) $(XDP_OBJ) $(COPY_LOADER) $(COPY_STATS)

# .PHONY: clean $(CLANG) $(LLC)

# # $(MAKE) -C $(LIBBPF_DIR) clean
# clean:
#	 rm -f $(XDP_OBJ) $(USER_OBJ)
#	 rm -f *.ll
#	 rm -f *~


# llvm-check: $(CLANG) $(LLC)
#	 @for TOOL in $^ ; do \
#		 if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
#			 echo "*** ERROR: Cannot find tool $${TOOL}" ;\
#			 exit 1; \
#		 else true; fi; \
#	 done

# $(OBJECT_LIBBPF):
#	 @if [ ! -d $(LIBBPF_DIR) ]; then \
#		 echo "Error: Need libbpf submodule"; \
#		 echo "May need to run git submodule update --init"; \
#		 exit 1; \
#	 else \
#		 cd $(LIBBPF_DIR) && $(MAKE) all; \
#		 mkdir -p root; DESTDIR=root $(MAKE) install_headers; \
#	 fi

# Makefile $(EXTRA_DEPS)

# $(USER_OBJ): %.o: %.c %.h 
#	 $(CC) $(XCFLAGS) -c -o $@ $<

# $(XDP_OBJ): %.o: %.c  Makefile $(EXTRA_DEPS)
#	 $(CLANG) -S \
#		 -target bpf \
#		 -D __BPF_TRACING__ \
#		 $(XCFLAGS) \
#		 -Wall \
#		 -Wno-unused-value \
#		 -Wno-pointer-sign \
#		 -Wno-compare-distinct-pointer-types \
#		 -Werror \
#		 -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
#	 $(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}

# libxdp.${SHARED_LIBRARY_EXTENSION}: ${USER_OBJ}
#	 $(CC) ${SHARED_LIBRARY_FLAG} -o $@ $^

# EXTRA_DIST += $(USER_C) $(XDP_C) $(xdp_headers) $(helpers_headers)

# if HAVE_XDP
# dist_xdp_DATA += $(USER_OBJ)
# endif

# CFLAGS += -Ixswitch/

# CFLAGS += -Ixswitch/headers/

# lib_LTLIBRARIES += xswitch/libxdp.la

# libxdp_la_LIBADD = $(LIBBPF_LDADD)

# libxdp_la_SOURCES = \
#	 xswitch/datapath.c \
#	 xswitch/datapath.h \
#	 xswitch/flow.c \
#	 xswitch/flow.h \
#	 xswitch/xlate.c \
#	 xswitch/xlate.h \
#	 xswitch/flow-table.c \
#	 xswitch/flow-table.h \
#	 xswitch/loader.c \
#	 xswitch/loader.h

# include_HEADERS = \
#	 xswitch/loader.h

# noinst_LTLIBRARIES = xswitch/libxdp.la

# libxdp_la_SOURCES = \
#	 xswitch/datapath.c \
#	 xswitch/datapath.h \
#	 xswitch/flow.c \
#	 xswitch/flow.h \
#	 xswitch/xlate.c \
#	 xswitch/xlate.h \
#	 xswitch/flow-table.c \
#	 xswitch/flow-table.h \
#	 xswitch/loader.c \
#	 xswitch/loader.h
bin_PROGRAMS += xswitch/xdp_logger
xswitch_xdp_logger_SOURCES = xswitch/xdp_logger.c

bin_PROGRAMS += xswitch/xdp-ctl

bin_PROGRAMS += xswitch/xdp-loader

xswitch_xdp_loader_SOURCES = \
	xswitch/xdp-loader.c

xswitch_xdp_loader_LDADD = \
	xswitch/libxswitchuser.la

xswitch_xdp_ctl_SOURCES = \
	xswitch/command.h \
	xswitch/xdp-ctl.c \
	xswitch/ctl_datapath.c \
	xswitch/ctl_datapath.h \
	xswitch/ctl_flow.c \
	xswitch/ctl_flow.h \
	xswitch/ctl_logs.c \
	xswitch/ctl_logs.h \
	xswitch/ctl_port.c \
	xswitch/ctl_port.h \
	xswitch/ctl_upcall.c \
	xswitch/ctl_upcall.h

xswitch_xdp_ctl_LDADD = \
	xswitch/libxswitchuser.la

lib_LTLIBRARIES += \
	xswitch/libxswitch.la 

xswitch_libxswitch_la_SOURCES =

xswitch_libxswitch_la_LIBADD = \
	xswitch/libxswitchuser.la \
	xswitch/tail_prog.o \
	xswitch/ep_inline_actions.o \
	xswitch/ep_inline_actions_v2.o \
	xswitch/ep_tail_actions.o

lib_LTLIBRARIES += xswitch/libxswitchuser.la

xswitch_libxswitchuser_la_SOURCES = \
	xswitch/dynamic-string.h \
	xswitch/dynamic-string.c \
	xswitch/xdp_user_helpers.h \
	xswitch/xf.h \
	xswitch/datapath.c \
	xswitch/datapath.h \
	xswitch/flow-table.c \
	xswitch/flow-table.h \
	xswitch/xf_map.c \
	xswitch/xf_map.h \
	xswitch/xf_netdev.c \
	xswitch/xf_netdev.h \
	xswitch/flow.c \
	xswitch/flow.h \
	xswitch/loader.c \
	xswitch/loader.h \
	xswitch/libxdp.h \
	xswitch/libxdp.c \
	xswitch/prog_dispatcher.h \
	xswitch/params.h \
	xswitch/params.c \
	xswitch/logging.h \
	xswitch/logging.c \
	xswitch/util.h \
	xswitch/util.c \
	xswitch/xdp_helpers.h \
	xswitch/err.h \
	xswitch/net_utils.h \
	xswitch/net_utils.c

# Build xdp-dispatcher.c from xdp-dispatcher.c.in
# Adapted the make config from the xdp-tools git repo
BPF_DIR_MNT ?=/sys/fs/bpf
MAX_DISPATCHER_ACTIONS ?=10
TOOLS_VERSION := "1.0.1"
M4:=m4
DEFINES := -DBPF_DIR_MNT=\"$(BPF_DIR_MNT)\" \
	 -DMAX_DISPATCHER_ACTIONS=$(MAX_DISPATCHER_ACTIONS) \
	 -DTOOLS_VERSION=\"$(TOOLS_VERSION)\"

QUIET_M4	   = @echo '	M4	   '$@;

xswitch/xdp-dispatcher.c: %.c: %.c.in Makefile
	 $(QUIET_M4)$(M4) $(DEFINES) $< > $@ || ( ret=$$?; rm -f $@; exit $$ret )

xswitch_libxswitchuser_la_LIBADD = $(LIBBPF_LDADD)

xswitch_libxswitch_la_LIBADD += $(LIBBPF_LDADD)

xswitch_libxswitchuser_la_LDFLAGS = \
		$(OVS_LTINFO) \
		$(AM_LDFLAGS)
	
XDP_TARGETS = \
	xswitch/tail_prog \
	xswitch/ep_inline_actions \
	xswitch/ep_inline_actions_v2 \
	xswitch/xs_inline_actions \
	xswitch/ep_tail_actions \
	xswitch/ep_pass_action \
	xswitch/ep_router_actions \
	xswitch/xdp-dispatcher

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
	xswitch/README \
	xswitch/nsh.h \
	xswitch/parsing_xf_key_helpers.h \
	xswitch/parsing_xdp_key_helpers.h \
	xswitch/parsing_helpers.h \
	xswitch/rewrite_helpers.h \
	xswitch/xf_kern.h \
	xswitch/actions.h \
	xswitch/xdp_kern_helpers.h \
	xswitch/xdp-dispatcher.c.in \
	$(XDP_C)

dist_xswitch_DATA += \
	xswitch/tail_prog.o \
	xswitch/ep_inline_actions.o \
	xswitch/ep_inline_actions_v2.o \
	xswitch/xs_inline_actions.o \
	xswitch/ep_tail_actions.o \
	xswitch/ep_pass_action.o \
	xswitch/ep_router_actions.o \
	xswitch/xdp-dispatcher.o

CLEANFILES += \
	xswitch/tail_prog.ll \
	xswitch/ep_inline_actions.ll \
	xswitch/ep_inline_actions_v2.ll \
	xswitch/xs_inline_actions.ll \
	xswitch/ep_tail_actions.ll \
	xswitch/ep_pass_action.ll \
	xswitch/ep_router_actions.ll \
	xswitch/xdp-dispatcher.c \
	xswitch/xdp-loader \
	xswitch/xdp-ctl \
	xswitch/stamp-h2