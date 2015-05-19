#  **********************************************************************
#
#   BSD LICENSE
#
#   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions
#   are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the
#       distribution.
#     * Neither the name of Intel Corporation nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#  **********************************************************************

ifeq ($(RTE_SDK),)
$(error "Please define RTE_SDK environment variable")
endif

# Default target, can be overriden by command line or environment
RTE_TARGET ?= x86_64-ivshmem-linuxapp-gcc

include $(RTE_SDK)/mk/rte.vars.mk

# Export DPDK variables for output directory and Makefile target. If these
# are ommited the wrong Makefile will be called by rte.exteapp.mk
RTE_EXTMK = $(RTE_SRCDIR)/Makefile.app

ifneq ($(CONFIG_RTE_EXEC_ENV),"linuxapp")
$(error This application can only operate in a linuxapp environment, \
please change the definition of the RTE_TARGET environment variable)
endif

# binary name
APP = ovs_dpdk

# all source are stored in SRCS-y
SRCS-y := main.c init.c args.c kni.c action.c vport.c datapath.c flow.c \
          stats.c ofpbuf_helper.c veth.c \
		  qos/core/rte_generic.c qos/core/sch_rtnetlink.c \
		  qos/core/sch_qdisc.c qos/list/rbtree.c \
		  qos/core/sch_stats.c \
		  qos/sched/sch_fifo.c \
		  qos/sched/sch_drr.c \
		  qos/sched/sch_htb.c
#		  logmod/rte_syslog.c logmod/log_mod.c #Added by Y.Born

INC := $(wildcard *.h)

#CFLAGS += -O3 -g
CFLAGS += -O0 -g
CFLAGS += -I$(SRCDIR)/../shared -I$(OVS_DIR)/include -I$(OVS_DIR)/lib -I$(OVS_DIR)
CFLAGS += -Wall -Werror -Wno-unused \
-Wclobbered \
-Wempty-body \
-Wignored-qualifiers \
-Wmissing-parameter-type \
-Wold-style-declaration \
-Woverride-init \
-Wsign-compare \
-Wtype-limits \
-Wuninitialized \
-Wunused-parameter \
-Wunused-but-set-parameter
# All extra arguments above are part of -Wextra.
# See http://stackoverflow.com/q/1538943
# There's a known bug in gcc4.6 that makes -Wmissing-field-initializers flag
# fail with a valid struct initialization. Left it out for now.

# fix dpdk link order, add to LDLIBS which is processed by dpdk's
# macros.
LDLIBS += -L$(OVS_DIR)/lib  -lopenvswitch -lrt

# for newer gcc, e.g. 4.4, no-strict-aliasing may not be necessary
# and so the next line can be removed in those cases.
#EXTRA_CFLAGS += -fno-strict-aliasing

include $(RTE_SDK)/mk/rte.extapp.mk

EMPTY_AUTOMAKE_TARGETS = dvi pdf ps info html tags ctags
.PHONY: $(EMPTY_AUTOMAKE_TARGETS)
$(EMPTY_AUTOMAKE_TARGETS):

clean:
	rm -rf $(OVS_DIR)/datapath/dpdk/build

distclean: clean
