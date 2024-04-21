# SPDX-License-Identifier: GPL-2.0-only

obj-$(CONFIG_SECURITY_ESF) += \
	esf.o \
	blobs.o \
	agent.o \
	hooks.o \
	event.o \
	events_queue.o \
	events_channel.o \
	hooks/process.o \
	hooks/file.o \
	hooks/fs.o \
	hooks/fillers.o

ccflags-y := -I$(srctree)/security/esf
ccflags-$(CONFIG_SECURITY_ESF_DEBUG) += -g -ggdb -O1 -fno-inline