#SPDX-License-Identifier: BSD-3-Clause

userprogs-always-y := sandboxer

userccflags += -I usr/include

.PHONY: all clean

all:
	$(MAKE) -C ../.. samples/esf/

clean:
	$(MAKE) -C ../.. M=samples/esf/ clean

standalone: standalone-agent

standalone-agent: $(info $(shell realpath $$(pwd)) $(EXTRA_FLAGS))
	gcc $(EXTRA_FLAGS) -g -ggdb -std=c11 ./events_queue.c ./agent.c -o agent