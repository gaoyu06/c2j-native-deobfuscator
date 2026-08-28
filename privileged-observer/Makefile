CC ?= cc
CPPFLAGS ?= -Iinclude
CFLAGS ?= -O2 -std=c11 -Wall -Wextra -Werror

PLUGIN := build/linux_maps.so

.PHONY: all clean test

all: $(PLUGIN)

$(PLUGIN): plugins/linux_maps.c include/privileged_observer_plugin.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared plugins/linux_maps.c -o $@

test:
	python3 -m unittest discover -s . -p 'test_*.py' -v

clean:
	rm -rf build
