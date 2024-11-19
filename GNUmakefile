ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
ALL_TARGETS := all base check install preinstall clean tutorial example
MAKE_FILE := Makefile

DEFAULT_BUILD_DIR := build.cmake
BUILD_DIR := $(shell if [ -f $(MAKE_FILE) ]; then echo "."; else echo $(DEFAULT_BUILD_DIR); fi)
CMAKE3 := $(shell if which cmake3>/dev/null ; then echo cmake3; else echo cmake; fi;)
ifeq ($(MINGW),y)
CMAKE3 += -G "MinGW Makefiles"
endif

.PHONY: $(ALL_TARGETS)

all: base
	make -C $(BUILD_DIR) -f Makefile

base:
	mkdir -p $(BUILD_DIR)

ifeq ($(DEBUG),y)
	cd $(BUILD_DIR) && $(CMAKE3) -D CMAKE_BUILD_TYPE=Debug -D KAFKA=$(KAFKA) -D MYSQL=$(MYSQL) -D REDIS=$(REDIS) -D UPSTREAM=$(UPSTREAM) $(ROOT_DIR)
else ifneq ("${INSTALL_PREFIX}install_prefix", "install_prefix")
	cd $(BUILD_DIR) && $(CMAKE3) -DCMAKE_INSTALL_PREFIX:STRING=${INSTALL_PREFIX} -D KAFKA=$(KAFKA) -D MYSQL=$(MYSQL) -D REDIS=$(REDIS) -D UPSTREAM=$(UPSTREAM) $(ROOT_DIR)
else
	cd $(BUILD_DIR) && $(CMAKE3) -D KAFKA=$(KAFKA) -D MYSQL=$(MYSQL) -D REDIS=$(REDIS) -D UPSTREAM=$(UPSTREAM) $(ROOT_DIR)
endif

tutorial: all
	make -C tutorial

example: all
	make -C example

check: all
	make -C test check

install preinstall: base
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && $(CMAKE3) $(ROOT_DIR)
	make -C $(BUILD_DIR) -f Makefile $@

clean:
	-make -C test clean
	-make -C tutorial clean
	rm -rf $(DEFAULT_BUILD_DIR)
	rm -rf _include
	rm -rf _lib
	find . -name CMakeCache.txt | xargs rm -f
	find . -name Makefile       | xargs rm -f
	find . -name "*.cmake"      | xargs rm -f
	find . -name CMakeFiles     | xargs rm -rf
