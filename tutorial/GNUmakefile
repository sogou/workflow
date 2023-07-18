ROOT_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
ALL_TARGETS := all clean
MAKE_FILE := Makefile

DEFAULT_BUILD_DIR := build.cmake
BUILD_DIR := $(shell if [ -f $(MAKE_FILE) ]; then echo "."; else echo $(DEFAULT_BUILD_DIR); fi)
CMAKE3 := $(shell if which cmake3>/dev/null ; then echo cmake3; else echo cmake; fi;)

.PHONY: $(ALL_TARGETS)

all:
	mkdir -p $(BUILD_DIR)
	rm -rf $(DEFAULT_BUILD_DIR)/CMakeCache.txt

ifeq ($(DEBUG),y)
	cd $(BUILD_DIR) && $(CMAKE3) -D CMAKE_BUILD_TYPE=Debug -D CONSUL=$(CONSUL) -D KAFKA=$(KAFKA) -D MYSQL=$(MYSQL) -D REDIS=$(REDIS) $(ROOT_DIR)
else
	cd $(BUILD_DIR) && $(CMAKE3) -D CONSUL=$(CONSUL) -D KAFKA=$(KAFKA) -D MYSQL=$(MYSQL) -D REDIS=$(REDIS) $(ROOT_DIR)
endif
	make -C $(BUILD_DIR) -f Makefile

clean:
ifeq ($(MAKE_FILE), $(wildcard $(MAKE_FILE)))
	-make -f Makefile clean
else ifeq ($(DEFAULT_BUILD_DIR), $(wildcard $(DEFAULT_BUILD_DIR)))
	-make -C $(DEFAULT_BUILD_DIR) clean
endif
	rm -rf $(DEFAULT_BUILD_DIR)
