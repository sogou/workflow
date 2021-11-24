#指定嵌入式系统的编译输出目录
set(SYSROOT_PATH "/home/shawntao/Backup/arm-use")

#指定交叉编译器路径
set(TOOLSCHAIN_PATH "/opt/toolchain/aarch64-linux-gnu/")
set(TOOLCHAIN_HOST "${TOOLSCHAIN_PATH}bin/aarch64-linux-gnu")

#message("${CMAKE_CURRENT_LIST_FILE}:${CMAKE_CURRENT_LIST_LINE}")
message(STATUS "Using sysroot path: ${SYSROOT_PATH}")

set(TOOLCHAIN_CC "${TOOLCHAIN_HOST}-gcc")
set(TOOLCHAIN_CXX "${TOOLCHAIN_HOST}-g++")

#告诉cmake是进行交叉编译
set(CMAKE_CROSSCOMPILING TRUE)

# Define name of the target system
set(CMAKE_SYSTEM_NAME "Linux")
# Define the compiler
set(CMAKE_C_COMPILER ${TOOLCHAIN_CC})
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_CXX})

#库和同头文件查找的路径。
set(CMAKE_FIND_ROOT_PATH "${SYSROOT_PATH}" "${CMAKE_PREFIX_PATH}" "${TOOLSCHAIN_PATH}")

# search for programs in the build host directories
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
# for libraries and headers in the target directories
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
