cmake_minimum_required(VERSION 3.10)

set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "build type")

project(workflow_test
		LANGUAGES C CXX
)

find_library(LIBRT rt)
find_package(OpenSSL REQUIRED)
find_package(workflow REQUIRED CONFIG HINTS ..)
include_directories(${OPENSSL_INCLUDE_DIR} ${WORKFLOW_INCLUDE_DIR})
link_directories(${WORKFLOW_LIB_DIR})
find_library(WORKFLOW_LIB NAMES libworkflow.a workflow HINTS ${WORKFLOW_LIB_DIR})

find_program(CMAKE_MEMORYCHECK_COMMAND valgrind)
set(memcheck_command ${CMAKE_MEMORYCHECK_COMMAND} ${CMAKE_MEMORYCHECK_COMMAND_OPTIONS} --error-exitcode=1 --leak-check=full)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

enable_testing()

set(CXX_STD "c++14")

find_package(GTest REQUIRED)

set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wall -fPIC -pipe -std=gnu90")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -pipe -std=${CXX_STD} -fno-exceptions")
if (APPLE)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
endif()

set(TEST_LIST
	task_unittest
	algo_unittest
	http_unittest
	redis_unittest
	mysql_unittest
	facilities_unittest
	graph_unittest
	memory_unittest
	upstream_unittest
	dns_unittest
	resource_unittest
	uriparser_unittest
)

if (APPLE)
	set(LIB ${WORKFLOW_LIB} pthread OpenSSL::SSL OpenSSL::Crypto)
else ()
	set(LIB ${WORKFLOW_LIB} pthread OpenSSL::SSL OpenSSL::Crypto ${LIBRT})
endif ()

foreach(src ${TEST_LIST})
	add_executable(${src} EXCLUDE_FROM_ALL ${src}.cc)
	target_link_libraries(${src} ${LIB} GTest::GTest GTest::Main)
	add_test(${src} ${src})
	add_dependencies(check ${src})
endforeach()

if (NOT ${CMAKE_MEMORYCHECK_COMMAND} STREQUAL "CMAKE_MEMORYCHECK_COMMAND-NOTFOUND")
	foreach(src ${TEST_LIST})
		add_test(${src}-memory-check ${memcheck_command} ./${src})
	endforeach()
endif ()
# --- Cache Unit Test ---
add_executable(cache_unittest cache_unittest.cc)

# 链接 Workflow 库
if (TARGET workflow-static)
    target_link_libraries(cache_unittest workflow-static)
else()
    target_link_libraries(cache_unittest workflow)
endif()

# 链接 GTest (尝试标准名称)
find_package(GTest REQUIRED)
target_link_libraries(cache_unittest GTest::GTest GTest::Main pthread ssl crypto)

# 头文件路径
target_include_directories(cache_unittest PRIVATE
    ${CMAKE_SOURCE_DIR}/src/include
    ${CMAKE_SOURCE_DIR}/src/util
    ${CMAKE_SOURCE_DIR}/src/kernel
)