cmake_minimum_required(VERSION 3.6)

set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "build type")

project(workflow_test
		LANGUAGES C CXX
)

find_library(LIBRT rt)
find_package(OpenSSL REQUIRED)
find_package(workflow REQUIRED CONFIG HINTS ..)
include_directories(${OPENSSL_INCLUDE_DIR} ${WORKFLOW_INCLUDE_DIR})
link_directories(${WORKFLOW_LIB_DIR})

find_program(CMAKE_MEMORYCHECK_COMMAND valgrind)
set(memcheck_command ${CMAKE_MEMORYCHECK_COMMAND} ${CMAKE_MEMORYCHECK_COMMAND_OPTIONS} --error-exitcode=1 --leak-check=full)

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

enable_testing()

set(CXX_STD "c++11")

find_package(GTest REQUIRED)
if (GTest_VERSION VERSION_GREATER_EQUAL "1.13.0")
	set(CXX_STD "c++14")
else ()
	get_filename_component(GTEST_PATH ${GTEST_LIBRARY} DIRECTORY ABSOLUTE)
	execute_process(COMMAND grep Version "${GTEST_PATH}/pkgconfig/gtest.pc"
					RESULT_VARIABLE GTEST_VERSION_RESULT
					OUTPUT_VARIABLE GTEST_VERSION_OUTPUT)
	if (${GTEST_VERSION_RESULT} EQUAL "0")
		string(REPLACE " " ";" GTEST_VERSION_STR ${GTEST_VERSION_OUTPUT})
		list(GET GTEST_VERSION_STR 1 GTEST_VERSION)
		if (${GTEST_VERSION} VERSION_GREATER_EQUAL "1.13.0")
			set(CXX_STD "c++14")
		endif ()
	endif ()
endif ()

if (WIN32)
		set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   /MP /wd4200")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /wd4200 /std:c++14")
else ()
		set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wall -fPIC -pipe -std=gnu90")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -pipe -std=${CXX_STD} -fno-exceptions")
		if (APPLE)
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
		endif()
endif ()

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
	set(WORKFLOW_LIB workflow pthread OpenSSL::SSL OpenSSL::Crypto)
else ()
	set(WORKFLOW_LIB workflow pthread OpenSSL::SSL OpenSSL::Crypto ${LIBRT})
endif ()

foreach(src ${TEST_LIST})
	add_executable(${src} EXCLUDE_FROM_ALL ${src}.cc)
	target_link_libraries(${src} ${WORKFLOW_LIB} GTest::GTest GTest::Main)
	add_test(${src} ${src})
	add_dependencies(check ${src})
endforeach()

if (NOT ${CMAKE_MEMORYCHECK_COMMAND} STREQUAL "CMAKE_MEMORYCHECK_COMMAND-NOTFOUND")
	foreach(src ${TEST_LIST})
		add_test(${src}-memory-check ${memcheck_command} ./${src})
	endforeach()
endif ()
