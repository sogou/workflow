cmake_minimum_required(VERSION 3.6)

set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "build type")

project(benchmark
		LANGUAGES C CXX
)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

find_library(LIBRT rt)
find_package(OpenSSL REQUIRED)
find_package(workflow REQUIRED CONFIG HINTS ..)
include_directories(${OPENSSL_INCLUDE_DIR} ${WORKFLOW_INCLUDE_DIR})
link_directories(${WORKFLOW_LIB_DIR})

if (WIN32)
		set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   /MP /wd4200")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /wd4200 /std:c++14")
else ()
		set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wall -fPIC -pipe -std=gnu90")
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -pipe -std=c++11 -fno-exceptions -Wno-invalid-offsetof")
		if (APPLE)
			set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-deprecated-declarations")
		endif()
endif ()

set(BENCHMARK_LIST
	benchmark-01-http_server
	benchmark-02-http_server_long_req
)

if (APPLE)
	set(WORKFLOW_LIB workflow pthread OpenSSL::SSL OpenSSL::Crypto)
else ()
	set(WORKFLOW_LIB workflow pthread OpenSSL::SSL OpenSSL::Crypto ${LIBRT})
endif ()

foreach(src ${BENCHMARK_LIST})
	string(REPLACE "-" ";" arr ${src})
	list(GET arr -1 bin_name)
	add_executable(${bin_name} ${src}.cc)
	target_link_libraries(${bin_name} ${WORKFLOW_LIB})
endforeach()
