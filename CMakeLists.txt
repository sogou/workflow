cmake_minimum_required(VERSION 3.6)

set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "build type")
set(CMAKE_SKIP_RPATH TRUE)

project(
	workflow
	VERSION 0.10.8
	LANGUAGES C CXX
)

if (CYGWIN)
	message(FATAL_ERROR "Sorry, DO NOT support Cygwin")
endif ()

if (MINGW)
	message(FATAL_ERROR "Sorry, DO NOT support MinGW")
endif ()

include(GNUInstallDirs)

set(CMAKE_CONFIG_INSTALL_FILE ${PROJECT_BINARY_DIR}/config.toinstall.cmake)
set(CMAKE_CONFIG_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
set(INC_DIR ${PROJECT_SOURCE_DIR}/_include CACHE PATH "workflow inc")
set(LIB_DIR ${PROJECT_SOURCE_DIR}/_lib CACHE PATH "workflow lib")

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${LIB_DIR})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${LIB_DIR})

add_custom_target(
	LINK_HEADERS ALL
	COMMENT "link headers..."
)

INCLUDE(CMakeLists_Headers.txt)

macro(makeLink src dest target)
	add_custom_command(
		TARGET ${target} PRE_BUILD
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${src} ${dest}
		DEPENDS ${dest}
	)
endmacro()

add_custom_command(
	TARGET LINK_HEADERS PRE_BUILD
	COMMAND ${CMAKE_COMMAND} -E make_directory ${INC_DIR}/${PROJECT_NAME}
)

foreach(header_file ${INCLUDE_HEADERS} ${INCLUDE_KERNEL_HEADERS})
	string(REPLACE "/" ";" arr ${header_file})
	list(GET arr -1 file_name)
	makeLink(${PROJECT_SOURCE_DIR}/${header_file} ${INC_DIR}/${PROJECT_NAME}/${file_name} LINK_HEADERS)
endforeach()

message("CMAKE_C_FLAGS_DEBUG is ${CMAKE_C_FLAGS_DEBUG}")
message("CMAKE_C_FLAGS_RELEASE is ${CMAKE_C_FLAGS_RELEASE}")
message("CMAKE_C_FLAGS_RELWITHDEBINFO is ${CMAKE_C_FLAGS_RELWITHDEBINFO}")
message("CMAKE_C_FLAGS_MINSIZEREL is ${CMAKE_C_FLAGS_MINSIZEREL}")

message("CMAKE_CXX_FLAGS_DEBUG is ${CMAKE_CXX_FLAGS_DEBUG}")
message("CMAKE_CXX_FLAGS_RELEASE is ${CMAKE_CXX_FLAGS_RELEASE}")
message("CMAKE_CXX_FLAGS_RELWITHDEBINFO is ${CMAKE_CXX_FLAGS_RELWITHDEBINFO}")
message("CMAKE_CXX_FLAGS_MINSIZEREL is ${CMAKE_CXX_FLAGS_MINSIZEREL}")

if (WIN32)
	set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   /MP /wd4200")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MP /wd4200 /std:c++14")
else ()
	set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -Wall -fPIC -pipe -std=gnu90")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -pipe -std=c++11 -fno-exceptions -Wno-invalid-offsetof")
endif ()

add_subdirectory(src)

####CONFIG

include(CMakePackageConfigHelpers)
set(CONFIG_INC_DIR ${INC_DIR})
set(CONFIG_LIB_DIR ${LIB_DIR})
configure_package_config_file(
	${PROJECT_NAME}-config.cmake.in
	${PROJECT_SOURCE_DIR}/${PROJECT_NAME}-config.cmake
	INSTALL_DESTINATION ${CMAKE_CONFIG_INSTALL_DIR}
	PATH_VARS CONFIG_INC_DIR CONFIG_LIB_DIR
)

set(CONFIG_INC_DIR ${CMAKE_INSTALL_INCLUDEDIR})
set(CONFIG_LIB_DIR ${CMAKE_INSTALL_LIBDIR})
configure_package_config_file(
	${PROJECT_NAME}-config.cmake.in
	${CMAKE_CONFIG_INSTALL_FILE}
	INSTALL_DESTINATION ${CMAKE_CONFIG_INSTALL_DIR}
	PATH_VARS CONFIG_INC_DIR CONFIG_LIB_DIR
)

write_basic_package_version_file(
	${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
	VERSION ${WORKFLOW_VERSION}
	COMPATIBILITY AnyNewerVersion 
)

install(
	FILES ${CMAKE_CONFIG_INSTALL_FILE}
	DESTINATION ${CMAKE_CONFIG_INSTALL_DIR}
	COMPONENT devel
	RENAME ${PROJECT_NAME}-config.cmake
)

install(
	FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
	DESTINATION ${CMAKE_CONFIG_INSTALL_DIR}
	COMPONENT devel
)

install(
	FILES ${INCLUDE_HEADERS} ${INCLUDE_KERNEL_HEADERS}
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/${PROJECT_NAME}
	COMPONENT devel
)

install(
	FILES README.md
	DESTINATION "${CMAKE_INSTALL_DOCDIR}-${PROJECT_VERSION}"
	COMPONENT devel
)
