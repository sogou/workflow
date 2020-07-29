cmake_minimum_required(VERSION 3.6)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR} ${INC_DIR}/workflow)

if (WIN32)
	add_subdirectory(kernel_win)
else ()
	add_subdirectory(kernel)
endif ()

add_subdirectory(util)
add_subdirectory(manager)
add_subdirectory(algorithm)
add_subdirectory(protocol)
add_subdirectory(factory)
add_subdirectory(server)
add_subdirectory(client)

add_dependencies(kernel LINK_HEADERS)
add_dependencies(util LINK_HEADERS)
add_dependencies(manager LINK_HEADERS)
add_dependencies(algorithm LINK_HEADERS)
add_dependencies(protocol LINK_HEADERS)
add_dependencies(factory LINK_HEADERS)
add_dependencies(server LINK_HEADERS)
add_dependencies(client LINK_HEADERS)

add_library(
	${PROJECT_NAME} STATIC
	$<TARGET_OBJECTS:kernel>
	$<TARGET_OBJECTS:util>
	$<TARGET_OBJECTS:manager>
	$<TARGET_OBJECTS:algorithm>
	$<TARGET_OBJECTS:protocol>
	$<TARGET_OBJECTS:factory>
	$<TARGET_OBJECTS:server>
	$<TARGET_OBJECTS:client>
)

install(
	TARGETS ${PROJECT_NAME}
	ARCHIVE
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
	COMPONENT devel
)

if (APPLE)
	set(LIBSO ${LIB_DIR}/libworkflow.a)
else ()
	set(LIBSO ${LIB_DIR}/libworkflow.so)
	add_custom_target(
		SCRIPT_SHARED_LIB ALL
		COMMAND ${CMAKE_COMMAND} -E echo 'GROUP ( libworkflow.a AS_NEEDED ( libpthread.so libssl.so libcrypto.so ) ) ' > ${LIBSO}
	)
	add_dependencies(SCRIPT_SHARED_LIB ${PROJECT_NAME})
endif ()

install(
	FILES ${LIBSO}
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
	COMPONENT devel
)

