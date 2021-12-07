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
add_subdirectory(nameservice)
add_subdirectory(server)
add_subdirectory(client)

add_dependencies(kernel LINK_HEADERS)
add_dependencies(util LINK_HEADERS)
add_dependencies(manager LINK_HEADERS)
add_dependencies(algorithm LINK_HEADERS)
add_dependencies(protocol LINK_HEADERS)
add_dependencies(factory LINK_HEADERS)
add_dependencies(nameservice LINK_HEADERS)
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
	$<TARGET_OBJECTS:nameservice>
	$<TARGET_OBJECTS:server>
	$<TARGET_OBJECTS:client>
)

#target_link_libraries(${LIB_SHARED} ws2_32 wsock32 OpenSSL::SSL OpenSSL::Crypto)
#if (NOT WIN32)

if (KAFKA STREQUAL "y")
	add_dependencies(client_kafka LINK_HEADERS)
	add_dependencies(util_kafka LINK_HEADERS)
	add_dependencies(protocol_kafka LINK_HEADERS)
	add_dependencies(factory_kafka LINK_HEADERS)
	add_library(
		"wfkafka" STATIC
		$<TARGET_OBJECTS:client_kafka>
		$<TARGET_OBJECTS:util_kafka>
		$<TARGET_OBJECTS:protocol_kafka>
		$<TARGET_OBJECTS:factory_kafka>
)
endif ()

install(
	TARGETS ${PROJECT_NAME}
	ARCHIVE
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
	COMPONENT devel
)

if (APPLE)
	set(LIBSO ${LIB_DIR}/libworkflow.a)
elseif (NOT WIN32)
	set(LIBSO ${LIB_DIR}/libworkflow.so)
	add_custom_target(
		SCRIPT_SHARED_LIB ALL
		COMMAND ${CMAKE_COMMAND} -E echo 'GROUP ( libworkflow.a AS_NEEDED ( libpthread.so libssl.so libcrypto.so ) ) ' > ${LIBSO}
	)
	add_dependencies(SCRIPT_SHARED_LIB ${PROJECT_NAME})
endif ()

if (KAFKA STREQUAL "y")
	if (APPLE)
		set(LIBSOKAFKA ${LIB_DIR}/libwfkafka.a)
	else ()
		set(LIBSOKAFKA ${LIB_DIR}/libwfkafka.so)
		add_custom_target(
			SCRIPT_SHARED_LIB_KAFKA ALL
			COMMAND ${CMAKE_COMMAND} -E echo 'GROUP ( libwfkafka.a AS_NEEDED ( libpthread.so libssl.so libcrypto.so ) ) ' > ${LIBSOKAFKA}
		)
		add_dependencies(SCRIPT_SHARED_LIB_KAFKA "wfkafka")
	endif ()
endif ()

install(
	FILES ${LIBSO}
	DESTINATION ${CMAKE_INSTALL_LIBDIR}
	COMPONENT devel
)

if (KAFKA STREQUAL "y")
	install(
		FILES ${LIB_DIR}/libwfkafka.a
		DESTINATION ${CMAKE_INSTALL_LIBDIR}
		COMPONENT devel
	)
	if (NOT APPLE)
		install(
			FILES ${LIBSOKAFKA}
			DESTINATION ${CMAKE_INSTALL_LIBDIR}
			COMPONENT devel
		)
	endif()
endif ()

install (
	TARGETS ${CMAKE_PROJECT_NAME} EXPORT ${CMAKE_PROJECT_NAME}-targets
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install (
	EXPORT ${CMAKE_PROJECT_NAME}-targets
	FILE ${CMAKE_PROJECT_NAME}-targets.cmake
	DESTINATION "${CMAKE_CONFIG_INSTALL_DIR}"
)
