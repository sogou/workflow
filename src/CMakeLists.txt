cmake_minimum_required(VERSION 3.6)

if(ANDROID)
	include_directories(${OPENSSL_INCLUDE_DIR})
	link_directories(${OPENSSL_LINK_DIR})
else()
	find_package(OpenSSL REQUIRED)
endif ()

include_directories(${OPENSSL_INCLUDE_DIR} ${INC_DIR}/workflow)

if (KAFKA STREQUAL "y")
	find_path(SNAPPY_INCLUDE_PATH NAMES snappy.h)
	find_library(SNAPPY_LIB NAMES snappy)
	if ((NOT SNAPPY_INCLUDE_PATH) OR (NOT SNAPPY_LIB))
		message(FATAL_ERROR "Fail to find snappy with KAFKA=y")
	endif ()
	include_directories(${SNAPPY_INCLUDE_PATH})
endif ()

add_subdirectory(kernel)
add_subdirectory(util)
add_subdirectory(manager)
add_subdirectory(protocol)
add_subdirectory(factory)
add_subdirectory(nameservice)
add_subdirectory(server)
add_subdirectory(client)

add_dependencies(kernel LINK_HEADERS)
add_dependencies(util LINK_HEADERS)
add_dependencies(manager LINK_HEADERS)
add_dependencies(protocol LINK_HEADERS)
add_dependencies(factory LINK_HEADERS)
add_dependencies(nameservice LINK_HEADERS)
add_dependencies(server LINK_HEADERS)
add_dependencies(client LINK_HEADERS)

set(STATIC_LIB_NAME ${PROJECT_NAME}-static)
set(SHARED_LIB_NAME ${PROJECT_NAME}-shared)

add_library(
	${STATIC_LIB_NAME} STATIC
	$<TARGET_OBJECTS:kernel>
	$<TARGET_OBJECTS:util>
	$<TARGET_OBJECTS:manager>
	$<TARGET_OBJECTS:protocol>
	$<TARGET_OBJECTS:factory>
	$<TARGET_OBJECTS:nameservice>
	$<TARGET_OBJECTS:server>
	$<TARGET_OBJECTS:client>
)

add_library(
	${SHARED_LIB_NAME} SHARED
	$<TARGET_OBJECTS:kernel>
	$<TARGET_OBJECTS:util>
	$<TARGET_OBJECTS:manager>
	$<TARGET_OBJECTS:protocol>
	$<TARGET_OBJECTS:factory>
	$<TARGET_OBJECTS:nameservice>
	$<TARGET_OBJECTS:server>
	$<TARGET_OBJECTS:client>
)

if(ANDROID)
	target_link_libraries(${SHARED_LIB_NAME} ssl crypto c)
else()
	target_link_libraries(${SHARED_LIB_NAME} OpenSSL::SSL OpenSSL::Crypto pthread)
endif ()

set_target_properties(${STATIC_LIB_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME})
set_target_properties(${SHARED_LIB_NAME} PROPERTIES OUTPUT_NAME ${PROJECT_NAME} VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

if (KAFKA STREQUAL "y")
	add_dependencies(client_kafka LINK_HEADERS)
	add_dependencies(util_kafka LINK_HEADERS)
	add_dependencies(protocol_kafka LINK_HEADERS)
	add_dependencies(factory_kafka LINK_HEADERS)

	set(KAFKA_STATIC_LIB_NAME "wfkafka-static")
	add_library(
		${KAFKA_STATIC_LIB_NAME} STATIC
		$<TARGET_OBJECTS:client_kafka>
		$<TARGET_OBJECTS:util_kafka>
		$<TARGET_OBJECTS:protocol_kafka>
		$<TARGET_OBJECTS:factory_kafka>
	)
	set_target_properties(${KAFKA_STATIC_LIB_NAME} PROPERTIES OUTPUT_NAME "wfkafka")

	set(KAFKA_SHARED_LIB_NAME "wfkafka-shared")
	add_library(
		${KAFKA_SHARED_LIB_NAME} SHARED
		$<TARGET_OBJECTS:client_kafka>
		$<TARGET_OBJECTS:util_kafka>
		$<TARGET_OBJECTS:protocol_kafka>
		$<TARGET_OBJECTS:factory_kafka>
	)
	if (APPLE)
		target_link_libraries(${KAFKA_SHARED_LIB_NAME}
							  ${SHARED_LIB_NAME} z lz4 zstd ${SNAPPY_LIB})
	else ()
		target_link_libraries(${KAFKA_SHARED_LIB_NAME} ${SHARED_LIB_NAME})
	endif ()
	set_target_properties(${KAFKA_SHARED_LIB_NAME} PROPERTIES OUTPUT_NAME "wfkafka" VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
endif ()

install(
	TARGETS ${STATIC_LIB_NAME}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	COMPONENT devel
)

install(
	TARGETS ${SHARED_LIB_NAME}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	COMPONENT devel
)

if (KAFKA STREQUAL "y")
	install(
		TARGETS ${KAFKA_STATIC_LIB_NAME}
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
		COMPONENT devel
	)
	install(
		TARGETS ${KAFKA_SHARED_LIB_NAME}
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
		COMPONENT devel
	)
endif ()

