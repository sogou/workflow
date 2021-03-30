cmake_minimum_required(VERSION 3.6)

## liuyang modified: change depend openssl to android so ##
# find_package(OpenSSL REQUIRED)
# include_directories(${OPENSSL_INCLUDE_DIR} ${INC_DIR}/workflow)
################################################################
if (NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
    find_package(OpenSSL REQUIRED)
    include_directories(${OPENSSL_INCLUDE_DIR} ${INC_DIR}/workflow)
else()
    include_directories(${INC_DIR} ${INC_DIR}/workflow)
	set(OPENSSL_ROOT_DIR ${PROJECT_SOURCE_DIR}/openssl/${ANDROID_ABI})
	set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
	set(OPENSSL_LIBRARIES ${OPENSSL_ROOT_DIR}/lib/libcrypto.so ${OPENSSL_ROOT_DIR}/lib/libssl.so)
endif ()
## liuyang modified: change depend openssl to android so ##

add_subdirectory(kernel)
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


## liuyang modified: change depend openssl to android so ##
# add_library(
# 	${PROJECT_NAME} STATIC
# 	$<TARGET_OBJECTS:kernel>
# 	$<TARGET_OBJECTS:util>
# 	$<TARGET_OBJECTS:manager>
# 	$<TARGET_OBJECTS:algorithm>
# 	$<TARGET_OBJECTS:protocol>
# 	$<TARGET_OBJECTS:factory>
# 	$<TARGET_OBJECTS:nameservice>
# 	$<TARGET_OBJECTS:server>
# 	$<TARGET_OBJECTS:client>
# )
############################################################
if(CMAKE_SHARED STREQUAL "true")
	set(LIB_TYPE "SHARED")
else()
	set(LIB_TYPE "STATIC")
endif()
add_library(
    ${PROJECT_NAME} ${LIB_TYPE}
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
if(${CMAKE_BUILD_TYPE} MATCHES "Release")
	set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS_RELEASE -s)
endif()
## liuyang modified: change depend openssl to android so ##

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

## liuyang modified: change depend openssl to android so ##
#if (APPLE)
#	set(LIBSO ${LIB_DIR}/libworkflow.a)
###########################################################
 if (CMAKE_SYSTEM_NAME STREQUAL "APPLE")
	set(LIBSO ${LIB_DIR}/libworkflow.a)
 elseif (CMAKE_SYSTEM_NAME STREQUAL "Android")
	target_link_libraries(${PROJECT_NAME}
	                      ${OPENSSL_LIBRARIES})
## liuyang modified: change depend openssl to android so ##
else ()
	set(LIBSO ${LIB_DIR}/libworkflow.so)
	add_custom_target(
		SCRIPT_SHARED_LIB ALL
		COMMAND ${CMAKE_COMMAND} -E echo 'GROUP ( libworkflow.a AS_NEEDED ( libpthread.so libssl.so libcrypto.so ) ) ' > ${LIBSO}
	)
	add_dependencies(SCRIPT_SHARED_LIB ${PROJECT_NAME})
endif()

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
	TARGETS ${PROJECT_NAME} EXPORT ${CMAKE_PROJECT_NAME}-targets
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install (
	EXPORT ${CMAKE_PROJECT_NAME}-targets
	FILE ${CMAKE_PROJECT_NAME}-targets.cmake
	DESTINATION "${CMAKE_CONFIG_INSTALL_DIR}"
)
