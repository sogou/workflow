cmake_minimum_required(VERSION 3.6)
project(server)

set(SRC
	WFServer.cc
	WFMySQLServer.cc
)

add_library(${PROJECT_NAME} OBJECT ${SRC})
if (WIN32)
	if (MINGW)
		target_compile_definitions(
			${PROJECT_NAME} PRIVATE
		)
	else ()
		target_compile_definitions(
			${PROJECT_NAME} PRIVATE
			dup=_dup
		)
	endif ()
endif ()

