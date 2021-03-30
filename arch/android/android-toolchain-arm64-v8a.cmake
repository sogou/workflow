set(CMAKE_SYSTEM_NAME Android)
set(ANDROID_TOOLCHAIN clang)
set(ANDROID_ABI arm64-v8a)
set(ANDROID_PLATFORM 21)
if (CMAKE_ANDROID_STL STREQUAL "shared")
    set(ANDROID_STL c++_shared)
endif()
include($ENV{ANDROID_NDK_ROOT}/build/cmake/android.toolchain.cmake)

add_definitions(-D ANDROID)
add_definitions(-D __ANDROID__)
add_definitions(-D SOGOU_SPEECH_SHARED_LIB)