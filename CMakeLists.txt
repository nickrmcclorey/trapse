cmake_minimum_required(VERSION 3.15)

project(Trapse VERSION 1.0 DESCRIPTION "Trapse")

set(CMAKE_C_STANDARD 11)

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

option(CAPSTONE_ARCHITECTURE_DEFAULT "" 0)
option(CAPSTONE_ARM64_SUPPORT "" 1)
option(CAPSTONE_BUILD_SHARED "" 1)
add_subdirectory("deps/capstone")

set(PLATFORM "LINUX" CACHE STRING "Platform on which to build.")

if(PLATFORM STREQUAL "MACOSX86")
	list(APPEND DEFINES "-DMACOSX86")
elseif(PLATFORM STREQUAL "WINX86")
	list(APPEND DEFINES "-DWINX86")
elseif(PLATFORM STREQUAL "LINUXARM")
	list(APPEND DEFINES "-DLINUX")
	list(APPEND DEFINES "-DARM")
else()
	list(APPEND DEFINES "-DLINUX")
endif()

include_directories("include/")
include_directories("deps/capstone/include/")

add_executable(trapse trapse.c zydis.c os.c support.c capstone_arm.c)
target_link_libraries(trapse PRIVATE "Zydis")
target_link_libraries(trapse PRIVATE capstone-shared)
target_compile_options(trapse PRIVATE ${DEFINES})
add_executable(hello_world hello_world.c)

unset(PLATFORM CACHE)
