cmake_minimum_required(VERSION 3.15)

project(Trapse VERSION 1.0 DESCRIPTION "Trapse")

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

set(PLATFORM "LINUX" CACHE STRING "Platform on which to build.")

if(PLATFORM STREQUAL "MACOSX86")
	list(APPEND DEFINES "-DMACOSX86")
else()
	list(APPEND DEFINES "-DLINUX")
endif()

include_directories("include/")

add_executable(trapse trapse.c zydis.c os.c)
target_link_libraries(trapse PRIVATE "Zydis")
target_compile_options(trapse PRIVATE ${DEFINES})
add_executable(hello_world hello_world.c)

unset(PLATFORM CACHE)
