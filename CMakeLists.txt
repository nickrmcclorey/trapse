cmake_minimum_required(VERSION 3.15)

project(Trapse VERSION 1.0 DESCRIPTION "Trapse")

option(ZYDIS_BUILD_TOOLS "" OFF)
option(ZYDIS_BUILD_EXAMPLES "" OFF)
add_subdirectory("deps/zydis")

include_directories("include/")

add_executable(trapse trapse.c zydis.c os.c)
target_link_libraries(trapse PRIVATE "Zydis")

add_executable(hello_world hello_world.c)
