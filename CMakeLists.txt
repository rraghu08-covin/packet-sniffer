cmake_minimum_required(VERSION 3.14)
project(packet-sniffer VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wpedantic -D_GNU_SOURCE)

file(GLOB_RECURSE SRCS "src/*.c")
add_executable(packet-sniffer ${SRCS})
target_include_directories(packet-sniffer PRIVATE include)

install(TARGETS packet-sniffer DESTINATION bin)
