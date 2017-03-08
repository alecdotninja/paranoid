cmake_minimum_required(VERSION 3.5)
project(paranoid)

set(CMAKE_C_STANDARD 99)

include_directories(.)

set(SOURCE_FILES main.c)

add_executable(paranoid ${SOURCE_FILES})
target_link_libraries(paranoid)
