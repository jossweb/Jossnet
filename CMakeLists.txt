cmake_minimum_required(VERSION 3.31)
project(jnet_c C)

set(CMAKE_C_STANDARD 11)

include_directories(${CMAKE_SOURCE_DIR}/build/include)

link_directories(${CMAKE_SOURCE_DIR}/build/lib)

add_executable(jnet_c server.c
        client.c
        common.c
        common.h
        keygen.c)

target_link_libraries(jnet_c noiseprotocol noisekeys noiseprotobufs)