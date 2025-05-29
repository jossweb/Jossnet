cmake_minimum_required(VERSION 3.31)
project(jnet_c C)

set(CMAKE_C_STANDARD 11)

# 📌 Indique où sont les headers de Noise
include_directories(${CMAKE_SOURCE_DIR}/build/include)

# 📌 Indique où sont les .a
link_directories(${CMAKE_SOURCE_DIR}/build/lib)

add_executable(jnet_c server.c
        client.c)

# 📌 Lie les .a
target_link_libraries(jnet_c noiseprotocol noisekeys noiseprotobufs)