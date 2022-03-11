cmake_minimum_required(VERSION 3.21)
project(HomPSI)

set(CMAKE_CXX_FLAGS "-g -Wall -Werror -std=c++14")
set(CMAKE_CXX_STANDARD 14)

add_executable(HomPSI main.cpp protoBuff/ciphertexts.pb.cc protoBuff/ciphertexts.pb.h)

INCLUDE(FindProtobuf)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR})
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ciphertexts.proto)
target_include_directories(HomPSI PUBLIC ${CMAKE_BINARY_DIR}/protoBuff)

find_package(SEAL 3.7 REQUIRED)
target_link_libraries(HomPSI SEAL::seal_shared)

find_package(Protobuf REQUIRED)
target_link_libraries(HomPSI ${Protobuf_LIBRARIES})