cmake_minimum_required(VERSION 3.21)
project(HomPSI)

set(CMAKE_CXX_STANDARD 14)

include_directories("/Users/Daniele/mylibs")

add_executable(HomPSI main.cpp)

find_package(SEAL 3.7 REQUIRED)
target_link_libraries(HomPSI SEAL::seal_shared)
