# SPDX-License-Identifier: MIT
#
# Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>

cmake_minimum_required(VERSION 3.22.1)
project(wgac)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-std=c++17")

add_library(spdlog STATIC IMPORTED)
set_target_properties(spdlog
	PROPERTIES IMPORTED_LOCATION
	${CMAKE_SOURCE_DIR}/external/lib/libspdlog.a)

add_library(boost_program_options STATIC IMPORTED)
set_target_properties(boost_program_options
	PROPERTIES IMPORTED_LOCATION
	${CMAKE_SOURCE_DIR}/external/boost_1_88_0/stage/lib/libboost_program_options.a)

include_directories(${CMAKE_SOURCE_DIR}/external/lib/include
	${CMAKE_SOURCE_DIR}/external/boost_1_88_0)
add_definitions(-DVTYSH)

#server
add_executable(wg_autod
		src/autod/main.cpp
		src/autod/server.cpp
		src/autod/sendrecv.cpp
		src/autod/peer_tbl.cpp
		src/autod/vtysh.cpp
		src/autod/configuration.cpp
		src/autod/common.cpp)
target_link_libraries (wg_autod spdlog boost_program_options)

#client
add_executable(wg_autoc
		src/autoc/main.cpp
		src/autoc/client.cpp
		src/autoc/communication.cpp
		src/autoc/configuration.cpp
		src/autoc/common.cpp)
target_link_libraries (wg_autoc spdlog boost_program_options)
