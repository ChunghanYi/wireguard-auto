#!/bin/sh

# Copyright (c) 2025 Chunghan Yi <chunghan.yi@gmail.com>
# SPDX-License-Identifier: MIT

build_it()
{
	if [ $1 = "release" ]; then
		CPPPATH=$(pwd)
		if [ ! -d ./external/spdlog ]; then
			mkdir -p external > /dev/null 2>&1
			cd external
			git clone https://github.com/gabime/spdlog
			cd spdlog
			mkdir build && cd build
			cmake .. && cmake --build .

			if [ ! -d $CPPPATH/external/lib ]; then
				mkdir $CPPPATH/external/lib > /dev/null 2>&1
			fi
			cp ./libspdlog.a ../../lib > /dev/null 2>&1
			cd ..
			cp -R ./include ../lib > /dev/null 2>&1
			cd $CPPPATH
		fi

		if [ ! -d ./external/boost_1_88_0 ]; then
			cd external
			if [ ! -r boost_1_88_0.tar.gz ]; then
				wget https://archives.boost.io/release/1.88.0/source/boost_1_88_0.tar.gz
			fi
			tar xvzf boost_1_88_0.tar.gz > /dev/null 2>&1
			cd boost_1_88_0
			./bootstrap.sh
			./b2
			./b2 headers
			cd $CPPPATH
		fi

		if [ ! -d ./external/libsodium-stable ]; then
			cd external
			if [ ! -r libsodium-1.0.20-stable.tar.gz ]; then
				wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.20-stable.tar.gz
			fi
			tar xvzf libsodium-1.0.20-stable.tar.gz > /dev/null 2>&1
			cd libsodium-stable
			mkdir -p output
			./configure --prefix=$(pwd)/output
			make
			make install
			cd $CPPPATH
		fi

		if [ -d ./lib/wg-tools ]; then
			cd ./lib/wg-tools
			make clean
			make target=linux
			cd $CPPPATH
		fi

		#for wg autoconnect client/server
		if [ ! -d ./build ]; then
			mkdir -p build
		fi
		cd build
		cmake .. && make
	elif [ $1 = "clean" ]; then
		rm -rf ./build > /dev/null 2>&1
		rm -rf ./external/lib > /dev/null 2>&1
		rm -rf ./external/spdlog > /dev/null 2>&1
		rm -rf ./external/boost_1_88_0 > /dev/null 2>&1
		rm -rf ./external/libsodium-stable > /dev/null 2>&1
	fi
}

start_now()
{
	if [ $# -eq 0 ]; then
		echo "Usage: $0 release|clean"
		exit 0
	fi
	build_it $1
}

start_now $1
