#!/bin/sh

g++ -std=c++20 -o secretbox secretbox.cpp -L../../../external/libsodium-stable/output/lib/ -lsodium
g++ -std=c++20 -o base64 base64.cpp -L../../../external/libsodium-stable/output/lib/ -lsodium

#export LD_LIBRARY_PATH=/mnt/hdd/workspace/mygithub_prj/wireguard-auto/external/libsodium-stable/output/lib:$LD_LIBRARY_PATH
