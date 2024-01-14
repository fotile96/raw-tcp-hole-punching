cmake_minimum_required(VERSION 3.26)
project(raw-tcp-hole-punching)

find_library(pcap NAMES pcap)
find_library(absl NAMES absl::cleanup)

add_executable(main main.cpp
        const.h
        in_cksum.h)
set_property(TARGET main PROPERTY CXX_STANDARD 20)
target_link_libraries(main -static-libstdc++ libpcap.a)
