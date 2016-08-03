cmake_minimum_required (VERSION 2.6)
project(dyndnsc)
add_executable(dyndnsc dyndnsc.c)
target_link_libraries(dyndnsc curl)
