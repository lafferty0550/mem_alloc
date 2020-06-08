cmake_minimum_required(VERSION 3.16)
project(simple_mem_allocator C)

set(CMAKE_C_STANDARD 11)

add_executable(simple_mem_allocator main.c sbrk.c sbrk.h)