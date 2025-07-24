cmake_minimum_required(VERSION 3.31)
project(clang)

set(CMAKE_CXX_STANDARD 11)

# 确保添加了所有需要的源文件
add_executable(clang main.c
        md5.c
        md5.h
        sha1.h
        sha1.c
        des.h
        des.c)
