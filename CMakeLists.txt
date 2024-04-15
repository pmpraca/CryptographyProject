cmake_minimum_required(VERSION 3.23)
project(CryptographyProject)

set(CMAKE_CXX_STANDARD 14)

include_directories(AES)

add_executable(CryptographyProject
        AES/AES.cpp
        AES/AES.h)
