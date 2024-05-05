cmake_minimum_required(VERSION 3.23)
project(CryptographyProject)

set(CMAKE_C_STANDARD 11)

include_directories(
        AES
        RSA
        DES
        )

add_executable(CryptographyProject
        AES/AES.c
        AES/AES.h
        DES/DES.c
        DES/DES.h
        RSA/RSA.c
        RSA/RSA.h
        main.c
        )
