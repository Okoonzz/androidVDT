cmake_minimum_required(VERSION 3.22.1)

project("integritydemo")

add_library(
        integritydemo
        SHARED
        native-lib.cpp
)

find_library(
        log-lib
        log
)

target_link_libraries(
        integritydemo
        ${log-lib}
)