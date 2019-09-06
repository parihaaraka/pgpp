cmake_minimum_required(VERSION 3.10)

project(pgpp C CXX)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)

set(CMAKE_CXX_STANDARD 17)

file(GLOB LIB_FILES src/*.cpp)
if(NOT DEFINED PGPP_QT)
    message("Qt-related sources disabled")
    list(FILTER LIB_FILES EXCLUDE REGEX ".*/qt.cpp$")
endif()
add_library(${PROJECT_NAME} STATIC ${LIB_FILES})

target_include_directories(${PROJECT_NAME} PUBLIC include)
