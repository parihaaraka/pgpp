cmake_minimum_required(VERSION 3.10)

project(pgpp C CXX)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_COLOR_MAKEFILE   ON)

set(CMAKE_CXX_STANDARD 17)

file(GLOB LIB_FILES src/*.cpp)
if(NOT DEFINED PGPP_QT)
	message("Qt-related sources disabled")
	list(FILTER LIB_FILES EXCLUDE REGEX ".*/qt.cpp$")
else()
	find_package(QT NAMES Qt6 Qt5 COMPONENTS Widgets REQUIRED)
	find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Widgets REQUIRED)
	include_directories(${Qt5Core_INCLUDE_DIRS} ${Qt5Widgets_INCLUDE_DIRS})
	set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()
add_library(${PROJECT_NAME} STATIC ${LIB_FILES})

set(PostgreSQL_ADDITIONAL_VERSIONS "10" "11" "12" "13" "14")
find_package(PostgreSQL REQUIRED)
target_include_directories(${PROJECT_NAME} PRIVATE ${PostgreSQL_INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE ${PostgreSQL_LIBRARIES})
message(${PostgreSQL_LIBRARIES})
message("-------------------------------------")
message(${PROJECT_SOURCE_DIR})
target_include_directories(${PROJECT_NAME} PUBLIC ${PROJECT_SOURCE_DIR} include)
