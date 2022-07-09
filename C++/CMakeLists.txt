cmake_minimum_required(VERSION 3.2)

project(passwords_cracker_c++ CXX)

set(CMAKE_CXX_STANDARD 17)

file(GLOB SOURCES "src/*.cc")
file(GLOB HEADERS "inc/*.h")

find_library(ssl REQUIRED)
find_library(crypto REQUIRED)
find_library(pthread REQUIRED)

add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ssl crypto pthread)
target_compile_definitions(${PROJECT_NAME} PUBLIC DATA_DIR_PATH="${CMAKE_SOURCE_DIR}/data/")
target_include_directories(${PROJECT_NAME} PUBLIC "${PROJECT_SOURCE_DIR}")
