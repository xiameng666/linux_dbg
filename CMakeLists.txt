cmake_minimum_required(VERSION 3.22.1)
project("linux_dbg")

# FetchContent is required for FetchContent_Declare / MakeAvailable
#include(FetchContent)

#FetchContent_Declare(
#  capstone
#  GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
#  GIT_TAG 5.0.3
#)

set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone)

# 配置静态库
#FetchContent_MakeAvailable(capstone)

add_executable(${CMAKE_PROJECT_NAME}
        # List C/C++ source files with relative paths to this CMakeLists.txt.
        main.cpp
        dbg.cpp)

if (TARGET capstone-static)
    set(CAPSTONE_LIB capstone-static)
elseif (TARGET capstone)
    set(CAPSTONE_LIB capstone)
else()
    message(FATAL_ERROR "Capstone target not found. Check add_subdirectory path.")
endif()

target_link_libraries(${CMAKE_PROJECT_NAME}
        # List libraries link to the target library
        android
        log
        ${CAPSTONE_LIB}
)