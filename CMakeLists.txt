cmake_minimum_required(VERSION 3.31)
project(extrktr)

set(CMAKE_CXX_STANDARD 20)

list(APPEND CMAKE_PREFIX_PATH "${CMAKE_CURRENT_SOURCE_DIR}/LIEF-0.16.5-Darwin-arm64")
find_package(LIEF REQUIRED)

include(FetchContent)
# Configure minizip-ng fetch
FetchContent_Declare(
        minizip-ng
        GIT_REPOSITORY https://github.com/zlib-ng/minizip-ng.git
        GIT_TAG        master
)

# Configure options to disable extras
set(MZ_FETCH_LIBS OFF CACHE BOOL "" FORCE)
set(MZ_BUILD_TEST OFF CACHE BOOL "" FORCE)
set(MZ_BUILD_UNIT_TESTS OFF CACHE BOOL "" FORCE)
set(MZ_BUILD_FUZZ OFF CACHE BOOL "" FORCE)
set(MZ_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(minizip-ng)

FetchContent_Declare(
        lzfse
        GIT_REPOSITORY https://github.com/lzfse/lzfse.git
        GIT_TAG        master
)
FetchContent_MakeAvailable(lzfse)

add_executable(extrktr src/main.cpp
        src/utils.cpp
        src/macho/macho_cli.cpp
        src/kernel/kernel_cli.cpp
        src/macho/actions.cpp
        src/signparse.cpp
        src/kernel/actions.cpp
)

target_include_directories(extrktr PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/external"
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${lzfse_SOURCE_DIR}/src"
)

target_link_libraries(extrktr LIEF::LIEF minizip lzfse)