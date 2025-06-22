cmake_minimum_required(VERSION 3.15)
project(BlockCrypt LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -g")

add_library(blockcrypt_lib
    constants/BlockCryptConstants.cpp
    src/blockcrypt.cpp
    src/padding.cpp
    src/CBC.cpp
)

target_include_directories(blockcrypt_lib
    PUBLIC
        include
        constants
)

include(FetchContent)
FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v3.5.3
)
FetchContent_MakeAvailable(Catch2)

include(CTest)
enable_testing()
add_subdirectory(tests)
add_test(NAME BlockCryptTests COMMAND test_blockcrypt)

