cmake_minimum_required(VERSION 3.13)
project(SMS
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 20)

add_executable(SMS main.cpp ucs2.cpp ucs2.h utf8/utf8.h utf8/utf8/checked.h utf8/utf8/unchecked.h utf8/utf8/core.h)
target_compile_options(SMS PUBLIC -Wall -Wextra -Wpedantic -pipe -pthread)
