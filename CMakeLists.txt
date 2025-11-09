cmake_minimum_required(VERSION 3.20)
project(encrypted_messenger CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")

# Find libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

add_executable(messenger messenger.cpp)
target_include_directories(messenger PRIVATE ${SODIUM_INCLUDE_DIRS})
target_link_libraries(messenger PRIVATE ${SODIUM_LIBRARIES} pthread)
