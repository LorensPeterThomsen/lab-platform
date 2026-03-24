cmake_minimum_required(VERSION 3.16)
project(login_server CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(login_server main.cpp)
target_include_directories(login_server PRIVATE third_party)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PQXX REQUIRED libpqxx)
pkg_check_modules(SODIUM REQUIRED libsodium)

target_include_directories(login_server PRIVATE
    ${PQXX_INCLUDE_DIRS}
    ${SODIUM_INCLUDE_DIRS}
)

target_link_directories(login_server PRIVATE
    ${PQXX_LIBRARY_DIRS}
    ${SODIUM_LIBRARY_DIRS}
)

target_link_libraries(login_server PRIVATE
    ${PQXX_LIBRARIES}
    pq
    ${SODIUM_LIBRARIES}
    pthread
)
