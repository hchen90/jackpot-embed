cmake_minimum_required(VERSION 3.0.2)
project(jackpot-embed)

add_subdirectory(mbedtls)

add_definitions("-Wall -g")

set(PACKAGE_NAME "jackpot-embed")
set(PACKAGE_VERSION "1.0")
set(PACKAGE_URL "https://github.com/hchen90/jackpot.git")
set(PACKAGE_BUGREPORT "a.chenxiang.z@gmail.com")
configure_file(config.h.in config.h @ONLY)

file(GLOB SRCFILES "*.c")
file(GLOB HDRFILES "*.h")

add_executable(jackpot-embed ${SRCFILES} ${HDRFILES})
target_include_directories(jackpot-embed PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls/include")
target_link_libraries(jackpot-embed LINK_PUBLIC mbedtls mbedcrypto mbedx509 "-pthread")

set(CMAKE_INSTALL_BINDIR "/usr/bin")
install(TARGETS jackpot-embed DESTINATION ${CMAKE_INSTALL_BINDIR})
