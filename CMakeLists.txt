cmake_minimum_required(VERSION 3.15)
project(osxppcemu LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)

find_package(LIEF REQUIRED COMPONENTS STATIC)

add_subdirectory(thirdparty/unicorn)

set(SOURCE_FILES src/main.cpp src/CMachoLoader.cpp src/COsxPpcEmu.cpp src/ImportDispatch.cpp)
set(HEADER_FILES include/CMachoLoader.hpp include/COsxPpcEmu.hpp include/Common.hpp include/ImportDispatch.hpp)

add_executable(osxppcemu ${SOURCE_FILES} ${HEADER_FILES})
target_compile_definitions(osxppcemu PRIVATE DEBUG)

target_include_directories(osxppcemu PRIVATE ${CMAKE_SOURCE_DIR}/thirdparty/unicorn/include)

find_package(Threads REQUIRED)
target_link_libraries(osxppcemu PRIVATE m Threads::Threads)
target_link_libraries(osxppcemu PRIVATE unicorn LIEF::LIEF)
