cmake_minimum_required(VERSION 3.15)
project(OsxPpcEmu LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)

set(EXECUTABLE_NAME ${PROJECT_NAME})
set(SOURCE_FILES
        src/CMachoLoader.cpp
        src/COsxPpcEmu.cpp
        src/ImportDispatch.cpp
        src/Common.cpp
        src/CMemory.cpp
)
set(HEADER_FILES
        include/CMachoLoader.hpp
        include/COsxPpcEmu.hpp
        include/Common.hpp
        include/ImportDispatch.hpp
        include/CMemory.hpp
)

add_subdirectory(thirdparty/unicorn)

add_library(OsxPpcEmuLib STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_include_directories(OsxPpcEmuLib PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_include_directories(OsxPpcEmuLib PUBLIC ${CMAKE_SOURCE_DIR}/thirdparty/unicorn/include)
target_compile_definitions(OsxPpcEmuLib PRIVATE DEBUG)

find_package(LIEF REQUIRED COMPONENTS STATIC)
find_package(Threads REQUIRED)
target_link_libraries(OsxPpcEmuLib PRIVATE Threads::Threads unicorn LIEF::LIEF)

add_executable(${EXECUTABLE_NAME} src/main.cpp)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE OsxPpcEmuLib)

add_subdirectory(test)
