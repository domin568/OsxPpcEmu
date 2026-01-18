cmake_minimum_required(VERSION 3.14)
project(OsxPpcEmu LANGUAGES C CXX)

if (MSVC)
    add_compile_options(/MP)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreadedDLL" CACHE STRING "CRT option")
endif ()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)

set(EXECUTABLE_NAME ${PROJECT_NAME})
set(SOURCE_FILES
        src/CMachoLoader.cpp
        src/COsxPpcEmu.cpp
        src/ImportDispatch.cpp
        src/Common.cpp
        src/CMemory.cpp
        src/CDebugger.cpp
        src/CGdbServer.cpp
)
set(HEADER_FILES
        include/CMachoLoader.hpp
        include/COsxPpcEmu.hpp
        include/Common.hpp
        include/ImportDispatch.hpp
        include/CMemory.hpp
        include/CDebugger.hpp
        include/CGdbServer.hpp
        include/PpcStructures.hpp
)

add_library(OsxPpcEmuLib STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_include_directories(OsxPpcEmuLib PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_compile_definitions(OsxPpcEmuLib PRIVATE DEBUG)

find_package(Unicorn CONFIG QUIET)
if (Unicorn_FOUND)
    target_link_libraries(OsxPpcEmuLib PUBLIC Unicorn::Unicorn)
else ()
    message(STATUS "Unicorn not found; falling back to FetchContent for build-from-source")
    include(FetchContent)
    FetchContent_Declare(
            unicorn
            GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
            GIT_TAG v2.1.4
    )
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libs" FORCE)
    FetchContent_MakeAvailable(unicorn)
    target_link_libraries(OsxPpcEmuLib PUBLIC unicorn)
endif ()

set(BUILD_SHARED_LIBS ON CACHE BOOL "Build LIEF as shared library" FORCE)
set(LIEF_BUILD_TESTS OFF CACHE BOOL "Disable tests" FORCE)
set(LIEF_BUILD_EXAMPLES OFF CACHE BOOL "Disable examples" FORCE)
set(vendorLIEF_submodule_dir "${CMAKE_CURRENT_LIST_DIR}/thirdparty/LIEF")
FetchContent_Declare(
        LIEF
        GIT_REPOSITORY https://github.com/lief-project/LIEF.git
        GIT_TAG 0.17.1
)
FetchContent_MakeAvailable(LIEF)

find_package(Threads REQUIRED)
target_link_libraries(OsxPpcEmuLib PUBLIC Threads::Threads LIEF::LIEF)

add_executable(${EXECUTABLE_NAME} src/main.cpp)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE OsxPpcEmuLib)
target_compile_definitions(${EXECUTABLE_NAME} PRIVATE DEBUG)

add_subdirectory(test)
