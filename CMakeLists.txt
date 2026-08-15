cmake_minimum_required(VERSION 3.20)
project(OsxPpcEmu LANGUAGES C CXX)

if (MSVC)
    add_compile_options(/MP /utf-8 /Zc:preprocessor)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
endif ()

set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 23)

set(EXECUTABLE_NAME ${PROJECT_NAME})
set(SOURCE_FILES
        src/loader/CMachoLoader.cpp
        src/COsxPpcEmu.cpp
        src/Common.cpp
        src/mem/CMemory.cpp
        src/mem/CHeap.cpp
        src/debug/CDebugger.cpp
        src/debug/CGdbServer.cpp
        src/hook/EmuHooks.cpp
        src/hook/EmuTrace.cpp
        src/hook/ImportTable.cpp
        src/mem/StackLayout.cpp
        src/shims/carbon/CarbonShims.cpp
        src/shims/dyld/DyldShims.cpp
        src/shims/libc/LibcShims.cpp
        src/platform/AbiTranslate.cpp
        src/platform/FsTranslate.cpp
        third_party/printf/printf.c
        third_party/scanf/scanf.c
)
set(HEADER_FILES
        include/loader/CMachoLoader.hpp
        include/COsxPpcEmu.hpp
        include/Common.hpp
        include/DefaultRuneLocale.hpp
        include/hook/EmuHooks.hpp
        include/hook/EmuTrace.hpp
        include/hook/HookContext.hpp
        include/hook/ImportDispatch.hpp
        include/hook/ImportTable.hpp
        include/mem/CMemory.hpp
        include/mem/CHeap.hpp
        include/mem/StackLayout.hpp
        include/debug/CDebugger.hpp
        include/debug/CGdbServer.hpp
        include/debug/PlatformSocket.hpp
        include/PpcStructures.hpp
        include/shims/ShimContext.hpp
        include/shims/carbon/CarbonShims.hpp
        include/shims/dyld/DyldShims.hpp
        include/shims/libc/LibcShims.hpp
        include/platform/AbiTranslate.hpp
        include/platform/FsTranslate.hpp
        third_party/printf/printf.h
        third_party/scanf/scanf.h
)

if(WIN32)
    list(APPEND HEADER_FILES
        include/platform/PosixCompat.hpp
    )
endif()

option(DEBUGGER_ENABLED "Enable built-in PPC debugger and GDB server" OFF)

add_library(OsxPpcEmuLib STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_include_directories(OsxPpcEmuLib PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/include/mem
        ${CMAKE_SOURCE_DIR}/include/debug
        ${CMAKE_SOURCE_DIR}/include/hook
        ${CMAKE_SOURCE_DIR}/include/loader
)
target_compile_definitions(OsxPpcEmuLib PRIVATE $<$<BOOL:${DEBUGGER_ENABLED}>:DEBUGGER_ENABLED>)

if (WIN32)
    target_compile_definitions(OsxPpcEmuLib PUBLIC
            NOMINMAX
            WIN32_LEAN_AND_MEAN
            _CRT_SECURE_NO_WARNINGS
            _CRT_NONSTDC_NO_WARNINGS
            _CRT_SECURE_NO_DEPRECATE
    )
endif ()

find_package(PkgConfig QUIET)

find_package(Unicorn CONFIG QUIET)

if (Unicorn_FOUND)
    message(STATUS "Found Unicorn via CMake package")
    target_link_libraries(OsxPpcEmuLib PUBLIC Unicorn::Unicorn)

elseif (PkgConfig_FOUND)

    pkg_check_modules(UNICORN QUIET unicorn)

    if (UNICORN_FOUND)
        message(STATUS "Found Unicorn via pkg-config")
        add_library(Unicorn::Unicorn INTERFACE IMPORTED)
        set_target_properties(Unicorn::Unicorn PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${UNICORN_INCLUDE_DIRS}"
                INTERFACE_LINK_LIBRARIES "${UNICORN_LIBRARIES}"
                INTERFACE_LINK_DIRECTORIES "${UNICORN_LIBRARY_DIRS}"
        )
        target_link_libraries(OsxPpcEmuLib PUBLIC Unicorn::Unicorn)

    else ()
        message(STATUS "Unicorn not found; using FetchContent")
        include(FetchContent)
        FetchContent_Declare(
                unicorn
                GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
                GIT_TAG v2.1.4
                GIT_SUBMODULES ""
        )

        set(UNICORN_ARCH "ppc" CACHE STRING "")
        set(UNICORN_BUILD_TESTS OFF CACHE BOOL "")
        FetchContent_MakeAvailable(unicorn)
        target_link_libraries(OsxPpcEmuLib PUBLIC unicorn)
    endif ()
else ()
    message(STATUS "pkg-config not found; searching for Unicorn library directly")
    find_library(UNICORN_LIBRARY NAMES unicorn)
    find_path(UNICORN_INCLUDE_DIR NAMES unicorn/unicorn.h)
    if (UNICORN_LIBRARY AND UNICORN_INCLUDE_DIR)
        add_library(Unicorn::Unicorn INTERFACE IMPORTED)
        set_target_properties(Unicorn::Unicorn PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${UNICORN_INCLUDE_DIR}"
                INTERFACE_LINK_LIBRARIES "${UNICORN_LIBRARY}"
        )
        target_link_libraries(OsxPpcEmuLib PUBLIC Unicorn::Unicorn)
    else ()
        message(FATAL_ERROR "Unicorn library not found")
    endif ()
endif ()

find_package(LIEF CONFIG QUIET)
if (LIEF_FOUND)
    message(STATUS "Found LIEF via CMake package")
    target_link_libraries(OsxPpcEmuLib PUBLIC LIEF::LIEF)
else ()
    if (PkgConfig_FOUND)
        pkg_check_modules(LIEF QUIET lief)
    endif ()

    if (LIEF_FOUND)
        message(STATUS "Found LIEF via pkg-config")
        add_library(LIEF::LIEF INTERFACE IMPORTED)
        set_target_properties(LIEF::LIEF PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${LIEF_INCLUDE_DIRS}"
                INTERFACE_LINK_LIBRARIES "${LIEF_LIBRARIES}"
                INTERFACE_LINK_DIRECTORIES "${LIEF_LIBRARY_DIRS}"
        )
        target_link_libraries(OsxPpcEmuLib PUBLIC LIEF::LIEF)
    else ()
        message(STATUS "LIEF not found; compile from source")
        include(FetchContent)

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
        target_link_libraries(OsxPpcEmuLib PUBLIC LIEF::LIEF)
    endif ()
endif ()

find_package(Threads REQUIRED)
target_link_libraries(OsxPpcEmuLib PUBLIC Threads::Threads)

if (WIN32)
    target_link_libraries(OsxPpcEmuLib PUBLIC ws2_32)
endif ()

add_executable(${EXECUTABLE_NAME} src/main.cpp)
target_link_libraries(${EXECUTABLE_NAME} PRIVATE OsxPpcEmuLib)
target_compile_definitions(${EXECUTABLE_NAME} PRIVATE $<$<BOOL:${DEBUGGER_ENABLED}>:DEBUGGER_ENABLED>)

include(CTest)
enable_testing()
add_subdirectory(test)
