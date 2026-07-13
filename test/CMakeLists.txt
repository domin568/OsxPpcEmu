include(FetchContent)

add_compile_definitions(GTEST)

add_compile_definitions("TEST_FOLDER=\"${CMAKE_CURRENT_SOURCE_DIR}\"")

FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.17.0
)
FetchContent_MakeAvailable(googletest)
add_library(GTest::GTest INTERFACE IMPORTED)
target_link_libraries(GTest::GTest INTERFACE gtest_main)

add_executable(OsxPpcEmuTest src/test.cpp src/test_qsort.cpp src/test_bsearch.cpp)

target_link_libraries(OsxPpcEmuTest
        PRIVATE
        GTest::GTest
        OsxPpcEmuLib
)

add_test(NAME OsxPpcEmuGtests COMMAND OsxPpcEmuTest)

# ── End-to-end test: runs the built OsxPpcEmu binary as a subprocess to emulate
# mwpefld linking a PPC object file. Kept as a separate target/executable so the
# fast unit-test suite above is unaffected by it (it needs fixtures under
# test_files/e2e/ that may be absent — see MANIFEST.txt — and will self-skip).
add_executable(OsxPpcEmuE2E src/test_e2e_mwpefld.cpp)
target_include_directories(OsxPpcEmuE2E PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(OsxPpcEmuE2E PRIVATE GTest::GTest)
target_compile_definitions(OsxPpcEmuE2E PRIVATE "EMU_BINARY=\"$<TARGET_FILE:${EXECUTABLE_NAME}>\"")
add_dependencies(OsxPpcEmuE2E ${EXECUTABLE_NAME})

add_test(NAME E2E_mwpefld COMMAND OsxPpcEmuE2E)
set_tests_properties(E2E_mwpefld PROPERTIES TIMEOUT 300)
