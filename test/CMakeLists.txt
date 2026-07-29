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

add_executable(OsxPpcEmuTest src/test.cpp src/test_qsort.cpp src/test_bsearch.cpp src/test_mwobj_parser.cpp src/test_stack_layout.cpp src/test_import_table.cpp)
target_include_directories(OsxPpcEmuTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(OsxPpcEmuTest PRIVATE GTest::GTest OsxPpcEmuLib)

add_test(NAME OsxPpcEmuTestCommon COMMAND OsxPpcEmuTest --gtest_filter=Common.*)
add_test(NAME OsxPpcEmuTestQsort COMMAND OsxPpcEmuTest --gtest_filter=Qsort.*)
add_test(NAME OsxPpcEmuTestBsearch COMMAND OsxPpcEmuTest --gtest_filter=Bsearch.*)
add_test(NAME OsxPpcEmuTestMwobj COMMAND OsxPpcEmuTest --gtest_filter=MwObj*)
add_test(NAME OsxPpcEmuTestStack COMMAND OsxPpcEmuTest --gtest_filter=StackLayout.*)
add_test(NAME OsxPpcEmuTestImportTable COMMAND OsxPpcEmuTest --gtest_filter=ImportTable.*:EmuMemoryFixture.*)

add_executable(OsxPpcEmuE2E src/test_e2e_mwpefld.cpp src/test_e2e_mwpefcc.cpp)
target_include_directories(OsxPpcEmuE2E PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(OsxPpcEmuE2E PRIVATE GTest::GTest)
target_compile_definitions(OsxPpcEmuE2E PRIVATE "EMU_BINARY=\"$<TARGET_FILE:${EXECUTABLE_NAME}>\"")
add_dependencies(OsxPpcEmuE2E ${EXECUTABLE_NAME})

add_test(NAME E2E_CodeWarriorLinkFile1 COMMAND OsxPpcEmuE2E --gtest_filter=MwpefldE2E.CodeWarriorLinkFile1)
add_test(NAME E2E_CodeWarriorLinkFile2 COMMAND OsxPpcEmuE2E --gtest_filter=MwpefldE2E.CodeWarriorLinkFile2)
add_test(NAME E2E_CodeWarriorCompileFile1 COMMAND OsxPpcEmuE2E --gtest_filter=MwpefccE2E.CodeWarriorCompileFile1)
add_test(NAME E2E_CodeWarriorCompileFile2 COMMAND OsxPpcEmuE2E --gtest_filter=MwpefccE2E.CodeWarriorCompileFile2)
set_tests_properties(E2E_CodeWarriorLinkFile1 E2E_CodeWarriorLinkFile2 E2E_CodeWarriorCompileFile1 E2E_CodeWarriorCompileFile2
        PROPERTIES TIMEOUT 300)
