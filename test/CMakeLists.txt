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

add_executable(OsxPpcEmuTest src/test.cpp src/test_qsort.cpp src/test_bsearch.cpp src/test_mwobj_parser.cpp src/test_stack_layout.cpp src/test_import_table.cpp src/test_heap.cpp)
target_include_directories(OsxPpcEmuTest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(OsxPpcEmuTest PRIVATE GTest::GTest OsxPpcEmuLib)

add_test(NAME OsxPpcEmuTestCommon COMMAND OsxPpcEmuTest --gtest_filter=Common.*)
add_test(NAME OsxPpcEmuTestQsort COMMAND OsxPpcEmuTest --gtest_filter=Qsort.*)
add_test(NAME OsxPpcEmuTestBsearch COMMAND OsxPpcEmuTest --gtest_filter=Bsearch.*)
add_test(NAME OsxPpcEmuTestMwobj COMMAND OsxPpcEmuTest --gtest_filter=MwObj*)
add_test(NAME OsxPpcEmuTestStack COMMAND OsxPpcEmuTest --gtest_filter=StackLayout.*)
add_test(NAME OsxPpcEmuTestImportTable COMMAND OsxPpcEmuTest --gtest_filter=ImportTable.*:EmuMemoryFixture.*)
add_test(NAME OsxPpcEmuTestHeap COMMAND OsxPpcEmuTest --gtest_filter=HeapFixture.*)

add_executable(OsxPpcEmuE2E src/test_e2e_mwpefld.cpp src/test_e2e_mwpefcc.cpp)
target_include_directories(OsxPpcEmuE2E PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(OsxPpcEmuE2E PRIVATE GTest::GTest)
target_compile_definitions(OsxPpcEmuE2E PRIVATE "EMU_BINARY=\"$<TARGET_FILE:${EXECUTABLE_NAME}>\"")
add_dependencies(OsxPpcEmuE2E ${EXECUTABLE_NAME})

add_test(NAME E2E_CodeWarriorLinkFile1 COMMAND OsxPpcEmuE2E --gtest_filter=MwpefldE2E.CodeWarriorLinkFile1)
add_test(NAME E2E_CodeWarriorLinkCMathIOstream COMMAND OsxPpcEmuE2E --gtest_filter=MwpefldE2E.CodeWarriorLinkCMathIOstream)
add_test(NAME E2E_CodeWarriorLinkSimpleMath COMMAND OsxPpcEmuE2E --gtest_filter=MwpefldE2E.CodeWarriorLinkSimpleMath)
add_test(NAME E2E_CodeWarriorCompileSimple COMMAND OsxPpcEmuE2E --gtest_filter=MwpefccE2E.CodeWarriorCompileSimple)
add_test(NAME E2E_CodeWarriorCompileCMathIOStream COMMAND OsxPpcEmuE2E --gtest_filter=MwpefccE2E.CodeWarriorCompileCMathIOStream)
#add_test(NAME E2E_CodeWarriorCompileCMathIOStreamO2 COMMAND OsxPpcEmuE2E --gtest_filter=MwpefccE2E.CodeWarriorCompileCMathIOStreamO2)
#add_test(NAME E2E_CodeWarriorCompileCMathIOStreamO3 COMMAND OsxPpcEmuE2E --gtest_filter=MwpefccE2E.CodeWarriorCompileCMathIOStreamO3)
#add_test(NAME E2E_CodeWarriorCompileCMathIOStreamO4 COMMAND OsxPpcEmuE2E --gtest_filter=MwpefccE2E.CodeWarriorCompileCMathIOStreamO4)
add_test(NAME E2E_CodeWarriorCompileInterfaceLib COMMAND OsxPpcEmuE2E --gtest_filter=MwpefccE2E.CodeWarriorCompileInterfaceLib)
add_test(NAME E2E_CodeWarriorLinkInterfaceLib COMMAND OsxPpcEmuE2E --gtest_filter=MwpefldE2E.CodeWarriorLinkInterfaceLib)

add_test(NAME E2E_CodeWarriorCompileSimpleMath COMMAND OsxPpcEmuE2E --gtest_filter=MwpefccE2E.CodeWarriorCompileSimpleMath)
add_test(NAME E2E_CodeWarriorCompilePolymorphic COMMAND OsxPpcEmuE2E --gtest_filter=MwpefccE2E.CodeWarriorCompilePolymorphic)
set_tests_properties(
        E2E_CodeWarriorLinkFile1
        E2E_CodeWarriorLinkCMathIOstream
        E2E_CodeWarriorCompileSimple
        E2E_CodeWarriorCompileCMathIOStream
        #E2E_CodeWarriorCompileCMathIOStreamO2
        #E2E_CodeWarriorCompileCMathIOStreamO3
        #E2E_CodeWarriorCompileCMathIOStreamO4
        E2E_CodeWarriorCompileSimpleMath
        E2E_CodeWarriorCompilePolymorphic
        E2E_CodeWarriorCompileInterfaceLib
        E2E_CodeWarriorLinkSimpleMath
        E2E_CodeWarriorLinkInterfaceLib
        PROPERTIES TIMEOUT 30)
