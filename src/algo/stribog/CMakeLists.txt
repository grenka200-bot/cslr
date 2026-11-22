find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

add_executable(stribog_tests stribog_tests.cc)
target_include_directories(stribog_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(stribog_tests PRIVATE GTest::gtest GTest::gtest_main Threads::Threads)

