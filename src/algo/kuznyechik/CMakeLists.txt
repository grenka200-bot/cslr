find_package(GTest REQUIRED)
find_package(Threads REQUIRED)

add_executable(kuznyechik_tests kuznyechik_tests.cc)
target_include_directories(kuznyechik_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(kuznyechik_tests PRIVATE GTest::gtest GTest::gtest_main Threads::Threads)

