cmake_minimum_required(VERSION 3.16)
project(cslr C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GMP REQUIRED IMPORTED_TARGET gmp)
pkg_check_modules(CJSON REQUIRED IMPORTED_TARGET libcjson)

# --- Основная утилита cslr ---
add_executable(cslr
    src/main.c
    src/storage.c
    src/algo/stribog/stribog.c
    src/algo/kuznyechik/kuznyechik.c
    src/algo/rsa/rsa.c
)

target_compile_definitions(cslr PRIVATE CSLR_RSA_NUM_PRIMES=8)

target_include_directories(cslr PRIVATE
    src
    src/algo/stribog
    src/algo/kuznyechik
    src/algo/rsa
)

target_link_libraries(cslr PRIVATE
    PkgConfig::GMP
    PkgConfig::CJSON
    Threads::Threads
)

# --- Юнит-тесты алгоритмов (GTest + CTest) ---
option(BUILD_TESTING "Собирать юнит-тесты криптоалгоритмов" ON)

if(BUILD_TESTING)
    enable_testing()

    add_subdirectory(src/algo/stribog)
    add_subdirectory(src/algo/kuznyechik)
    add_subdirectory(src/algo/rsa)

    add_test(NAME StreebogTests COMMAND stribog_tests)
    add_test(NAME KuznyechikTests COMMAND kuznyechik_tests)
    add_test(NAME RsaTests COMMAND rsa_tests)
endif()

