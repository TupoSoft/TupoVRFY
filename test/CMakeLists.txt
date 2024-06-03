include(../cmake/project.cmake)

set(BASE_PROJECT_NAME ${PROJECT_NAME})
cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${PROJECT_NAME}_test VERSION ${PROJECT_VERSION})

# ---- Options ----

option(ENABLE_TEST_COVERAGE "Enable test coverage" OFF)
option(TEST_INSTALLED_VERSION "Test the version found by find_package" OFF)

CPMAddPackage("gh:google/googletest@1.14.0")

if (TEST_INSTALLED_VERSION)
    find_package(${BASE_PROJECT_NAME} REQUIRED)
else ()
    CPMAddPackage(NAME ${BASE_PROJECT_NAME} SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)
endif ()

enable_testing()

file(GLOB SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp)
add_executable(${PROJECT_NAME} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${BASE_PROJECT_NAME}::${BASE_PROJECT_NAME} GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(${PROJECT_NAME})

if (ENABLE_TEST_COVERAGE)
    target_compile_options(${BASE_PROJECT_NAME} PUBLIC -O0 -g -fprofile-arcs -ftest-coverage)
    target_link_options(${BASE_PROJECT_NAME} PUBLIC -fprofile-arcs -ftest-coverage)
endif ()
