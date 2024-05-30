set(PROJECT_NAME "vrf")
set(CMAKE_MINIMUM_REQUIRED_VERSION 3.24)
set(PROJECT_DESCRIPTION "Email Verification")
set(PROJECT_VERSION 0.0.3.0)
set(CMAKE_PROJECT_HOMEPAGE_URL https://tuposoft.com)
set(CMAKE_CXX_STANDARD 23)

file(
        DOWNLOAD
        https://github.com/cpm-cmake/CPM.cmake/releases/download/v0.38.3/CPM.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake
        EXPECTED_HASH SHA256=cc155ce02e7945e7b8967ddfaff0b050e958a723ef7aad3766d368940cb15494
)
include(${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake)
