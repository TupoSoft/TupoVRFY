include(../cmake/project.cmake)

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})

project(${STANDALONE_PROJECT_NAME} VERSION ${PROJECT_VERSION})

set(BOOST_INCLUDE_LIBRARIES "beast;url")
set(BOOST_SKIP_INSTALL_RULES OFF)
CPMAddPackage(
        NAME Boost
        VERSION 1.85.0
        URL https://github.com/boostorg/boost/releases/download/boost-1.85.0/boost-1.85.0-cmake.tar.xz
)
CPMAddPackage(
        GITHUB_REPOSITORY jarro2783/cxxopts
        VERSION 3.2.0
        OPTIONS "CXXOPTS_BUILD_EXAMPLES NO" "CXXOPTS_BUILD_TESTS NO" "CXXOPTS_ENABLE_INSTALL YES"
)
CPMAddPackage(NAME ${BASE_PROJECT_NAME} SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/..)

file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

add_executable(${PROJECT_NAME} ${HEADERS} ${SOURCES})
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAMESPACE}::${BASE_PROJECT_NAME} "boost_beast" "boost_url" cxxopts)
target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIRS})
