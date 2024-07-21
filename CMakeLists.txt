include(cmake/project.cmake)

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${BASE_PROJECT_NAME} VERSION ${PROJECT_VERSION})

if (PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(
            FATAL_ERROR
            "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there."
    )
endif ()

file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

add_library(${PROJECT_NAME} ${HEADERS} ${SOURCES})

CPMAddPackage("gh:fmtlib/fmt#10.2.1")
CPMAddPackage("gh:Tuposoft/TupoResolv#b6470ef26b6ef8033a50fd247b78dafe5ffc1048")

set(BOOST_INCLUDE_LIBRARIES "asio")
set(BOOST_SKIP_INSTALL_RULES OFF)
CPMAddPackage(
        NAME Boost
        VERSION 1.85.0
        URL https://github.com/boostorg/boost/releases/download/boost-1.85.0/boost-1.85.0-cmake.tar.xz
)

set(DEPENDENCIES "fmt::fmt" "boost_asio" "tuporesolv")
if (WIN32)
    add_definitions(-D_WIN32_WINNT=0x0A00)
    list(APPEND DEPENDENCIES "ws2_32")
endif ()

target_compile_options(${PROJECT_NAME} PUBLIC "$<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/permissive->")
target_link_libraries(${PROJECT_NAME} PUBLIC ${DEPENDENCIES})
target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIRS} $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

CPMAddPackage("gh:TheLartians/PackageProject.cmake@1.11.2")

packageProject(
        NAME ${PROJECT_NAME}
        VERSION ${PROJECT_VERSION}
        NAMESPACE ${PROJECT_NAMESPACE}
        BINARY_DIR ${PROJECT_BINARY_DIR}
        INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include
        INCLUDE_DESTINATION include/${PROJECT_NAME}-${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
)
