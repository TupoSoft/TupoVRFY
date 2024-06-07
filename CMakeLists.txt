include(cmake/project.cmake)

cmake_minimum_required(VERSION ${CMAKE_MINIMUM_REQUIRED_VERSION})
project(${PROJECT_NAME} VERSION ${PROJECT_VERSION})

if (PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(
            FATAL_ERROR
            "In-source builds not allowed. Please make a new directory (called a build directory) and run CMake from there."
    )
endif ()

file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/source/*.cpp")

configure_file(config.h.in config.h @ONLY)
add_library(${PROJECT_NAME} ${HEADERS} ${SOURCES})

CPMAddPackage("gh:fmtlib/fmt#10.2.1")
CPMAddPackage("gh:c-ares/c-ares@1.30.0")

set(DEPENDENCIES "fmt" "c-ares")
if (WIN32)
    list(APPEND DEPENDENCIES "ws2_32" "dnsapi")
else ()
    list(APPEND DEPENDENCIES "resolv")
endif ()
target_link_libraries(${PROJECT_NAME} ${DEPENDENCIES})

set_target_properties(${PROJECT_NAME} PROPERTIES CXX_STANDARD 23)

# being a cross-platform target, we enforce standards conformance on MSVC
target_compile_options(${PROJECT_NAME} PUBLIC "$<$<COMPILE_LANG_AND_ID:CXX,MSVC>:/permissive->")
target_include_directories(${PROJECT_NAME} PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

# ---- Create an installable target ----
# this allows users to install and find the library via `find_package()`.

# the location where the project's version header will be placed should match the project's regular
# header paths
string(TOLOWER ${PROJECT_NAME}/version.h VERSION_HEADER_LOCATION)

CPMAddPackage("gh:TheLartians/PackageProject.cmake@1.11.2")

packageProject(
        NAME ${PROJECT_NAME}
        VERSION ${PROJECT_VERSION}
        NAMESPACE ${PROJECT_NAME}
        BINARY_DIR ${PROJECT_BINARY_DIR}
        INCLUDE_DIR ${PROJECT_SOURCE_DIR}/include
        INCLUDE_DESTINATION include/${PROJECT_NAME}-${PROJECT_VERSION}
        VERSION_HEADER "${VERSION_HEADER_LOCATION}"
        COMPATIBILITY SameMajorVersion
        DEPENDENCIES ${DEPENDENCIES}
)
