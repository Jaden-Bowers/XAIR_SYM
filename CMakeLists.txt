cmake_minimum_required(VERSION 3.16)
project(xair_sym VERSION 0.5.0 LANGUAGES C CXX)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../xair/cmake/XAIRCommon.cmake")
    include("${CMAKE_CURRENT_SOURCE_DIR}/../xair/cmake/XAIRCommon.cmake")
else()
    message(FATAL_ERROR "xair_sym requires sibling xair and xair_cfg checkouts")
endif()
include(GNUInstallDirs)
include(CTest)
include(CMakePackageConfigHelpers)

if(NOT TARGET xair_cfg)
    set(XAIR_BUILD_ALL OFF CACHE BOOL "" FORCE)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../xair_cfg" "${CMAKE_CURRENT_BINARY_DIR}/xair_cfg")
endif()

set(XAIR_Z3_SOURCE_ROOT "" CACHE PATH "Optional path to a Z3 source checkout")
if(NOT TARGET libz3 AND NOT TARGET z3::libz3)
    set(Z3_BUILD_LIBZ3_SHARED OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_EXECUTABLE OFF CACHE BOOL "" FORCE)
    set(Z3_BUILD_TEST_EXECUTABLES OFF CACHE BOOL "" FORCE)
    set(Z3_ENABLE_EXAMPLE_TARGETS OFF CACHE BOOL "" FORCE)
    if(XAIR_Z3_SOURCE_ROOT AND EXISTS "${XAIR_Z3_SOURCE_ROOT}/CMakeLists.txt")
        add_subdirectory("${XAIR_Z3_SOURCE_ROOT}" "${CMAKE_CURRENT_BINARY_DIR}/z3" EXCLUDE_FROM_ALL)
    else()
        include(FetchContent)
        FetchContent_Declare(z3
            GIT_REPOSITORY https://github.com/Z3Prover/z3.git
            GIT_TAG z3-5.0.0
            GIT_SHALLOW TRUE)
        FetchContent_MakeAvailable(z3)
    endif()
endif()

if(TARGET libz3)
    set(XAIR_Z3_TARGET libz3)
elseif(TARGET z3::libz3)
    set(XAIR_Z3_TARGET z3::libz3)
else()
    message(FATAL_ERROR "The pinned Z3 source build did not provide a static libz3 target")
endif()

add_library(xair_sym STATIC
    src/xair_sym_core.c
    src/xair_sym_memory.c
    src/xair_sym_taint.c
    src/xair_sym_concolic.c
    src/xair_sym_environment.c
    src/xair_sym_program.c
    src/xair_sym_snapshot.c
    src/xair_sym_parallel.c
    src/xair_sym_solver_z3.c
    src/xair_sym_exec.c
)
target_include_directories(xair_sym PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
add_library(XAIR::sym ALIAS xair_sym)
set_target_properties(xair_sym PROPERTIES EXPORT_NAME sym)
find_package(Threads REQUIRED)
target_link_libraries(xair_sym PUBLIC xair_cfg PRIVATE ${XAIR_Z3_TARGET} Threads::Threads)
xair_apply_warnings(xair_sym)

if(BUILD_TESTING AND XAIR_BUILD_TESTS)
add_executable(xair_sym_tests tests/test_sym.c)
target_link_libraries(xair_sym_tests PRIVATE xair_sym)
xair_apply_warnings(xair_sym_tests)
xair_keep_asserts(xair_sym_tests)
add_test(NAME xair_sym_tests COMMAND xair_sym_tests)
endif()

install(TARGETS xair_sym EXPORT XAIRSymTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT XAIRSymTargets NAMESPACE XAIR:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/XAIRSym)
configure_package_config_file(
    cmake/XAIRSymConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/XAIRSymConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/XAIRSym)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/XAIRSymConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/XAIRSymConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/XAIRSymConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/XAIRSym)
