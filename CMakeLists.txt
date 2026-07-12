cmake_minimum_required(VERSION 3.16)
project(xair_sym VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(XAIR_SYM_STRICT_WARNINGS "Treat extended warnings as errors" OFF)
set(XAIR_SYM_Z3_ROOT "/home/jaden/.venvs/xair-angr-312/lib/python3.12/site-packages/z3" CACHE PATH "Z3 installation root")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/../cfg_project ${CMAKE_CURRENT_BINARY_DIR}/xair_cfg)

find_path(XAIR_SYM_Z3_INCLUDE z3.h HINTS ${XAIR_SYM_Z3_ROOT}/include REQUIRED)
find_library(XAIR_SYM_Z3_LIBRARY NAMES z3 libz3 HINTS ${XAIR_SYM_Z3_ROOT}/lib REQUIRED NO_DEFAULT_PATH)

add_library(xair_sym STATIC
    src/xair_sym_core.c
    src/xair_sym_memory.c
    src/xair_sym_taint.c
    src/xair_sym_concolic.c
    src/xair_sym_environment.c
    src/xair_sym_solver_z3.c
    src/xair_sym_exec.c
)
target_include_directories(xair_sym PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include PRIVATE ${XAIR_SYM_Z3_INCLUDE})
target_link_libraries(xair_sym PUBLIC xair_cfg PRIVATE ${XAIR_SYM_Z3_LIBRARY})

function(xair_sym_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4)
        if(XAIR_SYM_STRICT_WARNINGS)
            target_compile_options(${target} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        if(XAIR_SYM_STRICT_WARNINGS)
            target_compile_options(${target} PRIVATE -Wconversion -Wsign-conversion -Werror)
        endif()
    endif()
endfunction()
xair_sym_warnings(xair_sym)

enable_testing()
add_executable(xair_sym_tests tests/test_sym.c)
target_link_libraries(xair_sym_tests PRIVATE xair_sym)
xair_sym_warnings(xair_sym_tests)
add_test(NAME xair_sym_tests COMMAND xair_sym_tests)
