cmake_minimum_required(VERSION 3.16)
project(nativex86 VERSION 0.1.0 LANGUAGES C)

# Experimental skeleton: a plugin ABI, a host stub that loads one plugin,
# and a sample plugin. Not part of the JAR-recovery pipeline.

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_library(nativex86_abi INTERFACE)
target_include_directories(nativex86_abi
    INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MSVC)
    set(NX86_WARNINGS /W4)
else()
    set(NX86_WARNINGS -Wall -Wextra -Wpedantic)
endif()

add_executable(nx86_host
    src/host/main.c
    src/host/event_bus.c
    src/host/platform.c
)
target_include_directories(nx86_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/host)
target_link_libraries(nx86_host PRIVATE nativex86_abi ${CMAKE_DL_LIBS})
target_compile_options(nx86_host PRIVATE ${NX86_WARNINGS})

add_library(nx86_plugin_hello MODULE plugins/hello/hello.c)
target_link_libraries(nx86_plugin_hello PRIVATE nativex86_abi)
target_compile_options(nx86_plugin_hello PRIVATE ${NX86_WARNINGS})

# ABI contract checks: prefix negotiation and the lifecycle delivery
# window. Compiles the host event bus and the sample plugin directly so
# it can drive nx86_plugin_init at different capacities.
add_executable(nx86_abi_checks
    tests/abi_checks.c
    src/host/event_bus.c
    src/host/platform.c
    plugins/hello/hello.c
)
target_include_directories(nx86_abi_checks PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/host)
target_link_libraries(nx86_abi_checks PRIVATE nativex86_abi ${CMAKE_DL_LIBS})
target_compile_options(nx86_abi_checks PRIVATE ${NX86_WARNINGS})

enable_testing()
add_test(NAME abi_checks COMMAND nx86_abi_checks)
