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
    src/host/pe_exports.c
    src/host/observe_linux.c
    src/host/observe_windows.c
    src/host/observe_stub.c
)
target_include_directories(nx86_host PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/host)
target_link_libraries(nx86_host PRIVATE nativex86_abi ${CMAKE_DL_LIBS})
if(WIN32)
    target_link_libraries(nx86_host PRIVATE advapi32)
endif()
target_compile_options(nx86_host PRIVATE ${NX86_WARNINGS})

# Observation plugins. Each exports exactly one symbol; all knowledge of
# a library's export names lives here, never in the host.
function(nx86_add_plugin name source)
    add_library(${name} MODULE ${source})
    target_link_libraries(${name} PRIVATE nativex86_abi)
    target_compile_options(${name} PRIVATE ${NX86_WARNINGS})
endfunction()

nx86_add_plugin(nx86_plugin_hello          plugins/hello/hello.c)
nx86_add_plugin(nx86_plugin_crypto_openssl plugins/crypto-openssl/crypto_openssl.c)
nx86_add_plugin(nx86_plugin_jni_natives    plugins/jni-natives/jni_natives.c)
nx86_add_plugin(nx86_plugin_crypto_cng     plugins/crypto-cng/crypto_cng.c)

# Smoke-test fixture: a shared library whose exports are named like
# well-known crypto / JNI entries, and a tiny process that calls them in
# a loop. No real OpenSSL, no JVM, no jni.h. Exports must stay visible
# despite the project-wide hidden visibility preset.
add_library(nx86_fixture_exports SHARED tests/fixtures/fake_exports.c)
set_target_properties(nx86_fixture_exports PROPERTIES
    C_VISIBILITY_PRESET default)
target_compile_options(nx86_fixture_exports PRIVATE ${NX86_WARNINGS})

add_executable(nx86_fixture_target tests/fixtures/fixture_target.c)
target_link_libraries(nx86_fixture_target PRIVATE nx86_fixture_exports)
target_compile_options(nx86_fixture_target PRIVATE ${NX86_WARNINGS})

# A Linux multithreaded variant used to check the ptrace preview's
# single-thread-only policy. Windows has no live pass to exercise.
if(UNIX)
    find_package(Threads REQUIRED)
    add_executable(nx86_fixture_target_mt tests/fixtures/fixture_target_mt.c)
    target_link_libraries(nx86_fixture_target_mt
        PRIVATE nx86_fixture_exports Threads::Threads)
    target_compile_options(nx86_fixture_target_mt PRIVATE ${NX86_WARNINGS})
endif()

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

# White-box unit checks for live-engine internals (the unique-address
# restore planner and the entry/return alias guard). It compiles the engine
# source directly to reach its static helpers without a live target, so it
# only needs the event bus and platform shim to link.
add_executable(nx86_observe_unit
    tests/observe_unit.c
    src/host/event_bus.c
    src/host/platform.c
)
target_include_directories(nx86_observe_unit PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/host)
target_link_libraries(nx86_observe_unit PRIVATE nativex86_abi ${CMAKE_DL_LIBS})
target_compile_options(nx86_observe_unit PRIVATE ${NX86_WARNINGS})

# Cross-platform, file-only PE parser checks. The committed DLL fixture is
# opened as bytes and never loaded or executed.
add_executable(nx86_pe_exports_test
    tests/pe_exports_test.c
    src/host/pe_exports.c
)
target_include_directories(nx86_pe_exports_test
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/host)
target_link_libraries(nx86_pe_exports_test PRIVATE nativex86_abi)
target_compile_options(nx86_pe_exports_test PRIVATE ${NX86_WARNINGS})

enable_testing()
add_test(NAME abi_checks COMMAND nx86_abi_checks)
add_test(NAME observe_unit COMMAND nx86_observe_unit)
add_test(
    NAME pe_exports
    COMMAND nx86_pe_exports_test
            ${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/jni_registrar.dll
)
