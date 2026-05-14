cmake_minimum_required(VERSION 3.16)
project(j2c_dumper_agent VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

find_package(JNI REQUIRED)

add_library(j2c_agent SHARED
    src/agent.cpp
    src/trace_writer.cpp
    src/jni_hook.cpp
)

target_include_directories(j2c_agent PRIVATE
    ${JNI_INCLUDE_DIRS}
    include
)

if(MSVC)
    target_compile_options(j2c_agent PRIVATE /W3 /EHsc)
else()
    target_compile_options(j2c_agent PRIVATE -Wall -Wextra -O2)
endif()

if(WIN32)
    set_target_properties(j2c_agent PROPERTIES OUTPUT_NAME "j2c_agent")
else()
    set_target_properties(j2c_agent PROPERTIES OUTPUT_NAME "j2c_agent")
endif()
