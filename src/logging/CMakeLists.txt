project(phantom_logging LANGUAGES CXX)

include_directories(
    ${PROJECT_SOURCE_DIR}/../../include
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/../../bindings/c
    ${PROJECT_BINARY_DIR}../../
)

# list of source files
set(libsrc
    ${PROJECT_SOURCE_DIR}/logger.cpp /
    ${PROJECT_SOURCE_DIR}/logger.hpp /
    ${PROJECT_SOURCE_DIR}/tracer.cpp /
    ${PROJECT_SOURCE_DIR}/tracer.hpp
)

# static object library
add_library(logging_obj OBJECT ${libsrc})

# shared object library
add_library(logging_shared_obj OBJECT ${libsrc})
set_property(TARGET logging_shared_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
