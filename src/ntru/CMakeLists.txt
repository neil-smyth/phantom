project(phantom_ntru LANGUAGES CXX)

include_directories(
    ${PROJECT_SOURCE_DIR}/../../include
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/../../bindings/c
    ${PROJECT_BINARY_DIR}../../
)

# list of source files
set(libsrc
    ${PROJECT_SOURCE_DIR}/ldl.cpp /
    ${PROJECT_SOURCE_DIR}/ldl.hpp /
    ${PROJECT_SOURCE_DIR}/ntru.cpp /
    ${PROJECT_SOURCE_DIR}/ntru.hpp /
    ${PROJECT_SOURCE_DIR}/ntru_number.hpp /
    ${PROJECT_SOURCE_DIR}/ntru_master_tree.hpp /
    ${PROJECT_SOURCE_DIR}/ntru_master_tree.cpp
)

# static library
add_library(ntru_obj OBJECT ${libsrc})

# shared library
add_library(ntru_shared_obj OBJECT ${libsrc})
set_property(TARGET ntru_shared_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
