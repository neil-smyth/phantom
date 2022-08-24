project(phantom_packing LANGUAGES CXX)

include_directories(
    ${PROJECT_SOURCE_DIR}/../../include
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/../../bindings/c
    ${PROJECT_BINARY_DIR}../../
)

# list of source files
set(libsrc
    ${PROJECT_SOURCE_DIR}/stream.cpp /
    ${PROJECT_SOURCE_DIR}/stream.hpp /
    ${PROJECT_SOURCE_DIR}/packer.cpp /
    ${PROJECT_SOURCE_DIR}/packer.hpp /
    ${PROJECT_SOURCE_DIR}/unpacker.cpp /
    ${PROJECT_SOURCE_DIR}/unpacker.hpp
)

# static library
add_library(packing_obj OBJECT ${libsrc})

# shared library
add_library(packing_shared_obj OBJECT ${libsrc})
set_property(TARGET packing_shared_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
