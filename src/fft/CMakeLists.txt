project(phantom_fft LANGUAGES CXX)

include_directories(
    ${PROJECT_SOURCE_DIR}/../../include
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/../../bindings/c
    ${PROJECT_BINARY_DIR}../../
)

# list of source files
set(libsrc
    ${PROJECT_SOURCE_DIR}/fft.cpp /
    ${PROJECT_SOURCE_DIR}/fft.hpp /
    ${PROJECT_SOURCE_DIR}/fft_poly.hpp
)

# static library
add_library(fft_obj OBJECT ${libsrc})

# shared library
add_library(fft_shared_obj OBJECT ${libsrc})
set_property(TARGET fft_shared_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
