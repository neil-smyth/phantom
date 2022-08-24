project(phantom_sampling LANGUAGES CXX)

include_directories(
    ${PROJECT_SOURCE_DIR}/../../include
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/../../bindings/c
    ${PROJECT_BINARY_DIR}../../
)

# list of source files
set(libsrc
    ${PROJECT_SOURCE_DIR}/gaussian.hpp /
    ${PROJECT_SOURCE_DIR}/gaussian_cdf.hpp /
    ${PROJECT_SOURCE_DIR}/gaussian_sampler.cpp /
    ${PROJECT_SOURCE_DIR}/gaussian_sampler.hpp /
    ${PROJECT_SOURCE_DIR}/uniform_sampler.hpp)

# static library
add_library(sampling_obj OBJECT ${libsrc})

# shared library
add_library(sampling_shared_obj OBJECT ${libsrc})
set_property(TARGET sampling_shared_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
