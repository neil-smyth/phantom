project(phantom_ecc LANGUAGES CXX)

include_directories(
    ${PROJECT_SOURCE_DIR}/../../include
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/../../bindings/c
    ${PROJECT_BINARY_DIR}../../
)

# list of source files
set(libsrc
    ${PROJECT_SOURCE_DIR}/curves.cpp /
    ${PROJECT_SOURCE_DIR}/curves.hpp /
    ${PROJECT_SOURCE_DIR}/point.hpp /
    ${PROJECT_SOURCE_DIR}/prime_point.cpp /
    ${PROJECT_SOURCE_DIR}/weierstrass_prime_affine.hpp /
    ${PROJECT_SOURCE_DIR}/weierstrass_prime_jacobian.hpp /
    ${PROJECT_SOURCE_DIR}/weierstrass_prime_projective.hpp /
    ${PROJECT_SOURCE_DIR}/ecc.hpp
)

# static library
add_library(ecc_obj OBJECT ${libsrc})

# shared library
add_library(ecc_shared_obj OBJECT ${libsrc})
set_property(TARGET ecc_shared_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
