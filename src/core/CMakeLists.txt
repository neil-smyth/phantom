project(phantom_core LANGUAGES CXX)

include_directories(
    ${PROJECT_SOURCE_DIR}/../../include
    ${PROJECT_SOURCE_DIR}/
    ${PROJECT_SOURCE_DIR}/../../bindings/c
    ${PROJECT_BINARY_DIR}../../
)

# list of source files
set(libsrc
    ${PROJECT_SOURCE_DIR}/limbstring.cpp /
    ${PROJECT_SOURCE_DIR}/limbstring.hpp /
    ${PROJECT_SOURCE_DIR}/bit_manipulation.cpp /
    ${PROJECT_SOURCE_DIR}/bit_manipulation.hpp /
    ${PROJECT_SOURCE_DIR}/const_time_disabled.hpp /
    ${PROJECT_SOURCE_DIR}/const_time_enabled.hpp /
    ${PROJECT_SOURCE_DIR}/const_time.hpp /
    ${PROJECT_SOURCE_DIR}/gf2n.cpp /
    ${PROJECT_SOURCE_DIR}/gf2n.hpp /
    ${PROJECT_SOURCE_DIR}/gf256.cpp /
    ${PROJECT_SOURCE_DIR}/gf256.hpp /
    ${PROJECT_SOURCE_DIR}/mod_metadata.hpp /
    ${PROJECT_SOURCE_DIR}/mpbase.cpp /
    ${PROJECT_SOURCE_DIR}/mpbase_additive.cpp /
    ${PROJECT_SOURCE_DIR}/mpbase_division.cpp /
    ${PROJECT_SOURCE_DIR}/mpbase_exponentiation.cpp /
    ${PROJECT_SOURCE_DIR}/mpbase_jacobi.cpp /
    ${PROJECT_SOURCE_DIR}/mpbase_multiplication.cpp /
    ${PROJECT_SOURCE_DIR}/mpbase_redc.cpp /
    ${PROJECT_SOURCE_DIR}/mpbase_toom_cook.cpp /
    ${PROJECT_SOURCE_DIR}/mpbase.hpp /
    ${PROJECT_SOURCE_DIR}/mpz.cpp /
    ${PROJECT_SOURCE_DIR}/mpz.hpp /
    ${PROJECT_SOURCE_DIR}/mpz_control.cpp /
    ${PROJECT_SOURCE_DIR}/mpz_core.cpp /
    ${PROJECT_SOURCE_DIR}/mp_gf2n.hpp /
    ${PROJECT_SOURCE_DIR}/mp.hpp /
    ${PROJECT_SOURCE_DIR}/ntt_binary.cpp /
    ${PROJECT_SOURCE_DIR}/ntt_binary.hpp /
    ${PROJECT_SOURCE_DIR}/ntt.hpp /
    ${PROJECT_SOURCE_DIR}/number.cpp /
    ${PROJECT_SOURCE_DIR}/number.hpp /
    ${PROJECT_SOURCE_DIR}/poly.cpp /
    ${PROJECT_SOURCE_DIR}/poly.hpp /
    ${PROJECT_SOURCE_DIR}/reduction.hpp /
    ${PROJECT_SOURCE_DIR}/reduction_factory.hpp /
    ${PROJECT_SOURCE_DIR}/reduction_barrett.hpp /
    ${PROJECT_SOURCE_DIR}/reduction_montgomery.hpp /
    ${PROJECT_SOURCE_DIR}/reduction_reference.hpp /
    ${PROJECT_SOURCE_DIR}/scalar_parser.cpp /
    ${PROJECT_SOURCE_DIR}/scalar_parser.hpp /
    ${PROJECT_SOURCE_DIR}/small_primes.cpp /
    ${PROJECT_SOURCE_DIR}/small_primes.hpp
)

# static library
add_library(core_obj OBJECT ${libsrc})

# shared library
add_library(core_shared_obj OBJECT ${libsrc})
set_property(TARGET core_shared_obj PROPERTY POSITION_INDEPENDENT_CODE 1)
