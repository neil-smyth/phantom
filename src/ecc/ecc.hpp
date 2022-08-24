/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <cmath>
#include <iomanip>
#include <limits>
#include <memory>
#include <vector>

#include "ecc/point.hpp"
#include "ecc/prime_point.hpp"
#include "ecc/weierstrass_prime_affine.hpp"
#include "ecc/weierstrass_prime_jacobian.hpp"
#include "ecc/weierstrass_prime_projective.hpp"
#include "ecc/binary_point.hpp"
#include "ecc/weierstrass_binary_affine.hpp"
#include "ecc/weierstrass_binary_projective.hpp"
#include "ecc/weierstrass_binary_jacobian.hpp"
#include "ecc/montgomery_prime_affine.hpp"
#include "ecc/montgomery_prime_projective.hpp"
#include "ecc/edwards_prime_affine.hpp"
#include "ecc/edwards_prime_projective.hpp"
#include "core/scalar_parser.hpp"
#include "core/template_helpers.hpp"


namespace phantom {
namespace elliptic {

/** 
 * @brief Elliptic Curve Cryptography
 * A facade for the various elliptic curve types and coordinate systems
 */
template<typename T>
class ecc
{
    static const size_t pre_width = 8;

    /**
     * @brief A helper method that generates pre-computed points for a particular coding type
     * and coordinate system
     * @tparam P A class derived from the point class
     */
    template<template<class TP> class P>
    void create_points()
    {
        m_point        = std::unique_ptr<point<T>>(new P<T>(m_config));
        m_point_pre[0] = std::unique_ptr<point<T>>(new P<T>(m_config));

        switch (m_coding_type)
        {
            case core::scalar_coding_e::ECC_BINARY_DUAL:
            {
                m_point_pre[1] = std::unique_ptr<point<T>>(new P<T>(m_config));
                m_point_pre[2] = std::unique_ptr<point<T>>(new P<T>(m_config));
            } break;

            case core::scalar_coding_e::ECC_NAF_2:
            case core::scalar_coding_e::ECC_NAF_3:
            case core::scalar_coding_e::ECC_NAF_4:
            case core::scalar_coding_e::ECC_NAF_5:
            case core::scalar_coding_e::ECC_NAF_6:
            case core::scalar_coding_e::ECC_NAF_7:
            {
                size_t w = (1 << ((static_cast<size_t>(m_coding_type) ^ SCALAR_CODING_NAF_BIT) - 1)) - 1;

                for (size_t i=1; i < 2*w; i++) {
                    m_point_pre[i] = std::unique_ptr<point<T>>(new P<T>(m_config));
                }
            } break;

            case core::scalar_coding_e::ECC_PRE_2:
            case core::scalar_coding_e::ECC_PRE_3:
            case core::scalar_coding_e::ECC_PRE_4:
            case core::scalar_coding_e::ECC_PRE_5:
            case core::scalar_coding_e::ECC_PRE_6:
            case core::scalar_coding_e::ECC_PRE_7:
            case core::scalar_coding_e::ECC_PRE_8:
            {
                size_t w = (1 << (static_cast<size_t>(m_coding_type) ^ SCALAR_CODING_PRE_BIT));

                for (size_t i=1; i < w; i++) {
                    m_point_pre[i] = std::unique_ptr<point<T>>(new P<T>(m_config));
                }
            } break;

            default: {}
        }
    }

protected:
    const ecc_config<T> m_config;
    const field_e m_field;
    const type_e m_coord_type;
    const core::scalar_coding_e m_coding_type;
    const bool m_masking;
    bool m_result_is_valid;
    std::unique_ptr<point<T>> m_point;
    std::unique_ptr<point<T>> m_point_pre[1 << pre_width];

public:
    /**
     * @brief Construct a new ecc object
     * @param cfg AN ecc_config object defining how ECC is configured
     * @param field The type of field to be used (default: WEIERSTRASS_PRIME_FIELD)
     * @param coord_type The coordinate system to be used (default: POINT_COORD_AFFINE)
     * @param coding The scalar coding method to be used (default: ECC_BINARY)
     * @param masking A flag to indicate if double-and-add masking is required (default: true)
     */
    ecc(const ecc_config<T>& cfg,
        field_e field = WEIERSTRASS_PRIME_FIELD,
        type_e coord_type = POINT_COORD_AFFINE,
        core::scalar_coding_e coding = core::scalar_coding_e::ECC_BINARY,
        bool masking = true) :
        m_config(cfg),
        m_field(field),
        m_coord_type(coord_type),
        m_coding_type(coding),
        m_masking(masking)
    {
        m_result_is_valid = false;

        switch (m_field)
        {
        case WEIERSTRASS_PRIME_FIELD:
            switch (m_coord_type)
            {
            case POINT_COORD_AFFINE:     create_points<weierstrass_prime_affine>();      break;
            case POINT_COORD_PROJECTIVE: create_points<weierstrass_prime_projective>();  break;
            case POINT_COORD_JACOBIAN:   create_points<weierstrass_prime_jacobian>();    break;
            default:                     {}
            }
            break;

        case WEIERSTRASS_BINARY_FIELD:
            switch (m_coord_type)
            {
            case POINT_COORD_AFFINE:     create_points<weierstrass_binary_affine>();     break;
            case POINT_COORD_PROJECTIVE: create_points<weierstrass_binary_projective>(); break;
            case POINT_COORD_JACOBIAN:   create_points<weierstrass_binary_jacobian>();   break;
            default:                     {}
            }
            break;

        case MONTGOMERY_PRIME_FIELD:
            switch (m_coord_type)
            {
            case POINT_COORD_AFFINE:     create_points<montgomery_prime_affine>();       break;
            case POINT_COORD_PROJECTIVE: create_points<montgomery_prime_projective>();   break;
            default:                     {}
            }
            break;

        case EDWARDS_PRIME_FIELD:
            switch (m_coord_type)
            {
            case POINT_COORD_AFFINE:     create_points<edwards_prime_affine>();          break;
            case POINT_COORD_PROJECTIVE: create_points<edwards_prime_projective>();      break;
            default:                     {}
            }
            break;

        default: {}
        }
    }

    virtual ~ecc() {}

    /**
     * @brief Get the Cartesian coordinates (x,y) of the current point
     * @param x X coordinate
     * @param y Y coordinate
     * @return retcode_e POINT_OK if success, SCALAR_MUL_ERROR if point multiplication was a failure
     */
    retcode_e get(core::mp<T>* x, core::mp<T>* y)
    {
        if (m_result_is_valid) {
            return m_point->convert_from(m_config, x, y);
        }
        else {
            return SCALAR_MUL_ERROR;
        }
    }

    /**
     * @brief Return POINT_OK if the scalar point multiplication was a success
     */
    retcode_e is_valid() const
    {
        return m_result_is_valid ? POINT_OK : SCALAR_MUL_ERROR;
    }

    /**
     * @brief Get the point object
     */
    const point<T>* get_point() const
    {
        return m_point.get();
    }

    /**
     * @brief Setup of pre-computed points for base point represented by primes p and q
     * @param p Base point
     * @return retcode_e Returns POINT_OK if successful
     */
    retcode_e setup(const point<T>& p, const point<T>& q)
    {
        const prime_point<T>& prime = reinterpret_cast<const prime_point<T>&>(q);
        m_point_pre[1]->copy(prime);

        return setup(p);
    }

    /**
     * @brief Setup of pre-computed points for base point p
     * @param p Base point
     * @return retcode_e Returns POINT_OK if successful
     */
    retcode_e setup(const point<T>& p)
    {
        // Pre-computation
        switch (m_field)
        {
        case field_e::WEIERSTRASS_PRIME_FIELD:
        case field_e::MONTGOMERY_PRIME_FIELD:
        case field_e::EDWARDS_PRIME_FIELD:
            {
                const prime_point<T>& prime = reinterpret_cast<const prime_point<T>&>(p);
                m_point_pre[0]->copy(prime);
            } break;

        case field_e::WEIERSTRASS_BINARY_FIELD:
            {
                const binary_point<T>& binary = reinterpret_cast<const binary_point<T>&>(p);
                m_point_pre[0]->copy(binary);
            } break;

        default: {}
        }

        switch (m_coding_type)
        {
            case core::scalar_coding_e::ECC_BINARY_DUAL:
            {
                m_point_pre[2]->copy(*m_point_pre[0].get());
                if (POINT_OK != m_point_pre[2]->addition(m_config, *m_point_pre[1].get())) {
                    return POINT_ERROR;
                }
            } break;

            case core::scalar_coding_e::ECC_NAF_2:
            case core::scalar_coding_e::ECC_NAF_3:
            case core::scalar_coding_e::ECC_NAF_4:
            case core::scalar_coding_e::ECC_NAF_5:
            case core::scalar_coding_e::ECC_NAF_6:
            case core::scalar_coding_e::ECC_NAF_7:
            {
                size_t w = static_cast<size_t>(m_coding_type) ^ SCALAR_CODING_NAF_BIT;
                size_t r = (1 << (w - 1)) - 1;

                for (size_t i=1; i < r; i++) {
                    m_point_pre[i]->copy(*m_point_pre[i-1].get());
                    if (POINT_OK != m_point_pre[i]->addition(m_config, *m_point_pre[0].get())) {
                        return POINT_ERROR;
                    }
                }

                for (size_t i=r; i < r+r; i++) {
                    m_point_pre[i]->copy(*m_point_pre[i-r].get());
                    m_point_pre[i]->negate(m_config);
                }

                // Converting to mixed is too expensive
            } break;

            case core::scalar_coding_e::ECC_PRE_2:
            case core::scalar_coding_e::ECC_PRE_3:
            case core::scalar_coding_e::ECC_PRE_4:
            case core::scalar_coding_e::ECC_PRE_5:
            case core::scalar_coding_e::ECC_PRE_6:
            case core::scalar_coding_e::ECC_PRE_7:
            case core::scalar_coding_e::ECC_PRE_8:
            {
                size_t w = static_cast<size_t>(m_coding_type) ^ SCALAR_CODING_PRE_BIT;
                size_t r = 1 << w;

                m_point_pre[1]->copy(*m_point_pre[0].get());
                if (POINT_OK != m_point_pre[1]->doubling(m_config, 1)) {
                    return POINT_ERROR;
                }

                for (size_t i=2; i < r; i++) {
                    m_point_pre[i]->copy(*m_point_pre[i-1].get());
                    if (POINT_OK != m_point_pre[i]->addition(m_config, *m_point_pre[0].get())) {
                        return POINT_ERROR;
                    }
                }
            } break;

            default: {}
        }

        return POINT_OK;
    }

    /**
     * @brief Scalar point multiplication
     * @param secret A byte vector representing the scalar value
     * @return retcode_e Returns POINT_OK if successful
     */
    retcode_e scalar_point_mul(const phantom_vector<uint8_t>& secret)
    {
        m_result_is_valid = false;

        // A flag to indicate if a windowed mode is to be used and the window size
        size_t w = 1;
        bool is_windowed = (m_coding_type & SCALAR_CODING_PRE_BIT);
        if (is_windowed) {
            w = static_cast<size_t>(m_coding_type & 0x3f);
        }

        // Recode the integer as required
        core::scalar_parser bitgen(m_coding_type, secret);
        size_t num_bits = bitgen.num_symbols();
        if (0 == num_bits) {
            std::cerr << "!!! SECRET_IS_ZERO" << std::endl;
            return SECRET_IS_ZERO;
        }

        // Pull the first encoded bit and ensure it is asserted
        num_bits--;
        uint32_t bit = bitgen.pull();
        if (SCALAR_IS_LOW == bit) {
            std::cerr << "!!! RECODING_ERROR" << std::endl;
            return RECODING_ERROR;
        }

        size_t sub_offset = 0;
        if (core::scalar_coding_e::ECC_NAF_2 <= m_coding_type && core::scalar_coding_e::ECC_NAF_7 >= m_coding_type) {
            sub_offset = (1 << ((static_cast<size_t>(m_coding_type) & 0x3f) - 1)) - 2;
        }

        retcode_e retcode;
        if (core::ECC_MONT_LADDER == m_coding_type) {
            if (POINT_OK != (retcode = montgomery_ladder(bitgen, num_bits, w, bit, sub_offset))) {
                std::cerr << "!!! montgomery_ladder() failed" << std::endl;
                return retcode;
            }
        }
        else if (m_masking) {
            if (POINT_OK != (retcode = double_and_add(bitgen, num_bits, w, bit, sub_offset))) {
                std::cerr << "!!! double_and_add() failed" << std::endl;
                return retcode;
            }
        }
        else {
            if (POINT_OK != (retcode = double_and_add_unmasked(bitgen, num_bits, w, bit, sub_offset))) {
                std::cerr << "!!! double_and_add_unmasked() failed" << std::endl;
                return retcode;
            }
        }

        m_result_is_valid = true;
        return POINT_OK;
    }

    /**
     * @brief Double-and-add algorithm with no masking of operations
     * @param bitgen A reference to the scalar_parser object used to encode the scalar
     * @param num_bits The number of bits in the encoded scalar
     * @param w The window size
     * @param bit The first bit to be pulled the encoded scalar
     * @param sub_offset An offset to negative pre-computed points
     * @return retcode_e Returns POINT_OK if successful
     */
    retcode_e double_and_add_unmasked(core::scalar_parser& bitgen, size_t num_bits,
        size_t w, uint32_t bit, size_t sub_offset)
    {
        // Set the initial point according to the encoding - it is guaranteed to be positive non-zero
        m_point->copy(*m_point_pre[(bit - 1) & ((1 << (static_cast<size_t>(m_coding_type) & 0x3f)) - 1)].get());

        retcode_e retcode;

        while (num_bits--) {

            // Point doubling on each iteration
            if (POINT_OK != (retcode = m_point->doubling(m_config, w))) {
                return retcode;
            }

            // Obtain the next integer bit to be encoded
            bit = bitgen.pull();

            // Decode the bit to determine the operation to be performed
            bool subtract = bit & SCALAR_IS_SUBTRACT;
            bool is_zero  = bit == SCALAR_IS_LOW;
            bit &= 0xff;
            T pre_idx  = is_zero? 0 : subtract? 0 : (bit - 1) & 0xff;
            T sub_idx  = (is_zero? 0 : subtract? bit & 0xff : 0) + sub_offset;

            // Determine the point to be added
            intptr_t mask, p_a, p_b;
            mask = -intptr_t(subtract);
            p_b  = intptr_t(m_point_pre[pre_idx].get()) ^
                   ((intptr_t(m_point_pre[pre_idx].get()) ^ intptr_t(m_point_pre[sub_idx].get())) & mask);
            point<T>* point_b = reinterpret_cast<point<T>*>(p_b);

            // If masking is disabled then only non-zero integer bits are subjected to point addition,
            // otherwise masking is enabled then point addition is always performed
            if (!is_zero) {
                if (POINT_OK != (retcode = m_point->addition(m_config, *point_b))) {
                    return retcode;
                }
            }
        }

        m_result_is_valid = true;
        return POINT_OK;
    }

    /**
     * @brief Double-and-add algorithm
     * @param bitgen A reference to the scalar_parser object used to encode the scalar
     * @param num_bits The number of bits in the encoded scalar
     * @param w The window size
     * @param bit The first bit to be pulled the encoded scalar
     * @param sub_offset An offset to negative pre-computed points
     * @return retcode_e Returns POINT_OK if successful
     */
    retcode_e double_and_add(core::scalar_parser& bitgen, size_t num_bits, size_t w, uint32_t bit, size_t sub_offset)
    {
        // Set the initial point according to the encoding - it is guaranteed to be positive non-zero
        m_point->copy(*m_point_pre[(bit - 1) & ((1 << (static_cast<size_t>(m_coding_type) & 0x3f)) - 1)].get());

        std::unique_ptr<point<T>> zero;
        switch (m_field)
        {
            case WEIERSTRASS_PRIME_FIELD:
                zero = std::unique_ptr<point<T>>(new weierstrass_prime_affine<T>(m_config));
                break;
            case WEIERSTRASS_BINARY_FIELD:
                zero = std::unique_ptr<point<T>>(new weierstrass_binary_affine<T>(m_config));
                break;
            case MONTGOMERY_PRIME_FIELD:
                zero = std::unique_ptr<point<T>>(new montgomery_prime_affine<T>(m_config));
                break;
            case EDWARDS_PRIME_FIELD:
                zero = std::unique_ptr<point<T>>(new edwards_prime_affine<T>(m_config));
                break;
            default: {}
        }

        retcode_e retcode;

        while (num_bits--) {

            // Point doubling on each iteration
            if (POINT_OK != (retcode = m_point->doubling(m_config, w))) {
                return retcode;
            }

            // Obtain the next integer bit to be encoded
            bit = bitgen.pull();

            // Decode the bit to determine the operation to be performed
            bool subtract = bit & SCALAR_IS_SUBTRACT;
            bool is_zero  = bit == SCALAR_IS_LOW;
            bit &= 0xff;
            T pre_idx  = is_zero? 0 : subtract? 0 : (bit - 1) & 0xff;
            T sub_idx  = (is_zero? 0 : subtract? bit & 0xff : 0) + sub_offset;

            // Determine the point to be added
            intptr_t mask, p_a, p_b;
            mask = -intptr_t(subtract);
            p_b  = intptr_t(m_point_pre[pre_idx].get()) ^
                   ((intptr_t(m_point_pre[pre_idx].get()) ^ intptr_t(m_point_pre[sub_idx].get())) & mask);
            point<T>* point_b = reinterpret_cast<point<T>*>(p_b);

            // If masking is disabled then only non-zero integer bits are subjected to point addition,
            // otherwise masking is enabled then point addition is always performed
            mask = -intptr_t(is_zero);
            p_a  = intptr_t(m_point.get()) ^ ((intptr_t(m_point.get()) ^ intptr_t(zero.get())) & mask);
            point<T>* point_a = reinterpret_cast<point<T>*>(p_a);

            if (POINT_OK != (retcode = point_a->addition(m_config, *point_b))) {
                return retcode;
            }
        }

        m_result_is_valid = true;
        return POINT_OK;
    }

    /**
     * @brief Constant-time swap of two pointers
     * @param swap Flag indicating if swap should occur
     * @param s Pointer to swap
     * @param r Pointer to swap
     */
    static void cswap(bool swap, intptr_t& s, intptr_t& r)
    {
        intptr_t dummy = -intptr_t(swap) & (s ^ r);
        s ^= dummy;
        r ^= dummy;
    }

    /**
     * @brief Montgomery ladder algorithm for scalar point multiplication
     * @param bitgen A reference to the scalar_parser object used to encode the scalar
     * @param num_bits The number of bits in the encoded scalar
     * @param w The window size (unused) 
     * @param bit The first bit to be pulled the encoded scalar
     * @param sub_offset An offset to negative pre-computed points (unused)
     * @return retcode_e Returns POINT_OK if successful
     */
    retcode_e montgomery_ladder(core::scalar_parser& bitgen, size_t num_bits, size_t w, uint32_t bit, size_t sub_offset)
    {
        (void) w;
        (void) sub_offset;

        // Set the initial point according to the encoding - it is guaranteed to be positive non-zero
        m_point->copy(*m_point_pre[0].get());
        montgomery_prime_projective<T> G(m_config);
        montgomery_prime_projective<T> p1(m_config);
        G.copy(*m_point_pre[0].get());
        p1.copy(*m_point_pre[0].get());

        // Set pointers
        intptr_t s = intptr_t(m_point.get());
        intptr_t r = intptr_t(&p1);

        // Initial doubling
        p1.doubling(m_config, 1);

        bool swap = false;
        while (num_bits--) {

            // Obtain the next integer bit to be encoded
            bit = bitgen.pull();

            // Conditionally swap s and r
            swap ^= bit == SCALAR_IS_LOW;
            cswap(swap, s, r);
            swap = bit == SCALAR_IS_LOW;

            // Perform a ladder step
            point<T>* p_s = reinterpret_cast<point<T>*>(s);
            point<T>* p_r = reinterpret_cast<point<T>*>(r);
            p_s->ladder_step(m_config, p_r, G);
        }

        // Generate the y coordinate
        m_point->y_recovery(m_config, G, p1);

        m_result_is_valid = true;
        return POINT_OK;
    }
};

}  // namespace elliptic
}  // namespace phantom
