/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <memory>

#include "./phantom.hpp"
#include "crypto/csprng.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/ntt_binary.hpp"
#include "sampling/gaussian_cdf.hpp"


namespace phantom {
namespace ntru {

/**
 * @brief An LDL decomposition class
 */
class ldl
{
public:
    /// Get the size of the tree
    static size_t treesize(size_t logn);

    /// Create a binary tree of FFT polynomials, each leaf is a real value
    static void create_tree(double       *_RESTRICT_ tree,
                            const double *_RESTRICT_ g00,
                            const double *_RESTRICT_ g01,
                            const double *_RESTRICT_ g11,
                            size_t                     logn,
                            double       *_RESTRICT_ tmp);

    /// Recursive normalization of a binary tree, each leaf of value x
    /// is replaced with sigma/sqrt(x)
    static void binary_normalize(double *tree, double sigma, size_t logn);

private:
    /// FFT domain calculation of L[1,0] and D[1,1] from
    /// G[0,0], G[0,1] and G[1,1]
    static void ldl_fft(double       *_RESTRICT_ d11,
                        double       *_RESTRICT_ l10,
                        const double *_RESTRICT_ g00,
                        const double *_RESTRICT_ g01,
                        const double *_RESTRICT_ g11,
                        size_t                     logn,
                        double       *_RESTRICT_ tmp);

    /// Recursive LDL decomposition to generate each row of the auto-adjoint
    /// quasicyclic matrix that forms the tree
    static void fft_inner(double *_RESTRICT_ tree,
                          double *_RESTRICT_ g0,
                          double *_RESTRICT_ g1,
                          size_t               logn,
                          double *_RESTRICT_ tmp);
};

}  // namespace ntru
}  // namespace phantom
