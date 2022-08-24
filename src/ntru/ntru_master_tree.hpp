/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <string>
#include <memory>
#include "crypto/csprng.hpp"
#include "core/ntt_binary.hpp"


namespace phantom {
namespace ntru {

/// @brief A class providing key generation and manipulation functionality for
/// an NTRU key pair
class ntru_master_tree
{
public:
    /// Translate the private key into a tree
    static bool create_master_tree(phantom_vector<double>* tree, uint32_t q, size_t logn,
        const int32_t *f, const int32_t *g, const int32_t *F, const int32_t *G);

    static void load_skey(double *_RESTRICT_ sk, uint32_t q, size_t logn, const int32_t *f_src, const int32_t *g_src,
        const int32_t *F_src, const int32_t *G_src, double *_RESTRICT_ tmp);

    static double gram_schmidt_norm(const int32_t* f, const int32_t* g, uint32_t q,
        size_t logn, double bd, double thresh);

    static bool gaussian_sample_with_tree(std::shared_ptr<csprng> prng, const double* sk, size_t logn, uint32_t q,
        const int32_t *c, uint32_t gaussian_flags, int32_t *s1, int32_t *s2);

private:
    static bool gaussian_lattice_sample(std::shared_ptr<csprng> prng, double *_RESTRICT_ z0, double *_RESTRICT_ z1,
        const double *_RESTRICT_ tree, const double *_RESTRICT_ t0, const double *_RESTRICT_ t1,
        size_t logn, double *_RESTRICT_ tmp, uint32_t flags);
};

}  // namespace ntru
}  // namespace phantom
