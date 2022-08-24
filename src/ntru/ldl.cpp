/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "ntru/ldl.hpp"

#include <algorithm>

#include "ntru/ntru.hpp"
#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "core/bit_manipulation.hpp"
#include "fft/fft_factory.hpp"
#include "fft/fft_poly.hpp"


namespace phantom {
namespace ntru {


void ldl::ldl_fft(double       *_RESTRICT_ d11,
                  double       *_RESTRICT_ l10,
                  const double *_RESTRICT_ g00,
                  const double *_RESTRICT_ g01,
                  const double *_RESTRICT_ g11,
                  size_t                     logn,
                  double       *_RESTRICT_ tmp)
{
    size_t n = 1 << logn;

    // Let tmp = mu = G[0,1] / G[0,0]
    std::copy(g01, g01 + n, tmp);
    fft_poly<double>::div(tmp, g00, logn);

    // Let L[1,0] = adj(mu) and tmp = aux = mu * adj(mu)
    std::copy(tmp, tmp + n, l10);
    fft_poly<double>::adjoint(l10, logn);
    fft_poly<double>::mul(tmp, l10, logn);

    // D[1,1] = G[1,1] - aux * G[0][0]
    fft_poly<double>::mul(tmp, g00, logn);
    std::copy(g11, g11 + n, d11);
    core::poly<double>::sub_inplace(d11, n, tmp);
}

size_t ldl::treesize(size_t logn)
{
    // For logn = 0 (polynomials are constant real values), the "tree" is a
    // single element. Otherwise, the tree node has size 2^logn, and has two
    // child trees of size logn-1 each.
    // Therefore, treesize s() must fulfill the following:
    //   s(0) = 1
    //   s(logn) = (2^logn) + 2*s(logn-1)
    // i.e. s(0) = 1, s(1) = 4, s(2) = 12, s(3) = 32
    return (logn + 1) << logn;
}

void ldl::fft_inner(double *_RESTRICT_ tree,
                    double *_RESTRICT_ g0,
                    double *_RESTRICT_ g1,
                    size_t               logn,
                    double *_RESTRICT_ tmp)
{
    if (0 == logn) {
        tree[0] = g0[0];
        return;
    }
    size_t n  = 1 << logn;
    size_t hn = n >> 1;

    // The LDL decomposition yields L (which is written in the tree)
    // and the diagonal of D. Since d00 = g0, we just write d11
    // into tmp
    ldl_fft(tmp, tree, g0, g1, g0, logn, tmp + n);

    // Split d00 (currently in g0) and d11 (currently in tmp). We
    // reuse g0 and g1 as temporary storage spaces:
    //   d00 splits into g1, g1+hn
    //   d11 splits into g0, g0+hn
    const std::shared_ptr<fft<double>> transform =
        std::shared_ptr<fft<double>>(fft_factory<double>::create(logn));
    transform->split_fft(g1, g1 + hn, g0, logn);
    transform->split_fft(g0, g0 + hn, tmp, logn);

    // Each split result is the first row of a new auto-adjoint
    // quasicyclic matrix for the next recursive step
    fft_inner(tree + n,                      g1, g1 + hn, logn - 1, tmp);
    fft_inner(tree + n + treesize(logn - 1), g0, g0 + hn, logn - 1, tmp);
}

void ldl::create_tree(double       *_RESTRICT_ tree,
                      const double *_RESTRICT_ g00,
                      const double *_RESTRICT_ g01,
                      const double *_RESTRICT_ g11,
                      size_t                     logn,
                      double       *_RESTRICT_ tmp)
{
    if (0 == logn) {
        tree[0] = g00[0];
        return;
    }

    // Set the length parameters
    size_t n  = 1 << logn;
    size_t hn = n >> 1;

    // Setup the pointers for the dummy arrays, ensuring that tmp is at the
    // address after d11
    double* d00 = tmp;
    double* d11 = tmp + n;
    tmp += n << 1;

    // Initialize d00, d11 and the tree as L[1,0]
    std::copy(g00, g00 + n, d00);
    ldl_fft(d11, tree, g00, g01, g11, logn, tmp);

    // Split d00 and d11. We reuse tmp as temporary storage space:
    //   d00 splits into tmp, tmp+hn
    //   d11 splits into d00, d00+hn
    // tmp is then copied into d11 after it is split
    const std::shared_ptr<fft<double>> transform =
        std::shared_ptr<fft<double>>(fft_factory<double>::create(logn));
    transform->split_fft(tmp, tmp + hn, d00, logn);
    transform->split_fft(d00, d00 + hn, d11, logn);
    std::copy(tmp, tmp + n, d11);

    // Each split result is the first row of a new auto-adjoint
    // quasicyclic matrix for the next recursive step
    fft_inner(tree + n,                      d11, d11 + hn, logn - 1, tmp);
    fft_inner(tree + n + treesize(logn - 1), d00, d00 + hn, logn - 1, tmp);
}

void ldl::binary_normalize(double *tree, double sigma, size_t logn)
{
    // Recursively step through the branches of the tree
    size_t n = 1 << logn;
    if (1 == n) {
        tree[0] = sigma * core::bit_manipulation::inv_sqrt(tree[0]);
    }
    else {
        binary_normalize(tree + n,                      sigma, logn - 1);
        binary_normalize(tree + n + treesize(logn - 1), sigma, logn - 1);
    }
}

}  // namespace ntru
}  // namespace phantom
