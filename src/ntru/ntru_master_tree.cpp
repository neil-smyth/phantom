/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "ntru/ntru_master_tree.hpp"

#include <algorithm>

#include "logging/logger.hpp"
#include "core/poly.hpp"
#include "ntru/ntru_number.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"
#include "sampling/gaussian_sampler.hpp"
#include "crypto/xof_sha3.hpp"
#include "fft/fft_factory.hpp"
#include "fft/fft_poly.hpp"
#include "ntru/ldl.hpp"
#include "ntru/ntru.hpp"


namespace phantom {
namespace ntru {


void ntru_master_tree::load_skey(double *_RESTRICT_ sk, uint32_t q, size_t logn,
    const int32_t *f_src, const int32_t *g_src,
    const int32_t *F_src, const int32_t *G_src,
    double *_RESTRICT_ tmp)
{
    size_t  n    = static_cast<size_t>(1) << logn;
    double* b00  = sk;
    double* b01  = sk + (1 << logn);
    double* b10  = sk + (2 << logn);
    double* b11  = sk + (3 << logn);
    double* tree = sk + (4 << logn);

    // We load the private key elements directly into the B0 matrix,
    // since B0 = [[g, -f], [G, -F]].
    double* f_tmp = b01;
    double* g_tmp = b00;
    double* F_tmp = b11;
    double* G_tmp = b10;

    // Convert integer keys to double representation
    for (size_t u = 0; u < n; u++) {
        f_tmp[u] = static_cast<double>(f_src[u]);
        g_tmp[u] = static_cast<double>(g_src[u]);
        F_tmp[u] = static_cast<double>(F_src[u]);
        G_tmp[u] = static_cast<double>(G_src[u]);
    }

    // Compute the FFT for the key elements, and negate f and F
    const std::shared_ptr<fft<double>> transform = std::shared_ptr<fft<double>>(fft_factory<double>::create(logn));
    transform->fwd(f_tmp);
    transform->fwd(g_tmp);
    transform->fwd(F_tmp);
    transform->fwd(G_tmp);
    core::poly<double>::negate(f_tmp, n);
    core::poly<double>::negate(F_tmp, n);

    // The Gram-Schmidt matrix is G = B·B*, the formulas are:
    //   g00 = b00*adj(b00) + b01*adj(b01)
    //   g01 = b00*adj(b10) + b01*adj(b11)
    //   g10 = b10*adj(b00) + b11*adj(b01)
    //   g11 = b10*adj(b10) + b11*adj(b11)
    double* g00 = tmp;
    double* g01 = g00 + n;
    double* g11 = g01 + n;
    double* gxx = g11 + n;  // Additional memory used for computation in create_tree()

    std::copy(b00, b00 + n, g00);
    fft_poly<double>::mul_self_adjoint(g00, logn);
    std::copy(b01, b01 + n, gxx);
    fft_poly<double>::mul_self_adjoint(gxx, logn);
    core::poly<double>::add_inplace(g00, n, gxx);

    std::copy(b00, b00 + n, g01);
    fft_poly<double>::mul_adjoint(g01, b10, logn);
    std::copy(b01, b01 + n, gxx);
    fft_poly<double>::mul_adjoint(gxx, b11, logn);
    core::poly<double>::add_inplace(g01, n, gxx);

    std::copy(b10, b10 + n, g11);
    fft_poly<double>::mul_self_adjoint(g11, logn);
    std::copy(b11, b11 + n, gxx);
    fft_poly<double>::mul_self_adjoint(gxx, logn);
    core::poly<double>::add_inplace(g11, n, gxx);

    // Compute the Falcon tree.
    ldl::create_tree(tree, g00, g01, g11, logn, gxx);

    // Normalize tree with sigma.
    double sigma = sqrt(q)* (1.55);
    ldl::binary_normalize(tree, sigma, logn);
}

double ntru_master_tree::gram_schmidt_norm(const int32_t* f, const int32_t* g, uint32_t q,
    size_t logn, double bd, double thresh)
{
    size_t n = static_cast<size_t>(1) << logn;

    phantom_vector<double> f_fft(n), g_fft(n);

    double modx = 0;
    for (size_t i = n; i--;) {
        f_fft[i] = static_cast<double>(f[i]);
        g_fft[i] = static_cast<double>(g[i]);
        modx += f_fft[i] * f_fft[i] + g_fft[i] * g_fft[i];
    }
    modx = sqrt(modx);

    // Early termination - if ||(g,-f)|| cannot satisfy the condition
    // threshold then there's no point continuing, output the bad
    // Gram Schmidt norm so we can try again.
    if (modx > bd) {
        return modx;
    }

    const std::shared_ptr<fft<double>> transform = std::shared_ptr<fft<double>>(fft_factory<double>::create(logn));
    phantom_vector<double> t(n);

    transform->fwd(f_fft.data());
    transform->fwd(g_fft.data());

    fft_poly<double>::invnorm2(t.data(), f_fft.data(), g_fft.data(), logn);
    fft_poly<double>::adjoint(f_fft.data(), logn);
    fft_poly<double>::adjoint(g_fft.data(), logn);
    fft_poly<double>::mul_const(f_fft.data(), q, logn);
    fft_poly<double>::mul_const(g_fft.data(), q, logn);
    fft_poly<double>::mul_auto_adjoint(f_fft.data(), t.data(), logn);
    fft_poly<double>::mul_auto_adjoint(g_fft.data(), t.data(), logn);

    transform->inv(f_fft.data());
    transform->inv(g_fft.data());

    double b_N1 = 0;
    for (size_t i = n; i--;) {
        b_N1 += f_fft[i] * f_fft[i] + g_fft[i] * g_fft[i];
    }

    if (b_N1 >= thresh || isnanl(b_N1)) {
        return 2 * thresh;
    }

    if (modx > b_N1) {
        return modx;
    }
    else {
        return b_N1;
    }
}

bool ntru_master_tree::create_master_tree(phantom_vector<double>* tree, uint32_t q, size_t logn,
    const int32_t *f, const int32_t *g, const int32_t *F, const int32_t *G)
{
    size_t master_tree_len = (static_cast<size_t>(logn + 5) << logn);
    size_t temp_len        = (static_cast<size_t>(7) << logn) * sizeof(double);

    // Allocate memory for the temporary buffer
    double* temp = reinterpret_cast<double*>(aligned_malloc(temp_len));
    if (0 == temp) {
        return false;
    }

    // Allocate memory for the IBE master tree
    *tree = phantom_vector<double>(master_tree_len);

    // Create the DLP IBE master tree
    load_skey(tree->data(), q, logn, f, g, F, G, temp);

    // Release temporary memory resources
    aligned_free(temp);

    return true;
}

bool ntru_master_tree::gaussian_lattice_sample(std::shared_ptr<csprng> prng,
    double *_RESTRICT_ z0, double *_RESTRICT_ z1,
    const double *_RESTRICT_ tree, const double *_RESTRICT_ t0, const double *_RESTRICT_ t1,
    size_t logn, double *_RESTRICT_ tmp, uint32_t flags)
{
    size_t n = static_cast<size_t>(1) << logn;
    if (1 == n) {
        double sigma = tree[0];

        sampling::gaussian<int32_t, uint64_t>* sampler =
            new sampling::gaussian_cdf<int32_t, uint64_t>(prng, sigma, 10.0f);
        if (!sampler) {
            throw std::invalid_argument("Gaussian sampler object could not be instantiated");
        }

        z0[0]  = floor(t0[0]) + sampler->get_signed_sample();
        z1[0]  = floor(t1[0]) + sampler->get_signed_sample();

        delete sampler;
        return true;
    }

    size_t hn = n >> 1;
    const double* tree0 = tree + n;
    const double* tree1 = tree + n + ldl::treesize(logn - 1);

    const std::shared_ptr<fft<double>> transform = std::shared_ptr<fft<double>>(fft_factory<double>::create(logn));

    // We split t1 into z1 (reused as temporary storage), then do
    // the recursive invocation, with output in tmp. We finally
    // merge back into z1.
    transform->split_fft(z1, z1 + hn, t1, logn);
    gaussian_lattice_sample(prng, tmp, tmp + hn, tree1, z1, z1 + hn, logn - 1, tmp + n, flags);
    transform->merge_fft(z1, tmp, tmp + hn, logn);

    // Compute tb0 = t0 + (t1 - z1) * L. Value tb0 ends up in tmp[].
    std::copy(t1, t1 + n, tmp);
    core::poly<double>::sub_inplace(tmp, n, z1);
    fft_poly<double>::mul(tmp, tree, logn);
    core::poly<double>::add_inplace(tmp, n, t0);

    // Second recursive invocation.
    transform->split_fft(z0, z0 + hn, tmp, logn);
    gaussian_lattice_sample(prng, tmp, tmp + hn, tree0, z0, z0 + hn, logn - 1, tmp + n, flags);
    transform->merge_fft(z0, tmp, tmp + hn, logn);

    return true;
}

bool ntru_master_tree::gaussian_sample_with_tree(std::shared_ptr<csprng> prng, const double* sk,
    size_t logn, uint32_t q,
    const int32_t *c, uint32_t gaussian_flags, int32_t *s1, int32_t *s2)
{
    bool retval = false;

    size_t n    = 1 << logn;

    // Assign pointers for the pre-computed Falcon tree
    const double* b00  = sk;
    const double* b01  = sk + (1 << logn);
    const double* b10  = sk + (2 << logn);
    const double* b11  = sk + (3 << logn);
    const double* tree = sk + (4 << logn);

    // Allocate memory for temporary storage
    double* c0   = reinterpret_cast<double*>(aligned_malloc(sizeof(double) * 11 * n));
    if (0 == c0) {
        return false;
    }
    double* c1   = c0 + n;
    double* tmp  = c1 + n;
    double* z0   = tmp + 7 * n;
    double* z1   = z0 + n;

    // Copy the message ring to a floating point representation for use with the
    // FFT (c1 is 0, but is modified later so does not require setting to 0 here)
    for (size_t i = 0; i < n; i++) {
        c0[i] = c[i];
    }

    /// Map the message ring to the poly basis of the secret key
    const std::shared_ptr<fft<double>> transform = std::shared_ptr<fft<double>>(fft_factory<double>::create(logn));
    transform->fwd(c0);
    std::copy(c0, c0 + n, c1);
    double ni       = 1.0 / static_cast<double>(q);
    fft_poly<double>::mul(c1, b01, logn);
    fft_poly<double>::mul_const(c1, -ni, logn);
    fft_poly<double>::mul(c0, b11, logn);
    fft_poly<double>::mul_const(c0, ni, logn);

    // Generate a sampled polynomial using the polynomial basis
    if (!gaussian_lattice_sample(prng, z0, z1, tree, c0, c1, logn, tmp, gaussian_flags)) {
        goto finish;
    }

    // Get the lattice point of the Gaussian sampled vector
    std::copy(z0, z0 + n, c0);
    std::copy(z1, z1 + n, c1);
    fft_poly<double>::mul(z0, b00, logn);
    fft_poly<double>::mul(z1, b10, logn);
    core::poly<double>::add_inplace(z0, n, z1);
    std::copy(c0, c0 + n, z1);
    fft_poly<double>::mul(z1, b01, logn);

    std::copy(z0, z0 + n, c0);
    fft_poly<double>::mul(c1, b11, logn);
    core::poly<double>::add_inplace(c1, n, z1);

    // The result is in FFT domain, so convert back
    transform->inv(c0);
    transform->inv(c1);

    // Compute the signature or IBE user key
    if (s1) {
        for (size_t i = 0; i < n; i++) {
            s1[i] = static_cast<int32_t>(c[i] - llrint(c0[i]));
        }
    }
    for (size_t i = 0; i < n; i++) {
        s2[i] = static_cast<int32_t>(-llrint(c1[i]));
    }

    retval = true;

finish:
    // Free heap memory resources
    aligned_free(c0);

    return retval;
}

}  // namespace ntru
}  // namespace phantom
