/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "schemes/signature/dilithium/dilithium_signature.hpp"
#include "schemes/signature/dilithium/ctx_dilithium.hpp"
#include "logging/logger.hpp"
#include "core/const_time.hpp"
#include "core/poly.hpp"
#include "packing/packer.hpp"
#include "packing/unpacker.hpp"
#include "packing/stream.hpp"


namespace phantom {
namespace schemes {


size_t dilithium_signature::bits_2_set(security_strength_e bits)
{
    // Select the most appropriate parameter set for the given security strength
    size_t set = 0;
    switch (bits)
    {
        case SECURITY_STRENGTH_60:  set = 0; break;

        case SECURITY_STRENGTH_80:
        case SECURITY_STRENGTH_96:  set = 1; break;

        case SECURITY_STRENGTH_112:
        case SECURITY_STRENGTH_128: set = 2; break;

        case SECURITY_STRENGTH_160: set = 3; break;

        default: throw std::invalid_argument("Security strength is invalid");
    }

    return set;
}

dilithium_signature::dilithium_signature()
{
}

dilithium_signature::~dilithium_signature()
{
}

std::unique_ptr<user_ctx> dilithium_signature::create_ctx(security_strength_e bits,
                                                          cpu_word_size_e size_hint,
                                                          bool masking) const
{
    ctx_dilithium* ctx = new ctx_dilithium(dilithium_signature::bits_2_set(bits));
    if (ctx->get_set() > 3) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

std::unique_ptr<user_ctx> dilithium_signature::create_ctx(size_t set,
                                                          cpu_word_size_e size_hint,
                                                          bool masking) const
{
    ctx_dilithium* ctx = new ctx_dilithium(set);
    if (ctx->get_set() > 3) {
        throw std::invalid_argument("Parameter set is out of range");
    }
    return std::unique_ptr<user_ctx>(ctx);
}

void dilithium_signature::uniform_rand_sample_small(std::shared_ptr<csprng> prng, uint32_t q, int32_t eta, size_t bits,
    int32_t *s, size_t n, size_t m) const
{
    // Uniform sampling of an mx1 matrix with coefficients of -eta to +eta

    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t r[128];
    uint32_t mask = (1 << (bits + 1)) - 1;
    int32_t *ptr = s;

    for (size_t i=0; i  <m*n; i+=256) {
        prng->get_mem(r, 128);

        size_t blocks = ((m*n - i) >= 256)? 128 : (m*n - i) >> 1;

        for (size_t j=0; j < blocks; j++) {
            int32_t temp;

            temp = r[j] & mask;
            temp -= (temp >> 1) & (static_cast<int32_t>(2*eta - temp) >> 31);
            *ptr++ = eta - temp;

            r[j] >>= 4;

            temp = r[j] & mask;
            temp -= (temp >> 1) & (static_cast<int32_t>(2*eta - temp) >> 31);
            *ptr++ = eta - temp;
        }
    }
}

void dilithium_signature::uniform_random_ring_q(dilithium* dil,
                                                uint32_t *a,
                                                size_t n,
                                                uint32_t q,
                                                uint32_t q_bits) const
{
    uint32_t mask = (1 << q_bits) - 1;

    dil->get_xof()->squeeze(reinterpret_cast<uint8_t*>(a), n * sizeof(int32_t));

    for (size_t i=0; i < n; i++) {
        a[i] &= mask;
        a[i] -= (static_cast<uint32_t>(q - a[i] - 1) >> 31) * q;
    }
}

void dilithium_signature::create_rand_product(
    ctx_dilithium& ctx, uint32_t q, uint32_t q_bits, uint32_t *t, int32_t *y, size_t logn,
    size_t k, size_t l, uint32_t *c) const
{
    const size_t n = 1 << logn;

    uint32_t *block = reinterpret_cast<uint32_t*>(aligned_malloc(n * sizeof(uint32_t)));
    uint32_t *yu    = reinterpret_cast<uint32_t*>(aligned_malloc(l * n * sizeof(uint32_t)));

    for (size_t i=0; i < l*n; i++) {
        y[i] += q * (static_cast<uint32_t>(y[i]) >> 31);
    }

    ctx.get_reduction().convert_to(yu, reinterpret_cast<uint32_t*>(y), l*n);

    // Compute the NTT of the input to create_rand_product() as an initial step
    for (size_t i=0; i < l; i++) {
        ctx.get_ntt()->fwd(yu + i*n, logn);
    }

    // k x l matrix multiplication of n-element rings
    for (size_t i=0; i < k; i++) {
        uniform_random_ring_q(ctx.get_dilithium(), c, n, q, q_bits);
        ctx.get_ntt()->mul(t + i*n, yu, c);

        for (size_t j=1; j < l; j++) {
            uniform_random_ring_q(ctx.get_dilithium(), c, n, q, q_bits);
            ctx.get_ntt()->mul(c, yu + j*n, c);

            for (size_t k=0; k < n; k++) {
                t[i*n + k] = ctx.get_reduction().add(t[i*n + k], c[k]);
            }
        }
        ctx.get_ntt()->inv(t + i*n, logn);
    }

    ctx.get_reduction().convert_from(t, t, k*n);

    aligned_free(block);
    aligned_free(yu);
}

bool dilithium_signature::keygen(std::unique_ptr<user_ctx>& ctx)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n        = myctx.get_dilithium()->get_params()->n;
    size_t   n_bits   = myctx.get_dilithium()->get_params()->n_bits;
    uint32_t q        = myctx.get_dilithium()->get_params()->q;
    uint32_t q_bits   = myctx.get_dilithium()->get_params()->q_bits;
    uint32_t eta      = myctx.get_dilithium()->get_params()->eta;
    uint32_t eta_bits = myctx.get_dilithium()->get_params()->eta_bits;
    uint32_t l        = myctx.get_dilithium()->get_params()->l;
    uint32_t k        = myctx.get_dilithium()->get_params()->k;
    uint32_t d        = myctx.get_dilithium()->get_params()->d;

    phantom_vector<uint32_t> c(n);

    // Generate rho and K, a 256 bit random byte array to be used to seed
    myctx.get_csprng()->get_mem(myctx.rho(), 32);
    myctx.get_csprng()->get_mem(myctx.K(), 32);
    LOG_DEBUG_ARRAY("rho", myctx.rho(), 32);
    LOG_DEBUG_ARRAY("K", myctx.K(), 32);

    // Seed an XOF with rho as entropy
    myctx.get_dilithium()->get_xof()->init(16);
    myctx.get_dilithium()->get_xof()->absorb(myctx.rho(), 32);
    myctx.get_dilithium()->get_xof()->final();

    // Generate s1 and s2 from a uniform random distribution with values of
    // -eta to +eta inclusive
    myctx.s1() = phantom_vector<int32_t>(l*n);
    myctx.s2() = phantom_vector<int32_t>(k*n);
    uniform_rand_sample_small(myctx.get_csprng(), q, eta, eta_bits, myctx.s1().data(), n, l);
    uniform_rand_sample_small(myctx.get_csprng(), q, eta, eta_bits, myctx.s2().data(), n, k);
    myctx.t()  = phantom_vector<int32_t>(k*n);
    LOG_DEBUG_ARRAY("s1", myctx.s1().data(), myctx.s1().size());
    LOG_DEBUG_ARRAY("s2", myctx.s2().data(), myctx.s2().size());

    myctx.ntt_s1() = phantom_vector<uint32_t>(l*n);
    myctx.ntt_s2() = phantom_vector<uint32_t>(k*n);
    to_montgomery(myctx, myctx.ntt_s1().data(), myctx.s1().data(), q, l*n, 0);
    for (size_t i = 0; i < l; i++) {
        myctx.get_ntt()->fwd(myctx.ntt_s1().data() + i*n, n_bits);
    }
    to_montgomery(myctx, myctx.ntt_s2().data(), myctx.s2().data(), q, k*n, 0);
    for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->fwd(myctx.ntt_s2().data() + i*n, n_bits);
    }

    // Matrix multiplication of A and s1, where A is uniform random
    // sampled as a k x l matrix of ring polynomials with n coefficients.
    // The kxl A matrix is multiplied by the lx1 s1 matrix to form a kx1
    // matrix to which s2 is added.
    create_rand_product(myctx, q, q_bits,
                        reinterpret_cast<uint32_t*>(myctx.t().data()), myctx.s1().data(), n_bits, k, l, c.data());
    core::poly<int32_t>::add(myctx.t().data(), k*n, myctx.t().data(), myctx.s2().data());
    core::poly<int32_t>::mod_unsigned(myctx.t().data(), k*n, q);
    LOG_DEBUG_ARRAY("t", (uint32_t*)myctx.t().data(), myctx.t().size());

    // Truncate and round the t ring polynomial by d bits and write to the public key.
    myctx.t1() = phantom_vector<int32_t>(k*n);
    myctx.get_dilithium()->pwr_2_round(myctx.t1().data(), myctx.t().data(), q, n, k, d);
    LOG_DEBUG_ARRAY("t1", myctx.t1().data(), myctx.t1().size());
    LOG_DEBUG_ARRAY("t0", myctx.t().data(), myctx.t().size());

    myctx.ntt_t0() = phantom_vector<uint32_t>(k*n);
    to_montgomery(myctx, myctx.ntt_t0().data(), myctx.t().data(), q, k*n, 0);
    for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->fwd(myctx.ntt_t0().data() + i*n, n_bits);
    }

    // Create tr (associated with the private key) for use in deterministic signature generation.
    // tr is formed from the 32 bytes of rho and the bit packed representation of t1.
    myctx.get_dilithium()->collision_resistant_hash_t1(myctx.rho(), myctx.t1().data(), n, k, q_bits - d, myctx.tr());
    LOG_DEBUG_ARRAY("tr", myctx.tr(), 48);

    // Convert t1 to Montgomery representation for use in verification
    myctx.ntt_t1() = phantom_vector<uint32_t>(k*n);
    for (size_t i = 0; i < k*n; i++) {
        myctx.ntt_t1()[i]   = myctx.t1()[i];
        myctx.ntt_t1()[i]  += q * (myctx.ntt_t1()[i] >> 31);
        myctx.ntt_t1()[i] <<= d;
    }
    myctx.get_reduction().convert_to(myctx.ntt_t1().data(), myctx.ntt_t1().data(), k*n);
    for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->fwd(myctx.ntt_t1().data() + i*n, n_bits);
    }

    return true;
}

bool dilithium_signature::set_public_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n      = myctx.get_dilithium()->get_params()->n;
    size_t   k      = myctx.get_dilithium()->get_params()->n;
    uint32_t d      = myctx.get_dilithium()->get_params()->d;
    uint32_t q_bits = myctx.get_dilithium()->get_params()->q_bits;

    myctx.t1().clear();
    myctx.t1().resize(k*n);

    packing::unpacker up(key);
    for (size_t i = 0; i < 32; i++) {
        myctx.rho()[i] = up.read_unsigned(8, packing::RAW);
    }
    for (size_t i = k*n; i--;) {
        myctx.t1().push_back(up.read_unsigned(q_bits - d, packing::RAW));
    }

    return true;
}

bool dilithium_signature::get_public_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n      = myctx.get_dilithium()->get_params()->n;
    size_t   k      = myctx.get_dilithium()->get_params()->n;
    uint32_t d      = myctx.get_dilithium()->get_params()->d;
    uint32_t q_bits = myctx.get_dilithium()->get_params()->q_bits;

    key.clear();

    packing::packer pack((q_bits - d) * k * n + 32 * 8);
    for (size_t i=0; i < 32; i++) {
        pack.write_unsigned(myctx.rho()[i], 8, packing::RAW);
    }
    for (size_t i=0; i < k*n; i++) {
        pack.write_unsigned(myctx.t1()[i], q_bits - d, packing::RAW);
    }

    key = pack.get();

    return true;
}

bool dilithium_signature::set_private_key(std::unique_ptr<user_ctx>& ctx, const phantom_vector<uint8_t>& key)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n        = myctx.get_dilithium()->get_params()->n;
    size_t   l        = myctx.get_dilithium()->get_params()->n;
    size_t   k        = myctx.get_dilithium()->get_params()->n;
    uint32_t q_bits   = myctx.get_dilithium()->get_params()->q_bits;
    uint32_t eta_bits = myctx.get_dilithium()->get_params()->eta_bits;

    myctx.s1().clear();
    myctx.s1().resize(l*n);
    myctx.s2().clear();
    myctx.s2().resize(k*n);
    myctx.t1().clear();
    myctx.t1().resize(k*n);

    packing::unpacker up(key);
    for (size_t i=0; i < 32; i++) {
        myctx.rho()[i] = up.read_unsigned(8, packing::RAW);
    }
    for (size_t i=0; i < 32; i++) {
        myctx.K()[i] = up.read_unsigned(8, packing::RAW);
    }
    for (size_t i=0; i < 48; i++) {
        myctx.tr()[i] = up.read_unsigned(8, packing::RAW);
    }
    for (size_t i=l*n; i--;) {
        myctx.s1().push_back(up.read_unsigned(eta_bits + 1, packing::RAW));
    }
    for (size_t i=k*n; i--;) {
        myctx.s2().push_back(up.read_unsigned(eta_bits + 1, packing::RAW));
    }
    for (size_t i=k*n; i--;) {
        myctx.t().push_back(up.read_unsigned(q_bits, packing::RAW));
    }

    return true;
}

bool dilithium_signature::get_private_key(std::unique_ptr<user_ctx>& ctx, phantom_vector<uint8_t>& key)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n        = myctx.get_dilithium()->get_params()->n;
    size_t   l        = myctx.get_dilithium()->get_params()->n;
    size_t   k        = myctx.get_dilithium()->get_params()->n;
    uint32_t q_bits   = myctx.get_dilithium()->get_params()->q_bits;
    uint32_t eta_bits = myctx.get_dilithium()->get_params()->eta_bits;

    key.clear();

    packing::packer pack(((eta_bits + 1) * (l + k) + q_bits * k) * n + (32 + 32 + 48) * 8);
    for (size_t i = 0; i < 32; i++) {
        pack.write_unsigned(myctx.rho()[i], 8, packing::RAW);
    }
    for (size_t i = 0; i < 32; i++) {
        pack.write_unsigned(myctx.K()[i], 8, packing::RAW);
    }
    for (size_t i = 0; i < 48; i++) {
        pack.write_unsigned(myctx.tr()[i], 8, packing::RAW);
    }
    for (size_t i = 0; i < l*n; i++) {
        pack.write_unsigned(myctx.s1()[i], eta_bits + 1, packing::RAW);
    }
    for (size_t i = 0; i < k*n; i++) {
        pack.write_unsigned(myctx.s2()[i], eta_bits + 1, packing::RAW);
    }
    for (size_t i = 0; i < k*n; i++) {
        pack.write_unsigned(myctx.t()[i], q_bits, packing::RAW);
    }

    key = pack.get();

    return true;
}

void dilithium_signature::to_montgomery(ctx_dilithium& ctx, uint32_t *out, const int32_t *in,
    uint32_t q, size_t n, size_t offset) const
{
    uint32_t temp;
    for (size_t j = 0; j < n; j++) {
        temp   = in[j + offset];
        temp  += q * (temp >> 31);
        out[j] = ctx.get_reduction().convert_to(temp);
    }
}

void dilithium_signature::from_montgomery(ctx_dilithium& ctx, int32_t *out, const uint32_t *in,
    uint32_t q, size_t n, size_t offset) const
{
    ctx.get_reduction().convert_from(reinterpret_cast<uint32_t*>(out) + offset, in, n);
}

uint32_t dilithium_signature::check_norm_inf(const int32_t *v, size_t n, size_t l, uint32_t q, uint32_t b) const
{
    uint32_t  lower_half = (q - 1) >> 1;
    uint32_t  upper_b    = q - b;
    const uint32_t *vu   = reinterpret_cast<const uint32_t*>(v);

    // Scan through the l matrices of length n,
    // Terminate early if the threshold is exceeded and return 1.
    volatile uint32_t retval = 0;
    for (size_t i = 0; i < l*n; i++) {
        uint32_t v_lte_q2 = (vu[i] - lower_half - 1) >> 31;
        uint32_t v_gte_b  = (b - vu[i] - 1) >> 31;
        uint32_t v_gte_ub = (vu[i] - upper_b - 1) >> 31;
        retval |= (v_lte_q2 & v_gte_b) | (~v_lte_q2 & v_gte_ub);
    }

    return retval;
}

bool dilithium_signature::sign(const std::unique_ptr<user_ctx>& ctx,
                               const phantom_vector<uint8_t>& m,
                               phantom_vector<uint8_t>& s)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n            = myctx.get_dilithium()->get_params()->n;
    size_t   n_bits       = myctx.get_dilithium()->get_params()->n_bits;
    size_t   q            = myctx.get_dilithium()->get_params()->q;
    uint32_t q_bits       = myctx.get_dilithium()->get_params()->q_bits;
    uint32_t z_bits       = myctx.get_dilithium()->get_params()->z_bits;
    uint32_t beta         = myctx.get_dilithium()->get_params()->beta;
    uint32_t omega        = myctx.get_dilithium()->get_params()->omega;
    uint32_t omega_bits   = myctx.get_dilithium()->get_params()->omega_bits;
    uint32_t gamma_1      = myctx.get_dilithium()->get_params()->gamma_1;
    uint32_t gamma_2      = myctx.get_dilithium()->get_params()->gamma_2;
    size_t   l            = myctx.get_dilithium()->get_params()->l;
    size_t   k            = myctx.get_dilithium()->get_params()->k;
    size_t   d            = myctx.get_dilithium()->get_params()->d;

    uint32_t kappa        = 0;
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t mu[48];
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t w1_bytes[k*n];
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t r1[k*n];

    phantom_vector<uint32_t> storage((3 + 2*l + 6*k) * n);
    int32_t*  c        = reinterpret_cast<int32_t*>(storage.data());
    int32_t*  y        = c + n;
    int32_t*  t0       = y + l*n;
    int32_t*  t1       = t0 + k*n;
    int32_t*  z        = t1 + k*n;
    int32_t*  wcs2     = z + l*n;
    int32_t*  ct0      = wcs2 + k*n;
    int32_t*  h        = ct0 + k*n;
    uint32_t* ntt_c    = reinterpret_cast<uint32_t*>(h + k*n);
    uint32_t* w        = ntt_c + n;
    uint32_t* ntt_temp = w + k*n;

    myctx.get_dilithium()->collision_resistant_hash_message(myctx.tr(), m, mu);
    LOG_DEBUG_ARRAY("mu", mu, 48);

restart:
    // Generate y from the deterministic ExpandMask() function
    myctx.get_dilithium()->expand_mask(mu, kappa, gamma_1, q, l, n, y, myctx.K());

    myctx.get_dilithium()->get_xof()->init(16);
    myctx.get_dilithium()->get_xof()->absorb(myctx.rho(), 32);
    myctx.get_dilithium()->get_xof()->final();

    LOG_DEBUG_ARRAY("y", y, l*n);
    create_rand_product(myctx, q, q_bits, w, y, n_bits, k, l, (reinterpret_cast<uint32_t*>(c)));
    LOG_DEBUG_ARRAY("create_rand_product() w", w, k*n);
    LOG_DEBUG_ARRAY("create_rand_product() y", y, l*n);

    // Generate the high order representation of w
    myctx.get_dilithium()->high_bits(w1_bytes, w, n, k);
    LOG_DEBUG_ARRAY("w1 bytes", w1_bytes, k*n);

    // Calculate H(mu, w1) such that a sparse polynomial with 60
    // coefficients have the values 1 or -1
    myctx.get_dilithium()->h_function(c, mu, w1_bytes, n, k);
    LOG_DEBUG_ARRAY("c", c, n);
    to_montgomery(myctx, ntt_c, c, q, n, 0);
    myctx.get_ntt()->fwd(ntt_c, n_bits);

    // Check 1 - Verify that the norm of z = y + c * s1 is less than gamma_1 - beta
    for (size_t i=0; i < l; i++) {
        myctx.get_ntt()->mul(reinterpret_cast<uint32_t*>(z + n*i), myctx.ntt_s1().data() + i*n, ntt_c);
        myctx.get_ntt()->inv(reinterpret_cast<uint32_t*>(z + n*i), n_bits);
        from_montgomery(myctx, z, reinterpret_cast<const uint32_t*>(z) + n*i, q, n, n*i);
    }
    LOG_DEBUG_ARRAY("c * s1", z, l*n);
    core::poly<int32_t>::add(z, l*n, z, y);
    for (size_t i=0; i < l*n; i++) {
        z[i] -= q * (static_cast<uint32_t>(q - z[i]) >> 31);
    }
    LOG_DEBUG_ARRAY("z = y + c * s1", z, l*n);
    if (check_norm_inf(z, n, l, q, gamma_1 - beta)) {
        kappa++;
        LOG_DEBUG("RESTART: || y + c * s1 || >= gamma_1 - beta");
        goto restart;
    }

    // Check 2 - Verify that the norm of LowOrderBits_q(w - c*s2, 2*gamma_2) is
    // less than gamma_2 - beta
    for (size_t i=0; i < k; i++) {
        myctx.get_ntt()->mul(ntt_temp, myctx.ntt_s2().data() + i*n, ntt_c);
        myctx.get_ntt()->inv(ntt_temp, n_bits);
        from_montgomery(myctx, wcs2, ntt_temp, q, n, n*i);
    }
    LOG_DEBUG_ARRAY("c * s2", wcs2, k*n);
    core::poly<int32_t>::sub(wcs2, k*n, reinterpret_cast<int32_t*>(w), wcs2);
    core::poly<int32_t>::mod_unsigned(wcs2, k*n, q);
    LOG_DEBUG_ARRAY("w - c*s2", wcs2, k*n);

    // (r1, r0) = Decompose(w - c*s2, 2* gamma2)
    myctx.get_dilithium()->decompose(t1, r1, wcs2, n, k, d, q);
    LOG_DEBUG_ARRAY("decompose t1", t1, k*n);
    LOG_DEBUG_ARRAY("decompose t0", r1, k*n);

    if (check_norm_inf(t1, n, k, q, gamma_2 - beta)) {
        kappa++;
        LOG_DEBUG("RESTART: || r0 || >= gamma_2 - beta");
        goto restart;
    }

    for (size_t i=0; i < k*n; i++) {
        if (r1[i] != w1_bytes[i]) {
            kappa++;
            LOG_DEBUG("RESTART: r1 != w1");
            goto restart;
        }
    }

    for (size_t i=0; i < k; i++) {
        myctx.get_ntt()->mul(ntt_temp, myctx.ntt_t0().data() + n*i, ntt_c);
        myctx.get_ntt()->inv(ntt_temp, n_bits);
        from_montgomery(myctx, ct0, ntt_temp, q, n, n*i);
    }
    LOG_DEBUG_ARRAY("ct0", ct0, k*n);

    if (check_norm_inf(ct0, n, k, q, gamma_2)) {
        kappa++;
        LOG_DEBUG("RESTART: || c*t0 || >= gamma_2");
        goto restart;
    }

    // Create the hint to be appended to the signature
    // Add ct0 to wcs2 and normalise, negate ct0
    core::poly<int32_t>::add(wcs2, k*n, wcs2, ct0);
    for (size_t i = 0; i < k*n; i++) {
        wcs2[i] -= q * (static_cast<uint32_t>(q - wcs2[i]) >> 31);
    }
    for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->negate(reinterpret_cast<uint32_t*>(ct0 + i*n));
    }
    size_t num_ones = myctx.get_dilithium()->make_hint(h, wcs2, ct0, n, k);
    LOG_DEBUG_ARRAY("wcs2", wcs2, k*n);
    LOG_DEBUG_ARRAY("h", h, k*n);
    LOG_DEBUG("num_ones = " << num_ones);

    // If the number of asserted bits in h is greater than omega then restart
    if (num_ones > omega) {
        kappa++;
        goto restart;
    }

    LOG_DEBUG_ARRAY("z", z, l*n);
    LOG_DEBUG_ARRAY("h", h, k*n);
    LOG_DEBUG_ARRAY("c", c, n);

    if (0) {
        LOG_DEBUG("Verification countermeasure");

        // Verify that the norm of z is less than or equal to gamma_1 - beta
        if (check_norm_inf(z, n, l, q, gamma_1 - beta)) {
            return false;
        }

        // Verify that the number of ones in the hint is <= omega
        if (myctx.get_dilithium()->check_hint_ones(h, k, n) > omega) {
            return false;
        }

        // Create a XOF random oracle and generate the kx1 matrix w = A*z mod q
        myctx.get_dilithium()->get_xof()->init(16);
        myctx.get_dilithium()->get_xof()->absorb(myctx.rho(), 32);
        myctx.get_dilithium()->get_xof()->final();

        alignas(DEFAULT_MEM_ALIGNMENT) int32_t temp[2*n];

        create_rand_product(myctx, q, q_bits, w, z, n_bits, k, l, reinterpret_cast<uint32_t*>(temp));

        for (size_t i=0; i < k; i++) {
            myctx.get_ntt()->mul(ntt_temp, myctx.ntt_t1().data() + i*n, ntt_c);
            myctx.get_ntt()->inv(ntt_temp, n_bits);
            from_montgomery(myctx, t0, ntt_temp, q, n, n*i);
        }
        LOG_DEBUG_ARRAY("c * t1 * 2^d", t0, k*n);

        // A*z - c*t1.2^d mod q
        core::poly<int32_t>::sub(t0, k*n, reinterpret_cast<int32_t*>(w), t0);
        core::poly<int32_t>::mod_unsigned(t0, k*n, q);
        LOG_DEBUG_ARRAY("A*z - c*t1.2^d mod q", t0, k*n);

        // Use the signature hint to recreate w1 from A*z - c*t1.2^d
        myctx.get_dilithium()->use_hint(w1_bytes, h, t0, n, k);
        LOG_DEBUG_ARRAY("verify w'", w1_bytes, k*n);

        // Calculate H(mu, w1) such that a sparse polynomial with 60
        // coefficients have the values 1 or -1
        myctx.get_dilithium()->h_function(temp, mu, w1_bytes, n, k);
        LOG_DEBUG_ARRAY("H(mu, w')", temp, n);
    }

    core::poly<int32_t>::centre(z, q, l*n);
    LOG_DEBUG_ARRAY("z", z, l*n);

    size_t h_bits      = 8 + ((k + 1) >> 1);
    size_t packer_bits = l*n*z_bits + omega_bits + num_ones*h_bits + 2*n;

    packing::packer pack(packer_bits);
    for (size_t i=0; i < l*n; i++) {
        pack.write_signed(z[i], z_bits, packing::RAW);
    }
    pack.write_unsigned(num_ones, omega_bits, packing::RAW);
    size_t h_idx = 0;
    while (num_ones) {
        if (h[h_idx]) {
            pack.write_unsigned(h_idx, h_bits, packing::RAW);
            num_ones--;
        }
        h_idx++;
    }
    for (size_t i=0; i < n; i++) {
        pack.write_unsigned(c[i], 2, packing::RAW);
    }

    pack.flush();
    s = pack.get();

    return true;
}

bool dilithium_signature::verify(const std::unique_ptr<user_ctx>& ctx,
                                 const phantom_vector<uint8_t>& m,
                                 const phantom_vector<uint8_t>& s)
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    size_t   n            = myctx.get_dilithium()->get_params()->n;
    size_t   n_bits       = myctx.get_dilithium()->get_params()->n_bits;
    size_t   q            = myctx.get_dilithium()->get_params()->q;
    uint32_t q_bits       = myctx.get_dilithium()->get_params()->q_bits;
    uint32_t z_bits       = myctx.get_dilithium()->get_params()->z_bits;
    uint32_t beta         = myctx.get_dilithium()->get_params()->beta;
    uint32_t omega        = myctx.get_dilithium()->get_params()->omega;
    uint32_t omega_bits   = myctx.get_dilithium()->get_params()->omega_bits;
    uint32_t gamma_1      = myctx.get_dilithium()->get_params()->gamma_1;
    size_t   l            = myctx.get_dilithium()->get_params()->l;
    size_t   k            = myctx.get_dilithium()->get_params()->k;
    size_t   d            = myctx.get_dilithium()->get_params()->d;

    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t mu[48];
    alignas(DEFAULT_MEM_ALIGNMENT) uint8_t w1_bytes[k*n];

    phantom_vector<uint32_t> storage((5 + l + 3*k) * n);
    uint32_t* ntt_c    = reinterpret_cast<uint32_t*>(storage.data());
    uint32_t* ntt_temp = ntt_c + n;
    int32_t*  z        = reinterpret_cast<int32_t*>(ntt_temp + n);
    int32_t*  h        = z + l*n;
    int32_t*  c        = h + k*n;
    int32_t*  t0       = c + n;
    int32_t*  w        = t0 + k*n;
    int32_t*  temp     = w + k*n;

    packing::unpacker unpack(s);
    for (size_t i = 0; i < l*n; i++) {
        z[i]  = unpack.read_signed(z_bits, packing::RAW);
        z[i] += q * (static_cast<uint32_t>(z[i]) >> 31);
    }
    size_t h_bits = 8 + ((k + 1) >> 1);
    size_t num_ones = unpack.read_unsigned(omega_bits, packing::RAW);
    memset(h, 0, k * n * sizeof(int32_t));
    for (size_t i = 0; i < num_ones; i++) {
        uint32_t tmp = unpack.read_unsigned(h_bits, packing::RAW);
        h[tmp] = 1;
    }
    for (size_t i = 0; i < n; i++) {
        uint32_t tmp = unpack.read_unsigned(2, packing::RAW);
        c[i] = (3 == tmp)? -1 : tmp;
    }

    LOG_DEBUG_ARRAY("z", z, l*n);
    LOG_DEBUG_ARRAY("h", h, k*n);
    LOG_DEBUG_ARRAY("c", c, n);

    // Verify that the norm of z is less than or equal to gamma_1 - beta
    if (check_norm_inf(z, n, l, q, gamma_1 - beta)) {
        goto finish_error;
    }

    // Verify that the number of ones in the hint is <= omega
    if (myctx.get_dilithium()->check_hint_ones(h, k, n) > omega) {
        goto finish_error;
    }

    // Create a XOF random oracle and generate the kx1 matrix w = A*z mod q
    myctx.get_dilithium()->get_xof()->init(16);
    myctx.get_dilithium()->get_xof()->absorb(myctx.rho(), 32);
    myctx.get_dilithium()->get_xof()->final();

    // Compute A*z
    create_rand_product(myctx, q, q_bits, reinterpret_cast<uint32_t*>(w),
        z, n_bits, k, l, reinterpret_cast<uint32_t*>(temp));

    // Convert c to Montgomery representation in the NTT domain
    to_montgomery(myctx, ntt_c, c, q, n, 0);
    myctx.get_ntt()->fwd(ntt_c, n_bits);

    // Compute c*t1.2^d mod q
    for (size_t i = 0; i < k; i++) {
        myctx.get_ntt()->mul(ntt_temp, myctx.ntt_t1().data() + i*n, ntt_c);
        myctx.get_ntt()->inv(ntt_temp, n_bits);
        from_montgomery(myctx, t0, ntt_temp, q, n, n*i);
    }

    // Compute A*z - c*t1.2^d mod q
    core::poly<int32_t>::sub_mod(t0, k*n, w, t0, q);
    LOG_DEBUG_ARRAY("A*z - c*t1.2^d mod q", t0, k*n);

    // Use the signature hint to recreate w (w') from A*z - c*t1.2^d
    myctx.get_dilithium()->use_hint(w1_bytes, h, t0, n, k);
    LOG_DEBUG_ARRAY("verify w'", w1_bytes, k*n);

    // Compute μ
    LOG_DEBUG_ARRAY("rho", myctx.rho(), 32);
    myctx.get_dilithium()->collision_resistant_hash_t1(myctx.rho(), myctx.t1().data(), n, k, q_bits - d, mu);
    myctx.get_dilithium()->collision_resistant_hash_message(mu, m, mu);
    LOG_DEBUG_ARRAY("mu", mu, 48);

    // Calculate H(μ, w1) such that a sparse polynomial with 60
    // coefficients have the values 1 or -1
    myctx.get_dilithium()->h_function(temp, mu, w1_bytes, n, k);
    LOG_DEBUG_ARRAY("H(mu, w')", temp, n);

    // Check the output of the H function against the received value
    // in the signature
    if (const_time<int32_t>::cmp_array_not_equal(temp, c, n)) {
        goto finish_error;
    }

    return true;

finish_error:

    return false;
}

size_t dilithium_signature::get_msg_len(const std::unique_ptr<user_ctx>& ctx) const
{
    ctx_dilithium& myctx = dynamic_cast<ctx_dilithium&>(*ctx.get());

    return myctx.get_dilithium()->get_params()->n;
}

}  // namespace schemes
}  // namespace phantom
