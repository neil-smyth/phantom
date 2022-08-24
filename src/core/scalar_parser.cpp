/*****************************************************************************
 * Copyright (C) Neil Smyth 2021                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/scalar_parser.hpp"
#include "core/bit_manipulation.hpp"


namespace phantom {
namespace core {


scalar_parser::scalar_parser(scalar_coding_e coding, const phantom_vector<uint8_t>& secret)
{
    if (0 == secret.size()) {
        m_max = 0;
        return;
    }

    size_t n = secret.size();
    while (0 == secret[n-1]) {
        n--;
    }

    uint8_t is_naf    = (coding & SCALAR_CODING_NAF_BIT) >> SCALAR_CODING_NAF_BIT_SHIFT;
    uint8_t is_pre    = (coding & SCALAR_CODING_PRE_BIT) >> SCALAR_CODING_PRE_BIT_SHIFT;
    size_t  max_scale = is_pre ? 8 : is_naf? 8 : 1;
    m_max = 0;

    // Convert the input secret array containing the scalar value to an MP integer
    uint8_t mask = (0 == (m_max & 0x07))? 0xff : (1 << (m_max & 0x07)) - 1;
    mpz<uint32_t> e;
    e.zero_init((n+3)/4);
    e = e + static_cast<uint8_t>(secret[n - 1] & mask);
    for (size_t i=1; i < n; i++) {
        e = e.mul_2exp(8) + secret[n - i - 1];
    }

    // If the exponent is zero the maximum bit size is set to 0
    if (e.is_zero()) {
        m_max = 0;
        return;
    }

    // Recoding of the secret value to non-adjacent form
    if (scalar_coding_e::ECC_NAF_2 <= coding && scalar_coding_e::ECC_NAF_7 >= coding) {
        m_recoded = phantom_vector<uint8_t>();
        m_max     = naf(m_recoded, e, static_cast<size_t>(coding) ^ SCALAR_CODING_NAF_BIT);
    }
    else if (scalar_coding_e::ECC_PRE_2 <= coding && scalar_coding_e::ECC_PRE_8 >= coding) {
        m_recoded = phantom_vector<uint8_t>();
        m_max     = window(m_recoded, secret, static_cast<size_t>(coding) ^ SCALAR_CODING_PRE_BIT);
    }
    else if (scalar_coding_e::ECC_BINARY_DUAL == coding) {
        m_recoded = phantom_vector<uint8_t>();
        m_max     = binary_dual(m_recoded, secret);
    }
    else if (scalar_coding_e::ECC_BINARY == coding || scalar_coding_e::ECC_MONT_LADDER == coding) {
        m_max     = 8*(n - 1) + 8 - bit_manipulation::clz(secret[n - 1]);
        m_recoded = phantom_vector<uint8_t>(secret.begin(), secret.begin() + n);
    }

    // Initialise the scalar variables
    m_secret1 = m_recoded.data();
    m_secret2 = nullptr;
    m_index   = (max_scale * m_max - 1) >> 3;
    m_shift   = ((max_scale * m_max & 7) - 1) & (7 ^ is_naf);
    m_coding  = coding;

    if (scalar_coding_e::ECC_BINARY == coding || scalar_coding_e::ECC_MONT_LADDER == coding ||
        (scalar_coding_e::ECC_NAF_2 <= coding && scalar_coding_e::ECC_NAF_7 >= coding) ||
        (scalar_coding_e::ECC_BINARY_DUAL == coding) ||
        (scalar_coding_e::ECC_PRE_2 <= coding && scalar_coding_e::ECC_PRE_8 >= coding)) {
        // Skim through the scalar value until the first bit/window to be pulled by the user will be non-zero
        while (m_max && m_index >= 0 && SCALAR_IS_LOW == peek()) {
            m_max--;
            pull();
        }
    }
}

size_t scalar_parser::window(phantom_vector<uint8_t>& recoded, const phantom_vector<uint8_t>& secret, size_t w)
{
    size_t num_windows = (secret.size() * 8 + w - 1) / w;

    recoded = phantom_vector<uint8_t>(num_windows);

    for (size_t i=0, j=0, k=0; i < secret.size() * 8; i++) {
        recoded[k] += ((secret[(i>>3)] >> (i & 0x7)) & 1) << j;

        j++;
        if (j == w) {
            j = 0;
            k++;
        }
    }

    return num_windows;
}

size_t scalar_parser::binary_dual(phantom_vector<uint8_t>& recoded, const phantom_vector<uint8_t>& secret)
{
    size_t num_codes = ((secret.size() + 1) >> 1) << 3;

    recoded = phantom_vector<uint8_t>(num_codes);

    std::cerr << "!!! binary_dual secret = "
              << mpz<uint8_t>(const_cast<uint8_t*>(secret.data()), secret.size()).get_str(16)
              << std::endl;

    for (size_t i=0; i < secret.size() * 8 - num_codes; i++) {
        recoded[i] = (secret[(i>>3)] >> (i & 0x7)) & 1;
        std::cerr << " " << static_cast<int>(recoded[i]);
    }
    std::cerr << std::endl;

    for (size_t i=secret.size() * 8 - num_codes, j=0; i < secret.size() * 8; i++, j++) {
        recoded[j] += ((secret[(i>>3)] >> (i & 0x7)) & 1) << 1;
        std::cerr << " " << static_cast<int>(recoded[j]);
    }
    std::cerr << std::endl;

    return num_codes;
}

size_t scalar_parser::naf(phantom_vector<uint8_t>& recoded, const mpz<uint32_t>& secret, size_t w)
{
    size_t   max         = secret.sizeinbase(2);
    size_t   num_ones    = 0;
    uint32_t wmask       = (1 << w) - 1;
    uint32_t wmax        = wmask >> 1;

    recoded = phantom_vector<uint8_t>(max + w - 1);

    mpz<uint32_t> e = secret;

    // Retrieve a pointer to the limbs of the scalar value
    const uint32_t *limbs = e.get_limbs().data();

    // The NAF encoding routine
    size_t idx = 0, code = 0;
    while (1) {
        uint32_t limb = e[0] & wmask;
        uint32_t zi = 0;

        // w=2 => 1 bit, w=3 => 2 bits, w=4 => 3 bits, ...
        uint8_t bits_high = limb & wmax;
        if (bits_high) {
            bool sub = (limb >> (w - 1)) & 1;
            zi = sub? ((~bits_high & wmax) + 1) : bits_high;
            // w=2: '11' -> -1 (e++), '01' -> 1 (e--)
            // w=3: '111' -> -1 (e+=1), '110' -> -2 (e+=2), '101' -> -3 (e+=3),
            //      '011' -> 3 (e-=3), '010' -> 2 (e-=2), '001' -> 1 (e-=1)

            if (sub) {
                e += zi;
            }
            else {
                e -= zi;
            }
            recoded[code] = sub? zi | (1 << (w-1)) : zi;
        }
        e = e / uint32_t(2);
        if (e.is_zero()) {
            break;
        }

        code++;
    }

    // If the NAF coded scalar is larger return a 1, 0 otherwise
    return max + w - 1;
}

uint16_t scalar_parser::peek() const
{
    // Peek ahead at the bit(s) to be pulled depending upon the coding mode
    if (scalar_coding_e::ECC_BINARY == m_coding || scalar_coding_e::ECC_MONT_LADDER == m_coding) {
        uint16_t word = m_secret1[m_index];
        uint16_t shift = m_shift;
        return (word >> shift) & 0x1;
    }
    else if (scalar_coding_e::ECC_BINARY_DUAL == m_coding) {
        uint16_t word = m_recoded[m_index];
        return (word == 0)? SCALAR_IS_LOW : word;
    }
    else if (scalar_coding_e::ECC_PRE_2 <= m_coding && scalar_coding_e::ECC_PRE_8 >= m_coding) {
        uint16_t word = m_recoded[m_index];
        return (word == 0)? SCALAR_IS_LOW : word;
    }
    else {
        uint16_t bits = m_recoded[m_index];
        uint16_t w    = static_cast<size_t>(m_coding) ^ SCALAR_CODING_NAF_BIT;
        uint16_t sub  = bits & (1 << (w - 1));
        return (bits == 0)? SCALAR_IS_LOW : (bits & ((1 << (w - 1))-1)) | (sub? SCALAR_IS_SUBTRACT : 0);
    }
}

size_t scalar_parser::num_symbols()
{
    return m_max;
}

size_t scalar_parser::get_window()
{
    return m_index + 1;
}

uint32_t scalar_parser::pull_naf()
{
    // Obtain the bit from the secret
    uint32_t bits  = m_recoded[m_index];
    uint32_t w     = static_cast<size_t>(m_coding) ^ SCALAR_CODING_NAF_BIT;
    uint32_t sub   = bits & (1 << (w - 1));

    // Decrement the index if shift reaches 0
    m_index--;

    return (bits == 0)? SCALAR_IS_LOW : (bits & ((1 << (w - 1))-1)) | (sub? SCALAR_IS_SUBTRACT : 0);
}

uint32_t scalar_parser::pull_window()
{
    // Obtain the bits from the secret
    uint32_t bits  = m_recoded[m_index];

    // Decrement the index
    m_index--;

    return (bits == 0)? SCALAR_IS_LOW : bits;
}

uint32_t scalar_parser::pull_binary()
{
    // Obtain the bit from the secret
    uint32_t word  = m_recoded[m_index];
    uint32_t bit   = (word >> m_shift) & 0x1;

    // Decrement the index if shift reaches 0
    m_index -= !(((m_shift | (~m_shift + 1)) >> 7) & 1);

    // Decrement the shift and reset to SC_LIMB_BITS_MASK when it wraps around
    m_shift = (m_shift - 1) & 0x7;

    return bit? SCALAR_IS_HIGH : SCALAR_IS_LOW;
}

uint32_t scalar_parser::pull_binary_dual()
{
    // Obtain the bits from the secret
    uint32_t bits  = m_recoded[m_index];

    // Decrement the index
    m_index--;

    return (bits == 0)? SCALAR_IS_LOW : bits;
}

uint32_t scalar_parser::pull()
{
    if (0 == m_max) {
        return 0;
    }

    uint16_t bit;
    uint16_t word, shift;

    // Obtain the bit depending upon the coding mode
    if (scalar_coding_e::ECC_BINARY == m_coding || scalar_coding_e::ECC_MONT_LADDER == m_coding) {
        bit = pull_binary();
    }
    else if (scalar_coding_e::ECC_BINARY_DUAL == m_coding) {
        bit = pull_binary_dual();
    }
    else if (scalar_coding_e::ECC_PRE_2 <= m_coding && scalar_coding_e::ECC_PRE_8 >= m_coding) {
        bit = pull_window();
    }
    else {
        bit = pull_naf();
    }

    // Return the coded bit
    return bit;
}

}  // namespace core
}  // namespace phantom
