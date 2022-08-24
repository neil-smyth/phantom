/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpbase.hpp"


namespace phantom {
namespace core {


template<typename T>
T mpbase<T>::addmul_1(T *inout, const T *in1, size_t n, T in2)
{
    T h, l;

    T cc = 0;
    do {
        // Calculate the product
        number<T>::umul(&h, &l, *in1++, in2);

        // Add the carry word and update the carry using the MSW
        l  += cc;
        cc  = h + (l < cc);

        // Add the LSW of the product from the output, update the carry
        // and write the output word
        l   = *inout + l;
        cc += l < *inout;
        *inout++ = l;
    } while (--n);

    return cc;
}

template<typename T>
T mpbase<T>::addmul_2(T *inout, const T *in1, size_t n, const T *in2)
{
    inout[n] = addmul_1(inout, in1, n, in2[0]);
    return addmul_1(inout + 1, in1, n, in2[1]);
}

template<typename T>
T mpbase<T>::submul_1(T *inout, const T *in1, size_t n, T in2)
{
    T h, l;

    T cc = 0;
    do {
        // Calculate the product
        number<T>::umul(&h, &l, *in1++, in2);

        // Add the carry word and update the carry using the MSW
        l  += cc;
        cc  = h + (l < cc);

        // Subtract the LSW of the product from the output, update the carry
        // and write the output word
        l   = *inout - l;
        cc += l > *inout;
        *inout++ = l;
    } while (0 != --n);

    return cc;
}

template<typename T>
void mpbase<T>::sqr_gradeschool(T *out, const T *in, size_t n)
{
    size_t in2_n = n;
    const T *in2 = in;

    if (1 == n) {
        number<T>::umul(&out[1], &out[0], in[0], in[0]);
    }
    else {
        out[n] = mul_1(out, in, n, *in);
        while (--in2_n) {
            out++;
            in2++;
            out[n] = addmul_1(out, in, n, *in2);
        }
    }
}

template<typename T>
void mpbase<T>::sqr(T *out, const T *in, size_t n)
{
    if (BELOW_THRESHOLD(n, SQR_TOOM2_THRESHOLD)) {
        sqr_gradeschool(out, in, n);
    }
    else if (BELOW_THRESHOLD(n, SQR_TOOM3_THRESHOLD)) {
        size_t num_scratch_limbs = get_toom22_scratch_size(2 * n);
        T *scratch = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * num_scratch_limbs));
        sqr_toom2(out, in, n, scratch);
        aligned_free(scratch);
    }
    else {
        size_t num_scratch_limbs = get_toom33_scratch_size(2 * n);
        T *scratch = reinterpret_cast<T *>(aligned_malloc(sizeof(T) * num_scratch_limbs));
        sqr_toom3(out, in, n, scratch);
        aligned_free(scratch);
    }
}

template<typename T>
T mpbase<T>::mul_1(T *out, const T *in1, size_t n, T in2)
{
    T h, l;

    T cc = 0;
    while (n--) {
        // Calculate the product
        number<T>::umul(&h, &l, *in1++, in2);

        // Add the carry word and update the carry using the MSW
        l  += cc;
        cc  = h + (l < cc);

        // Write the output word
        *out++ = l;
    }

    return cc;
}

template<typename T>
T mpbase<T>::mul_gradeschool(T *out, const T *in1, size_t n1, const T *in2, size_t n2)
{
    out[n1] = mul_1(out, in1, n1, *in2);
    while (--n2) {
        out++;
        in2++;
        out[n1] = addmul_1(out, in1, n1, *in2);
    }

    return out[n1 - 1];
}

template<typename T>
T mpbase<T>::mul(T *out, const T *in1, size_t n1, const T *in2, size_t n2)
{
    // NOTE: It is guaranteed that n1 >= n2

    if (in1 == in2 && n1 == n2) {
        // Multiply by self - squaring is optimal
        sqr(out, in1, n1);
        return out[2*n1 - 1];
    }
    else if (n1 == n2) {
        // Array lengths are identical - mul_n is optimal
        mul_n(out, in1, in2, n2);
        return out[2*n1 - 1];
    }
    else if (BELOW_THRESHOLD(MIN(n1, n2), MUL_TOOM22_THRESHOLD)) {
        // Input data arrays are different - fallback to gradeschool
        return mul_gradeschool(out, in1, n1, in2, n2);
    }
    else if (BELOW_THRESHOLD(MIN(n1, n2), MUL_TOOM33_THRESHOLD)) {
        size_t num_scratch_limbs = get_toom22_scratch_size(n1 + n2);
        T* scratch = reinterpret_cast<T*>(aligned_malloc(sizeof(T) * num_scratch_limbs));
        mul_toom22(out, in1, n1, in2, n2, scratch);
        aligned_free(scratch);
        return out[n1 + n2 - 1];
    }
    else {
        size_t num_scratch_limbs = get_toom33_scratch_size(n1 + n2);
        T* scratch = reinterpret_cast<T*>(aligned_malloc(sizeof(T) * num_scratch_limbs));
        mul_toom33(out, in1, n1, in2, n2, scratch);
        aligned_free(scratch);
        return out[n1 + n2 - 1];
    }
}

template<typename T>
void mpbase<T>::mul_n(T *out, const T *in1, const T *in2, size_t n)
{
    assert(n >= 1);
    assert(!OVERLAP_P(out, 2 * n, in1, n));
    assert(!OVERLAP_P(out, 2 * n, in2, n));

    if (BELOW_THRESHOLD(n, MUL_TOOM22_THRESHOLD)) {
        mul_gradeschool(out, in1, n, in2, n);
    }
    else if (BELOW_THRESHOLD(n, MUL_TOOM33_THRESHOLD)) {
        size_t num_scratch_limbs = get_toom22_scratch_size(2*n);
        T* scratch = reinterpret_cast<T*>(aligned_malloc(sizeof(T) * num_scratch_limbs));
        mul_toom22(out, in1, n, in2, n, scratch);
        aligned_free(scratch);
    }
    else {
        size_t num_scratch_limbs = get_toom33_scratch_size(2*n);
        T* scratch = reinterpret_cast<T*>(aligned_malloc(sizeof(T) * num_scratch_limbs));
        mul_toom33(out, in1, n, in2, n, scratch);
        aligned_free(scratch);
    }
}

template<typename T>
void mpbase<T>::mul_low_n(T* out, const T* in1, const T* in2, size_t n)
{
    phantom_vector<T> tmp;  // will be erased when out of scope
    tmp.resize(2 * n);
    mul(tmp.data(), in1, n, in2, n);
    copy(out, tmp.data(), n);
}

template<typename T>
void mpbase<T>::sqr_low_n(T* out, const T* in, size_t n)
{
    phantom_vector<T> scratch;
    scratch.resize(2 * n);
    sqr(scratch.data(), in, n);
    copy(out, scratch.data(), n);
}


// Forward declaration of common type declarations
/// @{
template class mpbase<uint8_t>;
template class mpbase<uint16_t>;
template class mpbase<uint32_t>;
template class mpbase<uint64_t>;
/// @}

}  // namespace core
}  // namespace phantom
