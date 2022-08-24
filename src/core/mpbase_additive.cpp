/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include "core/mpbase.hpp"
#include "core/const_time.hpp"


namespace phantom {
namespace core {


template<typename T>
T mpbase<T>::add_1(T *out, const T *in1, size_t n, T in2)
{
    // Re-use the local copy of in2 to use as the carry word
    size_t i = 0;
    do {
        T temp = in1[i] + in2;
        out[i] = temp;
        in2    = const_time<T>::cmp_lessthan(temp, in2);
        i++;
    } while (const_time<T>::cmp_lessthan(i, n));
    return in2;
}

template<typename T>
T mpbase<T>::add_n(T *out, const T *in1, const T *in2, size_t n)
{
    T cc = 0;

    for (size_t i=0; i < n; i++) {
        T temp = in1[i] + cc;
        cc     = const_time<T>::cmp_lessthan(temp, cc);
        temp  += in2[i];
        cc    += const_time<T>::cmp_lessthan(temp, in2[i]);
        out[i] = temp;
    }
    return cc;
}

template<typename T>
T mpbase<T>::add_nc(T *out, const T *in1, const T *in2, size_t n, T cin)
{
    T cc;
    cc  = add_n(out, in1, in2, n);
    cc += add_1(out, out, n, cin);
    return cc;
}

template<typename T>
T mpbase<T>::add(T *out, const T *in1, size_t n1, const T *in2, size_t n2)
{
    T cc = add_n(out, in1, in2, n2);
    if (n1 > n2) {
        cc = add_1(out + n2, in1 + n2, n1 - n2, cc);
    }
    return cc;
}

template<typename T>
T mpbase<T>::sub_1(T *out, const T *in1, size_t n, T in2)
{
    // Use the local copy of in2 to use as the carry word
    for (size_t i=0; i < n; i++) {
        T cc = const_time<T>::cmp_lessthan(in1[i], in2);
        out[i] = in1[i] - in2;
        in2 = cc;
    }
    return in2;
}

template<typename T>
T mpbase<T>::sub_n(T *out, const T *in1, const T *in2, size_t n)
{
    T cc = 0;

    for (size_t i=0; i < n; i++) {
        T temp = in2[i] + cc;
        cc     = const_time<T>::cmp_lessthan(temp, cc);
        cc    += const_time<T>::cmp_lessthan(in1[i], temp);
        out[i] = in1[i] - temp;
    }
    return cc;
}

template<typename T>
T mpbase<T>::sub_nc(T *out, const T *in1, const T *in2, size_t n, T cin)
{
    T cc;
    cc  = sub_n(out, in1, in2, n);
    cc += sub_1(out, out, n, cin);
    return cc;
}

template<typename T>
T mpbase<T>::sub(T *out, const T *in1, size_t n1, const T *in2, size_t n2)
{
    T cc = sub_n(out, in1, in2, n2);
    if (n1 > n2) {
        cc = sub_1(out + n2, in1 + n2, n1 - n2, cc);
    }
    return cc;
}

template<typename T>
int mpbase<T>::addsub_n(T *out, const T *x, const T *y, const T *z, size_t n)
{
    T ret;

    assert(n > 0);
    assert(ASSERT_ARRAY_SAME_OR_SEPARATE(out, n, x, n));
    assert(ASSERT_ARRAY_SAME_OR_SEPARATE(out, n, y, n));
    assert(ASSERT_ARRAY_SAME_OR_SEPARATE(out, n, z, n));

    if (out == x && out == y && out == z) {
        return 0;
    }

    if (out == x && out == y) {
        ret  = add_n(out, x, y, n);
        ret -= sub_n(out, out, z, n);

        return ret;
    }

    if (out == x && out == z) {
        ret  = -sub_n(out, x, z, n);
        ret += add_n(out, out, y, n);

        return ret;
    }

    if (out == y && out == z) {
        ret  = -sub_n(out, y, z, n);
        ret += add_n(out, out, x, n);

        return ret;
    }

    if (out == x) {
        ret  = add_n(out, x, y, n);
        ret -= sub_n(out, out, z, n);

        return ret;
    }

    if (out == y) {
        ret  = add_n(out, y, x, n);
        ret -= sub_n(out, out, z, n);

        return ret;
    }

    if (out == z) {
        ret = -sub_n(out, x, z, n);
        ret += add_n(out, out, y, n);

        return ret;
    }

    ret  = add_n(out, x, y, n);
    ret -= sub_n(out, out, z, n);

    return ret;
}

template<typename T>
int mpbase<T>::abs_sub_n(T* out, const T *in1, const T *in2, size_t n)
{
    int c = cmp(in1, in2, n);

    T c_gte_0 = const_time<T>::if_gte(c, 0, 1);
    intptr_t select_1 = intptr_t(c_gte_0);
    intptr_t select_2 = intptr_t(const_time<T>::cmp_lessthan(c, 0));
    sub_n(out,
          reinterpret_cast<const T*>(select_1 * intptr_t(in1) + select_2 * intptr_t(in2)),
          reinterpret_cast<const T*>(select_1 * intptr_t(in2) + select_2 * intptr_t(in1)),
          n);
    return c_gte_0;
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
