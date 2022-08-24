/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <limits>

/**
 * @defgroup mul_thresh_macros Preprocessor macros associated with multiplication algorithm thresholds
 * @{
 */

/// The threshold where Toom-Cook-3 multiplication becomes optimal
#define MUL_TOOM33_THRESHOLD        100

/// The threshold where Toom-Cook-2 multiplication becomes optimal
#define MUL_TOOM22_THRESHOLD        30

/// The threshold where Toom-Cook-3 squaring becomes optimal
#define SQR_TOOM3_THRESHOLD         120

/// The threshold where Toom-Cook-2 squaring becomes optimal
#define SQR_TOOM2_THRESHOLD         50

/**
 * @}
 */


/**
 * @defgroup range_macros Preprocessor macros associated with value range
 * @{
 */

/// Check if a value is greater than or equal to a defined threshold
#define ABOVE_THRESHOLD(v, t) ((t) == 0 || ((t) != std::numeric_limits<T>::max() && (v) >= (t)))

/// Check if a value is less than a defined threshold
#define BELOW_THRESHOLD(v, t)  (!ABOVE_THRESHOLD(v, t))

/// The maximum of two values
#define MAX(x, y) (((x) >= (y))? (x) : (y))

/// The minimum of two values
#define MIN(x, y) (((x) < (y))? (x) : (y))

/// Overlapping array check, xp + xn > yp AND yp + yn > xp
#define ASSERT_ARRAY_OVERLAP(xp, xn, yp, yn) \
  ((xp) + (xn) > (yp) && (yp) + (yn) > (xp))

/// A macro to detect identical or non-overlapping arrays
#define ASSERT_ARRAY_SAME_OR_SEPARATE(xp, xn, yp, yn) \
  ((xp) == (yp) || !ASSERT_ARRAY_OVERLAP(xp, xn, yp, yn))

// Return non-zero if xp,xsize and yp,ysize overlap. If xp+xsize<=yp there's no overlap, or if
// yp+ysize<=xp there's no overlap.  If both these are false, there's an overlap.
#define OVERLAP_P(xp, xsize, yp, ysize) \
    ((xp) + (xsize) > (yp) && (yp) + (ysize) > (xp))

/**
 * @}
 */


/**
 * @defgroup limb_macros Preprocessor macros associated with limb words
 * @{
 */

/// A limb word with only the most significant bit asserted high
#define LIMB_HIGHBIT   (T(1) << (std::numeric_limits<T>::digits - 1))

/// A limb word with all bits asserted high
#define LIMB_MASK      (2 * (T(1) << (std::numeric_limits<T>::digits - 1)) - 1)

/// A limb word with the least significant bit of the upper half-word asserted high
#define HLIMB_BIT      (T(1) << (std::numeric_limits<T>::digits / 2))

/// A limb word with all lower half bits asserted high
#define LLIMB_MASK     (HLIMB_BIT - 1)

/// If the MSB of the limb word is asserted high then return a bit mask, otherwise return 0
#define LIMB_HIGHBIT_TO_MASK(n)                                    \
    ((S(-1) >> 1) < 0 ?                                            \
        S(n) >> (std::numeric_limits<T>::digits - 1) :             \
        (n) & LIMB_HIGHBIT ? std::numeric_limits<T>::max() : T(0))

/// Extract a limb from two contiguous limbs at a bit offset, (xh << bits) | (xl >> (log2(B) - bits))
#define EXTRACT_LIMB(bits, xh, xl)                                 \
    ((((xh) << (bits)) & LIMB_MASK) |                              \
    ((xl) >> (std::numeric_limits<T>::digits - (bits))))

/**
 * @}
 */
