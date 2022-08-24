/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <cstdint>
#include <vector>

#include "core/reduction_barrett.hpp"
#include "core/reduction_montgomery.hpp"
#include "core/reduction_reference.hpp"


namespace phantom {
namespace core {

/** 
 * @brief Low-level reduction factory class
 * 
 * A factory class used to create new instances of reduction objects
 * derived from the reduction class
 */
class reduction_factory
{
public:
    enum reduction_type_e {
        REDUCTION_REFERENCE = 0,
        REDUCTION_MONTGOMERY,
        REDUCTION_BARRETT,
    };

    template<class C, typename T>
    static reduction<C, T>* create(reduction_type_e type, const reducer<T>& r)
    {
        switch (type)
        {
        case REDUCTION_REFERENCE:
        {
            return new reduction_reference(r);
        }
        case REDUCTION_MONTGOMERY:
        {
            return new reduction_montgomery(r);
        }
        case REDUCTION_BARRETT:
        {
            return new reduction_barrett(r);
        }
        default:
        {
            return 0;
        }
        }
    }

private:
    reduction_factory() {}
    virtual ~reduction_factory() {}
};

}  // namespace core
}  // namespace phantom



