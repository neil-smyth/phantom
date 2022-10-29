/*****************************************************************************
 * Copyright (C) Neil Smyth 2022                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <string>


namespace phantom {
namespace utilities {


/**
 * @brief A class to provide UUID's
 */
class uuid
{
public:
    static std::string generate();
};


}  // namespace utilities
}  // namespace phantom
