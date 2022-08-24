/*****************************************************************************
 * Copyright (C) Neil Smyth 2020                                             *
 *                                                                           *
 * This file is part of phantom.                                             *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#include <iostream>
#include <memory>
#include "./lest.hpp"
#include "./phantom.hpp"

namespace phantom {

const lest::test specification[] =
{
    CASE("Get version")
    {
        std::string version = build_info::version();
        //EXPECT(version == (PHANTOM_BUILD_VERSION));
        std::cout << "version: " << version << std::endl;
    },
    CASE("Get build date")
    {
        std::string version = build_info::build_date();
        //EXPECT(version == (PHANTOM_BUILD_VERSION));
        std::cout << "build date: " << version << std::endl;
    },
    CASE("Get compiler")
    {
        std::string version = build_info::compiler();
        //EXPECT(version == (PHANTOM_BUILD_VERSION));
        std::cout << "compiler: " << version << std::endl;
    },
};

}  // namespace phantom

int main(int argc, char *argv[])
{
    return lest::run(phantom::specification, argc, argv);
}

