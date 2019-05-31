//
// Created by joapil on 2019-05-27.
//

#ifndef TESTING_UCS2_H
#define TESTING_UCS2_H

#include <string>
#include <vector>

namespace ucs2
{
    std::vector<std::uint16_t> utf8_to_ucs2(const std::string& utf8Str);

    std::string ucs2_to_utf8(const std::vector<std::uint16_t>& ucs2Str);
}

#endif //TESTING_UCS2_H
