/**
 * The MIT License
 *
 * Copyright (c) 2020 Ilwoong Jeong (https://github.com/ilwoong)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "../../include/util/byte_array.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

using namespace mockup::crypto::util;

static inline uint8_t htoi(char letter) 
{
    if (letter >= '0' && letter <= '9') {
        return letter - '0';
    }

    if (letter >= 'a' && letter <= 'f') {
        return letter - 'a' + 10;
    }

    if (letter >= 'A' && letter <= 'F') {
        return letter - 'A' + 10;
    }

    return 0;
}

bytearray_t mockup::crypto::util::toByteArray(std::string str)
{
    auto result = std::vector<uint8_t>{};

    str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
    str.erase(std::remove(str.begin(), str.end(), '\t'), str.end());

    for (auto i = 0; i < str.length(); i += 2) {
        uint8_t data = htoi(str[i]) * 16 + htoi(str[i+1]);
        result.push_back(data);
    }

    return result;
}

std::string mockup::crypto::util::toString(const bytearray_t& array)
{
    std::ostringstream oss;

    oss << std::hex;

    for (auto elem : array) {
        oss << std::setw(2) << std::setfill('0');
        oss << +elem;
    }

    return oss.str();
}