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

#include "../../include/block_cipher/lea.h"
#include "test_tool.h"

using namespace mockup::crypto;
using namespace mockup::crypto::block_cipher;
using namespace mockup::crypto::util;

static void lea128_self_test(void)
{
    uint8_t mk[] = {
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0
    };

    uint8_t pt[] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    uint8_t ct[] = {
        0x9f, 0xc8, 0x4e, 0x35, 0x28, 0xc6, 0xc6, 0x18, 0x55, 0x32, 0xc7, 0xa7, 0x04, 0x64, 0x8b, 0xfd
    };
    
    constexpr auto blocksize = 16;
    constexpr auto keysize = 16;
    auto cipher = std::make_shared<Lea>();
    test_cipher<blocksize, keysize>(cipher, mk, pt, ct);
}

static void lea192_self_test() 
{
    uint8_t mk[] = {
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    };

    uint8_t pt[] = {
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };

    uint8_t ct[] = {
        0x6f, 0xb9, 0x5e, 0x32, 0x5a, 0xad, 0x1b, 0x87, 0x8c, 0xdc, 0xf5, 0x35, 0x76, 0x74, 0xc6, 0xf2
    };
    
    constexpr auto blocksize = 16;
    constexpr auto keysize = 24;
    auto cipher = std::make_shared<Lea>();
    test_cipher<blocksize, keysize>(cipher, mk, pt, ct);
}

static void lea256_self_test() 
{
    uint8_t mk[] = {
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f,
    };

    uint8_t pt[] = {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };

    uint8_t ct[] = {
        0xd6, 0x51, 0xaf, 0xf6, 0x47, 0xb1, 0x89, 0xc1, 0x3a, 0x89, 0x00, 0xca, 0x27, 0xf9, 0xe1, 0x97
    };
    
    constexpr auto blocksize = 16;
    constexpr auto keysize = 32;
    auto cipher = std::make_shared<Lea>();
    test_cipher<blocksize, keysize>(cipher, mk, pt, ct);
}

int main(int argc, const char** argv)
{
    lea128_self_test();
    lea192_self_test();
    lea256_self_test();

    return 0;
}