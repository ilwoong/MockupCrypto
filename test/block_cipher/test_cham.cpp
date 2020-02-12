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

#include "../../include/block_cipher/cham.h"
#include "test_tool.h"

using namespace mockup::crypto;
using namespace mockup::crypto::block_cipher;
using namespace mockup::crypto::util;

static void test_64_128(void)
{
    uint8_t mk[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    uint8_t pt[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    };

    uint8_t ct[] = {
        0x79, 0x65, 0x04, 0x12, 0x3f, 0x12, 0xa9, 0xe5,
    };
    
    constexpr auto blocksize = 8;
    constexpr auto keysize = 16;
    auto cipher = std::make_shared<Cham_64_128>();
    test_cipher<blocksize, keysize>(cipher, mk, pt, ct);
}

static void test_128_128() 
{
    uint8_t mk[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };

    uint8_t pt[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    uint8_t ct[] = {
        0xee, 0x19, 0x54, 0xd0, 0x4c, 0x8f, 0x11, 0x9f, 0x69, 0x64, 0xe3, 0x99, 0xc1, 0x5e, 0x88, 0x1c,
    };
    
    constexpr auto blocksize = 16;
    constexpr auto keysize = 16;
    auto cipher = std::make_shared<Cham_128_128>();
    test_cipher<blocksize, keysize>(cipher, mk, pt, ct);
}

static void test_128_256() 
{
    uint8_t mk[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xF5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };

    uint8_t pt[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    uint8_t ct[] = {
        0xdc, 0x77, 0x73, 0x02, 0x51, 0x56, 0x0b, 0x12, 0x95, 0x9b, 0x83, 0x8f, 0x75, 0xc0, 0x5e, 0x5e
    };
    
    constexpr auto blocksize = 16;
    constexpr auto keysize = 32;
    auto cipher = std::make_shared<Cham_128_256>();
    test_cipher<blocksize, keysize>(cipher, mk, pt, ct);
}

int main(int argc, const char** argv)
{
    test_64_128();
    test_128_128();
    test_128_256();

    return 0;
}