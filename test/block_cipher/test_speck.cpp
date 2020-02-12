/**
 * The MIT License
 *
 * Copyright (c) 2019 Ilwoong Jeong (https://github.com/ilwoong)
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

#include <iostream>
#include <cstdio>
#include <cstring>

#include "../../include/block_cipher/speck.h"
#include "test_tool.h"

using namespace mockup::crypto::block_cipher;
using namespace mockup::crypto::util;

struct st_testvector {
    uint8_t mk[64];
    uint8_t pt[32];
    uint8_t ct[32];
};

static const st_testvector TV32_64 {
    {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19},
    {0x4c, 0x69, 0x74, 0x65},
    {0xf2, 0x42, 0x68, 0xa8},
};

static const st_testvector TV64_96 {
    {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13},
    {0x65, 0x61, 0x6e, 0x73, 0x20, 0x46, 0x61, 0x74},
    {0x6c, 0x94, 0x75, 0x41, 0xec, 0x52, 0x79, 0x9f},
};

static const st_testvector TV64_128 {
    {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b},
    {0x2d, 0x43, 0x75, 0x74, 0x74, 0x65, 0x72, 0x3b},
    {0x8b, 0x02, 0x4e, 0x45, 0x48, 0xa5, 0x6f, 0x8c},
};

static const st_testvector TV128_128 {
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    {0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74, 0x20, 0x65, 0x71, 0x75, 0x69, 0x76, 0x61, 0x6c},
    {0x18, 0x0d, 0x57, 0x5c, 0xdf, 0xfe, 0x60, 0x78, 0x65, 0x32, 0x78, 0x79, 0x51, 0x98, 0x5d, 0xa6},
};

static const st_testvector TV128_192 {
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
    },
    {0x65, 0x6e, 0x74, 0x20, 0x74, 0x6f, 0x20, 0x43, 0x68, 0x69, 0x65, 0x66, 0x20, 0x48, 0x61, 0x72},
    {0x86, 0x18, 0x3c, 0xe0, 0x5d, 0x18, 0xbc, 0xf9, 0x66, 0x55, 0x13, 0x13, 0x3a, 0xcf, 0xe4, 0x1b},
};

static const st_testvector TV128_256 {
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 
    },
    {0x70, 0x6f, 0x6f, 0x6e, 0x65, 0x72, 0x2e, 0x20, 0x49, 0x6e, 0x20, 0x74, 0x68, 0x6f, 0x73, 0x65},
    {0x43, 0x8f, 0x18, 0x9c, 0x8d, 0xb4, 0xee, 0x4e, 0x3e, 0xf5, 0xc0, 0x05, 0x04, 0x01, 0x09, 0x41},
};

static void test_32_64() {
    constexpr auto blocksize = 4;
    constexpr auto keysize = 8;
    auto tv = TV32_64;
    auto cipher = std::make_shared<Speck32>();
    test_cipher<blocksize, keysize>(cipher, tv.mk, tv.pt, tv.ct);
}

static void test_64_96() {
    constexpr auto blocksize = 8;
    constexpr auto keysize = 12;
    auto tv = TV64_96;
    auto cipher = std::make_shared<Speck64>();
    test_cipher<blocksize, keysize>(cipher, tv.mk, tv.pt, tv.ct);
}

static void test_64_128() {
    constexpr auto blocksize = 8;
    constexpr auto keysize = 16;
    auto tv = TV64_128;
    auto cipher = std::make_shared<Speck64>();
    test_cipher<blocksize, keysize>(cipher, tv.mk, tv.pt, tv.ct);
}

static void test_128_128() {
    constexpr auto blocksize = 16;
    constexpr auto keysize = 16;
    auto tv = TV128_128;
    auto cipher = std::make_shared<Speck128>();
    test_cipher<blocksize, keysize>(cipher, tv.mk, tv.pt, tv.ct);
}

static void test_128_192() {
    constexpr auto blocksize = 16;
    constexpr auto keysize = 24;
    auto tv = TV128_192;
    auto cipher = std::make_shared<Speck128>();
    test_cipher<blocksize, keysize>(cipher, tv.mk, tv.pt, tv.ct);
}

static void test_128_256() {
    constexpr auto blocksize = 16;
    constexpr auto keysize = 32;
    auto tv = TV128_256;
    auto cipher = std::make_shared<Speck128>();
    test_cipher<blocksize, keysize>(cipher, tv.mk, tv.pt, tv.ct);
}

int main(int argc, const char** argv)
{
    test_32_64();
    test_64_96();
    test_64_128();
    test_128_128();
    test_128_192();
    test_128_256();

    uint64_t pt[] = {0x202e72656e6f6f70, 0x65736f6874206e49};
    uint64_t ct[] = {0x4eeeb48d9c188f43, 0x4109010405c0f53e};

    return 0;
}