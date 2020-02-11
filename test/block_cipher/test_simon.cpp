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

#include "../../include/block_cipher/simon.h"
#include "../../include/util/hex.h"

using namespace mockup::crypto::cipher;
using namespace mockup::crypto::util;

struct st_testvector {
    uint8_t mk[64];
    uint8_t pt[32];
    uint8_t ct[32];
};

static const st_testvector TV32_64 {
    {0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19},
    {0x77, 0x68, 0x65, 0x65},
    {0xbb, 0xe9, 0x9b, 0xc6},
};

static const st_testvector TV64_96 {
    {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13},
    {0x63, 0x6c, 0x69, 0x6e, 0x67, 0x20, 0x72, 0x6f},
    {0xc8, 0x8f, 0x1a, 0x11, 0x7f, 0xe2, 0xa2, 0x5c},
};

static const st_testvector TV64_128 {
    {0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0a, 0x0b, 0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1a, 0x1b},
    {0x75, 0x6e, 0x64, 0x20, 0x6c, 0x69, 0x6b, 0x65},
    {0x7a, 0xa0, 0xdf, 0xb9, 0x20, 0xfc, 0xc8, 0x44},
};

static const st_testvector TV128_128 {
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    {0x20, 0x74, 0x72, 0x61, 0x76, 0x65, 0x6c, 0x6c, 0x65, 0x72, 0x73, 0x20, 0x64, 0x65, 0x73, 0x63},
    {0xbc, 0x0b, 0x4e, 0xf8, 0x2a, 0x83, 0xaa, 0x65, 0x3f, 0xfe, 0x54, 0x1e, 0x1e, 0x1b, 0x68, 0x49},
};

static const st_testvector TV128_192 {
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 
    },
    {0x72, 0x69, 0x62, 0x65, 0x20, 0x77, 0x68, 0x65, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x72, 0x65, 0x20},
    {0x5b, 0xb8, 0x97, 0x25, 0x6e, 0x8d, 0x9c, 0x6c, 0x4f, 0x0d, 0xdc, 0xfc, 0xef, 0x61, 0xac, 0xc4},
};

static const st_testvector TV128_256 {
    {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 
    },
    {0x69, 0x73, 0x20, 0x61, 0x20, 0x73, 0x69, 0x6d, 0x6f, 0x6f, 0x6d, 0x20, 0x69, 0x6e, 0x20, 0x74},
    {0x68, 0xb8, 0xe7, 0xef, 0x87, 0x2a, 0xf7, 0x3b, 0xa0, 0xa3, 0xc8, 0xaf, 0x79, 0x55, 0x2b, 0x8d},
};

void test_cipher(BlockCipher* cipher, size_t keylen, const st_testvector tv)
{
    const size_t blocksize = cipher->blocksize();
    uint8_t enc[blocksize] = {0};
    uint8_t dec[blocksize] = {0};
    
    cipher->init(tv.mk, keylen);
    cipher->encryptBlock(enc, tv.pt);
    cipher->decryptBlock(dec, tv.ct);

    std::cout << cipher->name() << std::endl;
    if (memcmp(tv.ct, enc, blocksize) != 0) {
        print_hex("    ct:", tv.ct, blocksize);
        print_hex("   enc:", enc, blocksize);
    } else {
        std::cout << "   enc pass" << std::endl;
    }

    if (memcmp(tv.pt, dec, blocksize) != 0) {
        print_hex("    pt:", tv.pt, blocksize);
        print_hex("   dec:", dec, blocksize);
    } else {
        std::cout << "   dec pass" << std::endl;
    }
    std::cout << std::endl;
}

void test_32_64() {
    Simon32 simon;
    test_cipher(&simon, BIT_64, TV32_64);
}

void test_64_96() {
    Simon64 simon;
    test_cipher(&simon, BIT_96, TV64_96);
}

void test_64_128() {
    Simon64 simon;
    test_cipher(&simon, BIT_128, TV64_128);
}

void test_128_128() {
    Simon128 simon;
    test_cipher(&simon, BIT_128, TV128_128);
}

void test_128_192() {
    Simon128 simon;
    test_cipher(&simon, BIT_192, TV128_192);
}

void test_128_256() {
    Simon128 simon;
    test_cipher(&simon, BIT_256, TV128_256);
}

int main()
{
    test_32_64();
    test_64_96();
    test_64_128();
    test_128_128();
    test_128_192();
    test_128_256();

    return 0;
}