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

#ifndef __TEST_TOOLS_H__
#define __TEST_TOOLS_H__

#include <iostream>

#include "../../include/block_cipher.h"
#include "../../include/util/hex.h"

using namespace mockup::crypto;
using namespace mockup::crypto::util;

template <size_t blocksize>
void compare_block(std::string title, const uint8_t* pt, const uint8_t* ct, const uint8_t* enc, const uint8_t* dec)
{
    int out = 0;
    if(std::equal(ct, ct + blocksize, enc) == false) out=1;
    if(std::equal(pt, pt + blocksize, dec) == false) out|=2;

    std::cout << title << std::endl;
    print_hex("pt", dec, blocksize);
    print_hex("ct", enc, blocksize);

    if (out == 0) {
        printf("passed\n");
    }

    if (out & 0x1) {
        printf("encryption failed\n");
    }

    if (out & 0x2) {
        printf("decryption failed\n");
    }
    printf("\n");
}

template <size_t blocksize, size_t keysize>
void test_cipher(std::shared_ptr<BlockCipher> cipher, const uint8_t* mk, const uint8_t* pt, const uint8_t* ct)
{
    std::array<uint8_t, blocksize> enc;
    std::array<uint8_t, blocksize> dec;

    cipher->init(mk, keysize);
    cipher->encryptBlock(enc.data(), pt);
    cipher->decryptBlock(dec.data(), ct);

    compare_block<blocksize>(cipher->name(), pt, ct, enc.data(), dec.data());
}

inline uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

#endif