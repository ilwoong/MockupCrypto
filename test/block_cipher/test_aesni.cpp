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

#include "../../include/block_cipher/aesni.h"
#include "test_tool.h"
#include "test_ocb.h"

#include <cstdio>
#include <algorithm>

using namespace mockup::crypto;
using namespace mockup::crypto::block_cipher;
using namespace mockup::crypto::mode;
using namespace mockup::crypto::util;

static void test_128(void)
{
    uint8_t mk[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    uint8_t pt[] = {
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34
    };

    uint8_t ct[] = {
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32
    };
    
    constexpr auto blocksize = 16;
    constexpr auto keysize = 16;
    auto cipher = std::make_shared<AesNI>();
    test_cipher<blocksize, keysize>(cipher, mk, pt, ct);
}

static void test_192() 
{
    uint8_t mk[] = {
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b
    };

    uint8_t pt[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    uint8_t ct[] = {
        0xbd, 0x33, 0x4f, 0x1d, 0x6e, 0x45, 0xf2, 0x5f, 0xf7, 0x12, 0xa2, 0x14, 0x57, 0x1f, 0xa5, 0xcc
    };
    
    constexpr auto blocksize = 16;
    constexpr auto keysize = 24;
    auto cipher = std::make_shared<AesNI>();
    test_cipher<blocksize, keysize>(cipher, mk, pt, ct);
}

static void test_256() 
{
    uint8_t mk[] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };

    uint8_t pt[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    uint8_t ct[] = {
        0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
    };
    
    constexpr auto blocksize = 16;
    constexpr auto keysize = 32;
    auto cipher = std::make_shared<AesNI>();
    test_cipher<blocksize, keysize>(cipher, mk, pt, ct);
}

static void aes_ocb_test()
{
    uint8_t mk[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    uint8_t iv[] = {0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x01};
    uint8_t pt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    uint8_t ct[] = {0x68, 0x20, 0xB3, 0x65, 0x7B, 0x6F, 0x61, 0x5A, 0x57, 0x25, 0xBD, 0xA0, 0xD3, 0xB4, 0xEB, 0x3A, 0x25, 0x7C, 0x9A, 0xF1, 0xF8, 0xF0, 0x30, 0x09};
    
    uint8_t enc[8+16] = {0};
    uint8_t dec[8] = {0};

    std::shared_ptr<BufferedBlockCipherAead> ocb = std::make_shared<OCB3>();
    ocb->initCipher(std::make_shared<AesNI>(), mk, 16);
    ocb->initMode(BufferedBlockCipher::CipherMode::ENCRYPT, iv, 12, 16);
    ocb->updateAAD(pt, 8);
    ocb->doFinal(enc, pt, 8);

    print_hex("enc", enc, 8+16);
    print_hex(" ct",  ct, 8+16);
}

static void benchmark()
{
    uint8_t mk[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t pt[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t ct[] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};
    
    uint8_t enc[16] = {0};
    uint8_t dec[16] = {0};

    AesNI aes;
    aes.init(mk, 16);

    size_t iterations = 10000;
    size_t start = rdtsc();
    for (auto i = 0; i < iterations; ++i) {
        aes.encryptBlock(enc, pt);
    }
    size_t end = rdtsc();
    size_t elapsed = end - start;

    std::cout << "elapsed: " << elapsed << std::endl;
    std::cout << "cpb: " << static_cast<double>(elapsed) / (iterations * 16) << std::endl;
}

int main(int argc, const char** argv)
{
    test_128();
    test_192();
    test_256();

    aes_ocb_test();

    benchmark_ocb(std::make_shared<AesNI>(), 16, 4096, 0, 16);
    benchmark_ocb(std::make_shared<AesNI>(), 16, 4096, 4096, 16);

    benchmark();

    benchmark_ctr(std::make_shared<AesNI>(), 16, 4096);

    return 0;
}