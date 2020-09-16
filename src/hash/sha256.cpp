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

#include "../../include/hash/sha2.h"

using namespace mockup::crypto::hash;

Sha256::Sha256() : Sha2()
{
    K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    H = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    init();
}

const std::string Sha256::name() const 
{
    return "SHA256";
}

size_t Sha256::blocksize() const 
{
    return 64;
}

size_t Sha256::outputsize() const 
{
    return 32;
}

void Sha256::init()
{
    offset = 0;
    totalLength = 0;

    W.clear();
    W.assign(64, 0);

    block.clear();
    block.assign(64, 0);

    state.clear();
    state.assign(H.begin(), H.end());
}

void Sha256::expandMessage(const uint8_t* data) 
{
    for (auto i = 0; i < 16; ++i) {                
        W[i]  = static_cast<uint32_t>(data[0]) << 24;
        W[i] |= static_cast<uint32_t>(data[1]) << 16;
        W[i] |= static_cast<uint32_t>(data[2]) << 8;
        W[i] |= static_cast<uint32_t>(data[3]);

        data += 4;
    }

    for (auto t = 16; t < 64; ++t) {
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16];
    }
}

std::vector<uint8_t> Sha256::toOutput() const
{
    std::vector<uint8_t> digest;
    for (auto h : state) {
        digest.push_back(h >> 24);
        digest.push_back(h >> 16);
        digest.push_back(h >> 8);
        digest.push_back(h);
    }

    return digest;
}

void Sha256::processLength()
{
    if (offset > 56) {
        updateBlock(block.data());
        std::fill(block.begin(), block.end(), 0);
    }

    totalLength <<= 3;
    block[56] = totalLength >> 56;
    block[57] = totalLength >> 48;
    block[58] = totalLength >> 40;
    block[59] = totalLength >> 32;
    block[60] = totalLength >> 24;
    block[61] = totalLength >> 16;
    block[62] = totalLength >> 8;
    block[63] = totalLength;
}

uint32_t Sha256::sum0(uint32_t x) const
{
    return Arx::rotr(x, 2) ^ Arx::rotr(x, 13) ^ Arx::rotr(x, 22);
}

uint32_t Sha256::sum1(uint32_t x) const
{
    return Arx::rotr(x, 6) ^ Arx::rotr(x, 11) ^ Arx::rotr(x, 25);
}

uint32_t Sha256::sigma0(uint32_t x) const
{
    return Arx::rotr(x, 7) ^ Arx::rotr(x, 18) ^ (x >> 3);
}

uint32_t Sha256::sigma1(uint32_t x) const
{
    return Arx::rotr(x, 17) ^ Arx::rotr(x, 19) ^ (x >> 10);
}