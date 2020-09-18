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

#include "../include/pbkdf2.h"
#include "../include/mac/hmac.h"

#include <algorithm>
#include <functional>

using namespace mockup::crypto;
using namespace mockup::crypto::mac;

static std::vector<uint8_t> i2bs(uint32_t i)
{
    std::vector<uint8_t> bs;

    bs.push_back(i >> 24);
    bs.push_back(i >> 16);    
    bs.push_back(i >> 8);
    bs.push_back(i);

    return bs;
}

Pbkdf2::Pbkdf2(std::shared_ptr<Hash> hash)
{
    hmac = std::make_shared<Hmac>(hash);
}

const std::string Pbkdf2::name() const 
{
    return "PBKDF2-" + hmac->name();
}

std::vector<uint8_t> Pbkdf2::derive(const std::vector<uint8_t>& password, const std::vector<uint8_t>& salt, size_t iterations, size_t outsize)
{
    std::vector<uint8_t> derived;

    uint32_t idx = 1;
    while (outsize > 0) {
        hmac->init(password);
        hmac->update(salt);
        hmac->update(i2bs(idx));
        auto chunk = hmac->doFinal();
        auto block = std::vector<uint8_t>(chunk);

        for (auto i = 1; i < iterations; ++i) {
            hmac->init(password);
            hmac->update(chunk);
            chunk = hmac->doFinal();

            std::transform(chunk.begin(), chunk.end(), block.begin(), block.begin(), std::bit_xor<uint8_t>());
        }

        auto len = std::min(chunk.size(), outsize);
        derived.insert(derived.end(), block.begin(), block.begin() + len);
        outsize -= len;
        idx += 1;
    }

    return derived;
}