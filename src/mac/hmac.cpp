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

#include "../../include/mac/hmac.h"

#include <algorithm>
#include <functional>

using namespace mockup::crypto::mac;

Hmac::Hmac(std::shared_ptr<Hash> hash) : hash(hash)
{
    blocksize = hash->blocksize();
    block.assign(blocksize, 0);
}

void Hmac::init(const uint8_t* key, size_t keysize)
{
    offset = 0;

    std::vector<uint8_t> ptr;
    if (keysize > hash->blocksize()) {
        hash->update(key, keysize);
        ptr = hash->doFinal();
    } else {
        ptr.assign(key, key + keysize);
    }

    opad.assign(hash->blocksize(), 0x5c);
    ipad.assign(hash->blocksize(), 0x36);

    std::transform(ptr.begin(), ptr.end(), opad.begin(), opad.begin(), std::bit_xor<uint8_t>());
    std::transform(ptr.begin(), ptr.end(), ipad.begin(), opad.begin(), std::bit_xor<uint8_t>());

    hash->init();
    hash->update(ipad);
}

void Hmac::updateBlock(const uint8_t* data)
{
    hash->update(data, blocksize);
}

std::vector<uint8_t> Hmac::doFinal()
{
    block[offset] = 0x80;
    std::fill(block.begin() + offset + 1, block.end(), 0x00);
    hash->update(block);    
    auto tag = hash->doFinal();
    
    hash->update(opad);
    tag = hash->doFinal(tag);

    return tag;
}

