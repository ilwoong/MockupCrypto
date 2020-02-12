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

#include "../../include/padding/pkcs7_padding.h"

using namespace mockup::crypto::padding;

const std::string Pkcs7Padding::name() const
{
    return "PKCS7Padding";
}

void Pkcs7Padding::Pad(uint8_t* dst, const uint8_t* src, size_t srclen)
{
    auto pad = static_cast<uint8_t>(_blocksize - srclen);
    std::copy(src, src + srclen, dst);
    std::fill(dst + srclen, dst + _blocksize, pad);
}

size_t Pkcs7Padding::UnPad(uint8_t* dst, const uint8_t* src)
{
    auto pad = src[_blocksize - 1];
    size_t length = _blocksize - pad;

    for (auto i = length; i < _blocksize; ++i) {
        if (src[i] != pad) {
            throw "Invalid padding";
        }
    }

    std::copy(src, src + length, dst);

    return length;
}

