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

#include "../../include/mode/ctr.h"
#include "../../include/util/arrays.h"

using namespace mockup::crypto::mode;
using namespace mockup::crypto::util;

const std::string CTR::name() const
{
    return "CTR/" + _cipher->name();
}

void CTR::initMode(CipherMode mode, const uint8_t* iv, size_t ivLen)
{
    _counter.clear();
    _counter.assign(_blocksize, 0x00);
    std::copy(iv, iv + ivLen, _counter.data());
}

size_t CTR::doFinal(uint8_t* out)
{
    auto outlen = 0;
    auto offset = _buffer.size();

    if (offset > 0) {
        uint8_t ks[64] = {0};

        _cipher->encryptBlock(ks, _counter.data());
        increaseCounter();

        bitwise_xor(out, _buffer.data(), ks, offset);

        outlen += offset;
    }

    return outlen;
}

void CTR::updateBlock(uint8_t* out, const uint8_t* in)
{
    uint8_t ks[64] = {0};

    _cipher->encryptBlock(ks, _counter.data());
    increaseCounter();

    bitwise_xor(out, in, ks, _blocksize);
}

void CTR::increaseCounter()
{
    for (auto i = _counter.size(); ++_counter[i] == 0; --i) {
        if (i == 0) {
            break;
        }
    }
}