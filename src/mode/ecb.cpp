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

#include "../../include/mode/ecb.h"

using namespace mockup::crypto;
using namespace mockup::crypto::mode;

const std::string Ecb::name() const
{
    return "ECB/" + _cipher->name();
}

void Ecb::initMode(CipherMode mode, const uint8_t* iv, size_t ivLen)
{
    _mode = mode;
}

size_t Ecb::doFinal(uint8_t* out)
{
    return (_padding != nullptr) ? DoFinalWithPadding(out) : DoFinalWithoutPadding(out);
}

void Ecb::updateBlock(uint8_t* out, const uint8_t* in)
{
    if (_mode == CipherMode::ENCRYPT) {
        _cipher->encryptBlock(out, in);

    } else {
        _cipher->decryptBlock(out, in);
    }
}

size_t Ecb::DoFinalWithPadding(uint8_t* out)
{
    std::vector<uint8_t> padded(_blocksize);
    auto pdata = padded.data();

    if (_mode == CipherMode::ENCRYPT) {
        _padding->Pad(pdata, _buffer.data(), _buffer.size());
        _cipher->encryptBlock(out, pdata);

    } else {
        if (_buffer.size() != _blocksize) {
            throw "Illegal length";
        }
        
        _cipher->decryptBlock(pdata, _buffer.data());
        _padding->UnPad(out, pdata);
    }
}

size_t Ecb::DoFinalWithoutPadding(uint8_t* out)
{
    auto residue = _buffer.size();
    if (residue == 0) {
        return 0;

    } else if (residue != _blocksize) {
        throw "Illegal length";
    }

    updateBlock(out, _buffer.data());
    return _blocksize;
}