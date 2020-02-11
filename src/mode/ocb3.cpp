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

#include "../../include/mode/ocb3.h"
#include "../../include/util/hex.h"
#include "../../include/util/arrays.h"

#include <cmath>
#include <algorithm>
#include <functional>

using namespace mockup::crypto::mode;
using namespace mockup::crypto::util;

static size_t ntz(size_t i)
{
    return std::log2(i & -i);
}

const std::string OCB3::name() const
{
    return "OCB3/" + _cipher->name();
}

void OCB3::initBlocksize(size_t blocksize)
{
    switch(blocksize)
    {
    case 16:
        _residue = 135;
        _shift = 8;
        _mask = {0b00000000, 0b00111111};
        break;

    case 32:
        _residue = 1061;
        _shift = 1;
        _mask = {0b00000000, 0b11111111};
        break;
    }
}
        
void OCB3::initMode(CipherMode mode, const uint8_t* iv, size_t ivLen, size_t taglen = 0)
{
    initBlocksize(_blocksize);

    _mode = mode;
    _taglen = taglen;

    _deltaAAD.assign(_blocksize, 0);
    _checksum.assign(_blocksize, 0);

    _buffer.assign(_blocksize, 0);
    _lstar.assign(_blocksize, 0);
    _ldollar.assign(_blocksize, 0);
    _auth.assign(_blocksize, 0);

    // init L
    _cipher->encryptBlock(_lstar.data(), _buffer.data());
    _buffer.clear();

    times2(_ldollar, _lstar);
    block_t l0(_blocksize);
    times2(l0, _ldollar);

    _L.clear();
    _L.push_back(l0);

    // nonce = 0...01||iv
    block_t nonce(_blocksize - ivLen - 1, 0x00);
    nonce.push_back(0x01);
    nonce.insert(nonce.end(), iv, iv + ivLen);

    // top = nonce ^ (1...1 || 0...0)
    block_t top(nonce);
    top[_blocksize - 2] &= (_mask[0] ^ 0xff);
    top[_blocksize - 1] &= (_mask[1] ^ 0xff);

    _cipher->encryptBlock(top.data(), top.data());

    size_t bottom = ((nonce[_blocksize - 2] & _mask[0]) << 8) | (nonce[_blocksize-1] & _mask[1]);
    size_t bytes = bottom >> 3;
    size_t bits = bottom & 0x7;

    // stretch = ktop || (ktop ^ (ktop << shift))

    size_t shift_bytes = _shift >> 3;
    size_t shift_bits = _shift & 0b0111;

    //std::cout << shift_bytes << " and " << shift_bits << std::endl;

    block_t stretch(top);
    top.insert(top.end(), _blocksize, 0x00);
    for (auto i = 0; i < _blocksize; ++i) {
        auto shifted = (top[i + shift_bytes] << shift_bits) | (top[i + shift_bytes + 1] >> (8 - shift_bits));
        stretch.push_back(top[i] ^ shifted);
    }
    stretch.insert(stretch.end(), _blocksize, 0x00);

    _delta.assign(_blocksize, 0x00);
    for (auto i = 0; i < _blocksize; ++i) {
        _delta[i] = (stretch[bytes + i] << bits) | (stretch[bytes + i + 1] >> (8-bits));
    }
}

void OCB3::updateAAD(const uint8_t* aad, size_t aadlen)
{
    while (aadlen >= _blocksize) {
        updateAADBlock(aad);

        aad += _blocksize;
        aadlen -= _blocksize;
    }

    if (aadlen > 0) {        
        block_t buffer(aad, aad + aadlen);
        buffer.insert(buffer.end(), _blocksize - buffer.size(), 0);
        buffer[aadlen] = 0x80;

        bitwise_xor(_deltaAAD.data(), _lstar.data(), _blocksize);
        bitwise_xor(buffer.data(), _deltaAAD.data(), _blocksize);
        _cipher->encryptBlock(buffer.data(), buffer.data());        
        bitwise_xor(_auth.data(), buffer.data(), _blocksize);
    }

    _index = 0;
}

void OCB3::updateBlock(uint8_t* out, const uint8_t* in)
{
    block_t buffer(_blocksize);
    
    increaseDelta(_delta);

    bitwise_xor(buffer.data(), in, _delta.data(), _blocksize);
    
    _cipher->encryptBlock(buffer.data(), buffer.data());
    bitwise_xor(out, buffer.data(), _delta.data(), _blocksize);

    bitwise_xor(_checksum.data(), _checksum.data(), in, _blocksize);
}

size_t OCB3::doFinal(uint8_t* out)
{
    auto outlen = 0;
    auto offset = _buffer.size();
    
    if (offset > 0) 
    {   
        _buffer.insert(_buffer.end(), _blocksize - offset, 0);

        block_t pad(_blocksize);
        bitwise_xor(_delta.data(), _lstar.data(), _blocksize);
        _cipher->encryptBlock(pad.data(), _delta.data());
        bitwise_xor(out, pad.data(), _buffer.data(), offset);

        // final checksum
        _buffer[offset] = 0x80;
        bitwise_xor(_checksum.data(), _buffer.data(), _blocksize);

        out += offset;
        outlen += offset;
    }

    outlen += generateTag(out);

    return outlen;
}

void OCB3::times2(block_t& dst, const block_t& src)
{
    for (auto i = 0; i < _blocksize - 1; ++i) 
    {
        dst[i] = (src[i] << 1) | (src[i + 1] >> 7);
    }
    dst[_blocksize - 1] = src[_blocksize - 1] << 1;

    if (src[0] >> 7) {
        dst[_blocksize - 1] ^= static_cast<uint8_t>(_residue >> 0);
        dst[_blocksize - 2] ^= static_cast<uint8_t>(_residue >> 8);
        dst[_blocksize - 3] ^= static_cast<uint8_t>(_residue >> 16);
    }
}

void OCB3::updateAADBlock(const uint8_t* block)
{
    block_t buffer(_blocksize);

    increaseDelta(_deltaAAD);
    bitwise_xor(buffer.data(), block, _delta.data(), _blocksize);
    _cipher->encryptBlock(buffer.data(), buffer.data());
    bitwise_xor(_auth.data(), buffer.data(), _blocksize);
}

void OCB3::increaseDelta(block_t& delta)
{
    _index += 1;

    while (_L.size() < ntz(_index) + 1) {
        block_t doubled(_blocksize);
        times2(doubled, *_L.rbegin());
        _L.push_back(doubled);
    }

    bitwise_xor(delta.data(), _L[ntz(_index)].data(), _blocksize);
}

size_t OCB3::generateTag(uint8_t* out)
{
    auto tag = block_t(_taglen);
    
    bitwise_xor(_delta.data(), _ldollar.data(), _blocksize);
    bitwise_xor(tag.data(), _checksum.data(), _delta.data(), _blocksize);
    
    _cipher->encryptBlock(tag.data(), tag.data());
    bitwise_xor(out, tag.data(), _auth.data(), _taglen);

    return _taglen;
}