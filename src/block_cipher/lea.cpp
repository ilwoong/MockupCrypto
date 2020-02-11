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

#include "../../include/block_cipher/lea.h"
#include "../../include/util/safe_delete.h"

using namespace mockup::crypto::block_cipher;
using namespace mockup::crypto::util;

static constexpr size_t LEA128_ROUNDS = 24;
static constexpr size_t LEA192_ROUNDS = 28;
static constexpr size_t LEA256_ROUNDS = 32;

Lea::Lea() : _rks(nullptr)
{
}

Lea::~Lea() 
{
    safe_delete_array(_rks);
}

const std::string Lea::name() const
{
    return "LEA-" + (keysize() << 3);
}

size_t Lea::keysize() const 
{
    return 16;
}

size_t Lea::blocksize() const
{
    return 16;
}

void Lea::init(const uint8_t* mk, size_t keylen)
{

}

void Lea::encryptBlock(uint8_t* out, const uint8_t* in)
{

}

void Lea::decryptBlock(uint8_t* out, const uint8_t* in)
{

}

size_t Lea::rounds() const 
{
    auto rounds = LEA128_ROUNDS;
    switch(_keysize) {
    case 16:
        rounds = LEA128_ROUNDS;
        break;

    case 24:
        rounds = LEA192_ROUNDS;
        break;

    case 32:
        rounds = LEA256_ROUNDS;
        break;

    default:
        // should be error
        break;
    }

    return rounds;
}