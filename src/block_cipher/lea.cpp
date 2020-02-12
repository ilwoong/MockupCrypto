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

#include <sstream>

#include "../../include/util/safe_delete.h"

using namespace mockup::crypto::block_cipher;
using namespace mockup::crypto::util;

static constexpr size_t LEA128_ROUNDS = 24;
static constexpr size_t LEA192_ROUNDS = 28;
static constexpr size_t LEA256_ROUNDS = 32;

static constexpr uint32_t DELTA[8]= {
    0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 
    0x715ea49e, 0xc785da0a, 0xe04ef22a, 0xe5c40957,
};

Lea::Lea() : _rks(nullptr)
{
}

Lea::~Lea() 
{
    safe_delete_array(_rks);
}

const std::string Lea::name() const
{
    auto oss = std::ostringstream{};
    oss << "LEA-128-" << (keysize() << 3);
    return oss.str();
}

size_t Lea::keysize() const 
{
    return _keysize;
}

size_t Lea::blocksize() const
{
    return 16;
}

void Lea::init(const uint8_t* mk, size_t keylen)
{
    auto pmk = reinterpret_cast<const uint32_t*>(mk);

    switch(keylen) {
    case 16:        
        init128(pmk);
        break;

    case 24:        
        init192(pmk);
        break;

    case 32:
        init256(pmk);
        break;
    }
}

void Lea::init128(const uint32_t* mk)
{
    _keysize = 16;
    _rounds = LEA128_ROUNDS;
    safe_delete_array(_rks);
    _rks = new uint32_t[6 * _rounds];

    auto rk = _rks;
    auto t = std::array<uint32_t, 4>{};
    std::copy(mk, mk + 4, t.begin());

    for(auto round = 0; round < LEA128_ROUNDS; ++round) {
        auto delta = DELTA[round & 3];
        
        t[0] = Arx::rotl(t[0] + Arx::rotl(delta, round), 1);
        t[1] = Arx::rotl(t[1] + Arx::rotl(delta, round + 1), 3);
        t[2] = Arx::rotl(t[2] + Arx::rotl(delta, round + 2), 6);
        t[3] = Arx::rotl(t[3] + Arx::rotl(delta, round + 3), 11);

        rk[0] = t[0];
        rk[1] = t[1];
        rk[2] = t[2];
        rk[3] = t[1];
        rk[4] = t[3];
        rk[5] = t[1];
        rk += 6;
    }
}

void Lea::init192(const uint32_t* mk)
{
    _keysize = 24;
    _rounds = LEA192_ROUNDS;
    safe_delete_array(_rks);
    _rks = new uint32_t[6 * _rounds];

    auto rk = _rks;
    auto t = std::array<uint32_t, 6>{};
    std::copy(mk, mk + 6, t.begin());

    for(auto round = 0; round < LEA192_ROUNDS; ++round) {
        auto delta = DELTA[round % 6];
        
        t[0] = Arx::rotl(t[0] + Arx::rotl(delta, round), 1);
        t[1] = Arx::rotl(t[1] + Arx::rotl(delta, round + 1), 3);
        t[2] = Arx::rotl(t[2] + Arx::rotl(delta, round + 2), 6);
        t[3] = Arx::rotl(t[3] + Arx::rotl(delta, round + 3), 11);
        t[4] = Arx::rotl(t[4] + Arx::rotl(delta, round + 4), 13);
        t[5] = Arx::rotl(t[5] + Arx::rotl(delta, round + 5), 17);

        rk[0] = t[0];
        rk[1] = t[1];
        rk[2] = t[2];
        rk[3] = t[3];
        rk[4] = t[4];
        rk[5] = t[5];
        rk += 6;
    }
}

void Lea::init256(const uint32_t* mk)
{
    _keysize = 32;
    _rounds = LEA256_ROUNDS;
    safe_delete_array(_rks);
    _rks = new uint32_t[6 * _rounds];

    auto rk = _rks;
    auto t = std::array<uint32_t, 8>{};
    std::copy(mk, mk + 8, t.begin());

    for(auto round = 0; round < LEA256_ROUNDS; ++round) {
        auto delta = DELTA[round & 0x7];
        
        t[(6 * round) & 0x7] = Arx::rotl(t[(6 * round) & 0x7] + Arx::rotl(delta, round), 1);
        t[(6 * round + 1) & 0x7] = Arx::rotl(t[(6 * round + 1) & 0x7] + Arx::rotl(delta, round + 1), 3);
        t[(6 * round + 2) & 0x7] = Arx::rotl(t[(6 * round + 2) & 0x7] + Arx::rotl(delta, round + 2), 6);
        t[(6 * round + 3) & 0x7] = Arx::rotl(t[(6 * round + 3) & 0x7] + Arx::rotl(delta, round + 3), 11);
        t[(6 * round + 4) & 0x7] = Arx::rotl(t[(6 * round + 4) & 0x7] + Arx::rotl(delta, round + 4), 13);
        t[(6 * round + 5) & 0x7] = Arx::rotl(t[(6 * round + 5) & 0x7] + Arx::rotl(delta, round + 5), 17);

        rk[0] = t[(6 * round) & 0x7];
        rk[1] = t[(6 * round + 1) & 0x7];
        rk[2] = t[(6 * round + 2) & 0x7];
        rk[3] = t[(6 * round + 3) & 0x7];
        rk[4] = t[(6 * round + 4) & 0x7];
        rk[5] = t[(6 * round + 5) & 0x7];
        rk += 6;
    }
}

void Lea::encryptBlock(uint8_t* out, const uint8_t* in)
{
    auto rk = _rks;
    auto pin = reinterpret_cast<const uint32_t*>(in);
    std::copy(pin, pin + 4, _block.begin());

    for (auto round = 0; round < _rounds; round += 4) {
        _block[3] = Arx::rotr((_block[2] ^ rk[4]) + (_block[3] ^ rk[5]), 3);
        _block[2] = Arx::rotr((_block[1] ^ rk[2]) + (_block[2] ^ rk[3]), 5);
        _block[1] = Arx::rotl((_block[0] ^ rk[0]) + (_block[1] ^ rk[1]), 9);
        rk += 6;

        _block[0] = Arx::rotr((_block[3] ^ rk[4]) + (_block[0] ^ rk[5]), 3);
        _block[3] = Arx::rotr((_block[2] ^ rk[2]) + (_block[3] ^ rk[3]), 5);
        _block[2] = Arx::rotl((_block[1] ^ rk[0]) + (_block[2] ^ rk[1]), 9);
        rk += 6;

        _block[1] = Arx::rotr((_block[0] ^ rk[4]) + (_block[1] ^ rk[5]), 3);
        _block[0] = Arx::rotr((_block[3] ^ rk[2]) + (_block[0] ^ rk[3]), 5);
        _block[3] = Arx::rotl((_block[2] ^ rk[0]) + (_block[3] ^ rk[1]), 9);
        rk += 6;

        _block[2] = Arx::rotr((_block[1] ^ rk[4]) + (_block[2] ^ rk[5]), 3);
        _block[1] = Arx::rotr((_block[0] ^ rk[2]) + (_block[1] ^ rk[3]), 5);
        _block[0] = Arx::rotl((_block[3] ^ rk[0]) + (_block[0] ^ rk[1]), 9);
        rk += 6;
    }

    auto pout = reinterpret_cast<uint32_t*>(out);
    std::copy(_block.begin(), _block.end(), pout);
}

void Lea::decryptBlock(uint8_t* out, const uint8_t* in)
{
    auto rk = _rks;
    auto pin = reinterpret_cast<const uint32_t*>(in);
    std::copy(pin, pin + 4, _block.begin());

    rk += 6 * (_rounds - 1);
    for (auto round = 0; round < _rounds; round += 4) {
        _block[0] = (Arx::rotr(_block[0], 9) - (_block[3] ^ rk[0])) ^ rk[1];
        _block[1] = (Arx::rotl(_block[1], 5) - (_block[0] ^ rk[2])) ^ rk[3];
        _block[2] = (Arx::rotl(_block[2], 3) - (_block[1] ^ rk[4])) ^ rk[5];
        rk -= 6;

        _block[3] = (Arx::rotr(_block[3], 9) - (_block[2] ^ rk[0])) ^ rk[1];
        _block[0] = (Arx::rotl(_block[0], 5) - (_block[3] ^ rk[2])) ^ rk[3];
        _block[1] = (Arx::rotl(_block[1], 3) - (_block[0] ^ rk[4])) ^ rk[5];
        rk -= 6;

        _block[2] = (Arx::rotr(_block[2], 9) - (_block[1] ^ rk[0])) ^ rk[1];
        _block[3] = (Arx::rotl(_block[3], 5) - (_block[2] ^ rk[2])) ^ rk[3];
        _block[0] = (Arx::rotl(_block[0], 3) - (_block[3] ^ rk[4])) ^ rk[5];
        rk -= 6;

        _block[1] = (Arx::rotr(_block[1], 9) - (_block[0] ^ rk[0])) ^ rk[1];
        _block[2] = (Arx::rotl(_block[2], 5) - (_block[1] ^ rk[2])) ^ rk[3];
        _block[3] = (Arx::rotl(_block[3], 3) - (_block[2] ^ rk[4])) ^ rk[5];
        rk -= 6;
    }

    auto pout = reinterpret_cast<uint32_t*>(out);
    std::copy(_block.begin(), _block.end(), pout);
}