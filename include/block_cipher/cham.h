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

#ifndef __MOCKUP_CRYPTO_BLOCKCIPHER_CHAM_H__
#define __MOCKUP_CRYPTO_BLOCKCIPHER_CHAM_H__

#include <array>
#include <sstream>

#include "../block_cipher.h"
#include "../arx_primitive.h"
#include "../util/safe_delete.h"

namespace mockup { namespace crypto { namespace block_cipher {

    using namespace mockup::crypto;
    using namespace mockup::crypto::util;

    constexpr size_t CHAM64_ROUNDS = 88;
    constexpr size_t CHAM128_ROUNDS = 112;
    constexpr size_t CHAM256_ROUNDS = 120;
    
    template <size_t BLOCKSIZE, size_t KEYSIZE, typename WORD_T>
    class Cham : public BlockCipher, public ArxPrimitive<WORD_T> 
    {
        using Arx = ArxPrimitive<WORD_T>;

    private:
        WORD_T* _rks;
        size_t _rounds;
        std::array<WORD_T, 4> _block;

    public:
        Cham() : _rks(nullptr) {}

        ~Cham() {
            safe_delete_array(_rks);
        }

        const std::string name() const override
        {
            auto ss = std::stringstream{};
            ss << "CHAM-" << (BLOCKSIZE << 3) << "-" << (KEYSIZE << 3);
            return ss.str();
        }

        size_t keysize() const override
        {
            return KEYSIZE;
        }

        size_t blocksize() const override
        {
            return BLOCKSIZE;
        }

        void init(const uint8_t* mk, size_t keylen) override
        {
            if (BLOCKSIZE == 8) {
                _rounds = 88;
            } else {
                if (KEYSIZE == 16) {
                    _rounds = 112;
                } else {
                    _rounds = 120;
                }
            }

            safe_delete_array(_rks);
            _rks = new WORD_T[keylen];
            auto dist = KEYSIZE / sizeof(WORD_T);
            auto key = reinterpret_cast<const WORD_T*>(mk);
            auto rk = _rks;

            for (auto i = 0; i < dist; ++i) {
                rk[i] = key[i] ^ Arx::rotl(key[i], 1);
                rk[(i + dist) ^ (0x1)] = rk[i] ^ Arx::rotl(key[i], 11);
                rk[i] ^= Arx::rotl(key[i], 8);
            }
        }

        void encryptBlock(uint8_t* out, const uint8_t* in) override
        {
            auto rk = _rks;
            auto pin = reinterpret_cast<const WORD_T*>(in);
            std::copy(pin, pin + 4, _block.begin());

            auto dist = KEYSIZE / sizeof(WORD_T);

            auto toggle = true;
            auto rc = 0;
            for (auto round = 0; round < _rounds; round += 8) {
                _block[0] = Arx::rotl((_block[0] ^ (rc++)) + (Arx::rotl(_block[1], 1) ^ rk[0]), 8);
                _block[1] = Arx::rotl((_block[1] ^ (rc++)) + (Arx::rotl(_block[2], 8) ^ rk[1]), 1);
                _block[2] = Arx::rotl((_block[2] ^ (rc++)) + (Arx::rotl(_block[3], 1) ^ rk[2]), 8);
                _block[3] = Arx::rotl((_block[3] ^ (rc++)) + (Arx::rotl(_block[0], 8) ^ rk[3]), 1);

                _block[0] = Arx::rotl((_block[0] ^ (rc++)) + (Arx::rotl(_block[1], 1) ^ rk[4]), 8);
                _block[1] = Arx::rotl((_block[1] ^ (rc++)) + (Arx::rotl(_block[2], 8) ^ rk[5]), 1);
                _block[2] = Arx::rotl((_block[2] ^ (rc++)) + (Arx::rotl(_block[3], 1) ^ rk[6]), 8);
                _block[3] = Arx::rotl((_block[3] ^ (rc++)) + (Arx::rotl(_block[0], 8) ^ rk[7]), 1);

                if (dist == 8) {
                    rk = toggle ? _rks + 8 : _rks;
                    toggle = !toggle;
                }
            }

            auto pout = reinterpret_cast<WORD_T*>(out);
            std::copy(_block.begin(), _block.end(), pout);
        }

        void decryptBlock(uint8_t* out, const uint8_t* in) override
        {
            auto rk = _rks;
            auto pin = reinterpret_cast<const WORD_T*>(in);
            std::copy(pin, pin + 4, _block.begin());

            auto dist = KEYSIZE / sizeof(WORD_T);

            auto toggle = false;
            auto rc = _rounds;
            for (auto round = 0; round < _rounds; round += 8) {
                if (dist == 8) {
                    rk = toggle ? _rks + 8 : _rks;
                    toggle = !toggle;
                }

                _block[3] = (Arx::rotr(_block[3], 1) - (Arx::rotl(_block[0], 8) ^ rk[7])) ^ (--rc);
                _block[2] = (Arx::rotr(_block[2], 8) - (Arx::rotl(_block[3], 1) ^ rk[6])) ^ (--rc);
                _block[1] = (Arx::rotr(_block[1], 1) - (Arx::rotl(_block[2], 8) ^ rk[5])) ^ (--rc);
                _block[0] = (Arx::rotr(_block[0], 8) - (Arx::rotl(_block[1], 1) ^ rk[4])) ^ (--rc);

                _block[3] = (Arx::rotr(_block[3], 1) - (Arx::rotl(_block[0], 8) ^ rk[3])) ^ (--rc);
                _block[2] = (Arx::rotr(_block[2], 8) - (Arx::rotl(_block[3], 1) ^ rk[2])) ^ (--rc);
                _block[1] = (Arx::rotr(_block[1], 1) - (Arx::rotl(_block[2], 8) ^ rk[1])) ^ (--rc);
                _block[0] = (Arx::rotr(_block[0], 8) - (Arx::rotl(_block[1], 1) ^ rk[0])) ^ (--rc);
            }

            auto pout = reinterpret_cast<WORD_T*>(out);
            std::copy(_block.begin(), _block.end(), pout);
        }
    };

    using Cham_64_128 = Cham<8, 16, uint16_t>;
    using Cham_128_128 = Cham<16, 16, uint32_t>;
    using Cham_128_256 = Cham<16, 32, uint32_t>;
}}}

#endif