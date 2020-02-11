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

#ifndef __MOCKUP_CRYPTO_BLOCKCIPHER_SIMON_HPP__
#define __MOCKUP_CRYPTO_BLOCKCIPHER_SIMON_HPP__

#include <cstdint>
#include <array>
#include <sstream>

#include "../block_cipher.h"
#include "../arx_primitive.h"
#include "../util/safe_delete.h"

namespace mockup { namespace crypto { namespace cipher {

    using namespace mockup::crypto;
    using namespace mockup::crypto::util;
    
    template <typename WORD_T>
    class Simon : public BlockCipher, public ArxPrimitive<WORD_T> 
    {
        using Arx = ArxPrimitive<WORD_T>;
        
    private:
        const WORD_T Z0[62] = {1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,1,1,1,1,1,0,1,0,0,0,1,0,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,0,1,1,0,};
        const WORD_T Z1[62] = {1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,1,0,0,0,1,1,1,0,1,1,1,1,1,0,0,1,0,0,1,1,0,0,0,0,1,0,1,1,0,1,0,};
        const WORD_T Z2[62] = {1,0,1,0,1,1,1,1,0,1,1,1,0,0,0,0,0,0,1,1,0,1,0,0,1,0,0,1,1,0,0,0,1,0,1,0,0,0,0,1,0,0,0,1,1,1,1,1,1,0,0,1,0,1,1,0,1,1,0,0,1,1,};
        const WORD_T Z3[62] = {1,1,0,1,1,0,1,1,1,0,1,0,1,1,0,0,0,1,1,0,0,1,0,1,1,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,1,0,1,0,0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,1,1,1,};
        const WORD_T Z4[62] = {1,1,0,1,0,0,0,1,1,1,1,0,0,1,1,0,1,0,1,1,0,1,1,0,0,0,1,0,0,0,0,0,0,1,0,1,1,1,0,0,0,0,1,1,0,0,1,0,1,0,0,1,0,0,1,1,1,0,1,1,1,1,};

        const WORD_T *Z;
        size_t _num_words;
        size_t _num_rounds;
    
    public: 
        WORD_T* _rks;

    public:
        Simon() : _rks(nullptr) {
        }
        
        ~Simon() {
            safe_delete_array(_rks);
        }

        const std::string name() const override
        {
            std::stringstream ss;
            ss << "Simon" << (blocksize() << 3) << "-" << (keysize() << 3);
            return ss.str();
        }

        size_t keysize() const override 
        {
            return (Arx::_wordsize * _num_words) >> 3;
        }

        size_t blocksize() const override 
        {
            return (Arx::_wordsize * 2) >> 3;
        }

        void init(const uint8_t* mk, size_t keylen) override
        {
            setParams(keylen);

            WORD_T* ptr = (WORD_T*)(mk);
            
            std::copy(ptr, ptr + _num_words, _rks);

            for (size_t i = _num_words; i < _num_rounds; ++i) {
                auto tmp = Arx::rotr(_rks[i - 1], 3);
                if (_num_words == 4) {
                    tmp ^= _rks[i - 3];
                }
                tmp ^= Arx::rotr(tmp, 1);
                _rks[i] = ~_rks[i - _num_words] ^ tmp ^ Z[(i - _num_words) % 62] ^ 3;
            }
        }

        void encryptBlock(uint8_t* out, const uint8_t* in) override
        {
            WORD_T* pt = (WORD_T*)(in);
            WORD_T* ct = (WORD_T*)(out);

            WORD_T lhs = pt[0];
            WORD_T rhs = pt[1];

            for (size_t i = 0; i < _num_rounds - 1; i += 2) {
                lhs = lhs ^ (Arx::rotl(rhs, 1) & Arx::rotl(rhs, 8)) ^ Arx::rotl(rhs, 2) ^ _rks[i];
                rhs = rhs ^ (Arx::rotl(lhs, 1) & Arx::rotl(lhs, 8)) ^ Arx::rotl(lhs, 2) ^ _rks[i + 1];
            }

            if ((_num_rounds & 0x1) == 0x1) {
                auto tmp = rhs;
                rhs = lhs ^ (Arx::rotl(rhs, 1) & Arx::rotl(rhs, 8)) ^ Arx::rotl(rhs, 2) ^ _rks[_num_rounds - 1];
                lhs = tmp;
            }

            ct[0] = lhs;
            ct[1] = rhs;
        }

        void decryptBlock(uint8_t* out, const uint8_t* in) override
        {
            WORD_T* ct = (WORD_T*)(in);
            WORD_T* pt = (WORD_T*)(out);

            WORD_T lhs = ct[0];
            WORD_T rhs = ct[1];

            size_t rkidx = _num_rounds - 1;
            
            if ((_num_rounds & 0x1) == 0x1) {
                auto tmp = lhs;
                lhs = rhs ^ (Arx::rotl(lhs, 1) & Arx::rotl(lhs, 8)) ^ Arx::rotl(lhs, 2) ^ _rks[rkidx];
                rhs = tmp;

                rkidx -= 1;
            }

            for (size_t i = 0; i < _num_rounds - 1; i += 2, rkidx -= 2) {
                rhs = rhs ^ (Arx::rotl(lhs, 1) & Arx::rotl(lhs, 8)) ^ Arx::rotl(lhs, 2) ^ _rks[rkidx];
                lhs = lhs ^ (Arx::rotl(rhs, 1) & Arx::rotl(rhs, 8)) ^ Arx::rotl(rhs, 2) ^ _rks[rkidx - 1];
            }

            pt[0] = lhs;
            pt[1] = rhs;
        }

    private:
        void setParams(size_t keylen) {
            _num_words = keylen / sizeof(WORD_T);

            switch(Arx::_wordsize) {
            case 16:
                _num_rounds = 32;
                Z = Z0;
                break;
            
            case 24:
                _num_rounds = 36;
                Z = _num_words == 3 ? Z0 : Z1;
                break;
            
            case 32:
                _num_rounds = 42 + (_num_words - 3) * 2;
                Z = _num_words == 3 ? Z2 : Z3;
                break;
            
            case 48:
                _num_rounds = 52 + (_num_words - 2) * 2;
                Z = _num_words == 2 ? Z2 : Z3;
                break;
            
            case 64:
                switch(_num_words) {
                case 2:
                    _num_rounds = 68;
                    Z = Z2;
                    break;
                case 3:
                    _num_rounds = 69;
                    Z = Z3;
                    break;
                case 4:
                    _num_rounds = 72;
                    Z = Z4;
                    break;
                }                
                break;
            }

            _rks = new WORD_T[_num_rounds];
        }
    };

    using Simon32 = Simon<uint16_t>;
    using Simon64 = Simon<uint32_t>;
    using Simon128 = Simon<uint64_t>;

}}}

#endif
