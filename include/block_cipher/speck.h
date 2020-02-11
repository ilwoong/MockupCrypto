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

#ifndef __MOCKUP_CRYPTO_BLOCKCIPHER_SPECK_HPP__
#define __MOCKUP_CRYPTO_BLOCKCIPHER_SPECK_HPP__

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
    class Speck : public BlockCipher, public ArxPrimitive<WORD_T> 
    {
        using Arx = ArxPrimitive<WORD_T>;
        
    private:
        size_t _num_words;
        size_t _num_rounds;

        size_t _alpha;
        size_t _beta;
    
    public: 
        WORD_T* _rks;

    public:
        Speck() : _rks(nullptr), _alpha(8), _beta(3) {
        }
        
        ~Speck() {
            safe_delete_array(_rks);
        }

        const std::string name() const override
        {
            std::stringstream ss;
            ss << "Speck" << (blocksize() << 3) << "-" << (keysize() << 3);
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
            WORD_T* L = new WORD_T[_num_rounds - 2 + _num_words];

            _rks[0] = ptr[0];
            for (size_t i = 0; i < _num_words; ++i) {
                L[i] = ptr[i + 1];
            }

            for (size_t i = 0; i < _num_rounds - 1; ++i) {
                L[i + _num_words - 1] = (_rks[i] + Arx::rotr(L[i], _alpha)) ^ static_cast<WORD_T>(i);
                _rks[i + 1] = Arx::rotl(_rks[i], _beta) ^ L[i + _num_words - 1];
            }

            delete[] L;
        }

        void encryptBlock(uint8_t* out, const uint8_t* in) override
        {
            WORD_T* pt = (WORD_T*)(in);
            WORD_T* ct = (WORD_T*)(out);

            WORD_T y = pt[0];
            WORD_T x = pt[1];

            for (size_t i = 0; i < _num_rounds; ++i) {
                x = (Arx::rotr(x, _alpha) + y) ^ _rks[i];
                y = Arx::rotl(y, _beta) ^ x;
            }

            ct[0] = y;
            ct[1] = x;
        }

        void decryptBlock(uint8_t* out, const uint8_t* in) override
        {
            WORD_T* ct = (WORD_T*)(in);
            WORD_T* pt = (WORD_T*)(out);

            WORD_T y = ct[0];
            WORD_T x = ct[1];

            size_t rkidx = _num_rounds - 1;
            for (size_t i = 0; i < _num_rounds; ++i, --rkidx) {
                y = Arx::rotr(x ^ y, _beta);
                x = Arx::rotl((x ^ _rks[rkidx]) - y, _alpha);
            }
            
            pt[0] = y;
            pt[1] = x;
        }

    private:
        void setParams(size_t keylen) {
            _num_words = keylen / sizeof(WORD_T);

            switch(Arx::_wordsize) {
            case 16:
                _num_rounds = 22;
                break;
            case 24:
                _num_rounds = 19 + _num_words;
                break;
            case 32:
                _num_rounds = 23 + _num_words;
                break;
            case 48:
                _num_rounds = 26 + _num_words;
                break;
            case 64:
                _num_rounds = 30 + _num_words;
                break;
            }

            if (Arx::_wordsize == 16) {
                _alpha = 7;
                _beta = 2;
            }

            _rks = new WORD_T[_num_rounds];
        }
    };

    using Speck32 = Speck<uint16_t>;
    using Speck64 = Speck<uint32_t>;
    using Speck128 = Speck<uint64_t>;

}}}

#endif
