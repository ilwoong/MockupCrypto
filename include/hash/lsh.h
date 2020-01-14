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

#ifndef __MOCKUP_CRYPTO_HASH_LSH_H__
#define __MOCKUP_CRYPTO_HASH_LSH_H__

#include <array>
#include <sstream>

#include "../hash.h"
#include "../arx_primitive.h"

namespace mockup { namespace crypto { namespace hash {

    template <typename WORD_T, size_t NUM_STEPS>
    class Lsh : public Hash, public ArxPrimitive<WORD_T> 
    {
        using Arx = ArxPrimitive<WORD_T>;

    protected:

        const size_t _blocksize;
        size_t _blk_offset;
        size_t _output_length;

        WORD_T _alpha1, _alpha2;
        WORD_T _beta1, _beta2;
        std::array<WORD_T, 8> _gamma;
        std::array<WORD_T, 8 * NUM_STEPS> _step_constant;

        std::array<WORD_T, 16 * (NUM_STEPS + 1)> _msg;
        std::array<WORD_T, 16> _state;
        std::array<WORD_T, 16> _tmp_state;

        std::array<uint8_t, sizeof(WORD_T) << 5> _block;

    public:

        Lsh() : _blocksize(sizeof(WORD_T) << 5) {}
        virtual ~Lsh() {}

        const std::string name() const override
        {
            std::stringstream ss;
            ss << "LSH" << (_blocksize << 1) << "-" << (_output_length << 3);
            return ss.str();
        }

        virtual void init() override
        {
            _blk_offset = 0;
            _tmp_state.fill(0);
            _msg.fill(0);
            _block.fill(0);
        }

        void update(const uint8_t* data, size_t length) override
        {
            if (_blk_offset > 0) {
                size_t gap = _blocksize - _blk_offset;

                if (length >= gap) {
                    std::copy(data, data + gap, std::begin(_block) + _blk_offset);
                    compress(_block.data());
                    _blk_offset = 0;
                    data += gap;
                    length -= gap;

                } else {
                    std::copy(data, data + length, std::begin(_block) + _blk_offset);
                    _blk_offset += length;
                    data += length;
                    length = 0;
                }
            }
            
            while (length >= _blocksize) {
                compress(data);
                data += _blocksize;
                length -= _blocksize;
            }

            if (length > 0) {
                std::copy(data, data + length, std::begin(_block) + _blk_offset);
                _blk_offset += length;
            }
        }

        void do_final(uint8_t* output) override
        {
            WORD_T* result = (WORD_T*) output;
            
            _block[_blk_offset++] = static_cast<uint8_t>(0x80);
            std::fill(std::begin(_block) + _blk_offset, std::end(_block), 0);
            compress(_block.data());

            const WORD_T* lhs = _state.data();
            const WORD_T* rhs = lhs + 8;
            const size_t out_words = _output_length / sizeof(WORD_T);
            this->xor_array(result, lhs, rhs, out_words);

            init();
        }

    private:

        void expand_message(const uint8_t* in) 
        {
            const WORD_T* ptr = (const WORD_T*) in;
            std::copy(ptr, ptr + 32, std::begin(_msg));

            for (size_t i = 2; i <= NUM_STEPS; ++i) {
                size_t idx = 16 * i;
                _msg[idx     ] = _msg[idx - 16] + _msg[idx - 29];
                _msg[idx +  1] = _msg[idx - 15] + _msg[idx - 30];
                _msg[idx +  2] = _msg[idx - 14] + _msg[idx - 32];
                _msg[idx +  3] = _msg[idx - 13] + _msg[idx - 31];
                _msg[idx +  4] = _msg[idx - 12] + _msg[idx - 25];
                _msg[idx +  5] = _msg[idx - 11] + _msg[idx - 28];
                _msg[idx +  6] = _msg[idx - 10] + _msg[idx - 27];
                _msg[idx +  7] = _msg[idx -  9] + _msg[idx - 26];
                _msg[idx +  8] = _msg[idx -  8] + _msg[idx - 21];
                _msg[idx +  9] = _msg[idx -  7] + _msg[idx - 22];
                _msg[idx + 10] = _msg[idx -  6] + _msg[idx - 24];
                _msg[idx + 11] = _msg[idx -  5] + _msg[idx - 23];
                _msg[idx + 12] = _msg[idx -  4] + _msg[idx - 17];
                _msg[idx + 13] = _msg[idx -  3] + _msg[idx - 20];
                _msg[idx + 14] = _msg[idx -  2] + _msg[idx - 19];
                _msg[idx + 15] = _msg[idx -  1] + _msg[idx - 18];
            }
        }

        void permute_word() 
        {
            _state[ 0] = _tmp_state[ 6];
            _state[ 1] = _tmp_state[ 4];
            _state[ 2] = _tmp_state[ 5];
            _state[ 3] = _tmp_state[ 7];
            
            _state[ 4] = _tmp_state[12];
            _state[ 5] = _tmp_state[15];
            _state[ 6] = _tmp_state[14];
            _state[ 7] = _tmp_state[13];

            _state[ 8] = _tmp_state[ 2];
            _state[ 9] = _tmp_state[ 0];
            _state[10] = _tmp_state[ 1];
            _state[11] = _tmp_state[ 3];

            _state[12] = _tmp_state[ 8];
            _state[13] = _tmp_state[11];
            _state[14] = _tmp_state[10];
            _state[15] = _tmp_state[ 9];
        }

        void step(size_t idx, WORD_T alpha, WORD_T beta)
        {
            WORD_T lhs, rhs;
            for (size_t col = 0; col < 8; ++col) {
                lhs = _state[col    ] ^ _msg[16 * idx + col    ];
                rhs = _state[col + 8] ^ _msg[16 * idx + col + 8];

                lhs = Arx::rotl(lhs + rhs, alpha) ^ _step_constant[8 * idx + col];
                rhs = Arx::rotl(lhs + rhs, beta);
                
                _tmp_state[col    ] = lhs + rhs;
                _tmp_state[col + 8] = Arx::rotl(rhs, _gamma[col]);
            }

            permute_word();
        }

        void compress(const uint8_t* data)
        {
            expand_message(data);

            for (size_t i = 0; i < NUM_STEPS; i += 2) {
                step(i    , _alpha1, _beta1);
                step(i + 1, _alpha2, _beta2);
            }

            for (size_t i = 0; i < 16; ++i) {
                _state[i] ^= _msg[16 * NUM_STEPS + i];
            }
        }

    };

    using Lsh256_t = Lsh<uint32_t, 26>;
    using Lsh512_t = Lsh<uint64_t, 28>;

    class Lsh256 : public Lsh256_t
    {
    public:
        Lsh256();
        Lsh256(size_t outlen);
        ~Lsh256();

        void init();

    private:
        void init224();
        void init256();
    };

    class Lsh512 : public Lsh512_t
    {
    public:
        Lsh512();
        Lsh512(size_t outlen);
        ~Lsh512();

        void init();

    private:
        void init224();
        void init256();
        void init384();
        void init512();
    };

}}}

#endif