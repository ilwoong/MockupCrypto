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

#ifndef __MOCKUP_CRYPTO_HASH_SHA2_H__
#define __MOCKUP_CRYPTO_HASH_SHA2_H__

#include <array>
#include <sstream>

#include "../hash.h"
#include "../arx_primitive.h"

#include <iostream>

namespace mockup { namespace crypto { namespace hash {

    template <typename WORD_T, size_t NUM_STEPS>
    class Sha2 : public Hash, public ArxPrimitive<WORD_T>
    {
    protected:
        size_t offset;
        size_t totalLength;
        std::vector<uint8_t> block;
        std::vector<WORD_T> state;
        std::vector<WORD_T> W;
        std::vector<WORD_T> H;
        std::vector<WORD_T> K;

    public:
        Sha2() {
            offset = 0;
            totalLength = 0;
        }

        virtual ~Sha2() = default;

        void update(const uint8_t* data, size_t length) override 
        {
            totalLength += length;

            auto blocksize = block.size();
            auto gap = blocksize - offset;

            if (length >= gap) {
                std::copy(data, data + gap, block.begin() + offset);
                updateBlock(block.data());

                offset = 0;
                data += gap;
                length -= gap;
            }

            while (length >= blocksize) {
                updateBlock(data);

                data += blocksize;
                length -= blocksize;
            }

            if (length > 0) {
                std::copy(data, data + length, block.begin() + offset);

                offset += length;
            }
        }

        void updateBlock(const uint8_t* data)
        {
            auto a = state[0];
            auto b = state[1];
            auto c = state[2];
            auto d = state[3];
            auto e = state[4];
            auto f = state[5];
            auto g = state[6];
            auto h = state[7];

            WORD_T t1 = 0;
            WORD_T t2 = 0;

            expandMessage(data);
            for (auto i = 0; i < NUM_STEPS; ++i) {
                t1 = h + sum1(e) + ch(e, f, g) + K[i] + W[i];
                t2 = sum0(a) + maj(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + t1;
                d = c;
                c = b;
                b = a;
                a = t1 + t2;
            }

            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

        std::vector<uint8_t> doFinal() override
        {
            block[offset++] = 0x80;
            std::fill(block.begin() + offset, block.end(), 0);

            processLength();
            updateBlock(block.data());

            return toOutput();
        }

    protected:
        virtual void expandMessage(const uint8_t* data) = 0;
        virtual std::vector<uint8_t> toOutput() const = 0;
        virtual void processLength() = 0;

        virtual WORD_T ch(WORD_T x, WORD_T y, WORD_T z) const 
        {
            return (x & y) ^ (~x & z);
        }
        virtual WORD_T maj(WORD_T x, WORD_T y, WORD_T z) const 
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }

        virtual WORD_T sum0(WORD_T x) const = 0;
        virtual WORD_T sum1(WORD_T x) const = 0;
        
        virtual WORD_T sigma0(WORD_T x) const = 0;
        virtual WORD_T sigma1(WORD_T x) const = 0;
    };

    using Sha256_t = Sha2<uint32_t, 64>;
    using Sha512_t = Sha2<uint64_t, 80>;

    class Sha256 : public Sha256_t
    {
        using Arx = ArxPrimitive<uint32_t>;

    public:
        Sha256();
        virtual ~Sha256() = default;

        size_t blocksize() const override;
        size_t outputsize() const override;
        const std::string name() const override;

        void init() override;

    protected:
        void expandMessage(const uint8_t* data) override;
        std::vector<uint8_t> toOutput() const override;
        void processLength() override;

        uint32_t sum0(uint32_t x) const override;
        uint32_t sum1(uint32_t x) const override;
        
        uint32_t sigma0(uint32_t x) const override;
        uint32_t sigma1(uint32_t x) const override;
    };

    class Sha512 : public Sha512_t
    {
        using Arx = ArxPrimitive<uint64_t>;

    public:
        Sha512();
        virtual ~Sha512() = default;

        size_t blocksize() const override;
        size_t outputsize() const override;
        const std::string name() const override;

        void init() override;

    protected:
        void expandMessage(const uint8_t* data) override;
        std::vector<uint8_t> toOutput() const override;
        void processLength() override;

        uint64_t sum0(uint64_t x) const override;
        uint64_t sum1(uint64_t x) const override;

        uint64_t sigma0(uint64_t x) const override;
        uint64_t sigma1(uint64_t x) const override;
    };

}}}

#endif
