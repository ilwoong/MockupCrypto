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

#ifndef __MOCKUP_CRYPTO_MAC_H__
#define __MOCKUP_CRYPTO_MAC_H__

#include "named_algorithm.h"
#include <vector>

#include <iostream>
#include <iomanip>

namespace mockup { namespace crypto { 

    class Mac : public NamedAlgorithm {
    protected:
        size_t blocksize;
        size_t offset;
        std::vector<uint8_t> block;

    public:
        Mac() = default;
        virtual ~Mac() = default;

        virtual void init(const uint8_t* key, size_t keysize) = 0;        
        virtual void updateBlock(const uint8_t* data) = 0;
        virtual std::vector<uint8_t> doFinal() = 0;

        void init(const std::vector<uint8_t>& key) {
            init(key.data(), key.size());
        }

        void update(const uint8_t* data, size_t length) {
            auto gap = blocksize - offset;

            if (length >= gap) {
                std::copy(data, data + gap, block.data() + offset);
                updateBlock(block.data());

                offset = 0;
                data += gap;
                length -= gap;
            }

            while (length >= blocksize) {
                updateBlock(data);

                data += length;
                length -= blocksize;
            }

            if (length > 0) {
                std::copy(data, data + length, block.data() + offset);
                offset += length;
            }
        }

        void update(const std::vector<uint8_t>& data) 
        {
            update(data.data(), data.size());
        }

        std::vector<uint8_t> doFinal(const std::vector<uint8_t>& data)
        {
            update(data);
            return doFinal();
        }
    };
}}

#endif