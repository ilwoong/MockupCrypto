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

#ifndef __MOCKUP_CRYPTO_ARX_PRIMITIVE_H__
#define __MOCKUP_CRYPTO_ARX_PRIMITIVE_H__

namespace mockup { namespace crypto {

    template <typename WORD_T>
    class ArxPrimitive {
    protected:
        size_t _wordsize;

    public:
        ArxPrimitive() : _wordsize(sizeof(WORD_T) << 3) {}
        virtual ~ArxPrimitive() {}

    protected:
        inline WORD_T rotl(WORD_T value, size_t rot) const noexcept
        {
            return (value << rot) | (value >> (_wordsize - rot));
        }

        inline WORD_T rotr(WORD_T value, size_t rot) const noexcept
        {
            return (value >> rot) | (value << (_wordsize - rot));
        }

        template <typename T>
        void xor_array(T* out, const T* lhs, const T* rhs, size_t count) const
        {
            for (size_t i = 0; i < count; ++i) {
                out[i] = lhs[i] xor rhs[i];
            }
        }
    };
}}

#endif

