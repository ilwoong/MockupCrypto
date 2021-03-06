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

#ifndef __MOCKUP_CRYPTO_MODE_ECB_H__
#define __MOCKUP_CRYPTO_MODE_ECB_H__

#include "../buffered_block_cipher.h"

namespace mockup { namespace crypto { namespace mode {

    class Ecb : public BufferedBlockCipher
    {
    public:
        const std::string name() const override;
        
        void initMode(CipherMode mode, const uint8_t* iv, size_t ivLen) override;
        size_t doFinal(uint8_t* out) override;

    protected:
        void updateBlock(uint8_t* out, const uint8_t* in) override;
        
    private:
        size_t DoFinalWithPadding(uint8_t* out);
        size_t DoFinalWithoutPadding(uint8_t* out);

    };
}}}

#endif