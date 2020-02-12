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

#ifndef __MOCKUP_CRYPTO_BLOCK_CIPHER_AES_NI_H__
#define __MOCKUP_CRYPTO_BLOCK_CIPHER_AES_NI_H__

#include "../block_cipher.h"

namespace mockup { namespace crypto { namespace block_cipher {

    class AesNI : public BlockCipher {

    private:
        size_t _keysize;
        uint8_t* _rks;

    public:
        AesNI();
        ~AesNI();

        const std::string name() const override;
        size_t keysize() const override;
        size_t blocksize() const override;

        void init(const uint8_t* mk, size_t keylen) override;
        void encryptBlock(uint8_t* out, const uint8_t* in) override;
        void decryptBlock(uint8_t* out, const uint8_t* in) override;

    private:
        size_t rounds() const;
    };
}}}

#endif