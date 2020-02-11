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

#include "../buffered_block_cipher_aead.h"

#include <vector>
#include <array>

#ifndef __MOCKUP_CRYPTO_MODE_OCB3_H__
#define __MOCKUP_CRYPTO_MODE_OCB3_H__

namespace mockup { namespace crypto { namespace mode {
    
    class OCB3 : public BufferedBlockCipherAead {

        using block_t = std::vector<uint8_t>;

    private:
        block_t _delta;
        block_t _deltaAAD;
        block_t _checksum;
        block_t _auth;
        block_t _lstar;
        block_t _ldollar;

        size_t _index;
        size_t _taglen;

        size_t _residue;
        size_t _shift;
        std::array<uint8_t, 2> _mask;

        std::vector<block_t> _L;

    public:
        OCB3() = default;
        virtual ~OCB3() =default;

        const std::string name() const override;
        
        void initMode(CipherMode mode, const uint8_t* iv, size_t ivLen, size_t taglen) override;
        void updateAAD(const uint8_t* aad, size_t aadlen) override;        
        size_t doFinal(uint8_t* out) override;

    protected:
        void updateBlock(uint8_t* out, const uint8_t* in) override;

    private:
        void initBlocksize(size_t blocksize);
        void times2(block_t& dst, const block_t& src);
        void updateAADBlock(const uint8_t* block);
        void increaseDelta(block_t& delta);
        size_t generateTag(uint8_t* out);

        void xor_block(block_t& out, const block_t& lhs, const block_t& rhs);
    };
}}}

#endif