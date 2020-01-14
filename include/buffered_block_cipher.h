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

#ifndef __MOCKUP_CRYPTO_BUFFERED_BLOCK_CIPHER_H__
#define __MOCKUP_CRYPTO_BUFFERED_BLOCK_CIPHER_H__

#include "block_cipher.h"
#include "named_algorithm.h"
#include <vector>

namespace mockup { namespace crypto {

    class BufferedBlockCipher : public NamedAlgorithm 
    {
    public:
        enum class CipherMode {
            ENCRYPT,
            DECRYPT
        };

    protected:
        size_t _blocksize;
        CipherMode _mode;
        std::shared_ptr<BlockCipher> _cipher;
        std::vector<uint8_t> _buffer;

    protected:
        virtual size_t updateBlock(uint8_t* out, const uint8_t* in);

    public:
        BufferedBlockCipher() {};
        virtual ~BufferedBlockCipher() {};

        virtual const std::string name() const = 0;
        
        virtual void initMode(CipherMode mode, const uint8_t* iv, size_t ivLen, size_t taglen = 0) = 0;
        virtual size_t doFinal(uint8_t* out);

        void initCipher(std::shared_ptr<BlockCipher> cipher, const uint8_t* mk, size_t keylen)
        {
            _cipher = cipher;
            _cipher->init(mk, keylen);
            _blocksize = _cipher->blocksize();
        }

        size_t update(uint8_t* out, const uint8_t* msg, size_t msgLen)
        {
            auto outlen = 0;

            if (_buffer.size() > 0) {
                if (_buffer.size() + msgLen >= _blocksize) {
                    auto gap = _blocksize - _buffer.size();
                    _buffer.insert(_buffer.end(), msg, msg + gap);
                    updateBlock(out, _buffer.data());

                    _buffer.clear();
                    
                    out += _blocksize;
                    msg += gap;
                    msgLen -= gap;

                } else {
                    _buffer.insert(_buffer.end(), msg, msg + msgLen);
                    msgLen = 0;
                }
            }

            while (msgLen >= _blocksize) {
                updateBlock(out, msg);

                out += _blocksize;
                msg += _blocksize;
                outlen += _blocksize;
                msgLen -= _blocksize;
            }

            if (msgLen > 0) {
                _buffer.insert(_buffer.end(), msg, msg + msgLen);
            }

            return outlen;
        }

        size_t doFinal(uint8_t* out, const uint8_t* msg, size_t msgLen) 
        {
            auto outlen = update(out, msg, msgLen);
            outlen += doFinal(out);

            return outlen;
        }
    };
}}

#endif