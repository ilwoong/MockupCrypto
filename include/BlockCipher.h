#pragma once

#include "NamedAlgorithm.h"

namespace mockup { namespace crypto {

    class BlockCipher : public NamedAlgorithm {
    public:
        BlockCipher() {}
        virtual ~BlockCipher() {}

        virtual const std::string name() const = 0;
        virtual size_t keysize() const = 0;
        virtual size_t blocksize() const = 0;

        virtual void init(const uint8_t* mk) = 0;
        virtual void encryptBlock(uint8_t* out, const uint8_t* in) = 0;
        virtual void decryptBlock(uint8_t* out, const uint8_t* in) = 0;
    };
}}