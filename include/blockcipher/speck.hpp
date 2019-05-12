#pragma once

#include "../BlockCipher.h"

#include <cstdint>
#include <array>
#include <sstream>

namespace mockup { namespace crypto { namespace cipher {

    using namespace mockup::crypto;
    
    template <typename WORD_T>
    class Speck : public BlockCipher {
    private:
        size_t wordSize;
        size_t numWords;
        size_t numRounds;

        size_t alpha;
        size_t beta;
    
    public: 
        WORD_T* rks;

    public:
        Speck() : rks(nullptr), wordSize(sizeof(WORD_T) << 3) {
        }
        
        ~Speck() {
            delete[] rks;
        }

        const std::string name() const
        {
            std::stringstream ss;
            ss << "Speck" << (blocksize() << 3) << "-" << (keysize() << 3);
            return ss.str();
        }

        size_t keysize() const {
            return (wordSize * numWords) >> 3;
        }

        size_t blocksize() const {
            return (wordSize * 2) >> 3;
        }

        void init(const uint8_t* mk, size_t keylen) {
            setParams(keylen);

            WORD_T* ptr = (WORD_T*)(mk);
            WORD_T* L = new WORD_T[numRounds - 2 + numWords];

            rks[0] = ptr[0];
            for (size_t i = 0; i < numWords; ++i) {
                L[i] = ptr[i + 1];
            }

            for (size_t i = 0; i < numRounds - 1; ++i) {
                L[i + numWords - 1] = (rks[i] + rotr(L[i], alpha)) ^ static_cast<WORD_T>(i);
                rks[i + 1] = rotl(rks[i], beta) ^ L[i + numWords - 1];
            }

            delete[] L;
        }

        void encryptBlock(uint8_t* out, const uint8_t* in)
        {
            WORD_T* pt = (WORD_T*)(in);
            WORD_T* ct = (WORD_T*)(out);

            WORD_T y = pt[0];
            WORD_T x = pt[1];

            for (size_t i = 0; i < numRounds; ++i) {
                x = (rotr(x, alpha) + y) ^ rks[i];
                y = rotl(y, beta) ^ x;
            }

            ct[0] = y;
            ct[1] = x;
        }

        void decryptBlock(uint8_t* out, const uint8_t* in)
        {
            WORD_T* ct = (WORD_T*)(in);
            WORD_T* pt = (WORD_T*)(out);

            WORD_T y = ct[0];
            WORD_T x = ct[1];

            size_t rkidx = numRounds - 1;
            for (size_t i = 0; i < numRounds; ++i, --rkidx) {
                y = rotr(x ^ y, beta);
                x = rotl((x ^ rks[rkidx]) - y, alpha);
            }
            
            pt[0] = y;
            pt[1] = x;
        }

    private:
        void setParams(size_t keylen) {
            numWords = keylen / sizeof(WORD_T);

            switch(wordSize) {
            case 16:
                numRounds = 22;
                break;
            case 24:
                numRounds = 19 + numWords;
                break;
            case 32:
                numRounds = 23 + numWords;
                break;
            case 48:
                numRounds = 26 + numWords;
                break;
            case 64:
                numRounds = 30 + numWords;
                break;
            }

            alpha = 7;
            beta = 2;

            if (wordSize != 16) {
                alpha = 8;
                beta = 3;
            }

            rks = new WORD_T[numRounds];
        }

        WORD_T rotl(WORD_T value, size_t rot) {
            return (value << rot) | (value >> (wordSize - rot));
        }

        WORD_T rotr(WORD_T value, size_t rot) {
            return (value >> rot) | (value << (wordSize - rot));
        }
    };

    using Speck32 = Speck<uint16_t>;
    using Speck64 = Speck<uint32_t>;
    using Speck128 = Speck<uint64_t>;

}}}