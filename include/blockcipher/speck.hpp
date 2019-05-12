#pragma once

#include "../BlockCipher.h"

#include <cstdint>
#include <array>
#include <sstream>

namespace mockup { namespace crypto { namespace cipher {

    using namespace mockup::crypto;
    
    template <typename WORD_T, size_t WORDSIZE, size_t NUMWORDS>
    class Speck : public BlockCipher {
    private:
        size_t numRounds;
        size_t alpha;
        size_t beta;
    
    public: 
        WORD_T* rks;

    public:
        Speck() {
            setNumRounds();
            rks = new WORD_T[numRounds];
        }
        
        ~Speck() {
            delete[] rks;
        }

        const std::string name() const
        {
            std::stringstream ss;
            ss << "Speck" << (WORDSIZE * 2) << "-" << (WORDSIZE * NUMWORDS);
            return ss.str();
        }

        size_t keysize() const {
            return (WORDSIZE * NUMWORDS) >> 3;
        }

        size_t blocksize() const {
            return (WORDSIZE * 2) >> 3;
        }

        void init(const uint8_t* mk) {
            WORD_T* ptr = (WORD_T*)(mk);
            WORD_T* L = new WORD_T[numRounds - 2 + NUMWORDS];

            rks[0] = ptr[0];
            for (size_t i = 0; i < NUMWORDS; ++i) {
                L[i] = ptr[i + 1];
            }

            for (size_t i = 0; i < numRounds - 1; ++i) {
                L[i + NUMWORDS - 1] = (rks[i] + rotr(L[i], alpha)) ^ static_cast<WORD_T>(i);
                rks[i + 1] = rotl(rks[i], beta) ^ L[i + NUMWORDS - 1];
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
        void setNumRounds() {
            switch(WORDSIZE) {
            case 16:
                numRounds = 22;
                break;
            case 24:
                numRounds = 19 + NUMWORDS;
                break;
            case 32:
                numRounds = 23 + NUMWORDS;
                break;
            case 48:
                numRounds = 26 + NUMWORDS;
                break;
            case 64:
                numRounds = 30 + NUMWORDS;
                break;
            }

            alpha = 7;
            beta = 2;

            if (WORDSIZE != 16) {
                alpha = 8;
                beta = 3;
            }
        }

        WORD_T rotl(WORD_T value, size_t rot) {
            return (value << rot) | (value >> (WORDSIZE - rot));
        }

        WORD_T rotr(WORD_T value, size_t rot) {
            return (value >> rot) | (value << (WORDSIZE - rot));
        }
    };

    using Speck32_64 = Speck<uint16_t, 16, 4>;
    using Speck64_96 = Speck<uint32_t, 32, 3>;
    using Speck64_128 = Speck<uint32_t, 32, 4>;
    using Speck128_128 = Speck<uint64_t, 64, 2>;
    using Speck128_192 = Speck<uint64_t, 64, 3>;
    using Speck128_256 = Speck<uint64_t, 64, 4>;

}}}