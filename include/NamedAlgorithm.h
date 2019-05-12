#pragma once

#include <string>

namespace mockup { namespace crypto {

    const size_t BIT_64 = 8;
    const size_t BIT_96 = 12;
    const size_t BIT_128 = 16;
    const size_t BIT_192 = 24;
    const size_t BIT_256 = 32;

    class NamedAlgorithm {
    public:
        virtual const std::string name() const = 0;
    };
    
}}