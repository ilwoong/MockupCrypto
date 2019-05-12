#pragma once

#include <string>

namespace mockup {
    namespace crypto {
        class NamedAlgorithm {
        public:
            virtual const std::string name() const = 0;
        };
    }
}