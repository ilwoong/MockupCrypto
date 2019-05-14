/**
 * MIT License
 * 
 * Copyright (c) 2019 Ilwoong Jeong, https://github.com/ilwoong
 * 
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __MOCKUP_CRYPTO_UTIL_HEX_H__
#define __MOCKUP_CRYPTO_UTIL_HEX_H__

#include <iomanip>

namespace mockup { namespace crypto { namespace util {

    template<typename WORD_T>
    void print_hex(const WORD_T* data, size_t count)
    {
        for (size_t i = 0; i < count; ++i) {
            std::cout << std::hex << std::setw(sizeof(WORD_T) << 1) << std::setfill('0') << +data[i];

            if ( (i + 1) % 4 == 0) {
                std::cout << " ";
            }

            if ( (i + 1) % 32 == 0) {            
                std::cout << std::endl;
            }
        }

        std::cout << std::endl;
    }

    template<typename WORD_T>
    void print_hex(const char* title, const WORD_T* data, size_t count)
    {
        std::cout << title << std::endl;
        print_hex(data, count);
    }

}}}

#endif