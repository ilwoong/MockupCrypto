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

#include "../include/pbkdf2.h"
#include "../include/mac/hmac.h"
#include "../include/hash/sha2.h"
#include "../include/util/console.h"

using namespace mockup::crypto;
using namespace mockup::crypto::mac;
using namespace mockup::crypto::hash;
using namespace mockup::crypto::util;

static std::vector<uint8_t> i2bs(uint32_t i)
{
    std::vector<uint8_t> bs;

    bs.push_back(i >> 24);
    bs.push_back(i >> 16);    
    bs.push_back(i >> 8);
    bs.push_back(i);

    return bs;
}

std::vector<uint8_t> s2bs(const std::string str)
{
    std::vector<uint8_t> bs;

    for (auto letter : str) {
        bs.push_back(letter);
    }

    return bs;
}

int main(int argc, const char** argv)
{
    auto pbkdf2 = std::make_shared<Pbkdf2>(std::make_shared<Sha256>());

    std::vector<uint8_t> password = s2bs("password");
    std::vector<uint8_t> salt = s2bs("salt");

    auto derived = pbkdf2->derive(password, salt, 1, 32);
    console_print("OUT", derived);

    derived = pbkdf2->derive(password, salt, 2, 32);
    console_print("OUT", derived);

    derived = pbkdf2->derive(password, salt, 4096, 32);
    console_print("OUT", derived);

    derived = pbkdf2->derive(password, salt, 16777216, 32);
    console_print("OUT", derived);

    password = s2bs("passwordPASSWORDpassword");
    salt = s2bs("saltSALTsaltSALTsaltSALTsaltSALTsalt");

    derived = pbkdf2->derive(password, salt, 4096, 40);
    console_print("OUT", derived);

    password = {'p','a','s','s',0,'w','o','r','d'};
    salt = {'s','a',0,'l','t'};

    derived = pbkdf2->derive(password, salt, 4096, 16);
    console_print("OUT", derived);

    return 0;
}