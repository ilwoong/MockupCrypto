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

#include <algorithm>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <memory>

#include "../../include/mac/hmac.h"
#include "../../include/hash/sha2.h"
#include "../../include/util/hex.h"
#include "../test_vector_reader.h"

using namespace mockup::crypto;
using namespace mockup::crypto::hash;
using namespace mockup::crypto::mac;
using namespace mockup::crypto::util;

static std::shared_ptr<Mac> getMacInstance(int sha2size)
{
    std::shared_ptr<Mac> mac = nullptr;

    switch(sha2size) {
    case 256:
        mac = std::make_shared<Hmac>(std::make_shared<Sha256>());
        break;

    case 512:
        mac = std::make_shared<Hmac>(std::make_shared<Sha512>());
        break;

    default:
        break;
    }

    return mac;
}

static TestVectorReader getTestVector(std::string title)
{
    std::ostringstream path;
    path << "testvector/sha2/"<< title << ".rsp";

    TestVectorReader tvr;
    tvr.open(path.str());

    return tvr;
}

static void print(const std::vector<uint8_t>& data)
{
    std::cout << std::hex; 

    for (auto hex : data) {
        std::cout << std::setw(2) << std::setfill('0') << +hex;
    }

    std::cout << std::endl;
}

static void print_verify_result(const std::string& title, size_t countPassed, size_t countTotal)
{
    std::cout << title;
    std::cout << ((countPassed == countTotal) ? " passed" : " FAILED");
    std::cout << std::dec;
    std::cout << " (" << countPassed << " / " << countTotal << ")" << std::endl;
}

static void test_hmac_sha2(int sha2size, int outsize)
{
    auto mac = getMacInstance(sha2size);
    auto title = mac->name();
    auto tvr = getTestVector(title);
    auto len = tvr.get("Count");

    size_t countPassed = 0;
    for (int i = 0; i < len.size(); ++i) {
        auto key = tvr.getByteArray(i, "Key");
        auto msg = tvr.getByteArray(i, "Msg");
        auto tag = tvr.getByteArray(i, "Mac");
        
        mac->init(key);
        mac->update(msg);
        auto digest = mac->doFinal();

        if (std::equal(tag.begin(), tag.end(), digest.begin())) {
            countPassed += 1;            
        } else {
            print(tag);
            print(digest);
            std::cout << std::endl;
        }
    }

    print_verify_result(title, countPassed, len.size());
}

int main(int argc, const char** argv) 
{
    test_hmac_sha2(256, mockup::crypto::BIT_256);
    test_hmac_sha2(512, mockup::crypto::BIT_512);

    return 0;
}