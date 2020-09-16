/**
 * The MIT License
 *
 * Copyright (c) 2019 Ilwoong Jeong (https://github.com/ilwoong)
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

#include "../../include/hash/sha2.h"
#include "../../include/util/hex.h"
#include "../test_vector_reader.h"

using namespace mockup::crypto;
using namespace mockup::crypto::hash;
using namespace mockup::crypto::util;

static std::shared_ptr<Hash> getSha2Instance(int lshsize, int outsize)
{
    std::shared_ptr<Hash> hash = nullptr;

    switch(lshsize) {
    case 256:
        hash = std::make_shared<Sha256>();
        break;

    case 512:
        hash = std::make_shared<Sha512>();
        break;

    default:
        break;
    }

    return hash;
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
    std::cout << " (" << countPassed << " / " << countTotal << ")" << std::endl;
}

static void test_sha2(int sha2size, int outsize, std::string msgType)
{
    auto hash = getSha2Instance(sha2size, outsize);
    auto title = hash->name() + "_" + msgType;
    auto tvr = getTestVector(title);
    auto len = tvr.get("Len");

    size_t countPassed = 0;
    for (int i = 0; i < len.size(); ++i) {
        auto len = tvr.getSize(i, "Len");
        auto msg = tvr.getByteArray(i, "Msg");
        auto md = tvr.getByteArray(i, "MD");
        
        hash = getSha2Instance(sha2size, outsize);
        hash->init();
        if (len > 0) {
            hash->update(msg);
        }
        auto digest = hash->doFinal();

        if (std::equal(md.begin(), md.end(), digest.begin())) {
            countPassed += 1;
        } else {
            print(md);
            print(digest);
            std::cout << std::endl;
        }
    }

    print_verify_result(title, countPassed, len.size());
}

static void verify_testvector(std::string msgType) {    
    test_sha2(256, mockup::crypto::BIT_256, msgType);
    test_sha2(512, mockup::crypto::BIT_512, msgType);
}

int main(int argc, const char** argv) 
{
    verify_testvector("ShortMsg");
    verify_testvector("LongMsg");

    return 0;
}