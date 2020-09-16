#include "test_vector_reader.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <iostream>
#include <vector>

#include "../include/util/byte_array.h"

using namespace mockup::crypto::util;

static const std::string TRIM_SPACE = " \t\r\n\v";

std::string trim(std::string& s, const std::string& drop = TRIM_SPACE)
{
    auto r = s.erase(s.find_last_not_of(drop) + 1);
    return r.erase(0, r.find_first_not_of(drop));
}

std::vector<std::string> tokenize(const std::string& msg, const char delim)
{
    std::vector<std::string> tokens;
    std::stringstream ss(msg);
    std::string token;

    while (std::getline(ss, token, delim)) {
        tokens.push_back(trim(token));
    }

    return tokens;
}

bool TestVectorReader::open(std::string path)
{
    std::ifstream ifs;
    ifs.open(path);

    std::string line;

    while (!ifs.eof()) {
        std::getline(ifs, line);
        auto tokens = tokenize(line, '=');
        
        if (tokens.size() != 2) {
            continue;
        }

        auto key = tokens[0];
        auto value = tokens[1];

        if (container.find(key) == container.end()) {
            container[key] = std::vector<std::string>{};
        }

        container[key].push_back(value);
    }

    return false;
}

void TestVectorReader::printInfo() const
{
    for (auto& elem : container) {
        std::cout << elem.first << std::endl;
        for (auto value : elem.second) {
            std::cout << "\t" << value << std::endl;
        }
        std::cout << std::endl;
    }
}

const std::vector<std::string>& TestVectorReader::get(std::string key) 
{
    return container[key];
}

size_t TestVectorReader::getSize(size_t i, std::string key)
{
    size_t value = 0;

    if (container.find(key) == container.end()) {
        return value;
    }

    std::stringstream ss(container[key][i]);
    ss >> value;

    return value;
}

std::vector<uint8_t> TestVectorReader::getByteArray(size_t i, std::string key)
{
    auto result = std::vector<uint8_t>{};

    if (container.find(key) == container.end()) {
        return result;
    }

    auto value = container[key][i];
    return toByteArray(value);
}