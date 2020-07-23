#ifndef __TEST_VECTOR_READER_H__
#define __TEST_VECTOR_READER_H__

#include <map>
#include <string>
#include <vector>

class TestVectorReader {

private:
    std::map<std::string, std::vector<std::string>> container;

public:
    bool open(std::string path);

    void printInfo() const;

    const std::vector<std::string>& get(std::string key);
    std::vector<uint8_t> getByteArray(size_t i, std::string key);
};

#endif