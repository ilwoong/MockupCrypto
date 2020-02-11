#include "../../include/mode/ocb3.h"
#include "../../include/mode/ctr.h"
#include "../../include/block_cipher.h"

#include <memory>

using namespace mockup::crypto;

void benchmark_ctr(std::shared_ptr<BlockCipher> cipher, size_t keysize, size_t msglen, size_t iterations = 1000000);

void benchmark_ocb(std::shared_ptr<BlockCipher> cipher, size_t keysize, size_t msglen, size_t aadlen, size_t taglen, size_t iterations = 1000000);
