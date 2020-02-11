CC = g++
CPPFLAGS = -O2

SRC_MODES = src/mode/ocb3.cpp src/mode/ctr.cpp include/buffered_block_cipher.h include/buffered_block_cipher_aead.h

.PHONY: all clean

all: test_speck test_lsh test_simon test_lsh test_aes test_aesni

test_speck : test/block_cipher/test_speck.cpp
	$(CC) $(CPPFLAGS) $^ -o $@

test_simon : test/block_cipher/test_simon.cpp
	$(CC) $(CPPFLAGS) $^ -o $@

test_lsh : test/hash/test_lsh.cpp src/hash/lsh256.cpp src/hash/lsh512.cpp
	$(CC) $(CPPFLAGS) $^ -o $@

test_aes : test/block_cipher/test_aes.cpp test/block_cipher/test_ocb.cpp src/block_cipher/aes.cpp $(SRC_MODES)
	$(CC) $(CPPFLAGS) $^ -o $@

test_aesni : test/block_cipher/test_aesni.cpp test/block_cipher/test_ocb.cpp src/block_cipher/aesni.cpp $(SRC_MODES)
	$(CC) $(CPPFLAGS) $^ -o $@ -maes

rebuild:
	make clean
	make -j8


clean:
	rm -rf test_speck test_lsh test_simon test_lsh test_aes test_aesni