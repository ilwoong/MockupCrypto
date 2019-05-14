CC = g++
CPPFLAGS = -O2

.PHONY: all clean

all: test_speck test_lsh

test_speck : test/block_cipher/test_speck.cpp
	$(CC) $(CPPFLAGS) $^ -o $@

test_lsh : test/hash/test_lsh.cpp src/hash/lsh256.cpp src/hash/lsh512.cpp
	$(CC) $(CPPFLAGS) $^ -o $@

clean:
	rm -rf test_speck test_lsh