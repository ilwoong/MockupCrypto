CC = g++
CPPFLAGS = 

.PHONY: all clean

all: test_speck

test_speck : test/blockcipher/test_speck.cpp
	$(CC) $(CPPFLAGS) $^ -o $@

clean:
	rm -rf test_speck