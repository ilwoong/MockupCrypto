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

#include "test_ocb.h"

#include <iostream>

using namespace mockup::crypto::mode;

#include <cpuid.h>
#include <stdint.h>

/*** Low level interface ***/

/* there may be some unnecessary clobbering here*/
#define _setClockStart(HIs,LOs) {                                           \
asm volatile ("CPUID \n\t"                                                  \
              "RDTSC \n\t"                                                  \
              "mov %%edx, %0 \n\t"                                          \
              "mov %%eax, %1 \n\t":                                         \
              "=r" (HIs), "=r" (LOs)::                                      \
              "%rax", "%rbx", "%rcx", "%rdx");                              \
}

#define _setClockEnd(HIe,LOe) {                                             \
asm volatile ("RDTSCP \n\t"                                                 \
              "mov %%edx, %0 \n\t"                                          \
              "mov %%eax, %1 \n \t"                                         \
              "CPUID \n \t": "=r" (HIe), "=r" (LOe)::                       \
              "%rax", "%rbx", "%rcx", "%rdx");                              \
} 
#define _setClockBit(HIs,LOs,s,HIe,LOe,e) {                                 \
  s=LOs | ((uint64_t)HIs << 32);                                            \
  e=LOe | ((uint64_t)HIe << 32);                                            \
}

/*** High level interface ***/

typedef struct {
  volatile uint32_t hiStart;
  volatile uint32_t loStart;
  volatile uint32_t hiEnd;
  volatile uint32_t loEnd;
  volatile uint64_t tStart;
  volatile uint64_t tEnd;

  /*tend-tstart*/
  uint64_t tDur;
} timer_st;

#define startTimer(ts)                                                      \
{                                                                           \
  _setClockStart(ts.hiStart,ts.loStart);                                    \
} 


#define endTimer(ts)                                                        \
{                                                                           \
  _setClockEnd(ts.hiEnd,ts.loEnd);                                          \
  _setClockBit(ts.hiStart,ts.loStart,ts.tStart,                             \
      ts.hiEnd,ts.loEnd,ts.tEnd);                                           \
  ts.tDur=ts.tEnd-ts.tStart;                                                \
}                                                                             

#define lapTimer(ts)                                                        \
{                                                                           \
  ts.hiStart=ts.hiEnd;                                                      \
  ts.loStart=ts.loEnd;                                                      \
}

static inline uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

void benchmark_ocb(std::shared_ptr<BlockCipher> cipher, size_t keysize, size_t msglen, size_t aadlen, size_t taglen, size_t iterations)
{   
    uint8_t mk[64] = {0};    
    uint8_t iv[64] = {0};
    uint8_t* aad = new uint8_t[aadlen];
    uint8_t* pt = new uint8_t[msglen];
    uint8_t* ct = new uint8_t[msglen + taglen];

    std::shared_ptr<BufferedBlockCipherAead> ocb = std::make_shared<OCB3>();

    size_t min = -1;
    timer_st ts;

    for (auto iter = 0; iter < iterations; ++iter)
    {
        //auto started = rdtsc();
        startTimer(ts);

        ocb->initCipher(cipher, mk, keysize);
        ocb->initMode(BufferedBlockCipher::CipherMode::ENCRYPT, iv, 12, taglen);
        ocb->updateAAD(aad, aadlen);
        ocb->doFinal(ct, pt, msglen);

        //auto ended = rdtsc();
        //auto elapsed = ended - started;
        endTimer(ts);
        
        if (ts.tDur < min) {
            min = ts.tDur;
        }
    }

    std::cout << "---------------------------------" << std::endl;
    std::cout << ocb->name() << std::endl;
    std::cout << "     msg length: " << msglen << std::endl;
    std::cout << "     aad length: " << aadlen << std::endl;
    std::cout << "eclapsed cycles: " << min << std::endl;
    std::cout << "    elapsed cpb: " << static_cast<double>(min) / msglen << std::endl;
    std::cout << std::endl;

    delete[] pt;
    delete[] ct;
    delete[] aad;
}

void benchmark_ctr(std::shared_ptr<BlockCipher> cipher, size_t keysize, size_t msglen, size_t iterations)
{   
    uint8_t mk[64] = {0};    
    uint8_t iv[64] = {0};
    uint8_t* pt = new uint8_t[msglen];
    uint8_t* ct = new uint8_t[msglen];

    std::shared_ptr<BufferedBlockCipher> ctr = std::make_shared<CTR>();

    size_t min = -1;
    timer_st ts;

    for (auto iter = 0; iter < iterations; ++iter)
    {
        //auto started = rdtsc();
        startTimer(ts);

        ctr->initCipher(cipher, mk, keysize);
        ctr->initMode(BufferedBlockCipher::CipherMode::ENCRYPT, iv, 16);        
        ctr->doFinal(ct, pt, msglen);

        //auto ended = rdtsc();
        //auto elapsed = ended - started;
        endTimer(ts);
        
        if (ts.tDur < min) {
            min = ts.tDur;
        }
    }

    std::cout << "---------------------------------" << std::endl;
    std::cout << ctr->name() << std::endl;
    std::cout << "     msg length: " << msglen << std::endl;
    std::cout << "eclapsed cycles: " << min << std::endl;
    std::cout << "    elapsed cpb: " << static_cast<double>(min) / msglen << std::endl;
    std::cout << std::endl;

    delete[] pt;
    delete[] ct;
}