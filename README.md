# Constant-Weight-Strings-in-Constant-Time-a-Building-Block-for-Code-based-Post-quantum-Cryptosystems
This is a repository containing the C99 code for the paper Constant Weight Strings in Constant Time: a Building Block for Code-based Post-quantum Cryptosystems by Barenghi and Pelosi.

The paper can be found [here](https://dl.acm.org/doi/10.1145/3387902.3392630) and the source code is obtained from [here](https://zenodo.org/records/3747546).

The purpose of this repository is for me to have easy access to the source code, making sure that it is not lost, in the sense that I do not forget where to get it.
Additionally I might add, that the code was released under the Public Domain License, as stated in the paper.

## Usage
In order to use this librabry, one has to include ```constant_weight_codec.h``` in one's own codebase and employ the following interfaces:

- The ```constant_time_bin_to_cw``` takes three parameters:
  1. an unsigned character vector, containing the dense binary string to be encoded, with bit ordering going from left to right, i.e. from the most significant bit of the first element of the vector, to the least significant bit of the last;
  2. an integer specifying the maximum guaranteed encoding length, denoted as l in the paper, and iii) a vector of t unsigned integers, which will be filled with the positions of the set bits in the constant weight vector.
- The ```constant_time_cw_to_bin``` function takes the same three parameters as the ```constant_time_bin_to_cw```, acting on them in a dual fashion, i.e. it reads from the t element integer vector the positions of the asserted terms in the constant weight vector, and decodes them, writing the corresponing dense binary string in the character array provided.

## System Requirements
- The software library only relies on the the C standard library, and the availability of a C99 supporting compiler, together with the headers required to compile the ```_mm_mfence```, ```_mm_stream_si32```and ```_rdrand32_step``` intrinsics (both GCC and Clang/LLVM distribution packages are equipped to do so). The building system relies on CMake, version 3.9 or greater.
- The hardware requirement is an x86_64 CPU supporting the ```movnti```, ```mfence```, and ```rdrand``` instructions to be able to run the library, plus the ```rtdscp``` instruction to perform the timing measurements. Any Intel CPU starting from the Ivy Bridge generation fulfills these requirements, and so does any AMD CPU starting from the Excavator generation, including all the Zen and Zen2 CPUs.

## How to build
In order to build one simply has to make and enter a ```build``` subdirectory in the ```constant_weight_library``` directory and run ```cmake ../ && make```.

This will create four binaries performing the benchmarks recreating the results in Table 1 of the paper, and the t-statistics reported in the evaluation section. It is advisable, although not mandatory, to disable any frequency scaling/boosting  mechanism on the test machine, if possible.
