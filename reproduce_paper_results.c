/**
 * Software Artifact of the paper Constant Weight Strings in
 * Constant Time: a Building Block for Code-based Post-quantum Cryptosystems,
 * Published in the 17th ACM International Conference on Computing Frontiers
 * (CF '20), May 11--13, 2020, Catania, Italy. DOI :10.1145/3387902.3392630
 *
 * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/

#include <string.h>
#include <stdlib.h>

#include "constant_weight_codec.h"
#include "timing_and_stats.h"
#include "combinadics_library.h"
#include "rng.h"

#define BUFFER_LEN 1000
#define NUM_TESTS 10000
#define NUM_TESTS_COMBINADICS 100

void functional_test_constant_time_CWE(void){
    unsigned char inputstring[BUFFER_LEN]= {0};
    unsigned char inputstring_trim[BUFFER_LEN]= {0};
    unsigned char outputstring[BUFFER_LEN] = {0};
    unsigned char outputstring_trim[BUFFER_LEN] = {0};
    POSITION_T combination_out[NUM_ERRORS_T] = {0};

    int tests_to_pass = NUM_TESTS;

    for(int ntest=0;ntest < NUM_TESTS;ntest++){
         randombytes(inputstring,BUFFER_LEN);
         memset(outputstring,0,BUFFER_LEN);
         memcpy(inputstring_trim,inputstring,BUFFER_LEN);

         /* clear input string for prettyprinting keeping only first
          * MAX_PREFIX_LEN bits*/
         if(MAX_PREFIX_LEN % 8){
             unsigned char mask = ((unsigned char) 1 << (8-(MAX_PREFIX_LEN %8))) -1;
             mask = ~mask;
             inputstring_trim[MAX_PREFIX_LEN /8] &= mask;
         } else {
             inputstring_trim[MAX_PREFIX_LEN /8] = 0;
         }
         for (int i = MAX_PREFIX_LEN /8 +1 ;i < BUFFER_LEN;i++){
             inputstring_trim[i] = 0;
         }

         constant_time_bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         constant_time_cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);

         bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);

         /* trim output string to  MAX_PREFIX_LEN bits*/
         memcpy(outputstring_trim,outputstring,BUFFER_LEN);
         if(MAX_PREFIX_LEN % 8){
             unsigned char mask = ((unsigned char) 1 << (8-(MAX_PREFIX_LEN %8))) -1;
             mask = ~mask;
             outputstring_trim[MAX_PREFIX_LEN /8] &= mask;
         } else {
             outputstring_trim[MAX_PREFIX_LEN /8] = 0;
         }
         for (int i = MAX_PREFIX_LEN /8 +1 ;i < BUFFER_LEN;i++){
             outputstring_trim[i] = 0;
         }

         if(memcmp(outputstring_trim,inputstring_trim,BUFFER_LEN)!=0){
              fprintf(stderr,"Mismatch");
              fprintf(stderr,"\nInput string: ");
              for(int i = 0; i< BUFFER_LEN; i++){
                  fprintf(stderr,"%02X ", inputstring[i]);
              }
              fprintf(stderr,"\nInput pretty: ");
              for(int i = 0; i< BUFFER_LEN; i++){
                  fprintf(stderr,"%02X ", inputstring_trim[i]);
              }
              fprintf(stderr,"\nOutput string: ");
              for(int i = 0; i< BUFFER_LEN; i++){
                  fprintf(stderr,"%02X ", outputstring[i]);
              }
              fprintf(stderr,"\n");
              fprintf(stderr,"\nOutput string trim: ");
              for(int i = 0; i< BUFFER_LEN; i++){
                  fprintf(stderr,"%02X ", outputstring_trim[i]);
              }
              fprintf(stderr,"\n");
         } else{
             tests_to_pass--;
        }
    }
    if(tests_to_pass == 0){
        printf("Constant time constant weight enc-decoding functional test: Pass\n");
    }
}

void functional_test_variable_time_CWE(void){
    unsigned char inputstring[BUFFER_LEN]= {0};
    unsigned char inputstring_trim[BUFFER_LEN]= {0};
    unsigned char outputstring[BUFFER_LEN] = {0};
    unsigned char outputstring_trim[BUFFER_LEN] = {0};
    POSITION_T combination_out[NUM_ERRORS_T] = {0};

    int tests_to_pass = NUM_TESTS;

    for(int ntest=0;ntest < NUM_TESTS;ntest++){
         randombytes(inputstring,BUFFER_LEN);
         memset(outputstring,0,BUFFER_LEN);
         memcpy(inputstring_trim,inputstring,BUFFER_LEN);

         /* clear input string for prettyprinting keeping only first
          * MAX_PREFIX_LEN bits*/
         if(MAX_PREFIX_LEN % 8){
             unsigned char mask = ((unsigned char) 1 << (8-(MAX_PREFIX_LEN %8))) -1;
             mask = ~mask;
             inputstring_trim[MAX_PREFIX_LEN /8] &= mask;
         } else {
             inputstring_trim[MAX_PREFIX_LEN /8] = 0;
         }
         for (int i = MAX_PREFIX_LEN /8 +1 ;i < BUFFER_LEN;i++){
             inputstring_trim[i] = 0;
         }

         bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);

         /* trim output string to  MAX_PREFIX_LEN bits*/
         memcpy(outputstring_trim,outputstring,BUFFER_LEN);
         if(MAX_PREFIX_LEN % 8){
             unsigned char mask = ((unsigned char) 1 << (8-(MAX_PREFIX_LEN %8))) -1;
             mask = ~mask;
             outputstring_trim[MAX_PREFIX_LEN /8] &= mask;
         } else {
             outputstring_trim[MAX_PREFIX_LEN /8] = 0;
         }
         for (int i = MAX_PREFIX_LEN /8 +1 ;i < BUFFER_LEN;i++){
             outputstring_trim[i] = 0;
         }

         if(memcmp(outputstring_trim,inputstring_trim,BUFFER_LEN)!=0){
              fprintf(stderr,"Mismatch");
              fprintf(stderr,"\nInput string: ");
              for(int i = 0; i< BUFFER_LEN; i++){
                  fprintf(stderr,"%02X ", inputstring[i]);
              }
              fprintf(stderr,"\nInput pretty: ");
              for(int i = 0; i< BUFFER_LEN; i++){
                  fprintf(stderr,"%02X ", inputstring_trim[i]);
              }
              fprintf(stderr,"\nOutput string: ");
              for(int i = 0; i< BUFFER_LEN; i++){
                  fprintf(stderr,"%02X ", outputstring[i]);
              }
              fprintf(stderr,"\n");
              fprintf(stderr,"\nOutput string trim: ");
              for(int i = 0; i< BUFFER_LEN; i++){
                  fprintf(stderr,"%02X ", outputstring_trim[i]);
              }
              fprintf(stderr,"\n");
         } else{
             tests_to_pass--;
        }
    }
    if(tests_to_pass == 0){
        printf("Variable time constant weight enc-decoding functional test: Pass\n");
    }
}

void functional_test_combinadics(void){
  printf("Combinadics constant weight enc-decoding functional test running ...");
  uint32_t digitsMaxBinom = getNumDigitsBinom(N0*P, NUM_ERRORS_T);
  uint32_t full_decoded_length = digitsMaxBinom+NUM_ERRORS_T;
  uint32_t decoded_length;
  uint32_t randomIntLen = digitsMaxBinom;
  LIMB maxBinom[digitsMaxBinom];
  LIMB randomInt[randomIntLen];
  LIMB decodedInt[full_decoded_length];

  digitsMaxBinom = binom(digitsMaxBinom, maxBinom, N0*P, NUM_ERRORS_T);

  uint32_t combination[NUM_ERRORS_T];
  int status;

  uint32_t msbpos = -1;
  LIMB maxBinomMSD = maxBinom[0];
  while (maxBinomMSD) {
      msbpos++;
      maxBinomMSD >>= 1;
  }
  int tests_to_pass = NUM_TESTS_COMBINADICS;
  for (unsigned ntests = 0; ntests < NUM_TESTS_COMBINADICS; ntests++) {
     decoded_length = full_decoded_length;
     do {
        bigInt_rand(digitsMaxBinom, randomInt);
        randomInt[0] &= ((LIMB)1 << msbpos)-1;
        normalize(&randomIntLen,digitsMaxBinom,randomInt);
     } while (bigInt_cmp(digitsMaxBinom,maxBinom, randomIntLen,randomInt) < 0);

    status = unrank_combination(NUM_ERRORS_T, combination, randomIntLen, randomInt, N0*P);

    if (!status) {
        fprintf(stderr,"Error encountered during unrank\n");
        continue;
    }

    decoded_length = rank_combination(decoded_length, decodedInt,
                                      NUM_ERRORS_T, combination,
                                      N0*P);

    if (decoded_length - (randomIntLen)){
        fprintf(stderr,"decoded length mismatch\n");
    } else if (memcmp(decodedInt,randomInt,(randomIntLen)*LIMB_SIZE_B)){
        fprintf(stderr,"decoded value mismatch\n");
    } else {
        tests_to_pass--;
    }
  }
  if (tests_to_pass == 0){
    printf(" Pass\n");
  }
}


void timing_and_t_test_constant_time_CWE(void){
    unsigned char inputstring[BUFFER_LEN];
    unsigned char outputstring[BUFFER_LEN];
    POSITION_T combination_out[NUM_ERRORS_T];

    welford_t time_rand_input_enc,time_zero_input_enc,
              time_rand_input_dec,time_zero_input_dec;
    uint64_t pre,post;
    welford_init(&time_rand_input_enc);
    welford_init(&time_rand_input_dec);

    welford_init(&time_zero_input_enc);
    welford_init(&time_zero_input_dec);


     for(int ntest=0;ntest < NUM_TESTS;ntest++){
         memset(inputstring,0,BUFFER_LEN);
         memset(combination_out,0,NUM_ERRORS_T*sizeof(POSITION_T));
         memset(outputstring,0,BUFFER_LEN);

         constant_time_bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         pre=x86_64_rtdsc();
         constant_time_bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         post=x86_64_rtdsc();
         welford_update(&time_zero_input_enc,post-pre);

         constant_time_cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);
         pre=x86_64_rtdsc();
         constant_time_cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);
         post=x86_64_rtdsc();
         welford_update(&time_zero_input_dec,post-pre);

         randombytes(inputstring,BUFFER_LEN);
         memset(combination_out,0,NUM_ERRORS_T*sizeof(POSITION_T));
         memset(outputstring,0,BUFFER_LEN);

         constant_time_bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         pre=x86_64_rtdsc();
         constant_time_bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         post=x86_64_rtdsc();
         welford_update(&time_rand_input_enc,post-pre);

         constant_time_cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);
         pre=x86_64_rtdsc();
         constant_time_cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);
         post=x86_64_rtdsc();
         welford_update(&time_rand_input_dec,post-pre);

     }

    fprintf(stdout,"Constant time constant weight enc-decoding timing test. \nEncoding. ");
    welford_print(time_rand_input_enc);
    long double tstat;
    tstat = welch_t_statistic(time_zero_input_enc,time_rand_input_enc);
    fprintf(stdout," t-statistic: %.4Lf -> %s time",tstat, fabsl(tstat) < 4.5 ? "constant": "variable");

    fprintf(stdout,"\nDecoding. ");
    welford_print(time_rand_input_dec);
    tstat = welch_t_statistic(time_zero_input_dec,time_rand_input_dec);
    fprintf(stdout," t-statistic: %.4Lf -> %s time\n",tstat, fabsl(tstat) < 4.5 ? "constant": "variable");
}

void timing_and_t_test_variable_time_CWE(void){
    unsigned char inputstring[BUFFER_LEN];
    unsigned char outputstring[BUFFER_LEN];
    POSITION_T combination_out[NUM_ERRORS_T];

    welford_t time_rand_input_enc,time_zero_input_enc,
              time_rand_input_dec,time_zero_input_dec;
    uint64_t pre,post;
    welford_init(&time_rand_input_enc);
    welford_init(&time_rand_input_dec);

    welford_init(&time_zero_input_enc);
    welford_init(&time_zero_input_dec);


     for(int ntest=0;ntest < NUM_TESTS;ntest++){
         memset(inputstring,0,BUFFER_LEN);
         memset(combination_out,0,NUM_ERRORS_T*sizeof(POSITION_T));
         memset(outputstring,0,BUFFER_LEN);

         bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         pre=x86_64_rtdsc();
         bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         post=x86_64_rtdsc();
         welford_update(&time_zero_input_enc,post-pre);

         cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);
         pre=x86_64_rtdsc();
         cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);
         post=x86_64_rtdsc();
         welford_update(&time_zero_input_dec,post-pre);

         randombytes(inputstring,BUFFER_LEN);
         memset(combination_out,0,NUM_ERRORS_T*sizeof(POSITION_T));
         memset(outputstring,0,BUFFER_LEN);

         bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         pre=x86_64_rtdsc();
         bin_to_cw(combination_out,inputstring,MAX_PREFIX_LEN);
         post=x86_64_rtdsc();
         welford_update(&time_rand_input_enc,post-pre);

         cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);
         pre=x86_64_rtdsc();
         cw_to_bin(outputstring,MAX_PREFIX_LEN,combination_out);
         post=x86_64_rtdsc();
         welford_update(&time_rand_input_dec,post-pre);

     }

    fprintf(stdout,"Variable time constant weight enc-decoding timing test.\nEncoding. ");
    welford_print(time_rand_input_enc);
    long double tstat;
    tstat = welch_t_statistic(time_zero_input_enc,time_rand_input_enc);
    fprintf(stdout," t-statistic: %.4Lf -> %s time",tstat, fabsl(tstat) < 4.5 ? "constant": "variable");

    fprintf(stdout,"\nDecoding. ");
    welford_print(time_rand_input_dec);
    tstat = welch_t_statistic(time_zero_input_dec,time_rand_input_dec);
    fprintf(stdout," t-statistic: %.4Lf -> %s time\n",tstat, fabsl(tstat) < 4.5 ? "constant": "variable");
}

void timing_test_combinadics(void) {

  uint32_t digitsMaxBinom = getNumDigitsBinom(N0*P, NUM_ERRORS_T);
  uint32_t full_decoded_length = digitsMaxBinom+NUM_ERRORS_T;
  uint32_t decoded_length;
  uint32_t randomIntLen = digitsMaxBinom;
  LIMB maxBinom[digitsMaxBinom];
  LIMB randomInt[randomIntLen];
  LIMB decodedInt[full_decoded_length];
  welford_t time_cwe,time_cwd;
  uint64_t pre,post;
  welford_init(&time_cwe);
  welford_init(&time_cwd);

  digitsMaxBinom = binom(digitsMaxBinom, maxBinom, N0*P, NUM_ERRORS_T);

  uint32_t combination[NUM_ERRORS_T];
  int status;

  uint32_t msbpos = -1;
  LIMB maxBinomMSD = maxBinom[0];
  while (maxBinomMSD) {
      msbpos++;
      maxBinomMSD >>= 1;
  }
  for (unsigned ntests = 0; ntests < NUM_TESTS_COMBINADICS; ntests++) {
     decoded_length = full_decoded_length;
     do {
        bigInt_rand(digitsMaxBinom, randomInt);
        randomInt[0] &= ((LIMB)1 << msbpos)-1;
        normalize(&randomIntLen,digitsMaxBinom,randomInt);
     } while (bigInt_cmp(digitsMaxBinom,maxBinom, randomIntLen,randomInt) < 0);

    pre=x86_64_rtdsc();
    status = unrank_combination(NUM_ERRORS_T, combination, randomIntLen, randomInt, N0*P);
    post=x86_64_rtdsc();
    if (!status) {
        fprintf(stderr,"Error encountered during unrank\n");
        continue;
    }
    welford_update(&time_cwe,post-pre);

    pre=x86_64_rtdsc();
    decoded_length = rank_combination(decoded_length, decodedInt,
                                      NUM_ERRORS_T, combination,
                                      N0*P);
    post=x86_64_rtdsc();
    welford_update(&time_cwd,post-pre);
  }

  fprintf(stdout,"Combinadics\nEncoding. ");
  welford_print(time_cwe);
  fprintf(stdout,"\nDecoding. ");
  welford_print(time_cwd);
  fprintf(stdout,"\n");
}


int main(int argc, char *argv[]) {

    printf("Printing results for n=%d, t=%d, l=%d. (All timings are in clock cycles)\n\n",N0*P,NUM_ERRORS_T,MAX_PREFIX_LEN);
    functional_test_constant_time_CWE();
    timing_and_t_test_constant_time_CWE();

    printf("\n");
    functional_test_variable_time_CWE();
    timing_and_t_test_variable_time_CWE();

    printf("\n");
    functional_test_combinadics();
    timing_test_combinadics();

    return 0;
}



