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

#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#define LIMB uint64_t
#define LIMB_SIZE_b 64
#define LIMB_SIZE_B 8

int unrank_combination(const uint32_t T,
                       uint32_t combination[],
                       const uint32_t lenRank,
                       const LIMB rank[],
                       const uint32_t N0P
                      );

uint32_t rank_combination(const uint32_t lenRank, LIMB rank[],
                          const uint32_t T,
                          const uint32_t combination[],
                          const uint32_t N0P
                         );

uint32_t max_set_bit_position(uint32_t amountBlankedMaxBinomBits,
                              const uint32_t N0P,
                              const uint32_t T
                             );

void compute_and_print_pos_histogram(char* pathname,
                                     unsigned int numTests,
                                     uint32_t N0P,
                                     uint32_t T
                                    );



// Convention: Big Endian ... in the first cell of the array A[]
// (i.e.,A[0]) we store the Most Significant Word ...

// void bigInt_add(...)
// lenRes >= (lenA >lenB) ? 1+lenA : 1+lenB, Res[] may have some
// leading digits equal to zero
static void bigInt_add(const unsigned lenRes, LIMB Res[],
                       const unsigned lenA, const LIMB A[],
                       const unsigned lenB, const LIMB B[]
                      );

// void bigInt_cmp(...)
// return -1, if A < B;  return +1, if A > B; return 0, if A == B
int  bigInt_cmp(const unsigned lenA, const LIMB A[],
                       const unsigned lenB, const LIMB B[]
                      );

// void bigInt_sub(...)
// lenRes >= lenA, MANDATORY PRE: A >= B
// Res[] may have some leading digits equal to zero
static void bigInt_sub(const unsigned lenRes, LIMB Res[],
                       const unsigned lenA, const LIMB A[],
                       const unsigned lenB, const LIMB B[]
                      );

// void bigInt_mul(...)
// lenRes >= lenA + lenB, Res[] may have some leading digits
// equal to zero if lenRes is greater than lenA + lenB
static void bigInt_mul(const unsigned lenRes, LIMB Res[],
                       const unsigned lenA, const LIMB A[],
                       const unsigned lenB, const LIMB B[]
                      );

// void normalize(...)
// E.g., if len == 6 and x == 000123,
//       after the call lenNorm == 3 and x == 123xxx
void normalize(unsigned *const lenNorm,
                      const unsigned len, LIMB x[]
                     );

// void bigInt_exactDiv(...)
// lenQin >= lenU - lenV + 1, Most of the times, Q[] will need to be normalized
static void bigInt_exactDiv(const unsigned lenQin, LIMB Q[],
                            const unsigned lenUin, const LIMB Uin[],
                            const unsigned lenVin, const LIMB Vin[]
                           );

// Utilities for development purposes
void bigInt_rand(const unsigned lenRng, LIMB rng[]);
static uint32_t uint32_to_big_int(uint32_t resultLen,
                                  LIMB* result,
                                  uint32_t input
                                 );

// getNumDigitsBinom(...)
unsigned getNumDigitsBinom(const uint32_t N, const uint32_t K);


// binom(...)
// Res[] will be a normalized bigInt,
// the returned value is equal to the number of digit of the normalized bigInt
unsigned binom(const unsigned lenRes, LIMB Res[],
                      uint32_t N, uint32_t K
                     );



void timing_test(unsigned int numTests, uint32_t N0P, uint32_t T);

/*----------------------------------------------------------------------------*/

void bigInt_rand(const unsigned lenRng, LIMB rng[]) {

    int limit = RAND_MAX - (RAND_MAX % 256);
    int r;
    union conv_t { unsigned char charRng[LIMB_SIZE_B];
                   LIMB vd;
    } value;

    for (int i = lenRng-1; i >= 0; i--) {
       for (int j = 0; j < LIMB_SIZE_B; j++) {
           while((r = rand()) >= limit);
           value.charRng[j] = r % 256;
       }
       rng[i] = value.vd;
    }

} // end rand_range


/*----------------------------------------------------------------------------*/

static
void bigInt_add(const unsigned lenRes, LIMB Res[],
                const unsigned lenA, const LIMB A[],
                const unsigned lenB, const LIMB B[]) {

    assert(lenRes >= (lenA >lenB) ? 1+lenA : 1+lenB);
    unsigned lR = lenRes;
    memset(Res, 0x00, lR*LIMB_SIZE_B);

    LIMB *S = (LIMB*) &A[0], *G = (LIMB*) &B[0];
    unsigned lenMin = lenA, lenS = lenA, lenG = lenB;
    if (lenMin > lenB) {
      lenMin = lenB;
      S = (LIMB*) &B[0];
      G = (LIMB*) &A[0];
      lenS = lenB;
      lenG = lenA;
    }
    LIMB kout = (LIMB)0x00, kin, tmp;
    int i;
    for (i = 0; i < lenMin; i++) {
        kin = kout;
        Res[lR-1-i] = S[lenS-1-i] + G[lenG-1-i];
        tmp = Res[lR-i-1] + kin;
        kout = (Res[lR-1-i] < S[lenS-1-i]) + (tmp < kin);
        Res[lR-1-i] = tmp;
    }
    for (i = lenMin; i < lenG; i++) {
       kin = kout;
       Res[lR-1-i] = G[lenG-1-i]+kin;
       kout = (Res[lR-1-i] < kin);
    }
     Res[lR-1-i] = kout;
    //Res[0] = kout;
} // end bigInt_add

/*----------------------------------------------------------------------------*/

int bigInt_cmp(const unsigned lenA, const LIMB A[],
               const unsigned lenB, const LIMB B[]) {

   int i;
   unsigned lA = lenA, lB = lenB;
   for (i = 0; i < lenA && A[i] == 0; i++) lA--;
   for (i = 0; i < lenB && B[i] == 0; i++) lB--;
   if (lA < lB) return -1;
   if (lA > lB) return +1;
   for (i = 0; i < lA; i++) {
     if (A[i] > B[i]) return +1;
     if (A[i] < B[i]) return -1;
   }
   return 0;

} // end bigInt_cmp

/*----------------------------------------------------------------------------*/


void normalize(unsigned *const lenNorm, const unsigned len, LIMB x[]) {

    unsigned lN = len;
    LIMB *ptr = (LIMB*) &x[0];
    while (*ptr == 0 && lN > 1) { ptr++; lN--;}
    for(int i = 0; i < lN; i++) x[i] = ptr[i];
    *lenNorm = lN;
} // end normalize

/*----------------------------------------------------------------------------*/

static
void bigInt_sub(const unsigned lenRes, LIMB Res[],
               const unsigned lenA, const LIMB A[],
               const unsigned lenB, const LIMB B[]) {

    assert(lenRes >= lenA);
    unsigned lR = lenRes;
    memset(Res, 0x00, lenRes*LIMB_SIZE_B);

    LIMB *S = (LIMB*) &B[0], *G = (LIMB*) &A[0];
    unsigned lenS = lenB, lenG = lenA;

    LIMB kout = (LIMB)0x00, kin, tmp;
    int i;
    for (i = 0; i < lenS; i++) {
        kin = kout;
        Res[lR-1-i] =  G[lenG-1-i] - S[lenS-1-i];
        tmp = Res[lR-1-i] - kin;
        kout = (Res[lR-1-i] > G[lenG-1-i])+ (tmp > Res[lR-1-i]);
        Res[lR-1-i] = tmp;

    }
    for (i = lenS; i < lenG; i++) {
       kin = kout;
       Res[lR-1-i] = G[lenG-1-i] - kin;
       kout = (Res[lR-1-i] > G[lenG-1-i]);
    }

} // end bigInt_sub

/*----------------------------------------------------------------------------*/

static
void single_digit_mul(LIMB* const hi,
                      LIMB* const lo,
                      const LIMB a,
                      const LIMB b) {
#define HALF_LIMB_SIZE_b (LIMB_SIZE_b >> 1)
  LIMB op1 = a, op2 = b;

  LIMB mask = ((LIMB)0x01 << HALF_LIMB_SIZE_b)-1;

  LIMB u1 = op1 & mask;
  LIMB v1 = op2 & mask;

  LIMB t = u1 * v1;
  LIMB w3 = t & mask;
  LIMB k = t >> (HALF_LIMB_SIZE_b);

  op1 >>= (HALF_LIMB_SIZE_b);
  t = (op1 * v1) + k;
  k = t & mask;
  LIMB w1 = t >> (HALF_LIMB_SIZE_b);

  op2 >>= (HALF_LIMB_SIZE_b);
  t = (u1 * op2) + k;
  k = t >> (HALF_LIMB_SIZE_b);

  *hi = (op1 * op2) + w1 + k;
  *lo = (t << (HALF_LIMB_SIZE_b)) + w3;

} // end single_digit_mul

/*----------------------------------------------------------------------------*/

static
void bigInt_mul(const unsigned lenRes, LIMB res[],
                const unsigned lenA, const LIMB A[],
                const unsigned lenB, const LIMB B[]) {

   assert(lenRes >= lenA+lenB);
   memset(res, 0x00, lenRes*sizeof(LIMB));
   int i, j;
   LIMB k, lo, hi;
   unsigned lR = lenRes;
   for (i = 0; i < lenA; i++) {
      k = 0;
      for (j = 0; j < lenB; j++) {
        single_digit_mul(&hi, &lo, A[lenA-1-i], B[lenB-1-j]);
        lo += k;
        hi += (lo < k);
        lo += res[lR-1-(i+j)];
        hi += (lo < res[lR-1-(i+j)]);
        res[lR-1-(i+j)] = lo;
        k = hi;
      }
      res[lR-1-(i+lenB)] = k;
   }
} // end bigInt_mul

/*----------------------------------------------------------------------------*/

static
void right_bit_shift(const int length, LIMB in[]) {

  int j;
  for (j = length-1; j > 0 ; j--) {
      in[j] >>= 1;
      in[j] |=  (in[j-1] & (LIMB)0x01) << (LIMB_SIZE_b-1);
  }
  in[j] >>=1;
} // end right_bit_shift

/*----------------------------------------------------------------------------*/

// Exact division when the radix is a power of 2 (LIMB -- in our case)
// output: Q such that U = Q*V -- lenQ == lenU - lenV + 1
// T. Jebelean, "An Algorithm for exact division",
// Journal of Symbolic Computation, Vol 15, no. 2, 1993, Elsevier.
// Algorithm 10.39 pp. 189--190 in Henri Cohen, Gerhard Frey,
// "Handbook of Elliptic and Hyperelliptic Curve Cryptography".
// Chapman & Hall/CRC.

// lenQin must be equal to  number of cells allocated for the array Q

static
void bigInt_exactDiv(const unsigned lenQin, LIMB Q[],
                     const unsigned lenUin, const LIMB Uin[],
                     const unsigned lenVin, const LIMB Vin[]) {

  memset(Q, 0x00, lenQin*sizeof(LIMB));
  if (lenVin == 1 && Vin[0] == 0x00) return; // division by zero
  if (lenUin < lenVin) return;               // quotient is zero

  assert(lenQin >= lenUin - lenVin + 1);

  unsigned lenU = lenUin;
  unsigned lenV = lenVin;
  LIMB U[lenU], V[lenV];
  memcpy(U, Uin, lenU*LIMB_SIZE_B);
  memcpy(V, Vin, lenV*LIMB_SIZE_B);

  while (V[lenV-1] % 2 == 0)  {
      right_bit_shift(lenV, V);
      right_bit_shift(lenU, U);
  }
  normalize(&lenU, lenU, U);
  normalize(&lenV, lenV, V);

  LIMB t = (LIMB) 0x1, V0 = V[lenV-1];
  // t := V0^{-1} mod 2^{LIMB_SIZE_b}
  for (int i = 0; i < LIMB_SIZE_b-1; i++) {
     t *= t;
     t *= V0;
  }
  assert ((LIMB)((LIMB)t*(LIMB)V0) == (LIMB)0x1);

  unsigned lQ = lenUin - lenVin + 1;
  LIMB qi;
  LIMB qiV[lenV+1], modU[lQ], modqiV[lQ], sub[lQ], sub2[lQ+1], corr[lQ+1];
  unsigned lenSub;
  int i, j;
  memset(corr, 0x00, (lQ+1)*sizeof(LIMB));
  corr[0] = 0x1;
  for (i = 0 ; i < lQ; i++)
  {

     qi = U[lenU-1]*t;
     Q[lenQin-1-i] = qi;
     // u := ( (u-v*qi) mod b^{lenQin-i} ) / b

     for (j = 0; j < lQ-i; j++) {
         if ((int)lenU-1-j >= 0) modU[lQ-i-1-j] = U[lenU-1-j];
         else modU[lQ-i-1-j] = 0x00;
     }

     bigInt_mul(lenV+1, qiV, lenV, V, 1, &qi);
     for (j = 0; j < lQ-i; j++) {
         if ((int)lenV-j >= 0) modqiV[lQ-i-1-j] = qiV[lenV-j];
         else modqiV[lQ-i-1-j] = 0x00;
     }

     if (bigInt_cmp(lQ-i, modU, lQ-i, modqiV) >= 0) {
       bigInt_sub(lQ-i, sub, lQ-i, modU, lQ-i, modqiV);
     }
     else {
       bigInt_sub(lQ-i, sub,
                  lQ-i, modqiV,
                  lQ-i, modU);
       bigInt_sub(lQ-i+1, sub2,
                  lQ-i+1, corr,
                  lQ-i, sub);
       for (j = 0; j < lQ-i; j++) {
         if ((int)lQ-i+1-1-j >= 0) sub[lQ-i-1-j] = sub2[lQ-i+1-1-j];
         else sub[lQ-i-1-j] = 0x00;
       }
     }
     lenSub = lQ-i;
     for (j = 0; j < lQ-i; j++) U[lenSub-1-j] = sub[lenSub-1-j];
     if (lenSub > 1) { lenU = lenSub-1; } else { U[0] = 0; lenU = 1; }
  }

} // end bigInt_exactDiv

/*----------------------------------------------------------------------------*/


unsigned getNumDigitsBinom(const uint32_t N, const uint32_t K) {

   if (N <= 0 || K <= 0 || N <= K ) return 1;

   unsigned int logN = 0;
   LIMB v = N;

   while (v >>= (LIMB)0x1)
        logN++;
   logN++;
   if (K > 1) return (K-1)*logN;

   return logN;
} // end getNumDigitsBinom

/*----------------------------------------------------------------------------*/

unsigned binom(const unsigned lenRes, LIMB Res[], uint32_t N, uint32_t K) {

    assert( N >= K && K >= 0 );

    LIMB currentRes[lenRes];
    unsigned currentLenRes, newlenRes;

    memset(Res, 0x00, lenRes*LIMB_SIZE_B);
    memset(currentRes, 0x00, lenRes*LIMB_SIZE_B);

    uint32_t diff = N-K;
    if (diff == (uint32_t)0x00) {
        Res[0] = 1;
        return 1;
    }
    if (K < diff) { diff = K; K = N - diff; }

    currentRes[0] = (LIMB)K+1;
    currentLenRes = 1;

    uint32_t I, lenIDig = sizeof(uint32_t);
    LIMB IDig[4];

    for ( I = 2; I <= diff; I++ )
    {
        LIMB buff[4];
        uint32_t lenBuff = 4;
        lenBuff = uint32_to_big_int(lenBuff,buff,K+I);
        bigInt_mul(currentLenRes+1, Res,
                   currentLenRes, currentRes,
                   lenBuff, buff
                  );
        normalize(&newlenRes, currentLenRes+1, Res);
        lenIDig = uint32_to_big_int(lenIDig, IDig, I);
        bigInt_exactDiv(newlenRes, currentRes,
                        newlenRes, Res,
                        lenIDig, IDig
                       );
        normalize(&currentLenRes, newlenRes, currentRes);
    }
    for (int j = currentLenRes-1; j >= 0; j--)
       Res[j] = currentRes[j];

    return currentLenRes;
} // end binom

/*----------------------------------------------------------------------------*/

int unrank_combination(const uint32_t T,
                       uint32_t combination[],
                       const uint32_t lenRank,
                       const LIMB rank[],
                       const uint32_t N0P
                      ) {

    LIMB v[lenRank], vBuff[lenRank];
    memset(vBuff, 0x00, lenRank*LIMB_SIZE_B);

    unsigned int lenV = lenRank, lenVBuff;

    memcpy(v, rank, lenV*LIMB_SIZE_B);

    memset(combination, 0x00, T*sizeof(uint32_t));

    if ( (v[lenV-1] == (LIMB)0) && (lenV == (LIMB)1) ){
      for(unsigned i = 0; i < T; i++) combination[i] = i;
      return 1;
    }

    if ( (v[lenV-1] == (LIMB)1) && (lenV == (LIMB)1) ) {
      for(unsigned i = 0;i < T-1; i++) combination[i] = i;
      combination[T-1]=T;
      return 1;
    }

    unsigned int digitSizeBinom = getNumDigitsBinom(N0P, T);
    LIMB currBin[digitSizeBinom], mulBufferCurrBin[digitSizeBinom];
    memset(currBin, 0x00, digitSizeBinom);
    memset(mulBufferCurrBin, 0x00, digitSizeBinom);

    currBin[0] = 1;
    unsigned int lenCurrBin = 1, lenMulBufferCurrBin;

    LIMB eAcc = T-1;

    while(bigInt_cmp(lenCurrBin, currBin, lenV, v) == -1) {
        eAcc++;
        /* curr <- curr *(eacc+1)/(eacc+1-k) */
        lenMulBufferCurrBin = lenCurrBin+1;

        uint32_t lenNumer = lenCurrBin;
        LIMB numer[lenNumer];
        lenNumer = uint32_to_big_int(lenNumer,
                                     numer,
                                     eAcc + 1
                                    );
        bigInt_mul(lenMulBufferCurrBin,mulBufferCurrBin,
                   lenCurrBin,currBin,
                   lenNumer, numer
                  );
        normalize(&lenMulBufferCurrBin, lenMulBufferCurrBin, mulBufferCurrBin);

        uint32_t lenDenom = lenCurrBin;
        LIMB denom[lenDenom];
        lenDenom = uint32_to_big_int(lenDenom,
                                     denom,
                                     eAcc + 1 - T
                                    );

        lenCurrBin = lenMulBufferCurrBin;
        bigInt_exactDiv(lenCurrBin, currBin,
                        lenMulBufferCurrBin, mulBufferCurrBin,
                        lenDenom, denom
                       );
        normalize(&lenCurrBin, lenCurrBin, currBin);
    } // end while

    combination[T-1] = eAcc;

    int i = T;
    /* curr <- curr *(eacc+1-k)/(eacc+1) */
    lenMulBufferCurrBin = lenCurrBin+1;

    uint32_t lenNumer = lenCurrBin;
    LIMB numer[lenNumer];
    lenNumer = uint32_to_big_int(lenNumer,
                                 numer,
                                 eAcc +1 - T
                                );
    bigInt_mul(lenMulBufferCurrBin,mulBufferCurrBin,
               lenCurrBin,currBin,
               lenNumer, numer
              );
    normalize(&lenMulBufferCurrBin, lenMulBufferCurrBin, mulBufferCurrBin);

    uint32_t lenDenom = lenCurrBin;
    LIMB denom[lenDenom];
    lenDenom = uint32_to_big_int(lenDenom,
                                 denom,
                                 eAcc +1
                                );
    lenCurrBin = lenMulBufferCurrBin;
    bigInt_exactDiv(lenCurrBin,currBin,
                    lenMulBufferCurrBin, mulBufferCurrBin,
                    lenDenom, denom
                   );
    normalize(&lenCurrBin, lenCurrBin, currBin);

    /* v <- v - currBin*/
    lenVBuff = lenV;
    bigInt_sub(lenVBuff, vBuff,
               lenV, v,
               lenCurrBin, currBin
              );
    normalize(&lenV, lenVBuff, vBuff);
    for(int i = 0; i < lenV; i++) v[i] = vBuff[i];

    if ( (v[lenV-1] != (LIMB)0) || (lenV != (LIMB)1) ) {   // v > 0
        i--;
        while (i > 0) {
            /* curr <- curr *(i+1)/(eacc+1-(i+1)) */
            lenMulBufferCurrBin = lenCurrBin+1;
            uint32_t lenNumer = lenCurrBin;
            LIMB numer[lenNumer];
            lenNumer = uint32_to_big_int(lenNumer,
                                         numer,
                                         i+1
                                        );
            bigInt_mul(lenMulBufferCurrBin, mulBufferCurrBin,
                       lenCurrBin, currBin,
                       lenNumer, numer
                      );
            normalize(&lenMulBufferCurrBin,
                      lenMulBufferCurrBin,
                      mulBufferCurrBin
                     );
            uint32_t lenDenom = lenCurrBin;
            LIMB denom[lenDenom];
            lenDenom = uint32_to_big_int(lenDenom,
                                         denom,
                                         eAcc +1 - (i+1)
                                        );
            lenCurrBin = lenMulBufferCurrBin-1+1;
            bigInt_exactDiv(lenCurrBin,currBin,
                            lenMulBufferCurrBin, mulBufferCurrBin,
                            lenDenom, denom
                           );
            normalize(&lenCurrBin, lenCurrBin, currBin);

            while (bigInt_cmp(lenCurrBin, currBin, lenV, v) == 1) {
                /* curr <- curr *(eacc-i)/(eacc) */
                lenMulBufferCurrBin = lenCurrBin+1;
                uint32_t lenNumer = lenCurrBin;
                LIMB numer[lenNumer];
                lenNumer = uint32_to_big_int(lenNumer,
                                             numer,
                                             eAcc-i
                                             );
                bigInt_mul(lenMulBufferCurrBin, mulBufferCurrBin,
                           lenCurrBin, currBin,
                           lenNumer, numer
                          );
                normalize(&lenMulBufferCurrBin,
                          lenMulBufferCurrBin,
                          mulBufferCurrBin
                         );
                uint32_t lenDenom = lenCurrBin;
                LIMB denom[lenDenom];
                lenDenom = uint32_to_big_int(lenDenom,
                                             denom,
                                             eAcc
                                            );
                lenCurrBin = lenMulBufferCurrBin;
                bigInt_exactDiv(lenCurrBin, currBin,
                                lenMulBufferCurrBin, mulBufferCurrBin,
                                lenDenom, denom
                               );
                normalize(&lenCurrBin, lenCurrBin, currBin);
                eAcc --;
            } // end while  (bigInt_cmp... )
            /* v <- v - currBin*/
            lenVBuff = lenV;
            bigInt_sub(lenVBuff, vBuff,
                       lenV, v,
                       lenCurrBin, currBin
                      );
            normalize(&lenV, lenVBuff, vBuff);
            for(int i = 0; i < lenV; i++)  v[i] = vBuff[i];

            combination[i-1] = eAcc;
            i--;

            if (v[lenV-1] == (LIMB)0 && lenV == (LIMB)1)
              break;
        } // end while (i > 0)
        if (lenV != (LIMB)1 || v[lenV-1] != (LIMB)0)
            return 0;
    } // end if (v > 0)
    while (i > 0){
        combination[i-1] = i - 1;
        i--;
    }

    return 1;
} // end unrank_combination

/*----------------------------------------------------------------------------*/

static
uint32_t uint32_to_big_int(uint32_t resultLen, LIMB* result, uint32_t input) {

   if (LIMB_SIZE_B >= sizeof(uint32_t)) {
      result[0]=input;
      return 1;
   }
   if (LIMB_SIZE_B == sizeof(uint16_t)){
      LIMB msd = (LIMB) (input >> 16);
      if (msd == 0){
       result[0]= (LIMB) (input & 0xFFFF);
       return 1;
      }
      result[0] = msd;
      result[1] = input & 0xFFFF;
      return 2;
   }
   if (LIMB_SIZE_B == sizeof(uint8_t)){
      LIMB firstDigit = (LIMB) (input >> 24);
      LIMB secondDigit= (LIMB) (input >> 16);
      LIMB thirdDigit = (LIMB) (input >> 8);
      LIMB fourthDigit= (LIMB) (input & 0xFF);
      if ((firstDigit == 0) &&
          (secondDigit == 0)&&
          (thirdDigit == 0) ){
        result[0]=fourthDigit;
        return 1;
      }
      if ((firstDigit == 0) &&
          (secondDigit == 0)){
        result[0]=thirdDigit;
        result[1]=fourthDigit;
        return 2;
      }
      if ((firstDigit == 0)){
        result[0]=secondDigit;
        result[1]=thirdDigit;
        result[2]=fourthDigit;
        return 3;
      }
      result[0] = firstDigit;
      result[1] = secondDigit;
      result[2] = thirdDigit;
      result[3] = fourthDigit;
      return 4;
   }
} // end uint32_to_big_int

/*----------------------------------------------------------------------------*/

uint32_t rank_combination(const uint32_t lenRank,
                          LIMB rank[],
                          const uint32_t T,
                          const uint32_t combination[],
                          const uint32_t N0P
                         ) {
    int i = 0;
    while ((i < T) && (combination[i] < i+1)) {
        i++;
    }
    if (i >= T){
        rank[0]=0;
        return 1;
    }
    int eAcc = combination[i];

    unsigned int lenBinomAcc = getNumDigitsBinom(N0P, T);
    unsigned int lenV, lenVBuff, lenBinomAccBuff;


    LIMB binomAcc[lenBinomAcc], binomAccBuff[lenBinomAcc];
    lenV = lenBinomAcc+T;
    assert(lenV <= lenRank);
    LIMB v[lenV], vBuff[lenV];

    lenBinomAcc = binom(lenBinomAcc, binomAcc, combination[i], ((uint32_t)i)+1);

    memcpy(v, binomAcc, lenBinomAcc*LIMB_SIZE_B);
    lenV = lenBinomAcc;

    i++;
    while (i < T) {

        if (eAcc == i) {
            eAcc++;
            lenBinomAcc = 1;
            binomAcc[0] = 1;
        } else {
            uint32_t lenNumer = lenBinomAcc;
            LIMB numer[lenNumer];
            lenNumer = uint32_to_big_int(lenNumer,
                                         numer,
                                         eAcc - (uint32_t)i
                                        );

            lenBinomAccBuff = lenBinomAcc+lenNumer;
            bigInt_mul(lenBinomAccBuff, binomAccBuff,
                       lenBinomAcc, binomAcc,
                       lenNumer, numer
                      );
            normalize(&lenBinomAccBuff, lenBinomAccBuff, binomAccBuff);

            uint32_t lenDenom = lenBinomAcc;
            LIMB denom[lenDenom];
            lenDenom = uint32_to_big_int(lenDenom, denom, (uint32_t)i+1);

            lenBinomAcc = lenBinomAccBuff - lenDenom + 1;
            bigInt_exactDiv(lenBinomAcc, binomAcc,
                            lenBinomAccBuff, binomAccBuff,
                            lenDenom, denom);
            normalize(&lenBinomAcc, lenBinomAcc, binomAcc);
        } // end else
        while (eAcc < combination[i]) {

            uint32_t lenNumer = lenBinomAcc;
            LIMB numer[lenNumer];
            lenNumer = uint32_to_big_int(lenNumer, numer, (uint32_t)eAcc + 1);

            lenBinomAccBuff = lenBinomAcc+lenNumer;
            bigInt_mul(lenBinomAccBuff, binomAccBuff,
                       lenBinomAcc, binomAcc,
                       lenNumer, numer);
            normalize(&lenBinomAccBuff, lenBinomAccBuff, binomAccBuff);

            uint32_t lenDenom = lenBinomAcc;
            LIMB denom[lenDenom];
            lenDenom = uint32_to_big_int(lenDenom,
                                         denom,
                                         (uint32_t)eAcc - (uint32_t)i
                                        );

            lenBinomAcc = lenBinomAccBuff - lenDenom +1;
            bigInt_exactDiv(lenBinomAcc, binomAcc,
                            lenBinomAccBuff, binomAccBuff,
                            lenDenom, denom);
            normalize(&lenBinomAcc, lenBinomAcc, binomAcc);

           eAcc++;
        } // end while
        lenVBuff = (lenV > lenBinomAcc) ? lenV+1 : lenBinomAcc+1;
        bigInt_add(lenVBuff, vBuff,
                   lenV, v,
                   lenBinomAcc, binomAcc
                  );
        normalize(&lenVBuff, lenVBuff, vBuff);

        memcpy(v, vBuff, lenVBuff*LIMB_SIZE_B);
        lenV = lenVBuff;
        i++;
    } // end  while (i < T)

    memcpy(rank, v, lenV*LIMB_SIZE_B);

    return lenV;
} // end rank_combination

/*----------------------------------------------------------------------------*/


