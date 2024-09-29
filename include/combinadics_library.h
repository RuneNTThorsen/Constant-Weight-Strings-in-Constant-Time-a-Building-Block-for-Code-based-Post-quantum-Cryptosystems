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
#pragma once

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

unsigned getNumDigitsBinom(const uint32_t N,
                           const uint32_t K);
unsigned binom(const unsigned lenRes,
               LIMB Res[],
               uint32_t N,
               uint32_t K);

void bigInt_rand(const unsigned lenRng,
                 LIMB rng[]);
void normalize(unsigned *const lenNorm, const unsigned len, LIMB x[]);
int  bigInt_cmp(const unsigned lenA, const LIMB A[],
                       const unsigned lenB, const LIMB B[]
                      );
