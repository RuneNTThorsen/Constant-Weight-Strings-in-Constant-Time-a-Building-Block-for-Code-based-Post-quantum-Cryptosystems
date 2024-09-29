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

#include "bitstring_parameters.h"
#include "gf2x_limbs.h"
/*----------------------------------------------------------------------------*/

enum cwenc_result {
    OK, OUT_OF_BOUND, READ_LESS_THAN_MIN
};

enum d_choice {
    FIXED,      // estimate d, u at the beginning and never change it
    VARIABLE,   // new d, u every iteration
    FIRST_VAR   // first iteration d = min-{computed_d, (n-t-1)/margin}, next iterations like VARIABLE
};

enum padding_point {
    QUOTIENT, REM_PREFIX, REM_SUFFIX, ALL
};

int constant_time_bin_to_cw(POSITION_T positionsOut[NUM_ERRORS_T],
                            unsigned char * bitstreamIn,
                            int guaranteed_bit_lenght);

void constant_time_cw_to_bin(unsigned char *const bitstreamOut,
                             const int trimOutLength,
                            POSITION_T positionsIn[NUM_ERRORS_T]);
int bin_to_cw(POSITION_T positionsOut[NUM_ERRORS_T],
                            unsigned char * bitstreamIn,
                            int guaranteed_bit_lenght);
void cw_to_bin(unsigned char * bitstreamOut,
               const int trimOutLength,
               POSITION_T positionsIn[NUM_ERRORS_T]);
