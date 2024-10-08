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

#if (PARAMETER_SET == 71798)
// LEDAcrypt Category 1
#define P 35899
#define NUM_ERRORS_T 136
#define MAX_PREFIX_LEN 256
#define DIVISOR_POWER_OF_TWO 8
#elif (PARAMETER_SET == 115798)
// LEDAcrypt Category 3
#define P 57899
#define NUM_ERRORS_T 199
#define MAX_PREFIX_LEN 384
#define DIVISOR_POWER_OF_TWO 8
#elif (PARAMETER_SET == 178102)
// LEDAcrypt Category 5
#define P 89051
#define NUM_ERRORS_T 267
#define MAX_PREFIX_LEN 512
#define DIVISOR_POWER_OF_TWO 8
# elif (PARAMETER_SET == 20326)
// CSCML 2019 comparison
#define P 10163
#define NUM_ERRORS_T 134
#define MAX_PREFIX_LEN 256
#define DIVISOR_POWER_OF_TWO 6

#else
#error parameter set not available
#endif

#define N0 2
#define DIVISOR (1 << DIVISOR_POWER_OF_TWO)
#define MAX_COMPRESSED_LEN (((N0*P-NUM_ERRORS_T)/(DIVISOR))+ NUM_ERRORS_T*(1+DIVISOR_POWER_OF_TWO))
