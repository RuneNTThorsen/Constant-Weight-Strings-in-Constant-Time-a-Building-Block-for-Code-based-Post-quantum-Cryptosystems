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

#include "constant_weight_codec.h"
#include <string.h>
#include <emmintrin.h>
#include <stdio.h>

/******************************************************************************
 *          Variable time, reference implementation                           *
 ******************************************************************************/

/* bits will be written to the output matching the same convention of the
 * bitstream read, i.e., in the same order as they appear in the natural
 * encoding of the uint64_t, with the most significant bit being written
 * as the first one in the output bitstream, starting in the output_bit_cursor
 * position */


void bitstream_write(unsigned char *output,
                     const unsigned int amount_to_write,
                     unsigned int output_bit_cursor,
                     uint64_t value_to_write) {
    if (amount_to_write == 0) return;
    unsigned int bit_cursor_in_char = output_bit_cursor % 8;
    unsigned int byte_cursor = output_bit_cursor / 8;
    unsigned int remaining_bits_in_char = 8 - bit_cursor_in_char;

    if (amount_to_write <= remaining_bits_in_char) {
        uint64_t cleanup_mask = ( ( (uint64_t) 1 << amount_to_write ) - 1);
        cleanup_mask = cleanup_mask << (remaining_bits_in_char - amount_to_write);
        cleanup_mask = ~cleanup_mask;
        uint64_t buffer = output[byte_cursor];

        buffer = (buffer & cleanup_mask) | (value_to_write << (remaining_bits_in_char
                                                               - amount_to_write));
        output[byte_cursor] = (unsigned char) buffer;
        output_bit_cursor += amount_to_write;
    } else {
        /*copy remaining_bits_in_char, allowing further copies to be byte aligned */
        uint64_t write_buffer = value_to_write >> (amount_to_write -
                                                   remaining_bits_in_char);
        uint64_t cleanup_mask = ~((1 << remaining_bits_in_char) - 1);

        uint64_t buffer = output[byte_cursor];
        buffer = (buffer & cleanup_mask) | write_buffer;
        output[byte_cursor] = buffer;
        output_bit_cursor += remaining_bits_in_char;
        byte_cursor = output_bit_cursor / 8;

        /*write out as many as possible full bytes*/
        uint64_t still_to_write = amount_to_write - remaining_bits_in_char;
        while (still_to_write > 8) {
            write_buffer = value_to_write >> (still_to_write - 8) & (uint64_t) 0xFF;
            output[byte_cursor] = write_buffer;
            output_bit_cursor += 8;
            byte_cursor++;
            still_to_write -= 8;
        } // end while
        /*once here, only the still_to_write-LSBs of value_to_write are to be written
         * with their MSB as the MSB of the output[byte_cursor] */
        if (still_to_write > 0) {
            write_buffer = value_to_write & ((1 << still_to_write) - 1);
            uint64_t cleanup_mask = ~(((1 << still_to_write) - 1) << (8 - still_to_write));
            write_buffer = write_buffer << (8 - still_to_write);

            output[byte_cursor] &= cleanup_mask;
            output[byte_cursor] |= write_buffer;
            output_bit_cursor += still_to_write;
        } // end if
    } // end else
    _mm_mfence();
} // end bitstream_write


/*----------------------------------------------------------------------------*/

uint64_t bitstream_read(const unsigned char *const stream,
                        const unsigned int bit_amount,
                        unsigned int bit_cursor) {
    if (bit_amount == 0) return (uint64_t) 0;
    uint64_t extracted_bits = 0;
    int bit_cursor_in_char = bit_cursor % 8;
    int remaining_bits_in_char = 8 - bit_cursor_in_char;

    if (bit_amount <= remaining_bits_in_char) {
        extracted_bits = (uint64_t) (stream[bit_cursor / 8]);
        int slack_bits = remaining_bits_in_char - bit_amount;
        extracted_bits = extracted_bits >> slack_bits;
        extracted_bits = extracted_bits & ((((uint64_t) 1) << bit_amount) - 1);

    } else {
        unsigned int byte_cursor = bit_cursor / 8;
        unsigned int still_to_extract = bit_amount;
        if (bit_cursor_in_char != 0) {
            extracted_bits = (uint64_t) (stream[bit_cursor / 8]);
            extracted_bits = extracted_bits & ((((uint64_t) 1) << (7 -
                                                                   (bit_cursor_in_char - 1))) - 1);
            still_to_extract = bit_amount - (7 - (bit_cursor_in_char - 1));
            byte_cursor++;
        }
        while (still_to_extract > 8) {
            extracted_bits = extracted_bits << 8 | ((uint64_t) (stream[byte_cursor]));
            byte_cursor++;
            still_to_extract = still_to_extract - 8;
        }
        /* here byte cursor is on the byte where the still_to_extract MSbs are to be
         taken from */
        extracted_bits = (extracted_bits << still_to_extract) | ((uint64_t) (
                stream[byte_cursor])) >> (8 - still_to_extract);
    }
    return extracted_bits;
}

/*----------------------------------------------------------------------------*/

static
uint64_t bitstream_read_clamped(const unsigned char *const stream,
                               const unsigned int bitAmount,
                               const unsigned int bitstreamLength,
                               const unsigned int bitCursor) {
    uint64_t readBitstreamFragment = 0;
    if ( (bitCursor + bitAmount) <= bitstreamLength) {
        /* bitCursor can be right after the last if I read input up to the last*/
        readBitstreamFragment = bitstream_read(stream, bitAmount, bitCursor);
    } else {
        fprintf(stderr,"out of bounds: %d,amt %d, max %d",
                bitCursor,
                bitAmount,
                bitstreamLength);
    }
    return readBitstreamFragment;
}


/*----------------------------------------------------------------------------*/

static inline
uint64_t bitstream_read_single_bit(const unsigned char *const stream,
                                   const unsigned int bitCursor) {
    int index = bitCursor /8;
    int posInByte = bitCursor %8;
    unsigned char mask = ((unsigned char) 0x80) >> posInByte;
    return (stream[index] & mask)!=0;
}
/*----------------------------------------------------------------------------*/
/* constant time rand range: returns uniform random number in {0,...,range} */

#include <x86intrin.h>
#include <immintrin.h>

POSITION_T rand_range_ct(POSITION_T max){
    POSITION_T trim_mask, maxBitLen=0;
    POSITION_T max_count_bits = max;

    for(int i =0; i< sizeof(POSITION_T)*8; i++){
        maxBitLen += (max_count_bits>0);
        max_count_bits = max_count_bits >> 1;
    }

    trim_mask= (((POSITION_T)1) << maxBitLen )-1;

    POSITION_T result,randvalue;
    while (!_rdrand32_step(&randvalue));
    result =  max+1 / 2;
    result = (randvalue * (max+1) + result) / (((POSITION_T)RAND_MAX) + 1);
    result &= trim_mask;
    return result;
}

/*****************************************************************************/

typedef enum takenPath {CUT_QUOTIENT=0,
                        FULL_QUOTIENT,
                        CUT_REMAINDER,
                        FULL_LENGTH,
                        END_OF_INPUT} takenPath;

int bin_to_cw(POSITION_T positionsOut[NUM_ERRORS_T],
                            unsigned char * bitstreamIn,
                            int guaranteed_bit_lenght) {

    POSITION_T runLengths[NUM_ERRORS_T];

    uint32_t idxDistances = 0;
    int32_t outPositionsStillAvailable = (N0 * P) - NUM_ERRORS_T;
    unsigned int bitstreamCursor = 0;
    /* assuming trailing slack bits in the input stream.
     * In case the slack bits in the input stream are leading, change to
     * 8- (bitLength %8) - 1 */
    enum takenPath computation_path = FULL_LENGTH;

    for (idxDistances = 0; idxDistances < NUM_ERRORS_T; idxDistances++) {
        /* lack of positions should not be possible */
        /*estimate d and u : fixed as macros*/
        /* read unary-encoded quotient, i.e. leading 1^* 0 */
        unsigned int quotient = 0;
        uint32_t read_remainder = 0;
        int missing_remainder_bits =0;
        uint64_t read_bit =0;
        if(computation_path != END_OF_INPUT) {
           do{
               read_bit = bitstream_read_clamped(bitstreamIn,
                                                        1,
                                                        guaranteed_bit_lenght,
                                                        bitstreamCursor);
               bitstreamCursor++;
               quotient += read_bit;
           } while ((read_bit == 1) && (bitstreamCursor < guaranteed_bit_lenght));

           if ((read_bit == 1) && !(bitstreamCursor < guaranteed_bit_lenght)){
               computation_path = CUT_QUOTIENT;
           } else if ((read_bit == 0) && !(bitstreamCursor < guaranteed_bit_lenght)) {
               computation_path = FULL_QUOTIENT;
           }

           if (bitstreamCursor+DIVISOR_POWER_OF_TWO <= guaranteed_bit_lenght) {
               computation_path = FULL_LENGTH;
               /* decode binary encoded remainder*/
               read_remainder = bitstream_read_clamped(bitstreamIn,
                                          DIVISOR_POWER_OF_TWO,
                                          guaranteed_bit_lenght,
                                          bitstreamCursor);

               bitstreamCursor += DIVISOR_POWER_OF_TWO;
           } else if (bitstreamCursor < guaranteed_bit_lenght) {
               computation_path = CUT_REMAINDER;
               read_remainder = bitstream_read_clamped(bitstreamIn,
                                          guaranteed_bit_lenght-bitstreamCursor,
                                          guaranteed_bit_lenght,
                                          bitstreamCursor);
               missing_remainder_bits = DIVISOR_POWER_OF_TWO -
                                       (guaranteed_bit_lenght - bitstreamCursor);
               bitstreamCursor = guaranteed_bit_lenght;
           }
        }

        int range;
        switch(computation_path){
            case CUT_QUOTIENT:
                range = outPositionsStillAvailable - quotient*DIVISOR;
                runLengths[idxDistances] = read_remainder /* will be 0 here*/
                                           + quotient * DIVISOR
                                           + rand_range_ct(range);

                break;
            case FULL_QUOTIENT:
                range = outPositionsStillAvailable - quotient*DIVISOR;
                range = range > (DIVISOR-1) ? (DIVISOR-1) : range;
                runLengths[idxDistances] = read_remainder /* will be 0 here*/
                                           + quotient * DIVISOR
                                           + rand_range_ct(DIVISOR-1);
                break;
            case CUT_REMAINDER:
                runLengths[idxDistances] = (read_remainder << missing_remainder_bits)
                                           + quotient * DIVISOR
                                           + rand_range_ct( (1 << missing_remainder_bits)-1);
                break;
            case FULL_LENGTH:
                runLengths[idxDistances] = read_remainder + quotient * DIVISOR;
                break;
            case END_OF_INPUT:
                runLengths[idxDistances] = rand_range_ct(outPositionsStillAvailable);
                break;
        }
        outPositionsStillAvailable -= runLengths[idxDistances];
        if (bitstreamCursor >= guaranteed_bit_lenght){
            computation_path = END_OF_INPUT;
        }
    }

    /*encode ones according to runLengths into constantWeightOut */
    int current_one_position = -1;
    for (int i = 0; i < NUM_ERRORS_T; i++) {
        current_one_position += runLengths[i] + 1;
        positionsOut[i] = current_one_position;
    }

    return 1;
}

/*----------------------------------------------------------------------------*/
/* Encodes a bit string into a constant weight N0 polynomials vector*/
void cw_to_bin(unsigned char * bitstreamOut,
               const int trimOutLength,
               POSITION_T positionsIn[NUM_ERRORS_T]){
    unsigned int runLengths[NUM_ERRORS_T] = {0};

    /*compute the array of inter-ones distances. Note that there
     is an implicit one out of bounds to compute the first distance from */
    unsigned int idxDistances = 0;

    /* compute run lengths from one positions */
    runLengths[0]=positionsIn[0]-0;

    for (int i = 1; i<NUM_ERRORS_T; i++){
        runLengths[i] = positionsIn[i] - positionsIn[i-1] /*remove the 1*/ - 1;
    }

    /* perform encoding of distances into binary string*/
    unsigned int outputBitCursor = 0;

    for (idxDistances = 0; idxDistances < NUM_ERRORS_T; idxDistances++) {
        unsigned int quotient = runLengths[idxDistances] / DIVISOR;
        for (int outbit=0; outbit<quotient; outbit++){
        bitstream_write(bitstreamOut,1,
                        outputBitCursor,(uint64_t) 1);
        outputBitCursor++;
        }
        bitstream_write(bitstreamOut,1,
                        outputBitCursor,(uint64_t) 0);
        outputBitCursor++;
        unsigned int remainder = runLengths[idxDistances] % DIVISOR;
        bitstream_write(bitstreamOut, DIVISOR_POWER_OF_TWO, outputBitCursor, remainder);
        outputBitCursor += DIVISOR_POWER_OF_TWO;
    }
} // end constant_weight_to_binary_approximate


#define COND_EXP2(COND,TRUE,FALSE) ( ((COND)*(TRUE)) | (!(COND)*(FALSE)) )
#define CONVTOMASK(x) ((uint32_t)0 -x)
#define COND_EXP(COND,TRUE,FALSE) ( ( CONVTOMASK(COND)&(TRUE)) | (CONVTOMASK(!(COND))&(FALSE)) )


void ct_store(POSITION_T* v, int index, POSITION_T value){
     _mm_stream_si32 ((int*)(v+index), value);
     _mm_mfence();
}

int constant_time_bin_to_cw(POSITION_T positionsOut[NUM_ERRORS_T],
                            unsigned char * bitstreamIn,
                            int guaranteed_bit_lenght) {

    POSITION_T runLengths[NUM_ERRORS_T]={0};
    POSITION_T remaining_zeroes = N0*P-NUM_ERRORS_T;
    unsigned int bitstreamCursor = 0;
    POSITION_T current_lambda_idx=0;
    POSITION_T read_bit=0;
    POSITION_T quotient=0,quotient_complete=0;

    POSITION_T r=0, r_bit_counter=0, is_r_complete;
    POSITION_T lambda, is_lambda_complete;
    POSITION_T mask;

    for(int i=0; i<MAX_PREFIX_LEN; i++){

        read_bit = bitstream_read_single_bit(bitstreamIn,bitstreamCursor);
        quotient_complete = quotient_complete | !read_bit;
        bitstreamCursor++;

        quotient = quotient + (read_bit & !(quotient_complete));
        r_bit_counter += quotient_complete;
        is_r_complete = (DIVISOR_POWER_OF_TWO+1 - r_bit_counter) & 0x80000000;
        is_r_complete = (POSITION_T)0 - (is_r_complete >> 31);
        r= (r << 1) | (read_bit & quotient_complete);
        lambda = quotient*DIVISOR+r;
        ct_store(runLengths, current_lambda_idx, lambda);

        is_lambda_complete = (is_r_complete) & (quotient_complete);
        mask = CONVTOMASK(is_lambda_complete);
        current_lambda_idx = COND_EXP(mask,current_lambda_idx+1,current_lambda_idx);
        remaining_zeroes = COND_EXP(is_lambda_complete,remaining_zeroes-lambda,remaining_zeroes);


        quotient = COND_EXP(is_lambda_complete,0,quotient);
        quotient_complete = COND_EXP(is_lambda_complete,0,quotient_complete);
        r = COND_EXP(is_lambda_complete,0,r);
        r_bit_counter = COND_EXP(is_lambda_complete,0,r_bit_counter);
    }

    DIGIT case_partial_quotient = !(quotient_complete);
    int range;
    range = remaining_zeroes-lambda;
    lambda = COND_EXP(case_partial_quotient,lambda+rand_range_ct(range),lambda);

    DIGIT case_full_quotient = (quotient_complete) & (r_bit_counter == 1);
    range = COND_EXP((range > (DIVISOR-1)),(DIVISOR-1),range);
    lambda = COND_EXP(case_full_quotient,lambda+rand_range_ct(range),lambda);

    DIGIT case_partial_remainder = (quotient_complete) & !(is_lambda_complete) & (r_bit_counter > 1);
    int missing_remainder_bits = DIVISOR_POWER_OF_TWO+1-r_bit_counter;
    range = (1 << missing_remainder_bits )-1 ;
    lambda = COND_EXP(case_partial_remainder,(r << missing_remainder_bits) + quotient * DIVISOR +rand_range_ct(range) ,lambda);

    ct_store(runLengths, current_lambda_idx, lambda);
    current_lambda_idx = COND_EXP(!is_lambda_complete,current_lambda_idx+1,current_lambda_idx);
    remaining_zeroes = COND_EXP(!is_lambda_complete,remaining_zeroes-lambda,remaining_zeroes);

    for(int i = 0; i < NUM_ERRORS_T; i++){
        /* the following lines are equivalent to
        int need_random_lambda = (i >= current_lambda_idx); */
        int need_random_lambda = (i - current_lambda_idx) & 0x80000000;
        need_random_lambda = ~ ((POSITION_T)0- need_random_lambda);
        lambda = runLengths[current_lambda_idx];
        lambda = COND_EXP(need_random_lambda,rand_range_ct(remaining_zeroes),lambda);
        ct_store(runLengths, current_lambda_idx, lambda);
        current_lambda_idx = COND_EXP(need_random_lambda,current_lambda_idx+1,current_lambda_idx);
        remaining_zeroes = COND_EXP(need_random_lambda,remaining_zeroes-lambda,remaining_zeroes);
    }

    /*encode ones according to runLengths into constantWeightOut */
    int current_one_position = -1;
    for (int i = 0; i < NUM_ERRORS_T; i++) {
        current_one_position += runLengths[i] + 1;
        positionsOut[i] = current_one_position;
    }
    return 1;
}


void constant_time_cw_to_bin(unsigned char * bitstreamOut,
                             const int trimOutLength,
                             POSITION_T positionsIn[NUM_ERRORS_T]){
    unsigned int runLengths[NUM_ERRORS_T] = {0};

    /*compute the array of inter-ones distances. Note that there
     is an implicit one out of bounds to compute the first distance from */
    unsigned int idxDistances = 0;

    /* compute run lengths from one positions */
    runLengths[0]=positionsIn[0]-0;

    for (int i = 1; i<NUM_ERRORS_T; i++){
        runLengths[i] = positionsIn[i] - positionsIn[i-1] /*remove the 1*/ - 1;
    }

    /* perform encoding of distances into binary string*/
    unsigned int outputBitCursor = 0;

    for (idxDistances = 0; idxDistances < NUM_ERRORS_T; idxDistances++) {
        unsigned int quotient = runLengths[idxDistances] / DIVISOR;
        for (int outbit=0; outbit<quotient; outbit++){
        bitstream_write(bitstreamOut,1,
                        outputBitCursor,(uint64_t) 1);
        outputBitCursor++;
        }
        bitstream_write(bitstreamOut,1,
                        outputBitCursor,(uint64_t) 0);
        outputBitCursor++;
        unsigned int remainder = runLengths[idxDistances] % DIVISOR;
        bitstream_write(bitstreamOut, DIVISOR_POWER_OF_TWO, outputBitCursor, remainder);
        outputBitCursor += DIVISOR_POWER_OF_TWO;
    }
    while (outputBitCursor < MAX_COMPRESSED_LEN){
                bitstream_write(bitstreamOut,1,outputBitCursor,(uint64_t) 0);
                outputBitCursor++;
    }
}
