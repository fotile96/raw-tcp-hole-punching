#pragma once

#include <stdint.h>
#include <netinet/in.h>

#define ADDCARRY(x)  {if ((x) > 65535) (x) -= 65535;}
#define REDUCE {l_util.l = sum; sum = l_util.s[0] + l_util.s[1]; ADDCARRY(sum);}

struct cksum_vec {
    const uint8_t *ptr;
    int len;
};

template<int N, bool take_complement>
inline uint16_t ones_complement_sum(const cksum_vec vecs[], int last_vec_len) {
    const uint16_t *w;
    int sum = 0;
    int mlen = 0;
    int byte_swapped = 0;

    union {
        uint8_t c[2];
        uint16_t s;
    } s_util;
    union {
        uint16_t s[2];
        uint32_t l;
    } l_util;

    for (int veci = 0; veci < N; ++veci) {
        int veclen = veci < N - 1 || last_vec_len < 0 ? vecs[veci].len : last_vec_len;
        if (veclen == 0)
            continue;
        w = (const uint16_t *) (const void *) vecs[veci].ptr;
        if (mlen == -1) {
            /*
             * The first byte of this chunk is the continuation
             * of a word spanning between this chunk and the
             * last chunk.
             *
             * s_util.c[0] is already saved when scanning previous
             * chunk.
             */
            s_util.c[1] = *(const uint8_t *) w;
            sum += s_util.s;
            w = (const uint16_t *) (const void *) ((const uint8_t *) w + 1);
            mlen = veclen - 1;
        } else
            mlen = veclen;
        /*
         * Force to even boundary.
         */
        if ((1 & (uintptr_t) w) && (mlen > 0)) {
            REDUCE;
            sum <<= 8;
            s_util.c[0] = *(const uint8_t *) w;
            w = (const uint16_t *) (const void *) ((const uint8_t *) w + 1);
            mlen--;
            byte_swapped = 1;
        }
        /*
         * Unroll the loop to make overhead from
         * branches &c small.
         */
        while ((mlen -= 32) >= 0) {
            sum += w[0];
            sum += w[1];
            sum += w[2];
            sum += w[3];
            sum += w[4];
            sum += w[5];
            sum += w[6];
            sum += w[7];
            sum += w[8];
            sum += w[9];
            sum += w[10];
            sum += w[11];
            sum += w[12];
            sum += w[13];
            sum += w[14];
            sum += w[15];
            w += 16;
        }
        mlen += 32;
        while ((mlen -= 8) >= 0) {
            sum += w[0];
            sum += w[1];
            sum += w[2];
            sum += w[3];
            w += 4;
        }
        mlen += 8;
        if (mlen == 0 && byte_swapped == 0)
            continue;
        REDUCE;
        while ((mlen -= 2) >= 0) {
            sum += *w++;
        }
        if (byte_swapped) {
            REDUCE;
            sum <<= 8;
            byte_swapped = 0;
            if (mlen == -1) {
                s_util.c[1] = *(const uint8_t *) w;
                sum += s_util.s;
                mlen = 0;
            } else
                mlen = -1;
        } else if (mlen == -1)
            s_util.c[0] = *(const uint8_t *) w;
    }
    if (mlen == -1) {
        /* The last mbuf has odd # of bytes. Follow the
           standard (the odd byte may be shifted left by 8 bits
           or not as determined by endian-ness of the machine) */
        s_util.c[1] = 0;
        sum += s_util.s;
    }
    REDUCE;

    if (!take_complement)
        return (uint16_t) sum;
    return (~sum & 0xffff);
}

/*
 * Given the host-byte-order value of the checksum field in a packet
 * header, and the network-byte-order computed checksum of the data
 * that the checksum covers (including the checksum itself), compute
 * what the checksum field *should* have been.
 */
uint16_t
in_cksum_shouldbe(uint16_t sum, uint16_t computed_sum) {
    uint32_t shouldbe;

    /*
     * The value that should have gone into the checksum field
     * is the negative of the value gotten by summing up everything
     * *but* the checksum field.
     *
     * We can compute that by subtracting the value of the checksum
     * field from the sum of all the data in the packet, and then
     * computing the negative of that value.
     *
     * "sum" is the value of the checksum field, and "computed_sum"
     * is the negative of the sum of all the data in the packets,
     * so that's -(-computed_sum - sum), or (sum + computed_sum).
     *
     * All the arithmetic in question is one's complement, so the
     * addition must include an end-around carry; we do this by
     * doing the arithmetic in 32 bits (with no sign-extension),
     * and then adding the upper 16 bits of the sum, which contain
     * the carry, to the lower 16 bits of the sum, and then do it
     * again in case *that* sum produced a carry.
     *
     * As RFC 1071 notes, the checksum can be computed without
     * byte-swapping the 16-bit words; summing 16-bit words
     * on a big-endian machine gives a big-endian checksum, which
     * can be directly stuffed into the big-endian checksum fields
     * in protocol headers, and summing words on a little-endian
     * machine gives a little-endian checksum, which must be
     * byte-swapped before being stuffed into a big-endian checksum
     * field.
     *
     * "computed_sum" is a network-byte-order value, so we must put
     * it in host byte order before subtracting it from the
     * host-byte-order value from the header; the adjusted checksum
     * will be in host byte order, which is what we'll return.
     */
    shouldbe = sum;
    shouldbe += ntohs(computed_sum);
    shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16);
    shouldbe = (shouldbe & 0xFFFF) + (shouldbe >> 16);
    return (uint16_t) shouldbe;
}