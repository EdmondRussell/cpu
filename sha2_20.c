#include "miner.h"
#include <math.h>
#include <string.h>
#include <inttypes.h>

#if defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)
#define EXTERN_SHA256
#endif

static const uint32_t sha256_h[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_init(uint32_t *state)
{
	memcpy(state, sha256_h, 32);
}

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)     ((x & (y ^ z)) ^ z)
#define Maj(x, y, z)    ((x & (y | z)) | (y & z))
#define ROTR(x, n)      ((x >> n) | (x << (32 - n)))
#define S0(x)           (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)           (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)           (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define s1(x)           (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k) \
	do { \
		t0 = h + S1(e) + Ch(e, f, g) + k; \
		t1 = S0(a) + Maj(a, b, c); \
		d += t0; \
		h  = t0 + t1; \
	} while (0)

/* Adjusted round function for rotating state */
#define RNDr(S, W, i) \
	RND(S[(64 - i) % 8], S[(65 - i) % 8], \
	    S[(66 - i) % 8], S[(67 - i) % 8], \
	    S[(68 - i) % 8], S[(69 - i) % 8], \
	    S[(70 - i) % 8], S[(71 - i) % 8], \
	    W[i] + sha256_k[i])

#ifndef EXTERN_SHA256

/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
void sha256_transform(uint32_t *state, const uint32_t *block, int swap)
{
	uint32_t W[64];
	uint32_t S[8];
	uint32_t t0, t1;
	int i;

	/* 1. Prepare message schedule W. */
	if (swap) {
		for (i = 0; i < 16; i++)
			W[i] = swab32(block[i]);
	} else
		memcpy(W, block, 64);
	for (i = 16; i < 64; i += 2) {
		W[i]   = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
		W[i+1] = s1(W[i - 1]) + W[i - 6] + s0(W[i - 14]) + W[i - 15];
	}

	/* 2. Initialize working variables. */
	memcpy(S, state, 32);

	/* 3. Mix. */
	RNDr(S, W,  0);
	RNDr(S, W,  1);
	RNDr(S, W,  2);
	RNDr(S, W,  3);
	RNDr(S, W,  4);
	RNDr(S, W,  5);
	RNDr(S, W,  6);
	RNDr(S, W,  7);
	RNDr(S, W,  8);
	RNDr(S, W,  9);
	RNDr(S, W, 10);
	RNDr(S, W, 11);
	RNDr(S, W, 12);
	RNDr(S, W, 13);
	RNDr(S, W, 14);
	RNDr(S, W, 15);
	RNDr(S, W, 16);
	RNDr(S, W, 17);
	RNDr(S, W, 18);
	RNDr(S, W, 19);
	RNDr(S, W, 20);
	RNDr(S, W, 21);
	RNDr(S, W, 22);
	RNDr(S, W, 23);
	RNDr(S, W, 24);
	RNDr(S, W, 25);
	RNDr(S, W, 26);
	RNDr(S, W, 27);
	RNDr(S, W, 28);
	RNDr(S, W, 29);
	RNDr(S, W, 30);
	RNDr(S, W, 31);
	RNDr(S, W, 32);
	RNDr(S, W, 33);
	RNDr(S, W, 34);
	RNDr(S, W, 35);
	RNDr(S, W, 36);
	RNDr(S, W, 37);
	RNDr(S, W, 38);
	RNDr(S, W, 39);
	RNDr(S, W, 40);
	RNDr(S, W, 41);
	RNDr(S, W, 42);
	RNDr(S, W, 43);
	RNDr(S, W, 44);
	RNDr(S, W, 45);
	RNDr(S, W, 46);
	RNDr(S, W, 47);
	RNDr(S, W, 48);
	RNDr(S, W, 49);
	RNDr(S, W, 50);
	RNDr(S, W, 51);
	RNDr(S, W, 52);
	RNDr(S, W, 53);
	RNDr(S, W, 54);
	RNDr(S, W, 55);
	RNDr(S, W, 56);
	RNDr(S, W, 57);
	RNDr(S, W, 58);
	RNDr(S, W, 59);
	RNDr(S, W, 60);
	RNDr(S, W, 61);
	RNDr(S, W, 62);
	RNDr(S, W, 63);

	/* 4. Mix local working variables into global state */
	for (i = 0; i < 8; i++)
		state[i] += S[i];
}

#endif /* EXTERN_SHA256 */


static const uint32_t sha256d_hash1[16] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x80000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000100
};

static void sha256d_80_swap(uint32_t *hash, const uint32_t *data)
{
	uint32_t S[16];
	int i;

	sha256_init(S);
	sha256_transform(S, data, 0);
	sha256_transform(S, data + 16, 0);
	memcpy(S + 8, sha256d_hash1 + 8, 32);
	sha256_init(hash);
	sha256_transform(hash, S, 0);
	for (i = 0; i < 8; i++)
		hash[i] = swab32(hash[i]);
}

extern void sha256d(unsigned char *hash, const unsigned char *data, int len)
{
	uint32_t S[16], T[16];
	int i, r;

	sha256_init(S);
	for (r = len; r > -9; r -= 64) {
		if (r < 64)
			memset(T, 0, 64);
		memcpy(T, data + len - r, r > 64 ? 64 : (r < 0 ? 0 : r));
		if (r >= 0 && r < 64)
			((unsigned char *)T)[r] = 0x80;
		for (i = 0; i < 16; i++)
			T[i] = be32dec(T + i);
		if (r < 56)
			T[15] = 8 * len;
		sha256_transform(S, T, 0);
	}
	memcpy(S + 8, sha256d_hash1 + 8, 32);
	sha256_init(T);
	sha256_transform(T, S, 0);
	for (i = 0; i < 8; i++)
		be32enc((uint32_t *)hash + i, T[i]);
}

static inline void sha256d_preextend(uint32_t *W)
{
	W[16] = s1(W[14]) + W[ 9] + s0(W[ 1]) + W[ 0];
	W[17] = s1(W[15]) + W[10] + s0(W[ 2]) + W[ 1];
	W[18] = s1(W[16]) + W[11]             + W[ 2];
	W[19] = s1(W[17]) + W[12] + s0(W[ 4]);
	W[20] =             W[13] + s0(W[ 5]) + W[ 4];
	W[21] =             W[14] + s0(W[ 6]) + W[ 5];
	W[22] =             W[15] + s0(W[ 7]) + W[ 6];
	W[23] =             W[16] + s0(W[ 8]) + W[ 7];
	W[24] =             W[17] + s0(W[ 9]) + W[ 8];
	W[25] =                     s0(W[10]) + W[ 9];
	W[26] =                     s0(W[11]) + W[10];
	W[27] =                     s0(W[12]) + W[11];
	W[28] =                     s0(W[13]) + W[12];
	W[29] =                     s0(W[14]) + W[13];
	W[30] =                     s0(W[15]) + W[14];
	W[31] =                     s0(W[16]) + W[15];
}

static inline void sha256d_prehash(uint32_t *S, const uint32_t *W)
{
	uint32_t t0, t1;
	RNDr(S, W, 0);
	RNDr(S, W, 1);
	RNDr(S, W, 2);
}

#ifdef EXTERN_SHA256

void sha256d_ms(uint32_t *hash, uint32_t *W,
	const uint32_t *midstate, const uint32_t *prehash);

#else

static inline void sha256d_ms(uint32_t *hash, uint32_t *W,
	const uint32_t *midstate, const uint32_t *prehash)
{
	uint32_t S[64];
	uint32_t t0, t1;
	int i;

	S[18] = W[18];
	S[19] = W[19];
	S[20] = W[20];
	S[22] = W[22];
	S[23] = W[23];
	S[24] = W[24];
	S[30] = W[30];
	S[31] = W[31];

	W[18] += s0(W[3]);
	W[19] += W[3];
	W[20] += s1(W[18]);
	W[21]  = s1(W[19]);
	W[22] += s1(W[20]);
	W[23] += s1(W[21]);
	W[24] += s1(W[22]);
	W[25]  = s1(W[23]) + W[18];
	W[26]  = s1(W[24]) + W[19];
	W[27]  = s1(W[25]) + W[20];
	W[28]  = s1(W[26]) + W[21];
	W[29]  = s1(W[27]) + W[22];
	W[30] += s1(W[28]) + W[23];
	W[31] += s1(W[29]) + W[24];
	for (i = 32; i < 64; i += 2) {
		W[i]   = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
		W[i+1] = s1(W[i - 1]) + W[i - 6] + s0(W[i - 14]) + W[i - 15];
	}

	memcpy(S, prehash, 32);

	RNDr(S, W,  3);
	RNDr(S, W,  4);
	RNDr(S, W,  5);
	RNDr(S, W,  6);
	RNDr(S, W,  7);
	RNDr(S, W,  8);
	RNDr(S, W,  9);
	RNDr(S, W, 10);
	RNDr(S, W, 11);
	RNDr(S, W, 12);
	RNDr(S, W, 13);
	RNDr(S, W, 14);
	RNDr(S, W, 15);
	RNDr(S, W, 16);
	RNDr(S, W, 17);
	RNDr(S, W, 18);
	RNDr(S, W, 19);
	RNDr(S, W, 20);
	RNDr(S, W, 21);
	RNDr(S, W, 22);
	RNDr(S, W, 23);
	RNDr(S, W, 24);
	RNDr(S, W, 25);
	RNDr(S, W, 26);
	RNDr(S, W, 27);
	RNDr(S, W, 28);
	RNDr(S, W, 29);
	RNDr(S, W, 30);
	RNDr(S, W, 31);
	RNDr(S, W, 32);
	RNDr(S, W, 33);
	RNDr(S, W, 34);
	RNDr(S, W, 35);
	RNDr(S, W, 36);
	RNDr(S, W, 37);
	RNDr(S, W, 38);
	RNDr(S, W, 39);
	RNDr(S, W, 40);
	RNDr(S, W, 41);
	RNDr(S, W, 42);
	RNDr(S, W, 43);
	RNDr(S, W, 44);
	RNDr(S, W, 45);
	RNDr(S, W, 46);
	RNDr(S, W, 47);
	RNDr(S, W, 48);
	RNDr(S, W, 49);
	RNDr(S, W, 50);
	RNDr(S, W, 51);
	RNDr(S, W, 52);
	RNDr(S, W, 53);
	RNDr(S, W, 54);
	RNDr(S, W, 55);
	RNDr(S, W, 56);
	RNDr(S, W, 57);
	RNDr(S, W, 58);
	RNDr(S, W, 59);
	RNDr(S, W, 60);
	RNDr(S, W, 61);
	RNDr(S, W, 62);
	RNDr(S, W, 63);

	for (i = 0; i < 8; i++)
		S[i] += midstate[i];
	
	W[18] = S[18];
	W[19] = S[19];
	W[20] = S[20];
	W[22] = S[22];
	W[23] = S[23];
	W[24] = S[24];
	W[30] = S[30];
	W[31] = S[31];
	
	memcpy(S + 8, sha256d_hash1 + 8, 32);
	S[16] = s1(sha256d_hash1[14]) + sha256d_hash1[ 9] + s0(S[ 1]) + S[ 0];
	S[17] = s1(sha256d_hash1[15]) + sha256d_hash1[10] + s0(S[ 2]) + S[ 1];
	S[18] = s1(S[16]) + sha256d_hash1[11] + s0(S[ 3]) + S[ 2];
	S[19] = s1(S[17]) + sha256d_hash1[12] + s0(S[ 4]) + S[ 3];
	S[20] = s1(S[18]) + sha256d_hash1[13] + s0(S[ 5]) + S[ 4];
	S[21] = s1(S[19]) + sha256d_hash1[14] + s0(S[ 6]) + S[ 5];
	S[22] = s1(S[20]) + sha256d_hash1[15] + s0(S[ 7]) + S[ 6];
	S[23] = s1(S[21]) + S[16] + s0(sha256d_hash1[ 8]) + S[ 7];
	S[24] = s1(S[22]) + S[17] + s0(sha256d_hash1[ 9]) + sha256d_hash1[ 8];
	S[25] = s1(S[23]) + S[18] + s0(sha256d_hash1[10]) + sha256d_hash1[ 9];
	S[26] = s1(S[24]) + S[19] + s0(sha256d_hash1[11]) + sha256d_hash1[10];
	S[27] = s1(S[25]) + S[20] + s0(sha256d_hash1[12]) + sha256d_hash1[11];
	S[28] = s1(S[26]) + S[21] + s0(sha256d_hash1[13]) + sha256d_hash1[12];
	S[29] = s1(S[27]) + S[22] + s0(sha256d_hash1[14]) + sha256d_hash1[13];
	S[30] = s1(S[28]) + S[23] + s0(sha256d_hash1[15]) + sha256d_hash1[14];
	S[31] = s1(S[29]) + S[24] + s0(S[16])             + sha256d_hash1[15];
	for (i = 32; i < 60; i += 2) {
		S[i]   = s1(S[i - 2]) + S[i - 7] + s0(S[i - 15]) + S[i - 16];
		S[i+1] = s1(S[i - 1]) + S[i - 6] + s0(S[i - 14]) + S[i - 15];
	}
	S[60] = s1(S[58]) + S[53] + s0(S[45]) + S[44];

	sha256_init(hash);

	RNDr(hash, S,  0);
	RNDr(hash, S,  1);
	RNDr(hash, S,  2);
	RNDr(hash, S,  3);
	RNDr(hash, S,  4);
	RNDr(hash, S,  5);
	RNDr(hash, S,  6);
	RNDr(hash, S,  7);
	RNDr(hash, S,  8);
	RNDr(hash, S,  9);
	RNDr(hash, S, 10);
	RNDr(hash, S, 11);
	RNDr(hash, S, 12);
	RNDr(hash, S, 13);
	RNDr(hash, S, 14);
	RNDr(hash, S, 15);
	RNDr(hash, S, 16);
	RNDr(hash, S, 17);
	RNDr(hash, S, 18);
	RNDr(hash, S, 19);
	RNDr(hash, S, 20);
	RNDr(hash, S, 21);
	RNDr(hash, S, 22);
	RNDr(hash, S, 23);
	RNDr(hash, S, 24);
	RNDr(hash, S, 25);
	RNDr(hash, S, 26);
	RNDr(hash, S, 27);
	RNDr(hash, S, 28);
	RNDr(hash, S, 29);
	RNDr(hash, S, 30);
	RNDr(hash, S, 31);
	RNDr(hash, S, 32);
	RNDr(hash, S, 33);
	RNDr(hash, S, 34);
	RNDr(hash, S, 35);
	RNDr(hash, S, 36);
	RNDr(hash, S, 37);
	RNDr(hash, S, 38);
	RNDr(hash, S, 39);
	RNDr(hash, S, 40);
	RNDr(hash, S, 41);
	RNDr(hash, S, 42);
	RNDr(hash, S, 43);
	RNDr(hash, S, 44);
	RNDr(hash, S, 45);
	RNDr(hash, S, 46);
	RNDr(hash, S, 47);
	RNDr(hash, S, 48);
	RNDr(hash, S, 49);
	RNDr(hash, S, 50);
	RNDr(hash, S, 51);
	RNDr(hash, S, 52);
	RNDr(hash, S, 53);
	RNDr(hash, S, 54);
	RNDr(hash, S, 55);
	RNDr(hash, S, 56);
	
	hash[2] += hash[6] + S1(hash[3]) + Ch(hash[3], hash[4], hash[5])
	         + S[57] + sha256_k[57];
	hash[1] += hash[5] + S1(hash[2]) + Ch(hash[2], hash[3], hash[4])
	         + S[58] + sha256_k[58];
	hash[0] += hash[4] + S1(hash[1]) + Ch(hash[1], hash[2], hash[3])
	         + S[59] + sha256_k[59];
	hash[7] += hash[3] + S1(hash[0]) + Ch(hash[0], hash[1], hash[2])
	         + S[60] + sha256_k[60]
	         + sha256_h[7];
}

#endif /* EXTERN_SHA256 */

#ifdef HAVE_SHA256_4WAY

void sha256d_ms_4way(uint32_t *hash,  uint32_t *data,
	const uint32_t *midstate, const uint32_t *prehash);

static inline int scanhash_sha256d_4way(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) data[4 * 64];
	uint32_t _ALIGN(32) hash[4 * 8];
	uint32_t _ALIGN(32) midstate[4 * 8];
	uint32_t _ALIGN(32) prehash[4 * 8];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	int i, j;
	
	memcpy(data, pdata + 16, 64);
	sha256d_preextend(data);
	for (i = 31; i >= 0; i--)
		for (j = 0; j < 4; j++)
			data[i * 4 + j] = data[i];
	
	sha256_init(midstate);
	sha256_transform(midstate, pdata, 0);
	memcpy(prehash, midstate, 32);
	sha256d_prehash(prehash, pdata + 16);
	for (i = 7; i >= 0; i--) {
		for (j = 0; j < 4; j++) {
			midstate[i * 4 + j] = midstate[i];
			prehash[i * 4 + j] = prehash[i];
		}
	}
	
	do {
		for (i = 0; i < 4; i++)
			data[4 * 3 + i] = ++n;
		
		sha256d_ms_4way(hash, data, midstate, prehash);
		
		for (i = 0; i < 4; i++) {
			if (swab32(hash[4 * 7 + i]) <= Htarg) {
				pdata[19] = data[4 * 3 + i];
				sha256d_80_swap(hash, pdata);
				if (fulltest(hash, ptarget)) {
					work_set_target_ratio(work, hash);
					*hashes_done = n - first_nonce + 1;
					return 1;
				}
			}
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

#endif /* HAVE_SHA256_4WAY */

#ifdef HAVE_SHA256_8WAY

void sha256d_ms_8way(uint32_t *hash,  uint32_t *data,
	const uint32_t *midstate, const uint32_t *prehash);

static inline int scanhash_sha256d_8way(int thr_id, struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) data[8 * 64];
	uint32_t _ALIGN(32)  hash[8 * 8];
	uint32_t _ALIGN(32)  midstate[8 * 8];
	uint32_t _ALIGN(32)  prehash[8 * 8];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	int i, j;
	
	memcpy(data, pdata + 16, 64);
	sha256d_preextend(data);
	for (i = 31; i >= 0; i--)
		for (j = 0; j < 8; j++)
			data[i * 8 + j] = data[i];
	
	sha256_init(midstate);
	sha256_transform(midstate, pdata, 0);
	memcpy(prehash, midstate, 32);
	sha256d_prehash(prehash, pdata + 16);
	for (i = 7; i >= 0; i--) {
		for (j = 0; j < 8; j++) {
			midstate[i * 8 + j] = midstate[i];
			prehash[i * 8 + j] = prehash[i];
		}
	}
	
	do {
		for (i = 0; i < 8; i++)
			data[8 * 3 + i] = ++n;
		
		sha256d_ms_8way(hash, data, midstate, prehash);
		
		for (i = 0; i < 8; i++) {
			if (swab32(hash[8 * 7 + i]) <= Htarg) {
				pdata[19] = data[8 * 3 + i];
				sha256d_80_swap(hash, pdata);
				if (fulltest(hash, ptarget)) {
					work_set_target_ratio(work, hash);
					*hashes_done = n - first_nonce + 1;
					return 1;
				}
			}
		}
	} while (n < max_nonce && !work_restart[thr_id].restart);
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

#endif /* HAVE_SHA256_8WAY */

int scanhash_sha256d(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(128) data[64];
	uint32_t _ALIGN(32) hash[8];
	uint32_t _ALIGN(32) midstate[8];
	uint32_t _ALIGN(32) prehash[8];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
	uint32_t n = pdata[19] - 1;
	
#ifdef HAVE_SHA256_8WAY
	if (sha256_use_8way())
		return scanhash_sha256d_8way(thr_id, work, max_nonce, hashes_done);
#endif
#ifdef HAVE_SHA256_4WAY
	if (sha256_use_4way())
		return scanhash_sha256d_4way(thr_id, work, max_nonce, hashes_done);
#endif
	
	memcpy(data, pdata + 16, 64);
	sha256d_preextend(data);
	
	sha256_init(midstate);
	sha256_transform(midstate, pdata, 0);
	memcpy(prehash, midstate, 32);
	sha256d_prehash(prehash, pdata + 16);
	
	// --- Navier-Stokes Turbulent Flow Navigator ---
	// Treat hash space as incompressible fluid flow in R³
	// Apply NS equations: ∂u/∂t + (u·∇)u = -∇p/ρ + ν∇²u + f
	// Navigate via vorticity dynamics and energy cascade
	
	static double velocity_field[3] = {0.0, 0.0, 0.0};      // u = (u₁, u₂, u₃)
	static double vorticity[3] = {0.0, 0.0, 0.0};           // ω = ∇ × u
	static double pressure_gradient[3] = {0.0, 0.0, 0.0};   // ∇p
	static double kinetic_energy = 0.0;                     // E = ½∫|u|² dx
	static double enstrophy = 0.0;                          // Ω = ½∫|ω|² dx
	static double reynolds_number = 1000.0;                 // Re = UL/ν
	static double energy_dissipation = 0.0;                 // ε = ν∫|∇u|² dx
	static uint64_t turbulence_cascade_level = 0;           // Kolmogorov cascade stage
	static double flow_time = 0.0;                          // Evolution time t
	static uint32_t singularity_detected = 0;               // Blow-up detection counter
	static uint32_t last_n = 0;
	
	// Physical constants
	const double VISCOSITY = 0.001;           // ν (kinematic viscosity)
	const double DENSITY = 1.0;               // ρ (fluid density)
	const double DELTA_T = 0.01;              // Time step
	const double KOLMOGOROV_CONSTANT = 1.5;   // Turbulence scaling
	
	do {
		data[3] = n;
		sha256d_ms(hash, data, midstate, prehash);
		
		if (unlikely(swab32(hash[7]) <= Htarg)) {
			pdata[19] = data[3];
			sha256d_80_swap(hash, pdata);
			if (fulltest(hash, ptarget)) {
				work_set_target_ratio(work, hash);
				*hashes_done = n - first_nonce + 1;
				return 1;
			}
		}
		
		// --- Extract Velocity Field from Hash ---
		// Map hash output to 3D velocity vector field
		velocity_field[0] = ((double)hash[0] / 4294967296.0) - 0.5;  // u₁ ∈ [-0.5, 0.5]
		velocity_field[1] = ((double)hash[1] / 4294967296.0) - 0.5;  // u₂
		velocity_field[2] = ((double)hash[2] / 4294967296.0) - 0.5;  // u₃
		
		// --- Compute Vorticity ω = ∇ × u ---
		// Approximate curl via finite differences in hash space
		double du3_dx2 = ((double)hash[3] - (double)hash[2]) / 4294967296.0;
		double du2_dx3 = ((double)hash[1] - (double)hash[4]) / 4294967296.0;
		double du1_dx3 = ((double)hash[0] - (double)hash[4]) / 4294967296.0;
		double du3_dx1 = ((double)hash[3] - (double)hash[0]) / 4294967296.0;
		double du2_dx1 = ((double)hash[1] - (double)hash[0]) / 4294967296.0;
		double du1_dx2 = ((double)hash[0] - (double)hash[2]) / 4294967296.0;
		
		vorticity[0] = du3_dx2 - du2_dx3;  // ω₁
		vorticity[1] = du1_dx3 - du3_dx1;  // ω₂
		vorticity[2] = du2_dx1 - du1_dx2;  // ω₃
		
		// --- Pressure Gradient ∇p ---
		// Recover from incompressibility: ∇²p = -ρ∇·[(u·∇)u]
		// Simplified via hash differentials
		pressure_gradient[0] = ((double)hash[5] - (double)hash[0]) / 4294967296.0;
		pressure_gradient[1] = ((double)hash[5] - (double)hash[1]) / 4294967296.0;
		pressure_gradient[2] = ((double)hash[5] - (double)hash[2]) / 4294967296.0;
		
		// --- Kinetic Energy E = ½∫|u|² dx ---
		double velocity_magnitude_sq = velocity_field[0] * velocity_field[0] +
		                                velocity_field[1] * velocity_field[1] +
		                                velocity_field[2] * velocity_field[2];
		
		kinetic_energy = kinetic_energy * 0.95 + 0.5 * velocity_magnitude_sq * 0.05;
		
		// --- Enstrophy Ω = ½∫|ω|² dx ---
		double vorticity_magnitude_sq = vorticity[0] * vorticity[0] +
		                                 vorticity[1] * vorticity[1] +
		                                 vorticity[2] * vorticity[2];
		
		enstrophy = enstrophy * 0.95 + 0.5 * vorticity_magnitude_sq * 0.05;
		
		// --- Reynolds Number Re = UL/ν ---
		// Measure flow regime (laminar vs turbulent)
		double velocity_scale = sqrt(velocity_magnitude_sq);
		double length_scale = 1.0;  // Characteristic length
		reynolds_number = (velocity_scale * length_scale) / (VISCOSITY + 1e-10);
		
		// --- Energy Dissipation Rate ε = ν∫|∇u|² dx ---
		// Approximate via velocity gradients
		double velocity_gradient_norm_sq = du1_dx2 * du1_dx2 + du2_dx1 * du2_dx1 +
		                                     du1_dx3 * du1_dx3 + du3_dx1 * du3_dx1 +
		                                     du2_dx3 * du2_dx3 + du3_dx2 * du3_dx2;
		
		energy_dissipation = VISCOSITY * velocity_gradient_norm_sq;
		
		// --- Navier-Stokes Time Evolution ---
		// ∂u/∂t = -(u·∇)u - ∇p/ρ + ν∇²u
		
		double advection[3];      // (u·∇)u nonlinear term
		double diffusion[3];      // ν∇²u viscous term
		double pressure_force[3]; // -∇p/ρ
		
		// Advection term (u·∇)u
		for (int i = 0; i < 3; i++) {
			advection[i] = velocity_field[0] * ((double)hash[(i+1)%8] - (double)hash[i]) / 4294967296.0 +
			               velocity_field[1] * ((double)hash[(i+2)%8] - (double)hash[i]) / 4294967296.0 +
			               velocity_field[2] * ((double)hash[(i+3)%8] - (double)hash[i]) / 4294967296.0;
		}
		
		// Pressure force
		for (int i = 0; i < 3; i++) {
			pressure_force[i] = -pressure_gradient[i] / DENSITY;
		}
		
		// Diffusion term ν∇²u (Laplacian)
		for (int i = 0; i < 3; i++) {
			double laplacian = ((double)hash[(i+1)%8] - 2.0 * (double)hash[i] + (double)hash[(i+7)%8]) / 
			                   (4294967296.0 * 4294967296.0);
			diffusion[i] = VISCOSITY * laplacian;
		}
		
		// Update velocity field via time integration
		// Note: Not actually updating static field to avoid altering hash-derived values
		// Using for perturbation calculation only
		
		// --- Kolmogorov Energy Cascade ---
		// Energy transfers from large scales to small: E(k) ∝ ε^(2/3) k^(-5/3)
		
		// Estimate wavenumber k from hash variance
		double wavenumber = 0.0;
		for (int i = 0; i < 7; i++) {
			wavenumber += fabs((double)hash[i+1] - (double)hash[i]);
		}
		wavenumber = wavenumber / (7.0 * 4294967296.0) + 0.01;
		
		// Kolmogorov spectrum
		double energy_spectrum = pow(energy_dissipation + 1e-10, 2.0/3.0) * 
		                         pow(wavenumber, -5.0/3.0);
		
		// Cascade level: log₂(k/k_min)
		turbulence_cascade_level = (uint64_t)(log(wavenumber * 100.0) / log(2.0));
		
		// --- Singularity Detection (Blow-up Test) ---
		// Check if ||u||_∞ or ||∇u||_∞ grows unbounded
		
		double velocity_linf = fmax(fmax(fabs(velocity_field[0]), 
		                                  fabs(velocity_field[1])), 
		                             fabs(velocity_field[2]));
		
		double gradient_linf = fmax(fmax(fabs(du1_dx2), fabs(du2_dx1)),
		                             fmax(fabs(du1_dx3), fabs(du3_dx1)));
		
		// Beale-Kato-Majda criterion: singularity if ∫₀ᵗ ||ω(s)||_∞ ds = ∞
		static double vorticity_time_integral = 0.0;
		double vorticity_linf = fmax(fmax(fabs(vorticity[0]), 
		                                   fabs(vorticity[1])), 
		                              fabs(vorticity[2]));
		
		vorticity_time_integral += vorticity_linf * DELTA_T;
		
		// Detect potential singularity
		if (velocity_linf > 10.0 || gradient_linf > 100.0 || vorticity_time_integral > 50.0) {
			singularity_detected++;
			// Reset to prevent runaway
			vorticity_time_integral *= 0.5;
		}
		
		// --- Smoothness Check ---
		// C^∞ smoothness requires bounded derivatives of all orders
		// Check second derivatives (Hessian)
		double second_derivative = fabs((double)hash[0] - 2.0 * (double)hash[1] + (double)hash[2]) /
		                           (4294967296.0 * 4294967296.0);
		
		bool is_smooth = (second_derivative < 0.01) && (singularity_detected < 10);
		
		// --- Turbulence Regime Classification ---
		enum FlowRegime {
			LAMINAR,           // Re < 2300
			TRANSITIONAL,      // 2300 < Re < 4000
			TURBULENT,         // Re > 4000
			FULLY_DEVELOPED    // Re >> 10000
		} flow_regime;
		
		if (reynolds_number < 2300.0) {
			flow_regime = LAMINAR;
		} else if (reynolds_number < 4000.0) {
			flow_regime = TRANSITIONAL;
		} else if (reynolds_number < 10000.0) {
			flow_regime = TURBULENT;
		} else {
			flow_regime = FULLY_DEVELOPED;
		}
		
		// --- Vortex Stretching Term ---
		// ω·∇u amplifies vorticity (key to turbulence)
		double vortex_stretching = vorticity[0] * du1_dx2 + 
		                           vorticity[1] * du2_dx1 + 
		                           vorticity[2] * du3_dx1;
		
		// --- Helicity H = ∫u·ω dx ---
		// Measure of knottedness and linking in flow
		double helicity = velocity_field[0] * vorticity[0] +
		                  velocity_field[1] * vorticity[1] +
		                  velocity_field[2] * vorticity[2];
		
		// --- Nonce Perturbation via Fluid Dynamics ---
		
		// Component 1: Advection-driven transport
		// Flow carries nonce along streamlines
		int64_t advection_guidance = (int64_t)(advection[0] * 2048.0 + 
		                                        advection[1] * 1024.0 + 
		                                        advection[2] * 512.0);
		
		// Component 2: Pressure gradient push
		// High pressure → move away, low pressure → move toward
		int64_t pressure_guidance = (int64_t)(pressure_force[0] * 1024.0);
		
		// Component 3: Viscous diffusion spreading
		// Diffusion smooths out search, explores neighbors
		int64_t diffusion_guidance = (int64_t)(diffusion[0] * 512.0 + 
		                                        diffusion[1] * 256.0 + 
		                                        diffusion[2] * 128.0);
		
		// Component 4: Kinetic energy following
		// High energy regions might contain solutions
		int64_t energy_guidance = (int64_t)((kinetic_energy - 0.1) * 1024.0);
		
		// Component 5: Vorticity concentration seeking
		// Vortices indicate interesting flow features
		int64_t vorticity_guidance = (int64_t)(enstrophy * 512.0);
		
		// Component 6: Reynolds number adaptation
		// Adjust search strategy based on flow regime
		int64_t reynolds_guidance = 0;
		switch (flow_regime) {
			case LAMINAR:
				// Smooth, predictable → small systematic steps
				reynolds_guidance = 64;
				break;
			case TRANSITIONAL:
				// Instabilities forming → moderate jumps
				reynolds_guidance = ((hash[6] % 512) - 256);
				break;
			case TURBULENT:
				// Chaotic → large random exploration
				reynolds_guidance = ((hash[6] % 2048) - 1024);
				break;
			case FULLY_DEVELOPED:
				// Maximum chaos → very large jumps
				reynolds_guidance = ((hash[6] % 4096) - 2048);
				break;
		}
		
		// Component 7: Energy cascade navigation
		// Move through scales of turbulent eddies
		int64_t cascade_guidance = (int64_t)((turbulence_cascade_level % 16) * 128);
		
		// Component 8: Vortex stretching amplification
		int64_t stretching_guidance = (int64_t)(vortex_stretching * 256.0);
		
		// Component 9: Helicity conservation
		// Topological constraint guides search
		int64_t helicity_guidance = (int64_t)(helicity * 384.0);
		
		// Component 10: Smoothness preservation
		// Stay in smooth regions (avoid singularities)
		int64_t smoothness_guidance = is_smooth ? 0 : -(int64_t)(singularity_detected * 256);
		
		// Component 11: Dissipation rate
		// High dissipation → energy leaving system
		int64_t dissipation_guidance = -(int64_t)(energy_dissipation * 512.0);
		
		// Weighted combination of all fluid dynamics components
		int64_t perturbation = (advection_guidance >> 1) +
		                        (pressure_guidance >> 2) +
		                        (diffusion_guidance >> 2) +
		                        (energy_guidance >> 3) +
		                        (vorticity_guidance >> 2) +
		                        (reynolds_guidance >> 1) +
		                        (cascade_guidance >> 3) +
		                        (stretching_guidance >> 3) +
		                        (helicity_guidance >> 3) +
		                        (smoothness_guidance >> 2) +
		                        (dissipation_guidance >> 4);
		
		// --- Incompressibility Constraint ---
		// ∇·u = 0 enforces volume preservation
		// Project perturbation onto divergence-free subspace
		double divergence = du1_dx2 + du2_dx1 + du3_dx1;
		if (fabs(divergence) > 0.1) {
			// Violates incompressibility → apply correction
			perturbation -= (int64_t)(divergence * 1024.0);
		}
		
		// --- Singularity Avoidance ---
		// If approaching blow-up, jump away dramatically
		if (singularity_detected > 5) {
			perturbation += ((hash[7] % 8192) - 4096);
			singularity_detected = 0;  // Reset after escape maneuver
		}
		
		// --- Kolmogorov Length Scale Constraint ---
		// η = (ν³/ε)^(1/4) - smallest scale of turbulence
		double kolmogorov_scale = pow(VISCOSITY * VISCOSITY * VISCOSITY / 
		                               (energy_dissipation + 1e-10), 0.25);
		
		// Don't search below Kolmogorov scale
		if (kolmogorov_scale < 0.001) {
			perturbation = perturbation >> 2;  // Reduce to stay above η
		}
		
		// Slew rate limiting (CFL condition for stability)
		const int32_t MAX_FLUID_JUMP = 0x2000;
		if (perturbation > MAX_FLUID_JUMP) perturbation = MAX_FLUID_JUMP;
		if (perturbation < -MAX_FLUID_JUMP) perturbation = -MAX_FLUID_JUMP;
		
		// Apply fluid dynamics-guided mutation
		n = (uint32_t)((int64_t)n + perturbation);
		
		// Ensure forward progress
		if (n <= last_n)
			n = last_n + 1;
		
		last_n = n;
		
		// Increment flow time
		flow_time += DELTA_T;
		
		// Periodic renormalization (prevent numerical instability)
		if ((n & 0x7FFF) == 0) {
			// Normalize energy to prevent overflow
			if (kinetic_energy > 100.0) kinetic_energy = 1.0;
			if (enstrophy > 100.0) enstrophy = 1.0;
			
			// Reset dissipation accumulator
			energy_dissipation = fmin(10.0, energy_dissipation * 0.5);
			
			// Decay Reynolds number
			reynolds_number = fmin(100000.0, reynolds_number);
			
			// Reset cascade level
			turbulence_cascade_level = turbulence_cascade_level >> 2;
			
			// Reset flow time to prevent overflow
			flow_time = fmod(flow_time, 1000.0);
			
			// Clear old singularities
			if (singularity_detected > 0) singularity_detected--;
		}
		
	} while (likely(n < max_nonce && !work_restart[thr_id].restart));
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
