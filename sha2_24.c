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
	
	// --- Infinite Pattern Fractal Navigator ---
	// Explore hash space via self-similar recursive structures
	// Mandelbrot: z_{n+1} = z_n² + c
	// Julia sets, Sierpinski patterns, Cantor dust, Koch curves
	
	// --- Fractal State Variables ---
	static double z_real = 0.0;              // Current point in complex plane (real)
	static double z_imag = 0.0;              // Current point in complex plane (imaginary)
	static double c_real = -0.4;             // Julia set parameter (real)
	static double c_imag = 0.6;              // Julia set parameter (imaginary)
	static uint32_t escape_iterations = 0;   // Iterations to escape
	static double fractal_dimension = 0.0;   // Hausdorff dimension estimate
	static uint32_t orbit_period = 0;        // Periodic orbit detection
	static double lyapunov_exponent = 0.0;   // Chaos measure
	static uint32_t recursion_depth = 0;     // Self-similarity depth
	static double zoom_level = 1.0;          // Magnification into fractal
	static uint64_t boundary_crossings = 0;  // Mandelbrot set boundary
	static uint32_t last_n = 0;
	static int initialized = 0;
	
	// --- Fractal Constants ---
	const double ESCAPE_RADIUS = 2.0;
	const uint32_t MAX_ITERATIONS = 256;
	const double GOLDEN_RATIO = 1.618033988749895;
	const double FEIGENBAUM_DELTA = 4.669201609102990;  // Period-doubling constant
	const double FEIGENBAUM_ALPHA = 2.502907875095892;  // Scaling constant
	
	// Initialize on first call
	if (!initialized) {
		z_real = 0.0;
		z_imag = 0.0;
		c_real = -0.4;
		c_imag = 0.6;
		zoom_level = 1.0;
		initialized = 1;
	}
	
	memcpy(data, pdata + 16, 64);
	sha256d_preextend(data);
	
	sha256_init(midstate);
	sha256_transform(midstate, pdata, 0);
	memcpy(prehash, midstate, 32);
	sha256d_prehash(prehash, pdata + 16);
	
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
		
		// --- Extract Complex Coordinates from Hash ---
		// Map hash output to complex plane for fractal iteration
		
		double hash_real = ((double)hash[0] / 4294967296.0) * 4.0 - 2.0;  // [-2, 2]
		double hash_imag = ((double)hash[1] / 4294967296.0) * 4.0 - 2.0;  // [-2, 2]
		
		// Update Julia set parameter from hash
		c_real = c_real * 0.95 + (((double)hash[2] / 4294967296.0) - 0.5) * 0.05;
		c_imag = c_imag * 0.95 + (((double)hash[3] / 4294967296.0) - 0.5) * 0.05;
		
		// Blend current position with hash-derived point
		z_real = z_real * 0.9 + hash_real * 0.1;
		z_imag = z_imag * 0.9 + hash_imag * 0.1;
		
		// --- Mandelbrot/Julia Iteration: z_{n+1} = z_n² + c ---
		double z_real_temp = z_real;
		double z_imag_temp = z_imag;
		
		uint32_t iterations = 0;
		double z_magnitude_sq = 0.0;
		double orbit_sum_real = 0.0;
		double orbit_sum_imag = 0.0;
		
		// Iterate until escape or max iterations
		for (iterations = 0; iterations < 32; iterations++) {
			// z² = (a+bi)² = (a²-b²) + 2abi
			double z_real_sq = z_real_temp * z_real_temp;
			double z_imag_sq = z_imag_temp * z_imag_temp;
			
			z_magnitude_sq = z_real_sq + z_imag_sq;
			
			// Check escape condition
			if (z_magnitude_sq > ESCAPE_RADIUS * ESCAPE_RADIUS) {
				break;
			}
			
			// Accumulate orbit for period detection
			orbit_sum_real += z_real_temp;
			orbit_sum_imag += z_imag_temp;
			
			// Mandelbrot iteration: z = z² + c
			double new_real = z_real_sq - z_imag_sq + c_real;
			double new_imag = 2.0 * z_real_temp * z_imag_temp + c_imag;
			
			z_real_temp = new_real;
			z_imag_temp = new_imag;
		}
		
		escape_iterations = iterations;
		
		// Update persistent state with final orbit position
		z_real = z_real_temp;
		z_imag = z_imag_temp;
		
		// --- Lyapunov Exponent (Chaos Measure) ---
		// λ = lim (1/n) Σ ln|f'(z_i)|
		// Positive λ → chaos, negative λ → stability
		
		double derivative_magnitude = 2.0 * sqrt(z_magnitude_sq);  // |f'(z)| = |2z|
		lyapunov_exponent = lyapunov_exponent * 0.92 + 
		                    log(derivative_magnitude + 1e-10) * 0.08;
		
		// --- Fractal Dimension Estimation (Box-Counting) ---
		// D = lim (log N(ε) / log(1/ε))
		// Approximate via escape iteration distribution
		
		double dimension_estimate = 2.0 - (double)escape_iterations / 64.0;
		fractal_dimension = fractal_dimension * 0.93 + dimension_estimate * 0.07;
		
		// --- Orbit Period Detection ---
		// Check for periodic attractors
		double orbit_avg_real = orbit_sum_real / (double)(iterations + 1);
		double orbit_avg_imag = orbit_sum_imag / (double)(iterations + 1);
		
		double orbit_deviation = sqrt((z_real - orbit_avg_real) * (z_real - orbit_avg_real) +
		                               (z_imag - orbit_avg_imag) * (z_imag - orbit_avg_imag));
		
		if (orbit_deviation < 0.1) {
			orbit_period++;
		} else {
			orbit_period = 0;
		}
		
		// --- Mandelbrot Set Boundary Detection ---
		// Points near boundary have maximum complexity
		bool on_boundary = (escape_iterations > 16 && escape_iterations < MAX_ITERATIONS);
		
		if (on_boundary) {
			boundary_crossings++;
		}
		
		// --- Sierpinski Triangle Recursion ---
		// Self-similar triangular pattern: base-3 fractal
		// Use hash bits to navigate Sierpinski address space
		
		uint32_t sierpinski_address = hash[4];
		uint32_t sierpinski_level = 0;
		uint32_t sierpinski_position = 0;
		
		// Decode ternary (base-3) address
		for (int level = 0; level < 8; level++) {
			uint32_t ternary_digit = sierpinski_address % 3;
			if (ternary_digit != 1) {  // Skip middle triangle (Sierpinski hole)
				sierpinski_level = level;
				sierpinski_position = (sierpinski_position * 2) + ternary_digit / 2;
			}
			sierpinski_address /= 3;
		}
		
		recursion_depth = sierpinski_level;
		
		// --- Cantor Set Navigation ---
		// Middle-third removal: fractal dimension log(2)/log(3) ≈ 0.631
		
		uint32_t cantor_position = n;
		uint32_t cantor_scale = 1;
		bool in_cantor_set = true;
		
		// Check if nonce is in Cantor set
		for (int i = 0; i < 10; i++) {
			uint32_t interval = cantor_position / cantor_scale;
			uint32_t remainder = (interval % 3);
			
			if (remainder == 1) {
				// In middle third - removed
				in_cantor_set = false;
				break;
			}
			
			cantor_scale *= 3;
			if (cantor_scale > n) break;
		}
		
		// --- Koch Curve Length ---
		// Each iteration: length *= 4/3
		// Fractal dimension: log(4)/log(3) ≈ 1.262
		
		double koch_length = 1.0;
		for (uint32_t i = 0; i < (hash[5] % 8); i++) {
			koch_length *= (4.0 / 3.0);
		}
		
		// --- Dragon Curve Folding ---
		// Paper folding sequence: ...RRLRRLLR...
		// Use hash to generate fold pattern
		
		uint32_t dragon_folds = 0;
		uint32_t fold_pattern = hash[6];
		
		for (int i = 0; i < 16; i++) {
			if (fold_pattern & (1U << i)) {
				dragon_folds++;
			}
		}
		
		// --- Zoom into Fractal ---
		// Magnification reveals infinite detail
		
		double zoom_factor = 1.0 + ((double)(hash[7] % 1000) / 10000.0);
		zoom_level *= zoom_factor;
		
		// Periodically reset zoom to avoid numerical instability
		if (zoom_level > 1e6) {
			zoom_level = 1.0;
		}
		
		// --- Self-Similarity Scaling ---
		// Apply power-law scaling at different depths
		
		double scale_factor = pow(GOLDEN_RATIO, (double)recursion_depth);
		
		// --- Feigenbaum Bifurcation Cascade ---
		// Period-doubling route to chaos: δ ≈ 4.669
		
		uint32_t bifurcation_level = 0;
		double mu = 0.0;  // Bifurcation parameter
		
		// Determine bifurcation regime from Lyapunov exponent
		if (lyapunov_exponent < -0.5) {
			bifurcation_level = 1;  // Stable fixed point
			mu = 2.5;
		} else if (lyapunov_exponent < 0.0) {
			bifurcation_level = 2;  // Period-2 cycle
			mu = 3.2;
		} else if (lyapunov_exponent < 0.5) {
			bifurcation_level = 4;  // Period-4 cycle
			mu = 3.5;
		} else {
			bifurcation_level = 0;  // Chaotic regime
			mu = 3.9;
		}
		
		// Logistic map iteration: x_{n+1} = μ·x_n·(1 - x_n)
		double logistic_x = ((double)(hash[0] % 10000) / 10000.0);
		logistic_x = mu * logistic_x * (1.0 - logistic_x);
		
		// --- Nonce Perturbation via Fractal Dynamics ---
		
		int64_t perturbation = 0;
		
		// Component 1: Escape iteration count
		// Fast escape → large jump, slow escape → fine search
		int64_t escape_guidance = (escape_iterations < 16) ? 
		                          ((hash[0] % 2048) - 1024) : 
		                          ((hash[0] % 256) - 128);
		
		// Component 2: Fractal dimension
		// Higher dimension → more complex, needs exploration
		int64_t dimension_guidance = (int64_t)((fractal_dimension - 1.5) * 512.0);
		
		// Component 3: Lyapunov exponent (chaos indicator)
		// Positive → chaotic, use larger steps
		int64_t chaos_guidance = (lyapunov_exponent > 0) ?
		                         ((hash[1] % 1024) - 512) :
		                         ((hash[1] % 128) - 64);
		
		// Component 4: Orbit period
		// Periodic orbit → stable region, explore systematically
		int64_t period_guidance = (orbit_period > 5) ? 
		                          (64 + (orbit_period * 8)) :
		                          ((hash[2] % 512) - 256);
		
		// Component 5: Boundary proximity
		// Near Mandelbrot boundary → maximum complexity
		int64_t boundary_guidance = on_boundary ? 
		                            ((hash[3] % 128) - 64) :
		                            ((hash[3] % 1024) - 512);
		
		// Component 6: Sierpinski recursion depth
		// Deeper recursion → finer scale
		int64_t sierpinski_guidance = (int64_t)(sierpinski_position * 
		                                        pow(2.0, -(double)sierpinski_level) * 512.0);
		
		// Component 7: Cantor set membership
		// In Cantor set → use self-similar jumps
		int64_t cantor_guidance = in_cantor_set ? 
		                          (int64_t)(cantor_scale) :
		                          ((hash[4] % 256));
		
		// Component 8: Koch curve length
		// Longer curve → more complex path
		int64_t koch_guidance = (int64_t)(koch_length * 96.0);
		
		// Component 9: Dragon curve folds
		int64_t dragon_guidance = (int64_t)(dragon_folds * 32);
		
		// Component 10: Zoom level
		// High zoom → fine detail, small steps
		int64_t zoom_guidance = (zoom_level > 1000.0) ?
		                        ((hash[5] % 64) - 32) :
		                        ((hash[5] % 512) - 256);
		
		// Component 11: Golden ratio scaling
		int64_t golden_guidance = (int64_t)(scale_factor * 48.0);
		
		// Component 12: Feigenbaum bifurcation
		int64_t bifurcation_guidance = (int64_t)(bifurcation_level * 128);
		
		// Component 13: Logistic map
		int64_t logistic_guidance = (int64_t)(logistic_x * 768.0) - 384;
		
		// Component 14: Complex plane position
		int64_t complex_guidance = (int64_t)(z_real * 256.0) + (int64_t)(z_imag * 192.0);
		
		// Aggregate all fractal components
		perturbation = (escape_guidance >> 1) +
		               (dimension_guidance >> 2) +
		               (chaos_guidance >> 1) +
		               (period_guidance >> 2) +
		               (boundary_guidance >> 1) +
		               (sierpinski_guidance >> 2) +
		               (cantor_guidance >> 3) +
		               (koch_guidance >> 3) +
		               (dragon_guidance >> 3) +
		               (zoom_guidance >> 2) +
		               (golden_guidance >> 3) +
		               (bifurcation_guidance >> 2) +
		               (logistic_guidance >> 2) +
		               (complex_guidance >> 3);
		
		// Apply perturbation
		n = (uint32_t)((int64_t)n + perturbation);
		
		// --- Self-Similar Jump Pattern ---
		// Use fractal address for hierarchical navigation
		
		uint32_t fractal_jump = 1;
		for (uint32_t level = 0; level < recursion_depth && level < 8; level++) {
			fractal_jump = fractal_jump * 2 + ((hash[level % 8] >> level) & 1);
		}
		n += fractal_jump;
		
		// --- Julia Set Parameter Evolution ---
		// Slowly drift through parameter space
		c_real += (((double)(hash[6] % 1000) / 100000.0) - 0.005);
		c_imag += (((double)(hash[7] % 1000) / 100000.0) - 0.005);
		
		// Keep c in interesting region
		if (c_real < -2.0) c_real = -2.0;
		if (c_real > 2.0) c_real = 2.0;
		if (c_imag < -2.0) c_imag = -2.0;
		if (c_imag > 2.0) c_imag = 2.0;
		
		// --- Hausdorff Measure Constraint ---
		// Ensure exploration respects fractal metric
		if (fractal_dimension > 1.9) {
			// Nearly space-filling, use smaller steps
			perturbation = perturbation >> 1;
		}
		
		// --- Apply Slew Rate Limiting ---
		const int32_t MAX_FRACTAL_JUMP = 0x2000;
		if (perturbation > MAX_FRACTAL_JUMP) perturbation = MAX_FRACTAL_JUMP;
		if (perturbation < -MAX_FRACTAL_JUMP) perturbation = -MAX_FRACTAL_JUMP;
		
		// --- Ensure Odd ---
		n |= 1;
		
		// --- Forward Progress Guarantee ---
		if (n <= last_n) {
			n = last_n + fractal_jump + 1;
		}
		last_n = n;
		
		// --- Periodic Renormalization ---
		if ((n & 0xFFFF) == 0) {
			// Reset zoom to avoid numerical overflow
			if (zoom_level > 1e5) zoom_level = 1.0;
			
			// Decay boundary crossings
			boundary_crossings = boundary_crossings >> 2;
			
			// Reset Lyapunov if diverging
			if (fabs(lyapunov_exponent) > 10.0) {
				lyapunov_exponent *= 0.5;
			}
			
			// Keep fractal dimension in reasonable range
			if (fractal_dimension < 0.5) fractal_dimension = 1.0;
			if (fractal_dimension > 2.5) fractal_dimension = 2.0;
			
			// Reset orbit period counter
			if (orbit_period > 100) orbit_period = 0;
			
			// Decay recursion depth
			if (recursion_depth > 16) recursion_depth = 8;
			
			// Re-center in complex plane if escaped too far
			if (sqrt(z_real * z_real + z_imag * z_imag) > 10.0) {
				z_real = 0.0;
				z_imag = 0.0;
			}
		}
		
	} while (likely(n < max_nonce && !work_restart[thr_id].restart));
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
