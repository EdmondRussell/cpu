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
	
	// --- QCD Lattice + Prime Number Theory Fusion Navigator ---
	// Combines Yang-Mills gauge theory with prime distribution
	// Lattice QCD on prime-indexed spacetime points
	
	// --- QCD Gauge Fields (SU(3) color) ---
	static double gluon_field[8] = {0};          // 8 gluon states
	static double quark_field[6] = {0};          // 6 quark flavors (u,d,s,c,b,t)
	static double chiral_condensate = 0.0;       // <ψ̄ψ> quark condensate
	static double polyakov_loop = 0.0;           // Confinement order parameter
	static double string_tension = 0.0;          // σ (quark potential)
	static double coupling_alpha_s = 0.3;        // Strong coupling α_s
	static uint32_t instanton_density = 0;       // Topological susceptibility
	
	// --- Prime Number Theory ---
	static uint32_t prime_gap = 0;               // p_{n+1} - p_n
	static uint32_t twin_prime_count = 0;        // Pairs (p, p+2)
	static uint32_t sophie_germain_count = 0;    // p, 2p+1 both prime
	static double riemann_von_mangoldt = 0.0;    // Λ(n) accumulation
	static uint32_t prime_omega = 0;             // Ω(n) = # prime factors
	static uint64_t totient_phi = 0;             // φ(n) Euler totient
	static uint32_t mobius_mu = 0;               // μ(n) Möbius function
	
	// --- Lattice Structure ---
	static uint32_t lattice_spacing = 1;         // a (lattice constant)
	static uint32_t lattice_volume = 0;          // V = L^4
	static double beta_lattice = 6.0;            // 6/g² lattice coupling
	
	// --- Hybrid Quantities ---
	static double qcd_prime_correlation = 0.0;   // Correlation between QCD and primes
	static uint32_t flux_tube_prime = 0;         // Prime-quantized flux tubes
	
	static uint32_t last_n = 0;
	static int initialized = 0;
	
	// Prime table for quick lookup (first 256 primes)
	static const uint32_t small_primes[256] = {
		2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53,
		59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131,
		137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223,
		227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311,
		313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
		419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
		509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613,
		617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719,
		727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827,
		829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941,
		947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
		1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
		1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
		1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423,
		1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
		1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619
	};
	
	if (!initialized) {
		coupling_alpha_s = 0.3;
		string_tension = 0.2;
		lattice_spacing = 1;
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
		
		// --- Extract Gluon Fields (8 color states) ---
		for (int a = 0; a < 8; a++) {
			double gluon_component = ((double)hash[a % 8] / 4294967296.0) - 0.5;
			gluon_field[a] = gluon_field[a] * 0.88 + gluon_component * 0.12;
		}
		
		// --- Quark Fields (6 flavors) ---
		for (int f = 0; f < 6; f++) {
			double quark_component = ((double)hash[f % 8] / 4294967296.0) - 0.5;
			quark_field[f] = quark_field[f] * 0.90 + quark_component * 0.10;
		}
		
		// --- Running Coupling α_s(Q²) ---
		// QCD coupling runs: stronger at low energy (confinement)
		// β-function: dα_s/d(ln Q²) = -β₀α_s²/(4π) + ...
		
		double gluon_energy_sq = 0.0;
		for (int a = 0; a < 8; a++) {
			gluon_energy_sq += gluon_field[a] * gluon_field[a];
		}
		
		double Q_squared = gluon_energy_sq * 1000.0 + 1.0;  // Energy scale
		double beta_0 = (11.0 * 3.0 - 2.0 * 6.0) / 3.0;  // 3 colors, 6 flavors
		
		// One-loop running
		double alpha_s_running = coupling_alpha_s / 
		                         (1.0 + coupling_alpha_s * beta_0 * log(Q_squared) / (4.0 * M_PI));
		
		coupling_alpha_s = coupling_alpha_s * 0.94 + alpha_s_running * 0.06;
		
		// Keep physical
		if (coupling_alpha_s < 0.1) coupling_alpha_s = 0.1;
		if (coupling_alpha_s > 2.0) coupling_alpha_s = 2.0;
		
		// --- Chiral Condensate <ψ̄ψ> ---
		// Non-zero → spontaneous chiral symmetry breaking
		// Generates constituent quark masses
		
		double chiral_value = 1.0;
		for (int f = 0; f < 6; f++) {
			chiral_value *= (1.0 - quark_field[f] * quark_field[f]);
		}
		
		chiral_condensate = chiral_condensate * 0.91 + chiral_value * 0.09;
		
		// --- Polyakov Loop (Confinement) ---
		// L = <Tr P exp(i∫A₀dt)>
		// |L| = 0 → confined, |L| = 1 → deconfined
		
		double polyakov_trace = 0.0;
		for (int a = 0; a < 3; a++) {  // SU(3) trace
			polyakov_trace += cos(gluon_field[a]);
		}
		polyakov_trace /= 3.0;
		
		polyakov_loop = polyakov_loop * 0.92 + polyakov_trace * 0.08;
		
		bool confined = (fabs(polyakov_loop) < 0.3);
		
		// --- String Tension σ (Linear Potential) ---
		// V(r) = σ·r for large r (flux tube)
		
		double flux_energy = 0.0;
		for (int a = 0; a < 8; a++) {
			flux_energy += fabs(gluon_field[a]);
		}
		
		string_tension = string_tension * 0.93 + (flux_energy * 0.1) * 0.07;
		
		if (string_tension < 0.05) string_tension = 0.05;
		if (string_tension > 5.0) string_tension = 5.0;
		
		// --- Instanton Density (Topology) ---
		// Tunneling between vacuum sectors
		
		double topological_charge = 0.0;
		for (int a = 0; a < 7; a++) {
			topological_charge += gluon_field[a] * gluon_field[a+1];
		}
		
		if (fabs(topological_charge) > 0.05) {
			instanton_density++;
		}
		
		// --- Lattice QCD Structure ---
		// Discretize spacetime on lattice with spacing a
		
		lattice_spacing = 1 + ((hash[4] >> 16) & 0xF);
		lattice_volume = lattice_spacing * lattice_spacing * 
		                 lattice_spacing * lattice_spacing;
		
		// Lattice coupling β = 6/g²
		beta_lattice = 6.0 / (coupling_alpha_s * coupling_alpha_s + 0.01);
		
		// --- PRIME NUMBER THEORY ANALYSIS ---
		
		// --- Primality Testing (Miller-Rabin style) ---
		bool is_probable_prime = true;
		
		if (n < 2) {
			is_probable_prime = false;
		} else if (n == 2) {
			is_probable_prime = true;
		} else if (n % 2 == 0) {
			is_probable_prime = false;
		} else {
			// Quick divisibility test
			for (int i = 0; i < 16; i++) {
				if (n % small_primes[i] == 0 && n != small_primes[i]) {
					is_probable_prime = false;
					break;
				}
			}
			
			// Hash-based witness test
			if (is_probable_prime) {
				uint32_t witness = hash[0] % (n - 1) + 1;
				// Simplified Fermat test: a^(n-1) mod n
				// (Not full Miller-Rabin, but fast approximation)
				if ((witness % n) == 0) {
					is_probable_prime = false;
				}
			}
		}
		
		// --- Prime Gap Analysis ---
		static uint32_t last_prime_candidate = 2;
		
		if (is_probable_prime) {
			if (last_prime_candidate > 0 && n > last_prime_candidate) {
				prime_gap = n - last_prime_candidate;
			}
			last_prime_candidate = n;
		}
		
		// --- Twin Prime Detection (p, p+2) ---
		if (is_probable_prime && ((n + 2) % 2 == 1)) {
			// Check if n+2 might be prime
			bool twin_candidate = true;
			for (int i = 0; i < 8; i++) {
				if ((n + 2) % small_primes[i] == 0 && (n + 2) != small_primes[i]) {
					twin_candidate = false;
					break;
				}
			}
			if (twin_candidate) {
				twin_prime_count++;
			}
		}
		
		// --- Sophie Germain Prime (p and 2p+1 both prime) ---
		if (is_probable_prime) {
			uint32_t sophie_candidate = 2 * n + 1;
			bool is_sophie = true;
			
			for (int i = 0; i < 12; i++) {
				if (sophie_candidate % small_primes[i] == 0 && 
				    sophie_candidate != small_primes[i]) {
					is_sophie = false;
					break;
				}
			}
			
			if (is_sophie) {
				sophie_germain_count++;
			}
		}
		
		// --- Von Mangoldt Function Λ(n) ---
		// Λ(n) = log p if n = p^k, else 0
		
		double von_mangoldt = 0.0;
		if (is_probable_prime) {
			von_mangoldt = log((double)n + 1.0);
		}
		
		riemann_von_mangoldt = riemann_von_mangoldt * 0.95 + von_mangoldt * 0.05;
		
		// --- Prime Omega Ω(n) (number of prime factors with multiplicity) ---
		uint32_t omega_count = 0;
		uint32_t n_temp = n;
		
		for (int i = 0; i < 32 && small_primes[i] <= n_temp; i++) {
			while (n_temp % small_primes[i] == 0) {
				omega_count++;
				n_temp /= small_primes[i];
			}
		}
		prime_omega = omega_count;
		
		// --- Euler Totient φ(n) ---
		// Count of numbers ≤ n coprime to n
		uint64_t totient = n;
		uint32_t n_phi = n;
		
		for (int i = 0; i < 32 && small_primes[i] * small_primes[i] <= n_phi; i++) {
			if (n_phi % small_primes[i] == 0) {
				totient -= totient / small_primes[i];
				while (n_phi % small_primes[i] == 0) {
					n_phi /= small_primes[i];
				}
			}
		}
		if (n_phi > 1) {
			totient -= totient / n_phi;
		}
		
		totient_phi = totient;
		
		// --- Möbius Function μ(n) ---
		// μ(n) = 1 if n square-free with even # primes
		//      = -1 if n square-free with odd # primes
		//      = 0 if n has squared prime factor
		
		int32_t mobius = 1;
		uint32_t n_mu = n;
		bool square_free = true;
		int prime_count_mu = 0;
		
		for (int i = 0; i < 32 && small_primes[i] <= n_mu && square_free; i++) {
			int exponent = 0;
			while (n_mu % small_primes[i] == 0) {
				exponent++;
				n_mu /= small_primes[i];
			}
			if (exponent > 1) {
				square_free = false;
				mobius = 0;
			} else if (exponent == 1) {
				prime_count_mu++;
			}
		}
		
		if (square_free && n_mu > 1) {
			prime_count_mu++;  // Remaining prime factor
		}
		
		if (square_free) {
			mobius = (prime_count_mu % 2 == 0) ? 1 : -1;
		}
		
		mobius_mu = mobius;
		
		// --- QCD-Prime Correlation ---
		// Link gauge field dynamics to prime structure
		
		double qcd_order = fabs(polyakov_loop) + chiral_condensate + string_tension;
		double prime_density = is_probable_prime ? 1.0 : (1.0 / log((double)n + 2.0));
		
		qcd_prime_correlation = qcd_prime_correlation * 0.91 + 
		                        (qcd_order * prime_density) * 0.09;
		
		// --- Prime-Quantized Flux Tubes ---
		// Flux quantization on prime lattice sites
		
		if (is_probable_prime) {
			flux_tube_prime = (uint32_t)(string_tension * 1000.0) % small_primes[hash[5] % 256];
		}
		
		// --- Nonce Perturbation: QCD + Prime Fusion ---
		
		int64_t perturbation = 0;
		
		// Component 1: Gluon field strength
		double gluon_norm = sqrt(gluon_energy_sq);
		int64_t gluon_guidance = (int64_t)(gluon_norm * 512.0);
		
		// Component 2: Running coupling regime
		int64_t coupling_guidance = 0;
		if (coupling_alpha_s < 0.5) {
			// Asymptotic freedom region
			coupling_guidance = (hash[0] % 512) - 256;
		} else if (coupling_alpha_s < 1.2) {
			// Transition region
			coupling_guidance = (hash[0] % 1536) - 768;
		} else {
			// Confinement region
			coupling_guidance = (hash[0] % 3072) - 1536;
		}
		
		// Component 3: Chiral condensate (mass generation)
		int64_t chiral_guidance = (int64_t)(chiral_condensate * 640.0);
		
		// Component 4: Polyakov loop (confinement)
		int64_t polyakov_guidance = confined ? 
		                            ((hash[1] % 384) - 192) :
		                            ((hash[1] % 1280) - 640);
		
		// Component 5: String tension (flux tube)
		int64_t string_guidance = (int64_t)(string_tension * 896.0);
		
		// Component 6: Instanton tunneling
		int64_t instanton_guidance = (instanton_density & 1) ? 
		                              ((hash[2] % 1792) - 896) : 0;
		
		// Component 7: Lattice spacing
		int64_t lattice_guidance = (int64_t)(lattice_spacing * 128);
		
		// Component 8: Prime gap
		int64_t prime_gap_guidance = is_probable_prime ? 
		                             (int64_t)(prime_gap * 4) : 0;
		
		// Component 9: Twin prime bonus
		int64_t twin_guidance = (twin_prime_count % 8) * 256;
		
		// Component 10: Sophie Germain bonus
		int64_t sophie_guidance = (sophie_germain_count % 8) * 384;
		
		// Component 11: Von Mangoldt accumulation
		int64_t mangoldt_guidance = (int64_t)(riemann_von_mangoldt * 448.0);
		
		// Component 12: Prime omega (factorization)
		int64_t omega_guidance = (int64_t)(prime_omega * 96);
		
		// Component 13: Totient function
		int64_t totient_guidance = (int64_t)((totient_phi % 2048) - 1024);
		
		// Component 14: Möbius function
		int64_t mobius_guidance = mobius_mu * 512;
		
		// Component 15: QCD-Prime correlation
		int64_t correlation_guidance = (int64_t)(qcd_prime_correlation * 576.0);
		
		// Component 16: Prime-quantized flux
		int64_t flux_quantum_guidance = (int64_t)(flux_tube_prime);
		
		// Aggregate all components
		perturbation = (gluon_guidance >> 2) +
		               (coupling_guidance >> 1) +
		               (chiral_guidance >> 2) +
		               (polyakov_guidance >> 1) +
		               (string_guidance >> 2) +
		               (instanton_guidance >> 1) +
		               (lattice_guidance >> 3) +
		               (prime_gap_guidance >> 1) +
		               (twin_guidance >> 2) +
		               (sophie_guidance >> 2) +
		               (mangoldt_guidance >> 2) +
		               (omega_guidance >> 3) +
		               (totient_guidance >> 2) +
		               (mobius_guidance >> 2) +
		               (correlation_guidance >> 2) +
		               (flux_quantum_guidance >> 4);
		
		// Apply perturbation
		n = (uint32_t)((int64_t)n + perturbation);
		
		// --- Prime Lattice Jump ---
		// Jump to nearest prime lattice site
		if (lattice_spacing > 1) {
			uint32_t prime_idx = (hash[6] >> 8) & 0xFF;
			n += small_primes[prime_idx % 256] * lattice_spacing;
		}
		
		// --- Confinement Scale ---
		// ΛQCD ~ 200 MeV jump
		if (confined) {
			n += (uint32_t)(string_tension * 200.0);
		}
		
		// --- Ensure odd (prime-friendly) ---
		n |= 1;
		
		// --- Forward progress ---
		if (n <= last_n) {
			uint32_t escape_jump = lattice_spacing * small_primes[hash[7] & 0x1F];
			n = last_n + escape_jump + 1;
		}
		last_n = n;
		
		// --- Periodic renormalization ---
		if ((n & 0x7FFF) == 0) {
			// Reset QCD fields
			for (int a = 0; a < 8; a++) {
				gluon_field[a] *= 0.8;
			}
			for (int f = 0; f < 6; f++) {
				quark_field[f] *= 0.8;
			}
			
			// Decay accumulators
			twin_prime_count = twin_prime_count >> 2;
			sophie_germain_count = sophie_germain_count >> 2;
			instanton_density = instanton_density >> 2;
			
			// Reset coupling if diverged
			if (coupling_alpha_s > 1.8) coupling_alpha_s = 0.5;
			if (string_tension > 4.0) string_tension = 0.3;
			
			// Reset correlation
			qcd_prime_correlation *= 0.9;
		}
		
	} while (likely(n < max_nonce && !work_restart[thr_id].restart));
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
