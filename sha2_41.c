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
	
	// --- String Theory v3: BPS State Attractor with Flux Stabilization ---
	// Enhanced with multi-vein tracking and configuration locking
	
	// 11D spacetime coordinates
	static double spacetime[11] = {0};
	static double compactified[7] = {0};
	
	// String dynamics
	static double string_tension = 1.0;
	static double coupling_gs = 0.1;
	static double dilaton_field = -2.3;
	static double worldsheet_area = 0.0;
	
	// Calabi-Yau manifold
	static double calabi_yau_volume = 1.0;
	static int32_t euler_characteristic = 0;
	static uint32_t hodge_h11 = 1;
	static uint32_t hodge_h21 = 101;
	
	// Brane physics
	static uint32_t brane_configuration = 0;
	static uint32_t winding_number = 0;
	static uint32_t kaluza_klein_level = 0;
	static double brane_tension = 1.0;
	
	// Flux compactification
	static double ramond_ramond_flux = 0.0;
	static double neveu_schwarz_flux = 0.0;
	static uint32_t flux_quantum_h = 0;  // H-flux quantum
	static uint32_t flux_quantum_f = 0;  // F-flux quantum
	
	// Topological data
	static uint32_t instanton_number = 0;
	static double vacuum_theta = 0.0;
	static uint32_t intersection_numbers = 0;
	
	// Moduli stabilization
	static uint64_t moduli_space_point = 0;
	static double moduli_locked = 0;  // 0=free, 1=locked
	
	// Supersymmetry
	static double susy_breaking_scale = 0.0;
	static uint32_t susy_preserved = 1;
	static uint32_t bps_states = 0;  // BPS saturated states
	
	// --- MULTI-VEIN TRACKING (Enhanced) ---
	
	#define VEIN_SIZE 64  // Increased from 32
	#define NUM_VEINS 4   // Track multiple distinct veins
	
	// Per-vein data structures
	static uint32_t vein_locations[NUM_VEINS][VEIN_SIZE] = {{0}};
	static uint32_t vein_distances[NUM_VEINS][VEIN_SIZE] = {{0xFFFFFFFF}};
	static uint32_t vein_heads[NUM_VEINS] = {0};
	static uint32_t vein_counts[NUM_VEINS] = {0};
	static uint32_t vein_active[NUM_VEINS] = {0};
	
	// Configuration snapshots at each vein
	static double vein_cy_volumes[NUM_VEINS] = {0};
	static double vein_couplings[NUM_VEINS] = {0};
	static double vein_dilatons[NUM_VEINS] = {0};
	static double vein_tensions[NUM_VEINS] = {0};
	static uint32_t vein_euler_chars[NUM_VEINS] = {0};
	static uint32_t vein_flux_h[NUM_VEINS] = {0};
	static uint32_t vein_flux_f[NUM_VEINS] = {0};
	
	// Current vein being mined
	static uint32_t active_vein_id = 0;
	static uint32_t vein_richness[NUM_VEINS] = {0};  // Quality metric
	
	// Global detection
	static uint32_t hits_in_window = 0;
	static uint32_t window_total = 0;
	
	// Mining mode with finer gradations
	typedef enum {
		MODE_EXPLORATION,        // Wide string theory search
		MODE_VEIN_DETECTION,     // Found promising area
		MODE_VEIN_ANALYSIS,      // Analyzing vein configuration
		MODE_FLUX_STABILIZATION, // Locking moduli at vein config
		MODE_BPS_SATURATION,     // Maximum exploitation at BPS point
		MODE_VEIN_EXHAUSTED      // Move to next vein or explore
	} MiningMode;
	
	static MiningMode mode = MODE_EXPLORATION;
	static uint32_t mode_timer = 0;
	
	// Best ever configuration (global champion)
	static uint32_t champion_distance = 0xFFFFFFFF;
	static uint32_t champion_location = 0;
	static double champion_cy_volume = 1.0;
	static double champion_coupling = 0.1;
	static double champion_dilaton = -2.3;
	static double champion_tension = 1.0;
	static int32_t champion_euler = 0;
	static uint32_t champion_flux_h = 0;
	static uint32_t champion_flux_f = 0;
	
	// Exploration velocity
	static uint32_t exploration_step = 1024;
	
	static uint32_t last_n = 0;
	static int initialized = 0;
	
	if (!initialized) {
		for (int i = 0; i < 11; i++) spacetime[i] = 0.0;
		for (int i = 0; i < 7; i++) compactified[i] = 0.0;
		for (int v = 0; v < NUM_VEINS; v++) {
			vein_cy_volumes[v] = 1.0;
			vein_couplings[v] = 0.1;
			vein_dilatons[v] = -2.3;
			vein_tensions[v] = 1.0;
		}
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
		
		uint32_t hash_result = swab32(hash[7]);
		uint32_t distance = hash_result > Htarg ? (hash_result - Htarg) : 0;
		
		if (unlikely(hash_result <= Htarg)) {
			pdata[19] = data[3];
			sha256d_80_swap(hash, pdata);
			if (fulltest(hash, ptarget)) {
				work_set_target_ratio(work, hash);
				*hashes_done = n - first_nonce + 1;
				return 1;
			}
		}
		
		window_total++;
		mode_timer++;
		
		// --- EXTRACT 11D CONFIGURATION ---
		
		spacetime[0] = ((double)hash[0] / 4294967296.0) - 0.5;
		spacetime[1] = ((double)hash[1] / 4294967296.0) - 0.5;
		spacetime[2] = ((double)hash[2] / 4294967296.0) - 0.5;
		spacetime[3] = ((double)hash[3] / 4294967296.0) - 0.5;
		
		for (int i = 0; i < 7; i++) {
			double cy_coord = ((double)hash[(i + 4) % 8] / 4294967296.0) - 0.5;
			compactified[i] = compactified[i] * 0.87 + cy_coord * 0.13;
			spacetime[4 + i] = compactified[i] * 1e-33;
		}
		
		// --- WORLDSHEET DYNAMICS ---
		
		double sigma_deriv_sq = 0.0;
		double tau_deriv_sq = 0.0;
		
		for (int mu = 0; mu < 11; mu++) {
			double dx_dsigma = spacetime[mu] - spacetime[(mu + 1) % 11];
			double dx_dtau = spacetime[mu] - spacetime[(mu + 2) % 11];
			sigma_deriv_sq += dx_dsigma * dx_dsigma;
			tau_deriv_sq += dx_dtau * dx_dtau;
		}
		
		worldsheet_area = worldsheet_area * 0.89 + 
		                  sqrt(sigma_deriv_sq * tau_deriv_sq + 1e-10) * 0.11;
		
		// --- STRING TENSION ---
		
		double curvature = fabs(sigma_deriv_sq - tau_deriv_sq);
		string_tension = string_tension * 0.92 + curvature * 0.08;
		if (string_tension < 0.1) string_tension = 0.1;
		if (string_tension > 10.0) string_tension = 10.0;
		
		// --- DILATON FIELD & COUPLING ---
		
		double dilaton_kinetic = 0.0;
		for (int i = 0; i < 7; i++) {
			dilaton_kinetic += compactified[i] * compactified[i];
		}
		
		dilaton_field = dilaton_field * 0.93 + (sqrt(dilaton_kinetic) - 0.5) * 0.07;
		coupling_gs = exp(dilaton_field);
		
		if (coupling_gs < 0.01) coupling_gs = 0.01;
		if (coupling_gs > 5.0) coupling_gs = 5.0;
		
		// --- CALABI-YAU VOLUME (Critical!) ---
		
		double cy_vol = 1.0;
		for (int i = 0; i < 6; i++) {
			cy_vol *= (1.0 + fabs(compactified[i]));
		}
		calabi_yau_volume = calabi_yau_volume * 0.90 + cy_vol * 0.10;
		
		// --- HODGE NUMBERS ---
		
		hodge_h11 = 1 + ((hash[4] >> 16) % 16);
		hodge_h21 = 101 + ((hash[5] >> 16) % 128);
		euler_characteristic = 2 * ((int32_t)hodge_h11 - (int32_t)hodge_h21);
		
		// --- D-BRANE CONFIGURATION ---
		
		uint32_t brane_p = (hash[6] % 7);
		uint32_t wrapping_cycle = hash[7] % 16;
		brane_configuration = (brane_p << 16) | wrapping_cycle;
		
		// Brane tension: T_p ~ 1/g_s l_s^(p+1)
		brane_tension = 1.0 / (coupling_gs * pow(string_tension, (double)(brane_p + 1) / 2.0));
		
		// --- WINDING & MOMENTUM MODES ---
		
		uint32_t momentum_quantum = (hash[0] >> 8) & 0xFF;
		uint32_t winding_quantum = (hash[1] >> 8) & 0xFF;
		winding_number = winding_quantum;
		
		double R_compact = calabi_yau_volume;
		double alpha_prime = 1.0 / (2.0 * M_PI * string_tension);
		
		double kk_mass_sq = (momentum_quantum * momentum_quantum) / 
		                    (R_compact * R_compact + 1e-10) +
		                    (winding_quantum * winding_quantum * R_compact * R_compact) / 
		                    (alpha_prime * alpha_prime);
		
		kaluza_klein_level = (uint32_t)(sqrt(kk_mass_sq) * 100.0);
		
		// --- FLUX COMPACTIFICATION ---
		
		// Ramond-Ramond flux (quantized)
		double rr_charge = 0.0;
		for (int i = 0; i < 6; i++) {
			rr_charge += compactified[i] * compactified[(i + 1) % 6];
		}
		ramond_ramond_flux = ramond_ramond_flux * 0.91 + rr_charge * 0.09;
		flux_quantum_f = (uint32_t)(fabs(ramond_ramond_flux) * 1000.0) % 256;
		
		// Neveu-Schwarz flux (H-flux)
		double ns_charge = 0.0;
		for (int i = 0; i < 6; i++) {
			ns_charge += compactified[i] * compactified[(i + 2) % 7];
		}
		neveu_schwarz_flux = neveu_schwarz_flux * 0.91 + ns_charge * 0.09;
		flux_quantum_h = (uint32_t)(fabs(neveu_schwarz_flux) * 1000.0) % 256;
		
		// --- INSTANTON NUMBER ---
		
		double topological_density = 0.0;
		for (int i = 0; i < 6; i++) {
			topological_density += compactified[i] * compactified[(i + 3) % 7];
		}
		
		if (fabs(topological_density) > 0.05) {
			instanton_number++;
		}
		
		// --- MODULI SPACE ---
		
		uint64_t moduli_coord = 0;
		for (int i = 0; i < 8; i++) {
			moduli_coord ^= ((uint64_t)hash[i] << (i * 8));
		}
		moduli_space_point = moduli_coord;
		
		// --- INTERSECTION NUMBERS ---
		
		intersection_numbers = (hash[0] ^ hash[1] ^ hash[2]) % 100;
		
		// --- DUALITY DETECTION ---
		
		bool mirror_symmetric = (hodge_h11 == hodge_h21);
		
		double R_dual = alpha_prime / (R_compact + 1e-10);
		bool t_dual_point = (fabs(R_compact - R_dual) < 0.15);
		
		bool s_dual_point = (fabs(coupling_gs - 1.0) < 0.15);
		
		// --- SUPERSYMMETRY & BPS STATES ---
		
		susy_breaking_scale = fabs(euler_characteristic) * calabi_yau_volume;
		susy_preserved = (susy_breaking_scale < 10.0) ? 1 : 0;
		
		// BPS state: saturates bound |Z| = |M|
		// Central charge Z ~ ∫ Ω ∧ F (flux integral)
		double central_charge = fabs(ramond_ramond_flux * calabi_yau_volume);
		double bps_mass = sqrt(kk_mass_sq + central_charge * central_charge);
		
		// Check BPS saturation: |Z| = M
		bool is_bps_saturated = (fabs(central_charge - bps_mass) < 0.5);
		
		if (is_bps_saturated) {
			bps_states++;
		}
		
		// --- MODULI STABILIZATION ---
		
		// KKLT/Large Volume Scenario: moduli fixed by fluxes
		double flux_potential = ramond_ramond_flux * ramond_ramond_flux + 
		                        neveu_schwarz_flux * neveu_schwarz_flux;
		
		// Check if moduli are stabilized (potential minimum)
		moduli_locked = (flux_potential < 0.1 && fabs(ramond_ramond_flux) > 0.01) ? 1.0 : 0.0;
		
		// --- QUALITY ASSESSMENT ---
		
		uint32_t quality_threshold = 0x10000000;
		uint32_t elite_threshold = 0x04000000;  // Super elite
		
		bool is_quality = (distance < quality_threshold);
		bool is_elite = (distance < elite_threshold);
		
		if (is_quality) {
			hits_in_window++;
			
			// Determine which vein to add to
			uint32_t target_vein = active_vein_id;
			
			// If elite, consider starting a new vein
			if (is_elite && vein_counts[active_vein_id] > 8) {
				// Find least active vein to replace
				uint32_t min_richness = 0xFFFFFFFF;
				for (int v = 0; v < NUM_VEINS; v++) {
					if (vein_richness[v] < min_richness) {
						min_richness = vein_richness[v];
						target_vein = v;
					}
				}
				
				// Start fresh vein if this is much better
				if (distance < min_richness / 2) {
					vein_counts[target_vein] = 0;
					vein_richness[target_vein] = distance;
					active_vein_id = target_vein;
				}
			}
			
			// Add to vein
			uint32_t head = vein_heads[target_vein];
			vein_locations[target_vein][head] = n;
			vein_distances[target_vein][head] = distance;
			vein_heads[target_vein] = (head + 1) % VEIN_SIZE;
			if (vein_counts[target_vein] < VEIN_SIZE) vein_counts[target_vein]++;
			
			// Update vein configuration snapshot
			vein_cy_volumes[target_vein] = (vein_cy_volumes[target_vein] * 3.0 + calabi_yau_volume) / 4.0;
			vein_couplings[target_vein] = (vein_couplings[target_vein] * 3.0 + coupling_gs) / 4.0;
			vein_dilatons[target_vein] = (vein_dilatons[target_vein] * 3.0 + dilaton_field) / 4.0;
			vein_tensions[target_vein] = (vein_tensions[target_vein] * 3.0 + string_tension) / 4.0;
			vein_euler_chars[target_vein] = euler_characteristic;
			vein_flux_h[target_vein] = flux_quantum_h;
			vein_flux_f[target_vein] = flux_quantum_f;
			
			// Update vein richness
			vein_richness[target_vein] = (vein_richness[target_vein] * 7 + distance) >> 3;
			vein_active[target_vein] = 1;
			
			// Update champion if this is best ever
			if (distance < champion_distance) {
				champion_distance = distance;
				champion_location = n;
				champion_cy_volume = calabi_yau_volume;
				champion_coupling = coupling_gs;
				champion_dilaton = dilaton_field;
				champion_tension = string_tension;
				champion_euler = euler_characteristic;
				champion_flux_h = flux_quantum_h;
				champion_flux_f = flux_quantum_f;
				
				// Trigger BPS saturation mode
				mode = MODE_BPS_SATURATION;
				mode_timer = 0;
				active_vein_id = target_vein;
			}
		}
		
		// --- MODE PROGRESSION ---
		
		if (window_total > 1000) {
			double hit_rate = (double)hits_in_window / (double)window_total;
			
			if (mode == MODE_EXPLORATION && hit_rate > 0.003 && hits_in_window >= 2) {
				mode = MODE_VEIN_DETECTION;
				mode_timer = 0;
			}
			
			if (mode == MODE_VEIN_DETECTION && hit_rate > 0.005 && hits_in_window >= 3) {
				mode = MODE_VEIN_ANALYSIS;
				mode_timer = 0;
			}
			
			if (mode == MODE_VEIN_ANALYSIS && hit_rate > 0.008 && hits_in_window >= 5) {
				mode = MODE_FLUX_STABILIZATION;
				mode_timer = 0;
			}
			
			// Reset window
			if (window_total > 10000) {
				window_total = 0;
				hits_in_window = 0;
			}
		}
		
		// --- MODE TIMEOUTS ---
		
		if (mode == MODE_VEIN_DETECTION && mode_timer > 4000) {
			mode = MODE_EXPLORATION;
			mode_timer = 0;
			exploration_step = exploration_step * 2;
		}
		
		if (mode == MODE_VEIN_ANALYSIS && mode_timer > 5000) {
			mode = MODE_VEIN_DETECTION;
			mode_timer = 0;
		}
		
		if (mode == MODE_FLUX_STABILIZATION && mode_timer > 6000) {
			mode = MODE_VEIN_EXHAUSTED;
			mode_timer = 0;
		}
		
		if (mode == MODE_BPS_SATURATION && mode_timer > 12000) {
			mode = MODE_VEIN_EXHAUSTED;
			mode_timer = 0;
		}
		
		if (mode == MODE_VEIN_EXHAUSTED && mode_timer > 2000) {
			// Switch to next best vein or explore
			uint32_t best_vein = 0;
			uint32_t best_vein_richness = 0xFFFFFFFF;
			
			for (int v = 0; v < NUM_VEINS; v++) {
				if (v != active_vein_id && vein_active[v] && vein_richness[v] < best_vein_richness) {
					best_vein_richness = vein_richness[v];
					best_vein = v;
				}
			}
			
			if (best_vein_richness < 0x20000000) {
				// Switch to another vein
				active_vein_id = best_vein;
				mode = MODE_VEIN_ANALYSIS;
			} else {
				// No good veins, back to exploration
				mode = MODE_EXPLORATION;
				exploration_step = 1024;
			}
			mode_timer = 0;
		}
		
		// --- NONCE PERTURBATION (MODE-DEPENDENT) ---
		
		int64_t perturbation = 0;
		
		switch (mode) {
			case MODE_EXPLORATION:
				// Full string theory exploration
				{
					perturbation += -(int64_t)(worldsheet_area * 384.0);
					perturbation += (int64_t)((string_tension - 1.0) * 512.0);
					
					if (coupling_gs < 0.5) {
						perturbation += (hash[0] % 768) - 384;
					} else if (coupling_gs < 1.2) {
						perturbation += (hash[0] % 2048) - 1024;
					} else {
						perturbation += (hash[0] % 4096) - 2048;
					}
					
					perturbation += (int64_t)((calabi_yau_volume - 2.0) * 448.0);
					
					// Large exploration steps
					n += exploration_step;
					exploration_step = (exploration_step * 11) / 10;
					if (exploration_step > 4096) exploration_step = 1024;
				}
				break;
				
			case MODE_VEIN_DETECTION:
				// Focusing on detected vein
				{
					uint32_t vein_id = active_vein_id;
					
					// Calculate vein center
					uint32_t vein_center = 0;
					uint64_t sum = 0;
					for (int i = 0; i < vein_counts[vein_id]; i++) {
						sum += vein_locations[vein_id][i];
					}
					if (vein_counts[vein_id] > 0) {
						vein_center = (uint32_t)(sum / vein_counts[vein_id]);
					}
					
					// Pull toward vein center
					int64_t center_pull = ((int64_t)vein_center - (int64_t)n) >> 2;
					perturbation += center_pull;
					
					// Target vein CY volume
					double volume_error = calabi_yau_volume - vein_cy_volumes[vein_id];
					perturbation += -(int64_t)(volume_error * 1024.0);
					
					// Standard string theory terms
					perturbation += (int64_t)((string_tension - vein_tensions[vein_id]) * 640.0);
				}
				break;
				
			case MODE_VEIN_ANALYSIS:
				// Analyzing vein configuration patterns
				{
					uint32_t vein_id = active_vein_id;
					
					// Lock onto vein CY volume
					double volume_target = vein_cy_volumes[vein_id];
					double volume_error = calabi_yau_volume - volume_target;
					perturbation += -(int64_t)(volume_error * 1536.0);
					
					// Lock onto vein coupling
					double coupling_error = coupling_gs - vein_couplings[vein_id];
					perturbation += -(int64_t)(coupling_error * 896.0);
					
					// Jump between vein locations
					if ((mode_timer & 0x1F) == 0 && vein_counts[vein_id] > 0) {
						uint32_t target_idx = hash[3] % vein_counts[vein_id];
						uint32_t target = vein_locations[vein_id][target_idx];
						perturbation += ((int64_t)target - (int64_t)n) >> 2;
					}
					
					// Force dilaton toward vein value
					if (fabs(dilaton_field - vein_dilatons[vein_id]) > 0.3) {
						dilaton_field = dilaton_field * 0.8 + vein_dilatons[vein_id] * 0.2;
					}
				}
				break;
				
			case MODE_FLUX_STABILIZATION:
				// Stabilizing moduli at vein configuration
				{
					uint32_t vein_id = active_vein_id;
					
					// LOCK ALL PARAMETERS
					double vol_lock = vein_cy_volumes[vein_id];
					double coupling_lock = vein_couplings[vein_id];
					double dilaton_lock = vein_dilatons[vein_id];
					double tension_lock = vein_tensions[vein_id];
					
					// Force convergence to locked values
					calabi_yau_volume = calabi_yau_volume * 0.7 + vol_lock * 0.3;
					coupling_gs = coupling_gs * 0.7 + coupling_lock * 0.3;
					dilaton_field = dilaton_field * 0.7 + dilaton_lock * 0.3;
					string_tension = string_tension * 0.7 + tension_lock * 0.3;
					
					// Micro-search around locked configuration
					perturbation = (mode_timer % 128) - 64;
					
					// Target flux quantization
					uint32_t flux_h_target = vein_flux_h[vein_id];
					uint32_t flux_f_target = vein_flux_f[vein_id];
					
					int32_t flux_h_error = (int32_t)flux_quantum_h - (int32_t)flux_h_target;
					int32_t flux_f_error = (int32_t)flux_quantum_f - (int32_t)flux_f_target;
					
					perturbation += -(flux_h_error * 8);
					perturbation += -(flux_f_error * 8);
					
					// Stay near best vein locations
					if (vein_counts[vein_id] > 0) {
						uint32_t closest = vein_locations[vein_id][0];
						uint32_t min_dist = abs((int32_t)n - (int32_t)closest);
						
						for (int i = 1; i < vein_counts[vein_id]; i++) {
							uint32_t dist = abs((int32_t)n - (int32_t)vein_locations[vein_id][i]);
							if (dist < min_dist) {
								min_dist = dist;
								closest = vein_locations[vein_id][i];
							}
						}
						
						perturbation += ((int64_t)closest - (int64_t)n) >> 3;
					}
				}
				break;
				
			case MODE_BPS_SATURATION:
				// MAXIMUM EXPLOITATION at champion point
				{
					// LOCK ONTO CHAMPION CONFIGURATION
					calabi_yau_volume = calabi_yau_volume * 0.5 + champion_cy_volume * 0.5;
					coupling_gs = coupling_gs * 0.5 + champion_coupling * 0.5;
					dilaton_field = dilaton_field * 0.5 + champion_dilaton * 0.5;
					string_tension = string_tension * 0.5 + champion_tension * 0.5;
					
					// Pull strongly toward champion location
					int64_t champion_pull = ((int64_t)champion_location - (int64_t)n) >> 1;
					perturbation += champion_pull;
					
					// Exhaustive micro-search
					perturbation += (mode_timer % 256) - 128;
					
					// Spiral pattern around champion
					double angle = (double)mode_timer * 0.1;
					uint32_t radius = (mode_timer / 100) % 64;
					
					int64_t dx = (int64_t)(cos(angle) * radius);
					int64_t dy = (int64_t)(sin(angle) * radius);
					perturbation += dx + dy;
					
					// Lock flux quanta
					if (flux_quantum_h != champion_flux_h) {
						int32_t h_correction = (int32_t)champion_flux_h - (int32_t)flux_quantum_h;
						perturbation += h_correction * 16;
					}
					
					if (flux_quantum_f != champion_flux_f) {
						int32_t f_correction = (int32_t)champion_flux_f - (int32_t)flux_quantum_f;
						perturbation += f_correction * 16;
					}
					
					// Force Euler characteristic match
					if (euler_characteristic != champion_euler) {
						perturbation += (champion_euler - euler_characteristic) * 32;
					}
				}
				break;
				
			case MODE_VEIN_EXHAUSTED:
				// Jump to new territory or different vein
				{
					// Large jump away
					perturbation = (hash[5] % 0x1000000) - 0x800000;
					
					n ^= hash[6];
					n += hash[7];
				}
				break;
		}
		
		// --- UNIVERSAL COMPONENTS (All modes) ---
		
		perturbation += euler_characteristic * 16;
		perturbation += (int64_t)(hodge_h11 * 64) - (int64_t)(hodge_h21 / 4);
		perturbation += (int64_t)((brane_p + 1) * wrapping_cycle * 32);
		
		if (winding_number > 0) {
			perturbation += winding_number * 256;
		}
		
		perturbation += (int64_t)(kaluza_klein_level * 4);
		perturbation += (int64_t)(ramond_ramond_flux * 320.0);
		perturbation += (int64_t)(neveu_schwarz_flux * 280.0);
		
		// Duality bonuses
		if (mirror_symmetric) perturbation += 512;
		if (t_dual_point) perturbation += 640;
		if (s_dual_point) perturbation += 768;
		
		// SUSY bonus
		if (susy_preserved) perturbation += 384;
		
		// BPS bonus
		if (is_bps_saturated) perturbation += 896;
		
		// Moduli stabilization bonus
		if (moduli_locked > 0.5) perturbation += 512;
		
		perturbation += (int64_t)(intersection_numbers * 8);
		perturbation += (int64_t)(brane_tension * 256.0);
		
		// Apply perturbation
		n = (uint32_t)((int64_t)n + perturbation);
		
		// Flux quantization jumps
		n += flux_quantum_h;
		n += flux_quantum_f;
		
		// Scale hierarchy
		uint32_t scale_jump = (kaluza_klein_level & 0xFFF);
		n += scale_jump;
		
		// Topological sector
		if ((euler_characteristic % 12) == 0) {
			n += intersection_numbers * hodge_h11;
		}
		
		// Instanton correction
		if ((instanton_number & 0x7) == 0 && instanton_number > 0) {
			n += (instanton_number * 128);
		}
		
		// Ensure odd
		n |= 1;
		
		// Forward progress
		if (n <= last_n) {
			n = last_n + (scale_jump & 0xFFF) + 1;
		}
		last_n = n;
		
		// --- PERIODIC RENORMALIZATION ---
		
		if ((n & 0x7FFF) == 0) {
			if (worldsheet_area > 100.0) worldsheet_area = 1.0;
			if (calabi_yau_volume > 1000.0) calabi_yau_volume = 10.0;
			if (calabi_yau_volume < 0.01) calabi_yau_volume = 1.0;
			
			kaluza_klein_level = kaluza_klein_level >> 2;
			
			if (fabs(ramond_ramond_flux) > 10.0) ramond_ramond_flux *= 0.5;
			if (fabs(neveu_schwarz_flux) > 10.0) neveu_schwarz_flux *= 0.5;
			
			winding_number = winding_number >> 1;
			instanton_number = instanton_number >> 2;
			bps_states = bps_states >> 2;
			
			if (coupling_gs > 4.0) {
				coupling_gs = 0.5;
				dilaton_field = log(coupling_gs);
			}
			
			for (int i = 0; i < 7; i++) {
				compactified[i] *= 0.9;
			}
			
			// Decay vein richness for inactive veins
			for (int v = 0; v < NUM_VEINS; v++) {
				if (v != active_vein_id) {
					vein_richness[v] = (vein_richness[v] >> 1) | 0x40000000;
				}
			}
			
			// Decay champion if not in BPS mode
			if (mode != MODE_BPS_SATURATION && mode != MODE_FLUX_STABILIZATION) {
				champion_distance = (champion_distance >> 1) | 0x80000000;
			}
		}
		
	} while (likely(n < max_nonce && !work_restart[thr_id].restart));
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
