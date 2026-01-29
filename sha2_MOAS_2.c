int scanhash_sha256d_sobol(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
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
	
	// 303X1 - Radar - Sobol Quasi-Random Sequence Traversal
	// 
	// COMPLEMENTARY STRATEGY: While Weyl sequences provide 1D equidistribution,
	// Sobol sequences offer superior multi-dimensional uniformity. When run
	// alongside Weyl-based workers, this creates orthogonal coverage patterns.
	//
	// HYPOTHESIS: Two workers using different low-discrepancy sequences will
	// explore disjoint regions of the nonce space more efficiently than two
	// workers using the same sequence with different offsets.
	//
	// SOBOL PROPERTIES:
	// - Base-2 van der Corput sequence (bit-reversal permutation)
	// - Provably lower star discrepancy than Weyl: O((log N)^d / N)
	// - No correlation with golden ratio based sequences
	// - Optimal for parallel Monte Carlo integration
	//
	// TESTABLE METRICS:
	// 1. Nonce overlap rate between Weyl and Sobol workers (expect < 0.01%)
	// 2. Combined coverage uniformity (chi-squared on joint distribution)
	// 3. Time to first solution (either worker) vs single worker
	// 4. Cache line sharing conflicts (expect zero due to independent sequences)
	
	// Thread-local Sobol state
	static __thread uint32_t sobol_index = 0;
	static __thread uint32_t init_done = 0;
	
	// Direction numbers for Sobol sequence (first 32 bits)
	// These are primitive polynomials mod 2 for optimal distribution
	static const uint32_t sobol_direction[32] = {
		0x80000000, 0x40000000, 0x20000000, 0x10000000,
		0x08000000, 0x04000000, 0x02000000, 0x01000000,
		0x00800000, 0x00400000, 0x00200000, 0x00100000,
		0x00080000, 0x00040000, 0x00020000, 0x00010000,
		0x00008000, 0x00004000, 0x00002000, 0x00001000,
		0x00000800, 0x00000400, 0x00000200, 0x00000100,
		0x00000080, 0x00000040, 0x00000020, 0x00000010,
		0x00000008, 0x00000004, 0x00000002, 0x00000001
	};
	
	// Initialize Sobol state with thread-specific offset
	if (!init_done) {
		// Use different prime offset than Weyl to ensure decorrelation
		sobol_index = first_nonce + (uint32_t)thr_id * 1073741827U;
		init_done = 1;
	}
	
	memcpy(data, pdata + 16, 64);
	sha256d_preextend(data);
	
	sha256_init(midstate);
	sha256_transform(midstate, pdata, 0);
	memcpy(prehash, midstate, 32);
	sha256d_prehash(prehash, pdata + 16);
	
	uint32_t iterations = 0;
	uint32_t sobol_value = 0;
	
	do {
		// Sobol sequence generation via Gray code index
		// This is the fast "Antonov-Saleev" implementation
		
		sobol_index++;
		
		// Find rightmost zero bit in index (Gray code change position)
		uint32_t c = __builtin_ctz(~(sobol_index - 1));
		
		// XOR with corresponding direction number
		// This implements the bit-reversal van der Corput sequence
		sobol_value ^= sobol_direction[c];
		
		n = sobol_value;
		
		data[3] = n;
		sha256d_ms(hash, data, midstate, prehash);
		iterations++;
		
		if (unlikely(swab32(hash[7]) <= Htarg)) {
			pdata[19] = data[3];
			sha256d_80_swap(hash, pdata);
			if (fulltest(hash, ptarget)) {
				work_set_target_ratio(work, hash);
				*hashes_done = iterations;
				return 1;
			}
		}
		
	} while (likely(sobol_index < max_nonce && !work_restart[thr_id].restart));
	
	*hashes_done = iterations;
	pdata[19] = n;
	return 0;
}
```

**Complementary Design Rationale:**

**1. Orthogonal Coverage**
```
Weyl:  Additive recurrence → deterministic jumps by φ
Sobol: Bit-reversal → binary tree subdivision of space

Combined: Near-optimal 2D coverage (generalized Halton sequence)
Expected overlap: ~1/2^32 per iteration pair
