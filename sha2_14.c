int scanhash_sha256d(int thr_id, struct work *work,
                     uint32_t max_nonce, uint64_t *hashes_done)
{
    uint32_t _ALIGN(128) data[64];
    uint32_t _ALIGN(32) hash[8];
    uint32_t _ALIGN(32) midstate[8];
    uint32_t _ALIGN(32) prehash[8];

    uint32_t *restrict pdata   = work->data;
    uint32_t *restrict ptarget = work->target;

    const uint32_t first_nonce = pdata[19];
    const uint32_t Htarg       = ptarget[7];

#ifdef HAVE_SHA256_8WAY
    if (sha256_use_8way())
        return scanhash_sha256d_8way(thr_id, work, max_nonce, hashes_done);
#endif
#ifdef HAVE_SHA256_4WAY
    if (sha256_use_4way())
        return scanhash_sha256d_4way(thr_id, work, max_nonce, hashes_done);
#endif

    static const uint32_t WEYL_CONST = 0x9E3779B9U;

    static __thread uint32_t weyl_state;
    static __thread uint32_t last_first_nonce;
    static __thread int init_done;

    /* Reseed Weyl sequence per new work */
    if (!init_done || last_first_nonce != first_nonce) {
        weyl_state = first_nonce ^ (thr_id * WEYL_CONST);
        last_first_nonce = first_nonce;
        init_done = 1;
    }

    /* Prepare SHA pipeline */
    memcpy(data, pdata + 16, 64);
    sha256d_preextend(data);

    sha256_init(midstate);
    sha256_transform(midstate, pdata, 0);

    memcpy(prehash, midstate, 32);
    sha256d_prehash(prehash, pdata + 16);

    uint32_t iterations = 0;
    const uint32_t nonce_range = max_nonce - first_nonce;

    while (likely(!work_restart[thr_id].restart)) {

        weyl_state += WEYL_CONST;

        /* Bounded Weyl walk */
        uint32_t n = first_nonce + (weyl_state % nonce_range);
        data[3] = n;

        sha256d_ms(hash, data, midstate, prehash);
        iterations++;

        /* Early target filter */
        uint32_t h7 = bswap_32(hash[7]);
        if (unlikely(h7 <= Htarg)) {
            pdata[19] = n;
            sha256d_80_swap(hash, pdata);

            if (fulltest(hash, ptarget)) {
                work_set_target_ratio(work, hash);
                *hashes_done = iterations;
                return 1;
            }
        }
    }

    *hashes_done = iterations;
    pdata[19] = first_nonce + (weyl_state % nonce_range) + 1;
    return 0;
}
