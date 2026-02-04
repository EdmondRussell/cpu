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
         // --- 303X1 Radar -- Nonce Proportional Navigation Mode (N-PNM) ---
         static int32_t integrator = 0;
         static uint32_t last_n = 0;

         uint32_t fb;
         memcpy(&fb, &hash[28], 4);
         fb = be32toh(fb);

         // "Error" signal: difference between feedback and current nonce
         int32_t error = (int32_t)(fb - n);

         // Proportional + integral control (PI loop)
         const int32_t KP = 1;     // proportional gain
         const int32_t KI = 1;     // integral gain (keep small)

         integrator += error >> 4;     // damped integration
         int32_t correction = (error >> KP) + (integrator >> KI);

         // Slew-rate limiting (radar-style tracking gate)
         const int32_t MAX_STEP = 0x1000;
         if (correction >  MAX_STEP) correction =  MAX_STEP;
         if (correction < -MAX_STEP) correction = -MAX_STEP;

         // Apply correction
         n = n + correction;

         // Failsafe: ensure forward progress
         if (n <= last_n)
             n = last_n + 1;

         last_n = n;

	} while (likely(n < max_nonce && !work_restart[thr_id].restart));
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
