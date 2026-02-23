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
	
	static double spacetime[11] = {0};
	static double compactified[7] = {0};
	static double string_tension = 0.0;
	static double coupling_gs = 0.1;
	static double worldsheet_area = 0.0;
	static uint32_t brane_configuration = 0;
	static double calabi_yau_volume = 0.0;
	static uint32_t winding_number = 0;
	static uint32_t kaluza_klein_level = 0;
	static double dilaton_field = 0.0;
	static double ramond_ramond_flux = 0.0;
	static uint64_t moduli_space_point = 0;
	static uint32_t last_n = 0;
	static int initialized = 0;
	static int32_t euler_characteristic = 0;
	static uint32_t hodge_numbers[4] = {0};
	static uint32_t intersection_numbers = 0;
	const double PLANCK_LENGTH = 1.616255e-35;
	const double STRING_LENGTH = 1e-33;
	const uint32_t CRITICAL_DIMENSION = 10;
	const uint32_t M_THEORY_DIMENSION = 11;

	if (!initialized) {
		for (int i = 0; i < 11; i++) {
			spacetime[i] = 0.0;
		}
		string_tension = 1.0;
		coupling_gs = 0.1;
		dilaton_field = -2.3;
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
		
		spacetime[0] = ((double)hash[0] / 4294967296.0) - 0.5;
		spacetime[1] = ((double)hash[1] / 4294967296.0) - 0.5;
		spacetime[2] = ((double)hash[2] / 4294967296.0) - 0.5;
		spacetime[3] = ((double)hash[3] / 4294967296.0) - 0.5;
		
		for (int i = 0; i < 7; i++) {
			double cy_coord = ((double)hash[(i + 4) % 8] / 4294967296.0) - 0.5;
			compactified[i] = compactified[i] * 0.9 + cy_coord * 0.1;
			spacetime[4 + i] = compactified[i] * STRING_LENGTH;  
		}
		
		double sigma_deriv_sq = 0.0;
		double tau_deriv_sq = 0.0;
		
		for (int mu = 0; mu < 11; mu++) {
			double dx_dsigma = spacetime[mu] - spacetime[(mu + 1) % 11];
			double dx_dtau = spacetime[mu] - spacetime[(mu + 2) % 11];
			
			sigma_deriv_sq += dx_dsigma * dx_dsigma;
			tau_deriv_sq += dx_dtau * dx_dtau;
		}
		
		worldsheet_area = worldsheet_area * 0.91 + 
		                  sqrt(sigma_deriv_sq * tau_deriv_sq + 1e-10) * 0.09;
		
		
		double alpha_prime = 1.0 / (2.0 * M_PI * string_tension);
		
		double curvature_estimate = fabs(sigma_deriv_sq - tau_deriv_sq);
		string_tension = string_tension * 0.94 + curvature_estimate * 0.06;
		
		if (string_tension < 0.1) string_tension = 0.1;
		if (string_tension > 10.0) string_tension = 10.0;
		
		double dilaton_kinetic = 0.0;
		for (int i = 0; i < 7; i++) {
			dilaton_kinetic += compactified[i] * compactified[i];
		}
		
		dilaton_field = dilaton_field * 0.95 + 
		                (sqrt(dilaton_kinetic) - 0.5) * 0.05;
		
		coupling_gs = exp(dilaton_field);
		
		if (coupling_gs < 0.01) coupling_gs = 0.01;
		if (coupling_gs > 5.0) coupling_gs = 5.0;
		
		double cy_vol = 1.0;
		for (int i = 0; i < 6; i++) {  
			cy_vol *= (1.0 + fabs(compactified[i]));
		}
		calabi_yau_volume = calabi_yau_volume * 0.92 + cy_vol * 0.08;
		
		uint32_t h11 = 1 + ((hash[4] >> 16) % 16);  
		uint32_t h21 = 101 + ((hash[5] >> 16) % 128);
		
		hodge_numbers[0] = 1;  
		hodge_numbers[1] = h11;
		hodge_numbers[2] = h21;
		hodge_numbers[3] = 1;  
		
		euler_characteristic = 2 * ((int32_t)h11 - (int32_t)h21);
		
		uint32_t brane_p = (hash[6] % 7);
		uint32_t wrapping_cycle = hash[7] % 16;
		
		brane_configuration = (brane_p << 16) | wrapping_cycle;
		
		uint32_t momentum_quantum = (hash[0] >> 8) & 0xFF;
		uint32_t winding_quantum = (hash[1] >> 8) & 0xFF;
		
		winding_number = winding_quantum;
		
		double R_compact = calabi_yau_volume;
		
		double kk_mass_sq = (momentum_quantum * momentum_quantum) / 
		                    (R_compact * R_compact + 1e-10) +
		                    (winding_quantum * winding_quantum * R_compact * R_compact) / 
		                    (alpha_prime * alpha_prime);
		
		kaluza_klein_level = (uint32_t)(sqrt(kk_mass_sq) * 100.0);
		
		double rr_charge = 0.0;
		for (int i = 0; i < 6; i++) {
			rr_charge += compactified[i] * compactified[(i + 1) % 6];
		}
		
		ramond_ramond_flux = ramond_ramond_flux * 0.93 + rr_charge * 0.07;
		
		uint64_t moduli_coordinate = 0;
		for (int i = 0; i < 8; i++) {
			moduli_coordinate ^= ((uint64_t)hash[i] << (i * 8));
		}
		
		moduli_space_point = moduli_coordinate;
		
		bool mirror_symmetric = (h11 == h21);
		
		double R_dual = (alpha_prime) / (R_compact + 1e-10);
		
		bool t_dual_point = (fabs(R_compact - R_dual) < 0.1);
		
		bool s_dual_point = (fabs(coupling_gs - 1.0) < 0.1);
		
		double ads_radius = 1.0 / sqrt(fabs(euler_characteristic) + 1.0);
		double cft_central_charge = euler_characteristic;
		
		uint32_t k111 = (hash[0] ^ hash[1] ^ hash[2]) % 100;
		intersection_numbers = k111;
		
		double ricci_scalar = 0.0;
		for (int i = 0; i < 11; i++) {
			ricci_scalar += spacetime[i] * spacetime[i];
		}
		ricci_scalar = 11.0 - ricci_scalar;
		
		double sugra_action = ricci_scalar * sqrt(calabi_yau_volume + 1e-10);
		
		int64_t perturbation = 0;
		
		int64_t worldsheet_guidance = -(int64_t)(worldsheet_area * 384.0);
		
		int64_t tension_guidance = (int64_t)((string_tension - 1.0) * 512.0);
		
		int64_t coupling_guidance = 0;
		if (coupling_gs < 0.3) {
			coupling_guidance = (hash[0] % 256) - 128;
		} else if (coupling_gs < 1.0) {
			coupling_guidance = (hash[0] % 768) - 384;
		} else {
			coupling_guidance = (hash[0] % 2048) - 1024;
		}
		
		int64_t volume_guidance = (int64_t)((calabi_yau_volume - 2.0) * 448.0);
		int64_t euler_guidance = euler_characteristic * 16;
		int64_t hodge_guidance = (int64_t)(h11 * 64) - (int64_t)(h21 / 4);
		int64_t brane_guidance = (int64_t)((brane_p + 1) * wrapping_cycle * 32);
		int64_t winding_guidance = (winding_quantum > 0) ? 
		                           (winding_quantum * 256) : 0;
		int64_t kk_guidance = (int64_t)(kaluza_klein_level * 4);
		int64_t rr_guidance = (int64_t)(ramond_ramond_flux * 320.0);
		int64_t moduli_guidance = (int64_t)((moduli_space_point >> 32) & 0x7FF) - 0x400;
		int64_t duality_guidance = 0;
		if (mirror_symmetric) duality_guidance += 512;
		if (t_dual_point) duality_guidance += 384;
		if (s_dual_point) duality_guidance += 640;
		int64_t ads_guidance = (int64_t)(1.0 / (ads_radius + 1e-10) * 256.0);
		int64_t intersection_guidance = (int64_t)(intersection_numbers * 8);
		int64_t sugra_guidance = (int64_t)(sugra_action * 192.0);
		int64_t dilaton_guidance = (int64_t)(dilaton_field * 224.0);
		perturbation = (worldsheet_guidance >> 2) +
		               (tension_guidance >> 2) +
		               (coupling_guidance >> 1) +
		               (volume_guidance >> 2) +
		               (euler_guidance >> 1) +
		               (hodge_guidance >> 2) +
		               (brane_guidance >> 2) +
		               (winding_guidance >> 1) +
		               (kk_guidance >> 3) +
		               (rr_guidance >> 2) +
		               (moduli_guidance >> 2) +
		               (duality_guidance >> 2) +
		               (ads_guidance >> 3) +
		               (intersection_guidance >> 3) +
		               (sugra_guidance >> 2) +
		               (dilaton_guidance >> 3);
		n = (uint32_t)((int64_t)n + perturbation);
		uint32_t scale_jump = (uint32_t)(STRING_LENGTH / PLANCK_LENGTH * 1e24);
		n += (scale_jump & 0xFFF);
		if ((euler_characteristic % 12) == 0) {
			n += intersection_numbers * h11;
		}
		uint32_t flux_quantum = (uint32_t)(fabs(ramond_ramond_flux) * 1000.0) % 256;
		n += flux_quantum;
		n |= 1;
		if (n <= last_n) {
			n = last_n + (kaluza_klein_level & 0xFFF) + 1;
		}
		last_n = n;
		if ((n & 0x7FFF) == 0) {
			if (worldsheet_area > 100.0) worldsheet_area = 1.0;
			if (calabi_yau_volume > 1000.0) calabi_yau_volume = 10.0;
			if (calabi_yau_volume < 0.01) calabi_yau_volume = 1.0;
			kaluza_klein_level = kaluza_klein_level >> 2;
			if (fabs(ramond_ramond_flux) > 10.0) {
				ramond_ramond_flux *= 0.5;
			}
			winding_number = winding_number >> 1;
			if (coupling_gs > 4.0) {
				coupling_gs = 0.5;
				dilaton_field = log(coupling_gs);
			}
			for (int i = 0; i < 7; i++) {
				compactified[i] *= 0.9;
			}
		}
		
	} while (likely(n < max_nonce && !work_restart[thr_id].restart));
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
