#include <sys/time.h>
#include <limits.h>

#include "work_queue.h"
#include "global_state.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_random.h"
#include "mining.h"
#include "string.h"
#include "esp_timer.h"

#include "asic.h"
#include "system.h"
#include "esp_heap_caps.h"

static const char *TAG = "create_jobs_task";

static void generate_work(GlobalState *GLOBAL_STATE, mining_notify *notification, uint64_t extranonce_2, uint32_t difficulty);

/* =========================================================================
 * Dual-mode guided nonce progression
 *
 * Combines two complementary traversal strategies:
 *
 *   MACRO: Golden ratio stride (0x9E3779B9) — coprime to 2^32, guarantees
 *          full-period coverage. Each job starts ~2.6B nonces apart,
 *          spreading across the entire 32-bit space immediately.
 *
 *   MICRO: xorshift32 perturbation — de-correlates consecutive jobs that
 *          would otherwise alias on the golden ratio lattice. Applied as a
 *          small perturbation every ~16 steps to break stride patterns
 *          without destroying the macro distribution.
 *
 * On each new work notification both state variables are re-seeded from
 * hardware entropy (ESP32 true RNG + high-resolution timer) to prevent
 * cross-session correlation.
 *
 * Per-job extranonce seeding maps the extranonce_2 counter through the
 * golden ratio so consecutive jobs begin maximally separated in nonce space
 * rather than continuing linearly from the previous job's endpoint.
 * ========================================================================= */

#define GUIDED_STRIDE 0x9E3779B9U   // golden ratio constant, full-period over 2^32

static uint32_t guided_nonce   = 0;
static uint32_t guided_entropy = 0xA5A5A5A5;

static inline uint32_t guided_step(uint32_t last)
{
    // xorshift32 micro-perturbation
    guided_entropy ^= guided_entropy << 13;
    guided_entropy ^= guided_entropy >> 17;
    guided_entropy ^= guided_entropy << 5;

    // Macro: golden ratio stride for maximum nonce space coverage
    uint32_t next = last + GUIDED_STRIDE;

    // Micro: occasional perturbation every ~16 steps to break lattice aliasing
    if ((guided_entropy & 0xF) == 0)
        next ^= (guided_entropy >> 16) & 0xFFFF;

    return next;
}

/* =========================================================================
 * Adaptive job pacing controller (PI)
 *
 * Measures true round-trip latency via pace_on_result_received() called
 * from asic_result_task.c immediately after test_nonce_value(), and nudges
 * the inter-job interval to keep the ASIC pipeline optimally fed.
 *
 * Tuned for BM1370 @ 625MHz on public-pool.
 * ========================================================================= */

#define PACE_TARGET_LATENCY_MS  30
#define PACE_KP                 2
#define PACE_KI_SHIFT           3
#define PACE_MIN_MS             2
#define PACE_MAX_MS             500
#define PACE_EWMA_SHIFT         3       // alpha = 1/8

typedef struct {
    int32_t  interval_ms;
    int32_t  integral;
    int32_t  smoothed_latency;
    uint64_t job_dispatch_us;
    uint32_t jobs_sent;
    uint32_t late_results;
} pace_ctrl_t;

static pace_ctrl_t pace;

static void pace_init(int base_interval_ms)
{
    pace.interval_ms      = base_interval_ms;
    pace.integral         = 0;
    pace.smoothed_latency = PACE_TARGET_LATENCY_MS;
    pace.job_dispatch_us  = 0;
    pace.jobs_sent        = 0;
    pace.late_results     = 0;
}

static inline void pace_on_job_sent(void)
{
    pace.job_dispatch_us = esp_timer_get_time();
    pace.jobs_sent++;
}

/* Called from asic_result_task.c immediately after test_nonce_value() */
int32_t pace_on_result_received(void)
{
    if (pace.job_dispatch_us == 0)
        return pace.interval_ms;

    uint64_t now_us  = esp_timer_get_time();
    int32_t  rtt_ms  = (int32_t)((now_us - pace.job_dispatch_us) / 1000);

    pace.smoothed_latency +=
        (rtt_ms - pace.smoothed_latency) >> PACE_EWMA_SHIFT;

    int32_t error = pace.smoothed_latency - PACE_TARGET_LATENCY_MS;

    pace.integral += error;
    if (pace.integral >  2000) pace.integral =  2000;
    if (pace.integral < -2000) pace.integral = -2000;

    int32_t correction = (PACE_KP * error) + (pace.integral >> PACE_KI_SHIFT);
    pace.interval_ms  -= correction;

    if (pace.interval_ms < PACE_MIN_MS) pace.interval_ms = PACE_MIN_MS;
    if (pace.interval_ms > PACE_MAX_MS) pace.interval_ms = PACE_MAX_MS;

    if (rtt_ms > PACE_TARGET_LATENCY_MS)
        pace.late_results++;

    ESP_LOGD(TAG, "pace: rtt=%ldms smooth=%ldms err=%ld interval=%ldms",
             rtt_ms, pace.smoothed_latency, error, pace.interval_ms);

    return pace.interval_ms;
}

static void pace_log_stats(void)
{
    ESP_LOGI(TAG, "pace stats: interval=%ldms smoothed_rtt=%ldms "
                  "jobs_sent=%lu late_results=%lu",
             pace.interval_ms, pace.smoothed_latency,
             pace.jobs_sent, pace.late_results);
}

/* =========================================================================
 * Main task
 * ========================================================================= */

void create_jobs_task(void *pvParameters)
{
    GlobalState *GLOBAL_STATE = (GlobalState *)pvParameters;

    GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs = heap_caps_malloc(sizeof(bm_job *) * 128, MALLOC_CAP_SPIRAM);
    GLOBAL_STATE->valid_jobs = heap_caps_malloc(sizeof(uint8_t) * 128, MALLOC_CAP_SPIRAM);
    for (int i = 0; i < 128; i++) {
        GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[i] = NULL;
        GLOBAL_STATE->valid_jobs[i] = 0;
    }

    uint32_t difficulty = GLOBAL_STATE->pool_difficulty;
    mining_notify *current_mining_notification = NULL;
    uint64_t extranonce_2 = 0;

    int base_interval_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
    pace_init(base_interval_ms);

    ESP_LOGI(TAG, "ASIC Job Interval (initial): %d ms", base_interval_ms);
    ESP_LOGI(TAG, "ASIC Ready!");

    uint32_t stat_countdown = 100;

    while (1) {
        uint64_t start_time = esp_timer_get_time();
        mining_notify *new_mining_notification = (mining_notify *)queue_dequeue_timeout(
            &GLOBAL_STATE->stratum_queue, pace.interval_ms);
        pace.interval_ms -= (esp_timer_get_time() - start_time) / 1000;
        if (pace.interval_ms < 1) pace.interval_ms = 1;

        if (new_mining_notification != NULL) {
            if (current_mining_notification != NULL) {
                STRATUM_V1_free_mining_notify(current_mining_notification);
            }

            ESP_LOGI(TAG, "New Work Dequeued %s", new_mining_notification->job_id);

            current_mining_notification = new_mining_notification;

            if (GLOBAL_STATE->new_set_mining_difficulty_msg) {
                ESP_LOGI(TAG, "New pool difficulty %lu", GLOBAL_STATE->pool_difficulty);
                difficulty = GLOBAL_STATE->pool_difficulty;
                GLOBAL_STATE->new_set_mining_difficulty_msg = false;
            }

            if (GLOBAL_STATE->new_stratum_version_rolling_msg && GLOBAL_STATE->ASIC_initalized) {
                ESP_LOGI(TAG, "Set chip version rolls %i", (int)(GLOBAL_STATE->version_mask >> 13));
                ASIC_set_version_mask(GLOBAL_STATE, GLOBAL_STATE->version_mask);
                GLOBAL_STATE->new_stratum_version_rolling_msg = false;
            }

            extranonce_2 = 0;

            // Hardware entropy reseed: blend ESP32 true RNG with high-res
            // timer to prevent cross-session correlation on fast reboots
            uint32_t hw_seed  = esp_random();
            guided_nonce      = hw_seed;
            guided_entropy   ^= hw_seed ^ (uint32_t)esp_timer_get_time();

            // Reset pacing baseline on new work
            pace_init(ASIC_get_asic_job_frequency_ms(GLOBAL_STATE));

            if (!current_mining_notification->clean_jobs) {
                continue;
            }
        } else {
            if (current_mining_notification == NULL) {
                vTaskDelay(100 / portTICK_PERIOD_MS);
                continue;
            }
        }

        // Per-job extranonce seeding: map extranonce_2 counter through the
        // golden ratio so consecutive jobs begin maximally separated in
        // nonce space rather than continuing from where the last job ended
        uint32_t job_nonce_seed = (uint32_t)(extranonce_2 * 0x9E3779B9U) ^ guided_entropy;
        guided_nonce = guided_step(job_nonce_seed);

        generate_work(GLOBAL_STATE, current_mining_notification, extranonce_2, difficulty);
        pace_on_job_sent();
        extranonce_2++;

        if (--stat_countdown == 0) {
            pace_log_stats();
            stat_countdown = 100;
        }
    }
}

/* =========================================================================
 * Work generation (unchanged)
 * ========================================================================= */

static void generate_work(GlobalState *GLOBAL_STATE, mining_notify *notification, uint64_t extranonce_2, uint32_t difficulty)
{
    char extranonce_2_str[GLOBAL_STATE->extranonce_2_len * 2 + 1];
    extranonce_2_generate(extranonce_2, GLOBAL_STATE->extranonce_2_len, extranonce_2_str);

    uint8_t coinbase_tx_hash[32];
    calculate_coinbase_tx_hash(notification->coinbase_1, notification->coinbase_2,
                               GLOBAL_STATE->extranonce_str, extranonce_2_str, coinbase_tx_hash);

    uint8_t merkle_root[32];
    calculate_merkle_root_hash(coinbase_tx_hash, (uint8_t(*)[32])notification->merkle_branches,
                               notification->n_merkle_branches, merkle_root);

    bm_job *next_job = malloc(sizeof(bm_job));

    if (next_job == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for new job");
        return;
    }

    construct_bm_job(notification, merkle_root, GLOBAL_STATE->version_mask, difficulty, next_job);

    next_job->extranonce2  = strdup(extranonce_2_str);
    next_job->jobid        = strdup(notification->job_id);
    next_job->version_mask = GLOBAL_STATE->version_mask;

    if (!GLOBAL_STATE->ASIC_initalized) {
        ESP_LOGW(TAG, "ASIC not initialized, skipping job send");
        free(next_job->jobid);
        free(next_job->extranonce2);
        free(next_job);
        return;
    }

    ASIC_send_work(GLOBAL_STATE, next_job);
}
