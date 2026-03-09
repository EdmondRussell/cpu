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
 * Core-aware nonce strategy
 *
 * The BM1370 encodes the responding core directly into returned nonce bits:
 *   bits 31:25 — 7 bits — core_id    (128 cores)
 *   bits 24:17 — 8 bits — asic_nr
 *   bits 16:0  — 17 bits — nonce offset within core slice
 *
 * This means the 32-bit nonce space is partitioned into 128 core slices,
 * each 2^25 = 33,554,432 nonces wide. The starting_nonce sent in each job
 * determines which core slice gets priority.
 *
 * Strategy: rotate starting_nonce through all 128 core slices sequentially,
 * advancing one slice per job. This guarantees every core gets equal
 * coverage over time, rather than randomly clustering in a subset of slices.
 *
 * Within each slice, xorshift32 provides micro-perturbation to avoid
 * repeating the same offset within the slice across consecutive work units.
 *
 * On new work: randomise the starting slice from hardware entropy so
 * different sessions begin from different core rotation offsets.
 * ========================================================================= */

#define BM1370_CORE_BITS        7               // 128 cores
#define BM1370_CORE_COUNT       (1 << BM1370_CORE_BITS)   // 128
#define BM1370_SLICE_SHIFT      25              // nonce bits 31:25 = core id
#define BM1370_SLICE_SIZE       (1UL << BM1370_SLICE_SHIFT) // 33,554,432 nonces per slice

static uint8_t  core_rotation   = 0;           // current core slice index (0-127)
static uint32_t slice_entropy   = 0xA5A5A5A5;  // xorshift state for intra-slice offset

static inline uint32_t xorshift32(void)
{
    slice_entropy ^= slice_entropy << 13;
    slice_entropy ^= slice_entropy >> 17;
    slice_entropy ^= slice_entropy << 5;
    return slice_entropy;
}

static inline uint32_t core_aware_nonce(void)
{
    // Place starting nonce at the beginning of the current core's slice,
    // with a small entropy offset within the slice to avoid aliasing
    uint32_t slice_base   = (uint32_t)core_rotation << BM1370_SLICE_SHIFT;
    uint32_t intra_offset = xorshift32() & (BM1370_SLICE_SIZE - 1);

    // Advance to next core slice for next job
    core_rotation = (core_rotation + 1) & (BM1370_CORE_COUNT - 1);

    return slice_base | intra_offset;
}

/* =========================================================================
 * Adaptive job pacing controller (PI)
 *
 * Tuned for BM1370 @ 625MHz on public-pool.
 * Called from asic_result_task.c after test_nonce_value() for true RTT.
 * ========================================================================= */

#define PACE_TARGET_LATENCY_MS  30
#define PACE_KP                 2
#define PACE_KI_SHIFT           3
#define PACE_MIN_MS             2
#define PACE_MAX_MS             500
#define PACE_EWMA_SHIFT         3

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
                  "jobs_sent=%lu late_results=%lu core_rotation=%u",
             pace.interval_ms, pace.smoothed_latency,
             pace.jobs_sent, pace.late_results, core_rotation);
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

            // Randomise starting core rotation from hardware entropy so
            // each work unit begins from a different core slice
            uint32_t hw_seed  = esp_random();
            core_rotation     = hw_seed & (BM1370_CORE_COUNT - 1);
            slice_entropy    ^= hw_seed ^ (uint32_t)esp_timer_get_time();

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
 * Work generation
 *
 * Core-aware starting_nonce is injected here before sending to the ASIC.
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

    // Inject core-aware starting nonce — rotates through all 128 core
    // slices sequentially with entropy offset within each slice
    next_job->starting_nonce = core_aware_nonce();

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
