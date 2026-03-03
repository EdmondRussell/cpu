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
 * Guided nonce progression
 *
 * Lightweight deterministic perturbation model. Keeps firmware size small
 * and ASIC fed efficiently without expensive floating point or heap use.
 * Re-seeded from hardware entropy on every new work notification.
 * ========================================================================= */

static uint32_t guided_nonce   = 0;
static uint32_t guided_entropy = 0xA5A5A5A5;

static inline uint32_t guided_step(uint32_t last)
{
    // xorshift32 entropy mix
    guided_entropy ^= guided_entropy << 13;
    guided_entropy ^= guided_entropy >> 17;
    guided_entropy ^= guided_entropy << 5;

    uint32_t e = guided_entropy;

    uint32_t perturb =
        ((e & 0xFF) << 1) +
        ((e >> 8)  & 0x7F) +
        ((e >> 16) & 0x3F);

    perturb |= 1; // always odd, guarantees forward progress

    uint32_t next = last + perturb;

    if (next <= last)   // overflow guard
        next = last + 1;

    return next;
}

/* =========================================================================
 * Adaptive job pacing controller
 *
 * Measures round-trip latency (job dispatched -> result received) and nudges
 * the inter-job interval to keep the ASIC's internal FIFO at the target
 * depth - not starved, not flooded with stale work.
 *
 * Uses a lightweight PI controller (no derivative term needed at this
 * timescale). All arithmetic is integer; no floats, no heap.
 *
 * Tuning knobs:
 *   PACE_TARGET_LATENCY_MS  - ideal round-trip time in ms
 *   PACE_KP                 - proportional gain (ms correction per ms error)
 *   PACE_KI_SHIFT           - integral gain as right-shift (divide by 2^n)
 *   PACE_MIN_MS / MAX_MS    - hard clamp on output interval
 * ========================================================================= */

#define PACE_TARGET_LATENCY_MS  80      // tune to your chip's FIFO depth
#define PACE_KP                 1       // 1:1 proportional correction
#define PACE_KI_SHIFT           4       // integral gain = 1/16
#define PACE_MIN_MS             5
#define PACE_MAX_MS             500
#define PACE_EWMA_SHIFT         3       // EWMA smoothing: alpha = 1/8

typedef struct {
    int32_t  interval_ms;       // current controlled output
    int32_t  integral;          // accumulated I-term
    int32_t  smoothed_latency;  // EWMA of measured round-trip ms
    uint64_t job_dispatch_us;   // timestamp of last job send
    uint32_t jobs_sent;         // lifetime counter for telemetry
    uint32_t late_results;      // results that arrived after target latency
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

/* Call immediately after dispatching a job. */
static inline void pace_on_job_sent(void)
{
    pace.job_dispatch_us = esp_timer_get_time();
    pace.jobs_sent++;
}

/* Call when a result arrives. Returns updated interval_ms.
 * Ideally called from your ASIC result handler for true RTT;
 * calling it here gives a conservative loop-latency approximation. */
static int32_t pace_on_result_received(void)
{
    if (pace.job_dispatch_us == 0)
        return pace.interval_ms;

    uint64_t now_us  = esp_timer_get_time();
    int32_t  rtt_ms  = (int32_t)((now_us - pace.job_dispatch_us) / 1000);

    // EWMA smooth the raw RTT measurement
    pace.smoothed_latency +=
        (rtt_ms - pace.smoothed_latency) >> PACE_EWMA_SHIFT;

    int32_t error = pace.smoothed_latency - PACE_TARGET_LATENCY_MS;

    // Clamp integral to prevent wind-up (+/- 2 seconds worth)
    pace.integral += error;
    if (pace.integral >  2000) pace.integral =  2000;
    if (pace.integral < -2000) pace.integral = -2000;

    int32_t correction = (PACE_KP * error) +
                         (pace.integral >> PACE_KI_SHIFT);

    pace.interval_ms -= correction;

    if (pace.interval_ms < PACE_MIN_MS) pace.interval_ms = PACE_MIN_MS;
    if (pace.interval_ms > PACE_MAX_MS) pace.interval_ms = PACE_MAX_MS;

    if (rtt_ms > PACE_TARGET_LATENCY_MS)
        pace.late_results++;

    ESP_LOGD(TAG, "pace: rtt=%ldms smooth=%ldms err=%ld interval=%ldms late=%lu",
             rtt_ms, pace.smoothed_latency, error,
             pace.interval_ms, pace.late_results);

    return pace.interval_ms;
}

/* Periodic telemetry */
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

    // Initialize ASIC task module (moved from ASIC_task)
    GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs = heap_caps_malloc(sizeof(bm_job *) * 128, MALLOC_CAP_SPIRAM);
    GLOBAL_STATE->valid_jobs = heap_caps_malloc(sizeof(uint8_t) * 128, MALLOC_CAP_SPIRAM);
    for (int i = 0; i < 128; i++) {
        GLOBAL_STATE->ASIC_TASK_MODULE.active_jobs[i] = NULL;
        GLOBAL_STATE->valid_jobs[i] = 0;
    }

    uint32_t difficulty = GLOBAL_STATE->pool_difficulty;
    mining_notify *current_mining_notification = NULL;
    uint64_t extranonce_2 = 0;

    // Initialise pacing controller from hardware-derived base interval
    int base_interval_ms = ASIC_get_asic_job_frequency_ms(GLOBAL_STATE);
    pace_init(base_interval_ms);

    ESP_LOGI(TAG, "ASIC Job Interval (initial): %d ms", base_interval_ms);
    ESP_LOGI(TAG, "ASIC Ready!");

    uint32_t stat_countdown = 100; // log pace stats every ~100 jobs

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

            // Re-seed guided nonce from hardware entropy on new work
            guided_nonce    = esp_random();
            guided_entropy ^= guided_nonce;

            // New work resets the pacing baseline - don't penalise the
            // controller for the pool-side latency spike during job change
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

        // Dispatch job and record send timestamp for RTT measurement
        generate_work(GLOBAL_STATE, current_mining_notification, extranonce_2, difficulty);
        pace_on_job_sent();
        extranonce_2++;

        // Advance guided nonce; wrap safely back to hardware entropy
        guided_nonce = guided_step(guided_nonce);
        if (guided_nonce > 0xFFFFFF00)
            guided_nonce = esp_random();

        // Update pacing interval from latest RTT measurement
        pace_on_result_received();

        // Periodic telemetry
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
