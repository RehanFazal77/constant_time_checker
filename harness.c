#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <oqs/oqs.h>

#define SAMPLES 100000
#define FIXED_LEN 32

static double get_time_sec() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static double* measure_timing(OQS_KEM *kem, const uint8_t *fixed_input, size_t len, size_t samples) {
    double *times = calloc(samples, sizeof(double));
    if (!times) { perror("calloc"); exit(1); }

    uint8_t pk[kem->length_public_key];
    uint8_t sk[kem->length_secret_key];
    uint8_t ct[kem->length_ciphertext];
    uint8_t ss_enc[kem->length_shared_secret];
    uint8_t ss_dec[kem->length_shared_secret];

    OQS_KEM_keypair(kem, pk, sk); // Initialize once

   for (size_t i = 0; i < SAMPLES; i++) {
    double start = get_time_sec();
    OQS_KEM_encaps(kem, ct, ss_enc, pk);
    OQS_KEM_decaps(kem, ss_dec, ct, sk);
    double end = get_time_sec();
    times[i] = end - start;
}
    return times;
}

static double compute_mean(double *data, size_t n) {
    double sum = 0.0;
    for (size_t i = 0; i < n; i++) sum += data[i];
    return sum / n;
}

static double compute_var(double *data, size_t n, double mean) {
    double var = 0.0;
    for (size_t i = 0; i < n; i++) var += (data[i] - mean) * (data[i] - mean);
    return var / (n - 1);
}

// Welch t-test
static double welch_t(double *x, size_t nx, double *y, size_t ny) {
    double mean_x = compute_mean(x, nx);
    double mean_y = compute_mean(y, ny);
    double var_x = compute_var(x, nx, mean_x);
    double var_y = compute_var(y, ny, mean_y);
    double denom = sqrt(var_x/nx + var_y/ny);
    return (denom > 0 ? fabs(mean_x - mean_y) / denom : 0.0);
}

int main(void) {
    // if (OQS_SUCCESS != OQS_init()) {
    //     fprintf(stderr, "OQS init failed\n");
    //     return 1;
    // }
    OQS_init();
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        fprintf(stderr, "OQS_KEM_new failed\n");
        return 1;
    }

    uint8_t fixed_input[FIXED_LEN] = {0};
    double *fixed_times = measure_timing(kem, fixed_input, FIXED_LEN, SAMPLES);
    double *random_times = measure_timing(kem, NULL, FIXED_LEN, SAMPLES);

    double t_score = welch_t(fixed_times, SAMPLES, random_times, SAMPLES);

    printf("Welch t-test score: %.6f\n", t_score);
    if (t_score > 5.0) {
        printf("❌  Potential timing difference detected!\n");
    } else {
        printf("✅  No significant timing difference detected.\n");
    }

    free(fixed_times);
    free(random_times);
    OQS_KEM_free(kem);
    OQS_destroy();

    return 0;
}
