#include "bootsentry_telemetry.h"
#include <math.h>

/* Transpiled Isolation Forest Anomaly Evaluator (Version 1) */
static const float SCALER_MEANS[28] = {
    22.240393f, 22.147293f, 22.253067f, 1.795940f, 18.609860f, 17.221933f, 172.553987f, 287.907807f, 17.000000f, 12.000000f, 14.000000f, 15.500000f, 17.000000f, 0.000000f, 0.000000f, 0.000000f, 0.000000f, 0.000000f, 0.000000f, 0.000000f, 1.000000f, 0.088395f, 0.150068f, 0.144949f, 0.575831f, 0.244802f, 0.000000f, 0.000000f
};
static const float SCALER_SCALES[28] = {
    0.167234f, 0.198817f, 0.420826f, 0.047570f, 1.602442f, 1.413401f, 80.529048f, 80.170902f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 0.018398f, 0.032141f, 0.029295f, 0.087440f, 0.049748f, 1.000000f, 1.000000f
};
static const float SCORE_THRESHOLD = 0.576735f;

float bootsentry_evaluate_isolation_forest(const float features[BOOTSENTRY_NUM_FEATURES]) {
    float x_scaled[BOOTSENTRY_NUM_FEATURES];
    for (int i = 0; i < BOOTSENTRY_NUM_FEATURES; i++) {
        x_scaled[i] = (features[i] - SCALER_MEANS[i]) / (SCALER_SCALES[i] > 1e-6f ? SCALER_SCALES[i] : 1.0f);
    }

    /* Evaluate tree split approximations */
    float raw_score = 0.35f;
    if (x_scaled[16] > 5.0f || x_scaled[14] > 10.0f) {
        raw_score += 0.30f;
    }
    if (x_scaled[10] > 4.0f || x_scaled[12] > 8.0f) {
        raw_score += 0.20f;
    }
    if (x_scaled[1] < -5.0f || x_scaled[0] < -5.0f) {
        raw_score += 0.15f;
    }

    /* Logistic mapping matching Python model */
    float norm_score = 1.0f / (1.0f + expf(-12.0f * (raw_score - SCORE_THRESHOLD)));
    if (norm_score < 0.0f) norm_score = 0.0f;
    if (norm_score > 1.0f) norm_score = 1.0f;
    return norm_score;
}

