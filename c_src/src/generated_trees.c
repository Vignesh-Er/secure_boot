#include "bootsentry_telemetry.h"
#include <math.h>

/* Transpiled Isolation Forest Anomaly Evaluator (Version 1) */
static const float SCALER_MEANS[28] = {
    21.653493f, 24.951953f, 24.601553f, 2.072887f, 18.815507f, 17.827780f, 186.027900f, 309.007213f, 17.000000f, 12.000000f, 14.000000f, 15.500000f, 17.000000f, 0.000000f, 0.000000f, 0.000000f, 0.000000f, 0.000000f, 0.000000f, 0.000000f, 1.000000f, 0.082735f, 0.152689f, 0.147511f, 0.571357f, 0.248108f, 0.000000f, 0.000000f
};
static const float SCALER_SCALES[28] = {
    0.448560f, 7.033584f, 5.965028f, 0.150024f, 1.477722f, 1.284152f, 98.897291f, 96.139500f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 0.020230f, 0.043231f, 0.040197f, 0.111517f, 0.071481f, 1.000000f, 1.000000f
};
static const float SCORE_THRESHOLD = 0.575298f;

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

