#include "bootsentry_telemetry.h"
#include <math.h>

/* Transpiled Isolation Forest Anomaly Evaluator (8 Real Decision Trees) */
static const float SCALER_MEANS[28] = {
    35.786808f, 32.922233f, 33.621608f, 2.778467f, 34.636975f, 24.999508f, 311.570858f, 544.476750f, 205.166667f, 164.135833f, 184.651667f, 194.910833f, 205.166667f, 182.500000f, 0.000000f, 0.000000f, 90512.500000f, 0.000000f, 1571.216064f, 21.932292f, 71.636274f, 0.075551f, 0.137572f, 0.118240f, 0.538759f, 0.202753f, 393.228333f, 36.457500f
};
static const float SCALER_SCALES[28] = {
    6.746664f, 6.424490f, 3.426707f, 0.258484f, 24.845136f, 3.203537f, 177.169958f, 185.670394f, 0.034960f, 0.026286f, 0.030231f, 0.030946f, 0.034960f, 103.772588f, 1.000000f, 1.000000f, 9.682458f, 1.000000f, 0.018279f, 0.026223f, 0.084918f, 0.018755f, 0.067462f, 0.034811f, 0.120121f, 0.051100f, 177.559207f, 25.780608f
};
static const float SCORE_THRESHOLD = 0.564787f;
static const int NUM_EXPORTED_TREES = 8;

static float evaluate_tree_0(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[1] <= -0.013256f) {
        if (x[27] <= 0.123786f) {
            if (x[25] <= -1.225363f) {
                if (x[7] <= 2.083753f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[16] <= -0.134853f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            return (float)2;
        }
    } else {
        if (x[21] <= -0.062520f) {
            return (float)2;
        } else {
            if (x[5] <= -1.299130f) {
                return (float)3;
            } else {
                if (x[24] <= -0.269658f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_1(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= -0.021058f) {
        if (x[2] <= -1.270210f) {
            if (x[23] <= -0.588912f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[7] <= -0.033493f) {
                if (x[10] <= -0.254565f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[27] <= -0.666507f) {
            return (float)2;
        } else {
            if (x[8] <= -1.031891f) {
                return (float)3;
            } else {
                if (x[10] <= 0.071782f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_2(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[18] <= -0.424249f) {
        if (x[4] <= -0.389770f) {
            if (x[13] <= 0.749799f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[12] <= 0.527926f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[8] <= -1.630875f) {
            return (float)2;
        } else {
            if (x[22] <= 1.478518f) {
                if (x[3] <= -0.026914f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_3(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= -0.736365f) {
        if (x[16] <= -0.360607f) {
            return (float)2;
        } else {
            return (float)2;
        }
    } else {
        if (x[24] <= 0.048052f) {
            if (x[5] <= 0.305024f) {
                if (x[3] <= -0.316472f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[25] <= 1.466977f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[23] <= -1.557985f) {
                return (float)3;
            } else {
                if (x[10] <= -0.283757f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_4(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[21] <= -0.603548f) {
        if (x[10] <= 0.021762f) {
            if (x[2] <= -0.020309f) {
                return (float)3;
            } else {
                if (x[13] <= 1.457044f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            return (float)2;
        }
    } else {
        if (x[24] <= -0.095244f) {
            if (x[1] <= 1.131584f) {
                if (x[26] <= -0.653644f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[22] <= 0.860404f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[0] <= 0.691863f) {
                if (x[21] <= -0.013400f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_5(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[27] <= 1.077436f) {
        if (x[26] <= -0.468818f) {
            if (x[7] <= -0.452764f) {
                if (x[27] <= -0.212120f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[12] <= -1.562377f) {
                return (float)3;
            } else {
                if (x[2] <= -1.172802f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[2] <= 1.415414f) {
            return (float)2;
        } else {
            return (float)2;
        }
    }
}

static float evaluate_tree_6(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[26] <= -0.565829f) {
        if (x[24] <= -1.068240f) {
            if (x[7] <= -0.813423f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[24] <= -0.769564f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[7] <= -0.626124f) {
            if (x[12] <= -0.063866f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[21] <= -1.547992f) {
                return (float)3;
            } else {
                if (x[23] <= -0.631716f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_7(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[5] <= -0.116203f) {
        if (x[20] <= 0.193311f) {
            if (x[2] <= -1.810038f) {
                return (float)3;
            } else {
                if (x[6] <= 0.454119f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[0] <= 0.740669f) {
                return (float)3;
            } else {
                if (x[2] <= -0.120693f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[20] <= -0.671624f) {
            return (float)2;
        } else {
            if (x[10] <= 0.914537f) {
                if (x[24] <= -0.823475f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[5] <= 1.195812f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

float bootsentry_evaluate_isolation_forest(const float features[BOOTSENTRY_NUM_FEATURES]) {
    float x_scaled[BOOTSENTRY_NUM_FEATURES];
    for (int i = 0; i < BOOTSENTRY_NUM_FEATURES; i++) {
        x_scaled[i] = (features[i] - SCALER_MEANS[i]) / (SCALER_SCALES[i] > 1e-6f ? SCALER_SCALES[i] : 1.0f);
    }

    float total_path_length = 0.0f;
    total_path_length += evaluate_tree_0(x_scaled);
    total_path_length += evaluate_tree_1(x_scaled);
    total_path_length += evaluate_tree_2(x_scaled);
    total_path_length += evaluate_tree_3(x_scaled);
    total_path_length += evaluate_tree_4(x_scaled);
    total_path_length += evaluate_tree_5(x_scaled);
    total_path_length += evaluate_tree_6(x_scaled);
    total_path_length += evaluate_tree_7(x_scaled);
    float avg_path_length = total_path_length / (float)NUM_EXPORTED_TREES;
    /* Standard Isolation Forest average path length normalizer c(256) */
    float c_n = 2.0f * (logf(255.0f) + 0.5772156649f) - (2.0f * 255.0f / 256.0f);
    float raw_score = powf(2.0f, -avg_path_length / c_n);

    /* Logistic mapping matching Python model */
    float norm_score = 1.0f / (1.0f + expf(-12.0f * (raw_score - SCORE_THRESHOLD)));
    if (norm_score < 0.0f) norm_score = 0.0f;
    if (norm_score > 1.0f) norm_score = 1.0f;
    return norm_score;
}

