#include "bootsentry_telemetry.h"
#include <math.h>

/* Transpiled Isolation Forest Anomaly Evaluator (8 Real Decision Trees) */
static const float SCALER_MEANS[28] = {
    26.590442f, 25.023200f, 24.955400f, 2.532367f, 23.356383f, 21.504992f, 186.354558f, 371.949117f, 208.950000f, 167.160000f, 188.060000f, 198.510000f, 208.950000f, 132.916667f, 0.000000f, 0.000000f, 91760.000000f, 0.000000f, 1571.217204f, 21.931152f, 71.640038f, 0.080717f, 0.132353f, 0.128492f, 0.491329f, 0.211431f, 225.259167f, 45.574167f
};
static const float SCALER_SCALES[28] = {
    3.096041f, 1.335115f, 0.583179f, 0.494166f, 8.482670f, 2.011911f, 58.530231f, 60.127068f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 44.602799f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 0.016931f, 0.024944f, 0.080828f, 0.017794f, 0.023976f, 0.022858f, 0.091796f, 0.036328f, 69.426833f, 16.210908f
};
static const float SCORE_THRESHOLD = 0.555133f;
static const int NUM_EXPORTED_TREES = 8;

static float evaluate_tree_0(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[1] <= 1.109250f) {
        if (x[27] <= 1.412952f) {
            if (x[25] <= -1.154848f) {
                return (float)3;
            } else {
                if (x[7] <= 0.188646f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            return (float)2;
        }
    } else {
        return (float)1;
    }
}

static float evaluate_tree_1(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= 0.133045f) {
        if (x[2] <= -1.161421f) {
            if (x[23] <= -0.705811f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[7] <= -0.624161f) {
                if (x[21] <= 0.670937f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[20] <= -0.534406f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[20] <= 0.078829f) {
            if (x[21] <= -0.848132f) {
                if (x[1] <= -0.361517f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[23] <= 0.347337f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_2(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[18] <= -0.492831f) {
        if (x[4] <= -0.334491f) {
            return (float)2;
        } else {
            if (x[13] <= -0.831759f) {
                if (x[26] <= -0.684630f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[1] <= -0.292057f) {
            if (x[5] <= -0.475203f) {
                if (x[1] <= -0.641460f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[27] <= -1.083268f) {
                return (float)3;
            } else {
                if (x[5] <= 0.334055f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_3(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= -0.570632f) {
        if (x[20] <= 0.149259f) {
            return (float)2;
        } else {
            if (x[3] <= -0.406066f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[20] <= -0.465040f) {
            if (x[25] <= 0.262180f) {
                if (x[23] <= -0.901642f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[18] <= 0.317595f) {
                if (x[1] <= -0.321650f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[1] <= -0.578410f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_4(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[21] <= -0.375863f) {
        if (x[22] <= -1.195798f) {
            if (x[23] <= -1.556732f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[4] <= 1.425392f) {
                if (x[21] <= -0.776245f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[6] <= -0.679475f) {
            if (x[0] <= -0.010774f) {
                return (float)3;
            } else {
                if (x[4] <= -0.026185f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[23] <= 0.395563f) {
                if (x[23] <= 0.185233f) {
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
    if (x[27] <= 0.793836f) {
        if (x[26] <= -0.507048f) {
            if (x[7] <= -0.421231f) {
                if (x[0] <= -0.334679f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[2] <= -0.911650f) {
                return (float)3;
            } else {
                if (x[2] <= 1.577172f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[13] <= -0.028495f) {
            if (x[3] <= 1.440788f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            return (float)2;
        }
    }
}

static float evaluate_tree_6(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[26] <= -0.995146f) {
        if (x[24] <= -0.637876f) {
            return (float)2;
        } else {
            return (float)2;
        }
    } else {
        if (x[7] <= -0.727849f) {
            return (float)2;
        } else {
            if (x[24] <= -0.318878f) {
                if (x[7] <= -0.458356f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[24] <= 0.031686f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_7(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[5] <= 0.021704f) {
        if (x[20] <= -0.697203f) {
            return (float)2;
        } else {
            if (x[2] <= -1.648241f) {
                return (float)3;
            } else {
                if (x[6] <= -0.196978f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[0] <= 2.230496f) {
            if (x[2] <= 0.112299f) {
                return (float)3;
            } else {
                if (x[20] <= -0.219570f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            return (float)2;
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

