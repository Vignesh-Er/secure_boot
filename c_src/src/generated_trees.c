#include "bootsentry_telemetry.h"
#include <math.h>

/* Transpiled Isolation Forest Anomaly Evaluator (8 Real Decision Trees) */
static const float SCALER_MEANS[28] = {
    29.269342f, 30.153200f, 28.645033f, 2.652325f, 28.764850f, 27.747742f, 170.166492f, 383.962192f, 205.940000f, 164.746667f, 185.346667f, 195.640000f, 205.940000f, 123.750000f, 0.000000f, 0.000000f, 91311.666667f, 0.000000f, 1571.393962f, 21.960938f, 71.550877f, 0.084839f, 0.156787f, 0.149631f, 0.435903f, 0.234251f, 231.770000f, 39.061667f
};
static const float SCALER_SCALES[28] = {
    5.893231f, 6.977361f, 5.407717f, 0.325900f, 19.457446f, 18.168545f, 56.180607f, 57.240340f, 0.028284f, 0.023570f, 0.023570f, 0.028284f, 0.028284f, 58.206708f, 1.000000f, 1.000000f, 9.860133f, 1.000000f, 0.011735f, 0.017013f, 0.054896f, 0.019950f, 0.056899f, 0.050407f, 0.095068f, 0.046507f, 47.235259f, 22.553034f
};
static const float SCORE_THRESHOLD = 0.537957f;
static const int NUM_EXPORTED_TREES = 8;

static float evaluate_tree_0(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[1] <= 0.329208f) {
        if (x[27] <= 1.197548f) {
            if (x[25] <= -1.072188f) {
                if (x[7] <= 1.210728f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[16] <= -0.345595f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            return (float)2;
        }
    } else {
        if (x[21] <= -0.504357f) {
            if (x[5] <= -0.046180f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[24] <= -0.404762f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_1(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= 0.607865f) {
        if (x[2] <= -0.525119f) {
            if (x[23] <= 0.624038f) {
                if (x[7] <= 0.483848f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[21] <= -0.015931f) {
                if (x[20] <= 0.001282f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[20] <= 0.488462f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[21] <= -0.401260f) {
            return (float)2;
        } else {
            return (float)2;
        }
    }
}

static float evaluate_tree_2(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[18] <= 0.161012f) {
        if (x[4] <= -0.535371f) {
            return (float)2;
        } else {
            if (x[13] <= 0.099554f) {
                return (float)3;
            } else {
                if (x[12] <= 0.888236f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[8] <= -0.502383f) {
            if (x[22] <= 1.877792f) {
                if (x[3] <= 0.796870f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[5] <= -0.141504f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_3(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= -0.001309f) {
        if (x[16] <= -0.641176f) {
            if (x[24] <= 0.285261f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[5] <= 0.032765f) {
                if (x[3] <= -1.508148f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[25] <= 1.040661f) {
            if (x[23] <= -0.874536f) {
                return (float)3;
            } else {
                if (x[10] <= 0.544201f) {
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

static float evaluate_tree_4(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[21] <= 0.016530f) {
        if (x[10] <= 0.761897f) {
            if (x[2] <= -0.392024f) {
                return (float)3;
            } else {
                if (x[13] <= 1.467277f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[24] <= 1.052974f) {
                if (x[1] <= 1.455083f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[26] <= 0.126549f) {
            if (x[22] <= 0.085884f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[0] <= 1.047560f) {
                return (float)3;
            } else {
                if (x[21] <= 0.811376f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_5(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[27] <= 0.641316f) {
        if (x[26] <= -1.252446f) {
            if (x[7] <= -1.353352f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[27] <= 0.329298f) {
                if (x[0] <= 1.079697f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[19] <= -0.320659f) {
            if (x[23] <= 2.500301f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[1] <= -0.890671f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_6(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[26] <= -1.324482f) {
        return (float)1;
    } else {
        if (x[24] <= 0.971991f) {
            if (x[7] <= -1.567143f) {
                return (float)3;
            } else {
                if (x[24] <= -0.436299f) {
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

static float evaluate_tree_7(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[5] <= 0.866368f) {
        if (x[20] <= -0.502996f) {
            if (x[2] <= -0.745753f) {
                return (float)3;
            } else {
                if (x[6] <= -0.883526f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[0] <= 1.656454f) {
                if (x[2] <= -0.921020f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        return (float)1;
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

