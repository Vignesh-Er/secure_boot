#include "bootsentry_telemetry.h"
#include <math.h>

/* Transpiled Isolation Forest Anomaly Evaluator (8 Real Decision Trees) */
static const float SCALER_MEANS[28] = {
    30.998292f, 32.568642f, 31.043000f, 2.471383f, 23.950417f, 23.047208f, 204.324558f, 416.204517f, 205.743333f, 164.595000f, 185.167500f, 195.455833f, 205.743333f, 210.416667f, 0.000000f, 0.000000f, 91712.500000f, 0.000000f, 1571.225098f, 21.944092f, 71.598132f, 0.083946f, 0.142007f, 0.134612f, 0.484043f, 0.236029f, 268.227500f, 42.969167f
};
static const float SCALER_SCALES[28] = {
    5.106623f, 6.942992f, 4.813788f, 0.357335f, 4.353770f, 3.109966f, 66.249141f, 89.601742f, 0.067495f, 0.053774f, 0.062600f, 0.064866f, 0.067495f, 68.540084f, 1.000000f, 1.000000f, 20.866640f, 1.000000f, 0.013905f, 0.021474f, 0.069494f, 0.021068f, 0.040903f, 0.029270f, 0.071856f, 0.058008f, 75.699415f, 22.212538f
};
static const float SCORE_THRESHOLD = 0.560214f;
static const int NUM_EXPORTED_TREES = 8;

static float evaluate_tree_0(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[1] <= 0.084949f) {
        if (x[27] <= 1.852117f) {
            if (x[25] <= -0.754960f) {
                if (x[7] <= 0.119664f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[16] <= -0.286673f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            return (float)2;
        }
    } else {
        if (x[21] <= -1.601754f) {
            return (float)2;
        } else {
            if (x[5] <= -0.976405f) {
                return (float)3;
            } else {
                if (x[24] <= -0.112079f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_1(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= 0.055618f) {
        if (x[2] <= -1.125674f) {
            if (x[23] <= -0.918416f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[7] <= 0.075046f) {
                if (x[10] <= -0.542645f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[27] <= 0.166639f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[8] <= -0.805795f) {
            if (x[10] <= -1.329043f) {
                return (float)3;
            } else {
                if (x[6] <= 2.328585f) {
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

static float evaluate_tree_2(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[18] <= -0.554460f) {
        if (x[4] <= -1.215298f) {
            return (float)2;
        } else {
            if (x[13] <= -0.865831f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[12] <= 0.362004f) {
            if (x[20] <= -0.034489f) {
                if (x[3] <= 0.215656f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[5] <= -0.769525f) {
                if (x[27] <= 0.547870f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[3] <= -0.261456f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_3(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= -0.592940f) {
        if (x[16] <= -0.566015f) {
            return (float)2;
        } else {
            if (x[24] <= 0.970493f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[5] <= -0.874797f) {
            return (float)2;
        } else {
            if (x[3] <= -0.678117f) {
                return (float)3;
            } else {
                if (x[25] <= 1.716300f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_4(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[21] <= -0.555840f) {
        if (x[10] <= 0.249192f) {
            return (float)2;
        } else {
            if (x[2] <= -1.695342f) {
                return (float)3;
            } else {
                if (x[13] <= 1.819560f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[24] <= -0.610044f) {
            if (x[1] <= 1.022019f) {
                if (x[26] <= -0.946843f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[22] <= -0.025090f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[0] <= 0.330832f) {
                return (float)3;
            } else {
                if (x[21] <= 0.537313f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_5(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[27] <= 1.178747f) {
        if (x[26] <= -0.658211f) {
            if (x[7] <= -0.895648f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[27] <= 0.164306f) {
                if (x[12] <= -0.854497f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[2] <= -1.137671f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[2] <= -0.298025f) {
            return (float)2;
        } else {
            return (float)2;
        }
    }
}

static float evaluate_tree_6(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[26] <= -0.775431f) {
        if (x[24] <= -0.799875f) {
            if (x[7] <= -0.795216f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            return (float)2;
        }
    } else {
        if (x[24] <= -0.151922f) {
            if (x[7] <= -0.669517f) {
                return (float)3;
            } else {
                if (x[12] <= -0.302145f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[21] <= -1.620561f) {
                return (float)3;
            } else {
                if (x[23] <= 0.741188f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_7(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[5] <= -0.418955f) {
        if (x[20] <= -0.239344f) {
            if (x[2] <= -1.534461f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[6] <= -0.514259f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[0] <= 1.099924f) {
            if (x[2] <= -0.864166f) {
                return (float)3;
            } else {
                if (x[20] <= -0.442678f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[10] <= -1.084854f) {
                return (float)3;
            } else {
                if (x[24] <= -0.609405f) {
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

