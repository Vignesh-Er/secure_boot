#include "bootsentry_telemetry.h"
#include <math.h>

/* Transpiled Isolation Forest Anomaly Evaluator (8 Real Decision Trees) */
static const float SCALER_MEANS[28] = {
    25.397283f, 25.697058f, 26.378333f, 2.330783f, 20.818675f, 21.740658f, 176.074925f, 375.534317f, 205.190833f, 164.150833f, 184.670000f, 194.935000f, 205.190833f, 132.083333f, 0.000000f, 0.000000f, 89478.333333f, 0.000000f, 1571.221924f, 21.939453f, 71.613116f, 0.075025f, 0.126076f, 0.129545f, 0.466748f, 0.209614f, 209.637500f, 50.782500f
};
static const float SCALER_SCALES[28] = {
    1.785856f, 2.649333f, 2.503838f, 0.207825f, 1.741738f, 2.712524f, 42.998000f, 45.417655f, 0.055746f, 0.043100f, 0.045461f, 0.051720f, 0.055746f, 52.418919f, 1.000000f, 1.000000f, 17.240134f, 1.000000f, 0.013151f, 0.020053f, 0.064910f, 0.010914f, 0.019593f, 0.014991f, 0.085222f, 0.029944f, 46.638460f, 22.211658f
};
static const float SCORE_THRESHOLD = 0.546972f;
static const int NUM_EXPORTED_TREES = 8;

static float evaluate_tree_0(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[1] <= 1.152715f) {
        if (x[27] <= 1.283407f) {
            if (x[25] <= -0.898664f) {
                if (x[7] <= 1.460883f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[16] <= -1.366357f) {
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
    if (x[2] <= 0.564790f) {
        if (x[2] <= -0.750335f) {
            if (x[23] <= -0.136696f) {
                return (float)3;
            } else {
                if (x[7] <= -1.089578f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[10] <= -0.132620f) {
                if (x[27] <= -0.002187f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[5] <= -0.672364f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[27] <= 1.231177f) {
            if (x[20] <= -0.503392f) {
                return (float)3;
            } else {
                if (x[25] <= -0.804132f) {
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
    if (x[18] <= -0.377344f) {
        if (x[4] <= -1.331544f) {
            return (float)2;
        } else {
            if (x[13] <= -0.751161f) {
                return (float)3;
            } else {
                if (x[26] <= -0.614339f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[1] <= 0.773119f) {
            if (x[5] <= 0.016628f) {
                if (x[10] <= -2.736829f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[25] <= 0.317506f) {
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

static float evaluate_tree_3(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= -0.056179f) {
        if (x[16] <= -1.873511f) {
            return (float)2;
        } else {
            if (x[24] <= 0.108058f) {
                if (x[5] <= -0.656724f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[3] <= -1.084515f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[25] <= 1.081004f) {
            if (x[23] <= -0.978527f) {
                return (float)3;
            } else {
                if (x[10] <= 0.208832f) {
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
    if (x[21] <= -0.360766f) {
        if (x[10] <= 0.321702f) {
            if (x[2] <= -0.251173f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[13] <= 1.644967f) {
                if (x[24] <= 1.228967f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[1] <= 2.683721f) {
            if (x[26] <= 0.214294f) {
                if (x[22] <= 0.200444f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            return (float)2;
        }
    }
}

static float evaluate_tree_5(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[27] <= 0.605626f) {
        if (x[26] <= -0.497775f) {
            if (x[7] <= 0.363261f) {
                if (x[27] <= 0.515784f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[12] <= -0.401848f) {
                return (float)3;
            } else {
                if (x[2] <= -0.554602f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        return (float)1;
    }
}

static float evaluate_tree_6(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[26] <= -0.894650f) {
        return (float)1;
    } else {
        if (x[24] <= 0.217688f) {
            if (x[7] <= -1.082765f) {
                return (float)3;
            } else {
                if (x[24] <= -0.902875f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[7] <= -1.685380f) {
                return (float)3;
            } else {
                if (x[24] <= 0.601167f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_7(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[5] <= 0.305756f) {
        if (x[20] <= -0.029553f) {
            if (x[2] <= -1.096144f) {
                if (x[6] <= -0.315532f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[0] <= -0.246739f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[2] <= 0.088672f) {
                return (float)3;
            } else {
                if (x[20] <= 0.910453f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[10] <= 0.644815f) {
            return (float)2;
        } else {
            if (x[24] <= -0.369757f) {
                return (float)3;
            } else {
                if (x[5] <= 1.289553f) {
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

