#include "bootsentry_telemetry.h"
#include <math.h>

/* Transpiled Isolation Forest Anomaly Evaluator (8 Real Decision Trees) */
static const float SCALER_MEANS[28] = {
    19.252525f, 18.271792f, 16.475700f, 1.545175f, 16.051800f, 17.664425f, 152.703342f, 252.260942f, 205.790833f, 164.630833f, 185.210833f, 195.500833f, 205.790833f, 54.166667f, 0.000000f, 0.000000f, 90130.000000f, 0.000000f, 1571.220215f, 21.935628f, 71.625519f, 0.088211f, 0.143864f, 0.141897f, 0.582776f, 0.226431f, 183.595000f, 32.552500f
};
static const float SCALER_SCALES[28] = {
    3.753005f, 3.908468f, 2.837398f, 0.207469f, 2.698068f, 2.274395f, 64.615143f, 62.718393f, 0.002764f, 0.002764f, 0.002764f, 0.002764f, 0.002764f, 53.222541f, 1.000000f, 1.000000f, 1.000000f, 1.000000f, 0.011729f, 0.018934f, 0.061294f, 0.028873f, 0.038600f, 0.029568f, 0.098004f, 0.058022f, 60.890888f, 16.212782f
};
static const float SCORE_THRESHOLD = 0.577695f;
static const int NUM_EXPORTED_TREES = 8;

static float evaluate_tree_0(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[1] <= 0.712114f) {
        if (x[27] <= 0.586306f) {
            if (x[25] <= -1.140448f) {
                if (x[7] <= 1.731931f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[27] <= -0.802560f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[26] <= 0.417291f) {
                if (x[5] <= 0.514177f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[13] <= -0.336788f) {
            return (float)2;
        } else {
            if (x[19] <= 0.222922f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_1(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= 1.248156f) {
        if (x[2] <= -0.172825f) {
            if (x[23] <= -0.531084f) {
                if (x[7] <= 1.552163f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[1] <= -0.765916f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[5] <= -0.328615f) {
                return (float)3;
            } else {
                if (x[1] <= 1.404162f) {
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

static float evaluate_tree_2(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[18] <= 0.267924f) {
        if (x[4] <= -1.014520f) {
            return (float)2;
        } else {
            if (x[13] <= 0.517132f) {
                if (x[26] <= -0.000262f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[1] <= -0.040871f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[5] <= 0.116221f) {
            return (float)2;
        } else {
            if (x[10] <= -0.175281f) {
                if (x[25] <= -0.711059f) {
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
    if (x[2] <= 0.508409f) {
        if (x[20] <= -0.460267f) {
            if (x[8] <= 0.018296f) {
                if (x[13] <= -0.612837f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[25] <= 1.336873f) {
                if (x[23] <= -1.570754f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[18] <= 0.089339f) {
            return (float)2;
        } else {
            return (float)2;
        }
    }
}

static float evaluate_tree_4(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[21] <= -0.359739f) {
        if (x[10] <= 2.204030f) {
            if (x[2] <= -0.646708f) {
                return (float)3;
            } else {
                if (x[13] <= 0.781853f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            return (float)2;
        }
    } else {
        if (x[24] <= -0.807081f) {
            if (x[1] <= 0.768387f) {
                if (x[26] <= -0.772743f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[22] <= 0.258113f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_5(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[27] <= 0.633480f) {
        if (x[26] <= -0.860587f) {
            if (x[7] <= -0.980461f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[27] <= -0.096442f) {
                if (x[0] <= -0.560882f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[19] <= -0.350887f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[23] <= 1.071434f) {
            if (x[1] <= 0.160780f) {
                if (x[3] <= 0.804391f) {
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

static float evaluate_tree_6(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[26] <= -0.963456f) {
        if (x[24] <= -1.107188f) {
            return (float)2;
        } else {
            if (x[7] <= -0.944573f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[24] <= 0.002073f) {
            if (x[7] <= -0.854640f) {
                return (float)3;
            } else {
                if (x[24] <= -0.857633f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[23] <= -1.028093f) {
                if (x[10] <= 0.616940f) {
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

static float evaluate_tree_7(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[5] <= -0.074827f) {
        if (x[20] <= -0.249410f) {
            if (x[2] <= -0.731318f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[6] <= -0.406867f) {
                if (x[0] <= 1.597151f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[2] <= -0.352363f) {
            return (float)2;
        } else {
            if (x[20] <= -0.955396f) {
                return (float)3;
            } else {
                if (x[2] <= 0.224820f) {
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

