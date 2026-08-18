#include "bootsentry_telemetry.h"
#include <math.h>

/* Transpiled Isolation Forest Anomaly Evaluator (8 Real Decision Trees) */
static const float SCALER_MEANS[28] = {
    26.815727f, 25.885020f, 26.618100f, 2.320713f, 33.643487f, 21.409627f, 224.266073f, 422.149160f, 204.906000f, 163.918667f, 184.416000f, 194.656667f, 204.906000f, 168.000000f, 0.000000f, 0.000000f, 91679.333333f, 0.000000f, 1676.691536f, 21.934310f, 76.438136f, 0.073287f, 0.144712f, 0.119408f, 0.506877f, 0.198147f, 276.041333f, 44.790667f
};
static const float SCALER_SCALES[28] = {
    2.555372f, 1.597138f, 4.308957f, 0.174686f, 25.714182f, 2.738448f, 106.526424f, 111.524581f, 0.024166f, 0.019956f, 0.024166f, 0.023851f, 0.024166f, 101.584119f, 1.000000f, 1.000000f, 2.494438f, 1.000000f, 0.014272f, 0.021969f, 0.075909f, 0.018521f, 0.058409f, 0.025323f, 0.107573f, 0.042075f, 111.169493f, 21.245327f
};
static const float SCORE_THRESHOLD = 0.555955f;
static const int NUM_EXPORTED_TREES = 8;

static float evaluate_tree_0(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[1] <= 0.250085f) {
        if (x[27] <= 1.115009f) {
            if (x[25] <= -1.331868f) {
                if (x[7] <= 2.015872f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[11] <= -0.129713f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[25] <= 0.656606f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[5] <= 0.021190f) {
            if (x[26] <= -0.304242f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[8] <= 0.199261f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_1(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= 1.047115f) {
        if (x[2] <= -0.094544f) {
            if (x[23] <= -0.607334f) {
                if (x[7] <= 1.082204f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[10] <= -1.209743f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[27] <= -0.455831f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[8] <= -0.282320f) {
            return (float)2;
        } else {
            return (float)2;
        }
    }
}

static float evaluate_tree_2(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[18] <= -0.185533f) {
        if (x[4] <= -0.426640f) {
            if (x[13] <= -0.018443f) {
                return (float)3;
            } else {
                if (x[12] <= 0.271519f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[20] <= 1.697650f) {
                if (x[3] <= -0.539602f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[5] <= 0.021735f) {
            if (x[27] <= -0.595325f) {
                if (x[3] <= -0.328343f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[7] <= -0.632564f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[11] <= -1.382384f) {
                return (float)3;
            } else {
                if (x[25] <= 0.467455f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_3(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= 0.395323f) {
        if (x[20] <= -0.204876f) {
            if (x[8] <= -1.684037f) {
                if (x[13] <= -0.216242f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[25] <= 0.895156f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[23] <= -1.772667f) {
                return (float)3;
            } else {
                if (x[18] <= -0.360488f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[20] <= 0.531095f) {
            if (x[20] <= 0.084297f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            return (float)2;
        }
    }
}

static float evaluate_tree_4(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[21] <= -0.546907f) {
        if (x[10] <= -0.184155f) {
            if (x[2] <= 1.049317f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[13] <= 2.168104f) {
                if (x[24] <= 0.815927f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[1] <= 1.670887f) {
            if (x[26] <= -0.670270f) {
                if (x[22] <= -0.252791f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[0] <= -0.214779f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[21] <= 0.012131f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_5(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[27] <= 0.642602f) {
        if (x[26] <= -0.263518f) {
            if (x[7] <= -0.573415f) {
                if (x[0] <= -0.405993f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[2] <= 0.007438f) {
                if (x[2] <= -0.440352f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[9] <= 0.443035f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[5] <= 1.325306f) {
            if (x[21] <= 1.248366f) {
                if (x[26] <= -0.871259f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[3] <= 0.609982f) {
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

static float evaluate_tree_6(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[26] <= -0.762851f) {
        if (x[24] <= -0.926169f) {
            if (x[7] <= -0.929213f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[24] <= -0.736777f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[7] <= -0.559033f) {
            if (x[24] <= -1.188578f) {
                return (float)3;
            } else {
                if (x[23] <= 0.384134f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[10] <= -1.273239f) {
                if (x[13] <= -0.490752f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[12] <= -0.530623f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    }
}

static float evaluate_tree_7(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[5] <= 0.172890f) {
        if (x[20] <= -0.255288f) {
            if (x[2] <= -0.649971f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[6] <= -0.084591f) {
                if (x[0] <= 1.511893f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[2] <= -0.388035f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[20] <= -1.059131f) {
            if (x[2] <= -0.551280f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[10] <= -0.734240f) {
                return (float)3;
            } else {
                if (x[0] <= 0.426630f) {
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

