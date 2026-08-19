#include "bootsentry_telemetry.h"
#include <math.h>

/* Transpiled Isolation Forest Anomaly Evaluator (8 Real Decision Trees) */
static const float SCALER_MEANS[28] = {
    25.298611f, 25.226893f, 25.254584f, 2.198628f, 26.176040f, 25.186099f, 192.813467f, 378.931017f, 153.030400f, 122.424400f, 137.725400f, 145.378600f, 153.030400f, 128.025000f, 0.000000f, 0.000000f, 51.000000f, 0.000000f, 1575.328562f, 22.255449f, 70.780878f, 0.075586f, 0.140391f, 0.138078f, 0.495276f, 0.208194f, 240.273525f, 37.109125f
};
static const float SCALER_SCALES[28] = {
    2.368963f, 2.174347f, 2.471886f, 0.315993f, 16.509674f, 15.259136f, 77.760245f, 82.979608f, 0.216678f, 0.172812f, 0.194529f, 0.206659f, 0.216678f, 74.684164f, 1.000000f, 1.000000f, 18.272247f, 1.000000f, 0.400497f, 0.021497f, 0.070041f, 0.015911f, 0.048726f, 0.048083f, 0.095322f, 0.041022f, 80.183828f, 23.199508f
};
static const float SCORE_THRESHOLD = 0.516755f;
static const int NUM_EXPORTED_TREES = 8;

static float evaluate_tree_0(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[1] <= 1.564245f) {
        if (x[27] <= 1.818141f) {
            if (x[25] <= -1.708084f) {
                if (x[7] <= 3.238542f) {
                    if (x[11] <= 0.126667f) {
                        if (x[25] <= -1.777572f) {
                            if (x[5] <= 0.734516f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[26] <= 2.167712f) {
                            return (float)6;
                        } else {
                            if (x[8] <= 0.729973f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    }
                } else {
                    if (x[13] <= 0.440285f) {
                        if (x[19] <= 0.379239f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[11] <= 0.731947f) {
                            return (float)6;
                        } else {
                            if (x[11] <= 0.801523f) {
                                return (float)7;
                            } else {
                                if (x[21] <= -2.374917f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                }
            } else {
                if (x[0] <= 6.222207f) {
                    if (x[11] <= -3.404993f) {
                        if (x[25] <= 1.556029f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[8] <= -1.157262f) {
                            if (x[10] <= -2.211803f) {
                                return (float)7;
                            } else {
                                if (x[11] <= -1.686667f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[22] <= -0.921210f) {
                                if (x[22] <= -1.210895f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[9] <= 0.088814f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[9] <= 0.532379f) {
                if (x[8] <= -0.402455f) {
                    return (float)4;
                } else {
                    if (x[1] <= -0.731191f) {
                        return (float)5;
                    } else {
                        if (x[20] <= -1.026136f) {
                            return (float)6;
                        } else {
                            if (x[20] <= -0.444615f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    }
                }
            } else {
                if (x[21] <= -1.059265f) {
                    return (float)4;
                } else {
                    if (x[12] <= 0.906794f) {
                        if (x[12] <= 0.825101f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        return (float)5;
                    }
                }
            }
        }
    } else {
        if (x[22] <= 2.190012f) {
            if (x[10] <= 0.439825f) {
                if (x[20] <= -0.570436f) {
                    if (x[10] <= -0.832091f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                } else {
                    if (x[25] <= -1.252402f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                }
            } else {
                if (x[22] <= -0.721099f) {
                    return (float)4;
                } else {
                    if (x[27] <= -0.712905f) {
                        return (float)5;
                    } else {
                        if (x[13] <= 1.434709f) {
                            if (x[27] <= 0.799675f) {
                                if (x[3] <= -0.851974f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[22] <= 0.393142f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            }
        } else {
            if (x[8] <= 0.253843f) {
                return (float)3;
            } else {
                return (float)3;
            }
        }
    }
}

static float evaluate_tree_1(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= 2.764765f) {
        if (x[2] <= 0.252503f) {
            if (x[23] <= 1.186894f) {
                if (x[7] <= 2.415740f) {
                    if (x[10] <= -2.310767f) {
                        if (x[27] <= -0.436293f) {
                            return (float)6;
                        } else {
                            if (x[8] <= -3.259021f) {
                                return (float)7;
                            } else {
                                if (x[8] <= -2.609397f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        if (x[20] <= -0.527513f) {
                            if (x[11] <= -0.217376f) {
                                if (x[23] <= -0.439796f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[2] <= 0.067587f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[7] <= 0.326206f) {
                                if (x[20] <= 2.905864f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[20] <= 0.128772f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                } else {
                    if (x[1] <= -0.723584f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                }
            } else {
                if (x[5] <= 4.216704f) {
                    if (x[26] <= -0.321150f) {
                        if (x[26] <= -0.950444f) {
                            return (float)6;
                        } else {
                            if (x[4] <= -0.408097f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    } else {
                        if (x[27] <= -1.590575f) {
                            return (float)6;
                        } else {
                            if (x[5] <= 3.970477f) {
                                return (float)7;
                            } else {
                                if (x[5] <= 4.068290f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                } else {
                    if (x[26] <= 0.158248f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                }
            }
        } else {
            if (x[3] <= 2.083011f) {
                if (x[4] <= 3.260591f) {
                    if (x[27] <= 2.372227f) {
                        if (x[3] <= -0.108126f) {
                            if (x[12] <= 0.271469f) {
                                if (x[23] <= 2.382569f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[22] <= -0.408337f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[5] <= 3.392418f) {
                                if (x[19] <= -2.510937f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        }
                    } else {
                        return (float)5;
                    }
                } else {
                    if (x[5] <= -0.261800f) {
                        if (x[10] <= -1.523225f) {
                            return (float)6;
                        } else {
                            if (x[21] <= -0.352224f) {
                                if (x[10] <= 0.530938f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        }
                    } else {
                        if (x[22] <= 3.970107f) {
                            if (x[11] <= -0.414464f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            if (x[6] <= -0.856178f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    }
                }
            } else {
                if (x[27] <= 0.540163f) {
                    if (x[6] <= 0.383734f) {
                        if (x[18] <= -0.018619f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        return (float)5;
                    }
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[23] <= 1.212854f) {
            if (x[2] <= 4.151586f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            return (float)2;
        }
    }
}

static float evaluate_tree_2(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[18] <= 11.171957f) {
        if (x[4] <= -0.180661f) {
            if (x[13] <= 0.438569f) {
                if (x[12] <= -0.154097f) {
                    if (x[8] <= -3.230366f) {
                        return (float)5;
                    } else {
                        if (x[22] <= 0.648351f) {
                            if (x[3] <= 0.834551f) {
                                if (x[5] <= 1.286728f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[19] <= -0.207472f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[6] <= -0.879779f) {
                                if (x[7] <= -1.712041f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[11] <= -0.828466f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                } else {
                    if (x[10] <= 0.085118f) {
                        if (x[21] <= -1.183491f) {
                            return (float)6;
                        } else {
                            if (x[2] <= 0.602332f) {
                                if (x[26] <= -1.292667f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[6] <= -0.767873f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        if (x[6] <= -0.655097f) {
                            if (x[19] <= 0.048298f) {
                                if (x[21] <= 0.684529f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[22] <= -0.097595f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[1] <= 0.609827f) {
                                if (x[5] <= 0.977486f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[25] <= -0.180471f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                }
            } else {
                if (x[0] <= 0.614516f) {
                    if (x[10] <= -0.025323f) {
                        if (x[1] <= 0.209510f) {
                            if (x[12] <= -0.806282f) {
                                return (float)7;
                            } else {
                                if (x[21] <= -0.705034f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[4] <= -0.339440f) {
                                if (x[2] <= 0.654709f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        }
                    } else {
                        if (x[7] <= 1.882356f) {
                            if (x[2] <= -0.925614f) {
                                return (float)7;
                            } else {
                                if (x[13] <= 0.741473f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[18] <= -0.013037f) {
                                if (x[0] <= 0.339873f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[27] <= -0.218976f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                } else {
                    if (x[3] <= -0.370694f) {
                        if (x[13] <= 1.957707f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[5] <= 1.158589f) {
                            if (x[13] <= 3.107496f) {
                                if (x[9] <= 0.635047f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            }
        } else {
            if (x[7] <= -0.539499f) {
                if (x[25] <= 1.122059f) {
                    if (x[22] <= 1.948957f) {
                        if (x[21] <= 1.320145f) {
                            if (x[7] <= -0.881022f) {
                                return (float)7;
                            } else {
                                if (x[9] <= -0.055519f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[25] <= 0.922502f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    } else {
                        if (x[0] <= 0.605506f) {
                            if (x[11] <= -1.228173f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    }
                } else {
                    if (x[27] <= -0.298652f) {
                        if (x[13] <= -0.918551f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[13] <= 0.188726f) {
                            if (x[13] <= -0.736143f) {
                                if (x[6] <= -1.026525f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[12] <= 0.869422f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            } else {
                if (x[3] <= 4.741751f) {
                    if (x[0] <= 0.049718f) {
                        if (x[3] <= 2.534611f) {
                            if (x[23] <= 0.317868f) {
                                if (x[1] <= 1.490559f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[0] <= -0.672868f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[23] <= -0.115056f) {
                            if (x[13] <= -1.167412f) {
                                return (float)7;
                            } else {
                                if (x[18] <= -0.032202f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[20] <= 0.300147f) {
                                if (x[24] <= -0.756654f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        }
                    }
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        return (float)1;
    }
}

static float evaluate_tree_3(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[2] <= 1.708959f) {
        if (x[20] <= 0.334749f) {
            if (x[8] <= -3.155732f) {
                return (float)3;
            } else {
                if (x[12] <= -1.686482f) {
                    if (x[10] <= -2.573423f) {
                        if (x[0] <= 0.380507f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[18] <= -0.024799f) {
                            if (x[26] <= 0.579157f) {
                                if (x[20] <= 0.054901f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    }
                } else {
                    if (x[20] <= -1.130138f) {
                        if (x[24] <= 0.532747f) {
                            if (x[27] <= -0.310949f) {
                                if (x[5] <= -0.044578f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[4] <= 0.796343f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[3] <= -0.831341f) {
                                if (x[19] <= 1.407960f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[3] <= 0.746093f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        if (x[0] <= 2.322010f) {
                            if (x[12] <= 0.055157f) {
                                if (x[3] <= 2.952466f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[10] <= 0.528963f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            }
        } else {
            if (x[25] <= -0.955650f) {
                if (x[4] <= 0.414687f) {
                    if (x[1] <= -0.238043f) {
                        if (x[7] <= 0.818636f) {
                            return (float)6;
                        } else {
                            if (x[4] <= -0.273528f) {
                                if (x[0] <= 1.136552f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[18] <= -0.106752f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        return (float)5;
                    }
                } else {
                    return (float)4;
                }
            } else {
                if (x[1] <= 2.432814f) {
                    if (x[10] <= -0.678706f) {
                        if (x[26] <= -1.069086f) {
                            if (x[8] <= -1.467169f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            if (x[4] <= 3.486347f) {
                                if (x[0] <= 0.428068f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        }
                    } else {
                        if (x[22] <= 2.525694f) {
                            if (x[23] <= 0.380433f) {
                                if (x[13] <= -0.518604f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[13] <= -0.994060f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[5] <= -0.321087f) {
                                return (float)7;
                            } else {
                                if (x[8] <= -0.166755f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                } else {
                    return (float)4;
                }
            }
        }
    } else {
        if (x[2] <= 6.845457f) {
            if (x[0] <= -0.845841f) {
                return (float)3;
            } else {
                if (x[7] <= 0.475410f) {
                    if (x[19] <= -0.423291f) {
                        if (x[25] <= 1.448982f) {
                            if (x[11] <= -0.732965f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[13] <= -0.825756f) {
                            return (float)6;
                        } else {
                            if (x[26] <= 0.086918f) {
                                if (x[1] <= 1.219336f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        }
                    }
                } else {
                    if (x[21] <= -1.140749f) {
                        return (float)5;
                    } else {
                        if (x[11] <= 0.112453f) {
                            if (x[11] <= -1.419679f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            }
        } else {
            return (float)2;
        }
    }
}

static float evaluate_tree_4(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[21] <= -0.553970f) {
        if (x[10] <= -0.442117f) {
            if (x[2] <= -1.033066f) {
                return (float)3;
            } else {
                if (x[13] <= 1.010669f) {
                    if (x[24] <= 1.325640f) {
                        if (x[1] <= 0.994171f) {
                            if (x[26] <= 1.106634f) {
                                if (x[22] <= -0.960971f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    } else {
                        return (float)5;
                    }
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[0] <= 0.115558f) {
                if (x[21] <= -1.877158f) {
                    return (float)4;
                } else {
                    if (x[26] <= 2.279713f) {
                        if (x[4] <= 3.923314f) {
                            if (x[3] <= 0.600594f) {
                                if (x[21] <= -1.390904f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[7] <= 0.921381f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[1] <= 0.972502f) {
                            if (x[19] <= 1.004003f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            } else {
                if (x[18] <= -0.018784f) {
                    if (x[24] <= 1.757555f) {
                        if (x[0] <= 1.822154f) {
                            if (x[18] <= -0.080550f) {
                                if (x[4] <= -0.276956f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[6] <= 1.437242f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            return (float)6;
                        }
                    } else {
                        return (float)5;
                    }
                } else {
                    if (x[25] <= -2.068528f) {
                        return (float)5;
                    } else {
                        if (x[23] <= -0.806725f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    }
                }
            }
        }
    } else {
        if (x[0] <= 1.199712f) {
            if (x[7] <= 0.566266f) {
                if (x[3] <= -1.212817f) {
                    return (float)4;
                } else {
                    if (x[12] <= 0.661741f) {
                        if (x[20] <= 2.040873f) {
                            if (x[0] <= -0.477319f) {
                                if (x[19] <= 1.313342f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[27] <= 1.172640f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[2] <= 0.810623f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    } else {
                        if (x[2] <= 1.530607f) {
                            if (x[3] <= -0.307264f) {
                                if (x[4] <= 0.152787f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[2] <= 1.224570f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            } else {
                if (x[19] <= 0.204673f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[20] <= -0.670468f) {
                if (x[22] <= 0.257541f) {
                    if (x[19] <= 1.299870f) {
                        if (x[22] <= -0.523701f) {
                            return (float)6;
                        } else {
                            if (x[11] <= -1.451902f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    } else {
                        if (x[1] <= 0.041807f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    }
                } else {
                    if (x[19] <= 1.457935f) {
                        if (x[5] <= -0.320768f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        return (float)5;
                    }
                }
            } else {
                if (x[8] <= -0.084266f) {
                    if (x[3] <= 5.256290f) {
                        if (x[20] <= 4.254968f) {
                            if (x[12] <= -0.185819f) {
                                if (x[11] <= -2.345111f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[21] <= 1.876016f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            return (float)6;
                        }
                    } else {
                        return (float)5;
                    }
                } else {
                    if (x[4] <= -0.374433f) {
                        if (x[6] <= -0.431825f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[20] <= 1.179605f) {
                            if (x[1] <= 1.923030f) {
                                if (x[26] <= -0.102134f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            }
        }
    }
}

static float evaluate_tree_5(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[27] <= 1.630832f) {
        if (x[26] <= -0.734843f) {
            if (x[7] <= -0.140576f) {
                if (x[27] <= 1.071949f) {
                    if (x[12] <= -1.792940f) {
                        if (x[2] <= -0.250055f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[2] <= 1.046531f) {
                            if (x[9] <= 0.834233f) {
                                if (x[5] <= 2.521996f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[21] <= 1.608352f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[11] <= -0.415351f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    }
                } else {
                    if (x[22] <= -0.044092f) {
                        if (x[20] <= -1.137370f) {
                            if (x[4] <= -0.356301f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            if (x[19] <= -0.799494f) {
                                if (x[0] <= -0.891280f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[22] <= -0.120825f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        if (x[0] <= 0.355221f) {
                            if (x[4] <= -0.302502f) {
                                if (x[18] <= -0.061939f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            } else {
                if (x[5] <= -0.204410f) {
                    if (x[25] <= -0.304640f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                } else {
                    return (float)4;
                }
            }
        } else {
            if (x[13] <= 2.684180f) {
                if (x[1] <= 3.709192f) {
                    if (x[0] <= 0.985243f) {
                        if (x[18] <= -0.024936f) {
                            if (x[12] <= 0.768316f) {
                                if (x[4] <= 3.882639f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[26] <= 0.758227f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[18] <= -0.010428f) {
                                if (x[12] <= 0.234267f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[11] <= -2.089951f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        if (x[24] <= -0.943530f) {
                            if (x[25] <= 1.296374f) {
                                if (x[21] <= 1.689710f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        } else {
                            if (x[1] <= 0.035634f) {
                                if (x[23] <= -0.405539f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[1] <= 1.370868f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                } else {
                    if (x[27] <= -0.750704f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                }
            } else {
                if (x[18] <= -0.151606f) {
                    return (float)4;
                } else {
                    if (x[2] <= -0.016567f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                }
            }
        }
    } else {
        if (x[12] <= -0.609221f) {
            if (x[10] <= -1.812401f) {
                return (float)3;
            } else {
                return (float)3;
            }
        } else {
            if (x[23] <= -0.612832f) {
                if (x[6] <= 1.676093f) {
                    if (x[6] <= 0.874538f) {
                        if (x[20] <= 1.622194f) {
                            if (x[5] <= -0.151179f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    } else {
                        return (float)5;
                    }
                } else {
                    return (float)4;
                }
            } else {
                if (x[8] <= 0.363197f) {
                    if (x[4] <= -0.332965f) {
                        if (x[27] <= 1.845619f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[20] <= -0.934536f) {
                            if (x[1] <= -0.404018f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            if (x[6] <= 0.373258f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    }
                } else {
                    if (x[24] <= 0.043846f) {
                        if (x[22] <= 0.738492f) {
                            if (x[3] <= -0.475271f) {
                                if (x[12] <= 0.550894f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[0] <= -0.836923f) {
                            return (float)6;
                        } else {
                            if (x[1] <= -0.512410f) {
                                return (float)7;
                            } else {
                                if (x[23] <= -0.203543f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

static float evaluate_tree_6(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[26] <= -1.131461f) {
        if (x[24] <= -0.930771f) {
            if (x[7] <= -0.874983f) {
                if (x[24] <= -1.276327f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[7] <= -0.812825f) {
                    if (x[12] <= -0.455236f) {
                        return (float)5;
                    } else {
                        if (x[21] <= 0.270615f) {
                            return (float)6;
                        } else {
                            if (x[23] <= 0.185749f) {
                                if (x[10] <= 0.181821f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        }
                    }
                } else {
                    if (x[13] <= 0.217939f) {
                        if (x[1] <= -0.963075f) {
                            return (float)6;
                        } else {
                            if (x[7] <= -0.293026f) {
                                return (float)7;
                            } else {
                                if (x[5] <= -0.277841f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        if (x[6] <= -0.811516f) {
                            if (x[12] <= 0.867778f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            }
        } else {
            if (x[5] <= -0.229604f) {
                if (x[22] <= 0.926171f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                return (float)3;
            }
        }
    } else {
        if (x[4] <= 0.498055f) {
            if (x[25] <= 1.168244f) {
                if (x[19] <= -1.192992f) {
                    if (x[25] <= -1.688713f) {
                        if (x[19] <= -1.245708f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[27] <= 0.386730f) {
                            if (x[5] <= 2.399153f) {
                                if (x[18] <= -0.110721f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        } else {
                            if (x[9] <= 0.432927f) {
                                return (float)7;
                            } else {
                                if (x[0] <= -0.837266f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                } else {
                    if (x[10] <= -4.519293f) {
                        return (float)5;
                    } else {
                        if (x[21] <= -0.021239f) {
                            if (x[11] <= -0.289124f) {
                                if (x[13] <= 1.886423f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[25] <= -0.376191f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[0] <= -1.066374f) {
                                if (x[22] <= -0.055919f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[13] <= 0.972074f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                }
            } else {
                if (x[12] <= 0.234599f) {
                    if (x[8] <= -3.459684f) {
                        return (float)5;
                    } else {
                        if (x[19] <= 0.307458f) {
                            if (x[0] <= 1.478282f) {
                                if (x[25] <= 1.551029f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[5] <= -0.411190f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[4] <= -0.219532f) {
                                if (x[21] <= 2.008245f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        }
                    }
                } else {
                    if (x[12] <= 0.523107f) {
                        if (x[21] <= 1.181849f) {
                            return (float)6;
                        } else {
                            if (x[2] <= -0.399003f) {
                                return (float)7;
                            } else {
                                if (x[25] <= 1.772324f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        if (x[1] <= 0.929558f) {
                            if (x[25] <= 1.824436f) {
                                if (x[4] <= -0.183516f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    }
                }
            }
        } else {
            if (x[18] <= -0.084340f) {
                if (x[7] <= 0.831198f) {
                    return (float)4;
                } else {
                    return (float)4;
                }
            } else {
                if (x[19] <= 0.977440f) {
                    if (x[1] <= 2.832356f) {
                        if (x[10] <= -1.287807f) {
                            if (x[6] <= -0.333891f) {
                                if (x[9] <= -1.455726f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        } else {
                            if (x[6] <= 0.075044f) {
                                if (x[18] <= -0.075873f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[10] <= -1.052963f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        return (float)5;
                    }
                } else {
                    if (x[3] <= -0.274340f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                }
            }
        }
    }
}

static float evaluate_tree_7(const float x[BOOTSENTRY_NUM_FEATURES]) {
    if (x[5] <= 1.312827f) {
        if (x[20] <= 0.996172f) {
            if (x[2] <= -0.857572f) {
                if (x[6] <= 0.291487f) {
                    if (x[0] <= -0.029810f) {
                        if (x[2] <= -1.161657f) {
                            return (float)6;
                        } else {
                            if (x[20] <= -0.641493f) {
                                if (x[10] <= 0.217276f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[24] <= -1.737022f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        if (x[5] <= -0.530724f) {
                            return (float)6;
                        } else {
                            if (x[9] <= -0.764008f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    }
                } else {
                    if (x[5] <= -0.267433f) {
                        if (x[23] <= -1.212612f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        if (x[25] <= -1.516389f) {
                            return (float)6;
                        } else {
                            if (x[7] <= 0.876930f) {
                                if (x[8] <= 0.228041f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        }
                    }
                }
            } else {
                if (x[3] <= 2.321269f) {
                    if (x[26] <= 1.044982f) {
                        if (x[9] <= 0.516636f) {
                            if (x[3] <= 0.490526f) {
                                if (x[22] <= 0.702580f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[2] <= -0.144074f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[7] <= 0.736060f) {
                                if (x[5] <= -0.287012f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[19] <= 0.182197f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    } else {
                        if (x[7] <= 1.890843f) {
                            if (x[18] <= -0.014579f) {
                                if (x[23] <= -1.001158f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[23] <= -0.931735f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[24] <= 1.890113f) {
                                if (x[27] <= -0.205921f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                return (float)7;
                            }
                        }
                    }
                } else {
                    if (x[25] <= -0.068597f) {
                        if (x[9] <= 0.743089f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    } else {
                        return (float)5;
                    }
                }
            }
        } else {
            if (x[6] <= 1.500418f) {
                if (x[6] <= 1.325452f) {
                    if (x[13] <= -1.062540f) {
                        if (x[7] <= -0.908118f) {
                            return (float)6;
                        } else {
                            if (x[25] <= -0.110023f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        }
                    } else {
                        if (x[9] <= 0.829085f) {
                            if (x[3] <= 1.297479f) {
                                if (x[0] <= 6.152084f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[9] <= -4.594401f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        } else {
                            if (x[6] <= -0.572379f) {
                                if (x[0] <= -0.169160f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            } else {
                                if (x[13] <= 1.492001f) {
                                    return (float)8;
                                } else {
                                    return (float)8;
                                }
                            }
                        }
                    }
                } else {
                    return (float)4;
                }
            } else {
                if (x[3] <= -0.306404f) {
                    if (x[18] <= -0.086706f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                } else {
                    if (x[27] <= -0.321271f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                }
            }
        }
    } else {
        if (x[26] <= 0.273081f) {
            if (x[23] <= 5.192272f) {
                if (x[20] <= -0.297577f) {
                    if (x[19] <= 1.253461f) {
                        if (x[13] <= -0.264840f) {
                            if (x[4] <= -0.299036f) {
                                return (float)7;
                            } else {
                                return (float)7;
                            }
                        } else {
                            return (float)6;
                        }
                    } else {
                        return (float)5;
                    }
                } else {
                    if (x[27] <= -0.745771f) {
                        return (float)5;
                    } else {
                        if (x[10] <= -0.008516f) {
                            return (float)6;
                        } else {
                            return (float)6;
                        }
                    }
                }
            } else {
                return (float)3;
            }
        } else {
            if (x[2] <= -0.215586f) {
                if (x[13] <= 0.610620f) {
                    if (x[23] <= 2.233236f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
                } else {
                    return (float)4;
                }
            } else {
                if (x[8] <= -0.464253f) {
                    return (float)4;
                } else {
                    if (x[1] <= 0.465405f) {
                        return (float)5;
                    } else {
                        return (float)5;
                    }
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

