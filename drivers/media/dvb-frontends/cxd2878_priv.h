#ifndef _CXD2878_PRIV_H_
#define _CXD2878_PRIV_H_

#define AUTO         (0xFF) /* For IF_OUT_SEL and AGC_SEL, it means that the value is desided by config flags. */
								/* For RF_GAIN, it means that RF_GAIN_SEL(SubAddr:0x4E) = 1 */
#define OFFSET(ofs)  ((u8)(ofs) & 0x1F)
#define BW_6         (0x00)
#define BW_7         (0x01)
#define BW_8         (0x02)
#define BW_1_7       (0x03)

#define MAX_BIT_PRECISION  5
#define FRAC_BITMASK      0x1F
#define LOG2_10_100X            332                     /**< log2 (10) */
#define LOG2_E_100X             144                     /**< log2 (e) */

//////////////////////////////
 enum sony_ascot3_tv_system_t{
	SONY_ASCOT3_TV_SYSTEM_UNKNOWN,
	/* Analog */
	SONY_ASCOT3_ATV_MN_EIAJ,  /**< System-M (Japan) (IF: Fp=5.75MHz in default) */
	SONY_ASCOT3_ATV_MN_SAP,   /**< System-M (US)	(IF: Fp=5.75MHz in default) */
	SONY_ASCOT3_ATV_MN_A2,	  /**< System-M (Korea) (IF: Fp=5.9MHz in default) */
	SONY_ASCOT3_ATV_BG, 	  /**< System-B/G		(IF: Fp=7.3MHz in default) */
	SONY_ASCOT3_ATV_I,		  /**< System-I 		(IF: Fp=7.85MHz in default) */
	SONY_ASCOT3_ATV_DK, 	  /**< System-D/K		(IF: Fp=7.85MHz in default) */
	SONY_ASCOT3_ATV_L,		  /**< System-L 		(IF: Fp=7.85MHz in default) */
	SONY_ASCOT3_ATV_L_DASH,   /**< System-L DASH	(IF: Fp=2.2MHz in default) */
	/* Digital */
	SONY_ASCOT3_DTV_8VSB,	  /**< ATSC 8VSB		(IF: Fc=3.7MHz in default) */
	SONY_ASCOT3_DTV_QAM,	  /**< US QAM			(IF: Fc=3.7MHz in default) */
	SONY_ASCOT3_DTV_ISDBT_6,  /**< ISDB-T 6MHzBW	(IF: Fc=3.55MHz in default) */
	SONY_ASCOT3_DTV_ISDBT_7,  /**< ISDB-T 7MHzBW	(IF: Fc=4.15MHz in default) */
	SONY_ASCOT3_DTV_ISDBT_8,  /**< ISDB-T 8MHzBW	(IF: Fc=4.75MHz in default) */
	SONY_ASCOT3_DTV_DVBT_5,   /**< DVB-T 5MHzBW 	(IF: Fc=3.6MHz in default) */
	SONY_ASCOT3_DTV_DVBT_6,   /**< DVB-T 6MHzBW 	(IF: Fc=3.6MHz in default) */
	SONY_ASCOT3_DTV_DVBT_7,   /**< DVB-T 7MHzBW 	(IF: Fc=4.2MHz in default) */
	SONY_ASCOT3_DTV_DVBT_8,   /**< DVB-T 8MHzBW 	(IF: Fc=4.8MHz in default) */
	SONY_ASCOT3_DTV_DVBT2_1_7,/**< DVB-T2 1.7MHzBW	(IF: Fc=3.5MHz in default) */
	SONY_ASCOT3_DTV_DVBT2_5,  /**< DVB-T2 5MHzBW	(IF: Fc=3.6MHz in default) */
	SONY_ASCOT3_DTV_DVBT2_6,  /**< DVB-T2 6MHzBW	(IF: Fc=3.6MHz in default) */
	SONY_ASCOT3_DTV_DVBT2_7,  /**< DVB-T2 7MHzBW	(IF: Fc=4.2MHz in default) */
	SONY_ASCOT3_DTV_DVBT2_8,  /**< DVB-T2 8MHzBW	(IF: Fc=4.8MHz in default) */
	SONY_ASCOT3_DTV_DVBC_6,   /**< DVB-C 6MHzBW 	(IF: Fc=3.7MHz in default) */
	SONY_ASCOT3_DTV_DVBC_8,   /**< DVB-C 8MHzBW 	(IF: Fc=4.9MHz in default) */
	SONY_ASCOT3_DTV_DVBC2_6,  /**< DVB-C2 6MHzBW	(IF: Fc=3.7MHz in default) */
	SONY_ASCOT3_DTV_DVBC2_8,  /**< DVB-C2 8MHzBW	(IF: Fc=4.9MHz in default) */
	SONY_ASCOT3_DTV_ATSC3_6,  /**< ATSC 3.0 6MHzBW	(IF: Fc=3.6MHz in default) */
	SONY_ASCOT3_DTV_ATSC3_7,  /**< ATSC 3.0 7MHzBW	(IF: Fc=4.2MHz in default) */
	SONY_ASCOT3_DTV_ATSC3_8,  /**< ATSC 3.0 8MHzBW	(IF: Fc=4.8MHz in default) */
	SONY_ASCOT3_DTV_J83B_5_6, /**< J.83B 5.6Msps	(IF: Fc=3.75MHz in default) */
	SONY_ASCOT3_DTV_DTMB,	  /**< DTMB 			(IF: Fc=5.1MHz in default) */

	SONY_ASCOT3_ATV_MIN = SONY_ASCOT3_ATV_MN_EIAJ, /**< Minimum analog terrestrial system */
	SONY_ASCOT3_ATV_MAX = SONY_ASCOT3_ATV_L_DASH,  /**< Maximum analog terrestrial system */
	SONY_ASCOT3_DTV_MIN = SONY_ASCOT3_DTV_8VSB,    /**< Minimum digital terrestrial system */
	SONY_ASCOT3_DTV_MAX = SONY_ASCOT3_DTV_DTMB,    /**< Maximum digital terrestrial system */
	SONY_ASCOT3_TV_SYSTEM_NUM					   /**< Number of supported broadcasting system */
} ;

struct sony_ascot3_adjust_param_t {
    u8 OUTLMT;            /**< Addr:0x68 Bit[1:0] : Maximum IF output. (0: 1.5Vp-p, 1: 1.2Vp-p) */
    u8 RF_GAIN;           /**< Addr:0x69 Bit[6:4] : RFVGA gain. 0xFF means Auto. (RF_GAIN_SEL = 1) */
    u8 IF_BPF_GC;         /**< Addr:0x69 Bit[3:0] : IF_BPF gain. */
    u8 RFOVLD_DET_LV1_VL; /**< Addr:0x6B Bit[3:0] : RF overload RF input detect level. (FRF <= 172MHz) */
    u8 RFOVLD_DET_LV1_VH; /**< Addr:0x6B Bit[3:0] : RF overload RF input detect level. (172MHz < FRF <= 464MHz) */
    u8 RFOVLD_DET_LV1_U;  /**< Addr:0x6B Bit[3:0] : RF overload RF input detect level. (FRF > 464MHz) */
    u8 IFOVLD_DET_LV_VL;  /**< Addr:0x6C Bit[2:0] : Internal RFAGC detect level. (FRF <= 172MHz) */
    u8 IFOVLD_DET_LV_VH;  /**< Addr:0x6C Bit[2:0] : Internal RFAGC detect level. (172MHz < FRF <= 464MHz) */
    u8 IFOVLD_DET_LV_U;   /**< Addr:0x6C Bit[2:0] : Internal RFAGC detect level. (FRF > 464MHz) */
    u8 IF_BPF_F0;         /**< Addr:0x6D Bit[5:4] : IF filter center offset. */
    u8 BW;                /**< Addr:0x6D Bit[1:0] : 6MHzBW(0x00) or 7MHzBW(0x01) or 8MHzBW(0x02) or 1.7MHzBW(0x03) */
    u8 FIF_OFFSET;        /**< Addr:0x6E Bit[4:0] : 5bit signed. IF offset (kHz) = FIF_OFFSET x 50 */
    u8 BW_OFFSET;         /**< Addr:0x6F Bit[4:0] : 5bit signed. BW offset (kHz) = BW_OFFSET x 50 (BW_OFFSET x 10 in 1.7MHzBW) */
    u8 AGC_SEL;           /**< Addr:0x74 Bit[5:4] : AGC pin select. (0: AGC1, 1: AGC2) 0xFF means Auto (by config flags) */
    u8 IF_OUT_SEL;        /**< Addr:0x74 Bit[1:0] : IFOUT pin select. (0: IFOUT1, 1: IFOUT2) 0xFF means Auto. (by config flags) */
    u8 IS_LOWERLOCAL;     /**< Addr:0x9C Bit[0]   : Local polarity. (0: Upper Local, 1: Lower Local) */
} ;
////////////////////////
 enum sony_demod_chip_id_t{
    SONY_DEMOD_CHIP_ID_UNKNOWN = 0,      /**< Unknown */
    SONY_DEMOD_CHIP_ID_CXD2856 = 0x090,  /**< CXD2856 / CXD6800(SiP) */
    SONY_DEMOD_CHIP_ID_CXD2857 = 0x091,  /**< CXD2857 */
    SONY_DEMOD_CHIP_ID_CXD2878 = 0x396,  /**< CXD2878 / CXD6801(SiP) */
    SONY_DEMOD_CHIP_ID_CXD2879 = 0x297,  /**< CXD2879 */
    SONY_DEMOD_CHIP_ID_CXD6802 = 0x197   /**< CXD6802(SiP) */
} ;
 enum sony_ascot3_chip_id_t{
    SONY_ASCOT3_CHIP_ID_UNKNOWN,  /**< Unknown */
    SONY_ASCOT3_CHIP_ID_2871,     /**< CXD2871 (for TV) */
    SONY_ASCOT3_CHIP_ID_2872,     /**< CXD2872 (for STB) */
    SONY_ASCOT3_CHIP_ID_2871A,    /**< CXD2871A (ASCOT3I) (for TV) */
    SONY_ASCOT3_CHIP_ID_2875      /**< CXD2875 */
} ;
enum sony_dtv_system_t{
    SONY_DTV_SYSTEM_UNKNOWN,        /**< Unknown. */
    SONY_DTV_SYSTEM_DVBT,           /**< DVB-T */
    SONY_DTV_SYSTEM_DVBT2,          /**< DVB-T2 */
    SONY_DTV_SYSTEM_DVBC,           /**< DVB-C(J.83A) */
    SONY_DTV_SYSTEM_DVBC2,          /**< DVB-C2(J.382) */
    SONY_DTV_SYSTEM_ATSC,           /**< ATSC */
    SONY_DTV_SYSTEM_ATSC3,          /**< ATSC3.0 */
    SONY_DTV_SYSTEM_ISDBT,          /**< ISDB-T */
    SONY_DTV_SYSTEM_ISDBC,          /**< ISDB-C(J.83C) */
    SONY_DTV_SYSTEM_J83B,           /**< J.83B */
    SONY_DTV_SYSTEM_DVBS,           /**< DVB-S */
    SONY_DTV_SYSTEM_DVBS2,          /**< DVB-S2 */
    SONY_DTV_SYSTEM_ISDBS,          /**< ISDB-S */
    SONY_DTV_SYSTEM_ISDBS3,         /**< ISDB-S3 */
    SONY_DTV_SYSTEM_ANY             /**< Used for multiple system scanning / blind tuning */
} ;


 enum sony_dtv_bandwidth_t{
    SONY_DTV_BW_UNKNOWN = 0,              /**< Unknown bandwidth. */
    SONY_DTV_BW_1_7_MHZ = 1,              /**< 1.7MHz bandwidth. */
    SONY_DTV_BW_5_MHZ = 5,                /**< 5MHz bandwidth. */
    SONY_DTV_BW_6_MHZ = 6,                /**< 6MHz bandwidth. */
    SONY_DTV_BW_7_MHZ = 7,                /**< 7MHz bandwidth. */
    SONY_DTV_BW_8_MHZ = 8,                /**< 8MHz bandwidth. */

    SONY_DTV_BW_J83B_5_06_5_36_MSPS = 50, /**< For J.83B. 5.06/5.36Msps auto selection commonly used in US. */
    SONY_DTV_BW_J83B_5_60_MSPS = 51       /**< For J.83B. 5.6Msps used by SKY PerfecTV! Hikari in Japan. */
} ;

 enum sony_demod_state_t{
    SONY_DEMOD_STATE_UNKNOWN,           /**< Unknown. */
    SONY_DEMOD_STATE_SHUTDOWN,          /**< Chip is in Shutdown state. */
    SONY_DEMOD_STATE_SLEEP,             /**< Chip is in Sleep state. */
    SONY_DEMOD_STATE_ACTIVE,            /**< Chip is in Active state. */
    SONY_DEMOD_STATE_INVALID            /**< Invalid, result of an error during a state change. */
} ;
 struct sony_demod_ts_clk_configuration_t{
    u8 serialClkMode;      /**< Serial clock mode (gated or continuous) */
    u8 serialDutyMode;     /**< Serial clock duty mode (full rate or half rate) */
    u8 tsClkPeriod;        /**< TS clock period */
    u8 clkSelTSIf;         /**< TS clock frequency (low, mid or high) */
} ;
 struct sony_demod_iffreq_config_t{
    u32 configDVBT_5;              /**< DVB-T 5MHz */
    u32 configDVBT_6;              /**< DVB-T 6MHz */
    u32 configDVBT_7;              /**< DVB-T 7MHz */
    u32 configDVBT_8;              /**< DVB-T 8MHz */
    u32 configDVBT2_1_7;           /**< DVB-T2 1.7MHz */
    u32 configDVBT2_5;             /**< DVB-T2 5MHz */
    u32 configDVBT2_6;             /**< DVB-T2 6MHz */
    u32 configDVBT2_7;             /**< DVB-T2 7MHz */
    u32 configDVBT2_8;             /**< DVB-T2 8MHz */
    u32 configDVBC_6;              /**< DVB-C  6MHz */
    u32 configDVBC_7;              /**< DVB-C  7MHz */
    u32 configDVBC_8;              /**< DVB-C  8MHz */
    u32 configATSC;                /**< ATSC 1.0 */
    u32 configISDBT_6;             /**< ISDB-T 6MHz */
    u32 configISDBT_7;             /**< ISDB-T 7MHz */
    u32 configISDBT_8;             /**< ISDB-T 8MHz */
    u32 configJ83B_5_06_5_36;      /**< J.83B 5.06/5.36Msps auto selection */
    u32 configJ83B_5_60;           /**< J.83B. 5.6Msps */
} ;


#endif
