/*
    Tmas TAS2101 - DVBS/S2 Satellite demod/tuner driver

    Copyright (C) 2014 Luis Alves <ljalvs@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef GX1133_PRIV_H
#define GX1133_PRIV_H

#define Demod_TOP            		0xff
#define DVB_S2                 		0xf2

#define GXDemod_dejit_div	0x07
#define GXDemod_rpt_free    0x00

#define  GX1133_AGC_POLARITY 	1
#define  GX1133_AGC_STD_VALUE	28

/******************** 0xff-- **********************/
//chip ID
#define cfg_CHIP_ID_H    		0xf0	//0xfff0
#define cfg_CHIP_ID_L   		0xf1	//0xfff1
#define cfg_CHIP_VERSION   	0xf2	//0xfff2
#define cfg_CHIP_VER_LOCAL 	0xf3	//0xfff3

#define cfg_pll_pd			0x9f	//0xff9f[3:0]

#define cfg_pll_r_base		0xa0	//0xffa0
#define cfg_pll_f_base		0xa1	//0xffa1

//================	chanl_cfg_itf	================
#define cfg_DatSrc_base  		0xc0	//0xffc0, adc output distribution.


#define cfg_TS_s_sel			0xc2	//0xffc2, serial ts data source selection.
#define cfg_TS_mute			0xc2	//0xffc2
#define cfg_adc_bypass		0xc2	//0xffc2
#define cfg_agc_sel_base		0xc4	//0xffc4
#define cfg_ts_pin_sel_base	0xc8	//0xffc8

#define cfg_ts_mod_ctrl		0xce	//0xffce
#define cfg_cnl_rst       		0xd1	//0xffd1


//================	core_cfg_itf	================
#define  cfg_i2c_sla_mode	0x90       //0xff90
#define cfg_ADC_base 		0x91	//0xff92, cfg_adc's first reg
#define cfg_core_rst			0x9b	//0xff9b
#define cfg_core_vec_sel		0x9c	//0xff9c[3:0]

#define cfg_PathClk_en		0xad	//0xffad,
#define cfg_Path_sel			0xae	//0xffae,data path  selection

#define cfg_nogate			0xbf	//0xffbf
#define cfg_agc_a_sel		0xc4	//0xffc4[3:0]
#define cfg_chanl_vec_sel	0xc5	//0xffc5[3;0]
//================	i2c_sla		================
#define cfg_tuner_rpt			0xf4	//0xfff4,tuner repeater related config.
#define cfg_dejit_div			0xf4	//0xfff4

#define cfg_mcu_rd_crc_on	0xfa	//0xfffc

#define inf_mcu_crc_ok		0xfb	//0xfffb[1:0]
#define inf_mcu_rd_crc		0xfc	//0xfffc
#define inf_mcu_wr_crc		0xfd	//0xfffd
#define cfg_mcu_onoff_line	0xfe	//0xffff,rom on-off line.
#define cfg_mcu_rom_onoff	0xff	//0xffff,rom on-off

/*-- Register Address Defination begin ---------------*/
#define GX1133_l3_pid					0x00
#define GX1133_cfg_l3mod				0x01

#define GX1133_BBC_PLS					0x02
#define GX1133_BBC_PLS_RD				0x03

#define GX1133_PLL_ADC_RD               0x05

#define GX1133_T2MI_cfg_inf_sel			0x08
#define GX1133_T2MI_state				0x0a
#define GX1133_T2MI_rst					0x0b
#define GX1133_T2MI_ctrl					0x0c
#define GX1133_T2MI_stage				0x0d
#define GX1133_T2MI_cfg					0x0e
#define GX1133_T2MI_inf					0x0f

#define GX1133_DISEQC_MODE			0x10
#define GX1133_DISEQC_RATIO_L			0x11
#define GX1133_DISEQC_RATIO_H			0x12
#define GX1133_DISEQC_GUARD			0x13
#define GX1133_DISEQC_WR_EN			0x14
#define GX1133_DISEQC_WR_CTRL			0x15
#define GX1133_DISEQC_RD_INT			0x16
#define GX1133_DISEQC_STATE			0x17
#define GX1133_DISEQC_IO_CTRL			0x1F

#define GX1133_DISEQC_INS1				0x20
#define GX1133_DISEQC_INS2				0x21
#define GX1133_DISEQC_INS3				0x22
#define GX1133_DISEQC_INS4				0x23
#define GX1133_DISEQC_INS5				0x24
#define GX1133_DISEQC_INS6				0x25
#define GX1133_DISEQC_INS7				0x26
#define GX1133_DISEQC_INS8				0x27
#define GX1133_DISEQC_RD_RESP1		0x28
#define GX1133_DISEQC_RD_RESP2		0x29
#define GX1133_DISEQC_RD_RESP3		0x2A
#define GX1133_DISEQC_RD_RESP4		0x2B
#define GX1133_DISEQC_RD_RESP5		0x2C
#define GX1133_DISEQC_RD_RESP6		0x2D
#define GX1133_DISEQC_RD_RESP7		0x2E
#define GX1133_DISEQC_RD_RESP8		0x2F

#define GX1133_RST						0x30
#define GX1133_ALL_OK					0x31
#define GX1133_NOISE_POW_L			0x32
#define GX1133_NOISE_POW_H			0x33
#define GX1133_MODULE_RST				0x34
#define GX1133_CLK_OK_SEL				0x35
#define GX1133_AUTO_RST				0x36
#define GX1133_WAIT_LENGTH			0x37
#define GX1133_DATA_SEL				0x38
#define GX1133_TRIG_POS				0x39
#define GX1133_DOWN_SAMPLE			0x3A
#define GX1133_DATA_CATCH				0x3B
#define GX1133_PDM_VALUE				0x3C
#define GX1133_TST_MOD_SEL			0x3F

#define GX1133_AGC_SPEED				0x40
#define GX1133_AGC_STD					0x41
#define GX1133_AGC_CTRL_OUT_L			0x42
#define GX1133_AGC_CTRL_OUT_H			0x43
#define GX1133_AGC_AMP_ERR			0x44
#define GX1133_AGC_SET_DATA			0x45
#define GX1133_AGC_MODE				0x46
#define GX1133_AGC_PDM_CLK			0x47
#define GX1133_AGC_LOST_TIME			0x48
#define GX1133_AGC_AMP					0x49
#define GX1133_SNR_DET_N_TIM_L		0x4A
#define GX1133_SNR_DET_N_TIM_H		0x4B

#define GX1133_MIN_FS					0x50
#define GX1133_BCS_BND1				0x51
#define GX1133_BCS_BND2				0x52
#define GX1133_BCS_BND3				0x53
#define GX1133_BCS_BND4				0x54
#define GX1133_BCS_BND5				0x55
#define GX1133_BCS_RST					0x56
#define GX1133_SAME_FC					0x57
#define GX1133_BCS_OUT_ADDR			0x58
#define GX1133_VID_SIG_NUM				0x59
#define GX1133_BCS_FC_OFFSET_L		0x5A
#define GX1133_BCS_FC_OFFSET_H		0x5B
#define GX1133_BCS_FS_L				0x5C
#define GX1133_BCS_FS_H				0x5D
#define GX1133_BCS_SIG_AMP				0x5E
#define GX1133_BCS_SIG_POW			0x5F

#define GX1133_BCS_FS_FILT				0x61
#define GX1133_BCS_PLS0				0x62
#define GX1133_BCS_PLS1				0x63
#define GX1133_BCS_PLS2				0x64
#define GX1133_BCS_PLS3				0x65
#define GX1133_BCS_PLS4				0x66
#define GX1133_BCS_PLS5				0x67
#define GX1133_BCS_PLS6				0x68
#define GX1133_BCS_PLS7				0x69
#define GX1133_BCS_FS_THD				0x6C

#define GX1133_Fsample_Cfg_L			0x70
#define GX1133_Fsample_Cfg_M			0x71
#define GX1133_Fsample_Cfg_H			0x72
#define GX1133_SYMBOL_L				0x73
#define GX1133_SYMBOL_H				0x74
#define GX1133_FC_OFFSET_L				0x75
#define GX1133_FC_OFFSET_H				0x76
#define GX1133_DAGC_CTL				0x77
#define GX1133_DAGC_STD				0x78
#define GX1133_TIM_LOOP_BW			0x79
#define GX1133_TIM_OK_BOUND			0x7A
#define GX1133_TIM_LOCK_CNT			0x7B
#define GX1133_TIM_LOST_CNT			0x7C
#define GX1133_INTG_OUT				0x7D
#define GX1133_SFIC_CTL1				0x7E
#define GX1133_SFIC_CTL2				0x7F

#define GX1133_FLAG_DMY				0x80
#define GX1133_PLH_THRESH				0x81
#define GX1133_FSCAN_RANGE			0x82
#define GX1133_FRAME_EST_NUM			0x83
#define GX1133_PD_GAIN 					0x84
#define GX1133_PFD_ALPHA				0x85
#define GX1133_BBC_BW_CTRL			0x86
#define GX1133_BW_CTRL2				0x87
#define GX1133_BW_PHASE_SEL			0x88
#define GX1133_FB_FSCAN				0x89
#define GX1133_BBC_OK_BOUND			0x8A
#define GX1133_BBC_LOCK_COUNT			0x8B
#define GX1133_FREQ_BACK_L				0x8C
#define GX1133_FREQ_BACK_H			0x8D
#define GX1133_SCAN_SPEED				0x8E
#define GX1133_MSK_PLL_OK				0x8F

#define GX1133_EQU_SPEED				0x90
#define GX1133_EQU_CTL					0x91
#define GX1133_SNR_DET_N_FINE_L		0x92
#define GX1133_SNR_DET_N_FINE_H		0x93
#define GX1133_AWGN_POW_L			0x94
#define GX1133_AWGN_POW_H			0x95
#define GX1133_SCRAM_1X1Y0X_H			0x96
#define GX1133_SCRAM_1X_M				0x97
#define GX1133_SCRAM_1X_L				0x98
#define GX1133_SCRAM_1Y_M				0x99
#define GX1133_SCRAM_1Y_L				0x9A
#define GX1133_SCRAM_0X_M				0x9B
#define GX1133_SCRAM_0X_L				0x9C
#define GX1133_FFE_CTRL1				0x9D
#define GX1133_FFE_CTRL2                          0x9E
#define GX1133_ERR_BND_AMP_RATE		0x9F

#define GX1133_LDPC_CTRL				0xA0
#define GX1133_LDPC_ITER_NUM			0xA1
#define GX1133_LDPC_SIGMA_NUM			0xA2
#define GX1133_LDPC_TSID_CFG			0xA5
#define GX1133_LDPC_TSID_ROUT			0xA6
#define GX1133_LDPC_TSID_CTRL			0xA7
#define GX1133_LDPC_PLS_CTRL			0xA8
#define GX1133_LDPC_BCH_JUMP			0xAB
#define GX1133_LDPC_BCH_ADJ			0xAC
#define GX1133_LDPC_PLS_READ_CTRL		0xAD
#define GX1133_LDPC_TSID_RD_ADDR		0xAE
#define GX1133_LDPC_PLS_ROUT			0xAF

#define GX1133_BCH_ERR_THR				0xB0
#define GX1133_BCH_ERR_NUM_L			0xB1
#define GX1133_BCH_ERR_NUM_H			0xB2
#define GX1133_BCH_TST_SEL				0xB3
#define GX1133_BCH_ERR_STA_LEN_MOD	0xB4

#define GX1133_VIT_LEN_OPT				0xC0
#define GX1133_ICD_ERR_THR12			0xC1
#define GX1133_ICD_ERR_THR23			0xC2
#define GX1133_ICD_ERR_THR34			0xC3
#define GX1133_ICD_ERR_THR56			0xC4
#define GX1133_ICD_ERR_THR67			0xC5
#define GX1133_ICD_ERR_THR78			0xC6
#define GX1133_VIT_SYS_SEL				0xC7
#define GX1133_VIT_IQ_SHIFT			0xC8


#define GX1133_RSD_ERR_STATIC_CTRL	0xD0
#define GX1133_ERR_OUT_0				0xD1
#define GX1133_ERR_OUT_1				0xD2
#define GX1133_ERR_OUT_2				0xD3
#define GX1133_ERR_OUT_3				0xD4

#define GX1133_TS_MODE					0xE0
#define GX1133_PLS_0                                  0xE1
#define GX1133_PLS_1					0xE2
#define GX1133_PKT_LEN_SEL				0xE3
#define GX1133_CRC_ERR_THRESH_L		0xE4
#define GX1133_CRC_ERR_THRESH_H		0xE5
#define GX1133_CFG_TS_0				0xE6
#define GX1133_CFG_TS_2				0xE7
#define GX1133_CFG_TS_4				0xE8
#define GX1133_CFG_TS_6				0xE9
#define GX1133_CFG_TS_8				0xEA
#define GX1133_CFG_TS_A				0xEB
#define GX1133_CRC_ERR_SUM_L			0xEC
#define GX1133_CRC_ERR_SUM_H			0xED
#define GX1133_MODU_MODE				0xEE
#define GX1133_S2_MODE_CODE			0xEF

#define GX1133_A_MATYPE1				0xF0
#define GX1133_A_MATYPE2				0xF1
#define GX1133_A_UPL_L					0xF2
#define GX1133_A_UPL_H					0xF3
#define GX1133_A_SYNC					0xF4
#define GX1133_B_MATYPE1				0xF5
#define GX1133_B_MATYPE2				0xF6
#define GX1133_B_UPL_L					0xF7
#define GX1133_B_UPL_H					0xF8
#define GX1133_B_SYNC					0xF9
#define GX1133_CA_CTRL					0xFA
#define GX1133_CA_DIV					0xFB
#define GX1133_ISSY						0xFC
/*-- Register Address Defination end ---------------*/

/*-- diseqc control byte(standard) ---------------*/
#define	GX1133_DISEQC_CMD1			0xE0
#define	GX1133_DISEQC_CMD2			0x10
#define	GX1133_DISEQC_CMD3			0x38
#define	GX1133_DISEQC_CMD3_1			0x39
#define	GX1133_DISEQC_CMD4_LNB1		0xF0
#define	GX1133_DISEQC_CMD4_LNB2		0xF4
#define	GX1133_DISEQC_CMD4_LNB3		0xF8
#define	GX1133_DISEQC_CMD4_LNB4		0xFC
#define	GX1133_DISEQC_CMD4_SW01        0xF0
#define	GX1133_DISEQC_CMD4_SW02        0xF1
#define	GX1133_DISEQC_CMD4_SW03        0xF2
#define	GX1133_DISEQC_CMD4_SW04        0xF3
#define	GX1133_DISEQC_CMD4_SW05        0xF4
#define	GX1133_DISEQC_CMD4_SW06        0xF5
#define	GX1133_DISEQC_CMD4_SW07        0xF6
#define	GX1133_DISEQC_CMD4_SW08        0xF7
#define	GX1133_DISEQC_CMD4_SW09        0xF8
#define	GX1133_DISEQC_CMD4_SW10        0xF9
#define	GX1133_DISEQC_CMD4_SW11        0xFA
#define	GX1133_DISEQC_CMD4_SW12        0xFB
#define	GX1133_DISEQC_CMD4_SW13        0xFC
#define	GX1133_DISEQC_CMD4_SW14        0xFD
#define	GX1133_DISEQC_CMD4_SW15        0xFE
#define	GX1133_DISEQC_CMD4_SW16        0xFF
/*-- diseqc control byte(standard) ---------------*/


struct gx1133_priv {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	struct i2c_mux_core *muxc;
#endif
	struct list_head     stvlist;
	int                  count;
	/* master i2c adapter */
	struct i2c_adapter *i2c;
	/* muxed i2c adapter for the demod */
	struct i2c_adapter *i2c_demod;
	/* muxed i2c adapter for the tuner */
	struct i2c_adapter *i2c_tuner;

	int i2c_ch;

	struct dvb_frontend fe;
	const struct gx1133_config *cfg;

};

typedef enum _Demod_CorRst_Sel
{// data source for channel
	//!!!dont edit this enum!!!
	cor_crst_i2c=0,
    cor_crst_cnl,
    cor_crst_sdc,
    cor_hrst_sdc,
    cor_crst_mcu,
    cor_hrst_apb,
    cor_crst_chp=7
}Demod_CorRst_Sel;

typedef enum _Demod_PLL_SEL
{
	pll_a=0,
    pll_b,
    pll_c,
    pll_d
}Demod_PLL_SEL;

typedef enum _Demod_PLL_Freq
{
//dem / adc
	pll_27M_to_92_81M=0,
	pll_27M_to_185_63M,//92.81x2

	pll_27M_to_91_125M,
	pll_27M_to_182_25M,//91.125x2

	pll_27M_to_96_19M,
	pll_27M_to_192_38M,//96.19x2

	pll_27M_to_101_25M,
	pll_27M_to_202_50M,//101.25x2

	pll_27M_to_102_94M,
	pll_27M_to_205_88M,//102.94x2

	pll_27M_to_162_00M,//81*2

//dem
	pll_27M_to_111_375M,
	pll_27M_to_123_19M,
	pll_27M_to_121_50M,

//ts_base/ fec x2
	pll_27M_to_236_25M,
	pll_27M_to_249_75M,//
	pll_27M_to_256_50M,//
	pll_27M_to_297_00M,

    pll_27M_to_60_75M,
    pll_27M_to_45_5625M,
    pll_27M_to_116_4375M,
    pll_27M_to_131_625M
}Demod_PLL_Freq;

#define I2C_GATE		0x80

#define VSEL13_18		0x40
#define DISEQC_CMD_LEN_MASK	0x38
#define DISEQC_CMD_MASK		0x07

typedef enum _GX1133_LOCK_STATUS
{
	UNLOCKED = 0,
	AGC_LOCKED = 0x1,
	BCS_LOCKED = 0x3,
	TIM_LOCKED = 0x5,
	CRL_LOCKED = 0x15,
	EQU_LOCKED = 0x35,
	FEC_LOCKED = 0x75
}GX1133_LOCK_STATUS;


struct gx1133_snrtable_pair {
	u16 snr;
	u16 raw;
};

static struct gx1133_snrtable_pair gx1133_snrtable[] =  {
	{10, 0x65a}, /* 1.0 dB */
	{20, 0x50c},
	{30, 0x402},
	{40, 0x32f},
	{50, 0x287},
	{60, 0x202},
	{70, 0x198},
	{80, 0x144},
	{90, 0x100},
	{100, 0xcc},
	{110, 0xa2},
	{120, 0x81},
	{130, 0x66},
	{140, 0x51},
	{150, 0x40},
	{160, 0x33},
	{170, 0x28},
	{180, 0x20},
	{190, 0x19},
	{200, 0x14},
	{210, 0x10},
	{220, 0xc},
	{230, 0xa},
	{240, 0x8},
	{250, 0x6},
	{260, 0x5},
	{270, 0x4},
	{280, 0x3},
	{300, 0x2},
	{330, 0x1}, /* 33.0 dB */
	{0, 0}
};

struct gx1133_dbmtable_pair {
	u16 dbm;
	u16 raw;
};

static struct gx1133_dbmtable_pair gx1133_dbmtable[] =  {
	{ 0x3333, 0xfff}, /* 20% */
	{ 0x4CCC, 0x778},
	{ 0x6666, 0x621},
	{ 0x7FFF, 0x55c},
	{ 0x9999, 0x40e},
	{ 0xB332, 0x343},
	{ 0xCCCC, 0x2b7},
	{ 0xE665, 0x231},
	{ 0xFFFF, 0x1a1}, /* 100% */
	{0, 0}
};

/* modfec (modulation and FEC) lookup table */
struct gx1133_modfec {
	enum fe_delivery_system delivery_system;
	enum fe_modulation modulation;
	enum fe_code_rate fec;
};

static struct gx1133_modfec gx1133_modfec_modes[] = {
	{ SYS_DVBS, QPSK, FEC_AUTO },
	{ SYS_DVBS, QPSK, FEC_1_2 },
	{ SYS_DVBS, QPSK, FEC_2_3 },
	{ SYS_DVBS, QPSK, FEC_3_4 },
	{ SYS_DVBS, QPSK, FEC_4_5 },
	{ SYS_DVBS, QPSK, FEC_5_6 },
	{ SYS_DVBS, QPSK, FEC_6_7 },
	{ SYS_DVBS, QPSK, FEC_7_8 },
	{ SYS_DVBS, QPSK, FEC_8_9 },

	{ SYS_DVBS2, QPSK, FEC_1_2 },
	{ SYS_DVBS2, QPSK, FEC_3_5 },
	{ SYS_DVBS2, QPSK, FEC_2_3 },
	{ SYS_DVBS2, QPSK, FEC_3_4 },
	{ SYS_DVBS2, QPSK, FEC_4_5 },
	{ SYS_DVBS2, QPSK, FEC_5_6 },
	{ SYS_DVBS2, QPSK, FEC_8_9 },
	{ SYS_DVBS2, QPSK, FEC_9_10 },

	{ SYS_DVBS2, PSK_8, FEC_3_5 },
	{ SYS_DVBS2, PSK_8, FEC_2_3 },
	{ SYS_DVBS2, PSK_8, FEC_3_4 },
	{ SYS_DVBS2, PSK_8, FEC_5_6 },
	{ SYS_DVBS2, PSK_8, FEC_8_9 },
	{ SYS_DVBS2, PSK_8, FEC_9_10 },

	{ SYS_DVBS2, APSK_16, FEC_2_3 },
	{ SYS_DVBS2, APSK_16, FEC_3_4 },
	{ SYS_DVBS2, APSK_16, FEC_4_5 },
	{ SYS_DVBS2, APSK_16, FEC_5_6 },
	{ SYS_DVBS2, APSK_16, FEC_8_9 },
	{ SYS_DVBS2, APSK_16, FEC_9_10 },

	{ SYS_DVBS2, APSK_32, FEC_3_4 },
	{ SYS_DVBS2, APSK_32, FEC_4_5 },
	{ SYS_DVBS2, APSK_32, FEC_5_6 },
	{ SYS_DVBS2, APSK_32, FEC_8_9 },
	{ SYS_DVBS2, APSK_32, FEC_9_10 },
};

#endif /* GX1133_PRIV_H */
