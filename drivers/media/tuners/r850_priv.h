#ifndef __R850_PRIV_H__
#define __R850_PRIV_H__

#define R850_REG_NUM         48  //R0~R7: read only
#define R850_RING_POWER_FREQ 115000
#define R850_IMR_IF          5300
#define R850_IMR_TRIAL       9
#define R850_IMR_GAIN_REG    20
#define R850_IMR_PHASE_REG   21
#define R850_IMR_IQCAP_REG   21
#define R850_IMR_POINT_NUM  10
#define R850_ADC_READ_COUNT  1

#define  R850_PLL_LOCK_DELAY    10
#define  R850_FILTER_GAIN_DELAY 5
#define  R850_FILTER_CODE_DELAY 5


enum R850_Standard_Type  //Don't remove standand list!!
{
	//DTV
	R850_DVB_T_6M = 0,
	R850_DVB_T_7M,
	R850_DVB_T_8M,
    R850_DVB_T2_6M,       //IF=4.57M
	R850_DVB_T2_7M,       //IF=4.57M
	R850_DVB_T2_8M,       //IF=4.57M
	R850_DVB_T2_1_7M,
	R850_DVB_T2_10M,
	R850_DVB_C_8M,
	R850_DVB_C_6M,
	R850_J83B,
	R850_ISDB_T_4063,           //IF=4.063M
	R850_ISDB_T_4570,           //IF=4.57M
	R850_DTMB_8M_4570,      //IF=4.57M
	R850_DTMB_6M_4500,      //IF=4.5M, BW=6M
	R850_ATSC,
	//DTV IF=5M
	R850_DVB_T_6M_IF_5M,
	R850_DVB_T_7M_IF_5M,
	R850_DVB_T_8M_IF_5M,
	R850_DVB_T2_6M_IF_5M,
	R850_DVB_T2_7M_IF_5M,
	R850_DVB_T2_8M_IF_5M,
	R850_DVB_T2_6M_IF_5M_NORMAL,
	R850_DVB_T2_7M_IF_5M_NORMAL,
	R850_DVB_T2_8M_IF_5M_NORMAL,
	R850_DVB_T2_1_7M_IF_5M,
	R850_DVB_C_8M_IF_5M,
	R850_DVB_C_6M_IF_5M,
	R850_J83B_IF_5M,
	R850_ISDB_T_IF_5M,
	R850_DTMB_8M_IF_5M,
	R850_DTMB_6M_IF_5M,
	R850_ATSC_IF_5M,
	R850_FM,
	R850_STD_SIZE,
};


u8 R850_LPF_CAL_Array[3][R850_REG_NUM] = {   //24M  //16M  //27MHz
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //read only
		0xC0, 0x49, 0x3F, 0x90, 0x13, 0xE1, 0x89, 0x7A,
		0x07, 0xF1, 0x9A, 0x50, 0x30, 0x20, 0xE1, 0x00,
		0x00, 0x04, 0x81, 0x11, 0xEF, 0xEE, 0x17, 0x07,
		0x31, 0x71, 0x54, 0xB2, 0xEE, 0xA9, 0xBB, 0x0B,
		0xA3, 0x00, 0x0B, 0x44, 0x92, 0x1F, 0xE6, 0x80 },
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //read only
		0xC0, 0x49, 0x3F, 0x90, 0x13, 0xE1, 0x89, 0x7A,
		0x07, 0xF1, 0x9A, 0x50, 0x30, 0x20, 0xE1, 0x00,
		0x00, 0x04, 0x81, 0x1C, 0x66, 0x66, 0x16, 0x07,
		0x31, 0x71, 0x94, 0xBB, 0xEE, 0x89, 0xBB, 0x0B,
		0xA3, 0x00, 0x0B, 0x44, 0x92, 0x1F, 0xE6, 0x80 },
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //read only
		0xC0, 0x49, 0x3F, 0x90, 0x13, 0xE1, 0x89, 0x7A,
		0x07, 0xF1, 0x9A, 0x50, 0x30, 0x20, 0xE1, 0x00,
		0x00, 0x04, 0x81, 0x11, 0xEF, 0xEE, 0x17, 0x07,
		0x31, 0x71, 0x54, 0xB0, 0xEE, 0xA9, 0xBB, 0x0B,
		0xA3, 0x00, 0x0B, 0x44, 0x92, 0x1F, 0xE6, 0x80 }
};
//IMR Cal array 544MHz(24MHz)
u8 R850_IMR_CAL_Array[3][R850_REG_NUM] = {   //24M  //16M  //27MHz
	{  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //read only
		0xC0, 0x49, 0x3A, 0x90, 0x03, 0xC1, 0x61, 0x71,
		0x17, 0xF1, 0x18, 0x55, 0x30, 0x20, 0xF3, 0xED,
		0x1F, 0x1C, 0x81, 0x13, 0x00, 0x80, 0x0A, 0x07,
		0x21, 0x71, 0x54, 0xF1, 0xF2, 0xA9, 0xBB, 0x0B,
		0xA3, 0xF6, 0x0B, 0x44, 0x92, 0x17, 0xE6, 0x80 },
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //read only
		0xC0, 0x49, 0x3A, 0x90, 0x03, 0xC1, 0x61, 0x71,
		0x17, 0xF1, 0x18, 0x55, 0x30, 0x20, 0xF3, 0xED,
		0x1F, 0x1C, 0x81, 0x13, 0x00, 0x80, 0x0A, 0x07,
		0x21, 0x71, 0x94, 0xF1, 0xF2, 0x89, 0xBB, 0x0B,
		0xA3, 0xF6, 0x0B, 0x44, 0x92, 0x17, 0xE6, 0x80
	},
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //read only
		0xC0, 0x49, 0x3A, 0x90, 0x03, 0xC1, 0x61, 0x71,
		0x17, 0xF1, 0x18, 0x55, 0x30, 0x20, 0xF3, 0xED,
		0x1F, 0x1C, 0x81, 0x13, 0x00, 0x80, 0x0A, 0x07,
		0x21, 0x71, 0x54, 0xF1, 0xF2, 0xA9, 0xBB, 0x0B,
		0xA3, 0xF6, 0x0B, 0x44, 0x92, 0x17, 0xE6, 0x80 }

};

 u16 R850_Lna_Acc_Gain[4][32] =
{
	{0, 13, 24, 36, 49, 62, 76, 90, 105, 120, 135, 151, 163, 177, 191, 207, 222, 235, 249, 258, 267, 267, 267, 267, 267, 275, 286, 300, 316, 332, 329, 343},
	{0, 12, 23, 35, 48, 62, 77, 91, 107, 125, 142, 161, 171, 182, 194, 208, 220, 230, 242, 248, 255, 255, 255, 255, 255, 270, 285, 303, 320, 335, 321, 338},
	{0, 12, 24, 36, 50, 66, 81, 98, 117, 137, 158, 182, 192, 202, 213, 223, 232, 238, 244, 248, 251, 251, 251, 251, 251, 265, 280, 297, 312, 325, 318, 341},
	{0, 11, 23, 35, 49, 64, 80, 96, 114, 134, 153, 173, 184, 193, 202, 209, 215, 220, 222, 225, 227, 227, 227, 227, 227, 240, 254, 268, 281, 292, 307, 323},
};

 s8 Lna_Acc_Gain_offset[86]={6,  4, 4, 3, 3, 4, 3, 2, 2, 1,	//45~145
	0, -2, -3, -5, -6, -7, -10, -9, -9, -10,	//145~245
	-9, -9, -8, -8, -6, -4, -3, -1, -1, 0,	//245~345
	8, 10, 10, 11, 11, 9, 10, 8, 4, 4,	//345~445
	1, 0, 0, -2, -2, -2, -2, -2, -1, -2,	//445~545
	0, 3, 2, 4, -2, 6, 6, 4, 3, 4,	//545~645
	2, 0, -2, -4, -5, -7, 10, 7, 6, 4,	//645~745
	3, 2, 1, 0, -1, -1, -2, -2, -1, -2, //745~845
	-1, -2, -2, -2, -2, -3};	

 u16 R850_Rf_Acc_Gain[16] =
{
	0, 15, 31, 46, 58, 58, 58, 58, 58, 72,			//0~9
	86, 99, 113, 113, 124, 134						//10~15
};

 u16 R850_Mixer_Acc_Gain[16] =
{
	0, 0, 0, 0, 10, 22, 34, 46, 58, 70,			//0~9
	82, 93, 102, 122, 142, 142						//10~12
};

 u8 R850_iniArray[3][R850_REG_NUM] = {
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //24M initial frequency = 775MHz (LO)
		//   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
		//      0,    1,    2,    3,    4,    5,    6,    7
		0xCA, 0xC0, 0x72, 0x50, 0x00, 0xE0, 0x00, 0x30,
		//   0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
		//	  8,    9,   10,   11,   12,   13,   14,   15
		0x86, 0xBB, 0xF8, 0xB0, 0xD2, 0x81, 0xCD, 0x46,
		//   0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17
		//	 16,   17,   18,   19,   20,   21,   22,   23
		0x37, 0x40, 0x89, 0x8C, 0x55, 0x95, 0x07, 0x23,
		//   0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
		//	 24,   25,   26,   27,   28,   29,   30,   31,
		0x21, 0xF1, 0x4C, 0x5F, 0xC4, 0x20, 0xA9, 0x6C,
		//   0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27
		//     32,   33,   34,   35,   36,   37,   38,   39
		0x53, 0xAB, 0x5B, 0x46, 0xB3, 0x93, 0x6E, 0x41 },
	//   0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
	//	 40,   41,   42,   43,   44,   45,   46,   47
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //16M initial frequency = 775MHz  (LO)
		//   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
		//      0,    1,    2,    3,    4,    5,    6,    7
		0xCA, 0xC0, 0x72, 0x50, 0x00, 0xE0, 0x01, 0x30,
		//   0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
		//	  8,    9,   10,   11,   12,   13,   14,   15
		0x06, 0xBB, 0xF8, 0xB0, 0xF0, 0x61, 0xCD, 0x14,
		//   0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17
		//	 16,   17,   18,   19,   20,   21,   22,   23
		0x37, 0x42, 0x81, 0x92, 0x00, 0xE0, 0x07, 0x23,
		//   0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
		//	 24,   25,   26,   27,   28,   29,   30,   31,
		0x21, 0xF1, 0x8C, 0x5F, 0xC4, 0x00, 0xA9, 0x6C,
		//   0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27
		//     32,   33,   34,   35,   36,   37,   38,   39
		0x31, 0xAB, 0x5A, 0x47, 0xB3, 0x93, 0xE9, 0x41 },
	//   0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
	//	 40,   41,   42,   43,   44,   45,   46,   47
	{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  //27M initial frequency = 780MHz  (LO)
		//   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
		//      0,    1,    2,    3,    4,    5,    6,    7
		0xCA, 0xC0, 0x72, 0x50, 0x00, 0xE0, 0x00, 0x30,
		//   0x08  0x09  0x0A  0x0B  0x0C  0x0D  0x0E  0x0F
		//	  8,    9,   10,   11,   12,   13,   14,   15
		0x86, 0xBB, 0xF8, 0xB0, 0xD2, 0x81, 0xCD, 0x46,
		//   0x10  0x11  0x12  0x13  0x14  0x15  0x16  0x17
		//	 16,   17,   18,   19,   20,   21,   22,   23
		0x37, 0x40, 0x89, 0x8B, 0x4B, 0x68, 0x04, 0x23,
		//   0x18  0x19  0x1A  0x1B  0x1C  0x1D  0x1E  0x1F
		//	 24,   25,   26,   27,   28,   29,   30,   31,
		0x21, 0xF1, 0x4C, 0x5F, 0xC4, 0x20, 0xA9, 0x6C,
		//   0x20  0x21  0x22  0x23  0x24  0x25  0x26  0x27
		//     32,   33,   34,   35,   36,   37,   38,   39
		0x53, 0xAB, 0x5B, 0x46, 0xB3, 0x93, 0x6E, 0x41 }
	//   0x28  0x29  0x2A  0x2B  0x2C  0x2D  0x2E  0x2F
	//	 40,   41,   42,   43,   44,   45,   46,   47
};
 u8 R850_Fil_Cal_BW_def[R850_STD_SIZE]={
	3, 2, 2, 3, 2, 2, 2, 0,           //{DVB_T_6M, DVB_T_7M, DVB_T_8M, DVB_T2_6M, DVB_T2_7M, DVB_T2_8M, DVB_T2_1_7M, DVB_T2_10M}
	     0, 2, 2, 3, 2, 2, 3, 2,           //{DVB_C_8M, DVB_C_6M, J83B, ISDB_T_4063, ISDB_T_4570, DTMB_8M_4570, DTMB_6M_4500, ATSC}
	     2, 2, 0, 2, 2, 0, 3,              //{DVB_T_6M, DVB_T_7M, DVB_T_8M, DVB_T2_6M, DVB_T2_7M, DVB_T2_8M, DVB_T2_1_7M, DVB_T2_10M} (IF 5M)
	     0, 2, 2, 2, 0, 2, 2, 2            //{DVB_C_8M, DVB_C_6M, J83B, ISDB_T_4063, ISDB_T_4570, DTMB_8M_4570, DTMB_6M_4500, ATSC} (IF 5M), FM
};
 u8 R850_Fil_Cal_code_def[R850_STD_SIZE]={
	3,  8,  2,  3,  8,  2,  8,  0,             //{DVB_T_6M, DVB_T_7M, DVB_T_8M, DVB_T2_6M, DVB_T2_7M, DVB_T2_8M, DVB_T2_1_7M, DVB_T2_10M}
	     8,  4,  7,  5, 16,  1,  5,  6,             //{DVB_C_8M, DVB_C_6M, J83B, ISDB_T_4063, ISDB_T_4570, DTMB_8M_4570, DTMB_6M_4500, ATSC}
	     13,  1, 13, 13,  1, 13, 23,                 //{DVB_T_6M, DVB_T_7M, DVB_T_8M, DVB_T2_6M, DVB_T2_7M, DVB_T2_8M, DVB_T2_1_7M, DVB_T2_10M} (IF 5M)
	     11,  3, 11, 10, 11,  9,  8, 17              //{DVB_C_8M, DVB_C_6M, J83B, ISDB_T_4063, ISDB_T_4570, DTMB_8M_4570, DTMB_6M_4500, ATSC} (IF 5M), FM
};

typedef enum _R850_ErrCode
{
	R850_Success = TRUE,
	R850_Fail = FALSE
}R850_ErrCode;

enum R850_Cal_Type
{
	R850_IMR_CAL = 0,
	R850_IMR_LNA_CAL,
	R850_LPF_CAL,
	R850_LPF_LNA_CAL
};


struct R850_SectType
{
	u8   Phase_Y;
	u8   Gain_X;
	u8   Iqcap;
	u8   Value;
};

enum R850_XTAL_PWR_VALUE
{
	R850_XTAL_LOWEST = 0,
    R850_XTAL_LOW,
    R850_XTAL_HIGH,
    R850_XTAL_HIGHEST,
	R850_XTAL_CHECK_SIZE
};

enum R850_Xtal_Div_TYPE
{
	R850_XTAL_DIV1 = 0,
	R850_XTAL_DIV1_2,	//1st_div2=0(R34[0]), 2nd_div2=1(R34[1])  ; same AGC clock
	R850_XTAL_DIV2_1,	//1st_div2=1(R34[0]), 2nd_div2=0(R34[1])  ; diff AGC clock
	R850_XTAL_DIV4
};

struct R850_Sys_Info_Type
{
	u8          BW;
	u8		   HPF_COR;
	u8          FILT_EXT_ENA;
	u8          HPF_NOTCH;
	u8          AGC_CLK;
	u8          IMG_GAIN;
	u16		   FILT_COMP;
	u16		   IF_KHz;
	u16		   FILT_CAL_IF;
};

struct R850_Freq_Info_Type
{
	u8		RF_POLY;
	u8		LNA_BAND;
	u8		LPF_CAP;
	u8		LPF_NOTCH;
	u8		TF_DIPLEXER;
	u8		TF_HPF_BPF;
	u8		TF_HPF_CNR;
	u8		IMR_MEM_NOR;
	u8		IMR_MEM_REV;
	u8       TEMP;
};

struct R850_SysFreq_Info_Type
{
	u8	   LNA_TOP;
	u8	   LNA_VTL_H;
	u8      RF_TOP;
	u8      RF_VTL_H;
	u8      RF_GAIN_LIMIT;
	u8      NRB_TOP;
	u8      NRB_BW_HPF;
	u8      NRB_BW_LPF;
	u8	   MIXER_TOP;
	u8	   MIXER_VTH;
	u8	   MIXER_VTL;
	u8      MIXER_GAIN_LIMIT;
	u8      FILTER_TOP;
	u8      FILTER_VTH;
	u8      FILTER_VTL;
	u8      LNA_RF_DIS_MODE;
	u8      LNA_RF_DIS_CURR;
	u8      LNA_DIS_SLOW_FAST;
	u8      RF_DIS_SLOW_FAST;
	u8      BB_DET_MODE;
	u8      BB_DIS_CURR;
	u8      MIXER_FILTER_DIS;
	u8      IMG_NRB_ADDER;
	u8      LNA_NRB_DET;
	u8      ENB_POLY_GAIN;
	u8	   MIXER_AMP_LPF;
	u8	   NA_PWR_DET;
	u8	   FILT_3TH_LPF_CUR;
	u8	   FILT_3TH_LPF_GAIN;
	u8	   RF_LTE_PSG;
	u8	   HPF_COMP;
	u8	   FB_RES_1ST;
	u8	   MIXER_DETBW_LPF;
	u8	   LNA_RF_CHARGE_CUR;
//NA
	u8	   DEGLITCH_CLK;
	u8	   NAT_HYS;
	u8	   NAT_CAIN;
	u8	   PULSE_HYS;
	u8	   FAST_DEGLITCH;
	u8	   PUL_RANGE_SEL;
	u8	   PUL_FLAG_RANGE;
	u8      PULG_CNT_THRE;
	u8	   FORCE_PULSE;
	u8	   FLG_CNT_CLK;
	u8	   NATG_OFFSET;

	u8      TEMP;
};

struct R850_filer_cal{
	u8 flag;
	u8 code;
	u8 bw;
	u8 lpflsb;

};
struct I2C_LEN_TYPE
{
	u8 RegAddr;
	u8 Data[50];
	u8 Len;
};
enum R850_LoopThrough_Type
{
	R850_LT_ON = TRUE,
	R850_LT_OFF= FALSE
};

enum R850_ClkOutMode_Type
{
	R850_CLK_OUT_OFF = 0,
	R850_CLK_OUT_ON
};

struct R850_Set_Info
{
	u32                   RF_KHz;
	enum R850_Standard_Type       R850_Standard;
	enum R850_LoopThrough_Type    R850_LT;
	enum R850_ClkOutMode_Type     R850_ClkOutMode;
};

struct R850_RF_Gain_Info
{
	u16  RF_gain_comb;
	u8   RF_gain1;
	u8   RF_gain2;
	u8   RF_gain3;
	u8   RF_gain4;
};

struct r850_priv {
	struct r850_config 		*cfg;
	struct i2c_adapter 		*i2c;
	u8 				inited;


	u8 				regs[R850_REG_NUM];
	struct I2C_LEN_TYPE R850_I2C_Len ;
	
	struct R850_SectType	imr_data[R850_IMR_POINT_NUM];
	u8 R850_IMR_Cal_Result;
	u8 R850_IMR_done_flag;

	u8 R850_clock_out;
	u8 R850_Xtal_cap;
	u8 R850_Xtal_Pwr;
	u8 R850_XtalDiv;

	/* tune settings */
	u32				freq;		/* kHz */
	u32 R850_IF_GOLOBAL;

	struct R850_filer_cal		fc;

	
	struct R850_Sys_Info_Type R850_Sys_Info;

};

#endif //__R850_PRIV_H__
