//SPX-License-Identifier: GPL-2.0-or-later
/*
 * Montage Technology M88rs6060 demodulator and tuner drivers
 * some code form m88ds3103
 * Copyright (c) 2021 Davin zhang <Davin@tbsdtv.com> www.Turbosight.com
 *
*/
#include <media/dvb_math.h>

#include "m88rs6060_priv.h"
#include <linux/mutex.h>
#define HWTUNE

static LIST_HEAD(m88rs6060list);
static LIST_HEAD(si5351list);
struct si5351_base{
	struct list_head si5351list;
	struct i2c_adapter *i2c_si5351;	// i2c
	struct mutex i2c_mutex_ci;

	u32	count;
	int clk_port;
};

//for CI
struct si5351_priv{
	struct si5351_base *base1;
	int clk_port;
	u32 plla_freq;
	u32 pllb_freq;
};
struct m88rs6060_base{
	struct list_head m88rs6060list;
	struct mutex i2c_mutex;
	struct i2c_adapter *i2c;	// i2c
	u8 adr;
	u32	count;
//	struct i2c_client *tuner_client;	//tuner i2c

};

struct m88rs6060_dev {
	struct regmap *regmap;	//demod
	enum fe_status fe_status;
	struct dvb_frontend fe;
	struct m88rs6060_cfg config;

	bool TsClockChecked;  //clock retio
	bool warm;		// for the init and download fw
	s32 mclk;		/*main mclk */

	u32 dvbv3_ber;		/* for old DVBv3 API read_ber */
	u32 frequecy;    //khz
	u64 post_bit_error;
	u64 post_bit_count;
	struct m88rs6060_base *base;
	struct si5351_priv *priv;

	bool newTP;
	
};

static u16 mes_log10[] = {
	0, 3010, 4771, 6021, 6990, 7781, 8451, 9031, 9542, 10000,
	10414, 10792, 11139, 11461, 11761, 12041, 12304, 12553, 12788, 13010,
	13222, 13424, 13617, 13802, 13979, 14150, 14314, 14472, 14624, 14771,
	14914, 15052, 15185, 15315, 15441, 15563, 15682, 15798, 15911, 16021,
	16128, 16232, 16335, 16435, 16532, 16628, 16721, 16812, 16902, 16990,
	17076, 17160, 17243, 17324, 17404, 17482, 17559, 17634, 17709, 17782,
	17853, 17924, 17993, 18062, 18129, 18195, 18261, 18325, 18388, 18451,
	18513, 18573, 18633, 18692, 18751, 18808, 18865, 18921, 18976, 19031
};

static u16 mes_loge[] = {
	0, 6931, 10986, 13863, 16094, 17918, 19459, 20794, 21972, 23026,
	23979, 24849, 25649, 26391, 27081, 27726, 28332, 28904, 29444, 29957,
	30445, 30910, 31355, 31781, 32189, 32581, 32958, 33322, 33673, 34012,
	34340, 34657
};

static  struct MT_FE_PLS_INFO mPLSInfoTable[] = 
 {
 //   PLS Code,   Valid,  DVB Type, 		  Mod Mode, 			  Code Rate,			  Pilot,  Dummy Frames,  Frame Length
	 {0x00, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  TRUE, 		 0},
	 {0x01, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   TRUE, 		 0},
	 {0x02, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  TRUE, 		 1},
	 {0x03, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   TRUE, 		 1},
	 {0x04, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_4, 	  FALSE,  FALSE,		 0},
	 {0x05, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_4, 	  TRUE,   FALSE,		 0},
	 {0x06, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_4, 	  FALSE,  FALSE,		 1},
	 {0x07, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_4, 	  TRUE,   FALSE,		 1},
	 {0x08, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_3, 	  FALSE,  FALSE,		 0},
	 {0x09, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_3, 	  TRUE,   FALSE,		 0},
	 {0x0A, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_3, 	  FALSE,  FALSE,		 1},
	 {0x0B, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_3, 	  TRUE,   FALSE,		 1},
	 {0x0C, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_2_5, 	  FALSE,  FALSE,		 0},
	 {0x0D, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_2_5, 	  TRUE,   FALSE,		 0},
	 {0x0E, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_2_5, 	  FALSE,  FALSE,		 1},
	 {0x0F, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_2_5, 	  TRUE,   FALSE,		 1},
	 {0x10, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_2, 	  FALSE,  FALSE,		 0},
	 {0x11, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_2, 	  TRUE,   FALSE,		 0},
	 {0x12, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_2, 	  FALSE,  FALSE,		 1},
	 {0x13, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_1_2, 	  TRUE,   FALSE,		 1},
	 {0x14, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_3_5, 	  FALSE,  FALSE,		 0},
	 {0x15, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_3_5, 	  TRUE,   FALSE,		 0},
	 {0x16, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_3_5, 	  FALSE,  FALSE,		 1},
	 {0x17, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_3_5, 	  TRUE,   FALSE,		 1},
	 {0x18, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_2_3, 	  FALSE,  FALSE,		 0},
	 {0x19, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_2_3, 	  TRUE,   FALSE,		 0},
	 {0x1A, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_2_3, 	  FALSE,  FALSE,		 1},
	 {0x1B, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_2_3, 	  TRUE,   FALSE,		 1},
	 {0x1C, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_3_4, 	  FALSE,  FALSE,		 0},
	 {0x1D, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_3_4, 	  TRUE,   FALSE,		 0},
	 {0x1E, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_3_4, 	  FALSE,  FALSE,		 1},
	 {0x1F, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_3_4, 	  TRUE,   FALSE,		 1},
 //   PLS Code,   Valid,  DVB Type, 		  Mod Mode, 			  Code Rate,			  Pilot,  Dummy Frames,  Frame Length
	 {0x20, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_4_5, 	  FALSE,  FALSE,		 0},
	 {0x21, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_4_5, 	  TRUE,   FALSE,		 0},
	 {0x22, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_4_5, 	  FALSE,  FALSE,		 1},
	 {0x23, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_4_5, 	  TRUE,   FALSE,		 1},
	 {0x24, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_5_6, 	  FALSE,  FALSE,		 0},
	 {0x25, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_5_6, 	  TRUE,   FALSE,		 0},
	 {0x26, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_5_6, 	  FALSE,  FALSE,		 1},
	 {0x27, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_5_6, 	  TRUE,   FALSE,		 1},
	 {0x28, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_8_9, 	  FALSE,  FALSE,		 0},
	 {0x29, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_8_9, 	  TRUE,   FALSE,		 0},
	 {0x2A, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_8_9, 	  FALSE,  FALSE,		 1},
	 {0x2B, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_8_9, 	  TRUE,   FALSE,		 1},
	 {0x2C, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_9_10,	  FALSE,  FALSE,		 0},
	 {0x2D, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_9_10,	  TRUE,   FALSE,		 0},
	 {0x2E, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_9_10,	  FALSE,  FALSE,		 1},
	 {0x2F, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_9_10,	  TRUE,   FALSE,		 1},
	 {0x30, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_3_5, 	  FALSE,  FALSE,		 0},
	 {0x31, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_3_5, 	  TRUE,   FALSE,		 0},
	 {0x32, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_3_5, 	  FALSE,  FALSE,		 1},
	 {0x33, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_3_5, 	  TRUE,   FALSE,		 1},
	 {0x34, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_2_3, 	  FALSE,  FALSE,		 0},
	 {0x35, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_2_3, 	  TRUE,   FALSE,		 0},
	 {0x36, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_2_3, 	  FALSE,  FALSE,		 1},
	 {0x37, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_2_3, 	  TRUE,   FALSE,		 1},
	 {0x38, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_3_4, 	  FALSE,  FALSE,		 0},
	 {0x39, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_3_4, 	  TRUE,   FALSE,		 0},
	 {0x3A, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_3_4, 	  FALSE,  FALSE,		 1},
	 {0x3B, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_3_4, 	  TRUE,   FALSE,		 1},
	 {0x3C, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_5_6, 	  FALSE,  FALSE,		 0},
	 {0x3D, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_5_6, 	  TRUE,   FALSE,		 0},
	 {0x3E, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_5_6, 	  FALSE,  FALSE,		 1},
	 {0x3F, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_5_6, 	  TRUE,   FALSE,		 1},
 //   PLS Code,   Valid,  DVB Type, 		  Mod Mode, 			  Code Rate,			  Pilot,  Dummy Frames,  Frame Length
	 {0x40, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_8_9, 	  FALSE,  FALSE,		 0},
	 {0x41, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_8_9, 	  TRUE,   FALSE,		 0},
	 {0x42, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_8_9, 	  FALSE,  FALSE,		 1},
	 {0x43, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_8_9, 	  TRUE,   FALSE,		 1},
	 {0x44, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_9_10,	  FALSE,  FALSE,		 0},
	 {0x45, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_9_10,	  TRUE,   FALSE,		 0},
	 {0x46, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_9_10,	  FALSE,  FALSE,		 1},
	 {0x47, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_8psk, 	  MtFeCodeRate_9_10,	  TRUE,   FALSE,		 1},
	 {0x48, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_2_3, 	  FALSE,  FALSE,		 0},
	 {0x49, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_2_3, 	  TRUE,   FALSE,		 0},
	 {0x4A, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_2_3, 	  FALSE,  FALSE,		 1},
	 {0x4B, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_2_3, 	  TRUE,   FALSE,		 1},
	 {0x4C, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_3_4, 	  FALSE,  FALSE,		 0},
	 {0x4D, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_3_4, 	  TRUE,   FALSE,		 0},
	 {0x4E, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_3_4, 	  FALSE,  FALSE,		 1},
	 {0x4F, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_3_4, 	  TRUE,   FALSE,		 1},
	 {0x50, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_4_5, 	  FALSE,  FALSE,		 0},
	 {0x51, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_4_5, 	  TRUE,   FALSE,		 0},
	 {0x52, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_4_5, 	  FALSE,  FALSE,		 1},
	 {0x53, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_4_5, 	  TRUE,   FALSE,		 1},
	 {0x54, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_5_6, 	  FALSE,  FALSE,		 0},
	 {0x55, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_5_6, 	  TRUE,   FALSE,		 0},
	 {0x56, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_5_6, 	  FALSE,  FALSE,		 1},
	 {0x57, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_5_6, 	  TRUE,   FALSE,		 1},
	 {0x58, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_8_9, 	  FALSE,  FALSE,		 0},
	 {0x59, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_8_9, 	  TRUE,   FALSE,		 0},
	 {0x5A, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_8_9, 	  FALSE,  FALSE,		 1},
	 {0x5B, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_8_9, 	  TRUE,   FALSE,		 1},
	 {0x5C, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_9_10,	  FALSE,  FALSE,		 0},
	 {0x5D, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_9_10,	  TRUE,   FALSE,		 0},
	 {0x5E, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_9_10,	  FALSE,  FALSE,		 1},
	 {0x5F, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_16Apsk,	  MtFeCodeRate_9_10,	  TRUE,   FALSE,		 1},
 //   PLS Code,   Valid,  DVB Type, 		  Mod Mode, 			  Code Rate,			  Pilot,  Dummy Frames,  Frame Length
	 {0x60, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_3_4, 	  FALSE,  FALSE,		 0},
	 {0x61, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_3_4, 	  TRUE,   FALSE,		 0},
	 {0x62, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_3_4, 	  FALSE,  FALSE,		 1},
	 {0x63, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_3_4, 	  TRUE,   FALSE,		 1},
	 {0x64, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_4_5, 	  FALSE,  FALSE,		 0},
	 {0x65, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_4_5, 	  TRUE,   FALSE,		 0},
	 {0x66, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_4_5, 	  FALSE,  FALSE,		 1},
	 {0x67, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_4_5, 	  TRUE,   FALSE,		 1},
	 {0x68, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_5_6, 	  FALSE,  FALSE,		 0},
	 {0x69, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_5_6, 	  TRUE,   FALSE,		 0},
	 {0x6A, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_5_6, 	  FALSE,  FALSE,		 1},
	 {0x6B, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_5_6, 	  TRUE,   FALSE,		 1},
	 {0x6C, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_8_9, 	  FALSE,  FALSE,		 0},
	 {0x6D, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_8_9, 	  TRUE,   FALSE,		 0},
	 {0x6E, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_8_9, 	  FALSE,  FALSE,		 1},
	 {0x6F, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_8_9, 	  TRUE,   FALSE,		 1},
	 {0x70, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_9_10,	  FALSE,  FALSE,		 0},
	 {0x71, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_9_10,	  TRUE,   FALSE,		 0},
	 {0x72, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_9_10,	  FALSE,  FALSE,		 1},
	 {0x73, 	  TRUE,   MtFeType_DvbS2,	  MtFeModMode_32Apsk,	  MtFeCodeRate_9_10,	  TRUE,   FALSE,		 1},
	 {0x74, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0x75, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0x76, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 1},
	 {0x77, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 1},
	 {0x78, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0x79, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0x7A, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 1},
	 {0x7B, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 1},
	 {0x7C, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0x7D, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0x7E, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 1},
	 {0x7F, 	  FALSE,  MtFeType_DvbS2,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 1},
 //   PLS Code,   Valid,  DVB Type, 		  Mod Mode, 			  Code Rate,			  Pilot,  Dummy Frames,  Frame Length
	 {0x80, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0x81, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0x82, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0x83, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0x84, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_13_45,	  FALSE,  FALSE,		 0},
	 {0x85, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_13_45,	  TRUE,   FALSE,		 0},
	 {0x86, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_9_20,	  FALSE,  FALSE,		 0},
	 {0x87, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_9_20,	  TRUE,   FALSE,		 0},
	 {0x88, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_11_20,	  FALSE,  FALSE,		 0},
	 {0x89, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_11_20,	  TRUE,   FALSE,		 0},
	 {0x8A, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8Apsk_L,	  MtFeCodeRate_5_9, 	  FALSE,  FALSE,		 0},
	 {0x8B, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8Apsk_L,	  MtFeCodeRate_5_9, 	  TRUE,   FALSE,		 0},
	 {0x8C, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8Apsk_L,	  MtFeCodeRate_26_45,	  FALSE,  FALSE,		 0},
	 {0x8D, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8Apsk_L,	  MtFeCodeRate_26_45,	  TRUE,   FALSE,		 0},
	 {0x8E, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_23_36,	  FALSE,  FALSE,		 0},
	 {0x8F, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_23_36,	  TRUE,   FALSE,		 0},
	 {0x90, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_25_36,	  FALSE,  FALSE,		 0},
	 {0x91, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_25_36,	  TRUE,   FALSE,		 0},
	 {0x92, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_13_18,	  FALSE,  FALSE,		 0},
	 {0x93, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_13_18,	  TRUE,   FALSE,		 0},
	 {0x94, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk_L,   MtFeCodeRate_1_2, 	  FALSE,  FALSE,		 0},
	 {0x95, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk_L,   MtFeCodeRate_1_2, 	  TRUE,   FALSE,		 0},
	 {0x96, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk_L,   MtFeCodeRate_8_15,	  FALSE,  FALSE,		 0},
	 {0x97, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk_L,   MtFeCodeRate_8_15,	  TRUE,   FALSE,		 0},
	 {0x98, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk_L,   MtFeCodeRate_5_9, 	  FALSE,  FALSE,		 0},
	 {0x99, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk_L,   MtFeCodeRate_5_9, 	  TRUE,   FALSE,		 0},
	 {0x9A, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_26_45,	  FALSE,  FALSE,		 0},
	 {0x9B, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_26_45,	  TRUE,   FALSE,		 0},
	 {0x9C, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_3_5, 	  FALSE,  FALSE,		 0},
	 {0x9D, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_3_5, 	  TRUE,   FALSE,		 0},
	 {0x9E, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk_L,   MtFeCodeRate_3_5, 	  FALSE,  FALSE,		 0},
	 {0x9F, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk_L,   MtFeCodeRate_3_5, 	  TRUE,   FALSE,		 0},
 //   PLS Code,   Valid,  DVB Type, 		  Mod Mode, 			  Code Rate,			  Pilot,  Dummy Frames,  Frame Length
	 {0xA0, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_28_45,	  FALSE,  FALSE,		 0},
	 {0xA1, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_28_45,	  TRUE,   FALSE,		 0},
	 {0xA2, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_23_36,	  FALSE,  FALSE,		 0},
	 {0xA3, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_23_36,	  TRUE,   FALSE,		 0},
	 {0xA4, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk_L,   MtFeCodeRate_2_3, 	  FALSE,  FALSE,		 0},
	 {0xA5, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk_L,   MtFeCodeRate_2_3, 	  TRUE,   FALSE,		 0},
	 {0xA6, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_25_36,	  FALSE,  FALSE,		 0},
	 {0xA7, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_25_36,	  TRUE,   FALSE,		 0},
	 {0xA8, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_13_18,	  FALSE,  FALSE,		 0},
	 {0xA9, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_13_18,	  TRUE,   FALSE,		 0},
	 {0xAA, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_7_9, 	  FALSE,  FALSE,		 0},
	 {0xAB, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_7_9, 	  TRUE,   FALSE,		 0},
	 {0xAC, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_77_90,	  FALSE,  FALSE,		 0},
	 {0xAD, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_77_90,	  TRUE,   FALSE,		 0},
	 {0xAE, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk_L,   MtFeCodeRate_2_3, 	  FALSE,  FALSE,		 0},
	 {0xAF, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk_L,   MtFeCodeRate_2_3, 	  TRUE,   FALSE,		 0},
	 {0xB0, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0xB1, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0xB2, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk,	  MtFeCodeRate_32_45,	  FALSE,  FALSE,		 0},
	 {0xB3, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk,	  MtFeCodeRate_32_45,	  TRUE,   FALSE,		 0},
	 {0xB4, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk,	  MtFeCodeRate_11_15,	  FALSE,  FALSE,		 0},
	 {0xB5, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk,	  MtFeCodeRate_11_15,	  TRUE,   FALSE,		 0},
	 {0xB6, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk,	  MtFeCodeRate_7_9, 	  FALSE,  FALSE,		 0},
	 {0xB7, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk,	  MtFeCodeRate_7_9, 	  TRUE,   FALSE,		 0},
	 {0xB8, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_64Apsk_L,   MtFeCodeRate_32_45,	  FALSE,  FALSE,		 0},
	 {0xB9, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_64Apsk_L,   MtFeCodeRate_32_45,	  TRUE,   FALSE,		 0},
	 {0xBA, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_64Apsk,	  MtFeCodeRate_11_15,	  FALSE,  FALSE,		 0},
	 {0xBB, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_64Apsk,	  MtFeCodeRate_11_15,	  TRUE,   FALSE,		 0},
	 {0xBC, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0xBD, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0xBE, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_64Apsk,	  MtFeCodeRate_7_9, 	  FALSE,  FALSE,		 0},
	 {0xBF, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
 //   PLS Code,   Valid,  DVB Type, 		  Mod Mode, 			  Code Rate,			  Pilot,  Dummy Frames,  Frame Length
	 {0xC0, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0xC1, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0xC2, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_64Apsk,	  MtFeCodeRate_4_5, 	  FALSE,  FALSE,		 0},
	 {0xC3, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_64Apsk,	  MtFeCodeRate_4_5, 	  TRUE,   FALSE,		 0},
	 {0xC4, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0xC5, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0xC6, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_64Apsk,	  MtFeCodeRate_5_6, 	  FALSE,  FALSE,		 0},
	 {0xC7, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_64Apsk,	  MtFeCodeRate_5_6, 	  TRUE,   FALSE,		 0},
	 {0xC8, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_128Apsk,	  MtFeCodeRate_3_4, 	  FALSE,  FALSE,		 0},
	 {0xC9, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_128Apsk,	  MtFeCodeRate_3_4, 	  TRUE,   FALSE,		 0},
	 {0xCA, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_128Apsk,	  MtFeCodeRate_7_9, 	  FALSE,  FALSE,		 0},
	 {0xCB, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_128Apsk,	  MtFeCodeRate_7_9, 	  TRUE,   FALSE,		 0},
	 {0xCC, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk_L,  MtFeCodeRate_29_45,	  FALSE,  FALSE,		 0},
	 {0xCD, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk_L,  MtFeCodeRate_29_45,	  TRUE,   FALSE,		 0},
	 {0xCE, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk_L,  MtFeCodeRate_2_3, 	  FALSE,  FALSE,		 0},
	 {0xCF, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk_L,  MtFeCodeRate_2_3, 	  TRUE,   FALSE,		 0},
	 {0xD0, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk_L,  MtFeCodeRate_31_45,	  FALSE,  FALSE,		 0},
	 {0xD1, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk_L,  MtFeCodeRate_31_45,	  TRUE,   FALSE,		 0},
	 {0xD2, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk,	  MtFeCodeRate_32_45,	  FALSE,  FALSE,		 0},
	 {0xD3, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk,	  MtFeCodeRate_32_45,	  TRUE,   FALSE,		 0},
	 {0xD4, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk_L,  MtFeCodeRate_11_15,	  FALSE,  FALSE,		 0},
	 {0xD5, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk_L,  MtFeCodeRate_11_15,	  TRUE,   FALSE,		 0},
	 {0xD6, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk,	  MtFeCodeRate_3_4, 	  FALSE,  FALSE,		 0},
	 {0xD7, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_256Apsk,	  MtFeCodeRate_3_4, 	  TRUE,   FALSE,		 1},
	 {0xD8, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_11_45,	  FALSE,  FALSE,		 1},
	 {0xD9, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_11_45,	  TRUE,   FALSE,		 1},
	 {0xDA, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_4_15,	  FALSE,  FALSE,		 1},
	 {0xDB, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_4_15,	  TRUE,   FALSE,		 1},
	 {0xDC, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_14_45,	  FALSE,  FALSE,		 1},
	 {0xDD, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_14_45,	  TRUE,   FALSE,		 1},
	 {0xDE, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_7_15,	  FALSE,  FALSE,		 1},
	 {0xDF, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_7_15,	  TRUE,   FALSE,		 1},
 //   PLS Code,   Valid,  DVB Type, 		  Mod Mode, 			  Code Rate,			  Pilot,  Dummy Frames,  Frame Length
	 {0xE0, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_8_15,	  FALSE,  FALSE,		 1},
	 {0xE1, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_8_15,	  TRUE,   FALSE,		 1},
	 {0xE2, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_32_45,	  FALSE,  FALSE,		 1},
	 {0xE3, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_Qpsk, 	  MtFeCodeRate_32_45,	  TRUE,   FALSE,		 1},
	 {0xE4, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_7_15,	  FALSE,  FALSE,		 1},
	 {0xE5, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_7_15,	  TRUE,   FALSE,		 1},
	 {0xE6, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_8_15,	  FALSE,  FALSE,		 1},
	 {0xE7, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_8_15,	  TRUE,   FALSE,		 1},
	 {0xE8, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_26_45,	  FALSE,  FALSE,		 1},
	 {0xE9, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_26_45,	  TRUE,   FALSE,		 1},
	 {0xEA, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_32_45,	  FALSE,  FALSE,		 1},
	 {0xEB, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_8psk, 	  MtFeCodeRate_32_45,	  TRUE,   FALSE,		 1},
	 {0xEC, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_7_15,	  FALSE,  FALSE,		 1},
	 {0xED, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_7_15,	  TRUE,   FALSE,		 1},
	 {0xEE, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_8_15,	  FALSE,  FALSE,		 1},
	 {0xEF, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_8_15,	  TRUE,   FALSE,		 1},
	 {0xF0, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_26_45,	  FALSE,  FALSE,		 1},
	 {0xF1, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_26_45,	  TRUE,   FALSE,		 1},
	 {0xF2, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_3_5, 	  FALSE,  FALSE,		 1},
	 {0xF3, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_3_5, 	  TRUE,   FALSE,		 1},
	 {0xF4, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_32_45,	  FALSE,  FALSE,		 1},
	 {0xF5, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_16Apsk,	  MtFeCodeRate_32_45,	  TRUE,   FALSE,		 1},
	 {0xF6, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk,	  MtFeCodeRate_2_3, 	  FALSE,  FALSE,		 1},
	 {0xF7, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk,	  MtFeCodeRate_2_3, 	  TRUE,   FALSE,		 1},
	 {0xF8, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk,	  MtFeCodeRate_32_45,	  FALSE,  FALSE,		 1},
	 {0xF9, 	  TRUE,   MtFeType_DvbS2X,	  MtFeModMode_32Apsk,	  MtFeCodeRate_32_45,	  TRUE,   FALSE,		 1},
	 {0xFA, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0xFB, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0xFC, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0xFD, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0},
	 {0xFE, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  FALSE,  FALSE,		 0},
	 {0xFF, 	  FALSE,  MtFeType_DvbS2X,	  MtFeModMode_Undef,	  MtFeCodeRate_Undef,	  TRUE,   FALSE,		 0}
 };

static int si5351_write(struct si5351_priv *priv,u8 reg,u8 data)
{
	struct i2c_adapter *i2c = priv->base1->i2c_si5351;
	u8 buf[] = { reg, data };
	u8 val;
	int ret;
	struct i2c_msg msg = {
		.addr = SI5351_BUS_BASE_ADDR,.flags = 0,.buf = buf,.len = 2
	};

	ret = i2c_transfer(i2c, &msg, 1);
	if (ret != 1) {
		dev_err(&i2c->dev,
			"si5351(ret=%i, reg=0x%02x, value=0x%02x)\n",
			 ret, reg, data);
		return -EREMOTEIO;
	}	
	return 0;
}

static int si5351_write_bulk(struct si5351_priv *priv,u8 reg, u8 len,u8*data)

{
	struct i2c_adapter *i2c = priv->base1->i2c_si5351;
	u8 buf[80];
	u8 val;
	int ret;

	 buf[0] = reg;
	 memcpy(&buf[1],data,len);
	 
	 struct i2c_msg msg = {
		.addr = SI5351_BUS_BASE_ADDR,.flags = 0,.buf = buf,.len = len+1
		};

	 ret = i2c_transfer(i2c, &msg, 1);
	 if (ret != 1) {
		dev_err(&i2c->dev,
			"si5351(ret=%i, reg=0x%02x, value=0x%02x)\n",
			 ret, reg, data);
		return -EREMOTEIO;
		}	
	 return 0;
}

static u8 si5351_read(struct si5351_priv *priv,u8 reg,u8 *data)

{
	struct i2c_adapter *i2c = priv->base1->i2c_si5351;
	int ret;
	unsigned val;
	u8 b0[] = { reg };
	struct i2c_msg msg[] = {
		{
		 .addr = SI5351_BUS_BASE_ADDR,
		 .flags = 0,
		 .buf = b0,
		 .len = 1},
		{
		 .addr = SI5351_BUS_BASE_ADDR,
		 .flags = I2C_M_RD,
		 .buf = data,
		 .len = 1}
	};

	ret = i2c_transfer(i2c, msg, 2);
	if (ret != 2) {
		dev_err(&i2c->dev, "si5351 (ret=%d, reg=0x%02x)\n",
			 ret, reg);
		return -EREMOTEIO;
	}

	dev_dbg(&i2c->dev, "si5351 reg 0x%02x, value 0x%02x\n",
		 reg, *data);


	return 0;
}

/*
 * Calculate best rational approximation for a given fraction
 * taking into account restricted register size, e.g. to find
 * appropriate values for a pll with 5 bit denominator and
 * 8 bit numerator register fields, trying to set up with a
 * frequency ratio of 3.1415, one would say:
 *
 * rational_best_approximation(31415, 10000,
 *              (1 << 8) - 1, (1 << 5) - 1, &n, &d);
 *
 * you may look at given_numerator as a fixed point number,
 * with the fractional part size described in given_denominator.
 *
 * for theoretical background, see:
 * http://en.wikipedia.org/wiki/Continued_fraction
 */
static void rational_best_approximation(
        unsigned long given_numerator, unsigned long given_denominator,
        unsigned long max_numerator, unsigned long max_denominator,
        unsigned long *best_numerator, unsigned long *best_denominator)
{

	unsigned long n, d, n0, d0, n1, d1;
	n = given_numerator;
	d = given_denominator;
	n0 = d1 = 0;
	n1 = d0 = 1;
	for (;;) {
		unsigned long t, a;
		if ((n1 > max_numerator) || (d1 > max_denominator)) {
			n1 = n0;
			d1 = d0;
			break;
		}
		if (d == 0)
			break;

		t = d;
		a = n / d;
		d = n % d;
		n = t;
		t = n0 + a * n1;
		n0 = n1;
		n1 = t;
		t = d0 + a * d1;
		d0 = d1;
		d1 = t;
	}

	*best_numerator = n1;
	*best_denominator = d1;
}

static u32 pll_calc(u32 freq, struct Si5351RegSet *reg, int correction)

{

	u32 ref_freq = SI5351_XTAL_FREQ;
	u32 rfrac, denom, a,  p1, p2, p3;
	unsigned long b, c;
	u64 lltmp;

	/* Factor calibration value into nominal crystal frequency */
	/* Measured in parts-per-ten million */
	ref_freq += (u32)((correction / 10000000) * ref_freq);

	/* PLL bounds checking */
	if (freq < SI5351_PLL_VCO_MIN)
		freq = SI5351_PLL_VCO_MIN;
	if (freq > SI5351_PLL_VCO_MAX)
		freq = SI5351_PLL_VCO_MAX;

	/* Determine integer part of feedback equation */
	a = freq / ref_freq;
	if (a < SI5351_PLL_A_MIN)
		freq = ref_freq * SI5351_PLL_A_MIN;
	if (a > SI5351_PLL_A_MAX)
		freq = ref_freq * SI5351_PLL_A_MAX;

	/* find best approximation for b/c = fVCO mod fIN */
	denom = 1000L * 1000L;
	lltmp = freq % ref_freq;
	lltmp *= denom;
	do_div(lltmp, ref_freq);
	rfrac = (u32)lltmp;

	b = 0;
	c = 1;
	if (rfrac)
		rational_best_approximation(rfrac, denom, \
				    SI5351_PLL_B_MAX, SI5351_PLL_C_MAX, &b, &c);

	/* calculate parameters */
	p3  = c;
	p2  = (128 * b) % c;
	p1  = 128 * a;
	p1 += (128 * b / c);
	p1 -= 512;

	/* recalculate rate by fIN * (a + b/c) */
	lltmp  = ref_freq;
	lltmp *= b;
	do_div(lltmp, c);

	freq  = (u32)lltmp;
	freq += ref_freq * a;

	reg->p1 = p1;
	reg->p2 = p2;
	reg->p3 = p3;

	return freq;
}
/*
 * si5351_set_pll(uint32_t pll_freq, enum si5351_pll target_pll)
 *
 * Set the specified PLL to a specific oscillation frequency
 *
 * pll_freq - Desired PLL frequency
 * target_pll - Which PLL to set
 *     (use the si5351_pll enum)
 */
void si5351_set_pll(struct si5351_priv *priv,u32 pll_freq, enum si5351_pll target_pll)
{

	struct Si5351RegSet pll_reg;

	pll_calc(pll_freq, &pll_reg, 0);
	/* Derive the register values to write */
	/* Prepare an array for parameters to be written to */

	u8 params[30];
	u8 i = 0;
	u8 temp;

	/* Registers 26-27 */
	temp = ((pll_reg.p3 >> 8) & 0xFF);
	params[i++] = temp;

	temp = (u8)(pll_reg.p3  & 0xFF);
	params[i++] = temp;

	/* Register 28 */
	temp = (u8)((pll_reg.p1 >> 16) & 0x03);
	params[i++] = temp;

	/* Registers 29-30 */
	temp = (u8)((pll_reg.p1 >> 8) & 0xFF);
	params[i++] = temp;

	temp = (u8)(pll_reg.p1  & 0xFF);
	params[i++] = temp;

	/* Register 31 */
	temp = (u8)((pll_reg.p3 >> 12) & 0xF0);
	temp += (u8)((pll_reg.p2 >> 16) & 0x0F);
	params[i++] = temp;

	/* Registers 32-33 */
	temp = (u8)((pll_reg.p2 >> 8) & 0xFF);
	params[i++] = temp;

	temp = (u8)(pll_reg.p2  & 0xFF);
	params[i++] = temp;

	/* Write the parameters */
	if(target_pll == SI5351_PLLA)
	{
		si5351_write_bulk(priv,SI5351_PLLA_PARAMETERS, i + 1, params);
	}
	else if(target_pll == SI5351_PLLB)
	{
		si5351_write_bulk(priv,SI5351_PLLB_PARAMETERS, i + 1, params);
	}

}

/*
 * si5351_clock_enable(enum si5351_clock clk, uint8_t enable)
 *
 * Enable or disable a chosen clock
 * clk - Clock output
 *   (use the si5351_clock enum)
 * enable - Set to 1 to enable, 0 to disable
 */
static void si5351_clock_enable(struct si5351_priv *priv,enum si5351_clock clk, u8 enable)
{

	u8 reg_val;

	if(si5351_read(priv,SI5351_OUTPUT_ENABLE_CTRL, &reg_val) != 0)
	{
		return;
	}

	if(enable == 1)
	{
		reg_val &= ~(1<<(u8)clk);
	}
	else
	{
		reg_val |= (1<<(u8)clk);
	}

	si5351_write(priv,SI5351_OUTPUT_ENABLE_CTRL, reg_val);

}

/*
 * si5351_drive_strength(enum si5351_clock clk, enum si5351_drive drive)
 *
 * Sets the drive strength of the specified clock output
 *
 * clk - Clock output
 *   (use the si5351_clock enum)
 * drive - Desired drive level
 *   (use the si5351_drive enum)
 */
static void si5351_drive_strength(struct si5351_priv *priv, enum si5351_clock clk, enum si5351_drive drive)
{
	u8 reg_val;

	const u8 mask = 0x03;

	if(si5351_read(priv,SI5351_CLK0_CTRL + (u8)clk, &reg_val) != 0)
	{
		return;
	}

	switch(drive)
	{
	case SI5351_DRIVE_2MA:
		reg_val &= ~(mask);
		reg_val |= 0x00;
		break;
	case SI5351_DRIVE_4MA:
		reg_val &= ~(mask);
		reg_val |= 0x01;
		break;
	case SI5351_DRIVE_6MA:
		reg_val &= ~(mask);
		reg_val |= 0x02;
		break;
	case SI5351_DRIVE_8MA:
		reg_val &= ~(mask);
		reg_val |= 0x03;
		break;
	default:
		break;
	}

	si5351_write(priv,SI5351_CLK0_CTRL + (u8)clk, reg_val);
}


static u32 multisynth_calc(u32 freq, struct Si5351RegSet *reg)
{
	u32 pll_freq;
	u64 lltmp;
	u32 a, b, c, p1, p2, p3;
	u8 divby4;

	/* Multisynth bounds checking */
	if (freq > SI5351_MULTISYNTH_MAX_FREQ)
		freq = SI5351_MULTISYNTH_MAX_FREQ;
	if (freq < SI5351_MULTISYNTH_MIN_FREQ)
		freq = SI5351_MULTISYNTH_MIN_FREQ;

	divby4 = 0;
	if (freq > SI5351_MULTISYNTH_DIVBY4_FREQ)
		divby4 = 1;

	/* Find largest integer divider for max */
	/* VCO frequency and given target frequency */
	if (divby4 == 0)
	{
		lltmp = SI5351_PLL_VCO_MAX;
		do_div(lltmp, freq);
		a = (u32)lltmp;
	}
	else
		a = 4;

	b = 0;
	c = 1;
	pll_freq = a * freq;

	/* Recalculate output frequency by fOUT = fIN / (a + b/c) */
	lltmp  = pll_freq;
	lltmp *= c;
	do_div(lltmp, a * c + b);
	freq  = (unsigned long)lltmp;

	/* Calculate parameters */
	if (divby4)
	{
		p3 = 1;
		p2 = 0;
		p1 = 0;
	}
	else
	{
		p3  = c;
		p2  = (128 * b) % c;
		p1  = 128 * a;
		p1 += (128 * b / c);
		p1 -= 512;
	}

	reg->p1 = p1;
	reg->p2 = p2;
	reg->p3 = p3;

	return pll_freq;

}

static u32 multisynth_recalc(u32 freq, u32 pll_freq, struct Si5351RegSet *reg)
{

	u64 lltmp;
	u32 rfrac, denom, a, p1, p2, p3;
	unsigned long b,c;
	u8 divby4;

	/* Multisynth bounds checking */
	if (freq > SI5351_MULTISYNTH_MAX_FREQ)
		freq = SI5351_MULTISYNTH_MAX_FREQ;
	if (freq < SI5351_MULTISYNTH_MIN_FREQ)
		freq = SI5351_MULTISYNTH_MIN_FREQ;

	divby4 = 0;
	if (freq > SI5351_MULTISYNTH_DIVBY4_FREQ)
		divby4 = 1;

	/* Determine integer part of feedback equation */
	a = pll_freq / freq;
	/* TODO: not sure this is correct */
	if (a < SI5351_MULTISYNTH_A_MIN)
		freq = pll_freq / SI5351_MULTISYNTH_A_MIN;
	if (a > SI5351_MULTISYNTH_A_MAX)
		freq = pll_freq / SI5351_MULTISYNTH_A_MAX;

	/* find best approximation for b/c */
	denom = 1000L * 1000L;
	lltmp = pll_freq % freq;
	lltmp *= denom;
	do_div(lltmp, freq);
	rfrac = (u32)lltmp;

	b = 0;
	c = 1;
	if (rfrac)
		rational_best_approximation(rfrac, denom,   \
				    SI5351_MULTISYNTH_B_MAX, SI5351_MULTISYNTH_C_MAX, &b, &c);

	/* Recalculate output frequency by fOUT = fIN / (a + b/c) */
	lltmp  = pll_freq;
	lltmp *= c;
	do_div(lltmp, a * c + b);
	freq  = (unsigned long)lltmp;

	/* Calculate parameters */
	if (divby4)
	{
		p3 = 1;
		p2 = 0;
		p1 = 0;
	}
	else
	{
		p3  = c;
		p2  = (128 * b) % c;
		p1  = 128 * a;
		p1 += (128 * b / c);
		p1 -= 512;
	}

	reg->p1 = p1;
	reg->p2 = p2;
	reg->p3 = p3;

	return freq;
}

static void si5351_set_ms_source(struct si5351_priv *priv, enum si5351_clock clk,  enum si5351_pll pll)
{
	u8 reg_val = 0x0c;
	u8 reg_val2;

	if(si5351_read(priv,SI5351_CLK0_CTRL + (u8)clk, &reg_val2) != 0)
	{
		return;
	}

	if(pll == SI5351_PLLA)
	{
		reg_val &= ~(SI5351_CLK_PLL_SELECT);
	}
	else if(pll == SI5351_PLLB)
	{
		reg_val |= SI5351_CLK_PLL_SELECT;
	}
	si5351_write(priv,SI5351_CLK0_CTRL + (u8)clk, reg_val);

}

static void si5351_init(struct si5351_priv *priv)
{
	si5351_write(priv,SI5351_CRYSTAL_LOAD, SI5351_CRYSTAL_LOAD_10PF);
	return ;
}

static void si5351_set_freq(struct si5351_priv *priv,u32 freq, u32 pll_freq, enum si5351_clock clk)
{
	 struct Si5351RegSet ms_reg;
	 struct Si5351RegSet pll_reg;
	 enum si5351_pll target_pll;

	 u32 ret;

	/* Calculate the synth parameters */
	/* If pll_freq is 0, let the algorithm pick a PLL frequency */
	if(pll_freq == 0)
	{
		 pll_freq = multisynth_calc(freq, &ms_reg);
	}
	/* TODO: bounds checking */
	else
	{
		multisynth_recalc(freq, pll_freq, &ms_reg);
	}
	/* Determine which PLL to use */
	/* CLK0 gets PLLA, CLK1 gets PLLB */
	/* CLK2 gets PLLB if necessary */
	/* Only good for Si5351A3 variant at the moment */
	if(clk == SI5351_CLK0)
	{
		target_pll = SI5351_PLLA;
		priv->plla_freq = pll_freq;
	}
	else if(clk == SI5351_CLK1)
	{
		target_pll = SI5351_PLLB;
		priv->pllb_freq = pll_freq;
	}
	else
	{
		/* need to account for CLK2 set before CLK1 */
		if(priv->pllb_freq == 0)
		{
			target_pll = SI5351_PLLB;
			priv->pllb_freq = pll_freq;
		}
		else
		{
			target_pll = SI5351_PLLB;
			pll_freq = priv->pllb_freq;
			multisynth_recalc(freq, pll_freq, &ms_reg);
		}
	}

	ret=pll_calc(pll_freq, &pll_reg, 0);
	/* Derive the register values to write */
	/* Prepare an array for parameters to be written to */
	u8 params[30];
	u8 i = 0;
	u8 temp;
	/* PLL parameters first */
	if(ret== 0)
	{
		/* Registers 26-27 */
		temp = ((pll_reg.p3 >> 8) & 0xFF);
		params[i++] = temp;
		temp = (u8)(pll_reg.p3  & 0xFF);
		params[i++] = temp;

		/* Register 28 */
		temp = (u8)((pll_reg.p1 >> 16) & 0x03);
		params[i++] = temp;

		/* Registers 29-30 */
		temp = (u8)((pll_reg.p1 >> 8) & 0xFF);
		params[i++] = temp;
		temp = (u8)(pll_reg.p1  & 0xFF);
		params[i++] = temp;

		/* Register 31 */
		temp = (u8)((pll_reg.p3 >> 12) & 0xF0);
		temp += (u8)((pll_reg.p2 >> 16) & 0x0F);
		params[i++] = temp;

		/* Registers 32-33 */
		temp = (u8)((pll_reg.p2 >> 8) & 0xFF);
		params[i++] = temp;

		temp = (u8)(pll_reg.p2  & 0xFF);
		params[i++] = temp;

		/* Write the parameters */
		if(target_pll == SI5351_PLLA)
		{
			si5351_write_bulk(priv,SI5351_PLLA_PARAMETERS, i + 1, params);
		}
		else if(target_pll == SI5351_PLLB)
		{
			si5351_write_bulk(priv,SI5351_PLLB_PARAMETERS, i + 1, params);
		}
	}
	/* Now the multisynth parameters */
	memset (params, 0, 30);
	i = 0;

	/* Registers 42-43 */
	temp = (u8)((ms_reg.p3 >> 8) & 0xFF);
	params[i++] = temp;

	temp = (u8)(ms_reg.p3  & 0xFF);
	params[i++] = temp;

	/* Register 44 */
	/* TODO: add code for output divider */
	temp = (u8)((ms_reg.p1 >> 16) & 0x03);
	params[i++] = temp;

	/* Registers 45-46 */
	temp = (u8)((ms_reg.p1 >> 8) & 0xFF);
	params[i++] = temp;

	temp = (u8)(ms_reg.p1  & 0xFF);
	params[i++] = temp;

	/* Register 47 */
	temp = (u8)((ms_reg.p3 >> 12) & 0xF0);
	temp += (u8)((ms_reg.p2 >> 16) & 0x0F);
	params[i++] = temp;

	/* Registers 48-49 */
	temp = (u8)((ms_reg.p2 >> 8) & 0xFF);
	params[i++] = temp;
	temp = (u8)(ms_reg.p2  & 0xFF);
	params[i++] = temp;

	/* Write the parameters */
	switch(clk)
	{
	case SI5351_CLK0:
		si5351_write_bulk(priv,SI5351_CLK0_PARAMETERS, i + 1, params);
		si5351_set_ms_source(priv,clk, target_pll);
		break;
	case SI5351_CLK1:
		si5351_write_bulk(priv,SI5351_CLK1_PARAMETERS, i + 1, params);
		si5351_set_ms_source(priv,clk, target_pll);
		break;
	case SI5351_CLK2:
		si5351_write_bulk(priv,SI5351_CLK2_PARAMETERS, i + 1, params);
		si5351_set_ms_source(priv,clk, target_pll);
		break;
	case SI5351_CLK3:
		si5351_write_bulk(priv,SI5351_CLK3_PARAMETERS, i + 1, params);
		si5351_set_ms_source(priv,clk, target_pll);
		break;
	case SI5351_CLK4:
		si5351_write_bulk(priv,SI5351_CLK4_PARAMETERS, i + 1, params);
		si5351_set_ms_source(priv,clk, target_pll);
		break;
	case SI5351_CLK5:
		si5351_write_bulk(priv,SI5351_CLK5_PARAMETERS, i + 1, params);
		si5351_set_ms_source(priv,clk, target_pll);
		break;
	case SI5351_CLK6:
		si5351_write_bulk(priv,SI5351_CLK6_PARAMETERS, i + 1, params);
		si5351_set_ms_source(priv,clk, target_pll);
		break;
	case SI5351_CLK7:
		si5351_write_bulk(priv,SI5351_CLK7_PARAMETERS, i + 1, params);
		si5351_set_ms_source(priv,clk, target_pll);
		break;
	}

}
//end
static int rs6060_set_reg(struct m88rs6060_dev *dev, u8 reg, u8 data)
{

	u8 buf[] = { reg, data };
	u8 val;
	int ret;
	struct i2c_msg msg = {
		.addr = dev->config.tuner_adr,.flags = 0,.buf = buf,.len = 2
	};

	val = 0x11;
	ret = regmap_write(dev->regmap, 0x03, val);
	if (ret)
		dev_dbg(&dev->base->i2c->dev, "fail=%d\n", ret);

	ret = i2c_transfer(dev->base->i2c, &msg, 1);
	if (ret != 1) {
		dev_err(&dev->base->i2c->dev,
			"0x%02x (ret=%i, reg=0x%02x, value=0x%02x)\n",
			dev->config.tuner_adr, ret, reg, data);
		return -EREMOTEIO;
	}

	dev_dbg(&dev->base->i2c->dev, "0x%02x reg 0x%02x, value 0x%02x\n",
		dev->config.tuner_adr, reg, data);

	return 0;
}

static int rs6060_get_reg(struct m88rs6060_dev *dev, u8 reg)
{

	struct i2c_adapter *i2c = dev->base->i2c;
	int ret;
	unsigned val;
	u8 b0[] = { reg };
	u8 b1[] = { 0 };
	struct i2c_msg msg[] = {
		{
		 .addr = dev->config.tuner_adr,
		 .flags = 0,
		 .buf = b0,
		 .len = 1},
		{
		 .addr = dev->config.tuner_adr,
		 .flags = I2C_M_RD,
		 .buf = b1,
		 .len = 1}
	};

	val = dev->config.repeater_value;
	ret = regmap_write(dev->regmap, 0x03, val);
	if (ret)
		dev_dbg(&i2c->dev, "fail=%d\n", ret);

	ret = i2c_transfer(i2c, msg, 2);
	if (ret != 2) {
		dev_err(&i2c->dev, "0x%02x (ret=%d, reg=0x%02x)\n",
			dev->config.tuner_adr, ret, reg);
		return -EREMOTEIO;
	}

	dev_dbg(&i2c->dev, "0x%02x reg 0x%02x, value 0x%02x\n",
		dev->config.tuner_adr, reg, b1[0]);

	return b1[0];

}

static int m88rs6060_fireware_download(struct m88rs6060_dev *dev, u8 reg,
				       const u8 * data, int len)
{
	struct i2c_adapter *i2c = dev->base->i2c;
	int ret;
    	u8 buf[70];
    	struct i2c_msg msg = {
		.addr = dev->config.demod_adr,.flags = 0,.buf = buf,.len =
		    len + 1
	};

    	buf[0] = reg;
	memcpy(&buf[1], data, len);

	ret = i2c_transfer(i2c, &msg, 1);
	if (ret != 1) {
		dev_err(&i2c->dev,
			"0x%02x (ret=%i, reg=0x%02x)\n",
			dev->config.tuner_adr, ret, reg);
		return -EREMOTEIO;
	}

	return 0;
}

static int m88rs6060_update_bits(struct m88rs6060_dev *dev,
				 u8 reg, u8 mask, u8 val)
{
	int ret;
	unsigned tmp;

	/* no need for read if whole reg is written */
	if (mask != 0xff) {
		ret = regmap_read(dev->regmap, reg, &tmp);
		if (ret)
			return ret;

		val &= mask;
		tmp &= ~mask;
		val |= tmp;
	}

	return regmap_write(dev->regmap, reg, val);
}

static void m88rs6060_calc_PLS_gold_code(u8 * pNormalCode, u32 PLSGoldCode)
{
	struct PLS_Table_t {
		u32 iIndex;
		u8 PLSCode[3];
	};

	struct PLS_Table_t PLS_List[] = {
		{0, {0x01, 0x00, 0x00}},
		{5000, {0x0d, 0xe0, 0x00}},
		{10000, {0x51, 0x15, 0x00}},
		{15000, {0xcf, 0xc9, 0x00}},
		{20000, {0x67, 0x33, 0x03}},
		{25000, {0x02, 0xc9, 0x02}},
		{30000, {0xe5, 0xc6, 0x01}},
		{35000, {0xdb, 0xc0, 0x03}},
		{40000, {0x7c, 0x5f, 0x02}},
		{45000, {0x8d, 0x65, 0x00}},
		{50000, {0x14, 0x96, 0x00}},
		{55000, {0xf7, 0x61, 0x03}},
		{60000, {0xbc, 0x28, 0x00}},
		{65000, {0x77, 0xa9, 0x01}},
		{70000, {0xe7, 0x05, 0x01}},
		{75000, {0x88, 0x85, 0x01}},
		{80000, {0x2f, 0xbb, 0x02}},
		{85000, {0xe1, 0x07, 0x00}},
		{90000, {0xd5, 0x67, 0x01}},
		{95000, {0x94, 0x37, 0x03}},
		{100000, {0x57, 0x39, 0x02}},
		{105000, {0xc7, 0x03, 0x00}},
		{110000, {0xbf, 0x12, 0x00}},
		{115000, {0x50, 0x0e, 0x00}},
		{120000, {0xca, 0xc4, 0x00}},
		{125000, {0x46, 0xc3, 0x00}},
		{130000, {0x2f, 0xc6, 0x01}},
		{135000, {0x7c, 0xe5, 0x01}},
		{140000, {0xb9, 0x36, 0x01}},
		{145000, {0x9d, 0xe5, 0x01}},
		{150000, {0xc4, 0x32, 0x01}},
		{155000, {0x13, 0xb3, 0x00}},
		{160000, {0x0c, 0x9f, 0x02}},
		{165000, {0xb2, 0xb5, 0x03}},
		{170000, {0xac, 0x7e, 0x01}},
		{175000, {0xb6, 0xa2, 0x01}},
		{180000, {0xb6, 0x3e, 0x01}},
		{185000, {0x17, 0x2c, 0x02}},
		{190000, {0xd7, 0x2a, 0x02}},
		{195000, {0x93, 0x61, 0x02}},
		{200000, {0x67, 0x92, 0x02}},
		{205000, {0x38, 0x07, 0x01}},
		{210000, {0xb4, 0x5a, 0x01}},
		{215000, {0xed, 0x31, 0x02}},
		{220000, {0x9e, 0x4d, 0x02}},
		{225000, {0x17, 0x08, 0x02}},
		{230000, {0x37, 0xb9, 0x00}},
		{235000, {0x2c, 0xed, 0x00}},
		{240000, {0xe0, 0x64, 0x00}},
		{245000, {0x90, 0x39, 0x01}},
		{250000, {0x35, 0x0e, 0x01}},
		{255000, {0x1c, 0x9e, 0x02}},
		{260000, {0x58, 0x78, 0x00}}
	};

	u8 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15,
	    x16, x17;
	int i;
	u8 tmp;

	u32 ulPLSCode = 0, ulPLSIndex = 0;

	int iPLSCnt =
	    sizeof(PLS_List) / sizeof(struct PLS_Table_t), iPLSListIndex;
	u8 iPLSCode[3];

	ulPLSCode = PLSGoldCode;
	iPLSListIndex = ulPLSCode / 5000;

	if (iPLSListIndex > iPLSCnt - 1)
		iPLSListIndex = iPLSCnt - 1;

	ulPLSIndex = PLS_List[iPLSListIndex].iIndex;
	iPLSCode[0] = PLS_List[iPLSListIndex].PLSCode[0];
	iPLSCode[1] = PLS_List[iPLSListIndex].PLSCode[1];
	iPLSCode[2] = PLS_List[iPLSListIndex].PLSCode[2];

	x0 = (iPLSCode[0] >> 0) & 0x01;
	x1 = (iPLSCode[0] >> 1) & 0x01;
	x2 = (iPLSCode[0] >> 2) & 0x01;
	x3 = (iPLSCode[0] >> 3) & 0x01;
	x4 = (iPLSCode[0] >> 4) & 0x01;
	x5 = (iPLSCode[0] >> 5) & 0x01;
	x6 = (iPLSCode[0] >> 6) & 0x01;
	x7 = (iPLSCode[0] >> 7) & 0x01;
	x8 = (iPLSCode[1] >> 0) & 0x01;
	x9 = (iPLSCode[1] >> 1) & 0x01;
	x10 = (iPLSCode[1] >> 2) & 0x01;
	x11 = (iPLSCode[1] >> 3) & 0x01;
	x12 = (iPLSCode[1] >> 4) & 0x01;
	x13 = (iPLSCode[1] >> 5) & 0x01;
	x14 = (iPLSCode[1] >> 6) & 0x01;
	x15 = (iPLSCode[1] >> 7) & 0x01;
	x16 = (iPLSCode[2] >> 0) & 0x01;
	x17 = (iPLSCode[2] >> 1) & 0x01;

	for (i = ulPLSIndex; i <= ulPLSCode; i++) {
		iPLSCode[0] =
		    (x7 << 7) + (x6 << 6) + (x5 << 5) + (x4 << 4) + (x3 << 3) +
		    (x2 << 2) + (x1 << 1) + (x0 << 0);
		iPLSCode[1] =
		    (x15 << 7) + (x14 << 6) + (x13 << 5) + (x12 << 4) +
		    (x11 << 3) + (x10 << 2) + (x9 << 1) + (x8 << 0);
		iPLSCode[2] = (x17 << 1) + x16;

		tmp = (x0 ^ x7) & 0x01;
		x0 = x1;
		x1 = x2;
		x2 = x3;
		x3 = x4;
		x4 = x5;
		x5 = x6;
		x6 = x7;
		x7 = x8;
		x8 = x9;
		x9 = x10;
		x10 = x11;
		x11 = x12;
		x12 = x13;
		x13 = x14;
		x14 = x15;
		x15 = x16;
		x16 = x17;
		x17 = tmp;

	}

	pNormalCode[0] = iPLSCode[0];
	pNormalCode[1] = iPLSCode[1];
	pNormalCode[2] = iPLSCode[2];

	return;
}

static int m88rs6060_get_gain(struct m88rs6060_dev *dev, u32 freq_MHz,
			      s32 * p_gain)
{
	static s32 bb_list_dBm[16][16] = {
		{-5000, -4999, -4397, -4044, -3795, -3601, -3442, -3309, -3193,
		 -3090, -2999, -2916, -2840, -2771, -2706, -2647},
		{-2590, -2538, -2488, -2441, -2397, -2354, -2314, -2275, -2238,
		 -2203, -2169, -2136, -2104, -2074, -2044, -2016},
		{-1988, -1962, -1936, -1911, -1886, -1862, -1839, -1817, -1795,
		 -1773, -1752, -1732, -1712, -1692, -1673, -1655},
		{-1636, -1618, -1601, -1584, -1567, -1550, -1534, -1518, -1502,
		 -1487, -1472, -1457, -1442, -1428, -1414, -1400},
		{-1386, -1373, -1360, -1347, -1334, -1321, -1309, -1296, -1284,
		 -1272, -1260, -1249, -1237, -1226, -1215, -1203},
		{-1193, -1182, -1171, -1161, -1150, -1140, -1130, -1120, -1110,
		 -1100, -1090, -1081, -1071, -1062, -1052, -1043},
		{-1034, -1025, -1016, -1007, -999, -990, -982, -973, -965, -956,
		 -948, -940, -932, -924, -916, -908},
		{-900, -893, -885, -877, -870, -862, -855, -848, -840, -833,
		 -826, -819, -812, -805, -798, -791},
		{-784, -778, -771, -764, -758, -751, -745, -738, -732, -725,
		 -719, -713, -706, -700, -694, -688},
		{-682, -676, -670, -664, -658, -652, -647, -641, -635, -629,
		 -624, -618, -612, -607, -601, -596},
		{-590, -585, -580, -574, -569, -564, -558, -553, -548, -543,
		 -538, -533, -528, -523, -518, -513},
		{-508, -503, -498, -493, -488, -483, -479, -474, -469, -464,
		 -460, -455, -450, -446, -441, -437},
		{-432, -428, -423, -419, -414, -410, -405, -401, -397, -392,
		 -388, -384, -379, -375, -371, -367},
		{-363, -358, -354, -350, -346, -342, -338, -334, -330, -326,
		 -322, -318, -314, -310, -306, -302},
		{-298, -294, -290, -287, -283, -279, -275, -271, -268, -264,
		 -260, -257, -253, -249, -246, -242},
		{-238, -235, -231, -227, -224, -220, -217, -213, -210, -206,
		 -203, -199, -196, -192, -189, -186}

	};

	s32 BB_Power = 0;
	u32 Total_Gain = 8000;
	s32 delta = 0;

	u8 reg5a, reg5f, reg77, reg76, reg3f;
	u8 reg96 = 0;

	u32 PGA2_cri_GS = 46, PGA2_crf_GS = 290, TIA_GS = 290;
	u32 RF_GC = 1200, IF_GC = 1100, BB_GC = 300, PGA2_GC = 300, TIA_GC =
	    300;
	u32 PGA2_cri = 0, PGA2_crf = 0;
	u32 RFG = 0, IFG = 0, BBG = 0, PGA2G = 0, TIAG = 0;

	u32 i = 0;

	u32 RFGS[13] =
	    { 0, 276, 278, 283, 272, 294, 296, 292, 292, 299, 305, 292, 300 };
	u32 IFGS[12] =
	    { 0, 0, 232, 268, 266, 289, 295, 290, 291, 298, 304, 304 };
	u32 BBGS[13] =
	    { 0, 296, 297, 295, 298, 302, 293, 292, 286, 294, 278, 298, 267 };

	reg5a = rs6060_get_reg(dev, 0x5A);
	RF_GC = reg5a & 0x0f;

	reg5f = rs6060_get_reg(dev, 0x5F);
	IF_GC = reg5f & 0x0f;

	reg3f = rs6060_get_reg(dev, 0x3F);
	TIA_GC = (reg3f >> 4) & 0x07;

	reg77 = rs6060_get_reg(dev, 0x77);
	BB_GC = (reg77 >> 4) & 0x0f;

	reg76 = rs6060_get_reg(dev, 0x76);
	PGA2_GC = reg76 & 0x3f;
	PGA2_cri = PGA2_GC >> 2;
	PGA2_crf = PGA2_GC & 0x03;

	if (freq_MHz >= 1750) {
		RFGS[1] = 240;
		RFGS[2] = 260;
		IFGS[2] = 200;
		IFGS[3] = 245;
		IFGS[4] = 255;
	} else if (freq_MHz >= 1350) {
		RFGS[12] = 285;
	} else {
		RFGS[1] = 310;
		RFGS[2] = 293;
		IFGS[2] = 270;
		IFGS[3] = 290;
		IFGS[4] = 280;
		IFGS[11] = 320;
	}

	for (i = 0; i <= RF_GC; i++) {
		RFG += RFGS[i];
	}

	for (i = 1; i <= IF_GC; i++) {
		IFG += IFGS[i];
	}

	TIAG = TIA_GC * TIA_GS;

	for (i = 0; i <= BB_GC; i++) {
		BBG += BBGS[i];
	}

	PGA2G = PGA2_cri * PGA2_cri_GS + PGA2_crf * PGA2_crf_GS;
	Total_Gain = RFG + IFG - TIAG + BBG + PGA2G;

	if (freq_MHz >= 1750) {
		delta = 800;
	} else if (freq_MHz >= 1350) {
		delta = 900;
	} else {
		delta = 1000;
	}

	reg96 = rs6060_get_reg(dev, 0x96);
	BB_Power = bb_list_dBm[(reg96 >> 4) & 0x0f][reg96 & 0x0f];
	*p_gain = Total_Gain - delta - BB_Power;

	return 0;

}

static void rs6060_wakeup(struct m88rs6060_dev *dev)
{
	rs6060_set_reg(dev, 0x10, 0xfb);
	rs6060_set_reg(dev, 0x11, 0x1);
	rs6060_set_reg(dev, 0x7, 0x7d);
	msleep(10);

	return;
}

static void m88rs6060_hard_rest(struct m88rs6060_dev *dev)
{
	unsigned val;
	
	rs6060_set_reg(dev, 0x04, 0x01);
	rs6060_set_reg(dev, 0x04, 0x00);

	regmap_read(dev->regmap, 0x04, &val);
	val&=~0x01;
	regmap_write(dev->regmap, 0x04,val);
	
	msleep(1);
	rs6060_wakeup(dev);
	

	regmap_read(dev->regmap, 0x08, &val);
	regmap_write(dev->regmap, 0x08, (val | 0x01));

	regmap_read(dev->regmap, 0x0b, &val);
	regmap_write(dev->regmap, 0x0b, (val | 0x1));

	regmap_read(dev->regmap, 0xb2, &val);
	if (val == 0x1) {
		regmap_write(dev->regmap, 0x00, 0x00);
		regmap_write(dev->regmap, 0xb2, 0x00);
	}

	regmap_write(dev->regmap, 0x07, 0x80);
	regmap_write(dev->regmap, 0x07, 0x00);
	msleep(1);
	regmap_read(dev->regmap, 0x08, &val);
	regmap_write(dev->regmap, 0x8, (val | 0x1));
	
	return;
}

static void rs6060_select_mclk(struct m88rs6060_dev *dev, u32 freq_MHz,
			       u32 symbol_rate)
{
	u32 adc_freq_MHz[3] = { 96, 93, 99 };
	u8 reg16_list[3] = { 96, 92, 100 }, reg15, reg16;
	u32 offset_MHz[3];
	u32 max_offset = 0;
	int i = 0;
	reg16 = 96;
	dev->mclk = 96000;
	if (symbol_rate >= 46000) {
		dev->mclk = 99000;
		reg16 = 100;
	} else {
		for (i = 0; i < 3; i++) {
			offset_MHz[i] = freq_MHz % adc_freq_MHz[i];

			if (offset_MHz[i] > (adc_freq_MHz[i] / 2))
				offset_MHz[i] = adc_freq_MHz[i] - offset_MHz[i];

			if (offset_MHz[i] > max_offset) {

				max_offset = offset_MHz[i];
				reg16 = reg16_list[i];
				dev->mclk = adc_freq_MHz[i] * 1000;

			}

		}

	}
	reg15 = rs6060_get_reg(dev, 0x15);
	reg15 &= ~0x1;
	rs6060_set_reg(dev, 0x15, reg15);
	rs6060_set_reg(dev, 0x16, reg16);
	rs6060_set_reg(dev, 0x17, 0xc1);
	rs6060_set_reg(dev, 0x17, 0x81);

	msleep(5);

	return;

}

static void rs6060_set_ts_mclk(struct m88rs6060_dev *dev, u32 mclk)
{
	u8 reg15, reg16, reg1D, reg1E, reg1F, tmp;
	u8 sm, f0 = 0, f1 = 0, f2 = 0, f3 = 0;
	u16 pll_div_fb, N;
	u32 div;

	reg15 = rs6060_get_reg(dev, 0x15);
	reg16 = rs6060_get_reg(dev, 0x16);
	reg1D = rs6060_get_reg(dev, 0x1d);

	if (dev->config.ts_mode != MtFeTsOutMode_Serial) {
		if (reg16 == 92) {
			tmp = 93;
		} else if (reg16 == 100) {
			tmp = 99;
		} else		// if(reg16 == 96)
		{
			tmp = 96;
		}

		mclk *= tmp;
		mclk /= 96;
	}

	pll_div_fb = (reg15 & 0x01) << 8;
	pll_div_fb += reg16;
	pll_div_fb += 32;

	div = 9000 * pll_div_fb * 4;
	div /= mclk;

	if (dev->config.ts_mode == MtFeTsOutMode_Serial) {
		if (div <= 32) {
			N = 2;

			f0 = 0;
			f1 = div / N;
			f2 = div - f1;
			f3 = 0;
		} else if (div <= 64) {
			N = 4;

			f0 = div / N;
			f1 = (div - f0) / (N - 1);
			f2 = (div - f0 - f1) / (N - 2);
			f3 = div - f0 - f1 - f2;
		} else {
			N = 4;

			f0 = 16;
			f1 = 16;
			f2 = 16;
			f3 = 16;
		}

		if (f0 == 16)
			f0 = 0;
		else if ((f0 < 8) && (f0 != 0))
			f0 = 8;

		if (f1 == 16)
			f1 = 0;
		else if ((f1 < 8) && (f1 != 0))
			f1 = 8;

		if (f2 == 16)
			f2 = 0;
		else if ((f2 < 8) && (f2 != 0))
			f2 = 8;

		if (f3 == 16)
			f3 = 0;
		else if ((f3 < 8) && (f3 != 0))
			f3 = 8;
	} else {
		if (div <= 32) {
			N = 2;

			f0 = 0;
			f1 = div / N;
			f2 = div - f1;
			f3 = 0;
		} else if (div <= 48) {
			N = 3;

			f0 = div / N;
			f1 = (div - f0) / (N - 1);
			f2 = div - f0 - f1;
			f3 = 0;
		} else if (div <= 64) {
			N = 4;

			f0 = div / N;
			f1 = (div - f0) / (N - 1);
			f2 = (div - f0 - f1) / (N - 2);
			f3 = div - f0 - f1 - f2;
		} else {
			N = 4;

			f0 = 16;
			f1 = 16;
			f2 = 16;
			f3 = 16;
		}

		if (f0 == 16)
			f0 = 0;
		else if ((f0 < 9) && (f0 != 0))
			f0 = 9;

		if (f1 == 16)
			f1 = 0;
		else if ((f1 < 9) && (f1 != 0))
			f1 = 9;

		if (f2 == 16)
			f2 = 0;
		else if ((f2 < 9) && (f2 != 0))
			f2 = 9;

		if (f3 == 16)
			f3 = 0;
		else if ((f3 < 9) && (f3 != 0))
			f3 = 9;
	}

	sm = N - 1;

	reg1D &= ~0x03;
	reg1D |= sm;
	reg1D |= 0x80;

	reg1E = ((f3 << 4) + f2) & 0xFF;
	reg1F = ((f1 << 4) + f0) & 0xFF;

	rs6060_set_reg(dev, 0x1d, reg1D);
	rs6060_set_reg(dev, 0x1e, reg1E);
	rs6060_set_reg(dev, 0x1f, reg1F);
	msleep(1);

}
static int rs6060_get_ts_mclk(struct m88rs6060_dev *dev,u32*mclk )
{
	u8 reg15, reg16, reg1D, reg1E, reg1F;
	u8 sm, f0, f1, f2, f3;
	u16 pll_div_fb, N;
	u32 MCLK_KHz;


	*mclk = MT_FE_MCLK_KHZ;

	reg15 = rs6060_get_reg(dev, 0x15);
	reg16 = rs6060_get_reg(dev, 0x16);
	reg1D = rs6060_get_reg(dev, 0x1d);
	reg1E = rs6060_get_reg(dev, 0x1e);
	reg1F = rs6060_get_reg(dev, 0x1f);

	MCLK_KHz = 9000;
	pll_div_fb = reg15 & 0x01;
	pll_div_fb <<= 8;
	pll_div_fb += reg16;

	MCLK_KHz *= (pll_div_fb + 32);

	sm = reg1D & 0x03;

	f3 = (reg1E >> 4) & 0x0F;
	f2 = reg1E & 0x0F;
	f1 = (reg1F >> 4) & 0x0F;
	f0 = reg1F & 0x0F;

	if(f3 == 0)		f3 = 16;
	if(f2 == 0)		f2 = 16;
	if(f1 == 0)		f1 = 16;
	if(f0 == 0)		f0 = 16;
	N = f2 + f1;

	switch(sm){
		case 3:
			N = f3 + f2 + f1 + f0;
			break;
		case 2:
			N = f2 + f1 + f0;
			break;
		case 1:
		case 0:
		default:
			N = f2 + f1;
			break;
	}

	MCLK_KHz *= 4;
	MCLK_KHz /= N;

	*mclk = MCLK_KHz;

	return 0;

}
static int rs6060_set_pll_freq(struct m88rs6060_dev *dev, u32 tuner_freq_MHz)
{
	u32 fcry_KHz, ulNDiv1, ulNDiv2;
	u8 refDiv1, refDiv2, ucLoDiv1, ucLomod1, ucLoDiv2, ucLomod2, div1m,
	    div1p5m, lodiv_en_opt_div2;
	u8 reg27, reg29;
	u8 tmp;

	fcry_KHz = dev->config.clk / 1000;	/*tuner crycle */
	if (fcry_KHz == 27000) {

		div1m = 19;
		div1p5m = 10;
		rs6060_set_reg(dev, 0x41, 0x82);
	} else if (fcry_KHz == 24000) {
		div1m = 16;
		div1p5m = 8;
		rs6060_set_reg(dev, 0x41, 0x8a);

	} else {

		div1m = 19;
		div1p5m = 10;
		rs6060_set_reg(dev, 0x41, 0x82);

	}
	if (tuner_freq_MHz >= 1550) {
		ucLoDiv1 = 2;
		ucLomod1 = 0;
		refDiv1 = div1m;
		ucLoDiv2 = 2;
		ucLomod2 = 0;
		refDiv2 = div1m;
		lodiv_en_opt_div2 = 0;
	} else if (tuner_freq_MHz >= 1380) {
		ucLoDiv1 = 3;
		ucLomod1 = 16;
		refDiv1 = div1p5m;
		ucLoDiv2 = 2;
		ucLomod2 = 0;
		refDiv2 = div1m;
		lodiv_en_opt_div2 = 0;
	} else if (tuner_freq_MHz >= 1070) {
		ucLoDiv1 = 3;
		ucLomod1 = 16;
		refDiv1 = div1p5m;
		ucLoDiv2 = 3;
		ucLomod2 = 16;
		refDiv2 = div1p5m;
		lodiv_en_opt_div2 = 0;
	} else if (tuner_freq_MHz >= 1000) {
		ucLoDiv1 = 4;
		ucLomod1 = 64;
		refDiv1 = div1m;
		ucLoDiv2 = 4;
		ucLomod2 = 64;
		refDiv2 = div1m;
		lodiv_en_opt_div2 = 0;
	} else if (tuner_freq_MHz >= 775) {
		ucLoDiv1 = 4;
		ucLomod1 = 64;
		refDiv1 = div1m;
		ucLoDiv2 = 4;
		ucLomod2 = 64;
		refDiv2 = div1m;
		lodiv_en_opt_div2 = 0;
	} else if (tuner_freq_MHz >= 700) {
		ucLoDiv1 = 6;
		ucLomod1 = 48;
		refDiv1 = div1p5m;
		ucLoDiv2 = 4;
		ucLomod2 = 64;
		refDiv2 = div1m;
		lodiv_en_opt_div2 = 0;
	} else if (tuner_freq_MHz >= 520) {
		ucLoDiv1 = 6;
		ucLomod1 = 48;
		refDiv1 = div1p5m;
		ucLoDiv2 = 6;
		ucLomod2 = 48;
		refDiv2 = div1p5m;
		lodiv_en_opt_div2 = 0;
	} else if (tuner_freq_MHz >= 375) {
		ucLoDiv1 = 8;
		ucLomod1 = 96;
		refDiv1 = div1m;
		ucLoDiv2 = 8;
		ucLomod2 = 96;
		refDiv2 = div1m;
		lodiv_en_opt_div2 = 0;
	} else {
		ucLoDiv1 = 12;
		ucLomod1 = 80;
		refDiv1 = div1m;
		ucLoDiv2 = 12;
		ucLomod2 = 80;
		refDiv2 = div1m;
		lodiv_en_opt_div2 = 1;
	}

	ulNDiv1 =
	    ((tuner_freq_MHz * 1000 * ucLoDiv1) * (refDiv1 + 8) / fcry_KHz -
	     1024) / 2;
	ulNDiv2 =
	    ((tuner_freq_MHz * 1000 * ucLoDiv2) * (refDiv2 + 8) / fcry_KHz -
	     1024) / 2;

	reg27 = (((ulNDiv1 >> 8) & 0x0F) + ucLomod1) & 0x7F;

	rs6060_set_reg(dev, 0x27, reg27);
	rs6060_set_reg(dev, 0x28, (u8) (ulNDiv1 & 0xFF));

	reg29 = (((ulNDiv2 >> 8) & 0x0F) + ucLomod2) & 0x7f;

	rs6060_set_reg(dev, 0x29, reg29);
	rs6060_set_reg(dev, 0x2a, (u8) (ulNDiv2 & 0xFF));

	refDiv1 = refDiv1 & 0x1F;
	rs6060_set_reg(dev, 0x36, refDiv1);

	rs6060_set_reg(dev, 0x39, refDiv2);

	tmp = rs6060_get_reg(dev, 0x3d);
	if (lodiv_en_opt_div2 == 1)
		tmp |= 0x80;
	else
		tmp &= 0x7F;

	rs6060_set_reg(dev, 0x3d, tmp);

	if (refDiv1 == 19) {
		rs6060_set_reg(dev, 0x2c, 0x02);
	} else {
		rs6060_set_reg(dev, 0x2c, 0x00);
	}

	return 0;
}

static int rs6060_set_bb(struct m88rs6060_dev *dev,
			 u32 symbol_rate_KSs, s32 lpf_offset_KHz)
{
	u32 f3dB;
	u8 reg40;

	f3dB = symbol_rate_KSs * 9 / 14 + 2000;
	f3dB += lpf_offset_KHz;
	f3dB = clamp_val(f3dB, 6000U, 43000U);
	reg40 = f3dB / 1000;

	return rs6060_set_reg(dev, 0x40, reg40);

}

static void rs6060_init(struct m88rs6060_dev *dev)
{
	rs6060_set_reg(dev, 0x15, 0x6c);
	rs6060_set_reg(dev, 0x2b, 0x1e);

	rs6060_wakeup(dev);

	rs6060_set_reg(dev, 0x24, 0x4);
	rs6060_set_reg(dev, 0x6e, 0x39);
	rs6060_set_reg(dev, 0x83, 0x1);

	rs6060_set_reg(dev, 0x70, 0x90);
	rs6060_set_reg(dev, 0x71, 0xF0);
	rs6060_set_reg(dev, 0x72, 0xB6);
	rs6060_set_reg(dev, 0x73, 0xEB);
	rs6060_set_reg(dev, 0x74, 0x6F);
	rs6060_set_reg(dev, 0x75, 0xFC);

	return;
}

static void m88res6060_set_ts_mode(struct m88rs6060_dev *dev)
{
	unsigned tmp, val = 0;
	regmap_read(dev->regmap, 0x0b, &val);
	val &= ~0x1;
	regmap_write(dev->regmap, 0x0b, val);

	regmap_read(dev->regmap, 0xfd, &tmp);
	if (dev->config.ts_mode == MtFeTsOutMode_Parallel) {
		tmp &= ~0x01;
		tmp &= ~0x04;

		regmap_write(dev->regmap, 0xfa, 0x01);
		regmap_write(dev->regmap, 0xf1, 0x60);
		regmap_write(dev->regmap, 0xfa, 0x00);
	} else if (dev->config.ts_mode == MtFeTsOutMode_Serial) {

		tmp &= ~0x01;
		tmp |= 0x04;
	} else {
		tmp |= 0x01;
		tmp &= ~0x04;

		regmap_write(dev->regmap, 0xfa, 0x01);
		regmap_write(dev->regmap, 0xf1, 0x60);
		regmap_write(dev->regmap, 0xfa, 0x00);
	}

	tmp &= ~0xb8;
	tmp |= 0x42;
	tmp |= 0x80;
	regmap_write(dev->regmap, 0xfd, tmp);

	val = 0;
	if (dev->config.ts_mode != MtFeTsOutMode_Serial) {
		tmp = MT_FE_ENHANCE_TS_PIN_LEVEL_PARALLEL_CI;

		val |= tmp & 0x03;
		val |= (tmp << 2) & 0x0c;
		val |= (tmp << 4) & 0x30;
		val |= (tmp << 6) & 0xc0;
	} else {
		val = 0x00;
	}

	regmap_write(dev->regmap, 0x0a, val);

	regmap_read(dev->regmap, 0x0b, &tmp);
	if (dev->config.ts_pinswitch) {
		tmp |= 0x20;
	} else {
		tmp &= ~0x20;
	}
	tmp |= 0x1;
	regmap_write(dev->regmap, 0x0b, tmp);
	regmap_read(dev->regmap, 0x0c, &tmp);
	regmap_write(dev->regmap, 0xf4, 0x01);
	tmp &= ~0x80;
	regmap_write(dev->regmap, 0x0c, tmp);


	return;

}

static int m88rs6060_set_frontend(struct dvb_frontend *fe)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret;
	u32 symbol_rate_KSs;
	unsigned tmp, tmp1;
	static const struct reg_sequence reset_buf[] = {
		{0x7, 0x80}, {0x7, 0x0}

	};
	u32 realFreq;
	s16 lpf_offset_KHz = 0;
	u32 target_mclk = 144000;
	u32 u32tmp;
	s32 s32tmp;
	u32 pls_mode, pls_code;
	u8 pls[] = { 0x1, 0, 0 }, isi;
	u8 buf[2];
	int i = 0, j = 0;
	unsigned tsid[16];
	bool mis = false;

	dev_dbg(&i2c->dev,
		 "delivery_system=%u modulation=%u frequency=%u bandwidth_hz=%u symbol_rate=%u inversion=%u stream_id=%d\n",
		 c->delivery_system, c->modulation, c->frequency,
		 c->bandwidth_hz, c->symbol_rate, c->inversion, c->stream_id);

	if (!dev->warm) {
		ret = -EAGAIN;
		goto err;
	}

	if(dev->config.RF_switch)
		dev->config.RF_switch(i2c,dev->config.num,1);  //
		
	mutex_lock(&dev->base->i2c_mutex);
	
	symbol_rate_KSs = c->symbol_rate / 1000;
	realFreq = c->frequency;
	/*reset */
	ret = regmap_multi_reg_write(dev->regmap, reset_buf, 2);
	if (ret)
		goto err;

	msleep(2);
	/*clear ts */
	regmap_write(dev->regmap, 0xf5, 0x00);
	regmap_read(dev->regmap, 0xfd, &tmp);
	regmap_read(dev->regmap, 0xb2, &tmp);
	if (tmp == 0x01) {
		regmap_write(dev->regmap, 0x00, 0x0);
		regmap_write(dev->regmap, 0xb2, 0x0);
	}
	if (c->symbol_rate < 5000000) {
		lpf_offset_KHz = 3000;
		realFreq = c->frequency + 3000;
	}

	regmap_write(dev->regmap, 0x6, 0xe0);
	rs6060_select_mclk(dev, realFreq / 1000, symbol_rate_KSs);
	if (dev->mclk == 93000)
		regmap_write(dev->regmap, 0xa0, 0x42);
	else if (dev->mclk == 96000)
		regmap_write(dev->regmap, 0xa0, 0x44);
	else if (dev->mclk == 99000)
		regmap_write(dev->regmap, 0xa0, 0x46);
	else if (dev->mclk == 110250)
		regmap_write(dev->regmap, 0xa0, 0x4e);
	else
		regmap_write(dev->regmap, 0xa0, 0x44);

	regmap_read(dev->regmap, 0xfd, &tmp);
	rs6060_set_ts_mclk(dev, target_mclk);
	regmap_write(dev->regmap, 0x6, 0x0);
	msleep(10);

	rs6060_set_reg(dev, 0x5b, 0x4c);
	rs6060_set_reg(dev, 0x5c, 0x54);
	rs6060_set_reg(dev, 0x60, 0x4b);
	//set tuner pll
	ret = rs6060_set_pll_freq(dev, (realFreq + 500) / 1000);
	if (ret)
		goto err;
	ret = rs6060_set_bb(dev, symbol_rate_KSs, lpf_offset_KHz);
	if (ret)
		goto err;

	rs6060_set_reg(dev, 0x00, 0x1);
	rs6060_set_reg(dev, 0x00, 0x0);

	regmap_write(dev->regmap, 0xb2, 0x1);
	regmap_write(dev->regmap, 0x00, 0x1);

	for (i = 0; i < (sizeof(rs6060_reg_tbl_def) / 2); i++)
		ret =
		    regmap_write(dev->regmap, rs6060_reg_tbl_def[i].reg,
				 rs6060_reg_tbl_def[i].val);

	if (ret)
		goto err;

	if ((symbol_rate_KSs > 47100) && (symbol_rate_KSs < 47500)) {
		regmap_write(dev->regmap, 0xe6, 0x00);
		regmap_write(dev->regmap, 0xe7, 0x03);
	}

	regmap_read(dev->regmap, 0x4d, &tmp);
	tmp &= (~0x2);
	regmap_write(dev->regmap, 0x4d, tmp);

	regmap_read(dev->regmap, 0x08, &tmp);
	regmap_write(dev->regmap, 0x08, tmp & 0x7f);

	regmap_read(dev->regmap, 0xc9, &tmp);
	regmap_write(dev->regmap, 0xc9, tmp | 0x8);

	if (symbol_rate_KSs <= 3000)
		tmp = 0x20;
	else if (symbol_rate_KSs <= 10000)
		tmp = 0x10;
	else
		tmp = 0x6;

	regmap_write(dev->regmap, 0xc3, 0x8);
	regmap_write(dev->regmap, 0xc8, tmp);
	regmap_write(dev->regmap, 0xc4, 0x8);
	regmap_write(dev->regmap, 0xc7, 0x0);

	u32tmp = ((symbol_rate_KSs << 15) + (dev->mclk / 4)) / (dev->mclk / 2);

	regmap_write(dev->regmap, 0x61, (u8) (u32tmp & 0xff));
	regmap_write(dev->regmap, 0x62, (u8) ((u32tmp >> 8) & 0xff));

	regmap_read(dev->regmap, 0x76, &tmp);
	regmap_write(dev->regmap, 0x76, 0x30);

	regmap_write(dev->regmap, 0x22, pls[0]);
	regmap_write(dev->regmap, 0x23, pls[1]);
	regmap_write(dev->regmap, 0x24, pls[2]);

	regmap_read(dev->regmap, 0x08, &tmp);
	switch (c->delivery_system) {
	case SYS_DVBS:
		tmp = (tmp & 0xfb) | 0x40;
		regmap_write(dev->regmap, 0x08, tmp);
		regmap_write(dev->regmap, 0xe0, 0xf8);
		break;
	case SYS_DVBS2:
		tmp |= 0x44;
		regmap_write(dev->regmap, 0x08, tmp);
		break;
	default:
		tmp &= 0xbb;
		regmap_write(dev->regmap, 0x08, tmp);
		regmap_write(dev->regmap, 0xe0, 0xf8);
	}

//	regmap_write(dev->regmap, 0x08, 3);
//	regmap_write(dev->regmap, 0xe0, 0xf8);

	s32tmp = 0x10000 * lpf_offset_KHz;
	s32tmp = (2 * s32tmp + dev->mclk) / (2 * dev->mclk);
	buf[0] = (s32tmp >> 0) & 0xff;
	buf[1] = (s32tmp >> 8) & 0xff;
	//ret = regmap_bulk_write(dev->regmap, 0x5e, buf, 2);
	ret = regmap_write(dev->regmap, 0x5e, buf[0]);
	ret = regmap_write(dev->regmap, 0x5f, buf[1]);
	if (ret)
		goto err;

	ret = regmap_write(dev->regmap, 0x00, 0x00);
	if (ret)
		goto err;

	ret = regmap_write(dev->regmap, 0xb2, 0x00);
	if (ret)
		goto err;

	
//	ret = regmap_write(dev->regmap, 0xfe, 0xe1);
//	if (ret)
//		goto err;

//	ret = regmap_write(dev->regmap, 0xea, 0x4);
	//if (ret)
//		goto err;
	if (c->stream_id != NO_STREAM_ID_FILTER) {
		isi = c->stream_id & 0xff;
		pls_mode = (c->stream_id >> 26) & 3;
		pls_code = (c->stream_id >> 8) & 0x3ffff;
		if (!pls_mode && !pls_code)
			pls_code = 1;
	} else {
		isi = 0;
		pls_mode = 0;
		pls_code = 1;
	}

	if (c->scrambling_sequence_index) {
		pls_mode = 1;
		pls_code = c->scrambling_sequence_index;
	}

	if (pls_mode)
		m88rs6060_calc_PLS_gold_code(pls, pls_code);
	else {
		pls[0] = pls_code & 0xff;
		pls[1] = (pls_code >> 8) & 0xff;
		pls[2] = (pls_code >> 16) & 3;
	}

	dev_dbg(&i2c->dev, "isi = %d", isi);
	dev_dbg(&i2c->dev, "pls mode %d, code %d\n", pls_mode, pls_code);
	dev_dbg(&i2c->dev, "pls buf =%*ph \n", 3, pls);

	ret = regmap_bulk_write(dev->regmap, 0x22, pls, 3);

	rs6060_set_reg(dev, 0x5b, 0xcc);
	rs6060_set_reg(dev, 0x5c, 0xf4);
	rs6060_set_reg(dev, 0x60, 0xcb);

	for (i = 0; i < 150; i++) {
		regmap_read(dev->regmap, 0x8, &tmp);
		regmap_read(dev->regmap, 0xd, &tmp1);

		if ((tmp1 == 0x8f) || (tmp1 == 0xf7))
			break;
		msleep(20);
	}

	if (tmp1 == 0x8f) {
		regmap_read(dev->regmap, 0x89, &tmp);
		regmap_read(dev->regmap, 0xca, &tmp1);
		tmp &= 0x80;
		regmap_write(dev->regmap, 0xca,
			     (u8) ((tmp1 & 0xf7) | (tmp >> 4) | 0x02));
		regmap_write(dev->regmap, 0xfa, 0x00);
		regmap_write(dev->regmap, 0xf0, 0x00);
		regmap_write(dev->regmap, 0xf0, 0x03);

		msleep(20);
		regmap_read(dev->regmap, 0xf1, &tmp1);
		tmp1 &= 0x1f;
		dev_dbg(&i2c->dev, "ISI cnt = %d \n", tmp1);
		for (j = 0; j < tmp1; j++) {
			regmap_write(dev->regmap, 0xf2, j);
			regmap_read(dev->regmap, 0xf3, &tsid[j]);
			dev_dbg(&i2c->dev, "ISI = %d \n", tsid[j]);
		}
		for (j = 0; j < tmp1; j++)
			if (tsid[j] == isi) {
				mis = true;
				break;
			}

		if (mis)
			regmap_write(dev->regmap, 0xf5, isi);
		else
			regmap_write(dev->regmap, 0xf5, tsid[0]);
	}

	dev->TsClockChecked = true;
	
	if(dev->config.HAS_CI)
		dev->newTP = true;
		
	mutex_unlock(&dev->base->i2c_mutex);
	return 0;

 err:
 	mutex_unlock(&dev->base->i2c_mutex);
	dev_dbg(&i2c->dev, "failed = %d", ret);
	return ret;
}

static enum dvbfe_algo m88rs6060_get_algo(struct dvb_frontend *fe)
{
	return DVBFE_ALGO_HW;
}

static int m88rs6060_init(struct dvb_frontend *fe)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;

	/*warm state */
	dev->warm = true;

	//
	c->cnr.len = 1;
	c->cnr.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	c->post_bit_error.len = 1;
	c->post_bit_error.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	c->post_bit_count.len = 1;
	c->post_bit_count.stat[0].scale = FE_SCALE_NOT_AVAILABLE;

	//dev_info(&i2c->dev, "%s finished\n", __func__);

	return 0;

}
static int m88rs6060_get_sym_rate(struct m88rs6060_dev *dev,
						u32 *sym_rate_KSs)
{
	u16 tmp;
	u32 sym_rate_tmp;
	unsigned val_0x6d,val_0x6e;

	regmap_read(dev->regmap,0x6d,&val_0x6d);
	regmap_read(dev->regmap,0x6e,&val_0x6e);

	tmp = (u16)((val_0x6e<<8)|val_0x6d);
	sym_rate_tmp = tmp*dev->mclk;
	sym_rate_tmp /= (1<<16);
	*sym_rate_KSs = sym_rate_tmp;

	return 0;
}
static int m88rs6060_get_channel_info(struct m88rs6060_dev *dev,
						struct MT_FE_CHAN_INFO_DVBS2*p_info)
{
	unsigned tmp,val_0x17,val_0x18,ucPLSCode;
	
	regmap_read(dev->regmap,0x08,&tmp);
	if((tmp&0x08)==0x08){    //dvbs2 signal

		p_info->type = MtFeType_DvbS2;
		
		regmap_write(dev->regmap,0x8a,0x01);
		regmap_read(dev->regmap,0x17,&val_0x17);
		p_info->is_dummy_frame = (val_0x17&0x40)?true:false;

		regmap_read(dev->regmap,0x18,&val_0x18);
		tmp = (val_0x18>>5) & 0x07;
		switch(tmp){
		    case 1: p_info->mod_mode = MtFeModMode_8psk; break;
			case 2: p_info->mod_mode = MtFeModMode_16Apsk; break;
		    case 3: p_info->mod_mode = MtFeModMode_32Apsk; break;
		    case 4: p_info->mod_mode = MtFeModMode_64Apsk; break;
		    case 5: p_info->mod_mode = MtFeModMode_128Apsk; break;
		    case 6: 
		    case 7: p_info->mod_mode = MtFeModMode_256Apsk; break;
		    case 0: 
			default: p_info->mod_mode = MtFeModMode_Qpsk; break;
		
		}
		p_info->iVcmCycle = val_0x18 &0x1F;
		regmap_read(dev->regmap,0x19,&ucPLSCode);
		p_info->iPlsCode = ucPLSCode;
		p_info->type = mPLSInfoTable[ucPLSCode].mDvbType;

		if(mPLSInfoTable[ucPLSCode].bValid){
			p_info->mod_mode = mPLSInfoTable[ucPLSCode].mModMode;
			p_info->code_rate = mPLSInfoTable[ucPLSCode].mCodeRate;
			p_info->is_dummy_frame = mPLSInfoTable[ucPLSCode].bDummyFrame;
			p_info->is_pilot_on = mPLSInfoTable[ucPLSCode].bPilotOn;
			p_info->iFrameLength = mPLSInfoTable[ucPLSCode].iFrameLength;

		}else{
			//p_info->mod_mode = mPLSInfoTable[ucPLSCode].mModMode;
			p_info->code_rate = mPLSInfoTable[ucPLSCode].mCodeRate;
			//p_info->is_dummy_frame = mPLSInfoTable[ucPLSCode].bDummyFrame;
			p_info->is_pilot_on = mPLSInfoTable[ucPLSCode].bPilotOn;
			p_info->iFrameLength = mPLSInfoTable[ucPLSCode].iFrameLength;

		}

		regmap_read(dev->regmap,0x89,&tmp);
		p_info->is_spectrum_inv = 
			((tmp&0x80)!=0)? MtFeSpectrum_Inversion: MtFeSpectrum_Normal;

		regmap_read(dev->regmap,0x76,&tmp);
		tmp &=0x03;
		if(p_info->type == MtFeType_DvbS2X){  //dvbs2x
			switch(tmp){
				case 0 : p_info->roll_off = MtFeRollOff_0p15;break;
				case 1 : p_info->roll_off = MtFeRollOff_0p10;break;
				case 2 : p_info->roll_off = MtFeRollOff_0p05;break;
				default : p_info->roll_off = MtFeRollOff_Undef;break;
				
			}
		}else{    //dvbs2
				switch(tmp){
				case 0 : p_info->roll_off = MtFeRollOff_0p35;break;
				case 1 : p_info->roll_off = MtFeRollOff_0p25;break;
				case 2 : p_info->roll_off = MtFeRollOff_0p20;break;
				default : p_info->roll_off = MtFeRollOff_Undef;break;
				
			}
			}
	}
	else{
		p_info->type = MtFeType_DvbS;
		p_info->mod_mode = MtFeModMode_Qpsk;

		regmap_read(dev->regmap,0xe6,&tmp);
		tmp= (u8)tmp>>5;
		switch(tmp){
			case 0 : p_info->code_rate = MtFeCodeRate_7_8;break;
			case 1 : p_info->code_rate = MtFeCodeRate_5_6;break;
			case 2 : p_info->code_rate = MtFeCodeRate_3_4;break;
			case 3 : p_info->code_rate = MtFeCodeRate_2_3;break;
			case 4 : p_info->code_rate = MtFeCodeRate_1_2;break;
			default : p_info->code_rate = MtFeCodeRate_Undef;break;
		}
		p_info->is_pilot_on = false;
		regmap_read(dev->regmap,0xe0,&tmp);
		p_info->is_spectrum_inv = 
			((tmp&0x40)!=0)? MtFeSpectrum_Inversion: MtFeSpectrum_Normal;
		p_info->roll_off = MtFeRollOff_0p35;
		p_info->is_dummy_frame = false;
		p_info->iVcmCycle = -1;
		p_info->iPlsCode = 0;
		p_info->iFrameLength = 0;
	}

	return 0;
}
static int rs6060_select_xm(struct m88rs6060_dev*dev,u32 *xm_KHz)
{
	u32 symbol_rate = 0;
	u8 reg16;
	u32 offset_KHz[8] = {0};
	u32 max_offset = 0;
	u8 i, xm_line, xm_cnt = 5;
	u32 xm_list_KHz[3][8] = {
							{96000, 102400, 107162, 109714, 115200, 128000, 135529, 144000},
							{93000,  99200, 111600, 117473, 124000, 139500, 144000, 148800},
							{99000, 105600, 108000, 110511, 118800, 132000, 144000, 148500}
						   };


	
	m88rs6060_get_sym_rate(dev,&symbol_rate);
	xm_cnt = sizeof(xm_list_KHz) / sizeof(u32);
	xm_cnt /= 3;
	// C = (symbol * 1.35 / 2 + 2) * 1.1;
	symbol_rate *= 135;
	symbol_rate /= 200;
	symbol_rate += 2000;
	symbol_rate *= 110;
	symbol_rate /= 100;

	reg16 = rs6060_get_reg(dev, 0x16);

	if(reg16 == 92){
		xm_line = 1;
	}
	else if(reg16 == 100){
		xm_line = 2;
	}
	else{//if(reg16 == 96)
		xm_line = 0;
	}

	for(i = 0; i < xm_cnt; i ++){
		if(*xm_KHz > xm_list_KHz[xm_line][i])
		{
			continue;
		}
		offset_KHz[i] = (dev->frequecy % xm_list_KHz[xm_line][i]);
		if(offset_KHz[i] > (xm_list_KHz[xm_line][i] / 2))
			offset_KHz[i] = xm_list_KHz[xm_line][i] - offset_KHz[i];
		if(offset_KHz[i] > symbol_rate)
		{
			*xm_KHz = xm_list_KHz[xm_line][i];
			break;
		}
		if(offset_KHz[i] > max_offset)
		{
			max_offset = offset_KHz[i];
			*xm_KHz = xm_list_KHz[xm_line][i];
		}
	 }

	if(i == xm_cnt)
	{
		*xm_KHz = xm_list_KHz[xm_line][xm_cnt - 1];
	}

	return 0;
}

static int m88rs6060_set_clock_ratio(struct m88rs6060_dev *dev )
{
	struct i2c_adapter *i2c = dev->base->i2c;
	unsigned mod_fac,tmp1,tmp2,val;
	u32 input_datarate,locked_sym_rate_KSs;
	u32 Mclk_KHz = 96000,iSerialMclkHz;
	u16 divid_ratio = 0;
	struct MT_FE_CHAN_INFO_DVBS2 p_info;
	
	m88rs6060_get_sym_rate(dev,&locked_sym_rate_KSs);

	regmap_read(dev->regmap,0x9d,&val);
	regmap_write(dev->regmap,0x9d,val|0x08);

	m88rs6060_get_channel_info(dev,&p_info);

	if(p_info.type==MtFeType_DvbS2){
		dev_dbg(&i2c->dev, "iPlsCode = 0x%02X\n", p_info.iPlsCode);
		switch(p_info.mod_mode)
		{
			case MtFeModMode_8psk:
			case MtFeModMode_8Apsk_L:       mod_fac = 3; break;
			case MtFeModMode_16Apsk:
			case MtFeModMode_16Apsk_L:      mod_fac = 4; break;
			case MtFeModMode_32Apsk:
			case MtFeModMode_32Apsk_L:      mod_fac = 5; break;
			case MtFeModMode_64Apsk:
			case MtFeModMode_64Apsk_L:      mod_fac = 6; break;
			case MtFeModMode_128Apsk:
			case MtFeModMode_128Apsk_L:     mod_fac = 7; break;
			case MtFeModMode_256Apsk:
			case MtFeModMode_256Apsk_L:     mod_fac = 8; break;
			case MtFeModMode_Qpsk:
			default:                        mod_fac = 2; break;
		}
		switch(p_info.code_rate)
		{
			case MtFeCodeRate_1_4:		input_datarate = locked_sym_rate_KSs*mod_fac/8/4;		break;
			case MtFeCodeRate_1_3:		input_datarate = locked_sym_rate_KSs*mod_fac/8/3;		break;
			case MtFeCodeRate_2_5:		input_datarate = locked_sym_rate_KSs*mod_fac*2/8/5;		break;
			case MtFeCodeRate_1_2:		input_datarate = locked_sym_rate_KSs*mod_fac/8/2;		break;
			case MtFeCodeRate_3_5:		input_datarate = locked_sym_rate_KSs*mod_fac*3/8/5;		break;
			case MtFeCodeRate_2_3:		input_datarate = locked_sym_rate_KSs*mod_fac*2/8/3;		break;
			case MtFeCodeRate_3_4:		input_datarate = locked_sym_rate_KSs*mod_fac*3/8/4;		break;
			case MtFeCodeRate_4_5:		input_datarate = locked_sym_rate_KSs*mod_fac*4/8/5;		break;
			case MtFeCodeRate_5_6:		input_datarate = locked_sym_rate_KSs*mod_fac*5/8/6;		break;
			case MtFeCodeRate_8_9:		input_datarate = locked_sym_rate_KSs*mod_fac*8/8/9;		break;
			case MtFeCodeRate_9_10:		input_datarate = locked_sym_rate_KSs*mod_fac*9/8/10;	break;
			case MtFeCodeRate_5_9:		input_datarate = locked_sym_rate_KSs*mod_fac*5/8/9;		break;
			case MtFeCodeRate_7_9:		input_datarate = locked_sym_rate_KSs*mod_fac*7/8/9;		break;
			case MtFeCodeRate_4_15:		input_datarate = locked_sym_rate_KSs*mod_fac*4/8/15;	break;
			case MtFeCodeRate_7_15:		input_datarate = locked_sym_rate_KSs*mod_fac*7/8/15;	break;
			case MtFeCodeRate_8_15:		input_datarate = locked_sym_rate_KSs*mod_fac*8/8/15;	break;
			case MtFeCodeRate_11_15:	input_datarate = locked_sym_rate_KSs*mod_fac*11/8/15;	break;
			case MtFeCodeRate_13_18:	input_datarate = locked_sym_rate_KSs*mod_fac*13/8/18;	break;
			case MtFeCodeRate_9_20:		input_datarate = locked_sym_rate_KSs*mod_fac*9/8/20;	break;
			case MtFeCodeRate_11_20:	input_datarate = locked_sym_rate_KSs*mod_fac*11/8/20;	break;
			case MtFeCodeRate_23_36:	input_datarate = locked_sym_rate_KSs*mod_fac*23/8/36;	break;
			case MtFeCodeRate_25_36:	input_datarate = locked_sym_rate_KSs*mod_fac*25/8/36;	break;
			case MtFeCodeRate_11_45:	input_datarate = locked_sym_rate_KSs*mod_fac*11/8/45;	break;
			case MtFeCodeRate_13_45:	input_datarate = locked_sym_rate_KSs*mod_fac*13/8/45;	break;
			case MtFeCodeRate_14_45:	input_datarate = locked_sym_rate_KSs*mod_fac*14/8/45;	break;
			case MtFeCodeRate_26_45:	input_datarate = locked_sym_rate_KSs*mod_fac*26/8/45;	break;
			case MtFeCodeRate_28_45:	input_datarate = locked_sym_rate_KSs*mod_fac*28/8/45;	break;
			case MtFeCodeRate_29_45:	input_datarate = locked_sym_rate_KSs*mod_fac*29/8/45;	break;
			case MtFeCodeRate_31_45:	input_datarate = locked_sym_rate_KSs*mod_fac*31/8/45;	break;
			case MtFeCodeRate_32_45:	input_datarate = locked_sym_rate_KSs*mod_fac*32/8/45;	break;
			case MtFeCodeRate_77_90:	input_datarate = locked_sym_rate_KSs*mod_fac*77/8/90;	break;
			default:					input_datarate = locked_sym_rate_KSs*mod_fac*2/8/3;		break;

		}

		rs6060_get_ts_mclk(dev,&Mclk_KHz);
		if(dev->config.ts_mode==MtFeTsOutMode_Serial){
			u32 target_mclk = Mclk_KHz;
			input_datarate*=8;

			target_mclk = input_datarate;
			rs6060_select_xm(dev,&target_mclk);
			if(target_mclk != Mclk_KHz){
				regmap_write(dev->regmap,0x06,0xe0);
				rs6060_set_ts_mclk(dev,target_mclk);
				regmap_write(dev->regmap,0x06,0x00);
			}

			rs6060_get_ts_mclk(dev,&iSerialMclkHz);
			if(iSerialMclkHz>116000)
				regmap_write(dev->regmap,0x0a,0x01);
			else
				regmap_write(dev->regmap,0x0a,0x00);
		}else{
			iSerialMclkHz = input_datarate*49/5;
			input_datarate = input_datarate *105/100;
			if(iSerialMclkHz>115200)
				iSerialMclkHz = 144000;
			else if(iSerialMclkHz>96000)
				iSerialMclkHz = 115200;
			else if(iSerialMclkHz>72000)
				iSerialMclkHz = 96000;
			else
				iSerialMclkHz = 72000;
			if(input_datarate<6000)
				input_datarate= 6000;
			if(input_datarate != 0)
				divid_ratio = (u16) (Mclk_KHz/input_datarate);
			else
				divid_ratio = 0xff;
			dev_dbg(&i2c->dev, "MClk_KHz = %d,divid_ratio = %d \n", Mclk_KHz, divid_ratio);

			if(divid_ratio<8)
				divid_ratio = 8;
			if(dev->config.ts_mode == MtFeTsOutMode_Common){
				if(divid_ratio>27)
					divid_ratio = 27;
				if((divid_ratio == 14)||(divid_ratio==15))
					divid_ratio = 13;
				if((divid_ratio == 19)||(divid_ratio == 20))
					divid_ratio = 18;
			}else{
				if(divid_ratio>24)
					divid_ratio = 24;
				if((divid_ratio == 12)||(divid_ratio==13))
					divid_ratio = 11;
				if((divid_ratio == 19)||(divid_ratio == 20))
					divid_ratio = 18;
			}
			tmp1 = (u8) ((divid_ratio/2)-1);
			tmp2 = DIV_ROUND_UP(divid_ratio,2)-1;
			tmp1 &= 0x3f;
			tmp2 &= 0x3f;
			val = (tmp1 >>2)&0x0f;
			regmap_update_bits(dev->regmap,0xfe,0x0f,val);
			val = (u8)(((tmp1&0x3)<<6)|tmp2);
			regmap_write(dev->regmap,0xea,val);
		}
	}
	else{    //dvbs
	  mod_fac = 2;
	  switch(p_info.code_rate){
	  	case MtFeCodeRate_1_2:		input_datarate = locked_sym_rate_KSs*mod_fac/2/8;		break;
		case MtFeCodeRate_2_3:		input_datarate = locked_sym_rate_KSs*mod_fac*2/3/8;		break;
		case MtFeCodeRate_3_4:		input_datarate = locked_sym_rate_KSs*mod_fac*3/4/8;		break;
		case MtFeCodeRate_5_6:		input_datarate = locked_sym_rate_KSs*mod_fac*5/6/8;		break;
		case MtFeCodeRate_7_8:		input_datarate = locked_sym_rate_KSs*mod_fac*7/8/8;		break;
		default:		input_datarate = locked_sym_rate_KSs*mod_fac*3/4/8;		break;
	  }
		rs6060_get_ts_mclk(dev,&Mclk_KHz);

		if(dev->config.ts_mode==MtFeTsOutMode_Serial){
			u32 target_mclk = Mclk_KHz;
			input_datarate*=8;

		//	target_mclk = input_datarate;
				rs6060_select_xm(dev,&target_mclk);
			if(target_mclk != Mclk_KHz){
				regmap_write(dev->regmap,0x06,0xe0);
				rs6060_set_ts_mclk(dev,target_mclk);
				regmap_write(dev->regmap,0x06,0x00);
			}

			rs6060_get_ts_mclk(dev,&iSerialMclkHz);
			if(iSerialMclkHz>116000)
				regmap_write(dev->regmap,0x0a,0x01);
			else
				regmap_write(dev->regmap,0x0a,0x00);
			
		  }else{
				iSerialMclkHz = input_datarate*46/5;
				input_datarate = input_datarate *105/100;

				if(iSerialMclkHz>72000)
					iSerialMclkHz = 96000;
				else
					iSerialMclkHz = 72000;

				if(input_datarate<6000)
					input_datarate = 6000;
				if(input_datarate != 0)
					divid_ratio = (u16)(Mclk_KHz/input_datarate);
				else
					divid_ratio = 0xff;
				if(divid_ratio<8)
					divid_ratio = 8;
				if(dev->config.ts_mode == MtFeTsOutMode_Common){
					if(divid_ratio>27)
						divid_ratio=27;
					}
				else {
					if (divid_ratio>24)
						divid_ratio =24;
					}
				tmp1 = (u8)((divid_ratio/2)-1);
				tmp2 = DIV_ROUND_UP(divid_ratio,2)-1;

				tmp1 &= 0x3f;
				tmp2 &= 0x3f;
				val = (tmp1 >>2)&0x0f;
				regmap_update_bits(dev->regmap,0xfe,0x0f,val);
				val = (u8)(((tmp1&0x3)<<6)|tmp2);
				regmap_write(dev->regmap,0xea,val);		
			}
	}
	return 0;	
}
static int m88rs6060_read_status(struct dvb_frontend *fe,
				 enum fe_status *status)
{
		struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret, i, itmp;
	unsigned int utmp;
	u8 buf[3];
	s32 gain;
	u16 temp;
	dev_dbg(&i2c->dev, "%s\n", __func__);

	*status = 0;

	if (!dev->warm) {
		ret = -EAGAIN;
		goto err;
	}
	mutex_lock(&dev->base->i2c_mutex);
	switch (c->delivery_system) {
	case SYS_DVBS:
		ret = regmap_read(dev->regmap, 0x0d, &utmp);
		if (ret)
			goto err;

		if ((utmp & 0xf7) == 0xf7)
			*status = FE_HAS_SIGNAL | FE_HAS_CARRIER |
			    FE_HAS_VITERBI | FE_HAS_SYNC | FE_HAS_LOCK;
		break;
	case SYS_DVBS2:
		ret = regmap_read(dev->regmap, 0x0d, &utmp);
		if (ret)
			goto err;

		if ((utmp & 0x8f) == 0x8f)
			*status = FE_HAS_SIGNAL | FE_HAS_CARRIER |
			    FE_HAS_VITERBI | FE_HAS_SYNC | FE_HAS_LOCK;
		break;
	default:
		dev_dbg(&i2c->dev, "invalid delivery_system\n");
		ret = -EINVAL;
		goto err;
	}

	dev->fe_status = *status;
	dev_dbg(&i2c->dev, "lock=%02x status=%02x\n", utmp, *status);

	if ((!dev->config.ts_autoclock)&&(dev->fe_status & FE_HAS_LOCK)&&(dev->TsClockChecked)){
		dev->TsClockChecked = false;
		dev->frequecy = c->frequency;
		m88rs6060_set_clock_ratio(dev);
	}

	if((dev->config.HAS_CI)&&(dev->fe_status & FE_HAS_LOCK)&&(dev->newTP))
	{
		mutex_lock(&dev->priv->base1->i2c_mutex_ci);
		u32 value;
		u32 clock;
		clock = dev->config.SetCIClock(i2c,dev->config.num);
		value = (clock/8*204/188*25000/6)+500;
	//	printk("clk port = %d,clock = %d,value=%d\n",dev->priv->clk_port,clock,value);
		si5351_set_freq(dev->priv,value,0,dev->priv->clk_port);
		mutex_unlock(&dev->priv->base1->i2c_mutex_ci);
		dev->newTP = false;
	}	
	/*power of rf signal */
	m88rs6060_get_gain(dev, c->frequency / 1000, &gain);
	c->strength.len = 2;
	c->strength.stat[0].scale = FE_SCALE_DECIBEL;
	c->strength.stat[0].svalue = -gain * 10;

	c->strength.stat[1].scale = FE_SCALE_RELATIVE;
	c->strength.stat[1].svalue = (100 + (-gain / 100)) * 656;

	c->cnr.len = 1;
	c->cnr.stat[0].scale = FE_SCALE_NOT_AVAILABLE;

	if (dev->fe_status & FE_HAS_VITERBI) {
		unsigned int cnr, noise, signal, noise_tot, signal_tot;

		cnr = 0;
		/* more iterations for more accurate estimation */
#define M88rs6060_SNR_ITERATIONS 10

		switch (c->delivery_system) {
		case SYS_DVBS:
			itmp = 0;

			for (i = 0; i < M88rs6060_SNR_ITERATIONS; i++) {
				ret = regmap_read(dev->regmap, 0xff, &utmp);
				if (ret)
					goto err;

				itmp += utmp;
			}
			temp = (u16) (itmp / 80);

			if (temp > 32)
				temp = 32;
			if (temp > 1)
				cnr = (mes_loge[temp - 1] * 10) / 23;
			else
				cnr = 0;
			break;
		case SYS_DVBS2:
			noise_tot = 0;
			signal_tot = 0;

			for (i = 0; i < M88rs6060_SNR_ITERATIONS; i++) {
				ret =
				    regmap_bulk_read(dev->regmap, 0x8c, buf, 3);
				if (ret)
					goto err;

				noise = buf[1] << 6;	/* [13:6] */
				noise |= buf[0] & 0x3f;	/*  [5:0] */
				noise >>= 2;
				signal = buf[2] * buf[2];
				signal >>= 1;

				noise_tot += noise;
				signal_tot += signal;
			}

			noise = noise_tot / M88rs6060_SNR_ITERATIONS;
			signal = signal_tot / M88rs6060_SNR_ITERATIONS;
			if (signal == 0)
				cnr = 0;
			else if (noise == 0)
				cnr = 19;
			else if (signal > noise) {
				itmp = signal / noise;
				if (itmp > 80)
					itmp = 80;
				cnr = mes_log10[itmp - 1];
			} else if (signal < noise) {
				itmp = noise / signal;
				if (itmp > 80)
					itmp = 80;
				cnr = mes_log10[itmp - 1];
			}
			break;
		default:
			dev_dbg(&i2c->dev, "invalid delivery_system\n");
			ret = -EINVAL;
			goto err;
		}

		c->cnr.len = 2;
		c->cnr.stat[0].scale = FE_SCALE_DECIBEL;
		c->cnr.stat[0].svalue = cnr;
		c->cnr.stat[1].scale = FE_SCALE_RELATIVE;
		c->cnr.stat[1].uvalue = (cnr/100) * 328;
		if (c->cnr.stat[1].uvalue > 0xffff)
			c->cnr.stat[1].uvalue = 0xffff;
	}

	/* BER */
	if (dev->fe_status & FE_HAS_LOCK) {
		unsigned int utmp, post_bit_error, post_bit_count;

		switch (c->delivery_system) {
		case SYS_DVBS:

			ret = regmap_read(dev->regmap, 0xd5, &utmp);
			if (ret)
				goto err;

			/* measurement ready? */
			if (!(utmp & 0x10)) {
				ret =
				    regmap_bulk_read(dev->regmap, 0xd6, buf, 2);
				if (ret)
					goto err;

				post_bit_error = buf[1] << 8 | buf[0] << 0;
				post_bit_count = 0x800000;
				dev->post_bit_error += post_bit_error;
				dev->post_bit_count += post_bit_count;
				dev->dvbv3_ber = post_bit_error;

				/* restart measurement */
				ret = regmap_write(dev->regmap, 0xd5, 0x82);
				if (ret)
					goto err;
			}
			break;
		case SYS_DVBS2:
			ret = regmap_bulk_read(dev->regmap, 0xd5, buf, 3);
			if (ret)
				goto err;
			//dev_info(&i2c->dev,"buf =%*ph\n",3,buf);
			utmp = buf[2] << 16 | buf[1] << 8 | buf[0] << 0;

			/* enough data? */
			if (utmp > 4000) {
				ret =
				    regmap_bulk_read(dev->regmap, 0xf7, buf, 2);
				if (ret)
					goto err;

				post_bit_error = buf[1] << 8 | buf[0] << 0;
				post_bit_count = 32 * utmp;	/* TODO: FEC */
				dev->post_bit_error += post_bit_error;
				dev->post_bit_count += post_bit_count;
				dev->dvbv3_ber = post_bit_error;

				/* restart measurement */
				ret = regmap_write(dev->regmap, 0xd1, 0x01);
				if (ret)
					goto err;

				ret = regmap_write(dev->regmap, 0xf9, 0x01);
				if (ret)
					goto err;

				ret = regmap_write(dev->regmap, 0xf9, 0x00);
				if (ret)
					goto err;

				ret = regmap_write(dev->regmap, 0xd1, 0x00);
				if (ret)
					goto err;
			}
			break;
		default:
			dev_dbg(&i2c->dev, "invalid delivery_system\n");
			ret = -EINVAL;
			goto err;
		}

		c->post_bit_error.stat[0].scale = FE_SCALE_COUNTER;
		c->post_bit_error.stat[0].uvalue = dev->post_bit_error;

		c->post_bit_count.stat[0].scale = FE_SCALE_COUNTER;
		c->post_bit_count.stat[0].uvalue = dev->post_bit_count;
	} else {
		c->post_bit_error.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
		c->post_bit_count.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	}

	c->post_bit_error.len = 1;
	c->post_bit_count.len = 1;
	
	mutex_unlock(&dev->base->i2c_mutex);
	
	return 0;
 err:
 	mutex_unlock(&dev->base->i2c_mutex);
	dev_dbg(&i2c->dev, "failed=%d\n", ret);
	return ret;
}

static int m88rs6060_read_snr(struct dvb_frontend *fe, u16 * snr)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;
	int i;

	*snr = 0;
	for (i=0; i < p->cnr.len; i++)
		if (p->cnr.stat[i].scale == FE_SCALE_RELATIVE)
		  *snr = (u16)p->cnr.stat[i].uvalue;

	return 0;
}

static int m88rs6060_read_ber(struct dvb_frontend *fe, u32 * ber)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;

	if ( p->post_bit_error.stat[0].scale == FE_SCALE_COUNTER &&
		p->post_bit_count.stat[0].scale == FE_SCALE_COUNTER )
		*ber = (u32)p->post_bit_count.stat[0].uvalue ? (u32)p->post_bit_error.stat[0].uvalue /
					(u32)p->post_bit_count.stat[0].uvalue : 0;

	return 0;
}

static int m88rs6060_read_signal_strength(struct dvb_frontend *fe,
					  u16 * strength)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;
	int i;

	*strength = 0;
	for (i=0; i < p->strength.len; i++)
		if (p->strength.stat[i].scale == FE_SCALE_RELATIVE)
			*strength = (u16)p->strength.stat[i].uvalue;

	return 0;
}

static int m88rs6060_set_voltage(struct dvb_frontend*fe,
								enum fe_sec_voltage voltage)
{
		struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;
	int ret;
	u8 utmp;
	bool voltage_sel, lnb_power;

	
	switch(voltage){
		case SEC_VOLTAGE_18:
			voltage_sel = 1;
			lnb_power = 1;
			break;
		case SEC_VOLTAGE_13:
			voltage_sel = 0;
			lnb_power = 1;		
			break;
		case SEC_VOLTAGE_OFF:
			voltage_sel = 0;
			lnb_power = 0;		
			break;
	}
	utmp = lnb_power << 1 | voltage_sel << 0;
	ret = m88rs6060_update_bits(dev, 0xa2, 0x03, utmp);
	if (ret)
		goto err;

	return 0;
err:
	dev_dbg(&i2c->dev, "failed=%d\n", ret);
	return ret;
	
}

static int m88rs6060_set_tone(struct dvb_frontend *fe,
			      enum fe_sec_tone_mode fe_sec_tone_mode)
{
		struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;
	int ret;
	unsigned int utmp, tone, reg_a1_mask;

	dev_dbg(&i2c->dev, "fe_sec_tone_mode=%d\n", fe_sec_tone_mode);

	if (!dev->warm) {
		ret = -EAGAIN;
		goto err;
	}
	if((dev->config.num%2)&&(dev->config.disable_22k))   //for 6909se tuner 1,3,5,7 can not output 22k
		return 0;
	switch (fe_sec_tone_mode) {
	case SEC_TONE_ON:
		tone = 0;
		reg_a1_mask = 0x47;
		break;
	case SEC_TONE_OFF:
		tone = 1;
		reg_a1_mask = 0x00;
		break;
	default:
		dev_dbg(&i2c->dev, "invalid fe_sec_tone_mode\n");
		ret = -EINVAL;
		goto err;
	}

	utmp = tone << 7 | dev->config.envelope_mode << 5;
	ret = m88rs6060_update_bits(dev, 0xa2, 0xe0, utmp);
	if (ret)
		goto err;

	utmp = 1 << 2;
	ret = m88rs6060_update_bits(dev, 0xa1, reg_a1_mask, utmp);
	if (ret)
		goto err;

	return 0;
 err:
	dev_dbg(&i2c->dev, "failed=%d\n", ret);
	return ret;
}

static int m88rs6060_diseqc_send_master_cmd(struct dvb_frontend *fe, struct dvb_diseqc_master_cmd
					    *diseqc_cmd)
{
		struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;
	int ret;
	unsigned int utmp;
	unsigned long timeout;

	dev_dbg(&i2c->dev, "msg=%*ph\n",
		diseqc_cmd->msg_len, diseqc_cmd->msg);

	if (!dev->warm) {
		ret = -EAGAIN;
		goto err;
	}

	if (diseqc_cmd->msg_len < 3 || diseqc_cmd->msg_len > 6) {
		ret = -EINVAL;
		goto err;
	}

	utmp = dev->config.envelope_mode << 5;
	ret = m88rs6060_update_bits(dev, 0xa2, 0xe0, utmp);
	if (ret)
		goto err;

	ret = regmap_bulk_write(dev->regmap, 0xa3, diseqc_cmd->msg,
				diseqc_cmd->msg_len);
	if (ret)
		goto err;

	ret = regmap_write(dev->regmap, 0xa1,
			   (diseqc_cmd->msg_len - 1) << 3 | 0x07);
	if (ret)
		goto err;

	/* wait DiSEqC TX ready */
#define SEND_MASTER_CMD_TIMEOUT 120
	timeout = jiffies + msecs_to_jiffies(SEND_MASTER_CMD_TIMEOUT);

	/* DiSEqC message period is 13.5 ms per byte */
	utmp = diseqc_cmd->msg_len * 13500;
	usleep_range(utmp - 4000, utmp);

	for (utmp = 1; !time_after(jiffies, timeout) && utmp;) {
		ret = regmap_read(dev->regmap, 0xa1, &utmp);
		if (ret)
			goto err;
		utmp = (utmp >> 6) & 0x1;
	}

	if (utmp == 0) {
		dev_dbg(&i2c->dev, "diseqc tx took %u ms\n",
			jiffies_to_msecs(jiffies) -
			(jiffies_to_msecs(timeout) - SEND_MASTER_CMD_TIMEOUT));
	} else {
		dev_dbg(&i2c->dev, "diseqc tx timeout\n");

		ret = m88rs6060_update_bits(dev, 0xa1, 0xc0, 0x40);
		if (ret)
			goto err;
	}

	ret = m88rs6060_update_bits(dev, 0xa2, 0xc0, 0x80);
	if (ret)
		goto err;

	if (utmp == 1) {
		ret = -ETIMEDOUT;
		goto err;
	}

	return 0;
 err:
	dev_dbg(&i2c->dev, "failed=%d\n", ret);
	return ret;
}

static int m88rs6060_diseqc_send_burst(struct dvb_frontend *fe,
				       enum fe_sec_mini_cmd fe_sec_mini_cmd)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;
	int ret;
	unsigned int utmp, burst;
	unsigned long timeout;

	dev_dbg(&i2c->dev, "fe_sec_mini_cmd=%d\n", fe_sec_mini_cmd);

	if (!dev->warm) {
		ret = -EAGAIN;
		goto err;
	}

	utmp = dev->config.envelope_mode << 5;
	ret = m88rs6060_update_bits(dev, 0xa2, 0xe0, utmp);
	if (ret)
		goto err;

	switch (fe_sec_mini_cmd) {
	case SEC_MINI_A:
		burst = 0x02;
		break;
	case SEC_MINI_B:
		burst = 0x01;
		break;
	default:
		dev_dbg(&i2c->dev, "invalid fe_sec_mini_cmd\n");
		ret = -EINVAL;
		goto err;
	}

	ret = regmap_write(dev->regmap, 0xa1, burst);
	if (ret)
		goto err;

	/* wait DiSEqC TX ready */
#define SEND_BURST_TIMEOUT 40
	timeout = jiffies + msecs_to_jiffies(SEND_BURST_TIMEOUT);

	/* DiSEqC ToneBurst period is 12.5 ms */
	usleep_range(8500, 12500);

	for (utmp = 1; !time_after(jiffies, timeout) && utmp;) {
		ret = regmap_read(dev->regmap, 0xa1, &utmp);
		if (ret)
			goto err;
		utmp = (utmp >> 6) & 0x1;
	}

	if (utmp == 0) {
		dev_dbg(&i2c->dev, "diseqc tx took %u ms\n",
			jiffies_to_msecs(jiffies) -
			(jiffies_to_msecs(timeout) - SEND_BURST_TIMEOUT));
	} else {
		dev_dbg(&i2c->dev, "diseqc tx timeout\n");

		ret = m88rs6060_update_bits(dev, 0xa1, 0xc0, 0x40);
		if (ret)
			goto err;
	}

	ret = m88rs6060_update_bits(dev, 0xa2, 0xc0, 0x80);
	if (ret)
		goto err;

	if (utmp == 1) {
		ret = -ETIMEDOUT;
		goto err;
	}

	return 0;
 err:
	dev_dbg(&i2c->dev, "failed=%d\n", ret);
	return ret;
}

static int m88rs6060_tune(struct dvb_frontend *fe, bool re_tune,
		unsigned int mode_flags,
		unsigned int *delay, enum fe_status *status)
{
	//struct mxl *state = fe->demodulator_priv;
	int r = 0;

	*delay = HZ / 2;
	if (re_tune) {
		r = m88rs6060_set_frontend(fe);
		if (r)
			return r;
	}

	r = m88rs6060_read_status(fe, status);
	if (r)
		return r;

	if (*status & FE_HAS_LOCK)
		return 0;

	return 0;
}
static int m88rs6060_get_frontend(struct dvb_frontend *fe, struct dtv_frontend_properties *p)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;
	struct MT_FE_CHAN_INFO_DVBS2 p_info;
	
	
	m88rs6060_get_channel_info(dev,&p_info);
	
	switch(p_info.mod_mode)
        {
            case MtFeModMode_8psk:
                  p->modulation = PSK_8; break;
            case MtFeModMode_16Apsk:
                  p->modulation = APSK_16; break;
            case MtFeModMode_32Apsk:
                 p->modulation = APSK_32; break;
            case MtFeModMode_64Apsk:
                p->modulation = APSK_64; break;
            case MtFeModMode_Qpsk:
            default:   p->modulation = QPSK; break;
        }
         switch(p_info.code_rate)
		{
			case MtFeCodeRate_1_4:		p->fec_inner = FEC_1_4;     	break;
			case MtFeCodeRate_1_3:		p->fec_inner = FEC_1_3;	break;
			case MtFeCodeRate_2_5:		p->fec_inner = FEC_2_5;	break;
			case MtFeCodeRate_1_2:		p->fec_inner = FEC_1_2;	break;
			case MtFeCodeRate_3_5:		p->fec_inner = FEC_3_5;	break;
			case MtFeCodeRate_2_3:		p->fec_inner = FEC_2_3;	break;
			case MtFeCodeRate_3_4:		p->fec_inner = FEC_3_4;	break;
			case MtFeCodeRate_4_5:		p->fec_inner = FEC_4_5;	break;
			case MtFeCodeRate_5_6:		p->fec_inner = FEC_5_6;	break;
			case MtFeCodeRate_8_9:		p->fec_inner = FEC_8_9;	break;
			case MtFeCodeRate_9_10:	p->fec_inner = FEC_9_10;	break;
			case MtFeCodeRate_5_9:		p->fec_inner = FEC_5_9;	break;
			case MtFeCodeRate_7_9:		p->fec_inner = FEC_7_9;	break;
			case MtFeCodeRate_4_15:	p->fec_inner = FEC_4_15;	break;
			case MtFeCodeRate_7_15:	p->fec_inner = FEC_7_15;	break;
			case MtFeCodeRate_8_15:	p->fec_inner = FEC_8_15;	break;
			case MtFeCodeRate_11_15:	p->fec_inner = FEC_11_15;	break;
			case MtFeCodeRate_13_18:	p->fec_inner = FEC_13_18;	break;
			case MtFeCodeRate_9_20:	p->fec_inner = FEC_9_20;	break;
			case MtFeCodeRate_11_20:	p->fec_inner = FEC_11_20;	break;
			case MtFeCodeRate_23_36:	p->fec_inner = FEC_23_36;	break;
			case MtFeCodeRate_25_36:	p->fec_inner = FEC_25_36;	break;
			case MtFeCodeRate_11_45:	p->fec_inner = FEC_11_45;	break;
			case MtFeCodeRate_13_45:	p->fec_inner = FEC_13_45;	break;
			case MtFeCodeRate_14_45:	p->fec_inner = FEC_14_45;	break;
			case MtFeCodeRate_26_45:	p->fec_inner = FEC_26_45;	break;
			case MtFeCodeRate_28_45:	p->fec_inner = FEC_28_45;	break;
			case MtFeCodeRate_29_45:	p->fec_inner = FEC_29_45;	break;
			case MtFeCodeRate_31_45:	p->fec_inner = FEC_31_45;	break;
			case MtFeCodeRate_32_45:	p->fec_inner = FEC_32_45;	break;
			case MtFeCodeRate_77_90:	p->fec_inner = FEC_77_90;	break;
			default:			p->fec_inner = FEC_NONE;  	break;
		}
		p->pilot = p_info.is_pilot_on ? PILOT_ON : PILOT_OFF;
		switch(p_info.roll_off){
		   case MtFeRollOff_0p35:
		   		p->rolloff = ROLLOFF_35;break;
		   case MtFeRollOff_0p25:
		   		p->rolloff = ROLLOFF_25;break;		   		
		   case MtFeRollOff_0p20:
		   		p->rolloff = ROLLOFF_20;break;
		   case MtFeRollOff_0p15:
		   		p->rolloff = ROLLOFF_15;break;
		   case MtFeRollOff_0p10:
		   		p->rolloff = ROLLOFF_10;break;
		   case MtFeRollOff_0p05:
		   		p->rolloff = ROLLOFF_5;break;
		   	default:
		   		p->rolloff = ROLLOFF_AUTO;break;		   				   				   				
		}
		p->inversion = (p_info.is_spectrum_inv -1) ?INVERSION_ON : INVERSION_OFF;

 return 0;
}
static void m88rs6060_spi_read(struct dvb_frontend *fe,
			       struct ecp3_info *ecp3inf)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;

	if (dev->config.read_properties)
		dev->config.read_properties(i2c, ecp3inf->reg,
				     &(ecp3inf->data));

	return;
}

static void m88rs6060_spi_write(struct dvb_frontend *fe,
				struct ecp3_info *ecp3inf)
{
		struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;

	if (dev->config.write_properties)
		dev->config.write_properties(i2c, ecp3inf->reg,
				      ecp3inf->data);
	return;
}

static void m88rs6060_eeprom_read(struct dvb_frontend *fe, struct eeprom_info *eepinf)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;

	if (dev->config.read_eeprom)
		dev->config.read_eeprom(i2c, eepinf->reg,
				      &(eepinf->data));
	return ;
}

static void m88rs6060_eeprom_write(struct dvb_frontend *fe,struct eeprom_info *eepinf)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;

	if (dev->config.write_eeprom)
		dev->config.write_eeprom(i2c, eepinf->reg,
				      eepinf->data);
	return ;
}

static const struct dvb_frontend_ops m88rs6060_ops = {
	.delsys = {SYS_DVBS, SYS_DVBS2},
	.info = {
		 .name = "Montage m88rs6060",
		 .frequency_min_hz = 950 * MHz,
		 .frequency_max_hz = 2150 * MHz,
		 .symbol_rate_min = 1000000,
		 .symbol_rate_max = 45000000,
		.caps			= FE_CAN_INVERSION_AUTO |
					  FE_CAN_FEC_AUTO       |
					  FE_CAN_QPSK           |
					  FE_CAN_RECOVER	|
					  FE_CAN_2G_MODULATION  |
					  FE_CAN_MULTISTREAM
	},

	.init = m88rs6060_init,
#ifdef HWTUNE
	.get_frontend_algo = m88rs6060_get_algo,
	.tune = m88rs6060_tune,
	#else
	.set_frontend = m88rs6060_set_frontend,
#endif
	.get_frontend    = m88rs6060_get_frontend,
	.read_status = m88rs6060_read_status,
	.read_ber = m88rs6060_read_ber,
	.read_signal_strength = m88rs6060_read_signal_strength,
	.read_snr = m88rs6060_read_snr,
	.set_voltage = m88rs6060_set_voltage,
	.set_tone = m88rs6060_set_tone,
	.diseqc_send_burst = m88rs6060_diseqc_send_burst,
	.diseqc_send_master_cmd = m88rs6060_diseqc_send_master_cmd,
	.spi_read = m88rs6060_spi_read,
	.spi_write = m88rs6060_spi_write,
	.eeprom_read = m88rs6060_eeprom_read,
	.eeprom_write = m88rs6060_eeprom_write,

};
static int m88rs6060_ready(struct m88rs6060_dev *dev)
{
	//struct m88rs6060_dev *dev= i2c_get_clientdata(client);
	struct i2c_adapter *i2c = dev->base->i2c;
	int ret, len, rem;
	const struct firmware *firmware;
	const char *name = M88RS6060_FIRMWARE;
	unsigned val;
		
	dev_dbg(&dev->base->i2c->dev, "%s", __func__);

	//rest the harware and wake up the demod and tuner;
	m88rs6060_hard_rest(dev);
	rs6060_init(dev);

	ret = regmap_write(dev->regmap, 0x07, 0xe0);	//global reset ,diseqc and fec reset
	if (ret)
		goto err;
	ret = regmap_write(dev->regmap, 0x07, 0x00);
	if (ret)
		goto err;

	/* cold state - try to download firmware */
	dev_info(&i2c->dev, "found a '%s' in cold state\n",
		 dev->fe.ops.info.name);

	/* request the firmware, this will block and timeout */
	ret = request_firmware(&firmware, name, &i2c->dev);
	if (ret) {
		dev_err(&i2c->dev, "firmware file '%s' not found\n", name);
		goto err;
	}

	dev_info(&i2c->dev, "downloading firmware from file '%s'\n", name);

	ret = regmap_write(dev->regmap, 0xb2, 0x01);
	if (ret)
		goto err_release_firmware;

	dev_dbg(&i2c->dev, " firmware size  = %lu data %02x %02x %02x\n",
		 firmware->size, firmware->data[0], firmware->data[1],
		 firmware->data[2]);

	for (rem = firmware->size; rem > 0; rem -= (dev->config.i2c_wr_max - 1)) {
		len = min(dev->config.i2c_wr_max - 1, rem);
		ret = m88rs6060_fireware_download(dev, 0xb0,
						  &firmware->data[firmware->size - rem],
						  len);
		if (ret) {
			dev_err(&i2c->dev,
				"firmware download failed  len  %d  %d\n", len,
				ret);
			goto err_release_firmware;
		}
	}

	ret = regmap_write(dev->regmap, 0xb2, 0x00);
	if (ret)
		goto err_release_firmware;

	release_firmware(firmware);

	ret = regmap_read(dev->regmap, 0xb9, &val);
	if (ret)
		goto err;

	if (!val) {
		ret = -EINVAL;
		dev_info(&i2c->dev, "firmware did not run\n");
		goto err;
	}

	dev_info(&i2c->dev, "found a '%s' in warm state\n",
		 dev->fe.ops.info.name);
	dev_info(&i2c->dev, "firmware version:%X\n", val);
	msleep(5);
	m88res6060_set_ts_mode(dev);

	regmap_read(dev->regmap, 0x4d, &val);
	regmap_write(dev->regmap, 0x4d, val & 0xfd);

	return 0;
 err_release_firmware:
	release_firmware(firmware);
 err:
	dev_dbg(&i2c->dev, "failed=%d\n", ret);
	return ret;
	
}
static struct m88rs6060_base*match_base(struct i2c_adapter*i2c,u8 adr)
{
	struct m88rs6060_base*p;
	
	list_for_each_entry(p,&m88rs6060list,m88rs6060list)
		if(p->i2c == i2c)  // for two adapter in same i2c.
			return p;
	return NULL;
}
static struct si5351_base*match_si5351_base(struct i2c_adapter*i2c,int clk_port)
{
	struct si5351_base*p;
	
	list_for_each_entry(p,&si5351list,si5351list)
		if((p->i2c_si5351!= i2c)&&(p->clk_port!=clk_port))// for 6910v12 just a si5351 control two CI
			return p;
	return NULL;

}
static int m88rs6060_probe(struct i2c_client *client)
{
	struct m88rs6060_cfg *cfg = client->dev.platform_data;
	struct m88rs6060_dev *dev;
	struct m88rs6060_base *base;
	int ret;
	unsigned tmp;
	static const struct regmap_config regmap_config = {
		.reg_bits = 8,
		.val_bits = 8,
	};

	dev_dbg(&client->dev, "\n");

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto err_kfree;
	}

	dev->config.demod_adr = cfg->demod_adr;
	dev->config.tuner_adr = cfg->tuner_adr;
	dev->config.clk = cfg->clk;
	dev->config.ts_mode = cfg->ts_mode;
	dev->config.i2c_wr_max = cfg->i2c_wr_max;
	dev->config.ts_pinswitch = cfg->ts_pinswitch;
	dev->config.ts_autoclock = cfg->ts_autoclock;
	dev->config.repeater_value = cfg->repeater_value;
	dev->config.read_properties = cfg->read_properties;
	dev->config.write_properties = cfg->write_properties;
	dev->config.read_eeprom = cfg->read_eeprom;
	dev->config.write_eeprom = cfg->write_eeprom;
	dev->config.RF_switch	= cfg->RF_switch;
	dev->config.envelope_mode = cfg->envelope_mode;
	dev->config.disable_22k   = cfg->disable_22k;
	dev->TsClockChecked = false;
	dev->config.SetCIClock= cfg->SetCIClock;
	dev->config.SetTimes= cfg->SetTimes;
	dev->config.HAS_CI = cfg->HAS_CI;
	dev->config.num = cfg->num;
	dev->newTP = 0;
	

	//for i2c
	base = match_base(client->adapter,client->addr);
	if(base){
		base->count++;
		dev->base = base;
	}else{
		
		base = kzalloc(sizeof(struct m88rs6060_base),GFP_KERNEL);
		if(!base)
			goto err_kfree;
		base->i2c = client->adapter;
		base->count = 1;
		base->adr = client->addr;		
		mutex_init(&base->i2c_mutex);
		list_add(&base->m88rs6060list,&m88rs6060list);
		dev->base= base;
	}
	
	dev->regmap = regmap_init_i2c(client, &regmap_config);
		if (IS_ERR(dev->regmap)) {
			ret = PTR_ERR(dev->regmap);
			goto err_base_kfree;
		}
		/*check demod i2c */
		ret = regmap_read(dev->regmap, 0x00, &tmp);
		if (ret)
			goto err_regmap_exit;	
		if (tmp != 0xe2)
			goto err_regmap_exit;
				

	dev->mclk = 96000;

	memcpy(&dev->fe.ops, &m88rs6060_ops, sizeof(struct dvb_frontend_ops));
	*cfg->fe = &dev->fe;
	dev->fe_status = 0;

	
	if(dev->config.HAS_CI){  //for 6910SECI
		//for ci clk si5351
		struct si5351_priv *priv;
		struct si5351_base *base1;

		priv = kzalloc(sizeof(*priv), GFP_KERNEL);
		if (!priv) {
			ret = -ENOMEM;
		}
		base1 = match_si5351_base(client->adapter,cfg->clk_port);
		if(base1){
			base1->count++;
			priv->base1 = base1;
			
		}else{
		
		base1 = kzalloc(sizeof(struct si5351_base),GFP_KERNEL);
		if(!base1)
			goto err_regmap_exit;
		base1->i2c_si5351= client->adapter;
		base1->count = 1;
		base1->clk_port = cfg->clk_port;
		mutex_init(&base1->i2c_mutex_ci);
		list_add(&base1->si5351list,&si5351list);
		priv->base1 = base1;
	}
		priv->clk_port = cfg->clk_port;
		priv->plla_freq = 0;
		priv->pllb_freq = 0;
		dev->priv = priv;
		
		if(cfg->clk_port==0){
			si5351_init(priv);
			si5351_clock_enable(priv,SI5351_CLK0,1);
			si5351_clock_enable(priv,SI5351_CLK1,1);
			si5351_set_freq(priv,41666666,0,SI5351_CLK0);	
			si5351_set_freq(priv,41666666,0,SI5351_CLK1);
		}
	 }

	dev->fe.demodulator_priv = client;
	i2c_set_clientdata(client, dev);

	/* set cold state */
	dev->warm = false;

	dev_dbg(&client->dev, "found the chip of %s.", m88rs6060_ops.info.name);
	//ready chip
	m88rs6060_ready(dev);
	 
	return 0;

 err_regmap_exit:
	regmap_exit(dev->regmap);
 err_base_kfree:
	kfree(base);
 err_kfree:
	kfree(dev);
	
	dev_warn(&client->dev, "probe failed = %d\n", ret);
	return ret;
}

static void m88rs6060_remove(struct i2c_client *client)
{
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	
	dev_dbg(&client->dev, "\n");

	dev->base->count --;
	if(dev->base->count==0)
	{	
	list_del(&dev->base->m88rs6060list);
	kfree(dev->base);	 
	}
	if(dev->priv){
		dev->priv->base1->count --;
		if(dev->priv->base1->count==0){
			list_del(&dev->priv->base1->si5351list);
			kfree(dev->priv);	 
			}
	}
	regmap_exit(dev->regmap);
	dev->fe.ops.release = NULL;
	dev->fe.demodulator_priv = NULL;

	kfree(dev);
}

static const struct i2c_device_id m88rs6060_id_table[] = {
	{"m88rs6060", 0},
	{}
};

MODULE_DEVICE_TABLE(i2c, m88rs6060_id_table);

static struct i2c_driver m88rs6060_driver = {
	.driver = {
		   .name = "m88rs6060",
		   },
	.probe_new = m88rs6060_probe,
	.remove = m88rs6060_remove,
	.id_table = m88rs6060_id_table,
};

module_i2c_driver(m88rs6060_driver);

MODULE_AUTHOR("Davin zhang <Davin@tbsdtv.com>");
MODULE_DESCRIPTION("Montage M88RS6060 driver");
MODULE_LICENSE("GPL");
MODULE_FIRMWARE(M88RS6060_FIRMWARE);
