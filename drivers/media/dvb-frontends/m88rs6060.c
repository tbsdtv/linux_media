//SPX-License-Identifier: GPL-2.0-or-later
/*
 * Montage Technology M88rs6060 demodulator and tuner drivers
 * some code form m88ds3103
 * Copyright (c) 2021 Davin zhang <Davin@tbsdtv.com> www.Turbosight.com
 *
*/
#include <media/dvb_math.h>

#include "m88rs6060_priv.h"

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

static int rs6060_set_reg(struct m88rs6060_dev *dev, u8 reg, u8 data)
{
	struct i2c_client *client = dev->demod_client;
	u8 buf[] = { reg, data };
	u8 val;
	int ret;
	struct i2c_msg msg = {
		.addr = dev->config.tuner_adr,.flags = 0,.buf = buf,.len = 2
	};

	val = 0x11;
	ret = regmap_write(dev->regmap, 0x03, val);
	if (ret)
		dev_dbg(&client->dev, "fail=%d\n", ret);

	ret = i2c_transfer(dev->tuner_client->adapter, &msg, 1);
	if (ret != 1) {
		dev_err(&client->dev,
			"0x%02x (ret=%i, reg=0x%02x, value=0x%02x)\n",
			dev->config.tuner_adr, ret, reg, data);
		return -EREMOTEIO;
	}

	dev_dbg(&client->dev, "0x%02x reg 0x%02x, value 0x%02x\n",
		dev->config.tuner_adr, reg, data);

	return 0;
}

static int rs6060_get_reg(struct m88rs6060_dev *dev, u8 reg)
{

	struct i2c_client *client = dev->demod_client;
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

	val = 0x12;
	ret = regmap_write(dev->regmap, 0x03, val);
	if (ret)
		dev_dbg(&client->dev, "fail=%d\n", ret);

	ret = i2c_transfer(dev->tuner_client->adapter, msg, 2);
	if (ret != 2) {
		dev_err(&client->dev, "0x%02x (ret=%d, reg=0x%02x)\n",
			dev->config.tuner_adr, ret, reg);
		return -EREMOTEIO;
	}

	dev_dbg(&client->dev, "0x%02x reg 0x%02x, value 0x%02x\n",
		dev->config.tuner_adr, reg, b1[0]);

	return b1[0];

}

static int m88rs6060_fireware_download(struct m88rs6060_dev *dev, u8 reg,
				       const u8 * data, int len)
{
	struct i2c_client *client = dev->demod_client;
	int ret;
    u8 buf[50];
    struct i2c_msg msg = {
		.addr = dev->config.demod_adr,.flags = 0,.buf = buf,.len =
		    len + 1
	};

    buf[0] = reg;
	memcpy(&buf[1], data, len);

	ret = i2c_transfer(dev->demod_client->adapter, &msg, 1);
	if (ret != 1) {
		dev_err(&client->dev,
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

	rs6060_set_reg(dev, 0x4, 0x1);
	rs6060_set_reg(dev, 0x4, 0x0);
	msleep(1);
	rs6060_wakeup(dev);

	regmap_read(dev->regmap, 0x08, &val);
	regmap_write(dev->regmap, 0x8, (val | 0x1));

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
	tmp &= ~0x80;
	regmap_write(dev->regmap, 0x0c, tmp);
	regmap_write(dev->regmap, 0xf4, 0x01);

	return;

}

static int m88rs6060_set_frontend(struct dvb_frontend *fe)
{
	struct m88rs6060_dev *dev = fe->demodulator_priv;
	struct i2c_client *client = dev->demod_client;
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

	dev_info(&client->dev,
		 "delivery_system=%u modulation=%u frequency=%u bandwidth_hz=%u symbol_rate=%u inversion=%u stream_id=%d\n",
		 c->delivery_system, c->modulation, c->frequency,
		 c->bandwidth_hz, c->symbol_rate, c->inversion, c->stream_id);

	if (!dev->warm) {
		ret = -EAGAIN;
		goto err;
	}

	symbol_rate_KSs = c->symbol_rate / 1000;
	realFreq = c->frequency;
	/*reset */
	ret = regmap_multi_reg_write(dev->regmap, reset_buf, 2);
	if (ret)
		goto err;

	//test_search(dev);

	regmap_write(dev->regmap, 0x7, 0x80);
	regmap_write(dev->regmap, 0x7, 0x00);
	msleep(2);
	/*clear ts */
	regmap_write(dev->regmap, 0xf5, 0x00);

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
	regmap_write(dev->regmap, 0x00, 0x0);

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

	regmap_write(dev->regmap, 0x08, 3);
	regmap_write(dev->regmap, 0xe0, 0xf8);

	s32tmp = 0x10000 * lpf_offset_KHz;
	s32tmp = (2 * s32tmp + dev->mclk) / (2 * dev->mclk);
	buf[0] = (s32tmp >> 0) & 0xff;
	buf[1] = (s32tmp >> 8) & 0xff;
	ret = regmap_bulk_write(dev->regmap, 0x5e, buf, 2);
	if (ret)
		goto err;

	ret = regmap_write(dev->regmap, 0x00, 0x00);
	if (ret)
		goto err;

	ret = regmap_write(dev->regmap, 0xb2, 0x00);
	if (ret)
		goto err;

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

	dev_dbg(&client->dev, "isi = %d", isi);
	dev_dbg(&client->dev, "pls mode %d, code %d\n", pls_mode, pls_code);
	dev_dbg(&client->dev, "pls buf =%*ph \n", 3, pls);

	ret = regmap_bulk_write(dev->regmap, 0x22, pls, 3);

	rs6060_set_reg(dev, 0x5b, 0xcc);
	rs6060_set_reg(dev, 0x5c, 0xf4);
	rs6060_set_reg(dev, 0x60, 0xcb);

	for (i = 0; i < 250; i++) {
		regmap_read(dev->regmap, 0x8, &tmp);
		regmap_read(dev->regmap, 0xd, &tmp1);

		if ((tmp1 == 0x8f) || (tmp1 == 0xf7))
			break;
		msleep(2);
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
		dev_dbg(&client->dev, "ISI cnt = %d \n", tmp1);
		for (j = 0; j < tmp1; j++) {
			regmap_write(dev->regmap, 0xf2, j);
			regmap_read(dev->regmap, 0xf3, &tsid[j]);
			dev_dbg(&client->dev, "ISI = %d \n", tsid[j]);
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

	return 0;

 err:
	dev_dbg(&client->dev, "failed = %d", ret);
	return ret;
}

static int m88rs6060_init(struct dvb_frontend *fe)
{
	struct m88rs6060_dev *dev = fe->demodulator_priv;
	struct i2c_client *client = dev->demod_client;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret, len, rem;
	const struct firmware *firmware;
	const char *name = M88RS6060_FIRMWARE;
	unsigned val;

	dev_dbg(&client->dev, "%s", __func__);

	if (dev->warm)
		goto warm_start;

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
	dev_info(&client->dev, "found a '%s' in cold state\n",
		 dev->fe.ops.info.name);

	/* request the firmware, this will block and timeout */
	ret = request_firmware(&firmware, name, &client->dev);
	if (ret) {
		dev_err(&client->dev, "firmware file '%s' not found\n", name);
		goto err;
	}

	dev_info(&client->dev, "downloading firmware from file '%s'\n", name);

	ret = regmap_write(dev->regmap, 0xb2, 0x01);
	if (ret)
		goto err_release_firmware;

	dev_dbg(&client->dev, " firmware size  = %lu data %02x %02x %02x\n",
		 firmware->size, firmware->data[0], firmware->data[1],
		 firmware->data[2]);

	for (rem = firmware->size; rem > 0; rem -= (dev->config.i2c_wr_max - 1)) {
		len = min(dev->config.i2c_wr_max - 1, rem);
		ret = m88rs6060_fireware_download(dev, 0xb0,
						  &firmware->
						  data[firmware->size - rem],
						  len);
		if (ret) {
			dev_err(&client->dev,
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
		dev_info(&client->dev, "firmware did not run\n");
		goto err;
	}

	dev_info(&client->dev, "found a '%s' in warm state\n",
		 dev->fe.ops.info.name);
	dev_info(&client->dev, "firmware version:%X\n", val);
	msleep(5);
	m88res6060_set_ts_mode(dev);

	regmap_read(dev->regmap, 0x4d, &val);
	regmap_write(dev->regmap, 0x4d, val & 0xfd);

 warm_start:
	/*warm state */
	dev->warm = true;

	//
	c->cnr.len = 1;
	c->cnr.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	c->post_bit_error.len = 1;
	c->post_bit_error.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	c->post_bit_count.len = 1;
	c->post_bit_count.stat[0].scale = FE_SCALE_NOT_AVAILABLE;

	dev_info(&client->dev, "%s finished\n", __func__);

	return 0;

 err_release_firmware:
	release_firmware(firmware);
 err:
	dev_dbg(&client->dev, "failed=%d\n", ret);
	return ret;

}

static int m88rs6060_read_status(struct dvb_frontend *fe,
				 enum fe_status *status)
{
	struct m88rs6060_dev *dev = fe->demodulator_priv;
	struct i2c_client *client = dev->demod_client;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret, i, itmp;
	unsigned int utmp;
	u8 buf[3];
	s32 gain;
	u16 temp;
	dev_dbg(&client->dev, "%s\n", __func__);

	*status = 0;

	if (!dev->warm) {
		ret = -EAGAIN;
		goto err;
	}

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
		dev_dbg(&client->dev, "invalid delivery_system\n");
		ret = -EINVAL;
		goto err;
	}

	dev->fe_status = *status;
	dev_dbg(&client->dev, "lock=%02x status=%02x\n", utmp, *status);

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
			dev_dbg(&client->dev, "invalid delivery_system\n");
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
			//dev_info(&client->dev,"buf =%*ph\n",3,buf);
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
			dev_dbg(&client->dev, "invalid delivery_system\n");
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

	return 0;
 err:
	dev_dbg(&client->dev, "failed=%d\n", ret);
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

static int m88rs6060_set_tone(struct dvb_frontend *fe,
			      enum fe_sec_tone_mode fe_sec_tone_mode)
{
	struct m88rs6060_dev *dev = fe->demodulator_priv;
	struct i2c_client *client = dev->demod_client;
	int ret;
	unsigned int utmp, tone, reg_a1_mask;

	dev_dbg(&client->dev, "fe_sec_tone_mode=%d\n", fe_sec_tone_mode);

	if (!dev->warm) {
		ret = -EAGAIN;
		goto err;
	}

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
		dev_dbg(&client->dev, "invalid fe_sec_tone_mode\n");
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
	dev_dbg(&client->dev, "failed=%d\n", ret);
	return ret;
}

static int m88rs6060_diseqc_send_master_cmd(struct dvb_frontend *fe, struct dvb_diseqc_master_cmd
					    *diseqc_cmd)
{
	struct m88rs6060_dev *dev = fe->demodulator_priv;
	struct i2c_client *client = dev->demod_client;
	int ret;
	unsigned int utmp;
	unsigned long timeout;

	dev_dbg(&client->dev, "msg=%*ph\n",
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
		dev_dbg(&client->dev, "diseqc tx took %u ms\n",
			jiffies_to_msecs(jiffies) -
			(jiffies_to_msecs(timeout) - SEND_MASTER_CMD_TIMEOUT));
	} else {
		dev_dbg(&client->dev, "diseqc tx timeout\n");

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
	dev_dbg(&client->dev, "failed=%d\n", ret);
	return ret;
}

static int m88rs6060_diseqc_send_burst(struct dvb_frontend *fe,
				       enum fe_sec_mini_cmd fe_sec_mini_cmd)
{
	struct m88rs6060_dev *dev = fe->demodulator_priv;
	struct i2c_client *client = dev->demod_client;
	int ret;
	unsigned int utmp, burst;
	unsigned long timeout;

	dev_dbg(&client->dev, "fe_sec_mini_cmd=%d\n", fe_sec_mini_cmd);

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
		dev_dbg(&client->dev, "invalid fe_sec_mini_cmd\n");
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
		dev_dbg(&client->dev, "diseqc tx took %u ms\n",
			jiffies_to_msecs(jiffies) -
			(jiffies_to_msecs(timeout) - SEND_BURST_TIMEOUT));
	} else {
		dev_dbg(&client->dev, "diseqc tx timeout\n");

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
	dev_dbg(&client->dev, "failed=%d\n", ret);
	return ret;
}

static void m88rs6060_spi_read(struct dvb_frontend *fe,
			       struct ecp3_info *ecp3inf)
{
	struct m88rs6060_dev *dev = fe->demodulator_priv;
	struct i2c_client *client = dev->demod_client;

	if (dev->read_properties)
		dev->read_properties(client->adapter, ecp3inf->reg,
				     &(ecp3inf->data));

	return;
}

static void m88rs6060_spi_write(struct dvb_frontend *fe,
				struct ecp3_info *ecp3inf)
{
	struct m88rs6060_dev *dev = fe->demodulator_priv;
	struct i2c_client *client = dev->demod_client;

	if (dev->write_properties)
		dev->write_properties(client->adapter, ecp3inf->reg,
				      ecp3inf->data);
	return;
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
	.set_frontend = m88rs6060_set_frontend,

	.read_status = m88rs6060_read_status,
	.read_ber = m88rs6060_read_ber,
	.read_signal_strength = m88rs6060_read_signal_strength,
	.read_snr = m88rs6060_read_snr,

	.set_tone = m88rs6060_set_tone,
	.diseqc_send_burst = m88rs6060_diseqc_send_burst,
	.diseqc_send_master_cmd = m88rs6060_diseqc_send_master_cmd,
	.spi_read = m88rs6060_spi_read,
	.spi_write = m88rs6060_spi_write,

};

static int m88rs6060_probe(struct i2c_client *client,
			   const struct i2c_device_id *id)
{
	struct m88rs6060_cfg *cfg = client->dev.platform_data;
	struct m88rs6060_dev *dev;
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
	dev->config.repeater_value = cfg->repeater_value;
	dev->config.read_properties = cfg->read_properties;
	dev->config.write_properties = cfg->write_properties;
	dev->config.envelope_mode = cfg->envelope_mode;
	dev->demod_client = client;

	dev->regmap = devm_regmap_init_i2c(dev->demod_client, &regmap_config);
	if (IS_ERR(dev->regmap)) {
		ret = PTR_ERR(dev->regmap);
		goto err_kfree;
	}
	/*check demod i2c */
	ret = regmap_read(dev->regmap, 0x00, &tmp);
	if (ret)
		goto err_regmap_0_regmap_exit;
	if (tmp != 0xe2)
		goto err_regmap_0_regmap_exit;

	dev->tuner_client =
	    i2c_new_dummy_device(client->adapter, dev->config.tuner_adr);
	if (IS_ERR(dev->tuner_client)) {
		ret = PTR_ERR(dev->tuner_client);
		dev_err(&client->dev, "I2c register failed \n");
		goto err_client_1_i2c_unregister_device;
	}

	dev->mclk = 96000;

	memcpy(&dev->fe.ops, &m88rs6060_ops, sizeof(struct dvb_frontend_ops));
	*cfg->fe = &dev->fe;
	dev->fe_status = 0;
	dev->write_properties = cfg->write_properties;
	dev->read_properties = cfg->read_properties;

	dev->fe.demodulator_priv = dev;
	i2c_set_clientdata(client, dev);

	/* set cold state */
	dev->warm = false;

	dev_dbg(&client->dev, "found the chip of %s.", m88rs6060_ops.info.name);

	return 0;

 err_client_1_i2c_unregister_device:
	i2c_unregister_device(dev->tuner_client);
 err_regmap_0_regmap_exit:
	regmap_exit(dev->regmap);
 err_kfree:
	kfree(dev);
	dev_warn(&client->dev, "probe failed = %d\n", ret);
	return ret;
}

static int m88rs6060_remove(struct i2c_client *client)
{
	struct m88rs6060_dev *dev = i2c_get_clientdata(client);
	dev_dbg(&client->dev, "\n");

	i2c_unregister_device(dev->demod_client);
	i2c_unregister_device(dev->tuner_client);

	dev->fe.ops.release = NULL;
	dev->fe.demodulator_priv = NULL;

	kfree(dev);
	return 0;
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
	.probe = m88rs6060_probe,
	.remove = m88rs6060_remove,
	.id_table = m88rs6060_id_table,
};

module_i2c_driver(m88rs6060_driver);

MODULE_AUTHOR("Davin zhang <Davin@tbsdtv.com>");
MODULE_DESCRIPTION("Montage M88RS6060 driver");
MODULE_LICENSE("GPL");
MODULE_FIRMWARE(M88RS6060_FIRMWARE);
