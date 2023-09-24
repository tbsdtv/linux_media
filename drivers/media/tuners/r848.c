/*
 * Rafael Micro R848 silicon tuner driver
 *
 * Copyright (C) 2015 Luis Alves <ljalvs@gmail.com>
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License along
 *    with this program; if not, write to the Free Software Foundation, Inc.,
 *    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/bitrev.h>
#include "r848.h"
#include "r848_priv.h"

/* read tuner registers (always starts at addr 0) */
static int r848_rd(struct r848_priv *priv, u8 *buf, int len)
{
	int ret, i;
	struct i2c_msg msg = {
		.addr = priv->cfg->i2c_address,
		.flags = I2C_M_RD, .buf = buf, .len = len };

	ret = i2c_transfer(priv->i2c, &msg, 1);
	if (ret == 1) {
		for (i = 0; i < len; i++)
			buf[i] = bitrev8(buf[i]);
		ret = 0;
	} else {
		dev_warn(&priv->i2c->dev, "%s: i2c tuner rd failed=%d " \
				"len=%d\n", KBUILD_MODNAME, ret, len);
		ret = -EREMOTEIO;
	}
	return ret;
}

/* write registers starting at specified addr */
static int r848_wrm(struct r848_priv *priv, u8 addr, u8 *val, int len)
{
	int ret;
	u8 buf[len + 1];
	struct i2c_msg msg = {
		.addr = priv->cfg->i2c_address,
		.flags = 0, .buf = buf, .len = len + 1 };

	memcpy(&buf[1], val, len);
	buf[0] = addr;
	ret = i2c_transfer(priv->i2c, &msg, 1);
	if (ret == 1) {
		ret = 0;
	} else {
		dev_warn(&priv->i2c->dev, "%s: i2c tuner wr failed=%d " \
				"len=%d\n", KBUILD_MODNAME, ret, len);
		ret = -EREMOTEIO;
	}
	return ret;
}

/* write one register */
static int r848_wr(struct r848_priv *priv, u8 addr, u8 data)
{
	return r848_wrm(priv, addr, &data, 1);
}


static int r848_get_lock_status(struct r848_priv *priv, u8 *lock)
{
	int ret;
	u8 buf[3];

	ret = r848_rd(priv, buf, 3);
	if (ret)
		return ret;

	if ((buf[2] & 0x40) == 0x00)
		*lock = 0;
	else
	  	*lock = 1;

	return ret;
}


static int r848_init_regs(struct r848_priv *priv, u8 standard)
{
	u8 *ptr;

	if (standard != R848_DVB_S)
		ptr = R848_iniArray_hybrid;
	else
		ptr = R848_iniArray_dvbs;

	memcpy(priv->regs, ptr, R848_REG_NUM);

	return r848_wrm(priv, 0x08, ptr, R848_REG_NUM);
}

static int r848_get_imr(struct r848_priv *priv, u8 *imr)
{
	u8 buf[2];
	int i, ret = 0;
	u16 total = 0;

	for (i = 0; i < 4; i++) {
		ret |= r848_rd(priv, buf, 2);
		total += (buf[1] & 0x3f);
	}
	*imr = (u8) (total >> 2);
	return ret;
}





R848_Freq_Info_Type R848_Freq_Sel(u32 LO_freq, u32 RF_freq,R848_Standard_Type R848_Standard)
{
	R848_Freq_Info_Type R848_Freq_Info;

	// LNA band R13[6:5]
	if (RF_freq < R848_LNA_LOW_LOWEST[R848_TF_BEAD])	//<164
		R848_Freq_Info.LNA_BAND = 0x60;			// ultra low
	else if (RF_freq < R848_LNA_MID_LOW[R848_TF_BEAD])	//164~388
		R848_Freq_Info.LNA_BAND = 0x40;			// low
	else if (RF_freq < R848_LNA_HIGH_MID[R848_TF_BEAD])	//388~612
		R848_Freq_Info.LNA_BAND = 0x20;			// mid
	else							// >612
		R848_Freq_Info.LNA_BAND = 0x00;			// high

	// IMR point
	if (LO_freq < 133000)
		R848_Freq_Info.IMR_MEM = 0;
	else if (LO_freq<221000)
		R848_Freq_Info.IMR_MEM = 1;
	else if (LO_freq<450000)
		R848_Freq_Info.IMR_MEM = 2;
	else if (LO_freq<775000)
		R848_Freq_Info.IMR_MEM = 3;
	else
		R848_Freq_Info.IMR_MEM = 4;

	//RF polyfilter band   R33[7:6]
	if(LO_freq < 133000)
		R848_Freq_Info.RF_POLY = 0x80;   //low
	else if (LO_freq < 221000)
		R848_Freq_Info.RF_POLY = 0x40;   // mid
	else if (LO_freq < 775000)
		R848_Freq_Info.RF_POLY = 0x00;   // highest
	else
		R848_Freq_Info.RF_POLY = 0xC0;   // ultra high

	// LPF Cap, Notch
	switch(R848_Standard) {
	case R848_DVB_C_8M:
	case R848_DVB_C_6M:
	case R848_J83B:
	case R848_DVB_C_8M_IF_5M:
	case R848_DVB_C_6M_IF_5M:
	case R848_J83B_IF_5M:
		if (LO_freq<77000) {
			R848_Freq_Info.LPF_CAP = 16;
			R848_Freq_Info.LPF_NOTCH = 10;
		} else if (LO_freq<85000) {
			R848_Freq_Info.LPF_CAP = 16;
			R848_Freq_Info.LPF_NOTCH = 4;
		} else if (LO_freq<115000) {
			R848_Freq_Info.LPF_CAP = 13;
			R848_Freq_Info.LPF_NOTCH = 3;
		} else if (LO_freq<125000) {
			R848_Freq_Info.LPF_CAP = 11;
			R848_Freq_Info.LPF_NOTCH = 1;
		} else if (LO_freq<141000) {
			R848_Freq_Info.LPF_CAP = 9;
			R848_Freq_Info.LPF_NOTCH = 0;
		} else if (LO_freq<157000) {
			R848_Freq_Info.LPF_CAP = 8;
			R848_Freq_Info.LPF_NOTCH = 0;
		} else if (LO_freq<181000) {
			R848_Freq_Info.LPF_CAP = 6;
			R848_Freq_Info.LPF_NOTCH = 0;
		} else if (LO_freq<205000) {
			R848_Freq_Info.LPF_CAP = 3;
			R848_Freq_Info.LPF_NOTCH = 0;
		} else { //LO>=201M
			R848_Freq_Info.LPF_CAP = 0;
			R848_Freq_Info.LPF_NOTCH = 0;
		}
		break;
	default:
		if(LO_freq<73000) {
			R848_Freq_Info.LPF_CAP = 8;
			R848_Freq_Info.LPF_NOTCH = 10;
		} else if (LO_freq<81000) {
			R848_Freq_Info.LPF_CAP = 8;
			R848_Freq_Info.LPF_NOTCH = 4;
		} else if (LO_freq<89000) {
			R848_Freq_Info.LPF_CAP = 8;
			R848_Freq_Info.LPF_NOTCH = 3;
		} else if (LO_freq<121000) {
			R848_Freq_Info.LPF_CAP = 6;
			R848_Freq_Info.LPF_NOTCH = 1;
		} else if (LO_freq<145000) {
			R848_Freq_Info.LPF_CAP = 4;
			R848_Freq_Info.LPF_NOTCH = 0;
		} else if (LO_freq<153000) {
			R848_Freq_Info.LPF_CAP = 3;
			R848_Freq_Info.LPF_NOTCH = 0;
		} else if (LO_freq<177000) {
			R848_Freq_Info.LPF_CAP = 2;
			R848_Freq_Info.LPF_NOTCH = 0;
		} else if (LO_freq<201000) {
			R848_Freq_Info.LPF_CAP = 1;
			R848_Freq_Info.LPF_NOTCH = 0;
		} else { //LO>=201M
			R848_Freq_Info.LPF_CAP = 0;
			R848_Freq_Info.LPF_NOTCH = 0;
		}
		break;
	}
	return R848_Freq_Info;
}






R848_ErrCode R848_Cal_Prepare(struct r848_priv *priv, u8 u1CalFlag)
{
	R848_Cal_Info_Type Cal_Info;
	int ret;


	// R848:R38[3] +6dB
	Cal_Info.FILTER_6DB = 0x08;
	// R848:R8[7] LNA power
	Cal_Info.LNA_POWER = 0x80;
	// R848:R12[6:5] (bit5 = RF_Buf ON(?), bit6=RF_Buf pwr)
	Cal_Info.RFBUF_OUT = 0x20;
	// R848:R9[2] RF_BUF_pwr
	Cal_Info.RFBUF_POWER = 0x04;
	// R848:R14[6:5] (bit5=TF cal ON/OFF, bit6=TF_-6dB ON/OFF)
	Cal_Info.TF_CAL = 0x00;
	// R848:R13[7:0] (manual: 0x9f (-97?) max, 0x80 (-128?) min)
	Cal_Info.LNA_GAIN = 0x9F;
	// R848:R15[4:0] (manual +8) (min(0))
	Cal_Info.MIXER_AMP_GAIN = 0x08;
	// R848:R34[4:0] (manual min(0))
	Cal_Info.MIXER_BUFFER_GAIN = 0x10;

	switch(u1CalFlag) {
	case R848_IMR_LNA_CAL:
		Cal_Info.RFBUF_OUT = 0x00;
		Cal_Info.RFBUF_POWER = 0x00;
		Cal_Info.TF_CAL = 0x60;
		Cal_Info.MIXER_AMP_GAIN = 0x00;
		break;
	case R848_TF_LNA_CAL:
		Cal_Info.RFBUF_OUT = 0x00;
		Cal_Info.RFBUF_POWER = 0x00;
		Cal_Info.TF_CAL = 0x60;
		Cal_Info.LNA_GAIN = 0x80;
		Cal_Info.MIXER_AMP_GAIN = 0x00;
		break;
	case R848_LPF_LNA_CAL:
		Cal_Info.RFBUF_OUT = 0x00;
		Cal_Info.RFBUF_POWER = 0x00;
		Cal_Info.TF_CAL = 0x20;
		Cal_Info.LNA_GAIN = 0x80;
		Cal_Info.MIXER_AMP_GAIN = 0x00;
		break;
	case R848_TF_CAL:
		Cal_Info.MIXER_AMP_GAIN = 0x00;
		break;
	case R848_LPF_CAL:
	case R848_IMR_CAL:
	default:
		break;
	}

	// Ring From RF_Buf Output & RF_Buf Power
	// R848:R12[5]
	priv->regs[4] = (priv->regs[4] & 0xDF) | Cal_Info.RFBUF_OUT;
	ret = r848_wr(priv, 0x0c, priv->regs[4]);

	// RF_Buf Power
	priv->regs[1] = (priv->regs[1] & 0xFB) | Cal_Info.RFBUF_POWER;
	ret |= r848_wr(priv, 0x09, priv->regs[1]);

	// (LNA power ON/OFF )
	// R848:R8[7]
	priv->regs[0] = (priv->regs[0] & 0x7F) | Cal_Info.LNA_POWER;
	ret |= r848_wr(priv, 0x08, priv->regs[0]);

	// TF cal (TF cal ON/OFF, TF_-6dB ON/OFF)
	// R848:R14[6:5]
	priv->regs[6] = (priv->regs[6] & 0x9F) | Cal_Info.TF_CAL;
	ret |= r848_wr(priv, 0x0e, priv->regs[6]);

	// LNA gain
	// R848:R13[7:0]
	priv->regs[5] = (priv->regs[5] & 0x60) | Cal_Info.LNA_GAIN;
	ret |= r848_wr(priv, 0x0d, priv->regs[5]);

	// Mixer Amp Gain
	// R848:R15[4:0]  15-8=7  15(0x0F) is addr ; [7] is data
	priv->regs[7] = (priv->regs[7] & 0xE0) | Cal_Info.MIXER_AMP_GAIN;
	ret |= r848_wr(priv, 0x0f, priv->regs[7]);

	// Mixer Buffer Gain
	// R848:R34[4:0]  34-8=26  34(0x22) is addr ; [26] is data
	priv->regs[26] = (priv->regs[26] & 0xE0) | Cal_Info.MIXER_BUFFER_GAIN;
	ret |= r848_wr(priv, 0x22, priv->regs[26]);

	// Set filter +0/6dB; NA det=OFF
	// R848:R38[3]  38-8=30  38(0x26) is addr ; [30] is data
	priv->regs[30] = (priv->regs[30] & 0xF7) | Cal_Info.FILTER_6DB | 0x80;
	ret |= r848_wr(priv, 0x26, priv->regs[30]);

	// Set NA det 710 = OFF
	// R848:R40[3]  40-8=32  40(0x28) is addr ; [32] is data
	priv->regs[32] = (priv->regs[32] | 0x08);
	ret |= r848_wr(priv, 0x28, priv->regs[32]);

	//---- General calibration setting ----//
	// IMR IQ cap=0
	// R848:R11[1:0]  11-8=3  11(0x0B) is addr ; [3] is data
	priv->regs[3] = (priv->regs[3] & 0xFC);
	ret |= r848_wr(priv, 0x0b, priv->regs[3]);

	// Set RF_Flag ON(%)
	// R848:R22[0]  22-8=14  22(0x16) is addr ; [14] is data
	priv->regs[14] = priv->regs[14] | 0x01;  //force far-end mode
	ret |= r848_wr(priv, 0x16, priv->regs[14]);

	// RingPLL power ON
	// R848:R18[4]  18-8=10  18(0x12) is addr ; [10] is data
	priv->regs[10] = (priv->regs[10] & 0xEF);
	ret |= r848_wr(priv, 0x12, priv->regs[10]);

	// LPF filter code = 15
	// R848:R18[3:0]  18-8=10  18(0x12) is addr ; [10] is data
	priv->regs[10] = (priv->regs[10] & 0xF0) | 0x0F;
	ret |= r848_wr(priv, 0x12, priv->regs[10]);

	// HPF corner=narrowest; LPF coarse=6M; 1.7M disable
	// R848:R19[7:0]  19-8=11  19(0x13) is addr ; [11] is data
	priv->regs[11] = (priv->regs[11] & 0x00) | 0x60;
	ret |= r848_wr(priv, 0x13, priv->regs[11]);

	// ADC/VGA PWR on; Vga code mode(b4=1), Gain = 26.5dB; Large Code mode Gain(b5=1)
	// ADC PWR on (b7=0) R848:R15[7]  15-8=7  15(0x0F) is addr ; [7] is data
	priv->regs[7] = (priv->regs[7] & 0x7F);
	ret |= r848_wr(priv, 0x0f, priv->regs[7]);

/*	// VGA PWR on (b0=0)
	// R848:R9[0]  9-8=1  9(0x09) is addr ; [1] is data
	priv->regs[1] = (priv->regs[1] & 0xFE);
	ret |= r848_wr(priv, 0x09, priv->regs[1]);*/

	// VGA PWR on (b0=0)  MT2
	// R848:R18[7]
	priv->regs[10] = (priv->regs[10] & 0x7F);
	ret |= r848_wr(priv, 0x12, priv->regs[10]);

	// Large Code mode Gain(b5=1)
	// R848:R11[3]  11-8=3  11(0x0B) is addr ; [3] is data
	priv->regs[3] = (priv->regs[3] & 0xF7) | 0x08;
	ret |= r848_wr(priv, 0x0b, priv->regs[3]);

	// Vga code mode(b4=1)
	// R848:R9[1]  9-8=1  9(0x09) is addr ; [1] is data
	priv->regs[1] = (priv->regs[1] & 0xFD) | 0x02;
	ret |= r848_wr(priv, 0x09, priv->regs[1]);

	// Gain = 26.5dB
	// R848:R20[3:0]  20-8=12  20(0x14) is addr ; [12] is data
	priv->regs[12] = (priv->regs[12] & 0xF0) | 0x0B;
	ret |= r848_wr(priv, 0x14, priv->regs[12]);

	// LNA, RF, Nrb dector pw on; det2 cap=IF_det
	// R848:R37[3:0]  37-8=29  37(0x25) is addr ; [29] is data
	priv->regs[29] = (priv->regs[29] & 0xF0) | 0x02;
	ret |= r848_wr(priv, 0x25, priv->regs[29]);

	return ret;
}

R848_ErrCode R848_Xtal_Check( struct r848_priv *priv)
{
	u8 i = 0;
	u8 buf[3];
	int ret;

	// TF force sharp mode (for stable read)
	priv->regs[14] = priv->regs[14] | 0x01;
	ret = r848_wr(priv, 0x16, priv->regs[14]);

	// NA det off (for stable read)
	priv->regs[30] = priv->regs[30] | 0x80;
	ret |= r848_wr(priv, 0x26, priv->regs[30]);

	// Set NA det 710 = OFF
	priv->regs[32] = (priv->regs[32] | 0x08);
	ret |= r848_wr(priv, 0x28, priv->regs[32]);

	// Xtal_pow=lowest(11)					R848:R23[6:5]
	priv->regs[15] = (priv->regs[15] & 0x9F) | 0x60;
	ret |= r848_wr(priv, 0x17, priv->regs[15]);

	// Xtal_Gm=SMALL(0)					R848:R27[0]
	priv->regs[19] = (priv->regs[19] & 0xFE) | 0x00;
	ret |= r848_wr(priv, 0x1b, priv->regs[19]);

	// set pll autotune = 128kHz				R848:R23[4:3]
	priv->regs[15] = priv->regs[15] & 0xE7;
	ret |= r848_wr(priv, 0x17, priv->regs[15]);

	// set manual initial reg = 1 000000; b5=0 => cap 30p;	R848:R27[7:0]
	priv->regs[19] = (priv->regs[19] & 0x80) | 0x40;
	ret |= r848_wr(priv, 0x1b, priv->regs[19]);

	// set auto
	priv->regs[19] = (priv->regs[19] & 0xBF);
	ret |= r848_wr(priv, 0x1b, priv->regs[19]);
	if (ret)
		return ret;

	msleep(10);

	// Xtal_pow=lowest(11)					R848:R23[6:5]
	priv->regs[15] = (priv->regs[15] & 0x9F) | 0x60;
	ret = r848_wr(priv, 0x17, priv->regs[15]);

	// Xtal_Gm=SMALL(0) R848:R27[0]
	priv->regs[19] = (priv->regs[19] & 0xFE) | 0x00;
	ret |= r848_wr(priv, 0x1b, priv->regs[19]);
	if (ret)
		return ret;


	for (i = 0; i < XTAL_CHECK_SIZE; i++) {
		//set power
		if (i <= XTAL_SMALL_HIGHEST) {
			priv->regs[15] = (priv->regs[15] & 0x9F) | ((u8)(XTAL_SMALL_HIGHEST-i)<<5);
			priv->regs[19] = (priv->regs[19] & 0xFE) | 0x00 ;		//| 0x00;  //SMALL Gm(0)
		} else if (i == XTAL_LARGE_HIGHEST) {
			//priv->regs[15] = (priv->regs[15] & 0x87) | 0x00 | 0x18;  //3v Gm, highest
			priv->regs[15] = (priv->regs[15] & 0x9F) | 0X00 ;
			priv->regs[19] = (priv->regs[19] & 0xFE) | 0x01 ;		//| 0x00;  //LARGE Gm(1)
		} else {
			//priv->regs[15] = (priv->regs[15] & 0x87) | 0x00 | 0x18;  //3v Gm, highest
			priv->regs[15] = (priv->regs[15] & 0x9F) | 0X00 ;
			priv->regs[19] = (priv->regs[19] & 0xFE) | 0x01 ;		//| 0x00;  //LARGE Gm(1)
		}

		ret  = r848_wr(priv, 0x17, priv->regs[15]);
		ret |= r848_wr(priv, 0x1b, priv->regs[19]);
		if (ret)
			return ret;

		msleep(50);

		ret = r848_rd(priv, buf, 3);
		if (ret)
			return ret;

		// depend on init Nint & Div value (N=59.6667, Div=16)
		// lock to VCO band 8 if VCO=2768M for 16M Xtal
		// lock to VCO band 46 if VCO=2768M for 24M Xtal
		if ((buf[2] & 0x40) == 0x40) {
			u8 v = buf[2] & 0x3F;
			u8 ll, hl;
			if (priv->cfg->xtal == 16000000) {
				ll = 5;
				hl = 11;
			} else {
				ll = 42;
				hl = 48;
			}
			if ((v >= ll) && (v <= hl)) {
				priv->cfg->R848_Xtal_Pwr_tmp = i;
				break;
			}
		}
		if (i == (XTAL_CHECK_SIZE-1)) {
			priv->cfg->R848_Xtal_Pwr_tmp = i;
		}
	}

	return 0;
}


static int r848_set_pll(struct r848_priv *priv, u32 LO_Freq, R848_Standard_Type R848_Standard)
{
	int ret;
	u8 buf[3];

	u8  MixDiv = 2;
	u8  DivBuf = 0;
	u8  Ni = 0;
	u8  Si = 0;
	u8  DivNum = 0;
	u16  Nint = 0;
	u32 VCO_Min = 2410000;
	u32 VCO_Max = VCO_Min*2;
	u32 VCO_Freq = 0;
	u32 PLL_Ref	= R848_Xtal;
	u32 VCO_Fra	= 0;
	u16 Nsdm = 2;
	u16 SDM = 0;
	u16 SDM16to9 = 0;
	u16 SDM8to1 = 0;
	u8   CP_CUR = 0x00;
	u8   CP_OFFSET = 0x00;
	u8   SDM_RES = 0x00;
	u8   XTAL_POW1 = 0x00;
	u8   XTAL_POW0 = 0x00;
	u8   XTAL_GM = 0x00;
	u16  u2XalDivJudge;
	u8   u1XtalDivRemain;
	u8   VCO_current_trial = 0;

	u8   u1RfFlag = 0;
	u8   u1PulseFlag = 0;
	u8   u1SPulseFlag=0;

	u8	R848_XtalDiv = XTAL_DIV2;


	//TF, NA fix
	u1RfFlag = (priv->regs[14] & 0x01);      //R22[0]
	u1PulseFlag = (priv->regs[30] & 0x80);   //R38[7]
	u1SPulseFlag= (priv->regs[32] & 0x08);   //R40[3]


	priv->regs[14] = priv->regs[14] | 0x01;		// TF force sharp mode
	ret = r848_wr(priv, 0x16, priv->regs[14]);

	priv->regs[30] = priv->regs[30] | 0x80;		// NA det off
	ret |= r848_wr(priv, 0x26, priv->regs[30]);

	// Set NA det 710 = OFF
	priv->regs[32] = (priv->regs[32] | 0x08);
	ret |= r848_wr(priv, 0x28, priv->regs[32]);

	// DTV
	CP_CUR = 0x00;     //0.7m, R25[6:4]=000
	CP_OFFSET = 0x00;  //0u,     [2]=0

	// CP current  R25[6:4]=000
	priv->regs[17]    = (priv->regs[17] & 0x8F)  | CP_CUR ;
	ret |= r848_wr(priv, 0x19, priv->regs[17]);

	// Div Cuurent   R20[7:6]=2'b01(150uA)
	priv->regs[12]    = (priv->regs[12] & 0x3F)  | 0x40;
	ret |= r848_wr(priv, 0x14, priv->regs[12]);

	//CPI*2 R28[7]=1
	if ((R848_Standard!=R848_DVB_S) && (LO_Freq >= 865000))
		priv->regs[20] = (priv->regs[20] & 0x7F) | 0x80;
	else
		priv->regs[20] = (priv->regs[20] & 0x7F);
	ret |= r848_wr(priv, 0x1c, priv->regs[20]);

	//  R848:R26[7:5]  VCO_current= 2
	priv->regs[18]    = (priv->regs[18] & 0x1F) | 0x40;
	ret |= r848_wr(priv, 0x1a, priv->regs[18]);

	//CP Offset R21[7]
	priv->regs[13]    = (priv->regs[13] & 0x7F) | CP_OFFSET;
	ret |= r848_wr(priv, 0x15, priv->regs[13]);
	if (ret)
		return ret;

	//if(R848_Initial_done_flag==TRUE)
	{
		// set XTAL Power
		if ((priv->cfg->R848_Xtal_Pwr < XTAL_SMALL_HIGH) && (LO_Freq > (64000+8500))) {
			XTAL_POW1 = 0x00;        //high,       R16[4]=0  //R848:R23[7]
			XTAL_POW0 = 0x20;        //high,       R15[6:5]=01  //R848:R23[6:5]
			XTAL_GM = 0x00;            //SMALL(0),   R15[4:3]=00
		} else {
			if(priv->cfg->R848_Xtal_Pwr <= XTAL_SMALL_HIGHEST) {
				XTAL_POW1 = 0x00;        //high,       R16[4]=0	// R848:R23[7]
				XTAL_POW0 = ((u8)(XTAL_SMALL_HIGHEST-priv->cfg->R848_Xtal_Pwr)<<5);	//R848:R23[6:5]
				XTAL_GM = 0x00;            //SMALL(0),   R27[0]=0
			} else if(priv->cfg->R848_Xtal_Pwr == XTAL_LARGE_HIGHEST) {
				XTAL_POW1 = 0x00;        //high,      	// R848:R23[7]
				XTAL_POW0 = 0x00;        //highest,  	// R848:R23[6:5]
				XTAL_GM = 0x01;            //LARGE(1),         R27[0]=1
			} else {
				XTAL_POW1 = 0x00;        //high,     // R848:R23[7]
				XTAL_POW0 = 0x00;        //highest,  // R848:R23[6:5]
				XTAL_GM = 0x01;            //LARGE(1),         R27[0]=1
			}
		}
	}
//	else
//	{
//		XTAL_POW1 = 0x00;        //high,      	// R848:R23[7]  
//		XTAL_POW0 = 0x00;        //highest,  	// R848:R23[6:5] 
//		XTAL_GM = 0x01;          //LARGE(1),         R27[0]=1
//	}

	// Xtal_Gm=SMALL(0) R27[0]
	priv->regs[19] = (priv->regs[19] & 0xFE) | XTAL_GM;
	ret |= r848_wr(priv, 0x1b, priv->regs[19]);

	priv->regs[15] = (priv->regs[15] & 0x9F) | XTAL_POW0; // R23[6:5]
	ret |= r848_wr(priv, 0x17, priv->regs[15]);

	priv->regs[15] = (priv->regs[15] & 0x7F) | XTAL_POW1; // R23[7]
	ret |= r848_wr(priv, 0x17, priv->regs[15]);

	// IQ gen ON
	priv->regs[31] = (priv->regs[31] & 0xFD) | 0x00; // R39[1] [0]=0'b0
	ret |= r848_wr(priv, 0x27, priv->regs[31]);

	// current:Dmin, Bmin
	priv->regs[27]    = (priv->regs[27] & 0xCF) | 0x00; // R848:R35[5:4]=2'b00
	ret |= r848_wr(priv, 0x23, priv->regs[27]);

	//set pll autotune = 128kHz (fast)  R23[4:3]=2'b00
	priv->regs[15]    = priv->regs[15] & 0xE7;
	ret |= r848_wr(priv, 0x17, priv->regs[15]);

	//Divider
	while(MixDiv <= 64) {
		if (((LO_Freq * MixDiv) >= VCO_Min) && ((LO_Freq * MixDiv) < VCO_Max)) {
			DivBuf = MixDiv;
			while(DivBuf > 2) {
				DivBuf = DivBuf >> 1;
				DivNum ++;
			}
			break;
		}
		MixDiv = MixDiv << 1;
	}

	SDM_RES = 0x00;    //short, R27[4:3]=00
	priv->regs[19] = (priv->regs[19] & 0xE7) | SDM_RES;
	ret |= r848_wr(priv, 0x1b, priv->regs[19]);

	// Xtal Div      //R848:R24[2]
	if(R848_Standard == R848_STD_SIZE) { //for cal
		R848_XtalDiv = XTAL_DIV1;
		priv->regs[16] = priv->regs[16] & 0xFB; //b2=0  // R848:R24[2]
		PLL_Ref = R848_Xtal;
	} else { // DTV_Standard
		u2XalDivJudge = (u16) (LO_Freq/1000/8);
		u1XtalDivRemain = (u8) (u2XalDivJudge % 2);
		if(u1XtalDivRemain==1) { //odd
			R848_XtalDiv = XTAL_DIV1;
			priv->regs[16] = priv->regs[16] & 0xFB; //R24[2]=0
			PLL_Ref = R848_Xtal;
		} else { // div2, note that agc clk also div2
			R848_XtalDiv = XTAL_DIV2;
			priv->regs[16] |= 0x04;   	//R24[2]=1
			PLL_Ref = R848_Xtal / 2;
		}
	}
	ret |= r848_wr(priv, 0x18, priv->regs[16]);

	//Divider num //R24[7:5]
	priv->regs[16] &= 0x1F;
	priv->regs[16] |= (DivNum << 5);
	ret |= r848_wr(priv, 0x18, priv->regs[16]);

	VCO_Freq = LO_Freq * MixDiv;
	Nint     = (u16) (VCO_Freq / 2 / PLL_Ref);
	VCO_Fra  = (u16) (VCO_Freq - 2 * PLL_Ref * Nint);

	//Boundary spur prevention
	if (VCO_Fra < PLL_Ref / 64) {          //2*PLL_Ref/128
		VCO_Fra = 0;
	} else if (VCO_Fra > PLL_Ref * 127/64) {  //2*PLL_Ref*127/128
		VCO_Fra = 0;
		Nint ++;
	} else if((VCO_Fra > PLL_Ref * 127/128) && (VCO_Fra < PLL_Ref)) { //> 2*PLL_Ref*127/256,  < 2*PLL_Ref*128/256
		VCO_Fra = PLL_Ref*127/128;      // VCO_Fra = 2*PLL_Ref*127/256
	} else if((VCO_Fra > PLL_Ref) && (VCO_Fra < PLL_Ref * 129/128)) { //> 2*PLL_Ref*128/256,  < 2*PLL_Ref*129/256
		VCO_Fra = PLL_Ref * 129/128;      // VCO_Fra = 2*PLL_Ref*129/256
	} else {
		VCO_Fra = VCO_Fra;
	}

	//Ni:R848:R28[6:0]   Si:R848:R20[5:4]
	Ni = (Nint - 13) / 4;
	Si = Nint - 4 *Ni - 13;
	//Si
	priv->regs[12] = (priv->regs[12] & 0xCF) | ((Si << 4));
	ret |= r848_wr(priv, 0x14, priv->regs[12]);

	//Ni
	priv->regs[20] = (priv->regs[20] & 0x80) | (Ni);
	ret |= r848_wr(priv, 0x1c, priv->regs[20]);

	//pw_sdm		// R848:R27[7]
	priv->regs[19] &= 0x7F;
	if(VCO_Fra == 0)
		priv->regs[19] |= 0x80;
	ret |= r848_wr(priv, 0x1b, priv->regs[19]);

	//SDM calculator
	while(VCO_Fra > 1) {
		if (VCO_Fra > (2*PLL_Ref / Nsdm)) {
			SDM = SDM + 32768 / (Nsdm/2);
			VCO_Fra = VCO_Fra - 2*PLL_Ref / Nsdm;
			if (Nsdm >= 0x8000)
				break;
		}
		Nsdm = Nsdm << 1;
	}

	SDM16to9 = SDM >> 8;
	SDM8to1 =  SDM - (SDM16to9 << 8);

	// R848:R30[7:0]
	priv->regs[22] = (u8) SDM16to9;
	ret |= r848_wr(priv, 0x1e, priv->regs[22]);

	// R848:R29[7:0]
	priv->regs[21] = (u8) SDM8to1;
	ret |= r848_wr(priv, 0x1d, priv->regs[21]);
	if (ret)
		return ret;

	//if(R848_Standard <= R848_SECAM_L1_INV)
	if(R848_XtalDiv == XTAL_DIV2)
	    msleep(20);
	else
	    msleep(10);

	for (VCO_current_trial = 0; VCO_current_trial < 3; VCO_current_trial++) {
		// check PLL lock status
		ret = r848_rd(priv, buf, 3);
		if (ret)
			return ret;

		// R848:R26[7:5] | Set VCO current = 011 (3)
		if ((buf[2] & 0x40) == 0x00) {
			//increase VCO current
			priv->regs[18] = (priv->regs[18] & 0x1F) | ((2-VCO_current_trial) << 5);
			ret = r848_wr(priv, 0x1a, priv->regs[18]);
			if (ret)
				return ret;
		}
	}

	if (VCO_current_trial == 2) {
		//check PLL lock status
		ret = r848_rd(priv, buf, 3);
		if (ret)
			return ret;

		if( (buf[2] & 0x40) == 0x00) {
			if(priv->cfg->R848_Xtal_Pwr <= XTAL_SMALL_HIGHEST)
				XTAL_GM = 0x01;            //LARGE(1),         R15[4:3]=11

			priv->regs[19] = (priv->regs[19] & 0xFE) | XTAL_GM;
			ret = r848_wr(priv, 0x1b, priv->regs[19]);
			if (ret)
				return ret;
		}
	}

	// set pll autotune = 8kHz (slow)
	priv->regs[15] = (priv->regs[15] & 0xE7) | 0x10;
	ret = r848_wr(priv, 0x17, priv->regs[15]);

	// restore TF, NA det setting
	priv->regs[14] = (priv->regs[14] & 0xFE) | u1RfFlag;
	ret |= r848_wr(priv, 0x16, priv->regs[14]);

	priv->regs[30] = (priv->regs[30] & 0x7F) | u1PulseFlag;
	ret |= r848_wr(priv, 0x26, priv->regs[30]);

	// Set NA det 710 = OFF
	priv->regs[32] = (priv->regs[32] & 0xF7) | u1SPulseFlag;
	ret |= r848_wr(priv, 0x28, priv->regs[32]);

	return ret;
}



/*

--R9--
[7:3]=LNA Cap
[2]=RF_BUF_pwr
[1]=Vga code mode
[0]=VGA PWR on

R10
[5]=?(0)
[4:0]=LNA Notch

R11
[7]=force plain mode
[6]=TF current
[3]=vga6db
[2]=3~6 shrink
[1:0]=IMR_Iqcap

R13
[6:5]=LNA band
[4]=AGC Type (negative=0, positive=1)

R16
[5:0]=IMR_Gain

R17
[7]=LNAPD_PLUSE_ENA
[5:0]=IMR_Phase

R33
[7:6]=RF Polyfilter band
[5]=vco_band
[3:2]=Ring PLL power
[1:0]=ring_div2

*/

static int r848_set_mux(struct r848_priv *priv, u32 LO_KHz, u32 RF_KHz, R848_Standard_Type R848_Standard)
{
	int ret;

	R848_Freq_Info_Type Freq_Info1;
	u8 Reg08_IMR_Gain   = 0;
	u8 Reg09_IMR_Phase  = 0;
	u8 Reg03_IMR_Iqcap  = 0;
	Freq_Info1 = R848_Freq_Sel(LO_KHz, RF_KHz, R848_Standard);


	// LNA band (depend on RF_KHz)
	// R13[6:5]
	priv->regs[5] = (priv->regs[5] & 0x9F) | Freq_Info1.LNA_BAND;
	ret = r848_wr(priv, 0x0d, priv->regs[5]);

	// RF Polyfilter
	// R33[7:6]
	priv->regs[25] = (priv->regs[25] & 0x3F) | Freq_Info1.RF_POLY;
	ret |= r848_wr(priv, 0x21, priv->regs[25]);

	// LNA Cap
	// R9[7:3]
	priv->regs[1] = (priv->regs[1] & 0x07) | (Freq_Info1.LPF_CAP<<3);
	ret |= r848_wr(priv, 0x09, priv->regs[1]);

	// LNA Notch
	// R10[4:0]
	priv->regs[2] = (priv->regs[2] & 0xE0) | (Freq_Info1.LPF_NOTCH);
	ret |= r848_wr(priv, 0x0a, priv->regs[2]);

	//Set_IMR
	Reg08_IMR_Gain = priv->imr_data[Freq_Info1.IMR_MEM].gain_x & 0x3F;
	Reg09_IMR_Phase = priv->imr_data[Freq_Info1.IMR_MEM].phase_y & 0x3F;
	Reg03_IMR_Iqcap = priv->imr_data[Freq_Info1.IMR_MEM].iqcap & 0x03;

	// R16[5:0]
	priv->regs[8] = (priv->regs[8] & 0xC0) | Reg08_IMR_Gain;
	ret |= r848_wr(priv, 0x10, priv->regs[8]);

	// R17[5:0]
	priv->regs[9] = (priv->regs[9] & 0xC0) | Reg09_IMR_Phase;
	ret |= r848_wr(priv, 0x11, priv->regs[9]);

	// R11[1:0]
	priv->regs[3] = (priv->regs[3] & 0xFC) | Reg03_IMR_Iqcap;
	ret |= r848_wr(priv, 0x0b, priv->regs[3]);

	return ret;
}




//-----------------------------------------------------------------------------------/ 
// Purpose: compare IMC result aray [0][1][2], find min value and store to CorArry[0]
// input: CorArry: three IMR data array
//-----------------------------------------------------------------------------------/
static void R848_CompreCor(struct r848_priv *priv, struct r848_sect_type *CorArry)
{
	struct r848_sect_type CorTemp;
	int i;

	for (i = 3; i > 0; i--) {
		//compare IMC result [0][1][2], find min value
		if (CorArry[0].value > CorArry[i - 1].value) {
			CorTemp = CorArry[0];
			CorArry[0] = CorArry[i - 1];
			CorArry[i - 1] = CorTemp;
		}
	}
}


//--------------------------------------------------------------------------------------------
// Purpose: record IMC results by input gain/phase location
//          then adjust gain or phase positive 1 step and negtive 1 step, both record results
// input: FixPot: phase or gain
//        FlucPot phase or gain
//        PotReg: 0x10 or 0x11 for R848
//        CompareTree: 3 IMR trace and results
// output: TRUE or FALSE
//--------------------------------------------------------------------------------------------
static int R848_IQ_Tree( struct r848_priv *priv,u8 FixPot, u8 FlucPot, u8 PotReg, struct r848_sect_type* CompareTree)
{
	int ret, i;
	u8 PntReg;

	if(PotReg == 0x10)
		PntReg = 0x11; //phase control
	else
		PntReg = 0x10; //gain control

	for (i = 0; i < 3; i++) {
		ret = r848_wr(priv, PotReg, FixPot);
		ret |= r848_wr(priv, PntReg, FlucPot);
		ret |= r848_get_imr(priv,&CompareTree[i].value);
		if (ret)
			return ret;

		if (PotReg == 0x10) {
			CompareTree[i].gain_x  = FixPot;
			CompareTree[i].phase_y = FlucPot;
		} else {
			CompareTree[i].phase_y = FixPot;
			CompareTree[i].gain_x  = FlucPot;
		}

		if(i == 0) {  //try right-side point
			FlucPot ++;
		} else if (i == 1) { //try left-side point
			if((FlucPot & 0x1F) == 1) { //if absolute location is 1, change I/Q direction
				if(FlucPot & 0x20) { //b[5]:I/Q selection. 0:Q-path, 1:I-path
					FlucPot = (FlucPot & 0xC0) | 0x01;
				} else {
					FlucPot = (FlucPot & 0xC0) | 0x21;
				}
			} else {
				FlucPot = FlucPot - 2;
			}
		}
	}
	return ret;
}


static int R848_Section(struct r848_priv *priv, struct r848_sect_type *IQ_Pont)
{
	struct r848_sect_type Compare_IQ[3];
	struct r848_sect_type Compare_Bet[3];

	//Try X-1 column and save min result to Compare_Bet[0]
	if((IQ_Pont->gain_x & 0x1F) == 0x00)
	{
		Compare_IQ[0].gain_x = ((IQ_Pont->gain_x) & 0xDF) + 1;  //Q-path, Gain=1
	}
	else
	{
		Compare_IQ[0].gain_x  = IQ_Pont->gain_x - 1;  //left point
	}
	Compare_IQ[0].phase_y = IQ_Pont->phase_y;

	if(R848_IQ_Tree(priv,Compare_IQ[0].gain_x, Compare_IQ[0].phase_y, 0x10, &Compare_IQ[0]) != RT_Success)  // y-direction
		return RT_Fail;		

	R848_CompreCor(priv,&Compare_IQ[0]);

	Compare_Bet[0].gain_x = Compare_IQ[0].gain_x;
	Compare_Bet[0].phase_y = Compare_IQ[0].phase_y;
	Compare_Bet[0].value = Compare_IQ[0].value;

	//Try X column and save min result to Compare_Bet[1]
	Compare_IQ[0].gain_x = IQ_Pont->gain_x;
	Compare_IQ[0].phase_y = IQ_Pont->phase_y;

	if(R848_IQ_Tree(priv,Compare_IQ[0].gain_x, Compare_IQ[0].phase_y, 0x10, &Compare_IQ[0]) != RT_Success)
		return RT_Fail;	

	R848_CompreCor(priv,&Compare_IQ[0]);

	Compare_Bet[1].gain_x = Compare_IQ[0].gain_x;
	Compare_Bet[1].phase_y = Compare_IQ[0].phase_y;
	Compare_Bet[1].value = Compare_IQ[0].value;

	//Try X+1 column and save min result to Compare_Bet[2]
	if((IQ_Pont->gain_x & 0x1F) == 0x00)		
		Compare_IQ[0].gain_x = ((IQ_Pont->gain_x) | 0x20) + 1;  //I-path, Gain=1
	else
	    Compare_IQ[0].gain_x = IQ_Pont->gain_x + 1;
	Compare_IQ[0].phase_y = IQ_Pont->phase_y;

	if(R848_IQ_Tree(priv,Compare_IQ[0].gain_x, Compare_IQ[0].phase_y, 0x10, &Compare_IQ[0]) != RT_Success)
		return RT_Fail;		

	R848_CompreCor(priv,&Compare_IQ[0]);

	Compare_Bet[2].gain_x = Compare_IQ[0].gain_x;
	Compare_Bet[2].phase_y = Compare_IQ[0].phase_y;
	Compare_Bet[2].value = Compare_IQ[0].value;

	R848_CompreCor(priv,&Compare_Bet[0]);
		return RT_Fail;

	*IQ_Pont = Compare_Bet[0];
	
	return RT_Success;
}

R848_ErrCode R848_IMR_Cross( struct r848_priv *priv,struct r848_sect_type* IQ_Pont, u8* X_Direct)
{
	int ret;

	struct r848_sect_type Compare_Cross[9]; //(0,0)(0,Q-1)(0,I-1)(Q-1,0)(I-1,0)+(0,Q-2)(0,I-2)(Q-2,0)(I-2,0)
	struct r848_sect_type Compare_Temp;
	u8 CrossCount = 0;
	u8 Reg16 = priv->regs[8] & 0xC0;
	u8 Reg17 = priv->regs[9] & 0xC0;

	memset(&Compare_Temp, 0, sizeof(struct r848_sect_type));
	Compare_Temp.value = 255;

	for(CrossCount=0; CrossCount<9; CrossCount++)
	{

		if(CrossCount==0)
		{
		  Compare_Cross[CrossCount].gain_x = Reg16;
		  Compare_Cross[CrossCount].phase_y = Reg17;
		}
		else if(CrossCount==1)
		{
		  Compare_Cross[CrossCount].gain_x = Reg16;       //0
		  Compare_Cross[CrossCount].phase_y = Reg17 + 1;  //Q-1
		}
		else if(CrossCount==2)
		{
		  Compare_Cross[CrossCount].gain_x = Reg16;               //0
		  Compare_Cross[CrossCount].phase_y = (Reg17 | 0x20) + 1; //I-1
		}
		else if(CrossCount==3)
		{
		  Compare_Cross[CrossCount].gain_x = Reg16 + 1; //Q-1
		  Compare_Cross[CrossCount].phase_y = Reg17;
		}
		else if(CrossCount==4)
		{
		  Compare_Cross[CrossCount].gain_x = (Reg16 | 0x20) + 1; //I-1
		  Compare_Cross[CrossCount].phase_y = Reg17;
		}
		else if(CrossCount==5)
		{
		  Compare_Cross[CrossCount].gain_x = Reg16;       //0
		  Compare_Cross[CrossCount].phase_y = Reg17 + 2;  //Q-2
		}
		else if(CrossCount==6)
		{
		  Compare_Cross[CrossCount].gain_x = Reg16;               //0
		  Compare_Cross[CrossCount].phase_y = (Reg17 | 0x20) + 2; //I-2
		}
		else if(CrossCount==7)
		{
		  Compare_Cross[CrossCount].gain_x = Reg16 + 2; //Q-2
		  Compare_Cross[CrossCount].phase_y = Reg17;
		}
		else if(CrossCount==8)
		{
		  Compare_Cross[CrossCount].gain_x = (Reg16 | 0x20) + 2; //I-2
		  Compare_Cross[CrossCount].phase_y = Reg17;
		}

	ret = r848_wr(priv, 0x10, Compare_Cross[CrossCount].gain_x);
	if (ret)
		return ret;

	ret = r848_wr(priv, 0x11, Compare_Cross[CrossCount].phase_y);
	if (ret)
		return ret;

        if(r848_get_imr(priv,&Compare_Cross[CrossCount].value) != RT_Success)
		  return RT_Fail;

		if( Compare_Cross[CrossCount].value < Compare_Temp.value)
		{
		  Compare_Temp.value = Compare_Cross[CrossCount].value;
		  Compare_Temp.gain_x = Compare_Cross[CrossCount].gain_x;
		  Compare_Temp.phase_y = Compare_Cross[CrossCount].phase_y;
		}
	} //end for loop


    if(((Compare_Temp.phase_y & 0x3F)==0x01) || (Compare_Temp.phase_y & 0x3F)==0x02)  //phase Q1 or Q2
	{
      *X_Direct = (u8) 0;
	  IQ_Pont[0].gain_x = Compare_Cross[0].gain_x;    //0
	  IQ_Pont[0].phase_y = Compare_Cross[0].phase_y; //0
	  IQ_Pont[0].value = Compare_Cross[0].value;

	  IQ_Pont[1].gain_x = Compare_Cross[1].gain_x;    //0
	  IQ_Pont[1].phase_y = Compare_Cross[1].phase_y; //Q1
	  IQ_Pont[1].value = Compare_Cross[1].value;

	  IQ_Pont[2].gain_x = Compare_Cross[5].gain_x;   //0
	  IQ_Pont[2].phase_y = Compare_Cross[5].phase_y;//Q2
	  IQ_Pont[2].value = Compare_Cross[5].value;
	}
	else if(((Compare_Temp.phase_y & 0x3F)==0x21) || (Compare_Temp.phase_y & 0x3F)==0x22)  //phase I1 or I2
	{
      *X_Direct = (u8) 0;
	  IQ_Pont[0].gain_x = Compare_Cross[0].gain_x;    //0
	  IQ_Pont[0].phase_y = Compare_Cross[0].phase_y; //0
	  IQ_Pont[0].value = Compare_Cross[0].value;

	  IQ_Pont[1].gain_x = Compare_Cross[2].gain_x;    //0
	  IQ_Pont[1].phase_y = Compare_Cross[2].phase_y; //Q1
	  IQ_Pont[1].value = Compare_Cross[2].value;

	  IQ_Pont[2].gain_x = Compare_Cross[6].gain_x;   //0
	  IQ_Pont[2].phase_y = Compare_Cross[6].phase_y;//Q2
	  IQ_Pont[2].value = Compare_Cross[6].value;
	}
	else if(((Compare_Temp.gain_x & 0x3F)==0x01) || (Compare_Temp.gain_x & 0x3F)==0x02)  //gain Q1 or Q2
	{
      *X_Direct = (u8) 1;
	  IQ_Pont[0].gain_x = Compare_Cross[0].gain_x;    //0
	  IQ_Pont[0].phase_y = Compare_Cross[0].phase_y; //0
	  IQ_Pont[0].value = Compare_Cross[0].value;

	  IQ_Pont[1].gain_x = Compare_Cross[3].gain_x;    //Q1
	  IQ_Pont[1].phase_y = Compare_Cross[3].phase_y; //0
	  IQ_Pont[1].value = Compare_Cross[3].value;

	  IQ_Pont[2].gain_x = Compare_Cross[7].gain_x;   //Q2
	  IQ_Pont[2].phase_y = Compare_Cross[7].phase_y;//0
	  IQ_Pont[2].value = Compare_Cross[7].value;
	}
	else if(((Compare_Temp.gain_x & 0x3F)==0x21) || (Compare_Temp.gain_x & 0x3F)==0x22)  //gain I1 or I2
	{
      *X_Direct = (u8) 1;
	  IQ_Pont[0].gain_x = Compare_Cross[0].gain_x;    //0
	  IQ_Pont[0].phase_y = Compare_Cross[0].phase_y; //0
	  IQ_Pont[0].value = Compare_Cross[0].value;

	  IQ_Pont[1].gain_x = Compare_Cross[4].gain_x;    //I1
	  IQ_Pont[1].phase_y = Compare_Cross[4].phase_y; //0
	  IQ_Pont[1].value = Compare_Cross[4].value;

	  IQ_Pont[2].gain_x = Compare_Cross[8].gain_x;   //I2
	  IQ_Pont[2].phase_y = Compare_Cross[8].phase_y;//0
	  IQ_Pont[2].value = Compare_Cross[8].value;
	}
	else //(0,0) 
	{	
	  *X_Direct = (u8) 1;
	  IQ_Pont[0].gain_x = Compare_Cross[0].gain_x;
	  IQ_Pont[0].phase_y = Compare_Cross[0].phase_y;
	  IQ_Pont[0].value = Compare_Cross[0].value;

	  IQ_Pont[1].gain_x = Compare_Cross[3].gain_x;    //Q1
	  IQ_Pont[1].phase_y = Compare_Cross[3].phase_y; //0
	  IQ_Pont[1].value = Compare_Cross[3].value;

	  IQ_Pont[2].gain_x = Compare_Cross[4].gain_x;   //I1
	  IQ_Pont[2].phase_y = Compare_Cross[4].phase_y; //0
	  IQ_Pont[2].value = Compare_Cross[4].value;
	}
	return RT_Success;
}

//-------------------------------------------------------------------------------------//
// Purpose: if (Gain<9 or Phase<9), Gain+1 or Phase+1 and compare with min value
//          new < min => update to min and continue
//          new > min => Exit
// input: StepArry: three IMR data array
//        Pace: gain or phase register
//-------------------------------------------------------------------------------------//
R848_ErrCode R848_CompreStep( struct r848_priv *priv,struct r848_sect_type* StepArry, u8 Pace)
{
	int ret;
	struct r848_sect_type StepTemp;
	//min value already saved in StepArry[0]
	StepTemp.phase_y = StepArry[0].phase_y;
	StepTemp.gain_x  = StepArry[0].gain_x;
	//StepTemp.iqcap  = StepArry[0].iqcap;

	while(((StepTemp.gain_x & 0x1F) < R848_IMR_TRIAL) && ((StepTemp.phase_y & 0x1F) < R848_IMR_TRIAL))  
	{
		if(Pace == 0x10)	
			StepTemp.gain_x ++;
		else
			StepTemp.phase_y ++;
	
		ret = r848_wr(priv, 0x10, StepTemp.gain_x);
		if (ret)
			return ret;

		ret = r848_wr(priv, 0x11, StepTemp.phase_y);
		if (ret)
			return ret;

		if(r848_get_imr(priv,&StepTemp.value) != RT_Success)
			return RT_Fail;

		if(StepTemp.value <= StepArry[0].value)
		{
			StepArry[0].gain_x  = StepTemp.gain_x;
			StepArry[0].phase_y = StepTemp.phase_y;
			//StepArry[0].iqcap = StepTemp.iqcap;
			StepArry[0].value   = StepTemp.value;
		}
		else if((StepTemp.value - 2) > StepArry[0].value)
		{
			break;		
		}
		
	} //end of while()
	
	return RT_Success;
}

R848_ErrCode R848_IMR_Iqcap( struct r848_priv *priv,struct r848_sect_type* IQ_Point)   
{
    struct r848_sect_type Compare_Temp;
	int i = 0, ret;

	//Set Gain/Phase to right setting
//	R848_I2C.RegAddr = 0x10;	// R16[5:0]  
	ret = r848_wr(priv, 0x10, IQ_Point->gain_x);
	if (ret)
		return ret;

//	R848_I2C.RegAddr = 0x11;	// R17[5:0]  
	ret = r848_wr(priv, 0x11, IQ_Point->phase_y);
	if (ret)
		return ret;

	//try iqcap
	for(i=0; i<3; i++)	
	{
		Compare_Temp.iqcap = (u8) i;  
//		R848_I2C.RegAddr = 0x0B;		// R11[1:0] 
		priv->regs[3] = (priv->regs[3] & 0xFC) | Compare_Temp.iqcap;  
		ret = r848_wr(priv, 0x0b, priv->regs[3]);
		if (ret)
			return ret;

		if(r848_get_imr(priv,&(Compare_Temp.value)) != RT_Success)
			   return RT_Fail;

		if(Compare_Temp.value < IQ_Point->value)
		{
			IQ_Point->value = Compare_Temp.value; 
			IQ_Point->iqcap = Compare_Temp.iqcap;
		}
	}

    return RT_Success;
}


R848_ErrCode R848_IQ( struct r848_priv *priv,struct r848_sect_type* IQ_Pont)
{
	int ret;
	struct r848_sect_type Compare_IQ[3];
	u8   VGA_Count = 0;
	u8   VGA_Read = 0;
	u8   X_Direction;  // 1:X, 0:Y


	// increase VGA power to let image significant
	for(VGA_Count=11; VGA_Count < 16; VGA_Count ++)
	{
//		R848_I2C.RegAddr = 0x14; // R848:R20[3:0]  
		ret = r848_wr(priv, 0x14, (priv->regs[12] & 0xF0) + VGA_Count);
		if (ret)
			return ret;

		msleep(10);

		if(r848_get_imr(priv,&VGA_Read) != RT_Success)
			return RT_Fail;

		if(VGA_Read > 40)
			break;
	}

	Compare_IQ[0].gain_x  = priv->regs[8] & 0xC0; // R16[5:0]  
	Compare_IQ[0].phase_y = priv->regs[9] & 0xC0; // R17[5:0] 
	//Compare_IQ[0].iqcap = R848_iniArray[3] & 0xFC;

	    // Determine X or Y
	    if(R848_IMR_Cross(priv,&Compare_IQ[0], &X_Direction) != RT_Success)
			return RT_Fail;

		if(X_Direction==1)
		{
			//compare and find min of 3 points. determine I/Q direction
		    R848_CompreCor(priv,&Compare_IQ[0]);

		    //increase step to find min value of this direction
		    if(R848_CompreStep(priv,&Compare_IQ[0], 0x10) != RT_Success)  //X
			  return RT_Fail;	
		}
		else
		{
		   //compare and find min of 3 points. determine I/Q direction
		   R848_CompreCor(priv,&Compare_IQ[0]);

		   //increase step to find min value of this direction
		   if(R848_CompreStep(priv,&Compare_IQ[0], 0x11) != RT_Success)  //Y
			 return RT_Fail;	
		}

		//Another direction
		if(X_Direction==1)
		{	    
           if(R848_IQ_Tree(priv,Compare_IQ[0].gain_x, Compare_IQ[0].phase_y, 0x10, &Compare_IQ[0]) != RT_Success) //Y	
		     return RT_Fail;	

		   //compare and find min of 3 points. determine I/Q direction
		   R848_CompreCor(priv,&Compare_IQ[0]);

		   //increase step to find min value of this direction
		   if(R848_CompreStep(priv,&Compare_IQ[0], 0x11) != RT_Success)  //Y
			 return RT_Fail;	
		}
		else
		{
		   if(R848_IQ_Tree(priv,Compare_IQ[0].phase_y, Compare_IQ[0].gain_x, 0x11, &Compare_IQ[0]) != RT_Success) //X
		     return RT_Fail;	
        
		   //compare and find min of 3 points. determine I/Q direction
		   R848_CompreCor(priv,&Compare_IQ[0]);

	       //increase step to find min value of this direction
		   if(R848_CompreStep(priv,&Compare_IQ[0], 0x10) != RT_Success) //X
		     return RT_Fail;	
		}
		

		//--- Check 3 points again---//
		if(X_Direction==1)
		{
		    if(R848_IQ_Tree(priv,Compare_IQ[0].phase_y, Compare_IQ[0].gain_x, 0x11, &Compare_IQ[0]) != RT_Success) //X
			  return RT_Fail;	
		}
		else
		{
		   if(R848_IQ_Tree(priv,Compare_IQ[0].gain_x, Compare_IQ[0].phase_y, 0x10, &Compare_IQ[0]) != RT_Success) //Y
			return RT_Fail;		
		}

		R848_CompreCor(priv,&Compare_IQ[0]);

    //Section-9 check
    //if(R848_F_IMR(&Compare_IQ[0]) != RT_Success)
	if(R848_Section(priv,&Compare_IQ[0]) != RT_Success)
			return RT_Fail;

	//clear IQ_Cap = 0   //  R11[1:0]  
	Compare_IQ[0].iqcap = priv->regs[3] & 0xFC;

	if(R848_IMR_Iqcap(priv,&Compare_IQ[0]) != RT_Success)
			return RT_Fail;

	*IQ_Pont = Compare_IQ[0];

	//reset gain/phase/iqcap control setting
//	R848_I2C.RegAddr = 0x10;	// R16[5:0]  
	priv->regs[8] = priv->regs[8] & 0xC0;
	ret = r848_wr(priv, 0x10, priv->regs[8]);
	if (ret)
		return ret;

//	R848_I2C.RegAddr = 0x11;	// R17[5:0]  
	priv->regs[9] = priv->regs[9] & 0xC0;
	ret = r848_wr(priv, 0x11, priv->regs[9]);
	if (ret)
		return ret;

//	R848_I2C.RegAddr = 0x0B;	//  R11[1:0] 
	priv->regs[3] = priv->regs[3] & 0xFC;
	ret = r848_wr(priv, 0x0b, priv->regs[3]);
	if (ret)
		return ret;

	return RT_Success;
}

//----------------------------------------------------------------------------------------//
// purpose: search surrounding points from previous point 
//          try (x-1), (x), (x+1) columns, and find min IMR result point
// input: IQ_Pont: previous point data(IMR Gain, Phase, ADC Result, RefRreq)
//                 will be updated to final best point                 
// output: TRUE or FALSE
//----------------------------------------------------------------------------------------//
R848_ErrCode R848_F_IMR( struct r848_priv *priv,struct r848_sect_type* IQ_Pont)
{
	int ret;
	struct r848_sect_type Compare_IQ[3];
	struct r848_sect_type Compare_Bet[3];
	u8 VGA_Count = 0;
	u8 VGA_Read = 0;

	//VGA
	for(VGA_Count=11; VGA_Count < 16; VGA_Count ++)
	{
//		R848_I2C.RegAddr = 0x14;	//  R20[3:0]  
		ret = r848_wr(priv, 0x14, (priv->regs[12] & 0xF0) + VGA_Count);
		if (ret)
			return ret;

		msleep(10);
		
		if(r848_get_imr(priv,&VGA_Read) != RT_Success)
			return RT_Fail;

		if(VGA_Read > 40)
		break;
	}

	//Try X-1 column and save min result to Compare_Bet[0]
	if((IQ_Pont->gain_x & 0x1F) == 0x00)
	{
		Compare_IQ[0].gain_x = ((IQ_Pont->gain_x) & 0xDF) + 1;  //Q-path, Gain=1
	}
	else
	{
		Compare_IQ[0].gain_x  = IQ_Pont->gain_x - 1;  //left point
	}
	Compare_IQ[0].phase_y = IQ_Pont->phase_y;

	if(R848_IQ_Tree(priv,Compare_IQ[0].gain_x, Compare_IQ[0].phase_y, 0x10, &Compare_IQ[0]) != RT_Success)  // y-direction
		return RT_Fail;	

	R848_CompreCor(priv,&Compare_IQ[0]);

	Compare_Bet[0].gain_x = Compare_IQ[0].gain_x;
	Compare_Bet[0].phase_y = Compare_IQ[0].phase_y;
	Compare_Bet[0].value = Compare_IQ[0].value;

	//Try X column and save min result to Compare_Bet[1]
	Compare_IQ[0].gain_x = IQ_Pont->gain_x;
	Compare_IQ[0].phase_y = IQ_Pont->phase_y;

	if(R848_IQ_Tree(priv,Compare_IQ[0].gain_x, Compare_IQ[0].phase_y, 0x10, &Compare_IQ[0]) != RT_Success)
		return RT_Fail;	

	R848_CompreCor(priv,&Compare_IQ[0]);

	Compare_Bet[1].gain_x = Compare_IQ[0].gain_x;
	Compare_Bet[1].phase_y = Compare_IQ[0].phase_y;
	Compare_Bet[1].value = Compare_IQ[0].value;

	//Try X+1 column and save min result to Compare_Bet[2]
	if((IQ_Pont->gain_x & 0x1F) == 0x00)		
		Compare_IQ[0].gain_x = ((IQ_Pont->gain_x) | 0x20) + 1;  //I-path, Gain=1
	else
	    Compare_IQ[0].gain_x = IQ_Pont->gain_x + 1;
	Compare_IQ[0].phase_y = IQ_Pont->phase_y;

	if(R848_IQ_Tree(priv,Compare_IQ[0].gain_x, Compare_IQ[0].phase_y, 0x10, &Compare_IQ[0]) != RT_Success)
		return RT_Fail;		

	R848_CompreCor(priv,&Compare_IQ[0]);

	Compare_Bet[2].gain_x = Compare_IQ[0].gain_x;
	Compare_Bet[2].phase_y = Compare_IQ[0].phase_y;
	Compare_Bet[2].value = Compare_IQ[0].value;

	R848_CompreCor(priv,&Compare_Bet[0]);

	//clear IQ_Cap = 0
	Compare_Bet[0].iqcap = priv->regs[3] & 0xFC;	//  R11[1:0] 

	if(R848_IMR_Iqcap(priv,&Compare_Bet[0]) != RT_Success)
		return RT_Fail;

	*IQ_Pont = Compare_Bet[0];
	
	return RT_Success;
}


R848_ErrCode R848_SetTF( struct r848_priv *priv,u32 u4FreqKHz, u8 u1TfType)
{
	int ret;
    u8    u1FreqCount = 0;
	u32   u4Freq1 = 0;
	u32   u4Freq2 = 0;
	u32   u4Ratio;
	u8    u1TF_Set_Result1 = 0;
	u8    u1TF_Set_Result2 = 0;
	u8    u1TF_tmp1, u1TF_tmp2;
	u8    u1TFCalNum = R848_TF_HIGH_NUM;
	u8  R848_TF = 0;

	if(u4FreqKHz<R848_LNA_LOW_LOWEST[R848_TF_BEAD])  //Ultra Low
	{
		 u1TFCalNum = R848_TF_LOWEST_NUM;
         while((u4FreqKHz < R848_TF_Freq_Lowest[u1TfType][u1FreqCount]) && (u1FreqCount<R848_TF_LOWEST_NUM))
		 {
            u1FreqCount++;
		 }

		 if(u1FreqCount==0)
		 {
			 R848_TF = R848_TF_Result_Lowest[u1TfType][0];
		 }
		 else if(u1FreqCount==R848_TF_LOWEST_NUM)
         {
			 R848_TF = R848_TF_Result_Lowest[u1TfType][R848_TF_LOWEST_NUM-1];
		 }
		 else
		 {
			 u1TF_Set_Result1 = R848_TF_Result_Lowest[u1TfType][u1FreqCount-1]; 
		     u1TF_Set_Result2 = R848_TF_Result_Lowest[u1TfType][u1FreqCount]; 
		     u4Freq1 = R848_TF_Freq_Lowest[u1TfType][u1FreqCount-1];
		     u4Freq2 = R848_TF_Freq_Lowest[u1TfType][u1FreqCount]; 

			 //u4Ratio = (u4Freq1- u4FreqKHz)*100/(u4Freq1 - u4Freq2);
             //R848_TF = u1TF_Set_Result1 + (u8)((u1TF_Set_Result2 - u1TF_Set_Result1)*u4Ratio/100);

			 u1TF_tmp1 = ((u1TF_Set_Result1 & 0x40)>>2)*3 + (u1TF_Set_Result1 & 0x3F);  //b6 is 3xb4
			 u1TF_tmp2 = ((u1TF_Set_Result2 & 0x40)>>2)*3 + (u1TF_Set_Result2 & 0x3F);			 
			 u4Ratio = (u4Freq1- u4FreqKHz)*100/(u4Freq1 - u4Freq2);
			 R848_TF = u1TF_tmp1 + (u8)((u1TF_tmp2 - u1TF_tmp1)*u4Ratio/100);
			 if(R848_TF>=0x40)
				 R848_TF = (R848_TF + 0x10);

		 }
	}
	else if((u4FreqKHz>=R848_LNA_LOW_LOWEST[R848_TF_BEAD]) && (u4FreqKHz<R848_LNA_MID_LOW[R848_TF_BEAD]))  //Low
	{
		 u1TFCalNum = R848_TF_LOW_NUM;
         while((u4FreqKHz < R848_TF_Freq_Low[u1TfType][u1FreqCount]) && (u1FreqCount<R848_TF_LOW_NUM))
		 {
            u1FreqCount++;
		 }

		 if(u1FreqCount==0)
		 {
			 R848_TF = R848_TF_Result_Low[u1TfType][0];
		 }
		 else if(u1FreqCount==R848_TF_LOW_NUM)
        {
			 R848_TF = R848_TF_Result_Low[u1TfType][R848_TF_LOW_NUM-1];
		 }
		 else
		 {
			 u1TF_Set_Result1 = R848_TF_Result_Low[u1TfType][u1FreqCount-1]; 
		     u1TF_Set_Result2 = R848_TF_Result_Low[u1TfType][u1FreqCount]; 
		     u4Freq1 = R848_TF_Freq_Low[u1TfType][u1FreqCount-1];
		     u4Freq2 = R848_TF_Freq_Low[u1TfType][u1FreqCount]; 

			 //u4Ratio = (u4Freq1- u4FreqKHz)*100/(u4Freq1 - u4Freq2);
             //R848_TF = u1TF_Set_Result1 + (u8)((u1TF_Set_Result2 - u1TF_Set_Result1)*u4Ratio/100);

			 u1TF_tmp1 = ((u1TF_Set_Result1 & 0x40)>>2) + (u1TF_Set_Result1 & 0x3F);  //b6 is 1xb4
			 u1TF_tmp2 = ((u1TF_Set_Result2 & 0x40)>>2) + (u1TF_Set_Result2 & 0x3F);			 
			 u4Ratio = (u4Freq1- u4FreqKHz)*100/(u4Freq1 - u4Freq2);
			 R848_TF = u1TF_tmp1 + (u8)((u1TF_tmp2 - u1TF_tmp1)*u4Ratio/100);
			 if(R848_TF>=0x40)
				 R848_TF = (R848_TF + 0x30);
		 }
	}
	else if((u4FreqKHz>=R848_LNA_MID_LOW[R848_TF_BEAD]) && (u4FreqKHz<R848_LNA_HIGH_MID[R848_TF_BEAD]))  //Mid
    {
		 u1TFCalNum = R848_TF_MID_NUM;
         while((u4FreqKHz < R848_TF_Freq_Mid[u1TfType][u1FreqCount]) && (u1FreqCount<R848_TF_MID_NUM))
		 {
            u1FreqCount++;
		 }

		 if(u1FreqCount==0)
		 {
			 R848_TF = R848_TF_Result_Mid[u1TfType][0];
		 }
		 else if(u1FreqCount==R848_TF_MID_NUM)
        {
			 R848_TF = R848_TF_Result_Mid[u1TfType][R848_TF_MID_NUM-1];
		 }
		 else
		 {
			 u1TF_Set_Result1 = R848_TF_Result_Mid[u1TfType][u1FreqCount-1]; 
		     u1TF_Set_Result2 = R848_TF_Result_Mid[u1TfType][u1FreqCount]; 
		     u4Freq1 = R848_TF_Freq_Mid[u1TfType][u1FreqCount-1];
		     u4Freq2 = R848_TF_Freq_Mid[u1TfType][u1FreqCount]; 
			 u4Ratio = (u4Freq1- u4FreqKHz)*100/(u4Freq1 - u4Freq2);
             R848_TF = u1TF_Set_Result1 + (u8)((u1TF_Set_Result2 - u1TF_Set_Result1)*u4Ratio/100);
		 }
	}
	else  //HIGH
	{
		 u1TFCalNum = R848_TF_HIGH_NUM;
         while((u4FreqKHz < R848_TF_Freq_High[u1TfType][u1FreqCount]) && (u1FreqCount<R848_TF_HIGH_NUM))
		 {
            u1FreqCount++;
		 }

		 if(u1FreqCount==0)
		 {
			 R848_TF = R848_TF_Result_High[u1TfType][0];
		 }
		 else if(u1FreqCount==R848_TF_HIGH_NUM)
        {
			 R848_TF = R848_TF_Result_High[u1TfType][R848_TF_HIGH_NUM-1];
		 }
		 else
		 {
			 u1TF_Set_Result1 = R848_TF_Result_High[u1TfType][u1FreqCount-1]; 
		     u1TF_Set_Result2 = R848_TF_Result_High[u1TfType][u1FreqCount]; 
		     u4Freq1 = R848_TF_Freq_High[u1TfType][u1FreqCount-1];
		     u4Freq2 = R848_TF_Freq_High[u1TfType][u1FreqCount]; 
			 u4Ratio = (u4Freq1- u4FreqKHz)*100/(u4Freq1 - u4Freq2);
             R848_TF = u1TF_Set_Result1 + (u8)((u1TF_Set_Result2 - u1TF_Set_Result1)*u4Ratio/100);
		 }
	}
  
	// R8[6:0] 
//	R848_I2C.RegAddr = 0x08;
	priv->regs[0] = (priv->regs[0] & 0x80) | R848_TF;
	ret = r848_wr(priv, 0x0b, priv->regs[0]);
	if (ret)
		return ret;

    return RT_Success;
}

R848_ErrCode R848_IMR( struct r848_priv *priv,u8 IMR_MEM, bool IM_Flag)
{
	int ret;
	u32 RingVCO = 0;
	u32 RingFreq = 0;
	u8  u1MixerGain = 8;

	struct r848_sect_type IMR_POINT;

	RingVCO = 3200000;
	priv->regs[31] &= 0x3F;   //clear ring_div1, R24[7:6]	//R848:R39[7:6]  39-8=31  39(0x27) is addr ; [31] is data 
	priv->regs[25] &= 0xFC;   //clear ring_div2, R25[1:0]	//R848:R33[1:0]  33-8=25  33(0x21) is addr ; [25] is data 
	priv->regs[25] &= 0xDF;   //clear vco_band, R25[5]		//R848:R33[5]    33-8=25  33(0x21) is addr ; [25] is data 
	priv->regs[31] &= 0xC3;   //clear ring_div_num, R24[3:0]//R848:R39[5:2]  39-8=31  39(0x27) is addr ; [31] is data

	switch(IMR_MEM)
	{
	case 0: // RingFreq = 66.66M
		RingFreq = RingVCO/48;
		priv->regs[31] |= 0x80;  // ring_div1 /6 (2)
		priv->regs[25] |= 0x03;  // ring_div2 /8 (3)
		priv->regs[25] |= 0x00;  // vco_band = 0 (high)
		priv->regs[31] |= 0x24;  // ring_div_num = 9
		u1MixerGain = 8;
		break;
	case 1: // RingFreq = 200M
		RingFreq = RingVCO/16;
		priv->regs[31] |= 0x00;  // ring_div1 /4 (0)
		priv->regs[25] |= 0x02;  // ring_div2 /4 (2)
		priv->regs[25] |= 0x00;  // vco_band = 0 (high)
		priv->regs[31] |= 0x24;  // ring_div_num = 9
		u1MixerGain = 6;
		break;
	case 2: // RingFreq = 400M
		RingFreq = RingVCO/8;
		priv->regs[31] |= 0x00;  // ring_div1 /4 (0)
		priv->regs[25] |= 0x01;  // ring_div2 /2 (1)
		priv->regs[25] |= 0x00;  // vco_band = 0 (high)
		priv->regs[31] |= 0x24;  // ring_div_num = 9
		u1MixerGain = 6;
		break;
	case 3: // RingFreq = 533.33M
		RingFreq = RingVCO/6;
		priv->regs[31] |= 0x80;  // ring_div1 /6 (2)
		priv->regs[25] |= 0x00;  // ring_div2 /1 (0)
		priv->regs[25] |= 0x00;  // vco_band = 0 (high)
		priv->regs[31] |= 0x24;  // ring_div_num = 9
		u1MixerGain = 8;
		break;
	case 4: // RingFreq = 800M
		RingFreq = RingVCO/4;
		priv->regs[31] |= 0x00;  // ring_div1 /4 (0)
		priv->regs[25] |= 0x00;  // ring_div2 /1 (0)
		priv->regs[25] |= 0x00;  // vco_band = 0 (high)
		priv->regs[31] |= 0x24;  // ring_div_num = 9
		u1MixerGain = 8;
		break;
	default:
		RingFreq = RingVCO/4;
		priv->regs[31] |= 0x00;  // ring_div1 /4 (0)
		priv->regs[25] |= 0x00;  // ring_div2 /1 (0)
		priv->regs[25] |= 0x00;  // vco_band = 0 (high)
		priv->regs[31] |= 0x24;  // ring_div_num = 9
		u1MixerGain = 8;
		break;
	}

	//Mixer Amp Gain
	//R848_I2C.RegAddr = 0x0F;	//R848:R15[4:0] 
	priv->regs[7] = (priv->regs[7] & 0xE0) | u1MixerGain; 
	ret = r848_wr(priv, 0x0f, priv->regs[7]);

	//write I2C to set RingPLL
	ret |= r848_wr(priv, 0x27, priv->regs[31]);
	ret |= r848_wr(priv, 0x21, priv->regs[25]);

	//Ring PLL power
	//if((RingFreq>=0) && (RingFreq<R848_RING_POWER_FREQ_LOW))
	if(((RingFreq<R848_RING_POWER_FREQ_LOW)||(RingFreq>R848_RING_POWER_FREQ_HIGH)))  //R848:R33[3:2] 
         priv->regs[25] = (priv->regs[25] & 0xF3) | 0x08;   //R25[3:2]=2'b10; min_lp
	else
        priv->regs[25] = (priv->regs[25] & 0xF3) | 0x00;   //R25[3:2]=2'b00; min

	ret |= r848_wr(priv, 0x21, priv->regs[25]);
	
	//Must do MUX before PLL() 
	if(r848_set_mux(priv,RingFreq - R848_IMR_IF, RingFreq, R848_STD_SIZE) != RT_Success)      //IMR MUX (LO, RF)
		return RT_Fail;

	if(r848_set_pll(priv,(RingFreq - R848_IMR_IF), R848_STD_SIZE) != RT_Success)  //IMR PLL
	    return RT_Fail;

	//Set TF, place after R848_MUX( )
	//TF is dependent to LNA/Mixer Gain setting
	if(R848_SetTF(priv,RingFreq, (u8)R848_TF_BEAD) != RT_Success)
		return RT_Fail;

	//clear IQ_cap
	IMR_POINT.iqcap = priv->regs[3] & 0xFC; // R848:R11[1:0] 

	if(IM_Flag == 0)
	{
	     if(R848_IQ(priv,&IMR_POINT) != RT_Success)
		    return RT_Fail;
	}
	else
	{
		IMR_POINT.gain_x = priv->imr_data[3].gain_x;
		IMR_POINT.phase_y = priv->imr_data[3].phase_y;
		IMR_POINT.value = priv->imr_data[3].value;
		//IMR_POINT.iqcap = priv->imr_data[3].iqcap;
		if(R848_F_IMR(priv,&IMR_POINT) != RT_Success)
			return RT_Fail;
	}

	//Save IMR Value
	switch(IMR_MEM)
	{
	case 0:
		priv->imr_data[0].gain_x  = IMR_POINT.gain_x;
		priv->imr_data[0].phase_y = IMR_POINT.phase_y;
		priv->imr_data[0].value = IMR_POINT.value;
		priv->imr_data[0].iqcap = IMR_POINT.iqcap;		
		break;
	case 1:
		priv->imr_data[1].gain_x  = IMR_POINT.gain_x;
		priv->imr_data[1].phase_y = IMR_POINT.phase_y;
		priv->imr_data[1].value = IMR_POINT.value;
		priv->imr_data[1].iqcap = IMR_POINT.iqcap;
		break;
	case 2:
		priv->imr_data[2].gain_x  = IMR_POINT.gain_x;
		priv->imr_data[2].phase_y = IMR_POINT.phase_y;
		priv->imr_data[2].value = IMR_POINT.value;
		priv->imr_data[2].iqcap = IMR_POINT.iqcap;
		break;
	case 3:
		priv->imr_data[3].gain_x  = IMR_POINT.gain_x;
		priv->imr_data[3].phase_y = IMR_POINT.phase_y;
		priv->imr_data[3].value = IMR_POINT.value;
		priv->imr_data[3].iqcap = IMR_POINT.iqcap;
		break;
	case 4:
		priv->imr_data[4].gain_x  = IMR_POINT.gain_x;
		priv->imr_data[4].phase_y = IMR_POINT.phase_y;
		priv->imr_data[4].value = IMR_POINT.value;
		priv->imr_data[4].iqcap = IMR_POINT.iqcap;
		break;
    default:
		priv->imr_data[4].gain_x  = IMR_POINT.gain_x;
		priv->imr_data[4].phase_y = IMR_POINT.phase_y;
		priv->imr_data[4].value = IMR_POINT.value;
		priv->imr_data[4].iqcap = IMR_POINT.iqcap;
		break;
	}
	return ret;
}



#if 0
static int R848_GPO( struct r848_priv *priv,R848_GPO_Type R848_GPO_Conrl)
{
	if(R848_GPO_Conrl == HI_SIG)	//  R23[0]
		priv->regs[15] |= 0x01;	//high
	else
		priv->regs[15] &= 0xFE;	//low
	return r848_wr(priv, 0x17, priv->regs[15]);
}
#endif


u8  R848_Filt_Cal_ADC( struct r848_priv *priv,u32 IF_Freq, u8 R848_BW, u8 FilCal_Gap)
{
	int ret;
	 u8     u1FilterCodeResult = 0;
	 u8     u1FilterCode = 0;
	 u32   u4RingFreq = 72000;
	 u8     u1FilterCalValue = 0;
	 u8     u1FilterCalValuePre = 0;
	 u8     initial_cnt = 0;
	 u8     i = 0;
	 u8 	R848_Bandwidth = 0x00;
	 u8   VGA_Count = 0;
	 u8   VGA_Read = 0;

	 R848_Standard_Type	R848_Standard;
	 R848_Standard=R848_ATSC; //no set R848_DVB_S

	 //Write initial reg before doing calibration 
	 if(r848_init_regs(priv,R848_Standard) != RT_Success)        
		return RT_Fail;

	 if(R848_Cal_Prepare(priv,R848_LPF_CAL) != RT_Success)      
	      return RT_Fail;



	// R848:R39[5:2]
	priv->regs[31] = (priv->regs[31] & 0xC3) | 0x2C;
	ret = r848_wr(priv, 0x27, priv->regs[31]);

	// R848_I2C.RegAddr = 0x12;	//R848:R18[4]  
	 priv->regs[10] = (priv->regs[10] & 0xEF) | 0x00; 
	ret |= r848_wr(priv, 0x12, priv->regs[10]);

	// R848_I2C.RegAddr = 0x25;	//  R848:R37[7]  
	 priv->regs[29] = (priv->regs[29] & 0x7F) | 0x00; 
	ret |= r848_wr(priv, 0x25, priv->regs[29]);
	
	// R848_I2C.RegAddr = 0x27;	//  R848:R39[7:6]  
	 priv->regs[31] = (priv->regs[31] & 0x3F) | 0x80;  
	ret |= r848_wr(priv, 0x27, priv->regs[31]);
	
	// R848_I2C.RegAddr = 0x21;	//  R848:R33[7:0]  
	 priv->regs[25] = (priv->regs[25] & 0x00) | 0x8B;   //out div=8, RF poly=low band, power=min_lp
	ret |= r848_wr(priv, 0x21, priv->regs[25]);

     //Must do before PLL() 
	 if(r848_set_mux(priv,u4RingFreq + IF_Freq, u4RingFreq, R848_STD_SIZE) != RT_Success)     //FilCal MUX (LO_Freq, RF_Freq)
	     return RT_Fail;

	 //Set PLL
	 if(r848_set_pll(priv,(u4RingFreq + IF_Freq), R848_STD_SIZE) != RT_Success)   //FilCal PLL
	       return RT_Fail;

	 //-----below must set after R848_MUX()-------//
	 //Set LNA TF for RF=72MHz. no use

	//    R848_I2C.RegAddr = 0x08;	//  R848:R8[6:0]  
        priv->regs[0] = (priv->regs[0] & 0x80) | 0x00;  
	ret |= r848_wr(priv, 0x08, priv->regs[0]);

	 //Adc=on set 0;
	 //R848_I2C.RegAddr = 0x0F;		//  R848:R15[7]  
     priv->regs[7] = (priv->regs[7] & 0x7F);
	ret |= r848_wr(priv, 0x0f, priv->regs[7]);



	//pwd_vga  vga power on set 0;
	 //R848_I2C.RegAddr = 0x12;	//  R848:R18[7] 
     priv->regs[10] = (priv->regs[10] & 0x7F);  
	ret |= r848_wr(priv, 0x12, priv->regs[10]);


	 //vga6db normal set 0;
	 //R848_I2C.RegAddr = 0x0B;		// R848:R11[3]  
     priv->regs[3] = (priv->regs[3] & 0xF7);
	ret |= r848_wr(priv, 0x0b, priv->regs[3]);

 	 //Vga Gain = -12dB 
	 //R848_I2C.RegAddr = 0x14;		//  R848:R20[3:0]  
     priv->regs[12] = (priv->regs[12] & 0xF0);
	ret |= r848_wr(priv, 0x14, priv->regs[12]);

	 // vcomp = 0
	 //R848_I2C.RegAddr = 0x26;	//  R848:R38[6:5]  
	 priv->regs[30] = (priv->regs[30] & 0x9F);	
	ret |= r848_wr(priv, 0x26, priv->regs[30]);
	
	 //Set BW=8M, HPF corner narrowest; 1.7M disable
     //R848_I2C.RegAddr = 0x13;	//  R848:R19[7:0]  
	 priv->regs[11] = (priv->regs[11] & 0x00);	  
	ret |= r848_wr(priv, 0x13, priv->regs[11]);

	 //------- increase VGA power to let ADC read value significant ---------//

	 //R848_I2C.RegAddr = 0x12;	//  R848:R18[3:0]  
     priv->regs[10] = (priv->regs[10] & 0xF0) | 0;  //filter code=0
	ret |= r848_wr(priv, 0x12, priv->regs[10]);
	if (ret)
		return ret;


	 for (VGA_Count = 0; VGA_Count < 16; VGA_Count++) {
		//R848_I2C.RegAddr = 0x14;	//  R848:R20[3:0]
		ret = r848_wr(priv, 0x14, (priv->regs[12] & 0xF0) + VGA_Count);
		msleep(10);
		ret |= r848_get_imr(priv,&VGA_Read);
		if (ret)
			return ret;
		if (VGA_Read > 40)
			break;
	 }

	 //------- Try suitable BW --------//

	 if(R848_BW==0x60) //6M
         initial_cnt = 1;  //try 7M first
	 else
		 initial_cnt = 0;  //try 8M first

	 for(i=initial_cnt; i<3; i++)
	 {
         if(i==0)
             R848_Bandwidth = 0x00; //8M
		 else if(i==1)
			 R848_Bandwidth = 0x40; //7M
		 else
			 R848_Bandwidth = 0x60; //6M

		 //R848_I2C.RegAddr = 0x13;	//  R848:R19[7:0]  
	     priv->regs[11] = (priv->regs[11] & 0x00) | R848_Bandwidth;	  
	ret |= r848_wr(priv, 0x13, priv->regs[11]);

		 // read code 0
		 //R848_I2C.RegAddr = 0x12;	//  R848:R18[3:0]  
		 priv->regs[10] = (priv->regs[10] & 0xF0) | 0;  //code 0
	ret |= r848_wr(priv, 0x12, priv->regs[10]);

		 msleep(10); //delay ms
	     
		 if(r848_get_imr(priv,&u1FilterCalValuePre) != RT_Success)
			  return RT_Fail;

		 //read code 13
		 //R848_I2C.RegAddr = 0x12;	// R848:R18[3:0]  
		 priv->regs[10] = (priv->regs[10] & 0xF0) | 13;  //code 13
	ret |= r848_wr(priv, 0x12, priv->regs[10]);

		 msleep(10); //delay ms
	     
		 if(r848_get_imr(priv,&u1FilterCalValue) != RT_Success)
			  return RT_Fail;

		 if(u1FilterCalValuePre > (u1FilterCalValue+8))  //suitable BW found
			 break;
	 }

     //-------- Try LPF filter code ---------//
	 u1FilterCalValuePre = 0;
	 for(u1FilterCode=0; u1FilterCode<16; u1FilterCode++)
	 {
         //R848_I2C.RegAddr = 0x12;	//  R848:R18[3:0]  
         priv->regs[10] = (priv->regs[10] & 0xF0) | u1FilterCode;
	ret |= r848_wr(priv, 0x12, priv->regs[10]);

		 msleep(10); //delay ms

		 if(r848_get_imr(priv,&u1FilterCalValue) != RT_Success)
		      return RT_Fail;

		 if(u1FilterCode==0)
              u1FilterCalValuePre = u1FilterCalValue;

		 if((u1FilterCalValue+FilCal_Gap) < u1FilterCalValuePre)
		 {
			 u1FilterCodeResult = u1FilterCode;
			  break;
		 }

	 }

	 if(u1FilterCode==16)
          u1FilterCodeResult = 15;

	  return u1FilterCodeResult;

}


R848_ErrCode R848_DVBS_Setting(struct r848_priv *priv)
{
	int ret;
	 u32	LO_KHz;
	 u8 fine_tune,Coarse_tune;
	 u32 Coarse;

	//if (priv->standard != R848_DVB_S)
	{
		priv->standard = R848_DVB_S;
		if(r848_init_regs(priv,priv->standard))
			return RT_Fail;
	}

	LO_KHz = priv->freq;

	if (r848_set_pll(priv, LO_KHz, priv->standard))
		return RT_Fail;

	//VTH/VTL
	if ((priv->freq >= 1200000) && (priv->freq <= 1750000)) {
		priv->regs[23]=(priv->regs[23] & 0x00) | 0x93;	//R848:R31[7:0    1.24/0.64
	} else {
		priv->regs[23]=(priv->regs[23] & 0x00) | 0x83;	//R848:R31[7:0]   1.14/0.64
	}
	ret = r848_wr(priv, 0x1f, priv->regs[23]);



	if(priv->freq >= 2000000) 
	{
		priv->regs[38]=(priv->regs[38] & 0xCF) | 0x20;	//R848:R46[4:5]
		ret |= r848_wr(priv, 0x2e, priv->regs[38]);
	}


	if((priv->freq >= 1600000) && (priv->freq <= 1950000)) {
		priv->regs[35] |= 0x20; //LNA Mode with att   //R710 R2[6]    R848:R43[5]
		//priv->regs[36] |= 0x04; //Mixer Buf -3dB  //R710 R8[7]    R848:R44[2]
	} else {
		priv->regs[35] &= 0xDF; //LNA Mode no att
		//priv->regs[36] &= 0xFB; //Mixer Buf off
	}
	ret |= r848_wr(priv, 0x2b, priv->regs[35]);
	//ret |= r848_wr(priv, 0x2c, priv->regs[36]); //TEST


	//Output Signal Mode    (  O is diff  ; 1 is single  )
	if(priv->output_mode != SINGLEOUT) {
		priv->regs[35] &=0x7F;
	} else {
		priv->regs[35] |=0x80;  // R848:R43[7]
	}
	ret |= r848_wr(priv, 0x2b, priv->regs[35]);


	//AGC Type  //R13[4] Negative=0 ; Positive=1;
	if(priv->agc_mode != AGC_POSITIVE) {
		priv->regs[37] &= 0xF7;
	} else {
		priv->regs[37] |= 0x08;  // R848:R45[3]
	}
	ret |= r848_wr(priv, 0x2d, priv->regs[37]);


	if (priv->bw > 67400) {
		fine_tune=1;
		Coarse = ((priv->bw - 67400) / 1600) + 31;
		if (((priv->bw - 67400) % 1600) > 0)
			Coarse += 1;
	} else if ((priv->bw > 62360) && (priv->bw <= 67400)) {
		Coarse=31;
		fine_tune=1;
	} else if ((priv->bw > 38000) && (priv->bw <= 62360)) {
		fine_tune=1;
		Coarse = ((priv->bw - 38000) / 1740) + 16;
		if (((priv->bw - 38000) % 1740) > 0)
			Coarse+=1;
	} else if (priv->bw <= 5000) {
		Coarse = 0;
		fine_tune = 0;
	} else if ((priv->bw > 5000) && (priv->bw <= 8000)) {
		Coarse = 0;
		fine_tune = 1;
	} else if ((priv->bw > 8000) && (priv->bw <= 10000)) {
		Coarse = 1;
		fine_tune = 1;
	} else if ((priv->bw > 10000) && (priv->bw <= 12000)) {
		Coarse=2;
		fine_tune=1;
	} else if((priv->bw>12000) && (priv->bw<=14200)) {
		Coarse=3;
		fine_tune=1;
	} else if((priv->bw>14200) && (priv->bw<=16000)) {
		Coarse=4;
		fine_tune=1;
	} else if((priv->bw>16000) && (priv->bw<=17800)) {
		Coarse=5;
		fine_tune=0;
	} else if((priv->bw>17800) && (priv->bw<=18600)) {
		Coarse=5;
		fine_tune=1;
	} else if((priv->bw>18600) && (priv->bw<=20200)) {
		Coarse=6;
		fine_tune=1;
	} else if((priv->bw>20200) && (priv->bw<=22400)) {
		Coarse=7;
		fine_tune=1;
	} else if((priv->bw>22400) && (priv->bw<=24600)) {
		Coarse=9;
		fine_tune=1;
	} else if((priv->bw>24600) && (priv->bw<=25400)) {
		Coarse=10;
		fine_tune=0;
	} else if((priv->bw>25400) && (priv->bw<=26000)) {
		Coarse=10;
		fine_tune=1;
	} else if((priv->bw>26000) && (priv->bw<=27200)) {
		Coarse=11;
		fine_tune=0;
	} else if((priv->bw>27200) && (priv->bw<=27800)) {
		Coarse=11;
		fine_tune=1;
	} else if((priv->bw>27800) && (priv->bw<=30200)) {
		Coarse=12;
		fine_tune=1;
	} else if((priv->bw>30200) && (priv->bw<=32600)) {
		Coarse=13;
		fine_tune=1;
	} else if((priv->bw>32600) && (priv->bw<=33800)) {
		Coarse=14;
		fine_tune=1;
	} else if((priv->bw>33800) && (priv->bw<=36800)) {
		Coarse=15;
		fine_tune=1;
	} else if((priv->bw>36800) && (priv->bw<=38000)) {
		Coarse=16;
		fine_tune=1;
	}

	Coarse_tune = (unsigned char) Coarse;

	priv->regs[39] &= 0x00;		//47-8=39
	priv->regs[39] = ((priv->regs[39] | ( fine_tune<< 6 ) ) | ( Coarse_tune));
	ret |= r848_wr(priv, 0x2f, priv->regs[39]);

	// Set GPO Low
	// R848:R23[4:2]
	priv->regs[15] = (priv->regs[15] & 0xFE);
	ret |= r848_wr(priv, 0x17, priv->regs[15]);

	return ret;
}




R848_Sys_Info_Type R848_Sys_Sel( struct r848_priv *priv,R848_Standard_Type R848_Standard)
{
	R848_Sys_Info_Type R848_Sys_Info;

	switch (R848_Standard)
	{
	case R848_DVB_T_6M: 
	case R848_DVB_T2_6M: 
		R848_Sys_Info.IF_KHz=4570;					  //IF
		R848_Sys_Info.BW=0x40;							//BW=7M    R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=7450; 		 //CAL IF
		R848_Sys_Info.HPF_COR=0x05; 			 //R19[3:0]=5
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x03;	 //R38[1:0]=11, buf 8
		break;



	case R848_DVB_T_7M:  
	case R848_DVB_T2_7M:  
		R848_Sys_Info.IF_KHz=4570;					   //IF
		R848_Sys_Info.BW=0x40;							 //BW=7M	 R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=7750; 		  //CAL IF
		R848_Sys_Info.HPF_COR=0x08; 			 //R19[3:0]=8  (1.45M)
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x03;	 //R38[1:0]=11, buf 8
		break;

	case R848_DVB_T_8M: 
	case R848_DVB_T2_8M: 
		R848_Sys_Info.IF_KHz=4570;					   //IF
		R848_Sys_Info.BW=0x00;							 //BW=8M	R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=8130; 		  //CAL IF
		R848_Sys_Info.HPF_COR=0x09; 			 //R19[3:0]=9
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x03;	 //R38[1:0]=11, buf 8
		break;

	case R848_DVB_T2_1_7M: 
		R848_Sys_Info.IF_KHz=1900;
		R848_Sys_Info.BW=0x40;							 //BW=7M	R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=7800; 		  //CAL IF
		R848_Sys_Info.HPF_COR=0x08; 			 //R19[3:0]=8
		R848_Sys_Info.FILT_EXT_ENA=0x00;	  //R19[4]=0, ext disable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	case R848_DVB_T2_10M: 
		R848_Sys_Info.IF_KHz=5600;
		R848_Sys_Info.BW=0x00;							 //BW=8M	R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=10800;		 //CAL IF
		R848_Sys_Info.HPF_COR=0x0C; 			 //R19[3:0]=12
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	case R848_DVB_C_8M:  
		R848_Sys_Info.IF_KHz=5070;
		R848_Sys_Info.BW=0x00;							 //BW=8M   R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=9000; 		  //CAL IF //9150
		R848_Sys_Info.HPF_COR=0x0A; 			 //R19[3:0]=10
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x02;	 //R38[1:0]=10, lna=max-1 & Buf 4
		break;

	case R848_DVB_C_6M:  
		R848_Sys_Info.IF_KHz=5070;
		R848_Sys_Info.BW=0x40;							//BW=7M   R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=8025; 		 //CAL IF	
		R848_Sys_Info.HPF_COR=0x03; 			 //R19[3:0]=3 //3
		R848_Sys_Info.FILT_EXT_ENA=0x00;	  //R19[4]=0, ext disable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	case R848_J83B:  
		R848_Sys_Info.IF_KHz=5070;
		R848_Sys_Info.BW=0x40;							//BW=7M   R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=8025; 		 //CAL IF  
		R848_Sys_Info.HPF_COR=0x03; 			 //R19[3:0]=3 //3
		R848_Sys_Info.FILT_EXT_ENA=0x00;	  //R19[4]=0, ext disable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	case R848_ISDB_T: 
		R848_Sys_Info.IF_KHz=4063;
		R848_Sys_Info.BW=0x40;							//BW=7M 	R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=7000; 		 //CAL IF  //7200
		R848_Sys_Info.HPF_COR=0x08; 			 //R19[3:0]=8
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x03;	 //R38[1:0]=11, buf 8
		break;
	case R848_ISDB_T_4570:
		R848_Sys_Info.IF_KHz=4570;					  //IF
		R848_Sys_Info.BW=0x40;							//BW=7M
		R848_Sys_Info.FILT_CAL_IF=7250; 		 //CAL IF
		R848_Sys_Info.HPF_COR=0x05; 			 //R19[3:0]=5 (2.0M)
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x03;	 //R38[1:0]=11, buf 8, hpf+3
		break;

	case R848_DTMB_4570: 
		R848_Sys_Info.IF_KHz=4570;
		R848_Sys_Info.BW=0x00;							 //BW=8M   R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=8330; 		  //CAL IF	//8130
		R848_Sys_Info.HPF_COR=0x0B; 			 //R19[3:0]=11
		R848_Sys_Info.FILT_EXT_ENA=0x00;	  //R19[4]=0, ext disable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	case R848_DTMB_6000: 
		R848_Sys_Info.IF_KHz=6000;
		R848_Sys_Info.BW=0x00;							 //BW=8M	 R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=9550; 		  //CAL IF
		R848_Sys_Info.HPF_COR=0x03; 			 //R19[3:0]=3
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x02;	 //R38[1:0]=10, lna=max-1 & Buf 4
		break;

	case R848_DTMB_6M_BW_IF_5M:
		R848_Sys_Info.IF_KHz=5000;
		R848_Sys_Info.BW=0x40;							 //BW=7M
		R848_Sys_Info.FILT_CAL_IF=7700; 		  //CAL IF	
		R848_Sys_Info.HPF_COR=0x04; 			 //R19[3:0]=4
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1 & Buf 4, hpf+1
		break;

	case R848_DTMB_6M_BW_IF_4500:
		R848_Sys_Info.IF_KHz=4500;
		R848_Sys_Info.BW=0x40;							 //BW=7M
		R848_Sys_Info.FILT_CAL_IF=7000; 		  //CAL IF	
		R848_Sys_Info.HPF_COR=0x05; 			 //R19[3:0]=5
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x02;	 //R38[1:0]=10, lna=max-1 & Buf 4, hpf+3
		break;
	
	case R848_ATSC:  
		R848_Sys_Info.IF_KHz=5070;
		R848_Sys_Info.BW=0x40;							//BW=7M 	 R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=7900; 		 //CAL IF	  20130621 Ryan Modify
		R848_Sys_Info.HPF_COR=0x04; 			 //R19[3:0]=4 
		R848_Sys_Info.FILT_EXT_ENA=0x00;	  //R19[4]=0, ext disable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	case R848_DVB_T_6M_IF_5M: 
	case R848_DVB_T2_6M_IF_5M: 
		R848_Sys_Info.IF_KHz=5000;					  //IF
		R848_Sys_Info.BW=0x40;							//BW=7M 	R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=7800; 		 //CAL IF
		R848_Sys_Info.HPF_COR=0x04; 			 //R19[3:0]=4
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x03;	 //R38[1:0]=11, buf 8
		break;

	case R848_DVB_T_7M_IF_5M:  
	case R848_DVB_T2_7M_IF_5M:	
		R848_Sys_Info.IF_KHz=5000;					   //IF
		R848_Sys_Info.BW=0x00;							 //BW=8M	R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=8300; 		  //CAL IF
		R848_Sys_Info.HPF_COR=0x07; 			 //R19[3:0]=7
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x03;	 //R38[1:0]=11, buf 8
		break;

	case R848_DVB_T_8M_IF_5M: 
	case R848_DVB_T2_8M_IF_5M: 
		R848_Sys_Info.IF_KHz=5000;					   //IF
		R848_Sys_Info.BW=0x00;							 //BW=8M	R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=8500; 		  //CAL IF
		R848_Sys_Info.HPF_COR=0x08; 			 //R19[3:0]=8
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x03;	 //R38[1:0]=11, buf 8
		break;

	case R848_DVB_T2_1_7M_IF_5M: 
		R848_Sys_Info.IF_KHz=5000;
		R848_Sys_Info.BW=0x60;							 //BW=6M	 R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=5900; 		  //CAL IF
		R848_Sys_Info.HPF_COR=0x01; 			 //R19[3:0]=1
		R848_Sys_Info.FILT_EXT_ENA=0x00;	  //R19[4]=0, ext disable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	case R848_DVB_C_8M_IF_5M:  
//	case R848_DVB_C_CHINA_IF_5M:   //RF>115MHz
		R848_Sys_Info.IF_KHz=5000;
		R848_Sys_Info.BW=0x00;							 //BW=8M	 R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=9000; 		  //CAL IF 
		R848_Sys_Info.HPF_COR=0x0A; 			 //R19[3:0]=10
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x02;	 //R38[1:0]=10, lna=max-1 & Buf 4
		break;

	case R848_DVB_C_6M_IF_5M:  
		R848_Sys_Info.IF_KHz=5000;
		R848_Sys_Info.BW=0x40;							//BW=7M 	R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=8100; 		 //CAL IF	
		R848_Sys_Info.HPF_COR=0x04; 			 //R19[3:0]=4 
		R848_Sys_Info.FILT_EXT_ENA=0x00;	  //R19[4]=0, ext disable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	case R848_J83B_IF_5M:  
		R848_Sys_Info.IF_KHz=5000;
		R848_Sys_Info.BW=0x40;							//BW=7M    R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=8025; 		 //CAL IF  
		R848_Sys_Info.HPF_COR=0x03; 			 //R19[3:0]=3 
		R848_Sys_Info.FILT_EXT_ENA=0x00;	  //R19[4]=0, ext disable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	case R848_ISDB_T_IF_5M:
		R848_Sys_Info.IF_KHz=5000;	
		R848_Sys_Info.BW=0x40;							//BW=7M 	 R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=7940; 		 //CAL IF  
		R848_Sys_Info.HPF_COR=0x04; 			 //R19[3:0]=4
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x03;	 //R38[1:0]=11, buf 8
		break;

	case R848_DTMB_IF_5M: 
		R848_Sys_Info.IF_KHz=5000;
		R848_Sys_Info.BW=0x00;							 //BW=8M	  R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=8650; 		  //CAL IF	
		R848_Sys_Info.HPF_COR=0x09; 			 //R19[3:0]=9
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x02;	 //R38[1:0]=0, lna=max-1
		break;
	
	case R848_ATSC_IF_5M:  
		R848_Sys_Info.IF_KHz=5000;
		R848_Sys_Info.BW=0x40;							//BW=7M 	 R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=7900; 		 //CAL IF	
		R848_Sys_Info.HPF_COR=0x04; 			 //R19[3:0]=4 
		R848_Sys_Info.FILT_EXT_ENA=0x00;	  //R19[4]=0, ext disable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	case R848_FM:  
		R848_Sys_Info.IF_KHz=2400;
		R848_Sys_Info.BW=0x40;							 //BW=7M	R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=7200; 		  //CAL IF
		R848_Sys_Info.HPF_COR=0x02; 			 //R19[3:0]=2
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	default:  //R848_DVB_T_8M
		R848_Sys_Info.IF_KHz=4570;					   //IF
		R848_Sys_Info.BW=0x00;							 //BW=8M	R848:R19[6:5]
		R848_Sys_Info.FILT_CAL_IF=8330; 		  //CAL IF
		R848_Sys_Info.HPF_COR=0x0B; 			 //R19[3:0]=11
		R848_Sys_Info.FILT_EXT_ENA=0x10;	  //R19[4]=1, ext enable
		R848_Sys_Info.FILT_EXT_WIDEST=0x00;//R38[2]=0, ext normal
		R848_Sys_Info.FILT_EXT_POINT=0x00;	 //R38[1:0]=0, lna=max-1
		break;

	}

	//R848_Sys_Info.INDUC_BIAS = 0x01;	   //normal 	 
	//R848_Sys_Info.SWCAP_CLK = 0x01;	  //32k 	  
	R848_Sys_Info.SWCAP_CLK = 0x02; 	 //8k		 //AGC 500Hz map to 8k	R26[1:0]
	R848_Sys_Info.NA_PWR_DET = 0x00;   //on 								R38[7]
		
	R848_Sys_Info.TF_CUR = 0x40;				  //low  R11[6]=1
	R848_Sys_Info.SWBUF_CUR = 0x04; 		 //low	R12[2]=1



/*	switch(R848_Standard)
	{
		case R848_DVB_T2_6M: 
		case R848_DVB_T2_7M:
		case R848_DVB_T2_8M:
		case R848_DVB_T2_1_7M: 
		case R848_DVB_T2_10M: 
		case R848_DVB_T2_6M_IF_5M:
		case R848_DVB_T2_7M_IF_5M:
		case R848_DVB_T2_8M_IF_5M:
		case R848_DVB_T2_1_7M_IF_5M: 
			R848_Sys_Info.AGC_CLK = 0x1C;			   //250Hz	 R26[4:2] 
		break;
		default: 
			R848_Sys_Info.AGC_CLK = 0x00;			   //1k   R26[4:2] 
		break;
	}*/

	//Filter 3dB
	switch(R848_Standard)
	{
		case R848_DVB_C_8M_IF_5M:
			R848_Sys_Info.FILT_3DB = 0x08;		   // ON	  R38[3]
		break;
		default: 
			R848_Sys_Info.FILT_3DB = 0x00;		   // OFF	  R38[3]
		break;
	}

	R848_Sys_Info.FILT_COMP = 0x20; 
	R848_Sys_Info.FILT_CUR = 0x00;		 //highest R18[6:5]


	//BW 1.7M
	if((R848_Standard==R848_DVB_T2_1_7M) || (R848_Standard==R848_FM))
		R848_Sys_Info.V17M = 0x80;		 //enable,	R19[7]
	else
		R848_Sys_Info.V17M = 0x00;		 //disable, (include DVBT2 1.7M IF=5MHz) R19[7]

	//TF Type select
	switch(R848_Standard)
	{
		case R848_DTMB_4570:
		case R848_DTMB_6000:
		case R848_DTMB_6M_BW_IF_5M:
		case R848_DTMB_6M_BW_IF_4500:
		case R848_DTMB_IF_5M:
				if(priv->cfg->R848_DetectTfType == R848_UL_USING_BEAD )
				{
					priv->cfg->R848_SetTfType = R848_TF_82N_BEAD;	 
				}
				else
				{
					priv->cfg->R848_SetTfType = R848_TF_82N_270N;	 
				}
			 break; 

		default:		
				if(priv->cfg->R848_DetectTfType == R848_UL_USING_BEAD)
				{
					priv->cfg->R848_SetTfType = R848_TF_82N_BEAD;	 
				}
				else
				{
					priv->cfg->R848_SetTfType = R848_TF_82N_270N;	 
				}	
			break;
	}

	return R848_Sys_Info;
}



R848_SysFreq_Info_Type R848_SysFreq_Sel(struct r848_priv *priv, R848_Standard_Type R848_Standard, u32 RF_freq)
{
	R848_SysFreq_Info_Type R848_SysFreq_Info;

	switch (R848_Standard) {
	case R848_DVB_T_6M:
	case R848_DVB_T_7M:
	case R848_DVB_T_8M:
	case R848_DVB_T_6M_IF_5M:
	case R848_DVB_T_7M_IF_5M:
	case R848_DVB_T_8M_IF_5M:
	case R848_DVB_T2_6M:
	case R848_DVB_T2_7M:
	case R848_DVB_T2_8M:
	case R848_DVB_T2_1_7M:
	case R848_DVB_T2_10M:
	case R848_DVB_T2_6M_IF_5M:
	case R848_DVB_T2_7M_IF_5M:
	case R848_DVB_T2_8M_IF_5M:
	case R848_DVB_T2_1_7M_IF_5M:
		if((RF_freq>=300000)&&(RF_freq<=472000)) {
			R848_SysFreq_Info.LNA_VTH_L=0xA4;	   // LNA VTH/L=1.34/0.74     (R31=0xA4)
			R848_SysFreq_Info.MIXER_TOP=0x05;	       // MIXER TOP=10        (R36[3:0]=4'b0101)
			R848_SysFreq_Info.MIXER_VTH_L=0x95;   // MIXER VTH/L=1.24/0.84  (R32=0x95)
			R848_SysFreq_Info.NRB_TOP=0xC0;            // Nrb TOP=3                       (R36[7:4]=4'b1100)
		} else if((RF_freq>=184000) && (RF_freq<=299000)) {
			R848_SysFreq_Info.LNA_VTH_L=0xA5;	   // LNA VTH/L=1.34/0.84     (R31=0xA5)
			R848_SysFreq_Info.MIXER_TOP=0x04;	       // MIXER TOP=11        (R36[3:0]=4'b0101)
			R848_SysFreq_Info.MIXER_VTH_L=0xA6;   // MIXER VTH/L=1.34/0.94  (R32=0xA6)
			R848_SysFreq_Info.NRB_TOP=0x70;            // Nrb TOP=8                       (R36[7:4]=4'b1100)
		} else {
			R848_SysFreq_Info.LNA_VTH_L=0xA5;	   // LNA VTH/L=1.34/0.84     (R31=0xA5)
			R848_SysFreq_Info.MIXER_TOP=0x05;	       // MIXER TOP=10        (R36[3:0]=4'b0101)
			R848_SysFreq_Info.MIXER_VTH_L=0x95;   // MIXER VTH/L=1.24/0.84  (R32=0x95)
			R848_SysFreq_Info.NRB_TOP=0xC0;            // Nrb TOP=3                       (R36[7:4]=4'b1100)
		}
		R848_SysFreq_Info.LNA_TOP=0x03;		       // LNA TOP=4           (R35[2:0]=3'b011)
		R848_SysFreq_Info.RF_TOP=0x40;               // RF TOP=5                        (R34[7:5]=3'b010)
		R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
		break;

	case R848_DVB_C_8M:
	case R848_DVB_C_6M:
	case R848_J83B:
	case R848_DVB_C_8M_IF_5M:
	case R848_DVB_C_6M_IF_5M:
	case R848_J83B_IF_5M:
		if(RF_freq<165000) {
			R848_SysFreq_Info.LNA_TOP=0x02;		       // LNA TOP=5                    (R35[2:0]=3'b010)
			R848_SysFreq_Info.LNA_VTH_L=0x94;	   // LNA VTH/L=1.24/0.74     (R31=0x94)
			R848_SysFreq_Info.RF_TOP=0x80;               // RF TOP=3                        (R34[7:5]=3'b100)
			R848_SysFreq_Info.NRB_TOP=0x90;            // Nrb TOP=6                       (R36[7:4]=4'b1001)   //R848:R36[7:4]
		} else if((RF_freq>=165000) && (RF_freq<=299000)) {
			R848_SysFreq_Info.LNA_TOP=0x03;		       // LNA TOP=4                    (R35[2:0]=3'b011)
			R848_SysFreq_Info.LNA_VTH_L=0x94;	   // LNA VTH/L=1.24/0.74     (R31=0x94)
			R848_SysFreq_Info.RF_TOP=0x80;               // RF TOP=3                        (R34[7:5]=3'b100)
			R848_SysFreq_Info.NRB_TOP=0x90;            // Nrb TOP=6                       (R36[7:4]=4'b1001)
		} else if((RF_freq>299000) && (RF_freq<=345000)) {
			R848_SysFreq_Info.LNA_TOP=0x03;		        // LNA TOP=4                    (R35[2:0]=3'b011)
			R848_SysFreq_Info.LNA_VTH_L=0xA4;			// LNA VTH/L=1.34/0.74     (R31=0xA4)
			R848_SysFreq_Info.RF_TOP=0x80;              // RF TOP=3                        (R34[7:5]=3'b100)
			R848_SysFreq_Info.NRB_TOP=0x90;             // Nrb TOP=6                       (R36[7:4]=4'b1001)
		} else if((RF_freq>345000) && (RF_freq<=472000)) {
			R848_SysFreq_Info.LNA_TOP=0x04;		        // LNA TOP=3                    (R35[2:0]=3'b100)
			R848_SysFreq_Info.LNA_VTH_L=0x93;		    // LNA VTH/L=1.24/0.64     (R31=0x93)
			R848_SysFreq_Info.RF_TOP=0xA0;				// RF TOP=2                        (R34[7:5]=3'b101)
			R848_SysFreq_Info.NRB_TOP=0x20;             // Nrb TOP=13                       (R36[7:4]=4'b0010)
		} else {
			R848_SysFreq_Info.LNA_TOP=0x04;		        // LNA TOP=3                    (R35[2:0]=3'b100)
			R848_SysFreq_Info.LNA_VTH_L=0x83;		    // LNA VTH/L=1.14/0.64     (R31=0x83)
			R848_SysFreq_Info.RF_TOP=0xA0;              // RF TOP=2                        (R34[7:5]=3'b101)
			R848_SysFreq_Info.NRB_TOP=0x20;             // Nrb TOP=13                       (R36[7:4]=4'b0010)
		}
		R848_SysFreq_Info.MIXER_TOP=0x05;	        // MIXER TOP=10               (R36[3:0]=4'b0100)
		R848_SysFreq_Info.MIXER_VTH_L=0x95;			// MIXER VTH/L=1.24/0.84  (R32=0x95)
		break;

	case R848_ISDB_T:
	case R848_ISDB_T_4570:
	case R848_ISDB_T_IF_5M:
		if((RF_freq>=300000)&&(RF_freq<=472000)) {
			R848_SysFreq_Info.LNA_VTH_L=0xA4;	   // LNA VTH/L=1.34/0.74     (R31=0xA4)
		} else {
			R848_SysFreq_Info.LNA_VTH_L=0xA5;	   // LNA VTH/L=1.34/0.84     (R31=0xA5)
		}
		R848_SysFreq_Info.LNA_TOP=0x03;		       // LNA TOP=4                    (R35[2:0]=3'b011)
		R848_SysFreq_Info.MIXER_TOP=0x05;	       // MIXER TOP=10               (R36[3:0]=4'b0101)
		R848_SysFreq_Info.MIXER_VTH_L=0x95;   // MIXER VTH/L=1.24/0.84  (R32=0x95)
		R848_SysFreq_Info.RF_TOP=0x60;               // RF TOP=4                        (R34[7:5]=3'b011)
		//R848_SysFreq_Info.NRB_TOP=0x20;            // Nrb TOP=13                       (R36[7:4]=4'b0010)
		R848_SysFreq_Info.NRB_TOP=0xB0;            // Nrb TOP=4                       (R36[7:4]=4'b1011)
		R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
		break;
	case R848_DTMB_4570:
	case R848_DTMB_6000:
	case R848_DTMB_6M_BW_IF_5M:
	case R848_DTMB_6M_BW_IF_4500:
	case R848_DTMB_IF_5M:
		if((RF_freq>=300000)&&(RF_freq<=472000)) {
			R848_SysFreq_Info.LNA_VTH_L=0xA4;	   // LNA VTH/L=1.34/0.74     (R31=0xA4)
		} else {
			R848_SysFreq_Info.LNA_VTH_L=0xA5;	   // LNA VTH/L=1.34/0.84     (R31=0xA5)
		}
		R848_SysFreq_Info.LNA_TOP=0x03;		       // LNA TOP=4                    (R35[2:0]=3'b011)
		R848_SysFreq_Info.MIXER_TOP=0x05;	       // MIXER TOP=10               (R36[3:0]=4'b0100)
		R848_SysFreq_Info.MIXER_VTH_L=0x95;   // MIXER VTH/L=1.24/0.84  (R32=0x95)
		R848_SysFreq_Info.RF_TOP=0x60;               // RF TOP=4                        (R34[7:5]=3'b011)
		R848_SysFreq_Info.NRB_TOP=0xA0;            // Nrb TOP=5                       (R36[7:4]=4'b1010)
		R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
		break;

	case R848_ATSC:
	case R848_ATSC_IF_5M:
		if(priv->cfg->R848_DetectTfType==R848_UL_USING_BEAD) {
			if (RF_freq < 88000) {
				R848_SysFreq_Info.LNA_TOP=0x03;	 	       // LNA TOP=4                    (R35[2:0]=3'b011)
				R848_SysFreq_Info.LNA_VTH_L=0xA5;	       // LNA VTH/L=1.34/0.84     (R31=0xA5)
				R848_SysFreq_Info.RF_TOP=0xC0;               // RF TOP=1                        (R34[7:5]=3'b110)
				R848_SysFreq_Info.NRB_TOP=0x30;             // Nrb TOP=12                    (R36[7:4]=4'b0011)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			} else if((RF_freq>=88000) && (RF_freq<104000)) {
				R848_SysFreq_Info.LNA_TOP=0x02;		       // LNA TOP=5                    (R35[2:0]=3'b010)
				R848_SysFreq_Info.LNA_VTH_L=0xA5;	       // LNA VTH/L=1.34/0.84     (R31=0xA5)		
				R848_SysFreq_Info.RF_TOP=0xA0;               // RF TOP=2                        (R34[7:5]=3'b101)
				R848_SysFreq_Info.NRB_TOP=0x30;             // Nrb TOP=12                    (R36[7:4]=4'b0011)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			} else if((RF_freq>=104000) && (RF_freq<156000)) {
				R848_SysFreq_Info.LNA_TOP=0x01;		       // LNA TOP=6                    (R35[2:0]=3'b001)
				R848_SysFreq_Info.LNA_VTH_L=0xA5;	       // LNA VTH/L=1.34/0.84     (R31=0xA5)		
				R848_SysFreq_Info.RF_TOP=0x60;               // RF TOP=4                        (R34[7:5]=3'b011)
				R848_SysFreq_Info.NRB_TOP=0x30;             // Nrb TOP=12                    (R36[7:4]=4'b0011)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			} else if((RF_freq>=156000) && (RF_freq<464000)) {
				R848_SysFreq_Info.LNA_TOP=0x01;		       // LNA TOP=6                    (R35[2:0]=3'b001)
				R848_SysFreq_Info.LNA_VTH_L=0xA5;	       // LNA VTH/L=1.34/0.84     (R31=0xA5)		
				R848_SysFreq_Info.RF_TOP=0x60;               // RF TOP=4                        (R34[7:5]=3'b011)
				R848_SysFreq_Info.NRB_TOP=0x90;             // Nrb TOP=6                      (R36[7:4]=4'b1001)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			} else if((RF_freq>=464000) && (RF_freq<500000)) {
				R848_SysFreq_Info.LNA_TOP=0x01;		       // LNA TOP=6                    (R35[2:0]=3'b001)
				R848_SysFreq_Info.LNA_VTH_L=0xB6;	       // LNA VTH/L=1.44/0.94     (R31=0xB6)		
				R848_SysFreq_Info.RF_TOP=0x60;               // RF TOP=4                        (R34[7:5]=3'b011)
				R848_SysFreq_Info.NRB_TOP=0x90;             // Nrb TOP=6                      (R36[7:4]=4'b1001)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			} else {
				R848_SysFreq_Info.LNA_TOP=0x01;		       // LNA TOP=6                    (R35[2:0]=3'b001)
				R848_SysFreq_Info.LNA_VTH_L=0x94;	       // LNA VTH/L=1.24/0.74     (R31=0x94)		
				R848_SysFreq_Info.RF_TOP=0x40;               // RF TOP=5                        (R34[7:5]=3'b010)
				R848_SysFreq_Info.NRB_TOP=0x90;             // Nrb TOP=6                      (R36[7:4]=4'b1001)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			}
		} else { //270n
			if(RF_freq<88000) {
				R848_SysFreq_Info.LNA_TOP=0x02;	 	       // LNA TOP=5                    (R35[2:0]=3'b010)
				R848_SysFreq_Info.LNA_VTH_L=0x94;	       // LNA VTH/L=1.24/0.74     (R31=0x94)
				R848_SysFreq_Info.RF_TOP=0x80;               // RF TOP=3                        (R34[7:5]=3'b100)
				R848_SysFreq_Info.NRB_TOP=0xC0;             // Nrb TOP=3                    (R36[7:4]=4'b1100)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			} else if((RF_freq>=88000) && (RF_freq<104000)) {
				R848_SysFreq_Info.LNA_TOP=0x02;		       // LNA TOP=5                    (R35[2:0]=3'b010)
				R848_SysFreq_Info.LNA_VTH_L=0x94;	       // LNA VTH/L=1.24/0.74     (R31=0x94)
				R848_SysFreq_Info.RF_TOP=0x60;               // RF TOP=4                        (R34[7:5]=3'b011)
				R848_SysFreq_Info.NRB_TOP=0x90;             // Nrb TOP=6                      (R36[7:4]=4'b1001)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			} else if((RF_freq>=104000) && (RF_freq<248000)) {
				R848_SysFreq_Info.LNA_TOP=0x01;		       // LNA TOP=6                    (R35[2:0]=3'b001)
				R848_SysFreq_Info.LNA_VTH_L=0x94;	       // LNA VTH/L=1.24/0.74     (R31=0x94)	
				R848_SysFreq_Info.RF_TOP=0x60;               // RF TOP=4                        (R34[7:5]=3'b011)
				R848_SysFreq_Info.NRB_TOP=0x90;             // Nrb TOP=6                      (R36[7:4]=4'b1001)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			} else if((RF_freq>=248000) && (RF_freq<464000)) {
				R848_SysFreq_Info.LNA_TOP=0x01;		       // LNA TOP=6                    (R35[2:0]=3'b001)
				R848_SysFreq_Info.LNA_VTH_L=0xA5;	       // LNA VTH/L=1.34/0.84     (R31=0xA5)		
				R848_SysFreq_Info.RF_TOP=0x60;               // RF TOP=4                        (R34[7:5]=3'b011)
				R848_SysFreq_Info.NRB_TOP=0x90;             // Nrb TOP=6                      (R36[7:4]=4'b1001)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			} else if((RF_freq>=464000) && (RF_freq<500000)) {
				R848_SysFreq_Info.LNA_TOP=0x01;		       // LNA TOP=6                    (R35[2:0]=3'b001)
				R848_SysFreq_Info.LNA_VTH_L=0xB6;	       // LNA VTH/L=1.44/0.94     (R31=0xB6)		
				R848_SysFreq_Info.RF_TOP=0x60;               // RF TOP=4                        (R34[7:5]=3'b011)
				R848_SysFreq_Info.NRB_TOP=0x90;             // Nrb TOP=6                      (R36[7:4]=4'b1001)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			} else {
				R848_SysFreq_Info.LNA_TOP=0x01;		       // LNA TOP=6                    (R35[2:0]=3'b001)
				R848_SysFreq_Info.LNA_VTH_L=0x94;	       // LNA VTH/L=1.24/0.74     (R31=0x94)
				R848_SysFreq_Info.RF_TOP=0x40;               // RF TOP=5                        (R34[7:5]=3'b010)
				R848_SysFreq_Info.NRB_TOP=0x90;             // Nrb TOP=6                      (R36[7:4]=4'b1001)
				R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
			}
		}
		R848_SysFreq_Info.MIXER_TOP=0x04;	       // MIXER TOP=11               (R36[3:0]=4'b0100)
		R848_SysFreq_Info.MIXER_VTH_L=0xB7;   // MIXER VTH/L=1.44/1.04  (R32=0xB7)
		//R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
		break;
	case R848_FM:
		if ((RF_freq>=300000) && (RF_freq<=472000)) {
			R848_SysFreq_Info.LNA_VTH_L=0xA4;	   // LNA VTH/L=1.34/0.74     (R31=0xA4)
		} else {
			R848_SysFreq_Info.LNA_VTH_L=0xA5;	   // LNA VTH/L=1.34/0.84     (R31=0xA5)
		}
		R848_SysFreq_Info.LNA_TOP=0x03;		       // LNA TOP=4                    (R35[2:0]=3'b011)
		R848_SysFreq_Info.MIXER_TOP=0x05;	       // MIXER TOP=10               (R36[3:0]=4'b0100)
		R848_SysFreq_Info.MIXER_VTH_L=0x95;   // MIXER VTH/L=1.24/0.84  (R32=0x95)
		R848_SysFreq_Info.RF_TOP=0x60;               // RF TOP=4                        (R34[7:5]=3'b011)
		R848_SysFreq_Info.NRB_TOP=0x20;            // Nrb TOP=13                       (R36[7:4]=4'b0010)
		R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
		break;
	default: //DVB-T 8M
		if ((RF_freq >= 300000) && (RF_freq <= 472000)) {
			R848_SysFreq_Info.LNA_VTH_L=0xA4;	   // LNA VTH/L=1.34/0.74     (R31=0xA4)
		} else {
			R848_SysFreq_Info.LNA_VTH_L=0xA5;	   // LNA VTH/L=1.34/0.84     (R31=0xA5)
		}
		R848_SysFreq_Info.LNA_TOP=0x03;		       // LNA TOP=4                    (R35[2:0]=3'b011)
		R848_SysFreq_Info.MIXER_TOP=0x05;	       // MIXER TOP=10               (R36[3:0]=4'b0100)
		R848_SysFreq_Info.MIXER_VTH_L=0x95;   // MIXER VTH/L=1.24/0.84  (R32=0x95)
		R848_SysFreq_Info.RF_TOP=0x40;               // RF TOP=5                        (R34[7:5]=3'b010)
		R848_SysFreq_Info.NRB_TOP=0x20;            // Nrb TOP=13                       (R36[7:4]=4'b0010)
		R848_SysFreq_Info.NRB_BW=0xC0;             // Nrb BW=lowest                  (R35[7:6]=2'b11)
		break;
	}

	R848_SysFreq_Info.RF_FAST_DISCHARGE = 0x00;    //0 	 R848:R46[3:1]=3'b000
	R848_SysFreq_Info.RF_SLOW_DISCHARGE = 0x80;    //4   R848:R22[7:5]=2'b100
	R848_SysFreq_Info.RFPD_PLUSE_ENA = 0x10;	   //1   R848:R38[4]=1

	R848_SysFreq_Info.LNA_FAST_DISCHARGE = 0x0A;    //10  R848:R43[4:0]=5'b01010
	R848_SysFreq_Info.LNA_SLOW_DISCHARGE = 0x00;    //0  R848:R22[4:2]=3'b000
	R848_SysFreq_Info.LNAPD_PLUSE_ENA = 0x00 ;	    //0  R848:R17[7]=0

	//AGC Clk Rate
	R848_SysFreq_Info.AGC_CLK = 0x00;              //1k   R26[4:2]  //default

	//TF LPF setting
	switch (R848_Standard) {
		case R848_DTMB_4570:
		case R848_DTMB_6000:
		case R848_DTMB_6M_BW_IF_5M:
		case R848_DTMB_6M_BW_IF_4500:
		case R848_DTMB_IF_5M:
			R848_SysFreq_Info.BYP_LPF = 0x00;      //bypass  R12[6]
			break;
		case R848_DVB_T_6M:
		case R848_DVB_T_7M:
		case R848_DVB_T_8M:
		case R848_DVB_T_6M_IF_5M:
		case R848_DVB_T_7M_IF_5M:
		case R848_DVB_T_8M_IF_5M:
		case R848_DVB_T2_6M:
		case R848_DVB_T2_7M:
		case R848_DVB_T2_8M:
		case R848_DVB_T2_1_7M:
		case R848_DVB_T2_10M:
		case R848_DVB_T2_6M_IF_5M:
		case R848_DVB_T2_7M_IF_5M:
		case R848_DVB_T2_8M_IF_5M:
		case R848_DVB_T2_1_7M_IF_5M:
			if (RF_freq >= 662000 && RF_freq <= 670000) {
				R848_SysFreq_Info.RF_SLOW_DISCHARGE = 0x20;    //1   R848:R22[7:5]=2'b001
				R848_SysFreq_Info.AGC_CLK = 0x18;		 //60Hz   R26[4:2]
			} else {
				R848_SysFreq_Info.RF_SLOW_DISCHARGE = 0x80;    //4   R848:R22[7:5]=2'b100
				R848_SysFreq_Info.AGC_CLK = 0x00;		 //1KHz   R26[4:2]
				switch(R848_Standard) {
					case R848_DVB_T2_6M:
					case R848_DVB_T2_7M:
					case R848_DVB_T2_8M:
					case R848_DVB_T2_1_7M:
					case R848_DVB_T2_10M:
					case R848_DVB_T2_6M_IF_5M:
					case R848_DVB_T2_7M_IF_5M:
					case R848_DVB_T2_8M_IF_5M:
					case R848_DVB_T2_1_7M_IF_5M:
						R848_SysFreq_Info.AGC_CLK = 0x1C;		 //250Hz   R26[4:2]
						break;
				}
			}
			break;
		default:  //other standard
			if(RF_freq<=236000)
				R848_SysFreq_Info.BYP_LPF = 0x40;      //low pass  R12[6]
			else
				R848_SysFreq_Info.BYP_LPF = 0x00;      //bypass  R12[6]
			break;
	}
	return R848_SysFreq_Info;
}











#if 0
R848_ErrCode R848_RfGainMode( struct r848_priv *priv,R848_RF_Gain_TYPE R848_RfGainType)
{
	int ret;
	u8 buf[5];

	u8 MixerGain = 0;
	u8 RfGain = 0;
	u8 LnaGain = 0;

	if(R848_RfGainType==RF_MANUAL) {
		//LNA auto off
		priv->regs[5] = priv->regs[5] | 0x80;   // 848:13[7:0]
		ret = r848_wr(priv, 0x0d, priv->regs[5]);

		//Mixer buffer off
		priv->regs[26] = priv->regs[26] | 0x10;  // 848:34[7:0]
		ret |= r848_wr(priv, 0x22, priv->regs[26]);

		//Mixer auto off
		priv->regs[7] = priv->regs[7] & 0xEF;  //848:15[6:0]
		ret |= r848_wr(priv, 0x0f, priv->regs[7]);

		ret = r848_rd(priv, buf, 5);
		if (ret)
			return ret;

		//MixerGain = (((buf[1] & 0x40) >> 6)<<3)+((buf[3] & 0xE0)>>5);   //?
		MixerGain = (buf[3] & 0x0F); //mixer // 848:3[4:0]
		RfGain = ((buf[3] & 0xF0) >> 4);   //rf		 // 848:3[4:0]
		LnaGain = buf[4] & 0x1F;  //lna    // 848:4[4:0] 

		//set LNA gain
		priv->regs[5] = (priv->regs[5] & 0xE0) | LnaGain;  // 848:13[7:0]
		ret |= r848_wr(priv, 0x0d, priv->regs[5]);

		//set Mixer Buffer gain
		priv->regs[26] = (priv->regs[26] & 0xF0) | RfGain;  //848:34[7:0]
		ret |= r848_wr(priv, 0x22, priv->regs[26]);

		//set Mixer gain
		priv->regs[7] = (priv->regs[7] & 0xF0) | MixerGain; // 848:15[6:0]
		ret |= r848_wr(priv, 0x0f, priv->regs[7]);
	} else {
		//LNA auto on
		priv->regs[5] = priv->regs[5] & 0x7F;  // 848:13[7:0]
		ret = r848_wr(priv, 0x0d, priv->regs[5]);

		//Mixer buffer on
		priv->regs[26] = priv->regs[26] & 0xEF;	// 848:34[7:0]
		ret |= r848_wr(priv, 0x22, priv->regs[26]);

		//Mixer auto on
		priv->regs[7] = priv->regs[7] | 0x10;	// 848:15[6:0]
		ret |= r848_wr(priv, 0x0f, priv->regs[7]);
	}

	return ret;
}
#endif


static int R848_TF_Check(struct r848_priv *priv)
{
	u32 RingVCO, RingFreq;
	u8 divnum_ring;
	u8 VGA_Count;
	u8 VGA_Read;
	int ret;

	if (R848_Xtal == 16000) {
		divnum_ring = 11;
	} else { //24M
		divnum_ring = 2;
	}

	RingVCO = (16 + divnum_ring) * 8 * R848_Xtal;
	RingFreq = RingVCO / 48;

	if (R848_Cal_Prepare(priv, R848_TF_LNA_CAL))
	      return RT_Fail;

	priv->regs[31] = (priv->regs[31] & 0x03) | 0x80 | (divnum_ring<<2);  //pre div=6 & div_num
	ret = r848_wr(priv, 0x27, priv->regs[31]);

	// Ring PLL PW on
	priv->regs[18] = (priv->regs[18] & 0xEF);
	ret |= r848_wr(priv, 0x12, priv->regs[18]);

	// NAT Det Sour : Mixer buf out
	priv->regs[37] = (priv->regs[37] & 0x7F);
	ret |= r848_wr(priv, 0x25, priv->regs[37]);

	// R848 R33[7:0]
	priv->regs[25] = (priv->regs[25] & 0x00) | 0x8B;  //out div=8, RF poly=low band, power=min_lp
	if(RingVCO>=3200000)
		priv->regs[25] = (priv->regs[25] & 0xDF);      //vco_band=high, R25[5]=0
	else
		priv->regs[25] = (priv->regs[25] | 0x20);      //vco_band=low, R25[5]=1
	ret |= r848_wr(priv, 0x21, priv->regs[25]);
	if (ret)
		return ret;

	// Must do before PLL()
	if (r848_set_mux(priv, RingFreq + 5000, RingFreq, R848_STD_SIZE))     //FilCal MUX (LO_Freq, RF_Freq)
		return RT_Fail;

	// Set PLL
	if (r848_set_pll(priv, (RingFreq + 5000), R848_STD_SIZE))   //FilCal PLL
		return RT_Fail;

	// Set LNA TF=(1,15),for VGA training   // R848 R8[6:0]
	priv->regs[0] = (priv->regs[0] & 0x80) | 0x1F;
	ret = r848_wr(priv, 0x08, priv->regs[0]);

	// Qctrl=off  // R848 R14[5]
	priv->regs[6] = (priv->regs[6] & 0xDF);
	ret |= r848_wr(priv, 0x0e, priv->regs[6]);

	// FilterComp OFF  // R848 R14[2]
	priv->regs[6] = (priv->regs[6] & 0xFB);
	ret |= r848_wr(priv, 0x0e, priv->regs[6]);

	// Byp-LPF: Bypass  R848 R12[6]  12-8=4  12(0x0C) is addr ; [4] is data
	priv->regs[4] = priv->regs[4] & 0xBF;
	ret |= r848_wr(priv, 0x0c, priv->regs[4]);

	//Adc=on; Vga code mode, Gain = -12dB
	//R848 R20[3:0]         set 0
	//R848 R9[1]            set 1
	//R848 R11[3]           set 0
	//R848 R18[7]           set 0
	//R848 R15[7]           set 0

	// VGA Gain = -12dB
	priv->regs[12] = (priv->regs[12] & 0xF0);
	ret |= r848_wr(priv, 0x14, priv->regs[12]);

	// Vga code mode
	priv->regs[1] = (priv->regs[1] | 0x02);
	ret |= r848_wr(priv, 0x09, priv->regs[1]);

	// VGA 6dB
	priv->regs[3] = (priv->regs[3] & 0xF7);
	ret |= r848_wr(priv, 0x0b, priv->regs[3]);

	// VGA PW ON
	priv->regs[10] = (priv->regs[10] & 0x7F);
	ret |= r848_wr(priv, 0x12, priv->regs[10]);

	 // Adc on
	priv->regs[7] = (priv->regs[7] & 0x7F);
	ret |= r848_wr(priv, 0x0f, priv->regs[7]);
	if (ret)
		return ret;


	// increase VGA power to let ADC read value significant
	for (VGA_Count = 0; VGA_Count < 16; VGA_Count++) {
		ret = r848_wr(priv, 0x14, (priv->regs[12] & 0xf0) + VGA_Count);
		if (ret)
			return ret;
		msleep(10);

		if (r848_get_imr(priv,&VGA_Read))
			return RT_Fail;

		if (VGA_Read > 40)
			break;
	}

	// Set LNA TF=(0,0)
	priv->regs[0] = (priv->regs[0] & 0x80);
	ret = r848_wr(priv, 0x08, priv->regs[0]);
	if (ret)
		return ret;

	msleep(10);

	if (r848_get_imr(priv, &VGA_Read))
		return RT_Fail;

	if (VGA_Read > 36)
		priv->cfg->R848_DetectTfType = R848_UL_USING_BEAD;
	else
		priv->cfg->R848_DetectTfType = R848_UL_USING_270NH;

	return 0;
}










static int r848_set_standard(struct r848_priv *priv, u8 standard)
{
	struct filter_cal *fc = &priv->fc[standard];
	int ret;
	// Filter Calibration
	u8 u1FilCalGap = 8;


	if (standard != priv->standard) {
		 ret = r848_init_regs(priv, standard);
		 if (ret)
			 return ret;
	}
	priv->Sys_Info1 = R848_Sys_Sel(priv, standard);

	// Filter Calibration
	if (!fc->flag) {
		fc->code = R848_Filt_Cal_ADC(priv, priv->Sys_Info1.FILT_CAL_IF, priv->Sys_Info1.BW, u1FilCalGap);
		fc->bw = 0;// R848_Bandwidth;
		fc->flag = 1;
		//Reset register and Array
		ret = r848_init_regs(priv, standard);
		if (ret)
			return ret;
	}

	// Set Filter Auto Ext
	// R19[4]  
	priv->regs[11] = (priv->regs[11] & 0xEF) | priv->Sys_Info1.FILT_EXT_ENA;  
	ret = r848_wr(priv, 0x13, priv->regs[11]);

	if (priv->Sys_Info1.FILT_EXT_ENA == 0x10) { //(%)
		if (fc->code< 2)
			fc->code = 2;

		if ((priv->Sys_Info1.FILT_EXT_POINT & 0x02) == 0x02) {  //HPF+3
			if(priv->Sys_Info1.HPF_COR > 12)
				priv->Sys_Info1.HPF_COR = 12;
		} else {  //HPF+1
			if(priv->Sys_Info1.HPF_COR > 14)
				priv->Sys_Info1.HPF_COR = 15;
		}
	}

	// Set LPF fine code
	// R848:R18[3:0]  
	priv->regs[10] = (priv->regs[10] & 0xF0) | fc->code;  
	ret |= r848_wr(priv, 0x12, priv->regs[10]);

	// Set LPF coarse BW
	// R848:R19[6:5]  
	priv->regs[11] = (priv->regs[11] & 0x9F) | fc->bw;
	//ret |= r848_wr(priv, 0x13, priv->regs[11]);

	// Set HPF corner & 1.7M mode
	// R848:R19[7 & 3:0]  
	priv->regs[11] = (priv->regs[11] & 0x70) | priv->Sys_Info1.HPF_COR | priv->Sys_Info1.V17M;
	ret |= r848_wr(priv, 0x13, priv->regs[11]);

	// Set TF current 
	// R848:R11[6]  
	priv->regs[3] = (priv->regs[3] & 0xBF) | priv->Sys_Info1.TF_CUR;  
	ret |= r848_wr(priv, 0x0b, priv->regs[3]);

	// Set Filter current 
	// R848:R18[6:5]  
	priv->regs[10] = (priv->regs[10] & 0x9F) | priv->Sys_Info1.FILT_CUR;  
	//R848_Array[10] = (R848_Array[10] & 0x9F) | 0x60;   //lowest
	ret |= r848_wr(priv, 0x12, priv->regs[10]);

	// Set Switch Buffer current 
	// R848:R12[2] 
	priv->regs[4] = (priv->regs[4] & 0xFB) | priv->Sys_Info1.SWBUF_CUR;   
	ret |= r848_wr(priv, 0x0c, priv->regs[4]);

	// Set Filter Comp 
	// R848:R38[6:5]  
	priv->regs[30] = (priv->regs[30] & 0x9F) | priv->Sys_Info1.FILT_COMP;  
	//ret |= r848_wr(priv, 0x26, priv->regs[30]);
	// Set Filter 3dB
	// R848:R38[7]  
	priv->regs[30] = (priv->regs[30] & 0xF7) | priv->Sys_Info1.FILT_3DB;  
	// Set Filter Ext Condition (%)
	// R848:R38[2:0] 
	priv->regs[30] = (priv->regs[30] & 0xF8) | 0x04 | priv->Sys_Info1.FILT_EXT_POINT;   //ext both HPF/LPF
	ret |= r848_wr(priv, 0x26, priv->regs[30]);
/*
	// Set Inductor Bias
	R848_I2C.RegAddr = 0x04;
	R848_Array[4] = (R848_Array[4] & 0xFE) | Sys_Info1.INDUC_BIAS; 
	R848_I2C.Data = R848_Array[4];
	if(I2C_Write(&R848_I2C) != RT_Success)
		return RT_Fail;
*/
	// Set sw cap clk
	// R848:R26[1:0]  
	priv->regs[18] = (priv->regs[18] & 0xFC) | priv->Sys_Info1.SWCAP_CLK; 
	ret |= r848_wr(priv, 0x1a, priv->regs[18]);

	// Set NA det power
	// 848:R38[7] 
	priv->regs[30] = (priv->regs[30] & 0x7F) | priv->Sys_Info1.NA_PWR_DET; 
	ret |= r848_wr(priv, 0x26, priv->regs[30]);

/*
	// Set AGC clk 
	R848_I2C.RegAddr = 0x1A;	//  R848:R26[4:2] 
	R848_Array[18] = (R848_Array[18] & 0xE3) | Sys_Info1.AGC_CLK;  
	R848_I2C.Data = R848_Array[18];
	if(I2C_Write(&R848_I2C) != RT_Success)
		return RT_Fail;
*/

	// Set GPO High
	// R848:R23[4:2]  
	priv->regs[15] = (priv->regs[15] & 0xFE) | 0x01;
	ret |= r848_wr(priv, 0x17, priv->regs[15]);

	priv->standard = standard;

	return ret;
}



/* freq in kHz */
static int r848_set_frequency(struct r848_priv *priv)
{
	u32 LO_KHz;
	R848_SysFreq_Info_Type SysFreq_Info1;
	int ret;

	// Check Input Frequency Range
	if (priv->freq < 40000)
		return -EINVAL;

	if (priv->standard != R848_DVB_S) {
		if (priv->freq > 1002000)
			return -EINVAL;
	} else {
		if (priv->freq > 2400000)
			return -EINVAL;
	}

	LO_KHz = priv->freq + priv->Sys_Info1.IF_KHz;

	// Set MUX dependent var. Must do before PLL( )
	if (r848_set_mux(priv, LO_KHz, priv->freq, priv->standard))   //normal MUX
		return RT_Fail;

	// Set PLL
	if (r848_set_pll(priv, LO_KHz, priv->standard))
		return RT_Fail;

	//Set TF
	if (R848_SetTF(priv, priv->freq, priv->cfg->R848_SetTfType))
		return RT_Fail;

	//R848_IMR_point_num = Freq_Info1.IMR_MEM;

	//Q1.5K   Q_ctrl  R848:R14[4]
	//if(R848_INFO.RF_KHz<R848_LNA_MID_LOW[R848_TF_NARROW]) //<300MHz
	//	R848_Array[6] = R848_Array[6] | 0x10;
	//else
	//	R848_Array[6] = R848_Array[6] & 0xEF;

	if (priv->freq <= 472000) //<472MHz
		priv->regs[6] = priv->regs[6] | 0x10;
	else
		priv->regs[6] = priv->regs[6] & 0xEF;

	// medQctrl 1.5K
	if ((priv->freq >= 300000) && (priv->freq <= 472000)) //<473MHz and >299MHz
		priv->regs[6] = priv->regs[6] | 0x01;
	else
	 	priv->regs[6] = priv->regs[6] & 0xFE;
	ret = r848_wr(priv, 0x0e, priv->regs[6]); // R848:R14[1]

	// 3~6 shrink
	if ((priv->freq >= 300000) && (priv->freq <= 550000)) //<551MHz and >299MHz
		priv->regs[3] = priv->regs[3] & 0xFB;
	else
		priv->regs[3] = priv->regs[3] | 0x04;
	ret |= r848_wr(priv, 0x0b, priv->regs[3]); // R848:R11[2]

	// set Xtal AAC on=1; off=0
	priv->regs[16] = priv->regs[16] & 0xFD;
	ret |= r848_wr(priv, 0x18, priv->regs[16]); // R848:R24[1]

	// Get Sys-Freq parameter
	SysFreq_Info1 = R848_SysFreq_Sel(priv, priv->standard, priv->freq);

	// Set LNA_TOP
	priv->regs[27] = (priv->regs[27] & 0xF8) | (SysFreq_Info1.LNA_TOP);
	ret |= r848_wr(priv, 0x23, priv->regs[27]); // R848:R35[2:0]

	// Set LNA VTHL
	priv->regs[23] = (priv->regs[23] & 0x00) | SysFreq_Info1.LNA_VTH_L;
	ret |= r848_wr(priv, 0x1f, priv->regs[23]); // R848:R31[7:0]

	// Set MIXER TOP
	priv->regs[28] = (priv->regs[28] & 0xF0) | (SysFreq_Info1.MIXER_TOP);
	ret |= r848_wr(priv, 0x24, priv->regs[28]); // R848:R36[7:0]

	// Set MIXER VTHL
	priv->regs[24] = (priv->regs[24] & 0x00) | SysFreq_Info1.MIXER_VTH_L;
	ret |= r848_wr(priv, 0x20, priv->regs[24]); // R848:R32[7:0]

	// Set RF TOP
	priv->regs[26] = (priv->regs[26] & 0x1F) | SysFreq_Info1.RF_TOP;
	ret |= r848_wr(priv, 0x22, priv->regs[26]); // R848:R34[7:0]

	// Set Nrb TOP
	priv->regs[28] = (priv->regs[28] & 0x0F) | SysFreq_Info1.NRB_TOP;
	ret |= r848_wr(priv, 0x24, priv->regs[28]); // R848:R36[7:0]

	// Set Nrb BW
	priv->regs[27] = (priv->regs[27] & 0x3F) | SysFreq_Info1.NRB_BW;
	ret |= r848_wr(priv, 0x23, priv->regs[27]); // R848:R35[7:6]

	// Set TF LPF
	priv->regs[4] = (priv->regs[4] & 0xBF) | SysFreq_Info1.BYP_LPF;
	ret |= r848_wr(priv, 0x0c, priv->regs[4]); // R848:R12[6]

	priv->regs[38] = (priv->regs[38] & 0xF1) | SysFreq_Info1.RF_FAST_DISCHARGE;
	ret |= r848_wr(priv, 0x2e, priv->regs[38]); // R848:R46[3:1] = 0b000

	priv->regs[14] = (priv->regs[14] & 0x1F) | SysFreq_Info1.RF_SLOW_DISCHARGE;
	ret |= r848_wr(priv, 0x16, priv->regs[14]); // R848:R22[7:5] = 0b010

	priv->regs[30] = (priv->regs[30] & 0xEF) | SysFreq_Info1.RFPD_PLUSE_ENA;
	ret |= r848_wr(priv, 0x26, priv->regs[30]); // R848:R38[4] = 1

	priv->regs[35] = (priv->regs[35] & 0xE0) | SysFreq_Info1.LNA_FAST_DISCHARGE;
	ret |= r848_wr(priv, 0x2b, priv->regs[35]); // R848:R43[4:0] = 0b01010

	priv->regs[14] = (priv->regs[14] & 0xE3) | SysFreq_Info1.LNA_SLOW_DISCHARGE;
	ret |= r848_wr(priv, 0x16, priv->regs[14]); // R848:R22[4:2] = 0b000

	priv->regs[9] = (priv->regs[9] & 0x7F) | SysFreq_Info1.LNAPD_PLUSE_ENA;
	ret |= r848_wr(priv, 0x11, priv->regs[9]); // R848:R17[7] = 0

	// Set AGC clk
	priv->regs[18] = (priv->regs[18] & 0xE3) | SysFreq_Info1.AGC_CLK;
	ret |= r848_wr(priv, 0x1a, priv->regs[18]); // R848:R26[4:2]

	// no clk out
	priv->regs[17] = (priv->regs[17] | 0x80);   // R848:R25[7]
	ret |= r848_wr(priv, 0x19, priv->regs[17]);

	// for DVB-T2
        switch (priv->standard) {
		case R848_DVB_T2_6M:
		case R848_DVB_T2_7M:
		case R848_DVB_T2_8M:
		case R848_DVB_T2_1_7M:
		case R848_DVB_T2_10M:
		case R848_DVB_T2_6M_IF_5M:
		case R848_DVB_T2_7M_IF_5M:
		case R848_DVB_T2_8M_IF_5M:
		case R848_DVB_T2_1_7M_IF_5M:
			msleep(100);
/*
			// AGC clk 250Hz
			priv->regs[18] = (priv->regs[18] & 0xE3) | 0x1C; //[4:2]=111
			ret |= r848_wr(priv, 0x1a, priv->regs[18]); // R848:R26[4:2]
*/
			// force plain mode
			priv->regs[3] = (priv->regs[3] | 0x80);  //[7]=1
			ret |= r848_wr(priv, 0x0b, priv->regs[3]); // R848:R11[7]

			priv->regs[2] = (priv->regs[2] & 0xDF);  //[5]=0
			ret |= r848_wr(priv, 0x0a, priv->regs[2]); // R848:R10[5]
			break;
		default:
			break;
	}

	return ret;
}

static void r848_release(struct dvb_frontend *fe)
{
	struct r848_priv *priv = fe->tuner_priv;
	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	kfree(fe->tuner_priv);
	fe->tuner_priv = NULL;
}

static int r848_init(struct dvb_frontend *fe)
{
	struct r848_priv *priv = fe->tuner_priv;
	int ret;
	u8 i;

	printk("init tuner\n");

	if (priv->inited == 1)
		return 0;


	printk("init tuner first time\n");


	for (i = 0; i < R848_STD_SIZE; i++) {
		priv->fc[i].flag = 0;
		priv->fc[i].code = 0;
		priv->fc[i].bw = 0x00;
	}


	if (r848_init_regs(priv,R848_STD_SIZE) != RT_Success)
		return RT_Fail;

	if(R848_TF_Check(priv) != RT_Success)
		return RT_Fail;

	//start IMR calibration
	if(r848_init_regs(priv,R848_STD_SIZE) != RT_Success)        //write initial reg before doing IMR Cal
		return RT_Fail;

	if(R848_Cal_Prepare(priv,R848_IMR_CAL) != RT_Success)
		return RT_Fail;

	if(R848_IMR(priv,3, 0) != RT_Success)       //Full K node 3
		return RT_Fail;

	if(R848_IMR(priv,0, 1) != RT_Success)
		return RT_Fail;

	if(R848_IMR(priv,1, 1) != RT_Success)
		return RT_Fail;

	if(R848_IMR(priv,2, 1) != RT_Success)
		return RT_Fail;

	if(R848_IMR(priv,4, 0) != RT_Success)   //Full K node 4
		return RT_Fail;

	//do Xtal check
	if(r848_init_regs(priv,R848_STD_SIZE) != RT_Success)
		return RT_Fail;

	priv->cfg->R848_Xtal_Pwr = XTAL_SMALL_LOWEST;
	priv->cfg->R848_Xtal_Pwr_tmp = XTAL_SMALL_LOWEST;

	for (i=0; i<3; i++) {
		if(R848_Xtal_Check(priv) != RT_Success)
			return RT_Fail;

		if(priv->cfg->R848_Xtal_Pwr_tmp > priv->cfg->R848_Xtal_Pwr)
			priv->cfg->R848_Xtal_Pwr = priv->cfg->R848_Xtal_Pwr_tmp;
	}

	//write initial reg
	if(r848_init_regs(priv,R848_STD_SIZE) != RT_Success)
		return RT_Fail;

	priv->standard = R848_STD_SIZE;

	ret = 0;

	if (ret)
		dev_dbg(&priv->i2c->dev, "%s() failed\n", __func__);

	priv->inited = 1;

	printk("init tuner done\n");
	return ret;
}

static int r848_sleep(struct dvb_frontend *fe)
{
	struct r848_priv *priv = fe->tuner_priv;
	int ret = 0;
	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	//if (ret)
	//	dev_dbg(&priv->i2c->dev, "%s() failed\n", __func__);
	return ret;
}

static int r848_set_params(struct dvb_frontend *fe)
{
	struct r848_priv *priv = fe->tuner_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret, i;
	u8 tuner_lock;
	u8 standard;

	dev_info(&priv->i2c->dev, "%s() delivery_system=%d frequency=%d " \
			"symbol_rate=%d bandwidth_hz=%d\n", __func__,
			c->delivery_system, c->frequency, c->symbol_rate,
			c->bandwidth_hz);


	/* failsafe */
	standard = R848_DVB_T2_8M_IF_5M;

	switch (c->delivery_system) {
	case SYS_DVBC_ANNEX_A:
		priv->freq = c->frequency / 1000;
		if(c->bandwidth_hz <= 6000000) {
        		standard = R848_DVB_C_6M_IF_5M;
		} else if (c->bandwidth_hz <= 8000000) {
			standard = R848_DVB_C_8M_IF_5M;
		}

		/* set pll data */
		if(r848_set_standard(priv, standard) != RT_Success) {
			return RT_Fail;
		}
		if(r848_set_frequency(priv))
			return RT_Fail;
		break;
	case SYS_DVBS:
	case SYS_DVBS2:
		priv->freq = c->frequency;
		priv->standard = R848_DVB_S;
		priv->bw = (c->symbol_rate/200*135+2000000)/1000*2;//unit KHz
		priv->output_mode = DIFFERENTIALOUT;
		priv->agc_mode = AGC_NEGATIVE;

		/* set pll data */
		if(R848_DVBS_Setting(priv) != RT_Success)
			return RT_Fail;
		break;
	case SYS_DVBT:
	case SYS_DVBT2:
	default:
		priv->freq = c->frequency / 1000;
		if(c->bandwidth_hz <= 1700000) {
			standard = R848_DVB_T2_1_7M_IF_5M;
		} else if (c->bandwidth_hz <= 6000000) {
			standard = R848_DVB_T2_6M_IF_5M;
		} else if (c->bandwidth_hz <= 7000000) {
			standard = R848_DVB_T2_7M_IF_5M;
		} else {
			standard = R848_DVB_T2_8M_IF_5M;
		}

		if (r848_set_standard(priv, standard))
			return RT_Fail;
		if (r848_set_frequency(priv))
			return RT_Fail;
		break;
	}

	for (i = 0; i < 5; i++) {
		ret = r848_get_lock_status(priv, &tuner_lock);
		if(tuner_lock) {
			printk("Tuner Locked.\n");
			break;
		} else {
			printk("Tuner not Locked!\n");
		}
		msleep(20);
	}

	return ret;
}

static const struct dvb_tuner_ops r848_tuner_ops = {
	.info = {
		.name           = "Rafael R848",
//		.frequency_min_hz  =  250 * MHz,
//		.frequency_max_hz  = 2300 * MHz,
	},

	.release = r848_release,

	.init = r848_init,
	.sleep = r848_sleep,
	.set_params = r848_set_params,
};

struct dvb_frontend *r848_attach(struct dvb_frontend *fe,
		struct r848_config *cfg, struct i2c_adapter *i2c)
{
	struct r848_priv *priv = NULL;

	priv = kzalloc(sizeof(struct r848_priv), GFP_KERNEL);
	if (priv == NULL) {
		dev_dbg(&i2c->dev, "%s() attach failed\n", __func__);
		return NULL;
	}

	priv->cfg = cfg;
	priv->i2c = i2c;
	priv->inited = 0;

	dev_info(&priv->i2c->dev,
		"%s: Rafael R848 successfully attached\n",
		KBUILD_MODNAME);

	memcpy(&fe->ops.tuner_ops, &r848_tuner_ops,
			sizeof(struct dvb_tuner_ops));

	fe->tuner_priv = priv;
	return fe;
}

EXPORT_SYMBOL_GPL(r848_attach);

MODULE_DESCRIPTION("Rafael R848 silicon tuner driver");
MODULE_AUTHOR("Luis Alves <ljalvs@gmail.com>");
MODULE_LICENSE("GPL");
