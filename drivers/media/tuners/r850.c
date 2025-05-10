#include <linux/bitrev.h>
#include "r850.h"
#include "r850_priv.h"

static int r850_rd(struct r850_priv *priv,u8 reg, u8 *buf,u8 len)
{
	int ret,i;

	struct i2c_msg msg[2]={
		{
		 .addr = priv->cfg->i2c_address,
		 .flags = 0, .buf = &reg, .len =  1	
		},{
		.addr = priv->cfg->i2c_address,
		.flags = I2C_M_RD, .buf = buf, .len =  len	
		}
	};
	ret = i2c_transfer(priv->i2c, msg, 2);
	if (ret == 2) {
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
static int r850_wrm(struct r850_priv *priv,u8 reg, u8 *val,u8 len)
{
	int ret;
	u8 buf[len + 1];

	memcpy(&buf[1], val, len);
	buf[0] = reg;
	
	struct i2c_msg msg = {
		.addr = priv->cfg->i2c_address,
		.flags = 0, .buf = buf, .len = len + 1 };


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
static int r850_wr(struct r850_priv *priv,u8 reg, u8 val)
{
	return r850_wrm(priv,reg,&val,1);
}
struct R850_Freq_Info_Type R850_Freq_Sel(u32 LO_freq, u32 RF_freq, enum R850_Standard_Type R850_Standard)
{
	struct R850_Freq_Info_Type R850_Freq_Info;


	//----- LO dependent parameter --------

	//IMR point
	if((LO_freq>0) && (LO_freq<170000))
	{
		R850_Freq_Info.IMR_MEM_NOR = 0;
		R850_Freq_Info.IMR_MEM_REV = 5;
	}
	else if((LO_freq>=170000) && (LO_freq<240000))
	{
		R850_Freq_Info.IMR_MEM_NOR = 4;
		R850_Freq_Info.IMR_MEM_REV = 9;
	}
	else if((LO_freq>=240000) && (LO_freq<400000))
	{
		R850_Freq_Info.IMR_MEM_NOR = 1;
		R850_Freq_Info.IMR_MEM_REV = 6;
	}
	else if((LO_freq>=400000) && (LO_freq<760000))
	{
		R850_Freq_Info.IMR_MEM_NOR = 2;
		R850_Freq_Info.IMR_MEM_REV = 7;
	}
	else
	{
		R850_Freq_Info.IMR_MEM_NOR = 3;
		R850_Freq_Info.IMR_MEM_REV = 8;
	}

	//TF_HPF_BPF R16[2:0]
	/*	7-lowest:111 ; 6:011 ; 5:101 ; 4:001 ; 3:110 ; 2:010 ; 1:100 ; 0-noBPF:000	*/
	if(LO_freq<580000)
		R850_Freq_Info.TF_HPF_BPF = 0x07;		//7 => 111:lowset BPF  R16[2:0]
	else if(LO_freq>=580000 && LO_freq<660000)
		R850_Freq_Info.TF_HPF_BPF = 0x01;		//4 => 001
	else if(LO_freq>=660000 && LO_freq<780000)
		R850_Freq_Info.TF_HPF_BPF = 0x06;		//3 => 110
	else if(LO_freq>=780000 && LO_freq<900000)
		R850_Freq_Info.TF_HPF_BPF = 0x04;		//1 => 100
	else
		R850_Freq_Info.TF_HPF_BPF = 0x00;		//0 => 000

	/*
00: highest band
01: med band
10: low band
11: Ultrawide band
*/
	//RF polyfilter band
	if((LO_freq>0) && (LO_freq<133000))
		R850_Freq_Info.RF_POLY = 2;   //R17[6:5]=2; low	=> R18[1:0]
	else if((LO_freq>=133000) && (LO_freq<221000))
		R850_Freq_Info.RF_POLY = 1;   //R17[6:5]=1; mid	=> R18[1:0]
	else if((LO_freq>=221000) && (LO_freq<760000))
		R850_Freq_Info.RF_POLY = 0;   //R17[6:5]=0; highest    => R18[1:0]
	else
		R850_Freq_Info.RF_POLY = 3;   //R17[6:5]=3; ultra high	=> R18[1:0]


	/*
00: highest
01: high
10: low
11: lowest
*/
	//TF_HPF_Corner
	if((LO_freq>0) && (LO_freq<480000))
		R850_Freq_Info.TF_HPF_CNR = 3;   //lowest	=> R16[4:3]
	else if((LO_freq>=480000) && (LO_freq<550000))
		R850_Freq_Info.TF_HPF_CNR = 2;   // low	=> R16[4:3]
	else if((LO_freq>=550000) && (LO_freq<700000))
		R850_Freq_Info.TF_HPF_CNR = 1;   // high    => R16[4:3]
	else
		R850_Freq_Info.TF_HPF_CNR = 0;   //highest	=> R16[4:3]


	//LPF Cap, Notch
	switch(R850_Standard)
	{
		case R850_DVB_C_8M:                            //Cable
		case R850_DVB_C_6M:
		case R850_J83B:
		case R850_DVB_C_8M_IF_5M:
		case R850_DVB_C_6M_IF_5M:
		case R850_J83B_IF_5M:
			if(LO_freq<77000)
			{
				R850_Freq_Info.LPF_CAP = 15;
				R850_Freq_Info.LPF_NOTCH = 10;
			}
			else if((LO_freq>=77000) && (LO_freq<85000))
			{
				R850_Freq_Info.LPF_CAP = 15;
				R850_Freq_Info.LPF_NOTCH = 4;
			}
			else if((LO_freq>=85000) && (LO_freq<115000))
			{
				R850_Freq_Info.LPF_CAP = 13;
				R850_Freq_Info.LPF_NOTCH = 3;
			}
			else if((LO_freq>=115000) && (LO_freq<125000))
			{
				R850_Freq_Info.LPF_CAP = 11;
				R850_Freq_Info.LPF_NOTCH = 1;
			}
			else if((LO_freq>=125000) && (LO_freq<141000))
			{
				R850_Freq_Info.LPF_CAP = 9;
				R850_Freq_Info.LPF_NOTCH = 0;
			}
			else if((LO_freq>=141000) && (LO_freq<157000))
			{
				R850_Freq_Info.LPF_CAP = 8;
				R850_Freq_Info.LPF_NOTCH = 0;
			}
			else if((LO_freq>=157000) && (LO_freq<181000))
			{
				R850_Freq_Info.LPF_CAP = 6;
				R850_Freq_Info.LPF_NOTCH = 0;
			}
			else if((LO_freq>=181000) && (LO_freq<205000))
			{
				R850_Freq_Info.LPF_CAP = 3;
				R850_Freq_Info.LPF_NOTCH = 0;
			}
			else //LO>=201M
			{
				R850_Freq_Info.LPF_CAP = 0;
				R850_Freq_Info.LPF_NOTCH = 0;
			}
			//Diplexer Select R14[3:2]
			if(LO_freq<330000)
				R850_Freq_Info.TF_DIPLEXER = 2; //LPF   R14[3:2]
			else
				R850_Freq_Info.TF_DIPLEXER = 0; //HPF


			break;

		default:  //Air, DTMB (for 180nH)
			if((LO_freq>0) && (LO_freq<73000))
			{
				R850_Freq_Info.LPF_CAP = 8;
				R850_Freq_Info.LPF_NOTCH = 10;
			}
			else if((LO_freq>=73000) && (LO_freq<81000))
			{
				R850_Freq_Info.LPF_CAP = 8;
				R850_Freq_Info.LPF_NOTCH = 4;
			}
			else if((LO_freq>=81000) && (LO_freq<89000))
			{
				R850_Freq_Info.LPF_CAP = 8;
				R850_Freq_Info.LPF_NOTCH = 3;
			}
			else if((LO_freq>=89000) && (LO_freq<121000))
			{
				R850_Freq_Info.LPF_CAP = 6;
				R850_Freq_Info.LPF_NOTCH = 1;
			}
			else if((LO_freq>=121000) && (LO_freq<145000))
			{
				R850_Freq_Info.LPF_CAP = 4;
				R850_Freq_Info.LPF_NOTCH = 0;
			}
			else if((LO_freq>=145000) && (LO_freq<153000))
			{
				R850_Freq_Info.LPF_CAP = 3;
				R850_Freq_Info.LPF_NOTCH = 0;
			}
			else if((LO_freq>=153000) && (LO_freq<177000))
			{
				R850_Freq_Info.LPF_CAP = 2;
				R850_Freq_Info.LPF_NOTCH = 0;
			}
			else if((LO_freq>=177000) && (LO_freq<201000))
			{
				R850_Freq_Info.LPF_CAP = 1;
				R850_Freq_Info.LPF_NOTCH = 0;
			}
			else //LO>=201M
			{
				R850_Freq_Info.LPF_CAP = 0;
				R850_Freq_Info.LPF_NOTCH = 0;
			}
			//Diplexer Select R14[3:2]
			if(LO_freq<340000)
				R850_Freq_Info.TF_DIPLEXER = 2; //LPF   R14[3:2]
			else
				R850_Freq_Info.TF_DIPLEXER = 0; //HPF
			break;

	}//end switch(standard)


	return R850_Freq_Info;

}

struct R850_SysFreq_Info_Type R850_SysFreq_NrbDetOn_Sel(enum R850_Standard_Type R850_Standard,u32 RF_freq)
{

	struct R850_SysFreq_Info_Type R850_SysFreq_Info;

	switch(R850_Standard)
	{
		case R850_DTMB_8M_4570:
		case R850_DTMB_6M_4500:
		case R850_DTMB_8M_IF_5M:
		case R850_DTMB_6M_IF_5M:
			if(RF_freq<=100000)
			{
				//LNA
				R850_SysFreq_Info.LNA_VTL_H=0x6B;				//R39[7:0] LNA VTL/H = 0.94(6) / 1.44(B)

				//NRB
				R850_SysFreq_Info.NRB_TOP=10;					//R40[7:4]     ["15-highest ~ 0-lowest" (0~15) ; input: "15~0"]
				R850_SysFreq_Info.NRB_BW_LPF=3;					//R26[7:6]     [widest (0), wide (1), low (2), lowest (3)]
				R850_SysFreq_Info.NRB_BW_HPF=3;					//R26[3:2]     [lowest (0), low (1), high (2), highest (3)]
				R850_SysFreq_Info.IMG_NRB_ADDER=1;				//R46[3:2]		["original" (0), "top+6" (1), "top+9" (2), "top+11" (3)]

				//Filter
				R850_SysFreq_Info.FILT_3TH_LPF_GAIN=0;			//R24[1:0]		[normal (0), +1.5dB (1), +3dB (2), +4.5dB (3)]
			}
			else if(RF_freq<=340000)
			{
				//LNA
				R850_SysFreq_Info.LNA_VTL_H=0x6B;				//R39[7:0] LNA VTL/H = 0.94(6) / 1.44(B)

				//NRB
				R850_SysFreq_Info.NRB_TOP=10;					//R40[7:4]     ["15-highest ~ 0-lowest" (0~15) ; input: "15~0"]
				R850_SysFreq_Info.NRB_BW_LPF=2;					//R26[7:6]     [widest (0), wide (1), low (2), lowest (3)]
				R850_SysFreq_Info.NRB_BW_HPF=3;					//R26[3:2]     [lowest (0), low (1), high (2), highest (3)]
				R850_SysFreq_Info.IMG_NRB_ADDER=1;				//R46[3:2]		["original" (0), "top+6" (1), "top+9" (2), "top+11" (3)]

				//Filter
				R850_SysFreq_Info.FILT_3TH_LPF_GAIN=0;			//R24[1:0]		[normal (0), +1.5dB (1), +3dB (2), +4.5dB (3)]
			}
			else
			{
				//LNA
				R850_SysFreq_Info.LNA_VTL_H=0x5A;				//R39[7:0] LNA VTL/H = 0.84(5) / 1.34(A)

				//NRB
				R850_SysFreq_Info.NRB_TOP=6;					//R40[7:4]     ["15-highest ~ 0-lowest" (0~15) ; input: "15~0"]
				R850_SysFreq_Info.NRB_BW_LPF=2;					//R26[7:6]     [widest (0), wide (1), low (2), lowest (3)]
				R850_SysFreq_Info.NRB_BW_HPF=2;					//R26[3:2]     [lowest (0), low (1), high (2), highest (3)]
				R850_SysFreq_Info.IMG_NRB_ADDER=0;				//R46[3:2]		["original" (0), "top+6" (1), "top+9" (2), "top+11" (3)]

				//Filter
				R850_SysFreq_Info.FILT_3TH_LPF_GAIN=3;			//R24[1:0]		[normal (0), +1.5dB (1), +3dB (2), +4.5dB (3)]
			}

			//PW
			R850_SysFreq_Info.NA_PWR_DET = 0;				//R10[6]   ["off" (0), "on" (1)]
			R850_SysFreq_Info.LNA_NRB_DET=0;				//R11[7]    ["on" (0), "off" (1)]

			//LNA
			R850_SysFreq_Info.LNA_TOP=4;					//R38[2:0] ["7~0" (0~7) ; input: "7~0"]
			R850_SysFreq_Info.RF_LTE_PSG=1;					//R17[4]  ["no psg" (0), "7.5dB(5~8)" (1)]


			//RFBuf
			R850_SysFreq_Info.RF_TOP=4;						//R38[6:4]  ["7~0" (0~7) ; input: "7~0"]
			R850_SysFreq_Info.RF_VTL_H=0x4A;				//R42[7:0] RF VTL/H = 0.74(4) / 1.34(A)
			R850_SysFreq_Info.RF_GAIN_LIMIT=0;				//MSB R18[2], LSB R16[6]   ["max =15" (0), "max =11" (1), "max =13" (2), "max =9" (3)]

			//Mixer and Mixamp
			R850_SysFreq_Info.MIXER_AMP_LPF = 4;			//R19[2:0]	["normal (widest)" (0), "1" (1), "2" (2), "3" (3), "4" (4), "5" (5), "6" (6), "narrowest" (7)]
			R850_SysFreq_Info.MIXER_TOP=9;					//R40[3:0]	["15-highest ~ 0-lowest" (0~15) ; input: "15~0"]
			R850_SysFreq_Info.MIXER_VTH=0x09;				//R41[3:0]	1.24 (9)
			R850_SysFreq_Info.MIXER_VTL=0x04;				//R43[3:0]	0.74 (4)
			R850_SysFreq_Info.MIXER_GAIN_LIMIT=1;			//R22[7:6]	["max=6" (0), "max=8" (1), "max=10" (2), "max=12" (3)]
			R850_SysFreq_Info.MIXER_DETBW_LPF =0;			//R46[7]	["normal" (0), "enhance amp det LPF" (1)]

			//Filter
			R850_SysFreq_Info.FILTER_TOP=4;					//R44[3:0]  ["15-highest ~ 0-lowest" (0~15) ; input: "15~0"]
			R850_SysFreq_Info.FILTER_VTH=0x90;				//R41[7:4]  1.24 (9)
			R850_SysFreq_Info.FILTER_VTL=0x40;				//R43[7:4]  0.74 (4)
			R850_SysFreq_Info.FILT_3TH_LPF_CUR=0;			//R10[4] [high (0), low (1)]


			//Discharge
			R850_SysFreq_Info.LNA_RF_DIS_MODE=1;			//Both (fast+slow) (R45[1:0]=0'b00; R31[0]=1 ;R32[5]=1)	: 1111 Both (fast+slow)	case 1
			R850_SysFreq_Info.LNA_RF_CHARGE_CUR=1;			//R31[1]  ["6x chargeI" (0), "4x chargeI" (1)]
			R850_SysFreq_Info.LNA_RF_DIS_CURR=1;		    //R13[5]		["1/3 dis current" (0), "normal" (1)]
			R850_SysFreq_Info.RF_DIS_SLOW_FAST=5;			//R45[7:4]		0.3u (1) / 0.9u (4)
			R850_SysFreq_Info.LNA_DIS_SLOW_FAST=9;			//R44[7:4]		0.3u (1) / 1.5u (8)   => 1 + 8 = 9
			R850_SysFreq_Info.BB_DIS_CURR=0;                //R25[6]		["x1" (0) , "x1/2" (1)]
			R850_SysFreq_Info.MIXER_FILTER_DIS=2;			//R37[7:6]		["highest" (0), "high" (1), "low" (2), "lowest" (3)]
			R850_SysFreq_Info.BB_DET_MODE=0;				//R37[2]		["peak" (0), "average" (1)]

			//Polyphase
			R850_SysFreq_Info.ENB_POLY_GAIN=0;				//R25[1]=0		original ["original" (0), "ctrl by mixamp (>10)" (1)]

			//VGA
			R850_SysFreq_Info.HPF_COMP=0;					//R13[2:1]	   ["normal" (0) , "+1.5dB" (1), "+3dB" (2), "+4dB" (3)]
			R850_SysFreq_Info.FB_RES_1ST=0;					//R21[4]	   ["2K" (0) , "8K" (1)]

			break;

		default: //DVB-T
			//PW
			R850_SysFreq_Info.NA_PWR_DET = 0;				//R10[6]   ["off" (0), "on" (1)]
			R850_SysFreq_Info.LNA_NRB_DET=0;				//R11[7]    ["on" (0), "off" (1)]

			//LNA
			R850_SysFreq_Info.LNA_TOP=4;					//R38[2:0] ["7~0" (0~7) ; input: "7~0"]
			R850_SysFreq_Info.LNA_VTL_H=0x5A;				//R39[7:0] LNA VTL/H = 0.84(5) / 1.34(A)
			R850_SysFreq_Info.RF_LTE_PSG=1;					//R17[4]  ["no psg" (0), "7.5dB(5~8)" (1)]


			//RFBuf
			R850_SysFreq_Info.RF_TOP=4;						//R38[6:4]  ["7~0" (0~7) ; input: "7~0"]
			R850_SysFreq_Info.RF_VTL_H=0x4A;				//R42[7:0] RF VTL/H = 0.74(4) / 1.34(A)
			R850_SysFreq_Info.RF_GAIN_LIMIT=0;				//MSB R18[2], LSB R16[6]   ["max =15" (0), "max =11" (1), "max =13" (2), "max =9" (3)]

			//Mixer and Mixamp
			R850_SysFreq_Info.MIXER_AMP_LPF = 4;			//R19[2:0]	["normal (widest)" (0), "1" (1), "2" (2), "3" (3), "4" (4), "5" (5), "6" (6), "narrowest" (7)]
			R850_SysFreq_Info.MIXER_TOP=9;					//R40[3:0]	["15-highest ~ 0-lowest" (0~15) ; input: "15~0"]
			R850_SysFreq_Info.MIXER_VTH=0x09;				//R41[3:0]	1.24 (9)
			R850_SysFreq_Info.MIXER_VTL=0x04;				//R43[3:0]	0.74 (4)
			R850_SysFreq_Info.MIXER_GAIN_LIMIT=3;			//R22[7:6]	["max=6" (0), "max=8" (1), "max=10" (2), "max=12" (3)]
			R850_SysFreq_Info.MIXER_DETBW_LPF =0;			//R46[7]	["normal" (0), "enhance amp det LPF" (1)]


			//Filter
			R850_SysFreq_Info.FILTER_TOP=4;					//R44[3:0]  ["15-highest ~ 0-lowest" (0~15) ; input: "15~0"]
			R850_SysFreq_Info.FILTER_VTH=0x90;				//R41[7:4]  1.24 (9)
			R850_SysFreq_Info.FILTER_VTL=0x40;				//R43[7:4]  0.74 (4)
			R850_SysFreq_Info.FILT_3TH_LPF_CUR=1;			//R10[4] [high (0), low (1)]
			R850_SysFreq_Info.FILT_3TH_LPF_GAIN=3;			//R24[1:0]		[normal (0), +1.5dB (1), +3dB (2), +4.5dB (3)]

			//Discharge
			R850_SysFreq_Info.LNA_RF_DIS_MODE=1;			//Both (fast+slow) (R45[1:0]=0'b00; R31[0]=1 ;R32[5]=1)	: 1111 Both (fast+slow)	case 1
			R850_SysFreq_Info.LNA_RF_CHARGE_CUR=1;			//R31[1]  ["6x chargeI" (0), "4x chargeI" (1)]
			R850_SysFreq_Info.LNA_RF_DIS_CURR=1;		    //R13[5]		["1/3 dis current" (0), "normal" (1)]
			R850_SysFreq_Info.RF_DIS_SLOW_FAST=5;			//R45[7:4]		0.3u (1) / 0.9u (4)
			R850_SysFreq_Info.LNA_DIS_SLOW_FAST=9;			//R44[7:4]		0.3u (1) / 1.5u (8)   => 1 + 8 = 9
			R850_SysFreq_Info.BB_DIS_CURR=0;                //R25[6]		["x1" (0) , "x1/2" (1)]
			R850_SysFreq_Info.MIXER_FILTER_DIS=2;			//R37[7:6]		["highest" (0), "high" (1), "low" (2), "lowest" (3)]
			R850_SysFreq_Info.BB_DET_MODE=0;				//R37[2]		["peak" (0), "average" (1)]

			//Polyphase
			R850_SysFreq_Info.ENB_POLY_GAIN=0;				//R25[1]=0		original ["original" (0), "ctrl by mixamp (>10)" (1)]

			//NRB
			R850_SysFreq_Info.NRB_TOP=4;					//R40[7:4]     ["15-highest ~ 0-lowest" (0~15) ; input: "15~0"]
			R850_SysFreq_Info.NRB_BW_HPF=0;					//R26[3:2]     [lowest (0), low (1), high (2), highest (3)]
			R850_SysFreq_Info.NRB_BW_LPF=2;					//R26[7:6]     [widest (0), wide (1), low (2), lowest (3)]
			R850_SysFreq_Info.IMG_NRB_ADDER=2;				//R46[3:2]	   ["original" (0), "top+6" (1), "top+9" (2), "top+11" (3)]

			//VGA
			R850_SysFreq_Info.HPF_COMP=1;					//R13[2:1]	   ["normal" (0) , "+1.5dB" (1), "+3dB" (2), "+4dB" (3)]
			R850_SysFreq_Info.FB_RES_1ST=1;					//R21[4]	   ["2K" (0) , "8K" (1)]
			break;

	} //end switch

	
		R850_SysFreq_Info.DEGLITCH_CLK = 1;		//R38[3]		["500Hz"(0), "1KHz"(1)]
		//R850_SysFreq_Info.LNA_RF_DIS_MODE =1;			//Both (fast+slow) (R45[1:0]=0'b00; R31[0]=1 ;R32[5]=1)	: 1111 Both (fast+slow)	case 1
		//R850_SysFreq_Info.LNA_DIS_SLOW_FAST &= 0x03;
		//R850_SysFreq_Info.LNA_DIS_SLOW_FAST += 8;			//R44[7:6]	  R45[7:6] ["0.6u" (0), "0.9u" (4), "1.5u" (8), "2.4u" (12)]
		R850_SysFreq_Info.NAT_HYS = 1;			//R35[6]		["no hys"(0) , "-6.5dB hys"(1)]
		R850_SysFreq_Info.NAT_CAIN = 2;			//R31[4:5]	["max-17dB"(0) , "max-11dB"(1), "max-6dB"(2), "max"(3)]
		R850_SysFreq_Info.PULSE_HYS = 1;		//R26[1:0]	["1.0V"(0), "0.8V"(1), "0.6V"(2), "0.4V"(3)]
		R850_SysFreq_Info.FAST_DEGLITCH = 1;	//R36[3:2]	["70ms"(0), "45ms"(1), "20ms"(2), "10ms"(3)]
		R850_SysFreq_Info.PUL_RANGE_SEL = 0;	//R31[2]		["0"(0), "1"(1)]
		R850_SysFreq_Info.PUL_FLAG_RANGE = 3;	//R35[1:0]	["0~14"(0), "1~14"(1), "2~14"(2), "3~14"(3)]
		R850_SysFreq_Info.PULG_CNT_THRE = 1;	//R17[1]		["threshold =14"(0), "threshold =15"(1)]
		R850_SysFreq_Info.FORCE_PULSE = 1;		//R46[5]		["pul_flag=0"(0), "auto"(1)]
		R850_SysFreq_Info.FLG_CNT_CLK = 1;		//R47[7:6]	["0.25Sec"(0), "0.5Sec"(1), "1Sec"(2), "2Sec"(3)]
		R850_SysFreq_Info.NATG_OFFSET =	0;		//R36[5:4]	["-6dB"(0), "-3dB"(1), "Normal"(2), "3dB"(3)]


	return R850_SysFreq_Info;

}
//-----------------------------------------------------------------------------------/
// Purpose: read multiple IMR results for stability
// input: IMR_Reg: IMR result address
//        IMR_Result_Data: result
// output: TRUE or FALSE
//-----------------------------------------------------------------------------------/
R850_ErrCode R850_Muti_Read( struct r850_priv*priv, u8* IMR_Result_Data) //ok
{
	int ret = 0;
	u8 buf[2];


	 msleep(2);//2 //R850_ADC_READ_DELAY = 2;

	 ret = r850_rd(priv,0x00,buf,2);
	 if(ret!=0){
		 *IMR_Result_Data = 0;
	 	return R850_Fail;
	 	}
	*IMR_Result_Data = buf[1] & 0x3F;

	return R850_Success;
}
R850_ErrCode R850_SetXtalCap(struct r850_priv *priv,u8 u8XtalCap)
{
	u8 XtalCap;
	u8 Capx;
	u8 Capx_3_0, Capxx;

	if(u8XtalCap>31)
	{
		XtalCap = 1;  //10
		Capx = u8XtalCap-10;
	}
	else
	{
		XtalCap = 0; //0
		Capx = u8XtalCap;
	}

	Capxx = Capx & 0x01;
	Capx_3_0 = Capx >> 1;

	// Set Xtal Cap  R33[6:3], R34[3]     XtalCap => R33[7]

	priv->regs[33] = (priv->regs[33 ] & 0x07) | (Capx_3_0 << 3) | ( XtalCap << 7);
	if(r850_wr(priv,33,priv->regs[33])!=0)
		return R850_Fail;
	

	priv->regs[34] = (priv->regs[34] & 0xF7) | (Capxx << 3);
	if(r850_wr(priv,34,priv->regs[34])!=0)
		return R850_Fail;

	return R850_Success;
}

R850_ErrCode R850_SetXtalCap_No_Write(struct r850_priv *priv,u8 u8XtalCap)
{
	u8 XtalCap;
	u8 Capx;
	u8 Capx_3_0, Capxx;

	if(u8XtalCap>31)
	{
		XtalCap = 1;  //10
		Capx = u8XtalCap-10;
	}
	else
	{
		XtalCap = 0; //0
		Capx = u8XtalCap;
	}

	Capxx = Capx & 0x01;
	Capx_3_0 = Capx >> 1;

	// Set Xtal Cap  R33[6:3], R34[3]     XtalCap => R33[7]

	priv->regs[33] = (priv->regs[33] & 0x07) | (Capx_3_0 << 3) | ( XtalCap << 7);

	priv->regs[34] = (priv->regs[34] & 0xF7) | (Capxx << 3);

	return R850_Success;
}

/*parameter 2: xtal_gm
0:24MHz (strong)
1:24MHz
2:gm (16MHz)
3:off
*/
R850_ErrCode R850_Set_XTAL_GM(struct r850_priv *priv,u8 xtal_gm)
{
	// Set Xtal gm  R34[7:6]

	priv->regs[34] = (priv->regs[34] & 0x3F) | (xtal_gm << 6);
	if(r850_wr(priv,34,priv->regs[34])!=0)
		return R850_Fail;

	return R850_Success;
}

/*
 XTAL_PWR_VALUE
{
	XTAL_LOWEST = 0,
	XTAL_LOW,
	XTAL_HIGH,
	XTAL_HIGHEST,
	XTAL_CHECK_SIZE
};
*/
R850_ErrCode R850_SetXtalPW( struct r850_priv *priv,u8 u8Xtalpw)
{
	u8 Xtal_power;

	Xtal_power = (3 - u8Xtalpw);

	priv->regs[34] = (priv->regs[34] & 0xCF) | (Xtal_power<<4);	//R34[5:4]

	if(r850_wr(priv,34,priv->regs[34])!=0)
		return R850_Fail;

	return R850_Success;
}

R850_ErrCode R850_PLL(struct r850_priv*priv, u32 LO_Freq, enum R850_Standard_Type R850_Standard)//ok
{
	u8  MixDiv = 2;
	u8  DivBuf = 0;
	u8  Ni = 0;
	u8  Si = 0;
	u8  DivNum = 0;
	u16  Nint = 0;
	u32 VCO_Min = 2200000;
	u32 VCO_Max = 4400000;
	u32 VCO_Freq = 0;
	u32 PLL_Ref	= priv->cfg->R850_Xtal;
	u32 VCO_Fra	= 0;
	u16 Nsdm = 2;
	u16 SDM = 0;
	u16 SDM16to9 = 0;
	u16 SDM8to1 = 0;
	u8   XTAL_POW = 0;
	u16  u2XalDivJudge;
	u8   u1XtalDivRemain;
	u8   CP_CUR = 0x00;
	u8   CP_OFFSET = 0x00;
	u8   SDM_RES = 0x00;
	u8   NS_RES = 0x00;
	u8   IQGen_Cur = 0;    //DminDmin
	u8   IQBias = 1;           //BiasI
	u8   IQLoad = 0;          //3.2k/2
	u8   OutBuf_Bias = 0;   //max
	u8   BiasHf = 0;            //135u
	u8	PllArrayCunt = 0;
	int ret = 0;

//	if(R850_Chip == R850_MP)
//		VCO_Min=2270000;
//	else
	VCO_Min=2200000;

	VCO_Max = VCO_Min*2;

	// VCO current = 0 (max)
	priv->regs[32] = (priv->regs[32] & 0xFC) | 0x00; // R31[1:0] = 0   => R32[3:2] = 0

	// VCO power = auto
	priv->regs[46] = (priv->regs[46] & 0xBF) | 0x40; // R26[7] = 1 => R46[6] = 1

	// HfDiv Buf = 6dB buffer
	priv->regs[37] = (priv->regs[37] & 0xEF) | 0x00; // R17[7]=0	=> R37[4]=0

	// Divider HfDiv current = 135u
	priv->regs[12] = (priv->regs[12] & 0xFC) | 0x00; // R10[1:0]=00	=> R12[3:2]=00

	// PLL LDOA=2.2V
	priv->regs[11] = (priv->regs[11] & 0xF3) | 0x00; // R11[3:2]=00 => R11[3:2]=00

	// PFD DLDO=4mA
	priv->regs[12] = (priv->regs[12] & 0x3F) | 0x00; // R8[5:4]=00 => R12[7:6]=00

	// DLDO2=3mA
	priv->regs[11] = (priv->regs[11] & 0xCF) | 0x10; // R11[5:4]=01 => R11[5:4]=01

	// HF Fiv LDO=7mA (new bonding set this off)
	priv->regs[9] = (priv->regs[9] & 0xF9) | 0x00; // R12[2:1]=00	=> R9[2:1]=00

	//------ Xtal freq depend setting: Xtal Gm & AGC ref clk --------//
	if(priv->cfg->R850_Xtal==24000)
	{
		priv->regs[34] = (priv->regs[34] & 0x3F) | 0x00;  //gm*2(24)  R32[4:3]:00 => R34[7:6]:00
		priv->regs[37] = (priv->regs[37] & 0xDF) | 0x20;  //clk /3 (24) => R37[5]=1
	}
	else if(priv->cfg->R850_Xtal==16000)
	{
		priv->regs[34] = (priv->regs[34] & 0x3F) | 0x80;  //gm(16)	R32[4:3]:10 => R34[7:6]:10
		priv->regs[37] = (priv->regs[37] & 0xDF) | 0x00;  //clk /2 (16)	=> R37[5]=0
	}
	else if(priv->cfg->R850_Xtal==27000)
	{
		priv->regs[34] = (priv->regs[34] & 0x3F) | 0x00;  //gm*2(24)  R32[4:3]:00 => R34[7:6]:00
		priv->regs[37] = (priv->regs[37] & 0xDF) | 0x20;  //clk /3 (24) => R37[5]=1
	}
	else  //not support Xtal freq
		return R850_Fail;


	if(priv->R850_clock_out == 1)
	{
		XTAL_POW = 0;        //highest,       R32[2:1]=0
		//Set X'tal Cap
		R850_SetXtalCap(priv, priv->R850_Xtal_cap);
	}
	else if(priv->R850_clock_out == 0)
	{
		XTAL_POW = 3;        //lowest,       R32[2:1]=3
		//Set X'tal Cap
		R850_SetXtalCap(priv, 0);
		//gm off
		R850_Set_XTAL_GM(priv, 1); //3:xtal gm off
	}
	else
	{
		if(LO_Freq<100000) //Xtal PW : Low
		{
			if(priv->R850_Xtal_Pwr <= R850_XTAL_LOW )
			{
				XTAL_POW = 2;
			}
			else
			{
				XTAL_POW = 3 - priv->R850_Xtal_Pwr;
			}
		}
		else if((110000<=LO_Freq) && (LO_Freq<130000)) //Xtal PW: High
		{
			if(priv->R850_Xtal_Pwr <= R850_XTAL_HIGH )
			{
				XTAL_POW = 1;
			}
			else
			{
				XTAL_POW = 3 - priv->R850_Xtal_Pwr;
			}
		}
		else //Xtal PW : Highest
		{
			XTAL_POW = 0;
		}
	    //Set X'tal Cap
		R850_SetXtalCap(priv,  priv->R850_Xtal_cap);
	}


	priv->regs[34] = (priv->regs[34] & 0xCF) | (XTAL_POW<<4);	//R32[2:1] => R34[5:4]


	CP_CUR = 0x00;     //0.7m, R30[7:5]=000
	CP_OFFSET = 0x00;  //0u,     R37[1]=0
	if(priv->cfg->R850_Xtal == 24000)
	{
		u2XalDivJudge = (u16) ((LO_Freq+priv->R850_IF_GOLOBAL)/1000/12);
		//  48, 120 ,264 ,288, 336
		if((u2XalDivJudge==4)||(u2XalDivJudge==10)||(u2XalDivJudge==22)||(u2XalDivJudge==24)||(u2XalDivJudge==28))
		{
			CP_OFFSET = 0x02;  //30u,     R37[1]=1
		}
		else
		{
			CP_OFFSET = 0x00;  //0u,     R37[1]=0
		}
	}
	else if(priv->cfg->R850_Xtal == 16000)
	{
		u2XalDivJudge = (u16) ((LO_Freq+priv->R850_IF_GOLOBAL)/1000/8);
		//
		if((u2XalDivJudge==6)||(u2XalDivJudge==10)||(u2XalDivJudge==12)||(u2XalDivJudge==48))
		{
			CP_OFFSET = 0x02;  //30u,     R37[1]=1
		}
		else
		{
			CP_OFFSET = 0x00;  //0u,     R37[1]=0
		}
	}
	else if(priv->cfg->R850_Xtal == 27000)
	{
		u2XalDivJudge = (u16) ((LO_Freq+priv->R850_IF_GOLOBAL)*10/1000/135);
		//  48, 120 ,264 ,288, 336
		if((u2XalDivJudge==4)||(u2XalDivJudge==10)||(u2XalDivJudge==22)||(u2XalDivJudge==24)||(u2XalDivJudge==28))
		{
			CP_OFFSET = 0x02;  //30u,     R37[1]=1
		}
		else
		{
			CP_OFFSET = 0x00;  //0u,     R37[1]=0
		}
	}


	priv->regs[30] = (priv->regs[30] & 0x1F) | (CP_CUR);	//    => R30[7:5]

	priv->regs[37] = (priv->regs[37] & 0xFD) | (CP_OFFSET);	//    => R37[1]

	//set pll autotune = 64kHz (fast)  R47[1:0](MP) ,  R47[0](MT1)

	priv->regs[47] = priv->regs[47] & 0xFD;

	//Divider
	while(MixDiv <= 64)
	{
		if(((LO_Freq * MixDiv) >= VCO_Min) && ((LO_Freq * MixDiv) < VCO_Max))
		{
			DivBuf = MixDiv;
			while(DivBuf > 2)
			{
				DivBuf = DivBuf >> 1;
				DivNum ++;
			}
			break;
		}
		MixDiv = MixDiv << 1;
	}

	//IQ Gen block & BiasHF & NS_RES & SDM_Res
	if(MixDiv <= 4)  //Div=2,4
	{
		IQGen_Cur = 0;    //DminDmin
		IQBias = 1;           //BiasI
		IQLoad = 0;          //3.2k/2
		OutBuf_Bias = 0;   //0 (max)
		BiasHf = 0;           //135u
		SDM_RES = 0;     //short
		NS_RES = 0;        //0R
	}
	else if(MixDiv == 8)
	{
		IQGen_Cur = 0;    //DminDmin
		IQBias = 0;           //BiasI/2
		IQLoad = 1;          //3.2k
		OutBuf_Bias = 1;   //1
		BiasHf = 1;           //110u
		SDM_RES = 0;     //short
		NS_RES = 1;        //800R
	}
	else if(MixDiv == 16)
	{
		IQGen_Cur = 0;    //DminDmin
		IQBias = 0;           //BiasI/2
		IQLoad = 1;          //3.2k
		OutBuf_Bias = 2;   //2
		BiasHf = 1;           //110u
		SDM_RES = 0;     //short
		NS_RES = 0;        //0R
	}
	else if(MixDiv >= 32) //32, 64
	{
		IQGen_Cur = 0;    //DminDmin
		IQBias = 0;           //BiasI/2
		IQLoad = 1;          //3.2k
		OutBuf_Bias = 3;   //3 (min)
		BiasHf = 1;           //110u
		SDM_RES = 0;     //short
		NS_RES = 0;        //0R
	}
	else
	{
		return R850_Fail;
	}

	{
	
		{
			if(priv->cfg->R850_Xtal==24000)
				u2XalDivJudge = (u16) ((LO_Freq + priv->R850_IF_GOLOBAL)/1000/12);
			else if(priv->cfg->R850_Xtal==16000)
				u2XalDivJudge = (u16) ((LO_Freq + priv->R850_IF_GOLOBAL)/1000/8);
			else if(priv->cfg->R850_Xtal==27000)
				u2XalDivJudge = (u16) ((LO_Freq + priv->R850_IF_GOLOBAL)*10/1000/135);
			else
				return R850_Fail;

			u1XtalDivRemain = (u8) (u2XalDivJudge % 2);

			if(LO_Freq < (372000+8500))
			{
				if(u1XtalDivRemain==1) //odd
				{
					priv->R850_XtalDiv = R850_XTAL_DIV1;
				}
				else  //even, spur area
				{
					priv->R850_XtalDiv = R850_XTAL_DIV1_2;
				}
			}
			else if(((LO_Freq + priv->R850_IF_GOLOBAL) >= 478000) && ((LO_Freq + priv->R850_IF_GOLOBAL) < 482000) && (R850_Standard == R850_ISDB_T_4063))
			{
				priv->R850_XtalDiv = R850_XTAL_DIV4;
			}
			else
			{
				priv->R850_XtalDiv = R850_XTAL_DIV1;
			}
		}
	}


	//Xtal divider setting
	//R850_XtalDiv = XTAL_DIV2; //div 1, 2, 4
	if(priv->R850_XtalDiv==R850_XTAL_DIV1)
	{
		PLL_Ref = priv->cfg->R850_Xtal;
		priv->regs[34] = (priv->regs[34] & 0xFC) | 0x00; //b7:2nd_div2=0, b6:1st_div2=0	 R32[7:6] => R34[1:0]
	}
	else if(priv->R850_XtalDiv==R850_XTAL_DIV1_2)
	{
		PLL_Ref = priv->cfg->R850_Xtal/2;
		priv->regs[34] = (priv->regs[34] & 0xFC) | 0x02; //1st_div2=0(R34[0]), 2nd_div2=1(R34[1])
	}
	else if(priv->R850_XtalDiv==R850_XTAL_DIV2_1)
	{
		PLL_Ref = priv->cfg->R850_Xtal/2;
		priv->regs[34] = (priv->regs[34] & 0xFC) | 0x01; //1st_div2=1(R34[0]), 2nd_div2=0(R34[1])
	}
	else if(priv->R850_XtalDiv==R850_XTAL_DIV4)  //24MHz
	{
		PLL_Ref = priv->cfg->R850_Xtal/4;
		priv->regs[34] = (priv->regs[34] & 0xFC) | 0x03; //b7:2nd_div2=1, b6:1st_div2=1  R32[7:6] => R34[1:0]
	}


	//IQ gen current R10[7] => R11[0]
	priv->regs[11] = (priv->regs[11] & 0xFE) | (IQGen_Cur);

	//Out Buf Bias R10[6:5] => R45[3:2]
	priv->regs[45] = (priv->regs[45] & 0xF3) | (OutBuf_Bias<<2);

	//BiasI R29[2] => R46[0]
	priv->regs[46] = (priv->regs[46] & 0xFE) | (IQBias);

	//IQLoad R36[5] => R46[1]
	priv->regs[46] = (priv->regs[46] & 0xFD) | (IQLoad<<1);

	//BiasHF R29[7:6] => R32[1:0]
	priv->regs[32] = (priv->regs[32] & 0xFC) | (BiasHf);

	//SDM_RES R30[7] => R32[4]
	priv->regs[32] = (priv->regs[32] & 0xEF) | (SDM_RES<<4);

	//NS_RES  R36[0]  => R17[7]
	priv->regs[17] = (priv->regs[17] & 0x7F) | (NS_RES<<7);

	//Divider num R35[5:3] => R30[4:2]
	priv->regs[30] = (priv->regs[30] & 0xE3) | (DivNum << 2);

	VCO_Freq = LO_Freq * MixDiv;
	Nint = (u16) (VCO_Freq / 2 / PLL_Ref);
	VCO_Fra = (u16) (VCO_Freq - 2 * PLL_Ref * Nint);

	//Boundary spur prevention
	if (VCO_Fra < PLL_Ref/64)           //2*PLL_Ref/128
		VCO_Fra = 0;
	else if (VCO_Fra > PLL_Ref*127/64)  //2*PLL_Ref*127/128
	{
		VCO_Fra = 0;
		Nint ++;
	}
	else if((VCO_Fra > PLL_Ref*127/128) && (VCO_Fra < PLL_Ref)) //> 2*PLL_Ref*127/256,  < 2*PLL_Ref*128/256
		VCO_Fra = PLL_Ref*127/128;      // VCO_Fra = 2*PLL_Ref*127/256
	else if((VCO_Fra > PLL_Ref) && (VCO_Fra < PLL_Ref*129/128)) //> 2*PLL_Ref*128/256,  < 2*PLL_Ref*129/256
		VCO_Fra = PLL_Ref*129/128;      // VCO_Fra = 2*PLL_Ref*129/256
	else
		VCO_Fra = VCO_Fra;

	//Ni & Si
	Ni = (u8) ((Nint - 13) / 4);
	Si = (u8) (Nint - 4 *Ni - 13);


	priv->regs[27] = (priv->regs[27] & 0x80) | Ni;     //R26[6:0] => R27[6:0]
	priv->regs[30] = (priv->regs[30] & 0xFC) | Si;  //R35[7:6] => R30[1:0]

	//pw_sdm & pw_dither
	priv->regs[32] &= 0x3F;        //R29[1:0] => R32[7:6]
	if(VCO_Fra == 0)
	{
		priv->regs[32] |= 0xC0;
	}

	//SDM calculator
	while(VCO_Fra > 1)
	{
		if (VCO_Fra > (2*PLL_Ref / Nsdm))
		{
			SDM = SDM + 32768 / (Nsdm/2);
			VCO_Fra = VCO_Fra - 2*PLL_Ref / Nsdm;
			if (Nsdm >= 0x8000)
				break;
		}
		Nsdm = Nsdm << 1;
	}

	SDM16to9 = SDM >> 8;
	SDM8to1 =  SDM - (SDM16to9 << 8);


	priv->regs[29] = (u8) SDM16to9;  //R28 => R29
	priv->regs[28] = (u8) SDM8to1;    //R27 => R28


	ret = r850_wrm(priv,8,&priv->regs[8],40);
	if(ret!=0)
		return R850_Fail;



	if(priv->R850_XtalDiv == R850_XTAL_DIV1)
		msleep( R850_PLL_LOCK_DELAY); //correct gx_msleep ecos, don't modify delay function!
	else if((priv->R850_XtalDiv == R850_XTAL_DIV1_2) || (priv->R850_XtalDiv == R850_XTAL_DIV2_1))
		msleep( R850_PLL_LOCK_DELAY*2);
	else
		msleep( R850_PLL_LOCK_DELAY*4);

	//set pll autotune = 1khz (2'b10)

	priv->regs[47] = (priv->regs[47] & 0xFD) | 0x02;
	if(r850_wr(priv,47,priv->regs[47])!=0)
		return R850_Fail;


	return R850_Success;

}


R850_ErrCode R850_MUX( struct r850_priv *priv ,u32 LO_KHz, u32 RF_KHz, enum R850_Standard_Type R850_Standard)
{
	u8 Reg_IMR_Gain   = 0;
	u8 Reg_IMR_Phase  = 0;
	u8 Reg_IMR_Iqcap  = 0;
	struct R850_Freq_Info_Type Freq_Info1;

	//Freq_Info_Type Freq_Info1;
	Freq_Info1 = R850_Freq_Sel(LO_KHz, RF_KHz, R850_Standard);


	// TF_DIPLEXER
	priv->regs[14] = (priv->regs[14] & 0xF3) | (Freq_Info1.TF_DIPLEXER<<2);  //LPF    => R14[3:2]
	if(r850_wr(priv,14,priv->regs[14])!=0)
		return R850_Fail;



	//TF_HPF_BPF => R16[2:0]   	TF_HPF_CNR => R16[4:3]
	priv->regs[16] = (priv->regs[16] & 0xE0) | (Freq_Info1.TF_HPF_BPF) | (Freq_Info1.TF_HPF_CNR << 3);  // R16[2:0], R16[4:3]
	if(r850_wr(priv,16,priv->regs[16])!=0)
		return R850_Fail;


	// RF Polyfilter
	priv->regs[18] = (priv->regs[18] & 0xFC) | (Freq_Info1.RF_POLY);  //R17[6:5] => R18[1:0]
	if(r850_wr(priv,18,priv->regs[18])!=0)
		return R850_Fail;


	// LNA Cap
	priv->regs[14] = (priv->regs[14] & 0x0F) | (Freq_Info1.LPF_CAP<<4);	  //R16[3:0]	=>	R14[7:4]
	if(r850_wr(priv,14,priv->regs[14])!=0)
		return R850_Fail;


	// LNA Notch
	priv->regs[15] = (priv->regs[15] & 0xF0) | (Freq_Info1.LPF_NOTCH);  //R16[7:4]  =>  R15[3:0]
	if(r850_wr(priv,15,priv->regs[15])!=0)
		return R850_Fail;




	//Set_IMR
	if( (priv->R850_IMR_done_flag == TRUE) && (priv->R850_IMR_Cal_Result==0))
	{
	
		Reg_IMR_Gain = priv->imr_data[Freq_Info1.IMR_MEM_NOR].Gain_X & 0x2F;   //R20[4:0] => R20[3:0]
		Reg_IMR_Phase = priv->imr_data[Freq_Info1.IMR_MEM_NOR].Phase_Y & 0x2F; //R21[4:0] => R21[3:0]
		Reg_IMR_Iqcap = priv->imr_data[Freq_Info1.IMR_MEM_NOR].Iqcap;                  //0,1,2
	
	
	}
	else
	{
		Reg_IMR_Gain = 0;
		Reg_IMR_Phase = 0;
		Reg_IMR_Iqcap = 0;
	}

	//Gain, R20[4:0]
	priv->regs[R850_IMR_GAIN_REG] = (priv->regs[R850_IMR_GAIN_REG] & 0xD0) | (Reg_IMR_Gain & 0x2F);
	if(r850_wr(priv,R850_IMR_GAIN_REG,priv->regs[R850_IMR_GAIN_REG])!=0)
		return R850_Fail;

	//Phase, R21[4:0]
	priv->regs[R850_IMR_PHASE_REG] = (priv->regs[R850_IMR_PHASE_REG] & 0xD0) | (Reg_IMR_Phase & 0x2F);
	if(r850_wr(priv,R850_IMR_PHASE_REG,priv->regs[R850_IMR_PHASE_REG])!=0)
		return R850_Fail;


	//Iqcap, R21[7:6]
	priv->regs[R850_IMR_IQCAP_REG] = (priv->regs[R850_IMR_IQCAP_REG] & 0x3F) | (Reg_IMR_Iqcap<<6);
	if(r850_wr(priv,R850_IMR_IQCAP_REG,priv->regs[R850_IMR_IQCAP_REG])!=0)
		return R850_Fail;


	return R850_Success;
}

//-----------------------------------------------------------------------------------/
// Purpose: compare IMR result aray [0][1][2], find min value and store to CorArry[0]
// input: CorArry: three IMR data array
// output: TRUE or FALSE
//-----------------------------------------------------------------------------------/
R850_ErrCode R850_CompreCor(struct R850_SectType* CorArry)
{
	u8 CompCunt = 0;
	struct R850_SectType CorTemp;

	for(CompCunt=3; CompCunt > 0; CompCunt --)
	{
		if(CorArry[0].Value > CorArry[CompCunt - 1].Value) //compare IMR result [0][1][2], find min value
		{
			CorTemp = CorArry[0];
			CorArry[0] = CorArry[CompCunt - 1];
			CorArry[CompCunt - 1] = CorTemp;
		}
	}

	return R850_Success;
}


//-------------------------------------------------------------------------------------//
// Purpose: if (Gain<9 or Phase<9), Gain+1 or Phase+1 and compare with min value
//          new < min => update to min and continue
//          new > min => Exit
// input: StepArry: three IMR data array
//        Pace: gain or phase register
// output: TRUE or FALSE
//-------------------------------------------------------------------------------------//
R850_ErrCode R850_CompreStep(struct r850_priv*priv,  struct R850_SectType* StepArry, u8 Pace)
{
	struct R850_SectType StepTemp;

	//min value already saved in StepArry[0]
	StepTemp.Phase_Y = StepArry[0].Phase_Y;  //whole byte data
	StepTemp.Gain_X = StepArry[0].Gain_X;
	//StepTemp.Iqcap  = StepArry[0].Iqcap;

	while(((StepTemp.Gain_X & 0x0F) < R850_IMR_TRIAL) && ((StepTemp.Phase_Y & 0x0F) < R850_IMR_TRIAL))
	{
		if(Pace == R850_IMR_GAIN_REG)
			StepTemp.Gain_X ++;
		else
			StepTemp.Phase_Y ++;

		if(r850_wr(priv,R850_IMR_GAIN_REG,StepTemp.Gain_X)!=0)
			return R850_Fail;

		if(r850_wr(priv,R850_IMR_PHASE_REG,StepTemp.Phase_Y)!=0)
			return R850_Fail;

		if(R850_Muti_Read(priv, &StepTemp.Value) != R850_Success)
			return R850_Fail;

		if(StepTemp.Value <= StepArry[0].Value)
		{
			StepArry[0].Gain_X  = StepTemp.Gain_X;
			StepArry[0].Phase_Y = StepTemp.Phase_Y;
			//StepArry[0].Iqcap = StepTemp.Iqcap;
			StepArry[0].Value   = StepTemp.Value;
		}
		else if((StepTemp.Value - 2*R850_ADC_READ_COUNT) > StepArry[0].Value)
		{
			break;
		}

	} //end of while()

	return R850_Success;
}

//--------------------------------------------------------------------------------------------
// Purpose: record IMR results by input gain/phase location
//          then adjust gain or phase positive 1 step and negtive 1 step, both record results
// input: FixPot: phase or gain
//        FlucPot phase or gain
//        PotReg: Reg20 or Reg21
//        CompareTree: 3 IMR trace and results
// output: TREU or FALSE
//--------------------------------------------------------------------------------------------
R850_ErrCode R850_IQ_Tree( struct r850_priv *priv,u8 FixPot, u8 FlucPot, u8 PotReg, struct R850_SectType* CompareTree)
{
	u8 TreeCunt  = 0;
	u8 PntReg = 0;

	//PntReg is reg to change; FlucPot is change value
	if(PotReg == R850_IMR_GAIN_REG)
		PntReg = R850_IMR_PHASE_REG; //phase control
	else
		PntReg = R850_IMR_GAIN_REG; //gain control

	for(TreeCunt = 0; TreeCunt<3; TreeCunt ++)
	{

		if(r850_wr(priv,PotReg,FixPot)!=0)
			return R850_Fail;
		if(r850_wr(priv,PntReg,FlucPot)!=0)
			return R850_Fail;

		if(R850_Muti_Read(priv, &CompareTree[TreeCunt].Value) != R850_Success)
			return R850_Fail;

		if(PotReg == R850_IMR_GAIN_REG)
		{
			CompareTree[TreeCunt].Gain_X  = FixPot;
			CompareTree[TreeCunt].Phase_Y = FlucPot;
		}
		else
		{
			CompareTree[TreeCunt].Phase_Y  = FixPot;
			CompareTree[TreeCunt].Gain_X = FlucPot;
		}

		if(TreeCunt == 0)   //try right-side point
		{
			FlucPot ++;
		}
		else if(TreeCunt == 1) //try left-side point
		{
			if((FlucPot & 0x0F) == 1) //if absolute location is 1, change I/Q direction
			{
				if(FlucPot & 0x20) //b[5]:I/Q selection. 0:Q-path, 1:I-path
				{
					//FlucPot = (FlucPot & 0xE0) | 0x01;
					FlucPot = (FlucPot & 0xD0) | 0x01;
				}
				else
				{
					//FlucPot = (FlucPot & 0xE0) | 0x11;
					FlucPot = (FlucPot & 0xD0) | 0x21;
				}
			}
			else
			{
				FlucPot = FlucPot - 2;
			}
		}
	}

	return R850_Success;
}

R850_ErrCode R850_IQ_Tree5(struct r850_priv*priv,  u8 FixPot, u8 FlucPot, u8 PotReg, struct R850_SectType* CompareTree)
{
	u8 TreeCunt  = 0;
	u8 TreeTimes = 5;
	u8 TempPot   = 0;
	u8 PntReg    = 0;
	u8 CompCunt = 0;
	struct R850_SectType CorTemp[5];
	struct R850_SectType Compare_Temp;
	u8 CuntTemp = 0;

	memset(&Compare_Temp,0, sizeof(struct R850_SectType));
	Compare_Temp.Value = 255;

	for(CompCunt=0; CompCunt<3; CompCunt++)
	{
		CorTemp[CompCunt].Gain_X = CompareTree[CompCunt].Gain_X;
		CorTemp[CompCunt].Phase_Y = CompareTree[CompCunt].Phase_Y;
		CorTemp[CompCunt].Value = CompareTree[CompCunt].Value;
	}

	/*
	   if(PotReg == 0x08)
	   PntReg = 0x09; //phase control
	   else
	   PntReg = 0x08; //gain control
	   */

	//PntReg is reg to change; FlucPot is change value
	if(PotReg == R850_IMR_GAIN_REG)
		PntReg = R850_IMR_PHASE_REG; //phase control
	else
		PntReg = R850_IMR_GAIN_REG; //gain control




	for(TreeCunt = 0;TreeCunt < TreeTimes;TreeCunt++)
	{
		if(r850_wr(priv,PotReg,FixPot) != 0)
			return R850_Fail;
		if(r850_wr(priv,PntReg,FlucPot) != 0)
			return R850_Fail;

		if(R850_Muti_Read( priv,&CorTemp[TreeCunt].Value) != R850_Success)
			return R850_Fail;

		if(PotReg == R850_IMR_GAIN_REG)
		{
			CorTemp[TreeCunt].Gain_X  = FixPot;
			CorTemp[TreeCunt].Phase_Y = FlucPot;
		}
		else
		{
			CorTemp[TreeCunt].Phase_Y  = FixPot;
			CorTemp[TreeCunt].Gain_X = FlucPot;
		}

		if(TreeCunt == 0)   //next try right-side 1 point
		{
			FlucPot ++;     //+1
		}
		else if(TreeCunt == 1)   //next try right-side 2 point
		{
			FlucPot ++;     //1+1=2
		}
		else if(TreeCunt == 2)   //next try left-side 1 point
		{
			if((FlucPot & 0x0F) == 0x02) //if absolute location is 2, change I/Q direction and set to 1
			{
				TempPot = 1;
				if((FlucPot & 0x20)==0x20) //b[5]:I/Q selection. 0:Q-path, 1:I-path
				{
					FlucPot = (FlucPot & 0xD0) | 0x01;  //Q1
				}
				else
				{
					FlucPot = (FlucPot & 0xD0) | 0x21;  //I1
				}
			}
			else
			{
				FlucPot -= 3;  //+2-3=-1
			}
		}
		else if(TreeCunt == 3) //next try left-side 2 point
		{
			if(TempPot==1)  //been chnaged I/Q
			{
				FlucPot += 1;
			}
			else if((FlucPot & 0x0F) == 0x00) //if absolute location is 0, change I/Q direction
			{
				TempPot = 1;
				if((FlucPot & 0x20)==0x20) //b[5]:I/Q selection. 0:Q-path, 1:I-path
				{
					FlucPot = (FlucPot & 0xD0) | 0x01;  //Q1
				}
				else
				{
					FlucPot = (FlucPot & 0xD0) | 0x21;  //I1
				}
			}
			else
			{
				FlucPot -= 1;  //-1-1=-2
			}
		}

		if(CorTemp[TreeCunt].Value < Compare_Temp.Value)
		{
			Compare_Temp.Value = CorTemp[TreeCunt].Value;
			Compare_Temp.Gain_X = CorTemp[TreeCunt].Gain_X;
			Compare_Temp.Phase_Y = CorTemp[TreeCunt].Phase_Y;
			CuntTemp = TreeCunt;
		}
	}


	//CompareTree[0].Gain_X = CorTemp[CuntTemp].Gain_X;
	//CompareTree[0].Phase_Y = CorTemp[CuntTemp].Phase_Y;
	//CompareTree[0].Value = CorTemp[CuntTemp].Value;

	for(CompCunt=0; CompCunt<3; CompCunt++)
	{
		if(CuntTemp==3 || CuntTemp==4)
		{
			CompareTree[CompCunt].Gain_X = CorTemp[2+CompCunt].Gain_X;  //2,3,4
			CompareTree[CompCunt].Phase_Y = CorTemp[2+CompCunt].Phase_Y;
			CompareTree[CompCunt].Value = CorTemp[2+CompCunt].Value;
		}
		else
		{
			CompareTree[CompCunt].Gain_X = CorTemp[CompCunt].Gain_X;    //0,1,2
			CompareTree[CompCunt].Phase_Y = CorTemp[CompCunt].Phase_Y;
			CompareTree[CompCunt].Value = CorTemp[CompCunt].Value;
		}

	}

	return R850_Success;
}

R850_ErrCode R850_Section(struct r850_priv*priv,  struct R850_SectType* IQ_Pont)
{
	struct R850_SectType Compare_IQ[3];
	struct R850_SectType Compare_Bet[3];

	//Try X-1 column and save min result to Compare_Bet[0]
	if((IQ_Pont->Gain_X & 0x0F) == 0x00)
	{
		Compare_IQ[0].Gain_X = ((IQ_Pont->Gain_X) & 0xDF) + 1;  //Q-path, Gain=1
	}
	else
	{
		Compare_IQ[0].Gain_X  = IQ_Pont->Gain_X - 1;  //left point
	}
	Compare_IQ[0].Phase_Y = IQ_Pont->Phase_Y;

	if(R850_IQ_Tree(priv, Compare_IQ[0].Gain_X, Compare_IQ[0].Phase_Y, R850_IMR_GAIN_REG, &Compare_IQ[0]) != R850_Success)  // y-direction
		return R850_Fail;

	if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	Compare_Bet[0].Gain_X = Compare_IQ[0].Gain_X;
	Compare_Bet[0].Phase_Y = Compare_IQ[0].Phase_Y;
	Compare_Bet[0].Value = Compare_IQ[0].Value;

	//Try X column and save min result to Compare_Bet[1]
	Compare_IQ[0].Gain_X = IQ_Pont->Gain_X;
	Compare_IQ[0].Phase_Y = IQ_Pont->Phase_Y;

	if(R850_IQ_Tree(priv, Compare_IQ[0].Gain_X, Compare_IQ[0].Phase_Y, R850_IMR_GAIN_REG, &Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	Compare_Bet[1].Gain_X = Compare_IQ[0].Gain_X;
	Compare_Bet[1].Phase_Y = Compare_IQ[0].Phase_Y;
	Compare_Bet[1].Value = Compare_IQ[0].Value;

	//Try X+1 column and save min result to Compare_Bet[2]
	if((IQ_Pont->Gain_X & 0x0F) == 0x00)
		Compare_IQ[0].Gain_X = ((IQ_Pont->Gain_X) | 0x20) + 1;  //I-path, Gain=1
	else
		Compare_IQ[0].Gain_X = IQ_Pont->Gain_X + 1;
	Compare_IQ[0].Phase_Y = IQ_Pont->Phase_Y;

	if(R850_IQ_Tree(priv, Compare_IQ[0].Gain_X, Compare_IQ[0].Phase_Y, R850_IMR_GAIN_REG, &Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	Compare_Bet[2].Gain_X = Compare_IQ[0].Gain_X;
	Compare_Bet[2].Phase_Y = Compare_IQ[0].Phase_Y;
	Compare_Bet[2].Value = Compare_IQ[0].Value;

	if(R850_CompreCor(&Compare_Bet[0]) != R850_Success)
		return R850_Fail;

	*IQ_Pont = Compare_Bet[0];

	return R850_Success;
}
R850_ErrCode R850_IMR_Iqcap(struct r850_priv*priv, struct R850_SectType* IQ_Point)
{
	struct R850_SectType Compare_Temp;
	int i = 0;

	//Set Gain/Phase to right setting
	if(r850_wr( priv,R850_IMR_GAIN_REG,IQ_Point->Gain_X) != 0)
		return R850_Fail;

	if(r850_wr( priv,R850_IMR_PHASE_REG,IQ_Point->Phase_Y) != 0)
		return R850_Fail;

	//try iqcap
	for(i=0; i<3; i++)
	{
		Compare_Temp.Iqcap = (u8) i;
		priv->regs[R850_IMR_IQCAP_REG] = (priv->regs[R850_IMR_IQCAP_REG] & 0x3F) | (Compare_Temp.Iqcap<<6);
		if(r850_wr( priv,R850_IMR_IQCAP_REG,priv->regs[R850_IMR_IQCAP_REG]) != 0)
			return R850_Fail;



		if(R850_Muti_Read(priv, &(Compare_Temp.Value)) != R850_Success)
			return R850_Fail;

		if(Compare_Temp.Value < IQ_Point->Value)
		{
			IQ_Point->Value = Compare_Temp.Value;
			IQ_Point->Iqcap = Compare_Temp.Iqcap;  //0, 1, 2
		}
		else if(Compare_Temp.Value == IQ_Point->Value)
		{
			IQ_Point->Value = Compare_Temp.Value;
			IQ_Point->Iqcap = Compare_Temp.Iqcap;  //0, 1, 2
		}
	}

	return R850_Success;
}

R850_ErrCode R850_IMR_Cross( struct r850_priv*priv,struct R850_SectType* IQ_Pont, u8* X_Direct)
{

	struct R850_SectType Compare_Cross[9]; //(0,0)(0,Q-1)(0,I-1)(Q-1,0)(I-1,0)+(0,Q-2)(0,I-2)(Q-2,0)(I-2,0)
	struct R850_SectType Compare_Temp;
	u8 CrossCount = 0;
	u8 RegGain = priv->regs[R850_IMR_GAIN_REG] & 0xD0;
	u8 RegPhase = priv->regs[R850_IMR_PHASE_REG] & 0xD0;

	//memset(&Compare_Temp,0, sizeof(R850_SectType));
	Compare_Temp.Gain_X = 0;
	Compare_Temp.Phase_Y = 0;
	Compare_Temp.Iqcap = 0;
	Compare_Temp.Value = 255;

	for(CrossCount=0; CrossCount<9; CrossCount++)
	{

		if(CrossCount==0)
		{
			Compare_Cross[CrossCount].Gain_X = RegGain;
			Compare_Cross[CrossCount].Phase_Y = RegPhase;
		}
		else if(CrossCount==1)
		{
			Compare_Cross[CrossCount].Gain_X = RegGain;       //0
			Compare_Cross[CrossCount].Phase_Y = RegPhase + 1;  //Q-1
		}
		else if(CrossCount==2)
		{
			Compare_Cross[CrossCount].Gain_X = RegGain;               //0
			Compare_Cross[CrossCount].Phase_Y = (RegPhase | 0x20) + 1; //I-1
		}
		else if(CrossCount==3)
		{
			Compare_Cross[CrossCount].Gain_X = RegGain + 1; //Q-1
			Compare_Cross[CrossCount].Phase_Y = RegPhase;
		}
		else if(CrossCount==4)
		{
			//Compare_Cross[CrossCount].Gain_X = (RegGain | 0x10) + 1; //I-1
			Compare_Cross[CrossCount].Gain_X = (RegGain | 0x20) + 1; //I-1
			Compare_Cross[CrossCount].Phase_Y = RegPhase;
		}
		else if(CrossCount==5)
		{
			Compare_Cross[CrossCount].Gain_X = RegGain;       //0
			Compare_Cross[CrossCount].Phase_Y = RegPhase + 2;  //Q-2
		}
		else if(CrossCount==6)
		{
			Compare_Cross[CrossCount].Gain_X = RegGain;               //0
			Compare_Cross[CrossCount].Phase_Y = (RegPhase | 0x20) + 2; //I-2
		}
		else if(CrossCount==7)
		{
			Compare_Cross[CrossCount].Gain_X = RegGain + 2; //Q-2
			Compare_Cross[CrossCount].Phase_Y = RegPhase;
		}
		else if(CrossCount==8)
		{
			Compare_Cross[CrossCount].Gain_X = (RegGain | 0x20) + 2; //I-2
			Compare_Cross[CrossCount].Phase_Y = RegPhase;
		}

	//	R850_I2C.RegAddr = R850_IMR_GAIN_REG;
	//	R850_I2C.Data = Compare_Cross[CrossCount].Gain_X;
		if(r850_wr(priv,R850_IMR_GAIN_REG,Compare_Cross[CrossCount].Gain_X)!=0)
			return R850_Fail;


//		R850_I2C.RegAddr = R850_IMR_PHASE_REG;
//		R850_I2C.Data = Compare_Cross[CrossCount].Phase_Y;
		if(r850_wr(priv,R850_IMR_PHASE_REG,Compare_Cross[CrossCount].Phase_Y)!=0)
			return R850_Fail;


		if(R850_Muti_Read(priv, &Compare_Cross[CrossCount].Value) != R850_Success)
			return R850_Fail;

		if( Compare_Cross[CrossCount].Value < Compare_Temp.Value)
		{
			Compare_Temp.Value = Compare_Cross[CrossCount].Value;
			Compare_Temp.Gain_X = Compare_Cross[CrossCount].Gain_X;
			Compare_Temp.Phase_Y = Compare_Cross[CrossCount].Phase_Y;
		}
	} //end for loop


	if(((Compare_Temp.Phase_Y & 0x2F)==0x01) || (Compare_Temp.Phase_Y & 0x2F)==0x02)  //phase Q1 or Q2
	{
		*X_Direct = (u8) 0;
		IQ_Pont[0].Gain_X = Compare_Cross[0].Gain_X;    //0
		IQ_Pont[0].Phase_Y = Compare_Cross[0].Phase_Y; //0
		IQ_Pont[0].Value = Compare_Cross[0].Value;

		IQ_Pont[1].Gain_X = Compare_Cross[1].Gain_X;    //0
		IQ_Pont[1].Phase_Y = Compare_Cross[1].Phase_Y; //Q1
		IQ_Pont[1].Value = Compare_Cross[1].Value;

		IQ_Pont[2].Gain_X = Compare_Cross[5].Gain_X;   //0
		IQ_Pont[2].Phase_Y = Compare_Cross[5].Phase_Y;//Q2
		IQ_Pont[2].Value = Compare_Cross[5].Value;
	}
	else if(((Compare_Temp.Phase_Y & 0x2F)==0x21) || (Compare_Temp.Phase_Y & 0x2F)==0x22)  //phase I1 or I2
	{
		*X_Direct = (u8) 0;
		IQ_Pont[0].Gain_X = Compare_Cross[0].Gain_X;    //0
		IQ_Pont[0].Phase_Y = Compare_Cross[0].Phase_Y; //0
		IQ_Pont[0].Value = Compare_Cross[0].Value;

		IQ_Pont[1].Gain_X = Compare_Cross[2].Gain_X;    //0
		IQ_Pont[1].Phase_Y = Compare_Cross[2].Phase_Y; //Q1
		IQ_Pont[1].Value = Compare_Cross[2].Value;

		IQ_Pont[2].Gain_X = Compare_Cross[6].Gain_X;   //0
		IQ_Pont[2].Phase_Y = Compare_Cross[6].Phase_Y;//Q2
		IQ_Pont[2].Value = Compare_Cross[6].Value;
	}
	else if(((Compare_Temp.Gain_X & 0x2F)==0x01) || (Compare_Temp.Gain_X & 0x2F)==0x02)  //gain Q1 or Q2
	{
		*X_Direct = (u8) 1;
		IQ_Pont[0].Gain_X = Compare_Cross[0].Gain_X;    //0
		IQ_Pont[0].Phase_Y = Compare_Cross[0].Phase_Y; //0
		IQ_Pont[0].Value = Compare_Cross[0].Value;

		IQ_Pont[1].Gain_X = Compare_Cross[3].Gain_X;    //Q1
		IQ_Pont[1].Phase_Y = Compare_Cross[3].Phase_Y; //0
		IQ_Pont[1].Value = Compare_Cross[3].Value;

		IQ_Pont[2].Gain_X = Compare_Cross[7].Gain_X;   //Q2
		IQ_Pont[2].Phase_Y = Compare_Cross[7].Phase_Y;//0
		IQ_Pont[2].Value = Compare_Cross[7].Value;
	}
	else if(((Compare_Temp.Gain_X & 0x2F)==0x21) || (Compare_Temp.Gain_X & 0x2F)==0x22)  //gain I1 or I2
	{
		*X_Direct = (u8) 1;
		IQ_Pont[0].Gain_X = Compare_Cross[0].Gain_X;    //0
		IQ_Pont[0].Phase_Y = Compare_Cross[0].Phase_Y; //0
		IQ_Pont[0].Value = Compare_Cross[0].Value;

		IQ_Pont[1].Gain_X = Compare_Cross[4].Gain_X;    //I1
		IQ_Pont[1].Phase_Y = Compare_Cross[4].Phase_Y; //0
		IQ_Pont[1].Value = Compare_Cross[4].Value;

		IQ_Pont[2].Gain_X = Compare_Cross[8].Gain_X;   //I2
		IQ_Pont[2].Phase_Y = Compare_Cross[8].Phase_Y;//0
		IQ_Pont[2].Value = Compare_Cross[8].Value;
	}
	else //(0,0)
	{
		*X_Direct = (u8) 1;
		IQ_Pont[0].Gain_X = Compare_Cross[0].Gain_X;
		IQ_Pont[0].Phase_Y = Compare_Cross[0].Phase_Y;
		IQ_Pont[0].Value = Compare_Cross[0].Value;

		IQ_Pont[1].Gain_X = Compare_Cross[3].Gain_X;    //Q1
		IQ_Pont[1].Phase_Y = Compare_Cross[3].Phase_Y; //0
		IQ_Pont[1].Value = Compare_Cross[3].Value;

		IQ_Pont[2].Gain_X = Compare_Cross[4].Gain_X;   //I1
		IQ_Pont[2].Phase_Y = Compare_Cross[4].Phase_Y; //0
		IQ_Pont[2].Value = Compare_Cross[4].Value;
	}
	return R850_Success;
}


R850_ErrCode R850_IQ( struct r850_priv*priv, struct R850_SectType* IQ_Pont)
{
	struct R850_SectType Compare_IQ[3];
	u8   X_Direction;  // 1:X, 0:Y

	//------- increase Filter gain max to let ADC read value significant ---------//

	priv->regs[41] = (priv->regs[41] | 0xF0);
	if(r850_wr(priv,41,priv->regs[41])!=0)
		return R850_Fail;



	//give a initial value, no useful
	Compare_IQ[0].Gain_X  = priv->regs[R850_IMR_GAIN_REG] & 0xD0;
	Compare_IQ[0].Phase_Y = priv->regs[R850_IMR_PHASE_REG] & 0xD0;


	// Determine X or Y
	if(R850_IMR_Cross( priv,&Compare_IQ[0], &X_Direction) != R850_Success)
		return R850_Fail;

	if(X_Direction==1)
	{
		//compare and find min of 3 points. determine I/Q direction
		if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
			return R850_Fail;

		//increase step to find min value of this direction
		if(R850_CompreStep(priv, &Compare_IQ[0], R850_IMR_GAIN_REG) != R850_Success)  //X
			return R850_Fail;
	}
	else
	{
		//compare and find min of 3 points. determine I/Q direction
		if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
			return R850_Fail;

		//increase step to find min value of this direction
		if(R850_CompreStep(priv, &Compare_IQ[0], R850_IMR_PHASE_REG) != R850_Success)  //Y
			return R850_Fail;
	}

	//Another direction
	if(X_Direction==1) //Y-direct
	{
		// if(R850_IQ_Tree( Compare_IQ[0].Gain_X, Compare_IQ[0].Phase_Y, R850_IMR_GAIN_REG, &Compare_IQ[0]) != R850_Success) //Y
		if(R850_IQ_Tree5( priv,Compare_IQ[0].Gain_X, Compare_IQ[0].Phase_Y, R850_IMR_GAIN_REG, &Compare_IQ[0]) != R850_Success) //Y

			return R850_Fail;

		//compare and find min of 3 points. determine I/Q direction
		if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
			return R850_Fail;

		//increase step to find min value of this direction
		if(R850_CompreStep(priv, &Compare_IQ[0], R850_IMR_PHASE_REG) != R850_Success)  //Y
			return R850_Fail;
	}
	else //X-direct
	{
		// if(R850_IQ_Tree( Compare_IQ[0].Phase_Y, Compare_IQ[0].Gain_X, R850_IMR_PHASE_REG, &Compare_IQ[0]) != R850_Success) //X
		if(R850_IQ_Tree5(priv,Compare_IQ[0].Phase_Y, Compare_IQ[0].Gain_X, R850_IMR_PHASE_REG, &Compare_IQ[0]) != R850_Success) //X
			return R850_Fail;

		//compare and find min of 3 points. determine I/Q direction
		if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
			return R850_Fail;

		//increase step to find min value of this direction
		if(R850_CompreStep(priv, &Compare_IQ[0], R850_IMR_GAIN_REG) != R850_Success) //X
			return R850_Fail;
	}


	//--- Check 3 points again---//
	if(X_Direction==1)  //X-direct
	{
		if(R850_IQ_Tree(priv, Compare_IQ[0].Phase_Y, Compare_IQ[0].Gain_X, R850_IMR_PHASE_REG, &Compare_IQ[0]) != R850_Success) //X
			return R850_Fail;
	}
	else  //Y-direct
	{
		if(R850_IQ_Tree(priv,  Compare_IQ[0].Gain_X, Compare_IQ[0].Phase_Y, R850_IMR_GAIN_REG, &Compare_IQ[0]) != R850_Success) //Y
			return R850_Fail;
	}

	if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	//Section-9 check
	if(R850_Section(priv,  &Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	//clear IQ_Cap = 0
	//Compare_IQ[0].Iqcap = priv->regs[R850_IMR_IQCAP_REG] & 0x3F;
	Compare_IQ[0].Iqcap = 0;

	if(R850_IMR_Iqcap(priv,  &Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	*IQ_Pont = Compare_IQ[0];

	//reset gain/phase/iqcap control setting
	//R850_I2C.RegAddr = R850_IMR_GAIN_REG;
	priv->regs[R850_IMR_GAIN_REG] = priv->regs[R850_IMR_GAIN_REG] & 0xD0;
	if(r850_wr(priv,R850_IMR_GAIN_REG,priv->regs[R850_IMR_GAIN_REG])!=0)
		return R850_Fail;


	priv->regs[R850_IMR_PHASE_REG] = priv->regs[R850_IMR_PHASE_REG] & 0xD0;
	if(r850_wr(priv,R850_IMR_PHASE_REG,priv->regs[R850_IMR_PHASE_REG])!=0)
		return R850_Fail;


	priv->regs[R850_IMR_IQCAP_REG] = priv->regs[R850_IMR_IQCAP_REG] & 0x3F;
	if(r850_wr(priv,R850_IMR_IQCAP_REG,priv->regs[R850_IMR_IQCAP_REG])!=0)
		return R850_Fail;


	return R850_Success;
}






//----------------------------------------------------------------------------------------//
// purpose: search surrounding points from previous point
//          try (x-1), (x), (x+1) columns, and find min IMR result point
// input: IQ_Pont: previous point data(IMR Gain, Phase, ADC Result, RefRreq)
//                 will be updated to final best point
// output: TRUE or FALSE
//----------------------------------------------------------------------------------------//
R850_ErrCode R850_F_IMR(struct r850_priv *priv, struct R850_SectType* IQ_Pont)
{
	struct R850_SectType Compare_IQ[3];
	struct R850_SectType Compare_Bet[3];

	//------- increase Filter gain max to let ADC read value significant ---------//
	priv->regs[41] = (priv->regs[41] | 0xF0);
	if(r850_wr(priv,41,priv->regs[41]) != 0)
		return R850_Fail;

	//Try X-1 column and save min result to Compare_Bet[0]
	if((IQ_Pont->Gain_X & 0x0F) == 0x00)
	{
		Compare_IQ[0].Gain_X = ((IQ_Pont->Gain_X) & 0xDF) + 1;  //Q-path, Gain=1
	}
	else
	{
		Compare_IQ[0].Gain_X  = IQ_Pont->Gain_X - 1;  //left point
	}
	Compare_IQ[0].Phase_Y = IQ_Pont->Phase_Y;

	if(R850_IQ_Tree(priv, Compare_IQ[0].Gain_X, Compare_IQ[0].Phase_Y, R850_IMR_GAIN_REG, &Compare_IQ[0]) != R850_Success)  // y-direction
		return R850_Fail;

	if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	Compare_Bet[0].Gain_X = Compare_IQ[0].Gain_X;
	Compare_Bet[0].Phase_Y = Compare_IQ[0].Phase_Y;
	Compare_Bet[0].Value = Compare_IQ[0].Value;

	//Try X column and save min result to Compare_Bet[1]
	Compare_IQ[0].Gain_X = IQ_Pont->Gain_X;
	Compare_IQ[0].Phase_Y = IQ_Pont->Phase_Y;

	if(R850_IQ_Tree(priv, Compare_IQ[0].Gain_X, Compare_IQ[0].Phase_Y, R850_IMR_GAIN_REG, &Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	Compare_Bet[1].Gain_X = Compare_IQ[0].Gain_X;
	Compare_Bet[1].Phase_Y = Compare_IQ[0].Phase_Y;
	Compare_Bet[1].Value = Compare_IQ[0].Value;

	//Try X+1 column and save min result to Compare_Bet[2]
	if((IQ_Pont->Gain_X & 0x0F) == 0x00)
		Compare_IQ[0].Gain_X = ((IQ_Pont->Gain_X) | 0x20) + 1;  //I-path, Gain=1
	else
		Compare_IQ[0].Gain_X = IQ_Pont->Gain_X + 1;
	Compare_IQ[0].Phase_Y = IQ_Pont->Phase_Y;

	if(R850_IQ_Tree(priv, Compare_IQ[0].Gain_X, Compare_IQ[0].Phase_Y, R850_IMR_GAIN_REG, &Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	if(R850_CompreCor(&Compare_IQ[0]) != R850_Success)
		return R850_Fail;

	Compare_Bet[2].Gain_X = Compare_IQ[0].Gain_X;
	Compare_Bet[2].Phase_Y = Compare_IQ[0].Phase_Y;
	Compare_Bet[2].Value = Compare_IQ[0].Value;

	if(R850_CompreCor(&Compare_Bet[0]) != R850_Success)
		return R850_Fail;

	//clear IQ_Cap = 0
	//Compare_Bet[0].Iqcap = priv->regs[3] & 0xFC;
	Compare_Bet[0].Iqcap = 0;

	if(R850_IMR_Iqcap(priv, &Compare_Bet[0]) != R850_Success)
		return R850_Fail;

	*IQ_Pont = Compare_Bet[0];

	return R850_Success;
}



R850_ErrCode R850_InitReg(struct r850_priv *priv)//ok
{
	u8 InitArrayCunt = 0;


	//Write Full Table, Set Xtal Power = highest at initial
	//R850_I2C_Len.RegAddr = 0;
	//R850_I2C_Len.Len = R850_REG_NUM;
	u8 XtalCap;
	u8 Capx;
	u8 Capx_3_0, Capxx;
	int ret=0;
	
	if(priv->R850_clock_out==1)
	{
		if(priv->R850_Xtal_cap>31)
		{
			XtalCap = 1;  //10
			Capx = priv->R850_Xtal_cap-10;
		}
		else
		{
			XtalCap = 0; //0
			Capx = priv->R850_Xtal_cap;
		}

		Capxx = Capx & 0x01;
		Capx_3_0 = Capx >> 1;

		// Set Xtal Cap  R33[6:3], R34[3]     XtalCap => R33[7]
		R850_iniArray[0][33] = 0x01  | (Capx_3_0 << 3) | ( XtalCap << 7);
		R850_iniArray[1][33] = 0x01  | (Capx_3_0 << 3) | ( XtalCap << 7);
		R850_iniArray[2][33] = 0x01  | (Capx_3_0 << 3) | ( XtalCap << 7);
		// Set GM=strong
		R850_iniArray[0][34] = 0x04 | (Capxx << 3);
		R850_iniArray[1][34] = 0x04 | (Capxx << 3);
		R850_iniArray[2][34] = 0x04 | (Capxx << 3);
	}
	else
	{
		R850_iniArray[0][33]= 0x01;
		R850_iniArray[1][33]= 0x01;
		R850_iniArray[2][33]= 0x01;

		R850_iniArray[0][34]= 0x74;
		R850_iniArray[1][34]= 0x74;
		R850_iniArray[2][34]= 0x74;

	}



	if(priv->cfg->R850_Xtal == 24000)
	{
		for(InitArrayCunt = 8; InitArrayCunt<R850_REG_NUM; InitArrayCunt ++)
		{
			//R850_I2C_Len.Data[InitArrayCunt] = R850_iniArray[0][InitArrayCunt];
			priv->regs[InitArrayCunt] = R850_iniArray[0][InitArrayCunt];
		}
	}
	else if(priv->cfg->R850_Xtal == 16000)
	{
		for(InitArrayCunt = 8; InitArrayCunt<R850_REG_NUM; InitArrayCunt ++)
		{
			//R850_I2C_Len.Data[InitArrayCunt] = R850_iniArray[1][InitArrayCunt];
			priv->regs[InitArrayCunt] = R850_iniArray[1][InitArrayCunt];
		}
	}
	else if(priv->cfg->R850_Xtal == 27000)
	{
		for(InitArrayCunt = 8; InitArrayCunt<R850_REG_NUM; InitArrayCunt ++)
		{
			//R850_I2C_Len.Data[InitArrayCunt] = R850_iniArray[2][InitArrayCunt];
			priv->regs[InitArrayCunt] = R850_iniArray[2][InitArrayCunt];
		}
	}
	else
	{
		//no support now
		return R850_Fail;
	}


//Xtal cap

    if(priv->R850_clock_out == 1)
    {
	    R850_SetXtalPW( priv, R850_XTAL_HIGHEST);
		R850_SetXtalCap_No_Write(priv,  priv->R850_Xtal_cap);
    }
	else if(priv->R850_clock_out == 0)
	{
		R850_SetXtalPW(priv,  R850_XTAL_LOWEST);
		R850_SetXtalCap_No_Write(priv, 0);
		//gm off
		R850_Set_XTAL_GM(priv, 1); //3:xtal gm off
	}
	else
	{
		R850_SetXtalCap_No_Write(priv,  priv->R850_Xtal_cap);
	}

	ret = r850_wrm(priv,8,&priv->regs[8],40);
	if(ret!=0)
		return R850_Fail;

	return R850_Success;
}

R850_ErrCode R850_Cal_Prepare(struct r850_priv *priv,u8 u1CalFlag)
{
	//R850_Cal_Info_Type  Cal_Info;
	u8   InitArrayCunt = 0;

	//Write Full Table, include PLL & RingPLL all settings
	 //R850_I2C_Len.RegAddr = 0;
	 //R850_I2C_Len.Len = R850_REG_NUM;

	int ret = 0;

	switch(u1CalFlag)
	{
		case R850_IMR_CAL:
			if(priv->cfg->R850_Xtal == 24000)
			{
				//542MHz
				for(InitArrayCunt = 8; InitArrayCunt<R850_REG_NUM; InitArrayCunt ++)
				{
				//	R850_I2C_Len.Data[InitArrayCunt] = R850_IMR_CAL_Array[0][InitArrayCunt];
					priv->regs[InitArrayCunt] = R850_IMR_CAL_Array[0][InitArrayCunt];
				}
			}
			else if(priv->cfg->R850_Xtal == 16000)
			{
				//542MHz
				for(InitArrayCunt = 8; InitArrayCunt<R850_REG_NUM; InitArrayCunt ++)
				{
				//	R850_I2C_Len.Data[InitArrayCunt] = R850_IMR_CAL_Array[1][InitArrayCunt];
					priv->regs[InitArrayCunt] = R850_IMR_CAL_Array[1][InitArrayCunt];
				}
			}
			else if(priv->cfg->R850_Xtal == 27000)
			{
				//542MHz
				for(InitArrayCunt = 8; InitArrayCunt<R850_REG_NUM; InitArrayCunt ++)
				{
			//		R850_I2C_Len.Data[InitArrayCunt] = R850_IMR_CAL_Array[2][InitArrayCunt];
					priv->regs[InitArrayCunt] = R850_IMR_CAL_Array[2][InitArrayCunt];
				}
			}
			else
			{
				//no support now
				return R850_Fail;
			}
			break;

		case R850_IMR_LNA_CAL:

			break;

		case R850_LPF_CAL:

			if(priv->cfg->R850_Xtal == 24000)
			{
				for(InitArrayCunt = 8; InitArrayCunt<R850_REG_NUM; InitArrayCunt ++)
				{
				//	R850_I2C_Len.Data[InitArrayCunt] = R850_LPF_CAL_Array[0][InitArrayCunt];
					priv->regs[InitArrayCunt] = R850_LPF_CAL_Array[0][InitArrayCunt];
				}
			}
			else if(priv->cfg->R850_Xtal == 16000)
			{
				for(InitArrayCunt = 8; InitArrayCunt<R850_REG_NUM; InitArrayCunt ++)
				{
				//	R850_I2C_Len.Data[InitArrayCunt] = R850_LPF_CAL_Array[1][InitArrayCunt];
					priv->regs[InitArrayCunt] = R850_LPF_CAL_Array[1][InitArrayCunt];
				}
			}
			else if(priv->cfg->R850_Xtal == 27000)
			{
				for(InitArrayCunt = 8; InitArrayCunt<R850_REG_NUM; InitArrayCunt ++)
				{
				//	R850_I2C_Len.Data[InitArrayCunt] = R850_LPF_CAL_Array[2][InitArrayCunt];
					priv->regs[InitArrayCunt] = R850_LPF_CAL_Array[2][InitArrayCunt];
				}
			}
			else
			{
				//no support 27MHz now
				return R850_Fail;
			}
			break;

		default:
			break;

	}


//Xtal cap
	if(priv->R850_clock_out == 1)
	{
		R850_SetXtalPW(priv, R850_XTAL_HIGHEST);
		R850_SetXtalCap_No_Write( priv, priv->R850_Xtal_cap);
	}
	else if(priv->R850_clock_out == 0)
	{
		R850_SetXtalPW(priv, R850_XTAL_LOWEST);
		R850_SetXtalCap_No_Write(priv, 0);
		//gm off
		R850_Set_XTAL_GM(priv,  1); //3:xtal gm off
	}
	else
	{
		R850_SetXtalCap_No_Write(priv, priv->R850_Xtal_cap);
	}

	ret = r850_wrm(priv,8,&priv->regs[8],40);
	if(ret)
		return R850_Fail;
	
	return R850_Success;
}


R850_ErrCode R850_IMR(struct r850_priv* priv, u8 IMR_MEM, u8 IM_Flag)
{

	//-------------------------------------------------------------------
	//to do
	u32 RingVCO = 0;
	u32 RingFreq = 0;
	u32 RingRef = priv->cfg->R850_Xtal;
	u8  divnum_ring = 0;
	//u8  u1MixerGain = 6;  //fix at initial test

	u8  IMR_Gain = 0;
	u8  IMR_Phase = 0;
	struct R850_SectType IMR_POINT;

	//priv->regs[24] &= 0x3F;    //clear ring_div1, R24[7:6]
	//priv->regs[25] &= 0xFC;   //clear ring_div2, R25[1:0]

	if(priv->cfg->R850_Xtal==24000)  //24M
	{
		divnum_ring = 17;
	}
	else if(priv->cfg->R850_Xtal==16000) //16M
	{
		divnum_ring = 25;                    //3200/8/16.  32>divnum>7
	}
	else if(priv->cfg->R850_Xtal==27000) //27M
	{
		divnum_ring = 15;                    //3200/8/16.  32>divnum>7
	}
	else //not support
	{
		return R850_Fail;
	}

	RingVCO = (divnum_ring)* 8 * RingRef;
	RingFreq = RingVCO/48;

	switch(IMR_MEM)
	{
		case 0: // RingFreq = 136.0M  (16M, 24M) ;  RingFreq = 135.0M (27M) ;
			RingFreq = RingVCO/24;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x02;  // ring_div1 /6 (2)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x08;  // ring_div2 /4 (2)	R35[1:0] => R36[3:2]
			break;
		case 1: // RingFreq = 326M  (16M, 24M) ;  RingFreq = 324.0M (27M) ;
			RingFreq = RingVCO/10;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x01;  // ring_div1 /5 (1)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x04;  // ring_div2 /2 (1)	R35[1:0] => R36[3:2]
			break;
		case 2: // RingFreq = 544M  (16M, 24M) ;  RingFreq = 540.0M (27M) ;
			RingFreq = RingVCO/6;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x02;  // ring_div1 /6 (2)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x00;  // ring_div2 /1 (0)	R35[1:0] => R36[3:2]
			break;
		case 3: // RingFreq = 816M  (16M, 24M) ;  RingFreq = 810.0M (27M) ;
			RingFreq = RingVCO/4;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x00;  // ring_div1 /4 (0)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x00;  // ring_div2 /1 (0)	R35[1:0] => R36[3:2]
			break;
		case 4: // RingFreq = 200M  (16M, 24M) ;  RingFreq = 202M (27M) ;
			RingFreq = RingVCO/16;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x00;  // ring_div1 /4 (0)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x08;  // ring_div2 /4 (2)	R35[1:0] => R36[3:2]
			break;
		case 5: // RingFreq = 136M  (16M, 24M) ;  RingFreq = 135.0M (27M) ;
			RingFreq = RingVCO/24;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x02;  // ring_div1 /6 (2)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x08;  // ring_div2 /4 (2)	R35[1:0] => R36[3:2]
			break;
		case 6: // RingFreq = 326M  (16M, 24M) ;  RingFreq = 324.0M (27M) ;
			RingFreq = RingVCO/10;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x01;  // ring_div1 /5 (1)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x04;  // ring_div2 /2 (1)	R35[1:0] => R36[3:2]
			break;
		case 7: // RingFreq = 544M  (16M, 24M) ;  RingFreq = 540.0M (27M) ;
			RingFreq = RingVCO/6;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x02;  // ring_div1 /6 (2)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x00;  // ring_div2 /1 (0)	R35[1:0] => R36[3:2]
			break;
		case 8: // RingFreq = 816M  (16M, 24M) ;  RingFreq = 810.0M (27M) ;
			RingFreq = RingVCO/4;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x00;  // ring_div1 /4 (0)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x00;  // ring_div2 /1 (0)	R35[1:0] => R36[3:2]
			break;
		case 9: // RingFreq = 200M  (16M, 24M) ;  RingFreq = 202M (27M) ;
			RingFreq = RingVCO/16;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x00;  // ring_div1 /4 (0)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x08;  // ring_div2 /4 (2)	R35[1:0] => R36[3:2]
			break;
		default: // RingFreq = 544M  (16M, 24M) ;  RingFreq = 540.0M (27M) ;
			RingFreq = RingVCO/6;
			priv->regs[36] = (priv->regs[36] & 0xFC) | 0x02;  // ring_div1 /6 (2)	R34[6:5] => R36[1:0]
			priv->regs[36] = (priv->regs[36] & 0xF3) | 0x00;  // ring_div2 /1 (0)	R35[1:0] => R36[3:2]
			break;
	}

	//write RingPLL setting, R34[4:0] => R35[4:0]
	priv->regs[35] = (priv->regs[35] & 0xE0) | divnum_ring;   //ring_div_num, R34[4:0]

	if(RingVCO>=3200000)
		priv->regs[35] = (priv->regs[35] & 0xBF);   //vco_band=high, R34[7]=0 => R35[6]
	else
		priv->regs[35] = (priv->regs[35] | 0x40);      //vco_band=low, R34[7]=1 => R35[6]

	//write RingPLL setting, R35
	if(r850_wr(priv,35,priv->regs[35])!=0)
		return R850_Fail;

	//write RingPLL setting, R36
	if(r850_wr(priv,36,priv->regs[36])!=0)
		return R850_Fail;

	//Ring PLL power initial at "min_lp"
	/*
	//Ring PLL power, R25[2:1]
	if((RingFreq>0) && (RingFreq<R850_RING_POWER_FREQ))
	priv->regs[25] = (priv->regs[25] & 0xF9) | 0x04;   //R25[2:1]=2'b10; min_lp
	else
	priv->regs[25] = (priv->regs[25] & 0xF9) | 0x00;   //R25[2:1]=2'b00; min

	R850_I2C.RegAddr = 0x19;
	R850_I2C.Data = priv->regs[25];
	if(I2C_Write( &R850_I2C) != R850_Success)
	return R850_Fail;
	*/

	{
		//Must do MUX before PLL()
		if(R850_MUX( priv,RingFreq - R850_IMR_IF, RingFreq, R850_STD_SIZE) != R850_Success)      //IMR MUX (LO, RF)
			return R850_Fail;

		priv->R850_IF_GOLOBAL = R850_IMR_IF;
		if(R850_PLL(priv, (RingFreq - R850_IMR_IF), R850_STD_SIZE) != R850_Success)  //IMR PLL
			return R850_Fail;

		//Img_R = normal
		priv->regs[19] = (priv->regs[19] & 0xEF);  //R20[7]=0 => R19[4]=0
		// Mixer Amp LPF=7 (0 is widest)
		priv->regs[19] = (priv->regs[19] & 0xF8) | (7);
		if(r850_wr(priv,19,priv->regs[19])!=0)
			return R850_Fail;


		if(IMR_MEM==4)
		{
			//output atten
			priv->regs[36] = (priv->regs[36] & 0xCF) | (0x10);  // R41[3:0]=0
		}
		else
		{
			//output atten
			priv->regs[36] = (priv->regs[36] & 0xCF) | (0x30);  // R41[3:0]=0

		}
		if(r850_wr(priv,36,priv->regs[36])!=0)
			return R850_Fail;

		//Mixer Gain = 8
		priv->regs[41] = (priv->regs[41] & 0xF0) | (8);  //R41[3:0]=0
		if(r850_wr(priv,41,priv->regs[41])!=0)
			return R850_Fail;


		//clear IQ_cap
		//IMR_POINT.Iqcap = priv->regs[19] & 0x3F;
		IMR_POINT.Iqcap = 0;

		if(IM_Flag == TRUE)
		{
			if(R850_IQ( priv, &IMR_POINT) != R850_Success)
				return R850_Fail;
		}
		else  //IMR_MEM 1, 0, 3, 4
		{
			if((IMR_MEM==1) || (IMR_MEM==3))
			{
				IMR_POINT.Gain_X = priv->imr_data[2].Gain_X;   //node 3
				IMR_POINT.Phase_Y = priv->imr_data[2].Phase_Y;
				IMR_POINT.Value = priv->imr_data[2].Value;
			}
			else if((IMR_MEM==0) || (IMR_MEM==4))
			{
				IMR_POINT.Gain_X = priv->imr_data[1].Gain_X;
				IMR_POINT.Phase_Y = priv->imr_data[1].Phase_Y;
				IMR_POINT.Value = priv->imr_data[1].Value;
			}

			if(R850_F_IMR(priv,&IMR_POINT) != R850_Success)
				return R850_Fail;
		}
	}

	//Save IMR Value
	priv->imr_data[IMR_MEM].Gain_X  = IMR_POINT.Gain_X;
	priv->imr_data[IMR_MEM].Phase_Y = IMR_POINT.Phase_Y;
	priv->imr_data[IMR_MEM].Value = IMR_POINT.Value;
	priv->imr_data[IMR_MEM].Iqcap = IMR_POINT.Iqcap;

	IMR_Gain = priv->imr_data[IMR_MEM].Gain_X & 0x2F;   //R20[3:0]
	IMR_Phase = priv->imr_data[IMR_MEM].Phase_Y & 0x2F; //R21[3:0]


	if(((IMR_Gain & 0x0F)>6) || ((IMR_Phase & 0x0F)>6))
	{
		priv->R850_IMR_Cal_Result = 1; //fail
	}

	return R850_Success;
}

//----------------------------------------------------------------------//
//  R850_GetRfRssi( ): Get RF RSSI                                      //
//  1st parameter: input RF Freq    (KHz)                                //
//  2nd parameter: input Standard                                           //
//  3rd parameter: output signal level (dBm*1000)                    //
//  4th parameter: output RF max gain indicator (1:max gain)    //
//-----------------------------------------------------------------------//
R850_ErrCode R850_GetRfRssi( struct r850_priv*priv,u32 RF_Freq_Khz, enum R850_Standard_Type RT_Standard, s32 *RfLevelDbm, u8 *fgRfMaxGain)
{
	//u8 bPulseFlag;
	struct R850_RF_Gain_Info rf_gain_info;
	u16  acc_lna_gain;
	u16  acc_rfbuf_gain;
	u16  acc_mixer_gain;
	u16  rf_total_gain;
	u8   u1FreqIndex;
	s16  u2FreqFactor=0;
	u8  u1LnaGainqFactorIdx;
	s32     rf_rssi;
	s32    fine_tune = 0;    //for find tune
	u8 	rf_limit;
	u8	mixer_limit;
	u8	mixer_1315_gain = 0;
	u8	filter_limit;
	//{50~135, 135~215, 215~265, 265~315, 315~325, 325~345, 345~950}
	s8 R850_Start_Gain_Cal_By_Freq[7] = {10, -10, -30, -10, 20, 20, 20};
	u8 buf[6];
	

	r850_rd(priv,0,buf,6);

	//bPulseFlag = ((R850_I2C_Len.Data[1] & 0x40) >> 6);

	rf_gain_info.RF_gain1 = (buf[3] & 0x1F);          //lna
	rf_gain_info.RF_gain2 = (buf[4] & 0x0F);          //rf
	rf_gain_info.RF_gain3 = (buf[4] & 0xF0)>>4;       //mixer
	rf_gain_info.RF_gain4 = (buf[5] & 0x0F);          //filter


	//max gain indicator
	if((rf_gain_info.RF_gain1==31) && (rf_gain_info.RF_gain2==15) && (rf_gain_info.RF_gain3==15) && (rf_gain_info.RF_gain4==15))
		*fgRfMaxGain = 1;
	else
		*fgRfMaxGain = 0;
	rf_limit = (((priv->regs[18]&0x04)>>1) + ((priv->regs[16]&0x40)>>6));

	if(rf_limit==0)
		rf_limit = 15;
	else if(rf_limit==1)
		rf_limit = 11;
	else if(rf_limit==2)
		rf_limit = 13;
	else
		rf_limit = 9;

	mixer_limit = (((priv->regs[22]&0xC0)>>6)*2)+6;			//0=6, 1=8, 2=10, 3=12
	mixer_1315_gain = ((priv->regs[25]&0x02)>>1);			//0:original, 1:ctrl by mixamp (>10)

	if( rf_gain_info.RF_gain2 > rf_limit)
		rf_gain_info.RF_gain2 = rf_limit;

	if((rf_gain_info.RF_gain3 > 12)&&(mixer_1315_gain==1))
		mixer_1315_gain = rf_gain_info.RF_gain3;		//save 0 or 13 or 14 or 15

	if( rf_gain_info.RF_gain3 > mixer_limit)
		rf_gain_info.RF_gain3 = mixer_limit;


	filter_limit = (priv->regs[22]&0x01);
	if(filter_limit==1)
		filter_limit = 15;
	else
		filter_limit = 13;

	if( rf_gain_info.RF_gain4 > filter_limit)
		rf_gain_info.RF_gain4 = filter_limit;


	//coarse adjustment
	if(RF_Freq_Khz<135000)   //<135M
	{
		u1FreqIndex = 0;
		u2FreqFactor = R850_Start_Gain_Cal_By_Freq[0];
	}
	else if((RF_Freq_Khz>=135000)&&(RF_Freq_Khz<215000))   //135~215M
	{
		u1FreqIndex = 0;
		u2FreqFactor = R850_Start_Gain_Cal_By_Freq[1];
	}
	else if((RF_Freq_Khz>=215000)&&(RF_Freq_Khz<265000))   //215~265M
	{
		u1FreqIndex = 1;
		u2FreqFactor = R850_Start_Gain_Cal_By_Freq[2];
	}
	else if((RF_Freq_Khz>=265000)&&(RF_Freq_Khz<315000))   //265~315M
	{
		u1FreqIndex = 1;
		u2FreqFactor = R850_Start_Gain_Cal_By_Freq[3];
	}
	else if((RF_Freq_Khz>=315000)&&(RF_Freq_Khz<325000))   //315~325M
	{
		u1FreqIndex = 1;
		u2FreqFactor = R850_Start_Gain_Cal_By_Freq[4];
	}
	else if((RF_Freq_Khz>=325000)&&(RF_Freq_Khz<345000))   //325~345M
	{
		u1FreqIndex = 1;
		u2FreqFactor = R850_Start_Gain_Cal_By_Freq[5];
	}
	else if((RF_Freq_Khz>=345000)&&(RF_Freq_Khz<420000))   //345~420M
	{
		u1FreqIndex = 1;
		u2FreqFactor = R850_Start_Gain_Cal_By_Freq[6];
	}
	else if((RF_Freq_Khz>=420000)&&(RF_Freq_Khz<710000))   //420~710M
	{
		u1FreqIndex = 2;
		u2FreqFactor = R850_Start_Gain_Cal_By_Freq[6];

	}
	else    // >=710
	{
		u1FreqIndex = 3;
		u2FreqFactor = R850_Start_Gain_Cal_By_Freq[6];
	}


	//LNA Gain
	acc_lna_gain = R850_Lna_Acc_Gain[u1FreqIndex][rf_gain_info.RF_gain1];



	//fine adjustment
	//Cal LNA Gain	by Freq

	//Method 2 : All frequencies are finely adjusted..


	if(rf_gain_info.RF_gain1 >= 10)
	{
		u1LnaGainqFactorIdx = (u8) ((RF_Freq_Khz-50000) / 10000);

		if( ((RF_Freq_Khz-50000)  - (u1LnaGainqFactorIdx * 10000))>=5000)
			u1LnaGainqFactorIdx +=1;
		acc_lna_gain += (u16)(Lna_Acc_Gain_offset[u1LnaGainqFactorIdx]);

	}

	//RF buf
	acc_rfbuf_gain = R850_Rf_Acc_Gain[rf_gain_info.RF_gain2];
	if(RF_Freq_Khz<=300000)
		acc_rfbuf_gain += (rf_gain_info.RF_gain2 * 1);
	else if (RF_Freq_Khz>=600000)
		acc_rfbuf_gain -= (rf_gain_info.RF_gain2 * 1);

	//Mixer
	acc_mixer_gain = R850_Mixer_Acc_Gain [rf_gain_info.RF_gain3]  ;

	if((mixer_1315_gain!=0) && (mixer_1315_gain!=1))	//Gain 13 or 14 or 15
		acc_mixer_gain = acc_mixer_gain + (R850_Mixer_Acc_Gain[mixer_1315_gain] - R850_Mixer_Acc_Gain[12]);



	//Add Rf Buf and Mixer Gain
	rf_total_gain = acc_lna_gain + acc_rfbuf_gain + acc_mixer_gain + rf_gain_info.RF_gain4*153/10;

	rf_rssi = fine_tune - (s32) (rf_total_gain - u2FreqFactor);


	*RfLevelDbm = rf_rssi*100;

	return R850_Success;
}


//-----------------------------------------------------------------------//
//  R850_GetIfRssi( ): Get IF VGA GAIN                                   //
//  1st parameter: return IF VGA Gain     (dB*100)                       //
//-----------------------------------------------------------------------//
R850_ErrCode R850_GetIfRssi(struct r850_priv*priv,s32 *VgaGain)
{
	u8   adc_read;
	u8 buf[2];
	//Optimize value
	u16   vga_table[64] = {                        //*100
		0, 0, 20, 20, 30, 50, 60, 80, 110, 130, 130, 160,   //0~11
		200, 240, 280, 330, 380, 410, 430, 480, 530, 590,   //12~21
		640, 690, 730, 760, 780, 810, 840, 890, 930, 950,   //22~31
		980, 1010, 1010, 1030, 1060, 1100, 1120, 1140, 1170, 1180,   //32~41
		1190, 1210, 1220, 1260, 1270, 1300, 1320, 1320, 1340, 1340,   //42~51
		1360, 1390, 1400, 1420, 1440, 1450, 1460, 1480, 1490, 1510,   //52~61
		1550, 1600            //62~63
	};

	//ADC sel : vagc, R22[3:2]=2
	priv->regs[22] = (priv->regs[22] & 0xF3) | 0x08;
	if(r850_wr(priv,22,priv->regs[22]) != 0)
		return R850_Fail;

	//IF_AGC read, R18[5]=1
	priv->regs[18] = priv->regs[18] | 0x20;
	if(r850_wr(priv,18,priv->regs[18]) != 0)
		return R850_Fail;

	//ADC power on, R11[1]=0
	priv->regs[11] = priv->regs[11] & 0xFD;
	if(r850_wr(priv,11,priv->regs[11]) != 0)
		return R850_Fail;

	//read adc value
	r850_rd(priv,0x00,buf,2);
	adc_read = (buf[1] & 0x3F);

	*VgaGain = vga_table[adc_read];

	return R850_Success;
}


//  R850_GetRfRssi( ): Get RF RSSI                                      //
//  1st parameter: input RF Freq    (KHz)                                //
//  2nd parameter: input Standard                                           //
//  3rd parameter: return signal level indicator (dBm)               //
//-----------------------------------------------------------------------//
R850_ErrCode R850_GetTotalRssi( struct r850_priv*priv, u32 RF_Freq_Khz, enum R850_Standard_Type RT_Standard, s32 *RssiDbm)
{
	s32   rf_rssi;
	s32   if_rssi;
	s32   rem, total_rssi;
	s32   ssi_offset = 0;   //need to fine tune by platform
	s32   total_rssi_dbm;
	u8  rf_max_gain_flag;

	R850_GetRfRssi(priv, RF_Freq_Khz, RT_Standard, &rf_rssi, &rf_max_gain_flag);

	R850_GetIfRssi(priv, &if_rssi);  //vga gain

	total_rssi = rf_rssi - (if_rssi*10);
	rem = total_rssi - (total_rssi/1000)*1000; //for rounding
	if((rem>-500) && (rem<500))
		total_rssi_dbm = (total_rssi/1000);
	else if(rem<=-500)
		total_rssi_dbm = (total_rssi/1000)-1;
	else
		total_rssi_dbm = (total_rssi/1000)+1;

	//for different platform, need to fine tune offset value
	*RssiDbm = total_rssi_dbm + ssi_offset+8;

	return R850_Success;
}

u8  R850_Filt_Cal_ADC(struct r850_priv *priv, u32 IF_Freq, u8 R850_BW, u8 FilCal_Gap)
{
	u8     u1FilterCodeResult = 0;
	u8     u1FilterCode = 0;
	u8     u1FilterCalValue = 0;
	u8     u1FilterCalValuePre = 0;
	u8     initial_cnt = 0;
	u8     i = 0;
	//u32   RingVCO = 0;
	u32   RingFreq = 72000;
	u8   ADC_Read_Value = 0;
	u8	 ADC_Read_Value_8M5Hz = 0;
	u8   LPF_Count = 0;
	//u32   RingRef = R850_Xtal;
	//u8     divnum_ring = 0;
	//u8    VGA_Count = 0;


	if(R850_Cal_Prepare(priv, R850_LPF_CAL) != R850_Success)
		return R850_Fail;

	priv->R850_IF_GOLOBAL = IF_Freq;
	//Set PLL (TBD, normal)
	if(R850_PLL(priv, (RingFreq - IF_Freq), R850_STD_SIZE) != R850_Success)   //FilCal PLL
		return R850_Fail;

	//------- increase Filter gain to let ADC read value significant ---------//
	for(LPF_Count=5; LPF_Count < 16; LPF_Count ++)
	{

		priv->regs[41] = (priv->regs[41] & 0x0F) | (LPF_Count<<4);
		if(r850_wr(priv,41,priv->regs[41]) != 0)
			return R850_Fail;

		msleep( R850_FILTER_GAIN_DELAY); //

		if(R850_Muti_Read(priv, &ADC_Read_Value) != R850_Success)
			return R850_Fail;

		if(ADC_Read_Value > 40*R850_ADC_READ_COUNT)
		{
			break;
		}
	}


	//If IF_Freq>10MHz, need to compare 8.5MHz ADC Value,
	//If the ADC values greater than 8 in the same gain,the filter corner select 8M / 0
	if(IF_Freq>=10000)
	{
		priv->R850_IF_GOLOBAL = 8500;
		//Set PLL (TBD, normal)
		if(R850_PLL( priv,(RingFreq - 8500), R850_STD_SIZE) != R850_Success)   //FilCal PLL
			return R850_Fail;

		msleep( R850_FILTER_GAIN_DELAY); //

		if(R850_Muti_Read( priv,&ADC_Read_Value_8M5Hz) != R850_Success)
			return R850_Fail;

		if(ADC_Read_Value_8M5Hz > (ADC_Read_Value + 8) )
		{
			//priv->bw = 0; //8M	
			u1FilterCodeResult = 0;
			return u1FilterCodeResult;
		}
		else
		{
			priv->R850_IF_GOLOBAL = IF_Freq;
			//Set PLL (TBD, normal)
			if(R850_PLL(priv, (RingFreq - IF_Freq), R850_STD_SIZE) != R850_Success)   //FilCal PLL
				return R850_Fail;
		}
	}



	//------- Try suitable BW --------//
	if(R850_BW==2) //6M
		initial_cnt = 1;  //try 7M first
	else
		initial_cnt = 0;  //try 8M first

	for(i=initial_cnt; i<3; i++)
	{

		//Set BW R22[5:4] => R23[6:5]
		priv->regs[23] = (priv->regs[23] & 0xCF);
		if(r850_wr(priv,23,priv->regs[23]) != 0)
			return R850_Fail;

		// read code 0 R22[4:1] => R23[4:1]
		priv->regs[23] = (priv->regs[23] & 0xE1);  //code 0
		if(r850_wr(priv,23,priv->regs[23]) != 0)
			return R850_Fail;

		msleep( R850_FILTER_CODE_DELAY); //delay ms

		if(R850_Muti_Read(priv, &u1FilterCalValuePre) != R850_Success)
			return R850_Fail;

		//read code 26 R22[4:1] => R23[4:1]
		priv->regs[23] = (priv->regs[23] & 0xE1) | (13<<1);  //code 26
		if(r850_wr(priv,23,priv->regs[23]) != 0)
			return R850_Fail;

		msleep( R850_FILTER_CODE_DELAY); //delay ms

		if(R850_Muti_Read(priv, &u1FilterCalValue) != R850_Success)
			return R850_Fail;

		if(u1FilterCalValuePre > (u1FilterCalValue+16))  //suitable BW found
			break;
	}

	//-------- Try LPF filter code ---------//
	u1FilterCalValuePre = 0;
	for(u1FilterCode=0; u1FilterCode<16; u1FilterCode++)
	{
		priv->regs[23] = (priv->regs[23] & 0xE1) | (u1FilterCode<<1);
		if(r850_wr(priv,23,priv->regs[23]) != 0)

			return R850_Fail;

		msleep( R850_FILTER_CODE_DELAY); //delay ms

		if(R850_Muti_Read(priv, &u1FilterCalValue) != R850_Success)
			return R850_Fail;

		if((IF_Freq>=10000)&&(u1FilterCode==0))
		{
			u1FilterCalValuePre = ADC_Read_Value_8M5Hz;
		}
		else if(u1FilterCode==0)
		{
			u1FilterCalValuePre = u1FilterCalValue;
		}

		if((u1FilterCalValue+FilCal_Gap*R850_ADC_READ_COUNT) < u1FilterCalValuePre)
		{
			u1FilterCodeResult = u1FilterCode;
			break;
		}
	}

	//Try LSB bit
	if(u1FilterCodeResult>0)   //try code-1 & lsb=1
	{

		priv->regs[23] = (priv->regs[23] & 0xE0) | ((u1FilterCodeResult-1)<<1) | 0x01;
		if(r850_wr(priv,23,priv->regs[23]) != 0)
			return R850_Fail;

		msleep( R850_FILTER_GAIN_DELAY); //delay ms

		if(R850_Muti_Read( priv,&u1FilterCalValue) != R850_Success)
			return R850_Fail;

		if((u1FilterCalValue+FilCal_Gap*R850_ADC_READ_COUNT) < u1FilterCalValuePre)
		{
			u1FilterCodeResult = u1FilterCodeResult - 1;
		}

	}

	if(u1FilterCode==16)
		u1FilterCodeResult = 15;

	return u1FilterCodeResult;

}

R850_ErrCode R850_SetStandard(struct r850_priv *priv, enum R850_Standard_Type RT_Standard)
{
	u8 u1FilCalGap = 16;

	//HPF ext protection
	if(priv->fc.flag== 0)
	{
		priv->fc.code = R850_Filt_Cal_ADC(priv, priv->R850_Sys_Info.FILT_CAL_IF, priv->R850_Sys_Info.BW, u1FilCalGap);
		priv->fc.bw = 0;
		priv->fc.flag = 1;
		priv->fc.lpflsb = 0;

		//Reset register and Array
		if(R850_InitReg(priv) != R850_Success)
			return R850_Fail;
	}
	// Set LPF Lsb bit
	priv->regs[23] = (priv->regs[23] & 0xFE) ;  //R23[0]
	// Set LPF fine code
	priv->regs[23] = (priv->regs[23] & 0xE1) | (priv->fc.code<<1);  //R23[4:1]
	// Set LPF coarse BW
	priv->regs[23] = (priv->regs[23] & 0x9F) | (priv->fc.bw<<5);  //R23[6:5]
	//Set HPF notch  R23[7]
	priv->regs[23] = (priv->regs[23] & 0x7F) | (priv->R850_Sys_Info.HPF_NOTCH<<7);
	if(r850_wr(priv,23,priv->regs[23]) != 0)
		return R850_Fail;


	// Set HPF corner
	priv->regs[24] = (priv->regs[24] & 0x0F) | (priv->R850_Sys_Info.HPF_COR<<4);	//R24[3:0] => R24[7:4]
	if(r850_wr(priv,24,priv->regs[24]) != 0)
		return R850_Fail;


	// Set Filter Auto Ext
	priv->regs[18] = (priv->regs[18] & 0xBF) | (priv->R850_Sys_Info.FILT_EXT_ENA<<6);  // =>R18[6]
	if(r850_wr(priv,18,priv->regs[18]) != 0)
		return R850_Fail;

	//set Filter Comp				 //R24[3:2]
	priv->regs[24] = (priv->regs[24] & 0xF3) | (priv->R850_Sys_Info.FILT_COMP<<2);
	if(r850_wr(priv,24,priv->regs[24]) != 0)
		return R850_Fail;

	// Set AGC clk R47[3:2]
	priv->regs[47] = (priv->regs[47] & 0xF3) | (priv->R850_Sys_Info.AGC_CLK<<2);
	if(r850_wr(priv,47,priv->regs[47]) != 0)
		return R850_Fail;

	priv->regs[44] = (priv->regs[44] & 0xFE) | ((priv->R850_Sys_Info.IMG_GAIN & 0x02)>>1);
	if(r850_wr(priv,44,priv->regs[44]) != 0)
		return R850_Fail;
	
	priv->regs[46] = (priv->regs[46] & 0xEF) | ((priv->R850_Sys_Info.IMG_GAIN & 0x01)<<4);
	if(r850_wr(priv,46,priv->regs[46]) != 0)
		return R850_Fail;

	return R850_Success;
}



R850_ErrCode R850_SetFrequency(struct r850_priv *priv, struct R850_Set_Info R850_INFO) //Write Multi byte
{

	u32	LO_KHz;
	u8    Img_R;
	u8 SetFreqArrayCunt;
	int ret = 0;
	
	struct R850_SysFreq_Info_Type SysFreq_Info1;

	//Get Sys-Freq parameter

	SysFreq_Info1 = R850_SysFreq_NrbDetOn_Sel( R850_INFO.R850_Standard, R850_INFO.RF_KHz);
	
	//R850_IMR_point_num = Freq_Info1.IMR_MEM_NOR;

	// Check Input Frequency Range
	if((R850_INFO.RF_KHz<40000) || (R850_INFO.RF_KHz>1002000))
	{
		return R850_Fail;
	}


	
	LO_KHz = R850_INFO.RF_KHz + priv->R850_Sys_Info.IF_KHz;
	Img_R = 0;
	
	priv->regs[19] = (priv->regs[19] & 0xEF) | (Img_R<<4);  //R20[7] => R19[4]
	if(r850_wr(priv,19,priv->regs[19]))
		return R850_Fail;


	//Set MUX dependent var. Must do before PLL()
	if(R850_MUX( priv,LO_KHz, R850_INFO.RF_KHz, R850_INFO.R850_Standard) != R850_Success)   //normal MUX
		return R850_Fail;

	priv->R850_IF_GOLOBAL = priv->R850_Sys_Info.IF_KHz;
	//Set PLL
	if(R850_PLL(priv, LO_KHz, R850_INFO.R850_Standard) != R850_Success) //noraml PLL
		return R850_Fail;

	// PW
	// Set NA det power R10[6]
	//if(R850_External_LNA == 0)	//External LNA Disable => depend on setting
	priv->regs[10] = (priv->regs[10] & 0xBF) | (SysFreq_Info1.NA_PWR_DET<<6);
//	else	//External LNA Enable => fixed
	//	priv->regs[R850_I2C.RegAddr] = (priv->regs[R850_I2C.RegAddr] & 0xBF);

	//Set Man Buf Cur R16[5]
//	if(R850_External_LNA == 0)	//External LNA Disable => depend on initial value
		priv->regs[16] = (priv->regs[16] & 0xDF) | (R850_iniArray[0][16] & 0x20);
//	else	//External LNA Enable => fixed
//		priv->regs[R850_I2C.RegAddr] = (priv->regs[R850_I2C.RegAddr] | 0x20);


	//LNA_NRB_DET R11[7]
	priv->regs[11] = (priv->regs[11] & 0x7F) | (SysFreq_Info1.LNA_NRB_DET<<7);

	//LNA
	// LNA_TOP R38[2:0]
	priv->regs[38] = (priv->regs[38] & 0xF8) | (7 - SysFreq_Info1.LNA_TOP);

	// LNA VTL/H R39[7:0]
	priv->regs[39] = (priv->regs[39 ] & 0x00) | SysFreq_Info1.LNA_VTL_H;

	// RF_LTE_PSG R17[4]
	priv->regs[17] = (priv->regs[17 ] & 0xEF) | (SysFreq_Info1.RF_LTE_PSG<<4);

	//RF
	// RF TOP R38[6:4]
	priv->regs[38] = (priv->regs[38] & 0x8F) | ((7 - SysFreq_Info1.RF_TOP)<<4);

	// RF VTL/H R42[7:0]
	priv->regs[42] = (priv->regs[42] & 0x00) | SysFreq_Info1.RF_VTL_H;

	// RF Gain Limt  (MSB:R18[2] & LSB:R16[6])
	switch(SysFreq_Info1.RF_GAIN_LIMIT)
	{
		case 0://'b00
			priv->regs[18] = (priv->regs[18] & 0xFB);
			priv->regs[16] = (priv->regs[16] & 0xBF);
			break;
		case 1://'b01
			priv->regs[18] = (priv->regs[18] & 0xFB);
			priv->regs[16] = (priv->regs[16] | 0x40);
			break;
		case 2://'b10
			priv->regs[18] = (priv->regs[18] | 0x02);
			priv->regs[16] = (priv->regs[16] & 0xBF);
			break;
		case 3://'b11
			priv->regs[18] = (priv->regs[18] | 0x02);
			priv->regs[16] = (priv->regs[16] | 0x40);
			break;
	}

	//MIXER & FILTER
	//MIXER_AMP_LPF  R19[2:0]
	priv->regs[19] = (priv->regs[19] & 0xF8) | SysFreq_Info1.MIXER_AMP_LPF;

	// MIXER TOP R40[3:0]
	priv->regs[40] = (priv->regs[40] & 0xF0) | (15 - SysFreq_Info1.MIXER_TOP);

	// Filter TOP R44[3:0] for MP, R44[3:1] for MT1
	priv->regs[44] = (priv->regs[44] & 0xF1) | ((7-SysFreq_Info1.FILTER_TOP)<<1);

	//FILT_3TH_LPF_CUR=0;	//R10[4] [high (0), low (1)]
	priv->regs[10] = (priv->regs[10] & 0xEF) | (SysFreq_Info1.FILT_3TH_LPF_CUR<<4);

	// 3th_LPF_Gain R24[1:0]
	priv->regs[24] = (priv->regs[24] & 0xFC) | SysFreq_Info1.FILT_3TH_LPF_GAIN;

	priv->regs[19] = (priv->regs[19] & 0x7F) | 0x80;
    // MIXER VTH & Filter VTH  R41[7:0]
	priv->regs[41] = ((priv->regs[41] & 0x00) | SysFreq_Info1.MIXER_VTH | SysFreq_Info1.FILTER_VTH);

	// MIXER VTL & Filter VTL R43[7:0]
	priv->regs[43] = ((priv->regs[43] & 0x00) | SysFreq_Info1.MIXER_VTL | SysFreq_Info1.FILTER_VTL);

	// Mixer Gain Limt R22[7:6]
	priv->regs[22] = (priv->regs[22] & 0x3F) | (SysFreq_Info1.MIXER_GAIN_LIMIT << 6);

	// MIXER_DETBW_LPF R46[7]
	priv->regs[46] = (priv->regs[46] & 0x7F) | (SysFreq_Info1.MIXER_DETBW_LPF << 7);

	//Discharge
	//LNA_RF Discharge Mode  (R45[1:0]=2'b01; R9[6]=1)	=> (R45[1:0]=0'b00; R31[0]=1 ;R32[5]=1)
	if(SysFreq_Info1.LNA_RF_DIS_MODE==0)  //auto (normal)
	{
		priv->regs[45] = (priv->regs[45] & 0xFC) | 0x00;	//00
		priv->regs[31] = (priv->regs[31] & 0xFE) | 0x01;   //1
		priv->regs[32] = (priv->regs[32] & 0xDF) | 0x20;	//1
	}
	else if(SysFreq_Info1.LNA_RF_DIS_MODE==1)  //both(fast+slow)
	{
		priv->regs[45] = (priv->regs[45] & 0xFC) | 0x03;	//11
		priv->regs[31] = (priv->regs[31] & 0xFE) | 0x01;   //1
		priv->regs[32] = (priv->regs[32] & 0xDF) | 0x20;	//1
	}
	else if(SysFreq_Info1.LNA_RF_DIS_MODE==2)  //both(slow)
	{
		priv->regs[45] = (priv->regs[45] & 0xFC) | 0x03;	//11
		priv->regs[31] = (priv->regs[31] & 0xFE) | 0x00;   //0
		priv->regs[32] = (priv->regs[32] & 0xDF) | 0x00;	//0
	}
	else if(SysFreq_Info1.LNA_RF_DIS_MODE==3)  //LNA(slow)
	{
		priv->regs[45] = (priv->regs[45] & 0xFC) | 0x03;	//11
		priv->regs[31] = (priv->regs[31] & 0xFE) | 0x01;   //1
		priv->regs[32] = (priv->regs[32] & 0xDF) | 0x00;	//0
	}
	else if(SysFreq_Info1.LNA_RF_DIS_MODE==4)  //RF(slow)
	{
		priv->regs[45] = (priv->regs[45] & 0xFC) | 0x03;	//11
		priv->regs[31] = (priv->regs[31] & 0xFE) | 0x00;   //0
		priv->regs[32] = (priv->regs[32] & 0xDF) | 0x20;	//1
	}
	else
	{
		priv->regs[45] = (priv->regs[45] & 0xFC) | 0x00;	//00
		priv->regs[31] = (priv->regs[31] & 0xFE) | 0x01;   //1
		priv->regs[32] = (priv->regs[32] & 0xDF) | 0x20;	//1
	}

	//LNA_RF_CHARGE_CUR R31[1]
	priv->regs[31] = (priv->regs[31] & 0xFD) | (SysFreq_Info1.LNA_RF_CHARGE_CUR<<1);

	//LNA_RF_dis current  R13[5]
	priv->regs[13] = (priv->regs[13] & 0xDF) | (SysFreq_Info1.LNA_RF_DIS_CURR<<5);

	//RF_slow disch(5:4) / fast disch(7:6)  //(R45[7:4])
	priv->regs[45] = (priv->regs[45] & 0x0F) | (SysFreq_Info1.RF_DIS_SLOW_FAST<<4);

	//LNA slow disch(5:4) / fast disch(7:6) =>	R44[7:4]
	priv->regs[44] = (priv->regs[44] & 0x0F) | (SysFreq_Info1.LNA_DIS_SLOW_FAST<<4);

	//BB disch current R25[6]
	priv->regs[25] = (priv->regs[25] & 0xBF) | (SysFreq_Info1.BB_DIS_CURR<<6);

	//Mixer/Filter disch  R37[7:6]
	priv->regs[37] = (priv->regs[37] & 0x3F) | (SysFreq_Info1.MIXER_FILTER_DIS<<6);

	//BB Det Mode  R37[2]
	priv->regs[37] = (priv->regs[37] & 0xFB) | (SysFreq_Info1.BB_DET_MODE<<2);

	//Polyphase
	//ENB_POLY_GAIN  R25[1]
	priv->regs[25] = (priv->regs[25] & 0xFD) | (SysFreq_Info1.ENB_POLY_GAIN<<1);

	//NRB
	// NRB TOP R40[7:4]
	priv->regs[40] = (priv->regs[40] & 0x0F) | ((15 - SysFreq_Info1.NRB_TOP)<<4);

	//NRB LPF & HPF BW  R26[7:6 & 3:2]
	priv->regs[26] = (priv->regs[26] & 0x33) | (SysFreq_Info1.NRB_BW_HPF<<2) | (SysFreq_Info1.NRB_BW_LPF<<6);

	//NBR Image TOP adder R46[3:2]
	priv->regs[46] = (priv->regs[46] & 0xF3) | (SysFreq_Info1.IMG_NRB_ADDER<<2);

	//VGA
	//HPF_COMP R13[2:1]
	priv->regs[13] = (priv->regs[13] & 0xF9) | (SysFreq_Info1.HPF_COMP<<1);

	//FB_RES_1ST  //R21[4]
	priv->regs[21] = (priv->regs[21] & 0xEF) | (SysFreq_Info1.FB_RES_1ST<<4);

	//DEGLITCH_CLK;	R38[3]
	priv->regs[38] = (priv->regs[38] & 0xF7) | (SysFreq_Info1.DEGLITCH_CLK<<3);

	//NAT_HYS;			R35[6]
	priv->regs[35] = (priv->regs[35] & 0xBF) | (SysFreq_Info1.NAT_HYS<<6);

	//NAT_CAIN;		R31[4:5]
	priv->regs[31] = (priv->regs[31] & 0xCF) | (SysFreq_Info1.NAT_CAIN<<4);

	//PULSE_HYS;		R26[1:0]
	priv->regs[26] = (priv->regs[26] & 0xFC) | (SysFreq_Info1.PULSE_HYS);

	//FAST_DEGLITCH;	R36[3:2]
	priv->regs[36] = (priv->regs[36] & 0xF3) | (SysFreq_Info1.FAST_DEGLITCH<<2);

	//PUL_RANGE_SEL;	R31[2]
	priv->regs[31] = (priv->regs[31] & 0xFB) | (SysFreq_Info1.PUL_RANGE_SEL<<2);

	//PUL_FLAG_RANGE;	R35[1:0]
	priv->regs[35] = (priv->regs[35] & 0xFC) | (SysFreq_Info1.PUL_FLAG_RANGE);

	//PULG_CNT_THRE;	R17[1]
	priv->regs[17] = (priv->regs[17] & 0xFD) | (SysFreq_Info1.PULG_CNT_THRE<<1);

	//FORCE_PULSE;		R46[5]
	priv->regs[46] = (priv->regs[46] & 0xDF) | (SysFreq_Info1.FORCE_PULSE<<5);

	//FLG_CNT_CLK;		R47[7:6]
	priv->regs[47] = (priv->regs[47] & 0x3F) | (SysFreq_Info1.FLG_CNT_CLK<<6);

	//NATG_OFFSET;		R36[5:4]
	priv->regs[36] = (priv->regs[36] & 0xCF) | (SysFreq_Info1.NATG_OFFSET<<4);
	//other setting

	// Set AGC clk R47[3:2]    only for isdbt 4.063 (set 1Khz because Div/4, original agc clk is 512Hz)
	if( (R850_INFO.RF_KHz >= 478000) && (R850_INFO.RF_KHz < 482000) && (R850_INFO.R850_Standard == R850_ISDB_T_4063) )
	{
		priv->regs[47] = (priv->regs[47] & 0xF3);
	}


	//IF AGC1
	priv->regs[25] = priv->regs[25] & 0xDF;


	//Set LT
	if(R850_INFO.R850_LT==R850_LT_ON)
	{
		//LT Sel: active LT(after LNA) R8[6]=1 ; acLT PW: ON R8[7]=1
		priv->regs[8] = (priv->regs[8] | 0xC0 );
		//Pulse LT on R10[1]=1
		priv->regs[10] = (priv->regs[10] | 0x02);
	}
	else
	{
		//LT Sel: active LT(after LNA) R8[6]=1 ; acLT PW: OFF R8[7]=0
		priv->regs[8] = ((priv->regs[8] | 0x40) & 0x7F);
		//Pulse LT on R10[1]=0
		priv->regs[10] = (priv->regs[10] & 0xFD);
	}


	//Set Clk Out
	if(R850_INFO.R850_ClkOutMode==R850_CLK_OUT_OFF)
	{
		priv->regs[34] = (priv->regs[34] | 0x04);   //no clk out  R34[2] = 1
	}
	else
	{
		priv->regs[34] = (priv->regs[34] & 0xFB);   //clk out  R34[2] = 0
	}

	ret = r850_wrm(priv,8,&priv->regs[8],40);
	if(ret!=0)
		return R850_Fail;


	return R850_Success;
}


static int r850_init(struct dvb_frontend *fe)
{
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	struct r850_priv *priv = fe->tuner_priv;

	int ret = 0;
	
	if(priv->inited)
		return ret;
	
	priv->fc.bw = 0x00;
	priv->fc.code = 0;
	priv->fc.lpflsb = 0;
	priv->fc.flag =0;
	
	priv->R850_Sys_Info.IF_KHz=5000;
	priv->R850_Sys_Info.BW=0; 					 //BW=8M   R23[6:5] [8M(0), 7M(1), 6M(2)]
	priv->R850_Sys_Info.FILT_CAL_IF=8800; 		 //CAL IF
	priv->R850_Sys_Info.HPF_COR=11;				  //R24[7:4] [0~15 ; input: "0~15"]
	priv->R850_Sys_Info.FILT_EXT_ENA=0;			 //R18[6] filter ext disable [off(0), on(1)]
	priv->R850_Sys_Info.FILT_COMP=2;				 //R24[3:2] [0~3 ; input: "0~3"]
	priv->R850_Sys_Info.AGC_CLK = 1;			//R47[3:2] 1k	[1kHz(0), 512Hz(1), 4kHz(2), 64Hz(3)]
	priv->R850_Sys_Info.IMG_GAIN = 2; 		 ////MSB:R44[0] , LSB:R46[4]  highest	[lowest(0), high(1), low(2), highest(3)]

	priv->R850_clock_out = 0;
	priv->R850_IMR_Cal_Result = 0;

	priv->R850_Xtal_cap = 29;
	priv->R850_IF_GOLOBAL = 6000;
	priv->R850_XtalDiv = R850_XTAL_DIV1;

	priv->R850_IMR_done_flag = 0;
	priv->R850_IMR_Cal_Result = 0;

	
	if(R850_Cal_Prepare(priv, R850_IMR_CAL) != R850_Success)
		ret=-1;

		
	if(R850_IMR(priv,2, TRUE) != R850_Success)       //Full K node 2
		ret=-1;

	if(R850_IMR(priv, 1, FALSE) != R850_Success)
		ret=-1;

	if(R850_IMR(priv, 0, FALSE) != R850_Success)
		ret=-1;

	if(R850_IMR(priv, 3, FALSE) != R850_Success)
		ret=-1;

	if(R850_IMR(priv, 4, FALSE) != R850_Success)
		ret=-1;

	priv->R850_IMR_done_flag = 1;

	//do Xtal check

	if(priv->R850_clock_out == 1)
	{
		priv->R850_Xtal_Pwr = R850_XTAL_HIGHEST;
	}
	else  //==0
	{
		priv->R850_Xtal_Pwr = R850_XTAL_LOWEST;
	}

	//write initial reg
	if(R850_InitReg(priv) != R850_Success)
			ret=-1;

	priv->inited = 1;

	/* init statistics in order signal app which are supported */
	c->strength.len = 1;
	c->strength.stat[0].scale = FE_SCALE_NOT_AVAILABLE;

	return ret;

}

static int r850_set_params(struct dvb_frontend *fe)
{
	struct r850_priv *priv = fe->tuner_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	struct R850_Set_Info tuner_parameters;

	int ret = 0;
	
	if(!priv->inited)
		r850_init(fe);
		
	tuner_parameters.RF_KHz = c->frequency /1000;

	tuner_parameters.R850_LT=R850_LT_ON;
	tuner_parameters.R850_ClkOutMode=R850_CLK_OUT_OFF;
	tuner_parameters.R850_Standard = R850_DTMB_8M_IF_5M;
	

	
	if(R850_SetStandard(priv,R850_DTMB_8M_IF_5M) != R850_Success)
		ret=-1;

	if(R850_SetFrequency(priv, tuner_parameters) != R850_Success)
		ret=-1;

	return ret;
}
static int r850_get_rf_strength(struct dvb_frontend *fe, u16 *rssi)
{
	struct r850_priv *priv = fe->tuner_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	s32 RSSI_Value = 0;
	int strength;
	
	R850_GetTotalRssi(priv,c->frequency/1000,R850_DTMB_8M_IF_5M,&RSSI_Value);
	
	if(RSSI_Value>-70)
		RSSI_Value+=8;

	c->strength.len = 2;
	c->strength.stat[0].scale = FE_SCALE_DECIBEL;
	c->strength.stat[0].svalue = (s8)RSSI_Value * 1000;	
	
	if(RSSI_Value<-85)
	   RSSI_Value = -80;
	if(RSSI_Value> -50)
	   RSSI_Value = -20;
	   
	 strength = (85+RSSI_Value)*100/65+20;
	 
	 if(strength>100)
	 	strength=100;
	 	
	c->strength.stat[1].scale = FE_SCALE_RELATIVE;
	c->strength.stat[1].uvalue = strength*655;
			   
	*rssi =(u16)(strength*655);
	
	return 0;
}
static void r850_release(struct dvb_frontend *fe)
{
	struct r850_priv *priv = fe->tuner_priv;
	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	kfree(fe->tuner_priv);
	fe->tuner_priv = NULL;
}

static int r850_sleep(struct dvb_frontend *fe)
{
	struct r850_priv *priv = fe->tuner_priv;
	int ret = 0;
	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	//if (ret)
	//	dev_dbg(&priv->i2c->dev, "%s() failed\n", __func__);
	return ret;
}

static const struct dvb_tuner_ops r850_tuner_ops = {
	.info = {
		.name           = "Rafael R850",
//		.frequency_min_hz  =  250 * MHz,
//		.frequency_max_hz  = 2300 * MHz,
	},

	.release = r850_release,

	.init = r850_init,
	.sleep = r850_sleep,
	.set_params = r850_set_params,
	.get_rf_strength = r850_get_rf_strength,
};

struct dvb_frontend *r850_attach(struct dvb_frontend *fe,
		struct r850_config *cfg, struct i2c_adapter *i2c)
{
	struct r850_priv *priv = NULL;
	u8 chip_id;
	u8 buf[50];
	int ret = 0;

	priv = kzalloc(sizeof(struct r850_priv), GFP_KERNEL);
	if (priv == NULL) {
		dev_dbg(&i2c->dev, "%s() attach failed\n", __func__);
		return NULL;
	}

	priv->cfg = cfg;
	priv->i2c = i2c;

	priv->inited = 0;
	
	ret = r850_rd(priv,0x00,buf,48);
	if(ret!=0)
		return NULL;
	
	dev_info(&priv->i2c->dev,
		"%s: Rafael R850 successfully attached,id is 0x%x\n",
		KBUILD_MODNAME,buf[0]);

	memcpy(&fe->ops.tuner_ops, &r850_tuner_ops,
			sizeof(struct dvb_tuner_ops));

	fe->tuner_priv = priv;
	return fe;
}

EXPORT_SYMBOL_GPL(r850_attach);

MODULE_DESCRIPTION("Rafael R850 tuner driver");
MODULE_AUTHOR("Davin<Davin@tbsdtv.com>");
MODULE_LICENSE("GPL");

