#include "mtv23x_priv.h"

static unsigned int GetSNR_LP_Mode(u8 mod, int val)
{
	unsigned int  cn_a = 0;
	unsigned int cn_b = 0;

	if (mod == 1) {
		/* QPSK */
		if (val > 270000) {
			cn_a = 0;
			cn_b = 0;
			return 0;
		} else if (val > 258000) { /* 0~ */
			cn_a = 0;
			cn_b = (270000 - val)/1300;
		} else if (val > 246000) { /* 1~ */
			cn_a = 1;
			cn_b = (258000 - val)/1300;
		} else if (val > 226000) { /* 2~ */
			cn_a = 2;
			cn_b = (246000 - val)/2100;
		} else if (val > 206500) { /* 3~ */
			cn_a = 3;
			cn_b = (226000 - val)/2100;
		} else if (val > 186500) { /* 4~ */
			cn_a = 4;
			cn_b = (206500 - val)/2200;
		} else if (val > 163500) { /* 5~ */
			cn_a = 5;
			cn_b = (186500 - val)/2400;
		} else if (val > 142000) { /* 6~ */
			cn_a = 6;
			cn_b = (163500 - val)/2300;
		} else if (val > 121000) { /* 7~ */
			cn_a = 7;
			cn_b = (142000 - val)/2300;
		} else if (val > 100500) { /* 8~ */
			cn_a = 8;
			cn_b = (121000 - val)/2200;
		} else if (val > 83500) {
			cn_a = 9;
			cn_b = (100500 - val)/1800;
		} else if (val > 69000) {
			cn_a = 10;
			cn_b = (83500 - val)/1550;
		} else if (val > 57200) {
			cn_a = 11;
			cn_b = (69000 - val)/1250;
		} else if (val > 47900) {
			cn_a = 12;
			cn_b = (57200 - val)/1000;
		} else if (val > 40100) {
			cn_a = 13;
			cn_b = (47900 - val)/830;
		} else if (val > 33700) {
			cn_a = 14;
			cn_b = (40100 - val)/680;
		} else if (val > 29000) {
			cn_a = 15;
			cn_b = (33700 - val)/500;
		} else if (val > 25600) {
			cn_a = 16;
			cn_b = (29000 - val)/360;
		} else if (val > 22200) {
			cn_a = 17;
			cn_b = (25600 - val)/360;
		} else if (val > 19700) {
			cn_a = 18;
			cn_b = (22200 - val)/265;
		} else if (val > 18000) {
			cn_a = 19;
			cn_b = (19700 - val)/180;
		} else if (val > 16500) {
			cn_a = 20;
			cn_b = (18000 - val)/160;
		} else if (val > 15200) {
			cn_a = 21;
			cn_b = (16500 - val)/140;
		} else if (val > 14100) {
			cn_a = 22;
			cn_b = (15200 - val)/120;
		} else if (val > 13550) {
			cn_a = 23;
			cn_b = (14100 - val)/60;
		} else if (val > 12800) {
			cn_a = 24;
			cn_b = (13550 - val)/80;
		} else if (val > 12300) {
			cn_a = 25;
			cn_b = (12800 - val)/53;
		} else if (val > 11900) {
			cn_a = 26;
			cn_b = (12300 - val)/42;
		} else if (val > 11600) {
			cn_a = 27;
			cn_b = (11900 - val)/31;
		} else if (val > 11300) {
			cn_a = 28;
			cn_b = (11600 - val)/31;
		} else if (val > 11000) {
			cn_a = 29;
			cn_b = (11300 - val)/31;
		} else if (val > 0) {
			cn_a = 30;
			cn_b = 0;
		}
	} else if (mod == 2) {
		/* 16 QAM */
		if (val > 353500) {
			cn_a = 0;
			cn_b = 0;
		} else if (val > 353500) { /* 0~ */
			cn_a = 0;
			cn_b = (365000 - val)/124;
		} else if (val > 344200) { /* 1~ */
			cn_a = 1;
			cn_b = (353500 - val)/101;
		} else if (val > 333200) { /* 2~ */
			cn_a = 2;
			cn_b = (344200 - val)/120;
		} else if (val > 325000) { /* 3~ */
			cn_a = 3;
			cn_b = (333200 - val)/90;
		} else if (val > 316700) { /* 4~ */
			cn_a = 4;
			cn_b = (325000 - val)/91;
		} else if (val > 308200) { /* 5~ */
			cn_a = 5;
			cn_b = (316700 - val)/93;
		} else if (val > 299000) { /* 6~ */
			cn_a = 6;
			cn_b = (308200 - val)/98;
		} else if (val > 295000) { /* 7~ */
			cn_a = 7;
			cn_b = (299000 - val)/1050;
		} else if (val > 280500) { /* 8~ */
			cn_a = 8;
			cn_b = (295000 - val)/1550;
		} else if (val > 264000) {
			cn_a = 9;
			cn_b = (280500 - val)/1750;
		} else if (val > 245000) {
			cn_a = 10;
			cn_b = (264000 - val)/2050;
		} else if (val > 222000) {
			cn_a = 11;
			cn_b = (245000 - val)/2450;
		} else if (val > 197000) {
			cn_a = 12;
			cn_b = (222000 - val)/2650;
		} else if (val > 172000) {
			cn_a = 13;
			cn_b = (197000 - val)/2650;
		} else if (val > 147000) {
			cn_a = 14;
			cn_b = (172000 - val)/2650;
		} else if (val > 125000) {
			cn_a = 15;
			cn_b = (147000 - val)/2350;
		} else if (val > 105000) {
			cn_a = 16;
			cn_b = (125000 - val)/2150;
		} else if (val > 88000) {
			cn_a = 17;
			cn_b = (105000 - val)/1800;
		} else if (val > 75000) {
			cn_a = 18;
			cn_b = (88000 - val)/1400;
		} else if (val > 64000) {
			cn_a = 19;
			cn_b = (75000 - val)/1180;
		} else if (val > 55000) {
			cn_a = 20;
			cn_b = (64000 - val)/980;
		} else if (val > 48000) {
			cn_a = 21;
			cn_b = (55000 - val)/750;
		} else if (val > 42000) {
			cn_a = 22;
			cn_b = (48000 - val)/640;
		} else if (val > 38000) {
			cn_a = 23;
			cn_b = (42000 - val)/420;
		} else if (val > 34900) {
			cn_a = 24;
			cn_b = (38000 - val)/330;
		} else if (val > 32000) {
			cn_a = 25;
			cn_b = (34900 - val)/310;
		} else if (val > 29500) {
			cn_a = 26;
			cn_b = (32000 - val)/265;
		} else if (val > 27100) {
			cn_a = 27;
			cn_b = (29500 - val)/250;
		} else if (val > 26000) {
			cn_a = 28;
			cn_b = (27100 - val)/118;
		} else if (val > 25200) {
			cn_a = 29;
			cn_b = (26000 - val)/85;
		} else if (val > 0) {
			cn_a = 30;
			cn_b = 0;
		}
	} else {
		cn_a = 0;
		cn_b = 0;
		return 0;
	}

	if (cn_b > 1000)
		return (cn_a*1000) + cn_b;
	else if (cn_b > 100)
		return (cn_a*1000) + (cn_b*10);
	else
		return (cn_a*1000) + (cn_b*100);
}
static unsigned int GetSNR_FULL_Mode(u8 mod, int val)
{
	unsigned int cn_a = 0;
	unsigned int cn_b = 0;

	if (mod == 1) {
		/* QPSK */
		if (val > 32500) {
			cn_a = 0;
			cn_b = 0;
			return 0;
		} else if (val > 31400) { /* 0~ */
			cn_a = 0;
			cn_b = (32500 - val)/118;
		} else if (val > 29800) { /* 1~ */
			cn_a = 1;
			cn_b = (31400 - val)/170;
		} else if (val > 27900) { /* 2~ */
			cn_a = 2;
			cn_b = (29800 - val)/205;
		} else if (val > 25500) { /* 3~ */
			cn_a = 3;
			cn_b = (27900 - val)/258;
		} else if (val > 23000) { /* 4~ */
			cn_a = 4;
			cn_b = (25500 - val)/268;
		} else if (val > 20300) { /* 5~ */
			cn_a = 5;
			cn_b = (23000 - val)/290;
		} else if (val > 17500) { /* 6~ */
			cn_a = 6;
			cn_b = (20300 - val)/300;
		} else if (val > 14600) { /* 7~ */
			cn_a = 7;
			cn_b = (17500 - val)/310;
		} else if (val > 12000) { /* 8~ */
			cn_a = 8;
			cn_b = (14600 - val)/280;
		} else if (val > 9750) {
			cn_a = 9;
			cn_b = (12000 - val)/240;
		} else if (val > 7600) {
			cn_a = 10;
			cn_b = (9750 - val)/230;
		} else if (val > 6100) {
			cn_a = 11;
			cn_b = (7600 - val)/160;
		} else if (val > 5000) {
			cn_a = 12;
			cn_b = (6100 - val)/118;
		} else if (val > 3950) {
			cn_a = 13;
			cn_b = (5000 - val)/112;
		} else if (val > 3200) {
			cn_a = 14;
			cn_b = (3950 - val)/80;
		} else if (val > 2580) {
			cn_a = 15;
			cn_b = (3200 - val)/65;
		} else if (val > 2100) {
			cn_a = 16;
			cn_b = (2580 - val)/51;
		} else if (val > 1720) {
			cn_a = 17;
			cn_b = (2100 - val)/40;
		} else if (val > 1390) {
			cn_a = 18;
			cn_b = (1720 - val)/35;
		} else if (val > 1160) {
			cn_a = 19;
			cn_b = (1390 - val)/24;
		} else if (val > 980) {
			cn_a = 20;
			cn_b = (1160 - val)/19;
		} else if (val > 820) {
			cn_a = 21;
			cn_b = (980 - val)/17;
		} else if (val > 700) {
			cn_a = 22;
			cn_b = (820 - val)/13;
		} else if (val > 600) {
			cn_a = 23;
			cn_b = (700 - val)/11;
		} else if (val > 520) {
			cn_a = 24;
			cn_b = (600 - val)/8;
		} else if (val > 450) {
			cn_a = 25;
			cn_b = (520 - val)/7;
		} else if (val > 410) {
			cn_a = 26;
			cn_b = (450 - val)/4;
		} else if (val > 380) {
			cn_a = 27;
			cn_b = (410 - val)/3;
		} else if (val > 350) {
			cn_a = 28;
			cn_b = (380 - val)/3;
		} else if (val > 330) {
			cn_a = 29;
			cn_b = (350 - val)/2;
		} else if (val > 0) {
			cn_a = 30;
			cn_b = 0;
		}
	} else if (mod == 2) {
		/* 16 QAM */
		if (val > 42000) {
			cn_a = 0;
			cn_b = 0;
		} else if (val > 40500) { /* 0~ */
			cn_a = 0;
			cn_b = (42000 - val)/160;
		} else if (val > 39000) { /* 1~ */
			cn_a = 1;
			cn_b = (40500 - val)/160;
		} else if (val > 38000) { /* 2~ */
			cn_a = 2;
			cn_b = (39000 - val)/108;
		} else if (val > 37000) {
			cn_a = 3;
			cn_b = (38000 - val)/108;
		} else if (val > 36000) {
			cn_a = 4;
			cn_b = (37000 - val)/108;
		} else if (val > 35000) {
			cn_a = 5;
			cn_b = (36000 - val)/108;
		} else if (val > 34000) {
			cn_a = 6;
			cn_b = (35000 - val)/108;
		} else if (val > 32900) {
			cn_a = 7;
			cn_b = (34000 - val)/118;
		} else if (val > 31800) {
			cn_a = 8;
			cn_b = (32900 - val)/118;
		} else if (val > 29500) {
			cn_a = 9;
			cn_b = (31800 - val)/248;
		} else if (val > 27000) {
			cn_a = 10;
			cn_b = (29500 - val)/270;
		} else if (val > 24300) {
			cn_a = 11;
			cn_b = (27000 - val)/290;
		} else if (val > 21400) {
			cn_a = 12;
			cn_b = (24300 - val)/315;
		} else if (val > 18500) {
			cn_a = 13;
			cn_b = (21400 - val)/315;
		} else if (val > 15600) {
			cn_a = 14;
			cn_b = (18500 - val)/315;
		} else if (val > 13000) {
			cn_a = 15;
			cn_b = (15600 - val)/280;
		} else if (val > 10600) {
			cn_a = 16;
			cn_b = (13000 - val)/260;
		} else if (val > 8700) {
			cn_a = 17;
			cn_b = (10600 - val)/206;
		} else if (val > 7200) {
			cn_a = 18;
			cn_b = (8700 - val)/160;
		} else if (val > 6100) {
			cn_a = 19;
			cn_b = (7200 - val)/118;
		} else if (val > 5050) {
			cn_a = 20;
			cn_b = (6100 - val)/112;
		} else if (val > 4100) {
			cn_a = 21;
			cn_b = (5050 - val)/102;
		} else if (val > 3600) {
			cn_a = 22;
			cn_b = (4100 - val)/53;
		} else if (val > 3100) {
			cn_a = 23;
			cn_b = (3600 - val)/53;
		} else if (val > 2650) {
			cn_a = 24;
			cn_b = (3100 - val)/48;
		} else if (val > 2400) {
			cn_a = 25;
			cn_b = (2650 - val)/27;
		} else if (val > 2200) {
			cn_a = 26;
			cn_b = (2400 - val)/22;
		} else if (val > 2000) {
			cn_a = 27;
			cn_b = (2200 - val)/22;
		} else if (val > 1820) {
			cn_a = 28;
			cn_b = (2000 - val)/19;
		} else if (val > 1750) {
			cn_a = 29;
			cn_b = (1820 - val)/7;
		} else if (val > 0) {
			cn_a = 30;
			cn_b = 0;
		}
	} else if (mod == 3) {
		/* 64 QAM */
		if (val > 43000) {
			cn_a = 0;
			cn_b = 0;
		} else if (val > 40700) { /* 0~ */
			cn_a = 0;
			cn_b = (43000 - val)/250;
		} else if (val > 40000) { /* 1~ */
			cn_a = 1;
			cn_b = (40700 - val)/75;
		} else if (val > 38600) {
			cn_a = 2;
			cn_b = (40000 - val)/150;
		} else if (val > 37500) {
			cn_a = 3;
			cn_b = (38600 - val)/118;
		} else if (val > 36800) {
			cn_a = 4;
			cn_b = (37500 - val)/74;
		} else if (val > 36100) {
			cn_a = 5;
			cn_b = (36800 - val)/74;
		} else if (val > 35500) {
			cn_a = 6;
			cn_b = (36100 - val)/64;
		} else if (val > 35000) {
			cn_a = 7;
			cn_b = (35500 - val)/53;
		} else if (val > 34600) {
			cn_a = 8;
			cn_b = (35000 - val)/43;
		} else if (val > 34050) {
			cn_a = 9;
			cn_b = (34600 - val)/59;
		} else if (val > 33500) {
			cn_a = 10;
			cn_b = (34050 - val)/59;
		} else if (val > 32900) {
			cn_a = 11;
			cn_b = (33500 - val)/64;
		} else if (val > 32100) {
			cn_a = 12;
			cn_b = (32900 - val)/85;
		} else if (val > 31200) {
			cn_a = 13;
			cn_b = (32100 - val)/96;
		} else if (val > 30400) {
			cn_a = 14;
			cn_b = (31200 - val)/85;
		} else if (val > 29200) {
			cn_a = 15;
			cn_b = (30400 - val)/128;
		} else if (val > 27800) {
			cn_a = 16;
			cn_b = (29200 - val)/150;
		} else if (val > 25900) {
			cn_a = 17;
			cn_b = (27800 - val)/205;
		} else if (val > 23800) {
			cn_a = 18;
			cn_b = (25900 - val)/228;
		} else if (val > 21500) {
			cn_a = 19;
			cn_b = (23800 - val)/248;
		} else if (val > 19300) {
			cn_a = 20;
			cn_b = (21500 - val)/235;
		} else if (val > 17300) {
			cn_a = 21;
			cn_b = (19300 - val)/215;
		} else if (val > 15300) {
			cn_a = 22;
			cn_b = (17300 - val)/215;
		} else if (val > 13500) {
			cn_a = 23;
			cn_b = (15300 - val)/190;
		} else if (val > 11800) {
			cn_a = 24;
			cn_b = (13500 - val)/182;
		} else if (val > 10500) {
			cn_a = 25;
			cn_b = (11800 - val)/140;
		} else if (val > 9300) {
			cn_a = 26;
			cn_b = (10500 - val)/130;
		} else if (val > 8500) {
			cn_a = 27;
			cn_b = (9300 - val)/86;
		} else if (val > 8000) {
			cn_a = 28;
			cn_b = (8500 - val)/53;
		} else if (val > 7500) {
			cn_a = 29;
			cn_b = (8000 - val)/53;
		} else if (val > 0) {
			cn_a = 30;
			cn_b = 0;
		}
	} else {
		cn_a = 0;
		cn_b = 0;
		return 0;
	}

	if (cn_b > 1000)
		return (cn_a*1000) + cn_b;
	else if (cn_b > 100)
		return (cn_a*1000) + (cn_b*10);
	else
		return (cn_a*1000) + (cn_b*100);
}


static int mtv_rf_init(struct mtv23x_dev*dev)
{
	int ret,nNumTbalEntry = 0,i=0;
	struct RTV_REG_INIT_INFO t_mtv23x_INIT[] = {
		{0x25, 0xF8},
		{0x26, 0x00},
		{0x28, 0xDD},
		{0x29, 0xC4},
		{0x2C, 0x1D},
		{0x2D, 0x90},
		{0x2F, 0x06},
		{0x30, 0xDF},
		{0x33, 0x11},
		{0x36, 0x09},
		{0x38, 0xF0},
		{0x39, 0x00},
		{0x3A, 0xAA},
		{0x3E, 0x2D},
		{0x47, 0x59},
		{0x48, 0x28},
		{0x49, 0x41},
		{0x4A, 0x70},
		{0x4B, 0x65},
		{0x4E, 0x4B},
		{0x50, 0x6F},
		{0x51, 0x3C},
		{0x53, 0x65},
		{0x54, 0xC0},
		{0x5D, 0x01},
		{0x5E, 0x70},
		{0x5F, 0x75},
		{0x60, 0x62},
		{0x61, 0x80},
		{0x69, 0x0E},
		{0x6A, 0x14},
		{0x6B, 0x18},
		{0x6C, 0xFF},
		{0x6D, 0xFD},
		{0x6E, 0x19},
		{0x70, 0x80},
		{0x71, 0x6E},
		{0x74, 0x15},
		{0x75, 0xA4},
		{0x77, 0x69},
		{0x78, 0x3D},
		{0x7D, 0x28},
		{0x81, 0x9C},
		{0x83, 0x9F},
		{0x85, 0x40},
		{0x86, 0x87},
		{0x87, 0x84},
		{0x88, 0x22},
		{0x89, 0x20},
		{0x8A, 0xF6},
		{0x8B, 0xB5},
		{0x8C, 0xFC},
		{0x8D, 0xFF},
		{0x8E, 0xFE},
		{0x8F, 0xFD},
		{0x90, 0xFD},
		{0x91, 0xFC},
		{0x92, 0x0E},
		{0x93, 0x0D},
		{0x94, 0x09},
		{0x95, 0xA3},
		{0x96, 0xF0},
		{0x97, 0x19},
		{0x99, 0x42},
		{0x9A, 0x6C},
		{0x9B, 0x10},
		{0x9C, 0x8E},
		{0x9D, 0x3C},
		{0x9E, 0x30},
		{0x9F, 0x63},
		{0xA1, 0x40},
		{0xA2, 0x5C},
		{0xA3, 0x1C},
		{0xA4, 0x85},
		{0xA5, 0xB4},
		{0xA6, 0x30},
		{0xA7, 0x00},
		{0xA9, 0x00},
		{0xAA, 0x04},
		{0xAB, 0x30},
		{0xAC, 0x00},
		{0xAD, 0x14},
		{0xAE, 0x30},
		{0xAF, 0x00},
		{0xB1, 0x00},
		{0xB2, 0x04},
		{0xB3, 0x30},
		{0xB4, 0x00},
		{0xB5, 0xB1},
		{0xB7, 0x05},
		{0xBC, 0x1F},
		{0xBD, 0x1F},
		{0xBE, 0x5F},
		{0xBF, 0x1F},
		{0xC0, 0x1F},
		{0xC1, 0x5F},
		{0xC2, 0x1F},
		{0xC3, 0x1F},
		{0xC4, 0x5F},
		{0xC6, 0x4A},
		{0xC7, 0x4A},
		{0xCA, 0xCA},
		{0xCB, 0x4A},
		{0xCC, 0x4F},
		{0xCF, 0x80},
		{0xD0, 0x20},
		{0xD4, 0x1F},
		{0xD7, 0x80},
		{0xD8, 0x00},
		{0xDA, 0xA4},
		{0xDF, 0x01},
		{0xE2, 0x24},
		{0xE5, 0xA8},
		{0xE6, 0xA6},
		{0xE7, 0x64}
	};
	nNumTbalEntry = sizeof(t_mtv23x_INIT)/sizeof(struct RTV_REG_INIT_INFO );

	do {
		 ret = regmap_write(dev->regmap,t_mtv23x_INIT[i].bReg,t_mtv23x_INIT[i].bVal);
		 i++;
		}
	while(--nNumTbalEntry);


	return ret;

}
static int mtv_configTS(struct mtv23x_dev*dev)
{
	u8 REG9F;
	int temp;
	
	regmap_write(dev->regmap,MAP_SEL_REG,FEC_PAGE);
	regmap_read(dev->regmap,0x9F,&temp);
	REG9F = temp & 0x55;
	switch(dev->ts_mode){
		case 0: /* EN_high, CLK_rising */
			regmap_write(dev->regmap,0x9F, (REG9F | 0x00));
			regmap_write(dev->regmap,0xA6, 0x88);
			regmap_write(dev->regmap,0xA7, 0x48);
		break;
		case 1: /* EN_high, CLK_falling */
			regmap_write(dev->regmap,0x9F, (REG9F | 0x00));
			regmap_write(dev->regmap,0xA6, 0x88);
			regmap_write(dev->regmap,0xA7, 0x40);
		break;
		case 2: /* EN_low, CLK_rising */
			regmap_write(dev->regmap,0x9F, (REG9F | 0x20));
			regmap_write(dev->regmap,0xA6, 0x88);
			regmap_write(dev->regmap,0xA7, 0x48);
		break;
		case 3: /* EN_low, CLK_falling */
			regmap_write(dev->regmap,0x9F, (REG9F | 0x20));
			regmap_write(dev->regmap,0xA6, 0x88);
			regmap_write(dev->regmap,0xA7, 0x40);
		break;
		case 4: /* EN_high, CLK_rising + 1CLK add */
			regmap_write(dev->regmap,0x9F, (REG9F | 0x00));
			regmap_write(dev->regmap,0xA6, 0x88);
			regmap_write(dev->regmap,0xA7, 0x4C);
		break;
		case 5:	/* EN_high, CLK_falling + 1CLK add */
			regmap_write(dev->regmap,0x9F, (REG9F | 0x00));
			regmap_write(dev->regmap,0xA6, 0x88);
			regmap_write(dev->regmap,0xA7, 0x44);
		break;
		case 6: /* Parallel: EN_high, CLK_rising*/
			regmap_write(dev->regmap,0x9F, (REG9F | 0x00));
			regmap_write(dev->regmap,0xA6, 0x80);
			regmap_write(dev->regmap,0xA7, 0x48);
		break;
		case 7: /* Parallel: EN_high, CLK_falling */
			regmap_write(dev->regmap,0x9F, (REG9F | 0x00));
			regmap_write(dev->regmap,0xA6, 0x80);
			regmap_write(dev->regmap,0xA7, 0x40);
		break;
		default:
			printk("Code not present\n");
		break;
		}
	regmap_update_bits(dev->regmap,0xA4, 0x01, 0x01); /* TEI Enable */

	regmap_write(dev->regmap,0xA8, 0x87);
	regmap_write(dev->regmap,0xA9, (0xB8|0x01/*TS speed*/)); //set TS speed 1:30M 0:60M

	regmap_write(dev->regmap,0xAB, 0x87);

	return 0;
}
static int rtv_softReset(struct mtv23x_dev*dev)
{
	if(dev->rtv_1seglpmode)
		regmap_write(dev->regmap,MAP_SEL_REG,LPOFDM_PAGE);
	else
		regmap_write(dev->regmap,MAP_SEL_REG,OFDM_PAGE);
	
	regmap_update_bits(dev->regmap,0x10, 0x01, 0x01);
	regmap_update_bits(dev->regmap,0x10, 0x01, 0x00);
	
	regmap_write(dev->regmap,MAP_SEL_REG,FEC_PAGE);
	regmap_update_bits(dev->regmap,0xFB, 0x01, 0x01);
	regmap_update_bits(dev->regmap,0xFB, 0x01, 0x00);

	return 0;

}
static int mtv23x_init(struct dvb_frontend *fe)
{
	struct i2c_client*client = fe->demodulator_priv;
	struct mtv23x_dev*dev = i2c_get_clientdata(client);
	int ret,i,temp,read0,read1 ;
	u8 rev_num;
	u8 ALDO_OUT = 6,DLDO_OUT = 1;
	
	ret  = regmap_write(dev->regmap,MAP_SEL_REG,TOP_PAGE);
	ret |= regmap_write(dev->regmap,0x0C,0xC3);
	for(i = 0; i < 100 ; i++){
		regmap_read(dev->regmap,0x00,&read0);
		regmap_read(dev->regmap,0x01,&read1);

		if(read0 == 0xC6)
			goto RTV_POWER_ON_SUCCESS;
		msleep(5);
	}
	dev_err(&client->dev,"MTV23x Power on failed!!\n");
	return -1;
	
RTV_POWER_ON_SUCCESS:
	ret  = regmap_write(dev->regmap,MAP_SEL_REG,RF_PAGE);
	ret |= regmap_read(dev->regmap,0x10,&temp);
	rev_num = (temp&0xF0)>>4;
	if(rev_num>=0x05){
		regmap_update_bits(dev->regmap,0x3B, 0x01, 0x01);
		regmap_update_bits(dev->regmap,0x32, 0x01, 0x01);
	}
	ret  = regmap_write(dev->regmap,MAP_SEL_REG,RF_PAGE);
	ret |= regmap_update_bits(dev->regmap,0xC8, 0x80, ((ALDO_OUT & 0x04) << 5));
	ret |= regmap_update_bits(dev->regmap,0xD1, 0x80, ((ALDO_OUT & 0x02) << 6));
	ret |= regmap_update_bits(dev->regmap,0xD2, 0x80, ((ALDO_OUT & 0x01) << 7));
	ret |= regmap_update_bits(dev->regmap,0xD3, 0x80, ((DLDO_OUT & 0x04) << 5));
	ret |= regmap_update_bits(dev->regmap,0xD5, 0x80, ((DLDO_OUT & 0x02) << 6));
	ret |= regmap_update_bits(dev->regmap,0xD6, 0x80, ((DLDO_OUT & 0x01) << 7));
	if(ret)
		goto err;

	msleep(10);
	regmap_update_bits(dev->regmap,0xC9, 0x80, 0x80);

	/*Internal LDO mode*/
	ret = regmap_write(dev->regmap,0xCD, 0x4F);
	ret = regmap_write(dev->regmap,0xCE, 0x35);
	if(ret)
		goto err;

	/*init mtv_RF*/
	ret = mtv_rf_init(dev);
	if(ret)
		goto err;
	/*init demod*/
	regmap_write(dev->regmap,MAP_SEL_REG,TOP_PAGE);
	regmap_write(dev->regmap,0x09, 0x00);

	regmap_write(dev->regmap,MAP_SEL_REG,HOST_PAGE);
	regmap_write(dev->regmap,0x28, 0x70);

	regmap_write(dev->regmap,MAP_SEL_REG,LPOFDM_PAGE);
//	regmap_write(dev->regmap,0x71, 0xAA);
//	regmap_write(dev->regmap,0x8E, 0x0A);

	regmap_write(dev->regmap,0x34, 0x9F);
	regmap_write(dev->regmap,0x35, 0xFF);
	regmap_write(dev->regmap,0x36, 0x01);
	
	regmap_write(dev->regmap,0x71, 0xAA);
	regmap_write(dev->regmap,0x8E, 0x15);


	regmap_write(dev->regmap,MAP_SEL_REG,OFDM_PAGE);

	regmap_write(dev->regmap,0xB3, 0x31);
	regmap_write(dev->regmap,0xCA, 0x10);
	regmap_update_bits(dev->regmap,0x7E, 0x60, 0x60);

	regmap_write(dev->regmap,0x81, 0xFF);
	regmap_write(dev->regmap,0x82, 0xFF);

	regmap_write(dev->regmap,0x6D, 0x4A);
	regmap_write(dev->regmap,0xB8, 0xA8);
//	regmap_write(dev->regmap,0xC6, 0x78);
	regmap_write(dev->regmap,0xC6, 0xFF);


	regmap_write(dev->regmap,0x6F, 0x21);
	regmap_write(dev->regmap,0xC9, 0x80);
	regmap_write(dev->regmap,0x5F, 0x10);

	regmap_write(dev->regmap,0x58, 0x5A);
	regmap_write(dev->regmap,0x5E, 0x10);
	regmap_write(dev->regmap,0xCB, 0x02);

	regmap_write(dev->regmap,MAP_SEL_REG,DATA_PAGE);
	regmap_write(dev->regmap,0x8C, 0x80);
	regmap_write(dev->regmap,0x8F, 0x40);
	regmap_write(dev->regmap,0xDB, 0x01);
	regmap_write(dev->regmap,0xD8, 0x10);

	regmap_write(dev->regmap,MAP_SEL_REG,FEC_PAGE);
	regmap_write(dev->regmap,0x44, 0x68);
	regmap_write(dev->regmap,0x47, 0x40);

	regmap_write(dev->regmap,0x16, 0xFF);
	regmap_write(dev->regmap,0x17, 0xFF);
	regmap_write(dev->regmap,0x18, 0xFF);
	regmap_write(dev->regmap,0x19, 0xFF);
	regmap_write(dev->regmap,0xA7, 0x40);
	regmap_write(dev->regmap,0xA8, 0x80);
	regmap_write(dev->regmap,0xA9, 0xB9);
	regmap_write(dev->regmap,0xAA, 0x80);
	regmap_write(dev->regmap,0xAB, 0x80);

	regmap_write(dev->regmap,0x5C, 0x10);
	regmap_write(dev->regmap,0x5F, 0x10);

	regmap_write(dev->regmap,0xFC, 0x83);
	regmap_write(dev->regmap,0xFF, 0x03);

	mtv_configTS(dev);
	rtv_softReset(dev);
	
	return 0;


err:
	dev_err(&client->dev,"Failed = %d\n",ret);
	return ret;

}

static int rtvRF_LockCheck(struct mtv23x_dev*dev,u8 bCheckBlock)
{
	int temp, i = 0,ret = 0;
	
	u8 nLockCheck = 0;

	regmap_write(dev->regmap,MAP_SEL_REG,RF_PAGE);

	switch (bCheckBlock) {
	case 0: /* O == RF Lock Check */
		for (i = 0; i < 10; i++) {
			regmap_read(dev->regmap,0x1B,&temp);
			nLockCheck = temp & 0x02;
			if (nLockCheck)
				break;
			else
				printk("[rtvRF_LockCheck]VCheck(%d)\n", i);
			msleep(1);
		}

		if (i == 10) {
			printk("[rtvRF_LockCheck] VCO Pll unlocked!\n");
			ret = -3;
		}
		break;

	case 1: /* CLK Synth Lock Check */
		for (i = 0; i < 10; i++) {
			regmap_read(dev->regmap,0x1B,&temp);
			nLockCheck = temp & 0x01;
			if (nLockCheck)
				break;
			else
				printk("[rtvRF_LockCheck]SCheck(%d)\n", i);
			msleep(1);
		}

		if (i == 10) {
			printk("[rtvRF_LockCheck] ADC clock unlocked!\n");
			ret = -2;
		}
		break;
	}

	return ret;
}

static int rtvRF_SetOfdmPara(struct mtv23x_dev*dev,enum E_RTV_SERVICE_TYPE eServiceType,
			enum E_RTV_BANDWIDTH_TYPE eLpfBwType, u32 dwChFreqKHz)
{
	int nRet = 0;
	int nNumAdcType = 0;
	const struct RTV_ADC_CFG_INFO *ptOfdmCfgTbl = NULL;
	int freqMHz = dwChFreqKHz / 1000;
	
	struct RTV_ADC_CFG_INFO g_atAdcCfgTbl_ISDBT_6MHz[] = {
	/*8*/	 {0x00, 0x06, 0x48, 0x2E, 0x29,0x10410410,0x1B6C8B43,0x208208,0x41},
	/*9*/	 {0x00, 0x04, 0x36, 0x2E, 0x29,0x0E72AE47,0x18607BCA,0x1CE55C,0x39},
	/*19.2*/ {0x08, 0x05, 0x48, 0x2E, 0x29,0x6C5C1B17,0x00000000,0x0D8B83,0x1B},
	/*20.0*/ {0x08, 0x05, 0x4B, 0x2E, 0x29,0x68068068,0x00000000,0x0D00D0,0x1A},
	/*20.48*/{0x08, 0x19, 0x80, 0x6E, 0x29,0x65965965,0x00000000,0x0CB2CB,0x19} 
	};
	struct RTV_ADC_CFG_INFO g_atAdcCfgTbl_ISDBT_7MHz[] = {
	/*8*/	 {0x00, 0x06, 0x48, 0x2E, 0x29,0x12F684BD,0x1B6C8B43,0x25ED09,0x4B},
	/*9*/	 {0x00, 0x04, 0x36, 0x2E, 0x29,0x10DB20A8,0x18607BCA,0x21B641,0x43},
	/*19.2*/ {0x08, 0x05, 0x48, 0x2E, 0x29,0x7E6B74F0,0x00000000,0x0FCD6E,0x1F},
	/*20.0*/ {0x08, 0x05, 0x4B, 0x2E, 0x29,0x795CEB24,0x00000000,0x0F2B9D,0x1E},
	/*20.48*/{0x08, 0x19, 0x80, 0x6E, 0x29,0x7684BDA1,0x00000000,0x0ED097,0x1D} 
	};
	struct RTV_ADC_CFG_INFO g_atAdcCfgTbl_ISDBT_8MHz[] = {
	/*8*/	 {0x00, 0x06, 0x48, 0x2E, 0x29,0x15AC056B,0x1B6C8B43,0x2B580A,0x56},
	/*9*/	 {0x00, 0x04, 0x36, 0x2E, 0x29,0x13439309,0x18607BCA,0x268726,0x4D},
	/*19.2*/ {0x08, 0x05, 0x48, 0x2E, 0x29,0x907ACEC9,0x00000000,0x120F59,0x24},
	/*20.0*/ {0x08, 0x05, 0x4B, 0x2E, 0x29,0x8AB355E0,0x00000000,0x11566A,0x22},
	/*20.48*/{0x08, 0x19, 0x80, 0x6E, 0x29,0x877321DC,0x00000000,0x10EE64,0x21} 
	};
	switch (eServiceType) {
	case RTV_SERVICE_UHF_ISDBT_1seg:
		nNumAdcType = 1; /* ADC 9MHz */
		switch (eLpfBwType) {
		case RTV_BW_MODE_6MHZ:
		case RTV_BW_MODE_430KHZ:
			if ((freqMHz == 485) || (freqMHz == 503)
			|| (freqMHz == 539) || (freqMHz == 647)
			|| (freqMHz == 665) || (freqMHz == 683)
			|| (freqMHz == 755))
				nNumAdcType = 0; /* ADC 8MHz */

			ptOfdmCfgTbl = &g_atAdcCfgTbl_ISDBT_6MHz[nNumAdcType];
			break;

		case RTV_BW_MODE_7MHZ:
		case RTV_BW_MODE_500KHZ:
			ptOfdmCfgTbl = &g_atAdcCfgTbl_ISDBT_7MHz[nNumAdcType];
			break;

		case RTV_BW_MODE_8MHZ:
		case RTV_BW_MODE_571KHZ:
			ptOfdmCfgTbl = &g_atAdcCfgTbl_ISDBT_8MHz[nNumAdcType];
			break;
		default:
			printk("[rtvRF_SetOfdmPara] Unsupport 1seg BW\n");
			return -9;
		}
		break;

	case RTV_SERVICE_VHF_ISDBTmm_1seg:
		nNumAdcType = 0; /* ADC 8MHz */
		switch (eLpfBwType) {
		case RTV_BW_MODE_6MHZ:
		case RTV_BW_MODE_430KHZ:
			ptOfdmCfgTbl = &g_atAdcCfgTbl_ISDBT_6MHz[nNumAdcType];
			break;
		default:
			 printk("[rtvRF_SetOfdmPara] Unsupport Tmm1seg\n");
			 return -9;
		}
		break;

	case RTV_SERVICE_VHF_ISDBTsb_1seg:
		nNumAdcType = 1; /* ADC 9MHz */
		switch (eLpfBwType) {
		case RTV_BW_MODE_6MHZ:
		case RTV_BW_MODE_430KHZ:
			ptOfdmCfgTbl = &g_atAdcCfgTbl_ISDBT_6MHz[nNumAdcType];
			break;
		default:
			printk("[rtvRF_SetOfdmPara] Unsupport Tsb1seg\n");
			return -9;
		}
		break;

	case RTV_SERVICE_VHF_ISDBTsb_3seg:
		 printk("[rtvRF_SetOfdmPara] Unsupport Tsb3seg\n");
		 return -9;

	case RTV_SERVICE_VHF_ISDBTmm_13seg:
		nNumAdcType = 4; /* ADC 20.48MHz */
		ptOfdmCfgTbl = &g_atAdcCfgTbl_ISDBT_6MHz[nNumAdcType];
		break;

	case RTV_SERVICE_UHF_ISDBT_13seg:
		if ((freqMHz == 551) || (freqMHz == 581) ||
		(freqMHz == 611) || (freqMHz == 617) ||
		(freqMHz == 647) || (freqMHz == 677) ||
		(freqMHz == 707) || (freqMHz == 737) ||
		(freqMHz == 767) || (freqMHz == 797))
			nNumAdcType = 2; /* ADC 19.2MHz */
		else if ((freqMHz == 491) || (freqMHz == 521))
			nNumAdcType = 3; /* ADC 20.0MHz */
		else
			nNumAdcType = 4; /* ADC 20.48MHz */

		switch (eLpfBwType) {
		case RTV_BW_MODE_6MHZ:
			ptOfdmCfgTbl = &g_atAdcCfgTbl_ISDBT_6MHz[nNumAdcType];
			break;
		case RTV_BW_MODE_7MHZ:
			ptOfdmCfgTbl = &g_atAdcCfgTbl_ISDBT_7MHz[nNumAdcType];
			break;
		case RTV_BW_MODE_8MHZ:
			ptOfdmCfgTbl = &g_atAdcCfgTbl_ISDBT_8MHz[nNumAdcType];
			break;
		default:
			printk("[rtvRF_SetOfdmPara] Unsupport 13seg\n");
			return -9;
		}
		break;
	default:
			printk("[rtvRF_SetOfdmPara] Invaild Service Type\n");
		return -9;
	}

	regmap_write(dev->regmap,MAP_SEL_REG,RF_PAGE);
	regmap_write(dev->regmap,0x2A, ptOfdmCfgTbl->bData2A);
	regmap_write(dev->regmap,0x6E, ptOfdmCfgTbl->bData6E);
	regmap_write(dev->regmap,0x70, ptOfdmCfgTbl->bData70);
	regmap_write(dev->regmap,0x71, ptOfdmCfgTbl->bData71);
	regmap_update_bits(dev->regmap,0x75, 0xFC, (ptOfdmCfgTbl->bData75 << 2));

	if (rtvRF_LockCheck(dev,1) != 0)
		return -2;

	if ((eServiceType == RTV_SERVICE_UHF_ISDBT_1seg) ||
	(eServiceType == RTV_SERVICE_VHF_ISDBTmm_1seg) ||
	(eServiceType == RTV_SERVICE_VHF_ISDBTsb_1seg) ||
	(eServiceType == RTV_SERVICE_VHF_ISDBTsb_3seg)) {
		regmap_write(dev->regmap,MAP_SEL_REG,LPOFDM_PAGE);
		regmap_write(dev->regmap,0x14, (u8)((ptOfdmCfgTbl->dwTNCO >> 0) & 0xFF));
		regmap_write(dev->regmap,0x15, (u8)((ptOfdmCfgTbl->dwTNCO >>  8) & 0xFF));
		regmap_write(dev->regmap,0x16, (u8)((ptOfdmCfgTbl->dwTNCO >> 16) & 0xFF));
		regmap_write(dev->regmap,0x17, (u8)((ptOfdmCfgTbl->dwTNCO >> 24) & 0xFF));

		regmap_write(dev->regmap,0x18, (u8)((ptOfdmCfgTbl->dwPNCO >> 0) & 0xFF));
		regmap_write(dev->regmap,0x19, (u8)((ptOfdmCfgTbl->dwPNCO >> 8) & 0xFF));
		regmap_write(dev->regmap,0x1A, (u8)((ptOfdmCfgTbl->dwPNCO >> 16) & 0xFF));
		regmap_write(dev->regmap,0x1B, (u8)((ptOfdmCfgTbl->dwPNCO >> 24) & 0xFF));

		regmap_write(dev->regmap,0x1C, (u8)((ptOfdmCfgTbl->dwGAIN) & 0xFF));

		regmap_write(dev->regmap,0x1D, (u8)((ptOfdmCfgTbl->dwCFREQGAIN>>0) & 0xFF));
		regmap_write(dev->regmap,0x1E, (u8)((ptOfdmCfgTbl->dwCFREQGAIN>>8) & 0xFF));
		regmap_write(dev->regmap,0x1F, (u8)((ptOfdmCfgTbl->dwCFREQGAIN>>16) & 0xFF));
	} else {
		regmap_write(dev->regmap,MAP_SEL_REG,OFDM_PAGE);
		switch (eLpfBwType) {
		case RTV_BW_MODE_5MHZ:
			regmap_update_bits(dev->regmap,0x11, 0x01, 0x00);
			regmap_update_bits(dev->regmap,0x10, 0xE0, 0xB0);
			regmap_update_bits(dev->regmap,0x1F, 0xC0, 0xC0);
			break;
		case RTV_BW_MODE_6MHZ:
			regmap_update_bits(dev->regmap,0x11, 0x01, 0x00);
			regmap_update_bits(dev->regmap,0x10, 0xE0, 0xC0);
			regmap_update_bits(dev->regmap,0x1F, 0xC0, 0x80);
			break;
		case RTV_BW_MODE_7MHZ:
			regmap_update_bits(dev->regmap,0x11, 0x01, 0x00);
			regmap_update_bits(dev->regmap,0x10, 0xE0, 0xE0);
			regmap_update_bits(dev->regmap,0x1F, 0xC0, 0x40);
			break;
		case RTV_BW_MODE_8MHZ:
			regmap_update_bits(dev->regmap,0x11, 0x01, 0x01);
			regmap_update_bits(dev->regmap,0x10, 0xE0, 0x00);
			regmap_update_bits(dev->regmap,0x1F, 0xC0, 0x00);
			break;
		default:
			printk("[rtvRF_SetFrequency] Unsupported BW\n");
			return -9;
			break;
		}

		regmap_write(dev->regmap,0x34, (u8)((ptOfdmCfgTbl->dwTNCO>>0) & 0xFF));
		regmap_write(dev->regmap,0x35, (u8)((ptOfdmCfgTbl->dwTNCO>>8) & 0xFF));
		regmap_write(dev->regmap,0x36, (u8)((ptOfdmCfgTbl->dwTNCO>>16) & 0xFF));
		regmap_write(dev->regmap,0x37, (u8)((ptOfdmCfgTbl->dwTNCO>>24) & 0xFF));

		regmap_write(dev->regmap,0x38, (u8) (ptOfdmCfgTbl->dwPNCO>>0));
		regmap_write(dev->regmap,0x39, (u8) (ptOfdmCfgTbl->dwPNCO>>8));
		regmap_write(dev->regmap,0x3A, (u8) (ptOfdmCfgTbl->dwPNCO>>16));
		regmap_write(dev->regmap,0x3B, (u8) (ptOfdmCfgTbl->dwPNCO>>24));

		regmap_write(dev->regmap,0x3D, (u8)((ptOfdmCfgTbl->dwCFREQGAIN>>0) & 0xFF));
		regmap_write(dev->regmap,0x3E, (u8)((ptOfdmCfgTbl->dwCFREQGAIN>>8) & 0xFF));
		regmap_write(dev->regmap,0x3F, (u8)((ptOfdmCfgTbl->dwCFREQGAIN>>16) & 0xFF));

		regmap_update_bits(dev->regmap,0x55, 0xC0, (ptOfdmCfgTbl->dwGAIN & 0x03));
		regmap_write(dev->regmap,0x56, (ptOfdmCfgTbl->dwGAIN>>2) & 0xFF);
	}

	return nRet;
}

static int rtvRF_ConfigureClkCKSYN(struct mtv23x_dev*dev,enum E_RTV_BANDWIDTH_TYPE eBwType)
{
	int temp;
	u8 WR6D = 0, WR6E = 0, WR70 = 0, WR71 = 0;
	u8 WR2A = 0, WR72 = 0, WR73 = 0, WR74 = 0, WR75 = 0;

	const u16 g_atBW_TABLE_CKSYN[MAX_NUM_RTV_BW_MODE_TYPE][9] = 
	{
	/*RTV_BW_MODE_5MHZ*/	{0x19,0x180,0x01,0x01,0x2E,0x13,0x0E,0x01,0x29},
	/*RTV_BW_MODE_6MHZ*/	{0x19,0x180,0x01,0x01,0x2E,0x13,0x0E,0x01,0x29},
	/*RTV_BW_MODE_7MHZ*/	{0x19,0x180,0x01,0x01,0x2E,0x13,0x0E,0x01,0x29},
	/*RTV_BW_MODE_8MHZ*/	{0x19,0x180,0x01,0x01,0x2E,0x13,0x0E,0x01,0x29},
	/*RTV_BW_MODE_430KHZ*/	{0x04,0x36, 0x01,0x00,0x2E,0x13,0x0E,0x01,0x29},
	/*RTV_BW_MODE_500KHZ*/	{0x0A,0x7B, 0x01,0x00,0x2E,0x13,0x0E,0x01,0x29},
	/*RTV_BW_MODE_571KHZ*/	{0x14,0xAB, 0x00,0x00,0x2E,0x13,0x0E,0x01,0x29},
	/*RTV_BW_MODE_768KHZ*/	{0x06,0x48, 0x01,0x00,0x2E,0x13,0x0E,0x01,0x29},
	/*RTV_BW_MODE_1290KHZ*/ {0x05,0x24, 0x00,0x00,0x2E,0x13,0x0E,0x01,0x29}
	};


	regmap_read(dev->regmap,0x6D,&temp);
	WR6D = temp & 0xFC;
	regmap_read(dev->regmap,0x6E,&temp);
	WR6E = temp & 0x00;
	regmap_read(dev->regmap,0x70,&temp);
	WR70 = temp & 0x00;
	regmap_read(dev->regmap,0x2A,&temp);
	WR2A = temp & 0xF7;
	regmap_read(dev->regmap,0x71,&temp);
	WR71 = temp & 0x00;
	regmap_read(dev->regmap,0x72,&temp);
	WR72 = temp & 0x03;
	regmap_read(dev->regmap,0x73,&temp);
	WR73 = temp & 0x03;
	regmap_read(dev->regmap,0x74,&temp);
	WR74 = temp & 0x0F;
	regmap_read(dev->regmap,0x75,&temp);
	WR75 = temp & 0x03;

	regmap_write(dev->regmap,0x6D, WR6D | (u8)g_atBW_TABLE_CKSYN[eBwType][2]);
	regmap_write(dev->regmap,0x6E, WR6E | (u8)g_atBW_TABLE_CKSYN[eBwType][0]);
	regmap_write(dev->regmap,0x70, WR70 | (u8)(g_atBW_TABLE_CKSYN[eBwType][1] & 0xFF));
	regmap_write(dev->regmap,0x2A, WR2A | (u8)(g_atBW_TABLE_CKSYN[eBwType][3] << 3));
	regmap_write(dev->regmap,0x71, WR71 | (u8)(((g_atBW_TABLE_CKSYN[eBwType][1] & 0x300) >> 2)
		| g_atBW_TABLE_CKSYN[eBwType][4]));
	regmap_write(dev->regmap,0x72, WR72 | (u8)(g_atBW_TABLE_CKSYN[eBwType][6] << 2));
	regmap_write(dev->regmap,0x73, WR73 | (u8)(g_atBW_TABLE_CKSYN[eBwType][5] << 2));
	regmap_write(dev->regmap,0x74, WR74 | (u8)(g_atBW_TABLE_CKSYN[eBwType][7] << 4));
	regmap_write(dev->regmap,0x75, WR75 | (u8)(g_atBW_TABLE_CKSYN[eBwType][8] << 2));

	if (rtvRF_LockCheck(dev,1) != 0)
		return 1;

	return 0;
}

static int rtvRF_ConfigureIIRFilter(struct mtv23x_dev*dev,enum E_RTV_BANDWIDTH_TYPE eBwType)
{
	int temp;
	u8 WR95 = 0;
	int g_atBW_TABLE_IIR[MAX_NUM_RTV_BW_MODE_TYPE][14] = 
	{
	/*RTV_BW_MODE_5MHZ*/	{0x02,0xBB83E,0x436A1,0xC12C0,0xC3472,0x43762,0xC1CD3,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x398FD},
	/*RTV_BW_MODE_6MHZ*/	{0x02,0x3F019,0x43426,0xC108E,0xC3063,0x43405,0xC1C85,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x3B1B1},
	/*RTV_BW_MODE_7MHZ*/	{0x02,0x416DF,0x43084,0xBFBDC,0xC1331,0x41CF0,0xC1C18,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x3B78B}, //19.2MHz
	/*RTV_BW_MODE_8MHZ*/	{0x02,0x41F50,0x41B43,0xBF8A5,0xBF1E8,0x413E4,0xC1BEC,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x3BDB2},  //19.2MHz IIR
	/*RTV_BW_MODE_430KHZ*/	{0x02,0x43721,0x43400,0xBFDE1,0x3D238,0x4329D,0xC1965,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x371E2},  
	/*RTV_BW_MODE_500KHZ*/	{0x03,0x435CF,0x43466,0xC1185,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x3B27E}, 
	/*RTV_BW_MODE_571KHZ*/	{0x02,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000},
	/*RTV_BW_MODE_768KHZ*/	{0x02,0xC17A9,0x437A7,0xC1414,0xC38C3,0x439AA,0xC1DD4,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x3B394},
	/*RTV_BW_MODE_1290KHZ*/ {0x02,0xC37D0,0x43989,0xC1523,0xBF6D4,0x43B26,0xC1DFB,0x43000,0x43000,0x43000,0x43000,0x43000,0x43000,0x3732E}
	};

	regmap_read(dev->regmap,0x95,&temp);
	WR95 = temp & 0xC0;

	regmap_write(dev->regmap,0x95, (WR95 | (u8)((g_atBW_TABLE_IIR[eBwType][0]<<4) | ((g_atBW_TABLE_IIR[eBwType][1]&0xF0000)>>16))));
	regmap_write(dev->regmap,0x96, ((g_atBW_TABLE_IIR[eBwType][1] & 0x0FF00)>>8));
	regmap_write(dev->regmap,0x97, ((g_atBW_TABLE_IIR[eBwType][1] & 0x000FF)>>0));
	regmap_write(dev->regmap,0x98, ((g_atBW_TABLE_IIR[eBwType][2] & 0xFF000)>>12));
	regmap_write(dev->regmap,0x99, ((g_atBW_TABLE_IIR[eBwType][2] & 0x00FF0)>>4));
	regmap_write(dev->regmap,0x9A, (u8)((((g_atBW_TABLE_IIR[eBwType][2] & 0x0000F)>>0) << 4) |
			((g_atBW_TABLE_IIR[eBwType][3] & 0xF0000)>>16)));
	regmap_write(dev->regmap,0x9B, (u8)((g_atBW_TABLE_IIR[eBwType][3] & 0x0FF00)>>8));
	regmap_write(dev->regmap,0x9C, (u8)((g_atBW_TABLE_IIR[eBwType][3] & 0x000FF)>>0));
	regmap_write(dev->regmap,0x9D, (u8)((((g_atBW_TABLE_IIR[eBwType][13] & 0xF0000)>>16) << 4) |
			(u8)((g_atBW_TABLE_IIR[eBwType][4] & 0xF0000)>>16)));
	regmap_write(dev->regmap,0x9E, (u8)((g_atBW_TABLE_IIR[eBwType][4] & 0x0FF00)>>8));
	regmap_write(dev->regmap,0x9F, (u8)((g_atBW_TABLE_IIR[eBwType][4] & 0x000FF)>>0));
	regmap_write(dev->regmap,0xA0, (u8)((g_atBW_TABLE_IIR[eBwType][5] & 0xFF000)>>12));
	regmap_write(dev->regmap,0xA1, (u8)((g_atBW_TABLE_IIR[eBwType][5] & 0x00FF0)>>4));
	regmap_write(dev->regmap,0xA2, (u8)((((g_atBW_TABLE_IIR[eBwType][5] & 0x0000F)>>0) << 4) |
			((g_atBW_TABLE_IIR[eBwType][6] & 0xF0000)>>16)));
	regmap_write(dev->regmap,0xA3, (u8)((g_atBW_TABLE_IIR[eBwType][6] & 0x0FF00)>>8));
	regmap_write(dev->regmap,0xA4, (u8)((g_atBW_TABLE_IIR[eBwType][6] & 0x000FF)>>0));
	regmap_write(dev->regmap,0xA5, (u8)((((g_atBW_TABLE_IIR[eBwType][13] & 0x0F000)>>12) << 4) |
			(u8)((g_atBW_TABLE_IIR[eBwType][7] & 0xF0000)>>16)));
	regmap_write(dev->regmap,0xA6, (u8)((g_atBW_TABLE_IIR[eBwType][7] & 0x0FF00)>>8));
	regmap_write(dev->regmap,0xA7, (u8)((g_atBW_TABLE_IIR[eBwType][7] & 0x000FF)>>0));
	regmap_write(dev->regmap,0xA8, (u8)((g_atBW_TABLE_IIR[eBwType][8] & 0xFF000)>>12));
	regmap_write(dev->regmap,0xA9, (u8)((g_atBW_TABLE_IIR[eBwType][8] & 0x00FF0)>>4));
	regmap_write(dev->regmap,0xAA, (u8)((((g_atBW_TABLE_IIR[eBwType][8] & 0x0000F)>>0) << 4) |
			((g_atBW_TABLE_IIR[eBwType][9] & 0xF0000)>>16)));
	regmap_write(dev->regmap,0xAB, (u8)((g_atBW_TABLE_IIR[eBwType][9] & 0x0FF00)>>8));
	regmap_write(dev->regmap,0xAC, (u8)((g_atBW_TABLE_IIR[eBwType][9] & 0x000FF)>>0));
	regmap_write(dev->regmap,0xAD, (u8)((((g_atBW_TABLE_IIR[eBwType][13] & 0x00F00)>>8) << 4) |
			(u8)((g_atBW_TABLE_IIR[eBwType][10] & 0xF0000)>>16)));
	regmap_write(dev->regmap,0xAE, (u8)((g_atBW_TABLE_IIR[eBwType][10] & 0x0FF00)>>8));
	regmap_write(dev->regmap,0xAF, (u8)((g_atBW_TABLE_IIR[eBwType][10] & 0x000FF)>>0));
	regmap_write(dev->regmap,0xB0, (u8)((g_atBW_TABLE_IIR[eBwType][11] & 0xFF000)>>12));
	regmap_write(dev->regmap,0xB1, (u8)((g_atBW_TABLE_IIR[eBwType][11] & 0x00FF0)>>4));
	regmap_write(dev->regmap,0xB2, (u8)((((g_atBW_TABLE_IIR[eBwType][11] & 0x0000F)>>0) << 4) |
			((g_atBW_TABLE_IIR[eBwType][12] & 0xF0000)>>16)));
	regmap_write(dev->regmap,0xB3, (u8)((g_atBW_TABLE_IIR[eBwType][12] & 0x0FF00)>>8));
	regmap_write(dev->regmap,0xB4, (u8)((g_atBW_TABLE_IIR[eBwType][12] & 0x000FF)>>0));
	regmap_write(dev->regmap,0xB5, (u8)((g_atBW_TABLE_IIR[eBwType][13] & 0x000FF)>>0));

	return 0;


}
static int rtvRF_ConfigureBBA(struct mtv23x_dev*dev,enum E_RTV_BANDWIDTH_TYPE eBwType)
{
	int temp;
	u8 WR3E = 0, WR3F = 0, WR50 = 0, WR51 = 0, WR4F = 0, WR4E = 0, WR77 = 0;
	int g_atBW_TABLE_BBA[MAX_NUM_RTV_BW_MODE_TYPE][7] = 
	{
	/*RTV_BW_MODE_5MHZ*/	{0x2D,0x20,0x03,0x03,0x02,0x02,0x01},
	/*RTV_BW_MODE_6MHZ*/	{0x2D,0x20,0x03,0x03,0x02,0x02,0x01},
	/*RTV_BW_MODE_7MHZ*/	{0x28,0x19,0x03,0x03,0x02,0x02,0x02},
	/*RTV_BW_MODE_8MHZ*/	{0x22,0x13,0x03,0x03,0x02,0x02,0x03},
	/*RTV_BW_MODE_430KHZ*/	{0x9C,0x15,0x00,0x03,0x00,0x00,0x00},
	/*RTV_BW_MODE_500KHZ*/	{0xBF,0x20,0x03,0x03,0x02,0x02,0x00},
	/*RTV_BW_MODE_571KHZ*/	{0xBF,0x20,0x03,0x03,0x02,0x02,0x00},
	/*RTV_BW_MODE_768KHZ*/	{0xBF,0x20,0x03,0x03,0x02,0x02,0x00},
	/*RTV_BW_MODE_1290KHZ*/ {0xBF,0x20,0x03,0x03,0x02,0x02,0x00}
	};
	regmap_read(dev->regmap,0x3E,&temp);
	WR3E = temp & 0x00;
	regmap_read(dev->regmap,0x3F,&temp);
	WR3F = temp & 0x03;
	regmap_read(dev->regmap,0x50,&temp);
	WR50 = temp & 0x1F;
	regmap_read(dev->regmap,0x51,&temp);
	WR51 = temp & 0x8F;
	regmap_read(dev->regmap,0x4F,&temp);
	WR4F = temp & 0x1F;
	regmap_read(dev->regmap,0x4E,&temp);
	WR4E = temp & 0x1F;
	regmap_read(dev->regmap,0x77,&temp);
	WR77 = temp & 0xFC;

	regmap_write(dev->regmap,0x3E, WR3E | g_atBW_TABLE_BBA[eBwType][0]);
	regmap_write(dev->regmap,0x3F, WR3F | (u8)(g_atBW_TABLE_BBA[eBwType][1] << 2));
	regmap_write(dev->regmap,0x50, WR50 | (u8)(g_atBW_TABLE_BBA[eBwType][2] << 5));
	regmap_write(dev->regmap,0x51, WR51 | (u8)(g_atBW_TABLE_BBA[eBwType][3] << 4));
	regmap_write(dev->regmap,0x4F, WR4F | (u8)(g_atBW_TABLE_BBA[eBwType][4] << 5));
	regmap_write(dev->regmap,0x4E, WR4E | (u8)(g_atBW_TABLE_BBA[eBwType][5] << 5));
	regmap_write(dev->regmap,0x77, WR77 | (u8)(g_atBW_TABLE_BBA[eBwType][6] << 0));

	return 0;
}

static int rtvRF_ConfigureADC(struct mtv23x_dev*dev,enum E_RTV_BANDWIDTH_TYPE eBwType)
{
	int temp;
	u8 WRB7 = 0, WRC8 = 0, WRC9 = 0, WRCA = 0, WRCB = 0, WRCC = 0;
	u8 WRCD = 0, WRCE = 0;
	u8 WRD1 = 0, WRD2 = 0, WRD3 = 0, WRD5 = 0, WRD6 = 0, WRD7 = 0;
	u8 WRD8 = 0, WRD9 = 0, WRDA = 0;
	u8 g_atBW_TABLE_ADC[MAX_NUM_RTV_BW_MODE_TYPE][47] = 
	{
	/*RTV_BW_MODE_5MHZ*/	{0x00,0x00,0x00,0x00,0x24,0x24,0x00,0x00,0x0A,0x20,0x1F,0x12,0x20,0x13,0x20,0x00,0x00,0x00,0x02,0x35,0x49,0x49,0x4A,0x4A,0x4A,0x4A,0x4A,0x4A,0x12,0x10,0x1F,0x1F,0x1F,0x10,0x1F,0x1F,0x1F,0x10,0x1F,0x1F,0x1F,0x30,0x30,0x30,0x18,0x00,0x00},
	/*RTV_BW_MODE_6MHZ*/	{0x00,0x00,0x00,0x00,0x24,0x24,0x00,0x00,0x0A,0x20,0x1F,0x12,0x20,0x13,0x20,0x00,0x00,0x00,0x02,0x35,0x4F,0x4F,0x4A,0x4A,0x4A,0x4A,0x4A,0x4A,0x12,0x10,0x1F,0x1F,0x1F,0x10,0x1F,0x1F,0x1F,0x10,0x1F,0x1F,0x1F,0x30,0x30,0x30,0x18,0x00,0x00},
	/*RTV_BW_MODE_7MHZ*/	{0x00,0x00,0x00,0x00,0x24,0x24,0x00,0x00,0x0A,0x20,0x1F,0x12,0x20,0x13,0x20,0x00,0x00,0x00,0x02,0x35,0x4F,0x4F,0x4A,0x4A,0x4A,0x4A,0x4A,0x4A,0x12,0x10,0x1F,0x1F,0x1F,0x10,0x1F,0x1F,0x1F,0x10,0x1F,0x1F,0x1F,0x30,0x30,0x30,0x18,0x00,0x00},
	/*RTV_BW_MODE_8MHZ*/	{0x00,0x00,0x00,0x00,0x24,0x24,0x00,0x00,0x0A,0x20,0x1F,0x12,0x20,0x13,0x20,0x00,0x00,0x00,0x02,0x35,0x4F,0x4F,0x4A,0x4A,0x4A,0x4A,0x4A,0x4A,0x12,0x10,0x1F,0x1F,0x1F,0x10,0x1F,0x1F,0x1F,0x10,0x1F,0x1F,0x1F,0x30,0x30,0x30,0x18,0x00,0x00},
	/*RTV_BW_MODE_430KHZ*/	{0x00,0x00,0x00,0x00,0x24,0x24,0x00,0x00,0x08,0x20,0x03,0x08,0x20,0x08,0x20,0x00,0x00,0x00,0x00,0x09,0x23,0x23,0x21,0x21,0x21,0x21,0x21,0x21,0x12,0x10,0x0E,0x0E,0x0E,0x10,0x0E,0x0E,0x0E,0x10,0x0E,0x0E,0x0E,0x30,0x30,0x30,0x18,0x00,0x00},
	/*RTV_BW_MODE_500KHZ*/	{0x00,0x00,0x00,0x00,0x24,0x24,0x00,0x00,0x08,0x20,0x03,0x08,0x20,0x08,0x20,0x00,0x00,0x00,0x00,0x06,0x20,0x20,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x12,0x10,0x0D,0x0D,0x0D,0x10,0x0D,0x0D,0x0D,0x10,0x0D,0x0D,0x0D,0x30,0x30,0x30,0x18,0x00,0x00},
	/*RTV_BW_MODE_571KHZ*/	{0x00,0x00,0x00,0x00,0x24,0x24,0x00,0x00,0x0B,0x20,0x05,0x0B,0x20,0x0B,0x20,0x00,0x00,0x00,0x00,0x0F,0x2B,0x2B,0x29,0x29,0x29,0x29,0x29,0x29,0x12,0x10,0x11,0x11,0x11,0x10,0x11,0x11,0x11,0x10,0x11,0x11,0x11,0x30,0x30,0x30,0x18,0x00,0x00},
	/*RTV_BW_MODE_768KHZ*/	{0x00,0x00,0x00,0x00,0x24,0x24,0x00,0x00,0x08,0x20,0x03,0x08,0x20,0x08,0x20,0x00,0x00,0x00,0x00,0x06,0x20,0x20,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x12,0x10,0x0D,0x0D,0x0D,0x10,0x0D,0x0D,0x0D,0x10,0x0D,0x0D,0x0D,0x30,0x30,0x30,0x18,0x00,0x00},
	/*RTV_BW_MODE_1290KHZ*/ {0x00,0x00,0x00,0x00,0x24,0x24,0x00,0x00,0x08,0x20,0x04,0x08,0x20,0x08,0x20,0x00,0x00,0x00,0x00,0x03,0x1F,0x1F,0x1D,0x1D,0x1D,0x1D,0x1D,0x1D,0x12,0x10,0x0C,0x0C,0x0C,0x10,0x0C,0x0C,0x0C,0x10,0x0C,0x0C,0x0C,0x30,0x30,0x30,0x18,0x00,0x00}
	};
	regmap_read(dev->regmap,0xB7,&temp);
	WRB7 = temp& 0x07;
	regmap_read(dev->regmap,0xC8,&temp);
	WRC8 = temp & 0x80;
	regmap_read(dev->regmap,0xC9,&temp);
	WRC9 = temp & 0x80;
	regmap_read(dev->regmap,0xCA,&temp);
	WRCA = temp & 0x80;
	regmap_read(dev->regmap,0xCB,&temp);
	WRCB = temp & 0x80;
	regmap_read(dev->regmap,0xCC,&temp);
	WRCC = temp & 0x80;
	regmap_read(dev->regmap,0xCD,&temp);
	WRCD = temp & 0x80;
	regmap_read(dev->regmap,0xCE,&temp);
	WRCE = temp & 0x80;
	regmap_read(dev->regmap,0xD1,&temp);
	WRD1 = temp & 0x80;
	regmap_read(dev->regmap,0xD2,&temp);
	WRD2 = temp & 0x80;
	regmap_read(dev->regmap,0xD3,&temp);
	WRD3 = temp & 0x80;
	regmap_read(dev->regmap,0xD5,&temp);
	WRD5 = temp & 0x80;
	regmap_read(dev->regmap,0xD6,&temp);
	WRD6 = temp & 0x80;
	regmap_read(dev->regmap,0xD7,&temp);
	WRD7 = temp & 0x80;
	regmap_read(dev->regmap,0xD8,&temp);
	WRD8 = temp & 0x80;
	regmap_read(dev->regmap,0xD9,&temp);
	WRD9 = temp & 0xC0;
	regmap_read(dev->regmap,0xDA,&temp);
	WRDA = temp & 0xC0;

	regmap_write(dev->regmap,0xB7, (WRB7 | (g_atBW_TABLE_ADC[eBwType][45] << 6) |
				(g_atBW_TABLE_ADC[eBwType][46] << 5)));
	regmap_write(dev->regmap,0xB8, (g_atBW_TABLE_ADC[eBwType][44]));
	regmap_write(dev->regmap,0xB9, (g_atBW_TABLE_ADC[eBwType][43]));
	regmap_write(dev->regmap,0xBA, (g_atBW_TABLE_ADC[eBwType][42]));
	regmap_write(dev->regmap,0xBB, (g_atBW_TABLE_ADC[eBwType][41]));
	regmap_write(dev->regmap,0xBC, ((g_atBW_TABLE_ADC[eBwType][37] & 0x03) << 6) |
				g_atBW_TABLE_ADC[eBwType][40]);
	regmap_write(dev->regmap,0xBD, (((g_atBW_TABLE_ADC[eBwType][37] & 0x0C) >> 2) << 6) |
				g_atBW_TABLE_ADC[eBwType][39]);
	regmap_write(dev->regmap,0xBE, (((g_atBW_TABLE_ADC[eBwType][37] & 0x30) >> 4) << 6) |
				g_atBW_TABLE_ADC[eBwType][38]);
	regmap_write(dev->regmap,0xBF, ((g_atBW_TABLE_ADC[eBwType][33] & 0x03) << 6) |
				(g_atBW_TABLE_ADC[eBwType][36]));
	regmap_write(dev->regmap,0xC0, (((g_atBW_TABLE_ADC[eBwType][33] & 0x0C) >> 2) << 6) |
				(g_atBW_TABLE_ADC[eBwType][35]));
	regmap_write(dev->regmap,0xC1, (((g_atBW_TABLE_ADC[eBwType][33] & 0x30) >> 4) << 6) |
				(g_atBW_TABLE_ADC[eBwType][34]));
	regmap_write(dev->regmap,0xC2, ((g_atBW_TABLE_ADC[eBwType][29] & 0x03) << 6) |
				(g_atBW_TABLE_ADC[eBwType][32]));
	regmap_write(dev->regmap,0xC3, (((g_atBW_TABLE_ADC[eBwType][29] & 0x0C) >> 2) << 6) |
				(g_atBW_TABLE_ADC[eBwType][31]));
	regmap_write(dev->regmap,0xC4, (((g_atBW_TABLE_ADC[eBwType][29] & 0x30) >> 4) << 6) |
				(g_atBW_TABLE_ADC[eBwType][30]));
	regmap_write(dev->regmap,0xC5, (g_atBW_TABLE_ADC[eBwType][28]));
	regmap_write(dev->regmap,0xC6, (g_atBW_TABLE_ADC[eBwType][27]));
	regmap_write(dev->regmap,0xC7, (g_atBW_TABLE_ADC[eBwType][26]));
	regmap_write(dev->regmap,0xC8, (WRC8 | (g_atBW_TABLE_ADC[eBwType][25])));
	regmap_write(dev->regmap,0xC9, (WRC9 | (g_atBW_TABLE_ADC[eBwType][24])));
	regmap_write(dev->regmap,0xCA, (WRCA | (g_atBW_TABLE_ADC[eBwType][23])));
	regmap_write(dev->regmap,0xCB, (WRCB | (g_atBW_TABLE_ADC[eBwType][22])));
	regmap_write(dev->regmap,0xCC, (WRCC | (g_atBW_TABLE_ADC[eBwType][21])));
	regmap_write(dev->regmap,0xCD, (WRCD | (g_atBW_TABLE_ADC[eBwType][20])));
	regmap_write(dev->regmap,0xCE, (WRCE | (g_atBW_TABLE_ADC[eBwType][19])));
	regmap_write(dev->regmap,0xCF, (g_atBW_TABLE_ADC[eBwType][18] << 6) |
				(g_atBW_TABLE_ADC[eBwType][17] << 4) |
				(g_atBW_TABLE_ADC[eBwType][16] << 2) |
				(g_atBW_TABLE_ADC[eBwType][15] << 0));
	regmap_write(dev->regmap,0xD0, (g_atBW_TABLE_ADC[eBwType][14]));
	regmap_write(dev->regmap,0xD1, (WRD1 | (g_atBW_TABLE_ADC[eBwType][13])));
	regmap_write(dev->regmap,0xD2, (WRD2 | (g_atBW_TABLE_ADC[eBwType][12])));
	regmap_write(dev->regmap,0xD3, (WRD3 | (g_atBW_TABLE_ADC[eBwType][11])));
	regmap_write(dev->regmap,0xD4, (g_atBW_TABLE_ADC[eBwType][10]));
	regmap_write(dev->regmap,0xD5, (WRD5 | (g_atBW_TABLE_ADC[eBwType][9])));
	regmap_write(dev->regmap,0xD6, (WRD6 | (g_atBW_TABLE_ADC[eBwType][8])));
	regmap_write(dev->regmap,0xD7, (WRD7 | (g_atBW_TABLE_ADC[eBwType][7])));
	regmap_write(dev->regmap,0xD8, (WRD8 | (g_atBW_TABLE_ADC[eBwType][6])));
	regmap_write(dev->regmap,0xD9, (WRD9 | (g_atBW_TABLE_ADC[eBwType][5])));
	regmap_write(dev->regmap,0xDA, (WRDA | (g_atBW_TABLE_ADC[eBwType][4])));
	regmap_write(dev->regmap,0xDB, ((g_atBW_TABLE_ADC[eBwType][3]) << 4) |
				(g_atBW_TABLE_ADC[eBwType][2]));
	regmap_write(dev->regmap,0xDC, ((g_atBW_TABLE_ADC[eBwType][1]) << 4) |
				(g_atBW_TABLE_ADC[eBwType][0]));

	return 0;
}

static int rtvRF_Lna_Tuning(struct mtv23x_dev*dev,u32 dwLoFreq)
{
	u8 nidx = 0;
	u8 WR50 = 0, WR73 = 0, WR4E = 0, WR69 = 0, WR88 = 0, WR89 = 0;
	u8 WR8A = 0, WR8B = 0;
	u8 WR6C = 0, WR6D = 0, WR6A = 0, WR6B = 0, WR8C = 0, WR8D = 0;
	u8 WR8E = 0, WR8F = 0;
	u8 WR90 = 0, WR91 = 0, WR92 = 0, WR87 = 0, WR93 = 0, WR94 = 0;
	int temp;
	 const u8 g_atLNA_TABLE[20][29] = 
	{
	/* 80 - 90*/ {0x07,0x02,0x0A,0x03,0x03,0x07,0x00,0x00,0x0F,0x00,0x03,0x03,0x1F,0x00,0x00,0x00,0x1F,0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0x00},
	/* 90 - 100*/{0x07,0x02,0x0A,0x03,0x02,0x07,0x00,0x00,0x0F,0x00,0x03,0x03,0x1F,0x00,0x00,0x00,0x1F,0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0x00},
	/*100 - 110*/{0x07,0x02,0x0A,0x03,0x02,0x07,0x00,0x00,0x0F,0x00,0x02,0x03,0x1F,0x00,0x00,0x00,0x1F,0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0x3F,0x00,0x00,0x00,0x00},
	/*170 - 180*/{0x0B,0x02,0x10,0x03,0x05,0x00,0x05,0x02,0x07,0x00,0x03,0x04,0x3F,0x08,0x1F,0x2F,0x3F,0x12,0x14,0x02,0x3F,0x0C,0x1F,0x0F,0x03,0x3F,0x0F,0x0F,0x01},
	/*180 - 190*/{0x0B,0x02,0x10,0x03,0x04,0x00,0x04,0x02,0x06,0x00,0x03,0x04,0x3F,0x08,0x1F,0x14,0x3F,0x12,0x14,0x02,0x3F,0x0C,0x1F,0x0F,0x03,0x3F,0x0F,0x0F,0x01},
	/*190 - 200*/{0x0B,0x02,0x10,0x03,0x04,0x00,0x03,0x01,0x04,0x00,0x02,0x04,0x3F,0x08,0x1F,0x14,0x1F,0x0F,0x0F,0x02,0x14,0x07,0x1F,0x0F,0x03,0x3F,0x0F,0x0F,0x01},
	/*200 - 210*/{0x0B,0x02,0x10,0x03,0x03,0x00,0x03,0x01,0x02,0x00,0x02,0x04,0x3F,0x0A,0x1F,0x11,0x1F,0x0F,0x0F,0x02,0x14,0x07,0x1F,0x0F,0x03,0x3F,0x0F,0x0F,0x01},
	/*210 - 220*/{0x09,0x02,0x10,0x03,0x03,0x00,0x02,0x01,0x00,0x00,0x01,0x04,0x1E,0x0C,0x1F,0x0D,0x19,0x0C,0x03,0x02,0x14,0x07,0x1F,0x0F,0x03,0x3F,0x0F,0x0F,0x01},
	/*220 - 230*/{0x09,0x02,0x10,0x03,0x03,0x00,0x02,0x01,0x00,0x00,0x01,0x04,0x1E,0x0C,0x1F,0x0D,0x19,0x0C,0x03,0x02,0x14,0x07,0x1F,0x0F,0x03,0x3F,0x0F,0x0F,0x01},
	/*230 - 240*/{0x09,0x02,0x10,0x03,0x02,0x00,0x01,0x01,0x0F,0x00,0x01,0x04,0x12,0x0C,0x1F,0x0C,0x19,0x0C,0x03,0x02,0x14,0x07,0x1F,0x0F,0x03,0x3F,0x0F,0x0F,0x01},
	/*240 - 250*/{0x09,0x02,0x10,0x03,0x02,0x00,0x01,0x01,0x0E,0x00,0x01,0x04,0x12,0x0C,0x1F,0x0C,0x19,0x0C,0x03,0x02,0x14,0x07,0x1F,0x0F,0x03,0x3F,0x0F,0x0F,0x01},
	/*250 - 320*/{0x09,0x02,0x10,0x03,0x02,0x00,0x00,0x01,0x0E,0x00,0x01,0x04,0x12,0x0C,0x1F,0x0C,0x19,0x0C,0x03,0x02,0x14,0x07,0x1F,0x0F,0x03,0x3F,0x0F,0x0F,0x01},
	/*470 - 510*/{0x1F/*0x0F*/,0x02,0x0B,0x03,0x01,0x00,0x01,0x00,0x00/*0x0F*/,0x06,0x0B,0x05,0x3F,0x3F,0x00/*0x0A*/,0x00/*0x06*/,0x3F,0x3F,0x07,0x03,0x3F,0x3F,0x05,0x03,0x3F,0x3F,0x05,0x02,0x02},
	/*510 - 540*/{0x1F/*0x0F*/,0x02,0x0B,0x03,0x00,0x00,0x00,0x00,0x00/*0x07*/,0x06,0x07,0x05,0x3F,0x2F,0x00/*0x0A*/,0x00/*0x05*/,0x3F,0x3F,0x07,0x03,0x3F,0x3F,0x04,0x03,0x3F,0x3F,0x04,0x02,0x02},
	/*540 - 560*/{0x1F/*0x0F*/,0x02,0x0B,0x03,0x00,0x00,0x00,0x00,0x00/*0x05*/,0x06,0x03,0x05,0x3F,0x1F,0x00/*0x0A*/,0x00/*0x04*/,0x3F,0x0F,0x03,0x02,0x3F,0x3F,0x04,0x03,0x0F,0x0F,0x03,0x01,0x02},
	/*560 - 600*/{0x1F/*0x0D*/,0x02,0x0B,0x03,0x00,0x00,0x00,0x00,0x00/*0x03*/,0x06,0x03,0x05,0x2F,0x16,0x00/*0x09*/,0x00/*0x02*/,0x3F,0x0F,0x03,0x02,0x1F,0x08,0x02,0x00,0x0F,0x0F,0x02,0x00,0x02},
	/*600 - 630*/{0x1F/*0x0D*/,0x02,0x0B,0x03,0x00,0x00,0x00,0x00,0x00/*0x01*/,0x06,0x00,0x05,0x1F,0x0C,0x00/*0x08*/,0x00/*0x00*/,0x3F,0x00,0x00,0x00,0x1F,0x08,0x02,0x00,0x00,0x10,0x01,0x00,0x02},
	/*630 - 710*/{0x1F/*0x0D*/,0x02,0x10,0x03,0x00,0x00,0x00,0x00,0x00/*0x00*/,0x06,0x00,0x05,0x15,0x00,0x00/*0x06*/,0x00/*0x00*/,0x3F,0x00,0x00,0x00,0x0C,0x00,0x00,0x00,0x00,0x0C,0x00,0x00,0x02},
	/*710 - 810*/{0x1F/*0x0F*/,0x02,0x10,0x03,0x00,0x00,0x00,0x00,0x00/*0x00*/,0x06,0x00,0x05,0x15,0x00,0x00/*0x00*/,0x00/*0x00*/,0x3F,0x00,0x00,0x00,0x0C,0x00,0x00,0x00,0x00,0x0C,0x00,0x00,0x02},
	/*810 - 880*/{0x1F/*0x14*/,0x02,0x16,0x03,0x00,0x00,0x00,0x00,0x00/*0x00*/,0x06,0x00,0x05,0x09,0x00,0x00/*0x00*/,0x00/*0x00*/,0x3F,0x00,0x00,0x00,0x0C,0x00,0x00,0x00,0x00,0x08,0x00,0x00,0x02}
	};

	if (75000 < dwLoFreq && 90000 >= dwLoFreq)
		nidx = 0;
	else if (90000 < dwLoFreq && 100000 >= dwLoFreq)
		nidx = 1;
	else if (100000 < dwLoFreq && 115000 >= dwLoFreq)
		nidx = 2;
	else if (115000 < dwLoFreq && 180000 >= dwLoFreq)
		nidx = 3;
	else if (180000 < dwLoFreq && 190000 >= dwLoFreq)
		nidx = 4;
	else if (190000 < dwLoFreq && 200000 >= dwLoFreq)
		nidx = 5;
	else if (200000 < dwLoFreq && 210000 >= dwLoFreq)
		nidx = 6;
	else if (210000 < dwLoFreq && 220000 >= dwLoFreq)
		nidx = 7;
	else if (220000 < dwLoFreq && 230000 >= dwLoFreq)
		nidx = 8;
	else if (230000 < dwLoFreq && 240000 >= dwLoFreq)
		nidx = 9;
	else if (240000 < dwLoFreq && 250000 >= dwLoFreq)
		nidx = 10;
	else if (250000 < dwLoFreq && 320000 >= dwLoFreq)
		nidx = 11;
	else if (320000 < dwLoFreq && 510000 >= dwLoFreq)
		nidx = 12;
	else if (510000 < dwLoFreq && 540000 >= dwLoFreq)
		nidx = 13;
	else if (540000 < dwLoFreq && 560000 >= dwLoFreq)
		nidx = 14;
	else if (560000 < dwLoFreq && 600000 >= dwLoFreq)
		nidx = 15;
	else if (600000 < dwLoFreq && 630000 >= dwLoFreq)
		nidx = 16;
	else if (630000 < dwLoFreq && 710000 >= dwLoFreq)
		nidx = 17;
	else if (710000 < dwLoFreq && 810000 >= dwLoFreq)
		nidx = 18;
	else if (810000 < dwLoFreq && 880000 >= dwLoFreq)
		nidx = 19;
	else
		return -5;

	regmap_write(dev->regmap,MAP_SEL_REG,RF_PAGE);
	regmap_read(dev->regmap,0x50,&temp);
	WR50 = temp & 0xE0;
	regmap_read(dev->regmap,0x73,&temp);
	WR73 = temp & 0xFC;
	regmap_read(dev->regmap,0x4E,&temp);
	WR4E = temp & 0xE0;
	regmap_read(dev->regmap,0x69,&temp);
	WR69 = temp & 0x80;
	regmap_read(dev->regmap,0x88,&temp);
	WR88 = temp & 0x03;
	regmap_read(dev->regmap,0x89,&temp);
	WR89 = temp & 0x03;
	regmap_read(dev->regmap,0x8A,&temp);
	WR8A = temp & 0x00;
	regmap_read(dev->regmap,0x8B,&temp);
	WR8B = temp & 0x00;
	regmap_read(dev->regmap,0x6C,&temp);
	WR6C = temp & 0x03;
	regmap_read(dev->regmap,0x6D,&temp);
	WR6D = temp & 0x03;
	regmap_read(dev->regmap,0x6A,&temp);
	WR6A = temp & 0xC1;
	regmap_read(dev->regmap,0x6B,&temp);
	WR6B = temp & 0x03;
	regmap_read(dev->regmap,0x8C,&temp);
	WR8C = temp & 0x00;
	regmap_read(dev->regmap,0x8D,&temp);
	WR8D = temp & 0x00;
	regmap_read(dev->regmap,0x8E,&temp);
	WR8E = temp & 0x00;
	regmap_read(dev->regmap,0x8F,&temp);
	WR8F = temp & 0x00;
	regmap_read(dev->regmap,0x90,&temp);
	WR90 = temp & 0x00;
	regmap_read(dev->regmap,0x91,&temp);
	WR91 = temp & 0x00;
	regmap_read(dev->regmap,0x92,&temp);
	WR92 = temp & 0x00;
	regmap_read(dev->regmap,0x87,&temp);
	WR87 = temp & 0xFB;
	regmap_read(dev->regmap,0x93,&temp);
	WR93 = temp & 0x03;
	regmap_read(dev->regmap,0x94,&temp);
	WR94 = temp & 0x03;

	regmap_write(dev->regmap,0x50, WR50 |  g_atLNA_TABLE[nidx][0]);
	regmap_write(dev->regmap,0x73, WR73 |  g_atLNA_TABLE[nidx][1]);
	regmap_write(dev->regmap,0x4E, WR4E |  g_atLNA_TABLE[nidx][2]);
	regmap_write(dev->regmap,0x69, WR69 | (g_atLNA_TABLE[nidx][3] << 2)
				| g_atLNA_TABLE[nidx][28]);

	regmap_write(dev->regmap,0x88, WR88 | (g_atLNA_TABLE[nidx][4] << 5)
				| (g_atLNA_TABLE[nidx][5] << 2));

	regmap_write(dev->regmap,0x89, WR89 | (g_atLNA_TABLE[nidx][6] << 5)
				| (g_atLNA_TABLE[nidx][7] << 2));

	regmap_write(dev->regmap,0x8A, WR8A | (g_atLNA_TABLE[nidx][8] << 4)
				| g_atLNA_TABLE[nidx][9]);

	regmap_write(dev->regmap,0x8B, WR8B | (g_atLNA_TABLE[nidx][10] << 4)
				| g_atLNA_TABLE[nidx][11]);

	regmap_write(dev->regmap,0x6C, WR6C | (g_atLNA_TABLE[nidx][12] << 2));
	regmap_write(dev->regmap,0x6D, WR6D | (g_atLNA_TABLE[nidx][13] << 2));
	regmap_write(dev->regmap,0x6A, WR6A | (g_atLNA_TABLE[nidx][14] << 1));
	regmap_write(dev->regmap,0x6B, WR6B | (g_atLNA_TABLE[nidx][15] << 2));
	regmap_write(dev->regmap,0x8C, WR8C | (g_atLNA_TABLE[nidx][16] << 2)
				| ((g_atLNA_TABLE[nidx][18] & 0x18) >> 3));

	regmap_write(dev->regmap,0x8D, WR8D | (g_atLNA_TABLE[nidx][20] << 2)
				| ((g_atLNA_TABLE[nidx][18] & 0x06) >> 1));

	regmap_write(dev->regmap,0x8E, WR8E | (g_atLNA_TABLE[nidx][24] << 2)
				| ((g_atLNA_TABLE[nidx][18] & 0x01) << 1)
				| ((g_atLNA_TABLE[nidx][22] & 0x10) >> 4));

	regmap_write(dev->regmap,0x8F, WR8F | (g_atLNA_TABLE[nidx][17] << 2)
				| ((g_atLNA_TABLE[nidx][22] & 0x0C) >> 2));

	regmap_write(dev->regmap,0x90, WR90 | (g_atLNA_TABLE[nidx][21] << 2)
				| ((g_atLNA_TABLE[nidx][22] & 0x03) >> 0));

	regmap_write(dev->regmap,0x91, WR91 | (g_atLNA_TABLE[nidx][25] << 2)
				| ((g_atLNA_TABLE[nidx][26] & 0x18) >> 3));

	regmap_write(dev->regmap,0x92, WR92 | (g_atLNA_TABLE[nidx][19] << 2)
				| ((g_atLNA_TABLE[nidx][26] & 0x06) >> 1));

	regmap_write(dev->regmap,0x87, WR87 | ((g_atLNA_TABLE[nidx][26] & 0x01) << 2));
	regmap_write(dev->regmap,0x93, WR93 | (g_atLNA_TABLE[nidx][23] << 2));
	regmap_write(dev->regmap,0x94, WR94 | (g_atLNA_TABLE[nidx][27] << 2));

	return 0;
}

static int rtvRF_SetUpVCO(struct mtv23x_dev*dev,u32 dwLoFreq, u32 *dwPllfreq)
{
	int nRet = 0;
	int nVcoDivRate = 0;

	regmap_write(dev->regmap,MAP_SEL_REG,RF_PAGE);

	if (dwLoFreq < 107500) {
		nVcoDivRate = 5;
		regmap_update_bits(dev->regmap,0x78, 0x0F, 0x0F);
	} else if (dwLoFreq >= 107500 && dwLoFreq < 215000) {
		nVcoDivRate = 4;
		regmap_update_bits(dev->regmap,0x78, 0x0F, 0x0E);
	} else if (dwLoFreq >= 215000 && dwLoFreq < 430000) {
		nVcoDivRate = 3;
		regmap_update_bits(dev->regmap,0x78, 0x0F, 0x0E);
	} else {
		nVcoDivRate = 2;
		regmap_update_bits(dev->regmap,0x78, 0x0F, 0x0D);
	}

	*dwPllfreq = dwLoFreq * (1<<nVcoDivRate);

	regmap_update_bits(dev->regmap,0x28, 0x03, ((nVcoDivRate & 0x06)>>1));
	regmap_update_bits(dev->regmap,0x29, 0x08, (nVcoDivRate & 0x01)<<3);

	if (*dwPllfreq >= 1720000 && *dwPllfreq < 1892000) {
		regmap_update_bits(dev->regmap,0x94, 0x02, 0x00);
		regmap_update_bits(dev->regmap,0x78, 0x70, 0x40);
		regmap_update_bits(dev->regmap,0xEA, 0x60, 0x00);
	} else if (*dwPllfreq >= 1892000 && *dwPllfreq < 3440000) {
		regmap_update_bits(dev->regmap,0x94, 0x02, 0x00);
		regmap_update_bits(dev->regmap,0x78, 0x70, 0x30);
		regmap_update_bits(dev->regmap,0xEA, 0x60, 0x00);
	} else
		nRet = -5;

	return nRet;
}

static int rtvRF_SelectService(struct mtv23x_dev*dev,enum E_RTV_SERVICE_TYPE eServiceType)
{
	int nRet = 0;

	switch (eServiceType) {
	case RTV_SERVICE_UHF_ISDBT_1seg:
	case RTV_SERVICE_VHF_ISDBTmm_1seg:
	case RTV_SERVICE_VHF_ISDBTsb_1seg:
		regmap_write(dev->regmap,MAP_SEL_REG,HOST_PAGE);
		regmap_write(dev->regmap,0x0B, 0x36);

		regmap_write(dev->regmap,0x12, 0x08);
		regmap_write(dev->regmap,0x21, 0x01);
		regmap_write(dev->regmap,0x26, 0x00);

		regmap_write(dev->regmap,MAP_SEL_REG,FEC_PAGE);
		regmap_write(dev->regmap,0x20, 0x0C);

		regmap_write(dev->regmap,0x23, 0xF0); /* Layer A */
		regmap_write(dev->regmap,0x24, 0x31);
		regmap_write(dev->regmap,0x4F, 0x1F);
		regmap_write(dev->regmap,0x44, 0x68);
		regmap_write(dev->regmap,0x47, 0x40);

		regmap_write(dev->regmap,0x53, 0x3E);
		regmap_write(dev->regmap,0x21, 0x00);
		regmap_write(dev->regmap,0x22, 0x00);
		regmap_write(dev->regmap,0x5C, 0x10);
		regmap_write(dev->regmap,0x5F, 0x10);
		regmap_write(dev->regmap,0x77, 0x40);
		regmap_write(dev->regmap,0x7A, 0x20);
		regmap_write(dev->regmap,0x83, 0x10);
		regmap_write(dev->regmap,0x96, 0x00);
		regmap_write(dev->regmap,0xAE, 0x00);

		regmap_write(dev->regmap,0xFC, 0x83);
		regmap_write(dev->regmap,0xFF, 0x03);

#if 0
		regmap_write(dev->regmap,0x44, 0x48);
		regmap_write(dev->regmap,0x47, 0x00);
#endif
		dev->rtv_1seglpmode= 1;
		break;
	case RTV_SERVICE_VHF_ISDBTsb_3seg:
		printk("[rtvRF_SelectService] 3seg is not implemented\n");
		break;

	case RTV_SERVICE_UHF_ISDBT_13seg:
	case RTV_SERVICE_VHF_ISDBTmm_13seg:
		regmap_write(dev->regmap,MAP_SEL_REG,HOST_PAGE);
		regmap_write(dev->regmap,0x0B, 0x96);

		regmap_write(dev->regmap,0x12, 0x00);
		regmap_write(dev->regmap,0x21, 0x00);
		regmap_write(dev->regmap,0x26, 0xB8);

		regmap_write(dev->regmap,MAP_SEL_REG,OFDM_PAGE);
		regmap_write(dev->regmap,0x10, 0xD4);

		regmap_write(dev->regmap,MAP_SEL_REG,FEC_PAGE);
		regmap_write(dev->regmap,0x20, 0x00);
		regmap_write(dev->regmap,0x21, 0x21);
		regmap_write(dev->regmap,0x22, 0x21);

#if 0
		regmap_write(dev->regmap,0x23, 0x84);
		regmap_write(dev->regmap,0x24, 0x31);
		regmap_write(dev->regmap,0x4F, 0x1F);
#endif

		regmap_write(dev->regmap,0x23, 0x90);
		regmap_write(dev->regmap,0x24, 0x01);
		regmap_write(dev->regmap,0x4F, 0x00);
		regmap_write(dev->regmap,0x44, 0x68);
		regmap_write(dev->regmap,0x47, 0x40);

		regmap_write(dev->regmap,0x53, 0x1E);
		regmap_write(dev->regmap,0x5C, 0x11);
		regmap_write(dev->regmap,0x5F, 0x11);
		regmap_write(dev->regmap,0x77, 0x00);
		regmap_write(dev->regmap,0x7A, 0x00);
		regmap_write(dev->regmap,0x83, 0x00);
		regmap_write(dev->regmap,0x96, 0x20);
		regmap_write(dev->regmap,0xAE, 0x02);

		regmap_write(dev->regmap,0xFC, 0x83);
		regmap_write(dev->regmap,0xFF, 0x03);

#if 0
		regmap_write(dev->regmap,0x44, 0xE8);
		regmap_write(dev->regmap,0x47, 0x40);
#endif
		dev->rtv_1seglpmode= 0;
		break;

	case RTV_SERVICE_DVBT:
		regmap_write(dev->regmap,MAP_SEL_REG,HOST_PAGE);
		regmap_write(dev->regmap,0x0B, 0x96);
		regmap_write(dev->regmap,0x12, 0x00);
		regmap_write(dev->regmap,0x21, 0x00);
		regmap_write(dev->regmap,0x26, 0xB8);

		regmap_write(dev->regmap,MAP_SEL_REG,DATA_PAGE);
		regmap_write(dev->regmap,0xA2, 0x0E);
		regmap_write(dev->regmap,0xA3, 0x0E);
		regmap_write(dev->regmap,0xA7, 0x0D);
		regmap_write(dev->regmap,0xA6, 0x0D);

		regmap_write(dev->regmap,MAP_SEL_REG,OFDM_PAGE);
		regmap_write(dev->regmap,0x10, 0xD6);

		regmap_write(dev->regmap,MAP_SEL_REG,FEC_PAGE);
		regmap_write(dev->regmap,0x20, 0x00);
		regmap_write(dev->regmap,0x21, 0x21);
		regmap_write(dev->regmap,0x22, 0x21);
		regmap_write(dev->regmap,0x53, 0x1E);

		regmap_write(dev->regmap,0x23, 0xF0); /* Layer A */
#if !defined(RTV_IF_SPI) && !defined(RTV_IF_EBI2)
		regmap_write(dev->regmap,0x24, 0x11);
		regmap_write(dev->regmap,0x4F, 0x07);
#endif
		regmap_write(dev->regmap,0x44, 0xE8);
		regmap_write(dev->regmap,0x47, 0x40);

		regmap_write(dev->regmap,0x5C, 0x10);
		regmap_write(dev->regmap,0x5F, 0x10);
		regmap_write(dev->regmap,0x77, 0x00);
		regmap_write(dev->regmap,0x7A, 0x00);
		regmap_write(dev->regmap,0x83, 0x00);
		regmap_write(dev->regmap,0x96, 0x20);
		regmap_write(dev->regmap,0xAE, 0x02);

		regmap_write(dev->regmap,0xFC, 0x83);
		regmap_write(dev->regmap,0xFF, 0x03);
		
#if 0
		regmap_write(dev->regmap,0x44, 0xE8);
		regmap_write(dev->regmap,0x47, 0x40);
#endif
		dev->rtv_1seglpmode= 0;
		break;
	default:
		nRet = -9;
	}

	regmap_write(dev->regmap,MAP_SEL_REG,RF_PAGE);

	switch (eServiceType) {
	case RTV_SERVICE_UHF_ISDBT_1seg:
		regmap_write(dev->regmap,0x49, 0x21);
		regmap_write(dev->regmap,0x4A, 0x60);
		regmap_write(dev->regmap,0x4B, 0x50);
		regmap_write(dev->regmap,0x5E, 0x70);
		regmap_write(dev->regmap,0x5F, 0x75);
		break;
	case RTV_SERVICE_VHF_ISDBTmm_1seg:
		regmap_write(dev->regmap,0x49, 0x21);
		regmap_write(dev->regmap,0x4A, 0x30);
		regmap_write(dev->regmap,0x4B, 0x20);
		regmap_write(dev->regmap,0x5E, 0x70);
		regmap_write(dev->regmap,0x5F, 0x75);
		break;
	case RTV_SERVICE_VHF_ISDBTsb_1seg:
		regmap_write(dev->regmap,0x49, 0x21);
		regmap_write(dev->regmap,0x4A, 0x60);
		regmap_write(dev->regmap,0x4B, 0x50);
		regmap_write(dev->regmap,0x5E, 0x70);
		regmap_write(dev->regmap,0x5F, 0x75);
		break;
	case RTV_SERVICE_VHF_ISDBTsb_3seg:
		printk("[rtvRF_SelectService] Unsupported 3seg\n");
		break;
	case RTV_SERVICE_UHF_ISDBT_13seg:
		regmap_write(dev->regmap,0x49, 0x41);
		regmap_write(dev->regmap,0x4A, 0x70);
		regmap_write(dev->regmap,0x4B, 0x65);
		regmap_write(dev->regmap,0x5E, 0x70);
		regmap_write(dev->regmap,0x5F, 0x75);
		break;
	case RTV_SERVICE_VHF_ISDBTmm_13seg:
		regmap_write(dev->regmap,0x49, 0x41);
		regmap_write(dev->regmap,0x4A, 0x70);
		regmap_write(dev->regmap,0x4B, 0x65);
		regmap_write(dev->regmap,0x5E, 0x70);
		regmap_write(dev->regmap,0x5F, 0x75);
		break;
	case RTV_SERVICE_DVBT:
		regmap_write(dev->regmap,0x49, 0x41);
		regmap_write(dev->regmap,0x4A, 0x70);
		regmap_write(dev->regmap,0x4B, 0x65);
		regmap_write(dev->regmap,0x5E, 0x70);
		regmap_write(dev->regmap,0x5F, 0x75);
		break;

	default:
		nRet = -9;
	}


	return nRet;
}

static int rtvRF_SetFrequency(struct mtv23x_dev*dev,enum E_RTV_SERVICE_TYPE eServiceType,
			enum E_RTV_BANDWIDTH_TYPE eBwType,u32 dwChFreqKHz)
{
	u8 pllf_mul = 0, r_div = 4;
	u32 dwPLLN = 0, dwPLLF = 0, dwPLLNF = 0;
	u32 dwPllFreq = 0, dwLoFreq = 0;
	
	regmap_write(dev->regmap,MAP_SEL_REG,RF_PAGE);
	rtvRF_ConfigureClkCKSYN(dev,eBwType);
	rtvRF_ConfigureIIRFilter(dev,eBwType);
	rtvRF_ConfigureBBA(dev,eBwType);
	rtvRF_ConfigureADC(dev,eBwType);
	rtvRF_SetOfdmPara(dev,eServiceType, eBwType, dwChFreqKHz);
	rtvRF_SelectService(dev,eServiceType);

	if (dev->rtv_1seglpmode) {
		regmap_write(dev->regmap,MAP_SEL_REG,LPOFDM_PAGE);

		if (eServiceType == RTV_SERVICE_VHF_ISDBTmm_1seg) {
			regmap_write(dev->regmap,0x10, 0xFA);
			dwLoFreq = dwChFreqKHz - 857;
		} else {
			regmap_write(dev->regmap,0x10, 0xF8);
			dwLoFreq = dwChFreqKHz + 857;
		}
	} else {
		dwLoFreq = dwChFreqKHz;
	}

	rtvRF_Lna_Tuning(dev,dwLoFreq);
	rtvRF_SetUpVCO(dev,dwLoFreq, &dwPllFreq);

	dwPLLN = dwPllFreq / dev->clk_freq;
	dwPLLF = dwPllFreq - (dwPLLN * dev->clk_freq);
	if (dev->clk_freq == 13000 || dev->clk_freq == 27000) {
		pllf_mul = 1;
		r_div = 3;
	}

	dwPLLNF = (dwPLLN<<20)
		+ (((dwPLLF<<16) / (dev->clk_freq>>r_div)) << pllf_mul);

	regmap_write(dev->regmap,MAP_SEL_REG,RF_PAGE);
	regmap_write(dev->regmap,0x20, ((dwPLLNF>>22)&0xFF));
	regmap_write(dev->regmap,0x21, ((dwPLLNF>>14)&0xFF));
	regmap_update_bits(dev->regmap,0x28, 0xFC, ((dwPLLNF&0x3F)<<2));
	regmap_write(dev->regmap,0x22, ((dwPLLNF>>6)&0xFF));

	msleep(1);

	if (rtvRF_LockCheck(dev,0) != 0)
		return -1;

	if (dwPllFreq >= 2140000 && dwPllFreq < 2950000) {
		regmap_update_bits(dev->regmap,0x94, 0x02, 0x02);
		regmap_update_bits(dev->regmap,0x78, 0x70, 0x50);
		regmap_update_bits(dev->regmap,0xEA, 0x60, 0x40);
	} else if (dwPllFreq >= 2950000 && dwPllFreq < 3440000) {
		regmap_update_bits(dev->regmap,0x94, 0x02, 0x02);
		regmap_update_bits(dev->regmap,0x78, 0x70, 0x40);
		regmap_update_bits(dev->regmap,0xEA, 0x60, 0x00);
	}

	return 0;
}

static void rtv_UpdateMon(struct mtv23x_dev*dev)
{
	if (dev->rtv_1seglpmode) {
		regmap_write(dev->regmap,MAP_SEL_REG,LPOFDM_PAGE);
		regmap_update_bits(dev->regmap,0x13, 0x80, 0x80);
		regmap_update_bits(dev->regmap,0x13, 0x80, 0x00);
	} else {
		regmap_write(dev->regmap,MAP_SEL_REG,OFDM_PAGE);
		regmap_update_bits(dev->regmap,0x1B, 0x80, 0x80);
		regmap_update_bits(dev->regmap,0x1B, 0x80, 0x00);
	}

	regmap_write(dev->regmap,MAP_SEL_REG,FEC_PAGE);
	regmap_update_bits(dev->regmap,0x11, 0x04, 0x04);
	regmap_update_bits(dev->regmap,0x11, 0x04, 0x00);
}

static int mtv23x_get_frontend(struct dvb_frontend *fe,
				struct dtv_frontend_properties *c)
{
	struct i2c_client*client = fe->demodulator_priv;
	struct mtv23x_dev*dev = i2c_get_clientdata(client);
	int tempData = 0, i;
	u8 R_Data = 0;
	u8 tempSeg = 0, tempModule = 0, tempCoderate = 0, tempInterl = 0;

	rtv_UpdateMon(dev);
	if (dev->rtv_1seglpmode) {
		regmap_write(dev->regmap, MAP_SEL_REG, LPOFDM_PAGE);
		regmap_read(dev->regmap, 0xC6, &tempData);
		R_Data = ((tempData & 0x30) >> 2) | ((tempData & 0xC0) >> 2);
	} else {
		regmap_write(dev->regmap, MAP_SEL_REG, SHAD_PAGE);
		regmap_read(dev->regmap, 0x80, &tempData);
		R_Data = tempData;
	}

	switch (R_Data & 0x03) {
		case 0:
			c->guard_interval = GUARD_INTERVAL_1_32;
			break;
		case 1:
			c->guard_interval = GUARD_INTERVAL_1_16;
			break;
		case 2:
			c->guard_interval = GUARD_INTERVAL_1_8;
			break;
		case 3:
			c->guard_interval = GUARD_INTERVAL_1_4;
			break;
	}

	switch ((R_Data>>2) & 0x03) {
		case 0:
			c->isdbt_sb_mode = 1;
			break;
		case 1:
			c->isdbt_sb_mode = 2;
			break;
		case 2:
			c->isdbt_sb_mode = 3;
			break;
	}

	regmap_write(dev->regmap, MAP_SEL_REG, FEC_PAGE);

	c->isdbt_layer_enabled = 7;
	for (i = 0; i < 3; i++) {
		switch (i) {
			case 0:
				//Layer A
				regmap_update_bits(dev->regmap, 0x76, 0x18, 0x00);
				break;
			case 1:
				//Layer B
				regmap_update_bits(dev->regmap, 0x76, 0x18, 0x08);
				break;
			case 2:
				//Layer C
				regmap_update_bits(dev->regmap, 0x76, 0x18, 0x10);
				break;
		}
		regmap_read(dev->regmap, 0x7B, &tempData);
		R_Data = tempData & 0x3f;
		tempCoderate = ((R_Data>>3) & 0x07);
		tempModule = (R_Data & 0x07);
		regmap_read(dev->regmap, 0x7C, &tempData);
		R_Data = tempData & 0x7f;
		tempInterl = R_Data & 0x07;
		tempSeg = (R_Data>>3) & 0x0f;

		switch (tempCoderate) {
			case 0:
				c->layer[i].fec = FEC_1_2;
				break;
			case 1:
				c->layer[i].fec = FEC_2_3;
				break;
			case 2:
				c->layer[i].fec = FEC_3_4;
				break;
			case 3:
				c->layer[i].fec = FEC_5_6;
				break;
			case 4:
				c->layer[i].fec = FEC_7_8;
				break;
		}

		switch (tempModule) {
			case 0:
				c->layer[i].modulation = DQPSK;
				break;
			case 1:
				c->layer[i].modulation = QPSK;
				break;
			case 2:
				c->layer[i].modulation = QAM_16;
				break;
			case 3:
				c->layer[i].modulation = QAM_64;
				break;
		}

		if (tempInterl > 0) {
			c->layer[i].interleaving = (1 << (tempInterl - 1)) << (3 - c->isdbt_sb_mode);
		} else {
			c->layer[i].interleaving = 0;
		}

		if (tempSeg >= 1 && tempSeg <= 13) {
			c->layer[i].segment_count = tempSeg;
		} else {
			c->layer[i].segment_count = 0;
		}
	}

	return 0;
}

static int mtv23x_set_frontend(struct dvb_frontend *fe)
{
	struct i2c_client*client = fe->demodulator_priv;
	struct mtv23x_dev*dev = i2c_get_clientdata(client);
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	enum E_RTV_BANDWIDTH_TYPE bandwidth ;
	enum E_RTV_SERVICE_TYPE svc_type ;
	int ret, subchannel_id;

	const u8 g_atSubChNum[] = {
	0x00, 0x00, 0x10, 0x10, 0x10, 0x20, /*0  ~ 5  */
	0x20, 0x20, 0x30, 0x30, 0x30, 0x40, /*6  ~ 11 */
	0x40, 0x40, 0x50, 0x50, 0x50, 0x60, /*12 ~ 17 */
	0x60, 0x60, 0x70, 0x70, 0x70, 0x80, /*18 ~ 23 */
	0x80, 0x80, 0x90, 0x90, 0x90, 0xA0, /*24 ~ 29 */
	0xA0, 0xA0, 0xB0, 0xB0, 0xB0, 0xC0, /*30 ~ 35 */
	0xC0, 0xC0, 0xD0, 0xD0, 0xD0, 0x00  /*31 ~ 41 */
	};

	if (c->isdbt_sb_subchannel > 0 && c->isdbt_sb_subchannel < 42) {
		subchannel_id = c->isdbt_sb_subchannel;
	} else {
		subchannel_id = 0;
	}

	if (c->bandwidth_hz == 0) {
		ret = -EINVAL;
		goto err;
	}else if(c->bandwidth_hz<=435000){
		bandwidth = RTV_BW_MODE_430KHZ;
	} else if (c->bandwidth_hz <= 505000){
		bandwidth = RTV_BW_MODE_500KHZ;
	} else if (c->bandwidth_hz <= 575000){
		bandwidth = RTV_BW_MODE_571KHZ;
	} else if (c->bandwidth_hz <= 860000){
		bandwidth = RTV_BW_MODE_857KHZ;
	} else if (c->bandwidth_hz <= 1295000){
		bandwidth = RTV_BW_MODE_1290KHZ;
	} else if (c->bandwidth_hz <= 5000000) {
		bandwidth = RTV_BW_MODE_5MHZ;
	} else if (c->bandwidth_hz <= 6000000) {
		bandwidth = RTV_BW_MODE_6MHZ;
	} else if (c->bandwidth_hz <= 7000000) {
		bandwidth = RTV_BW_MODE_7MHZ;
	} else if(c->bandwidth_hz <= 8000000) {
		bandwidth = RTV_BW_MODE_8MHZ;
	} else {
		bandwidth = RTV_BW_MODE_6MHZ;
	}

	if (c->frequency < 300000000) { //VHF
		if (c->isdbt_sb_mode == 1) {
			if (c->bandwidth_hz <= 860000) {
				svc_type = RTV_SERVICE_VHF_ISDBTsb_1seg;
			} else {
				svc_type = RTV_SERVICE_VHF_ISDBTsb_3seg;
			}
		} else if (c->bandwidth_hz <= 860000) {
			svc_type = RTV_SERVICE_VHF_ISDBTmm_1seg;
		} else {
			svc_type = RTV_SERVICE_VHF_ISDBTmm_13seg;
		}
	} else if (c->bandwidth_hz <= 860000) {
		svc_type = RTV_SERVICE_UHF_ISDBT_1seg;
	} else {
		svc_type = RTV_SERVICE_UHF_ISDBT_13seg;
	}

	rtvRF_SetFrequency(dev,svc_type,bandwidth,c->frequency/1000);

	if ((svc_type == RTV_SERVICE_VHF_ISDBTmm_1seg) ||
	(svc_type == RTV_SERVICE_VHF_ISDBTsb_1seg) ||
	(svc_type == RTV_SERVICE_VHF_ISDBTsb_3seg)) {
		regmap_write(dev->regmap,MAP_SEL_REG,LPOFDM_PAGE);
		regmap_write(dev->regmap,0x31, g_atSubChNum[subchannel_id]);
		regmap_write(dev->regmap,0x34, 0xD1);
		regmap_write(dev->regmap,0x36, 0x00);
	} else if (svc_type == RTV_SERVICE_UHF_ISDBT_1seg) {
		regmap_write(dev->regmap,MAP_SEL_REG,LPOFDM_PAGE);
		regmap_write(dev->regmap,0x31, 0x70);
		regmap_write(dev->regmap,0x34, 0x9F);
		regmap_write(dev->regmap,0x36, 0x01);
	}

	msleep(20);
	rtv_softReset(dev);
	msleep(20);

	regmap_write(dev->regmap,MAP_SEL_REG,FEC_PAGE);
	regmap_write(dev->regmap,0xA8, 0x87);
	regmap_write(dev->regmap,0xAB, 0x87);

	dev->svc_type = svc_type;
	return 0;
err:
	dev_dbg(&client->dev,"Failed =%d\n",ret);
	return ret;
}

static u32 rtvMTV23x_GetCNR(struct mtv23x_dev*dev)
{
	u32 data = 0, cnr = 0;
	u8 Mod = 0xFF, Cd = 0xFF;
	int temp,temp1,temp2;

	rtv_UpdateMon(dev);

	regmap_update_bits(dev->regmap,0x76, 0x18, 0x00);

	if (dev->rtv_1seglpmode) {
		regmap_read(dev->regmap,0x7B,&temp);
		Mod = temp & 0x07;

		regmap_write(dev->regmap,MAP_SEL_REG,LPOFDM_PAGE);
		regmap_update_bits(dev->regmap,0x25, 0x70, 0x10);
		regmap_update_bits(dev->regmap,0x13, 0x80, 0x80);
		regmap_update_bits(dev->regmap,0x13, 0x80, 0x00);

		regmap_read(dev->regmap,0xCA,&temp);
		regmap_read(dev->regmap,0xC9,&temp1);
		regmap_read(dev->regmap,0xC8,&temp2);
		data = ((temp &0xff)<<16)
				| ((temp1 &0xff)<<8)
				| (temp2 &0xff);

		cnr = GetSNR_LP_Mode(Mod, data);
	} else {
		regmap_read(dev->regmap,0x7C,&temp);
		Cd = (temp >> 3) & 0x0F;

		if (Cd < 2)
			regmap_update_bits(dev->regmap,0x76, 0x18, 0x08);


		if (dev->svc_type == RTV_SERVICE_DVBT){
			regmap_read(dev->regmap,0x6F,&temp);
			Mod = ((temp >> 2) & 0x03) + 1;
			}
		else
			{
			regmap_read(dev->regmap,0x7B,&temp);
			Mod = (temp & 0x07);
			}
		regmap_write(dev->regmap,MAP_SEL_REG,OFDM_PAGE);
		regmap_update_bits(dev->regmap,0x1B, 0x80, 0x80);
		regmap_update_bits(dev->regmap,0x1B, 0x80, 0x00);

		regmap_write(dev->regmap,MAP_SEL_REG,SHAD_PAGE);

		regmap_read(dev->regmap,0xde,&temp);
		regmap_read(dev->regmap,0xdd,&temp1);
		regmap_read(dev->regmap,0xdc,&temp2);
		data  = ((temp << 16)
			     | (temp1 << 8)
			     | (temp2 << 0));

		cnr = GetSNR_FULL_Mode(Mod, data);
	}

	return cnr;
}

static s32 rtvMTV23x_GetRSSI(struct mtv23x_dev*dev)
{
	u8  LNAGAIN = 0, RFAGC = 0, CH_FLAG = 0;
	s32 nRssi = 0;
	s32 nRssiAppDelta = 4*10;
	int RD11 = 0, GVBB = 0;
	
	if (dev->rtv_1seglpmode)
		nRssiAppDelta = 0;

	regmap_write(dev->regmap,MAP_SEL_REG,RF_PAGE);
	regmap_read(dev->regmap,0x11,&RD11);
	regmap_read(dev->regmap,0x14,&GVBB);
//	RD11 = RTV_REG_GET(0x11);
//	GVBB = RTV_REG_GET(0x14);

	CH_FLAG = ((RD11 & 0xC0) >> 6);
	LNAGAIN = ((RD11 & 0x18) >> 3);
	RFAGC = (RD11 & 0x07);

	switch (LNAGAIN) {
	case 0:
		nRssi = -(RSSI_RFAGC_VAL(RFAGC, 2.8)
			+ RSSI_GVBB_VAL(GVBB, 0.44) + 0)
			+ 5*10;
		break;

	case 1:
		nRssi = -(RSSI_RFAGC_VAL(RFAGC, 3)
			+ RSSI_GVBB_VAL(GVBB, 0.3)
			+ (19*10))
			+ 0*10;
		break;

	case 2:
		nRssi = -(RSSI_RFAGC_VAL(RFAGC, 3)
			+ RSSI_GVBB_VAL(GVBB, 0.3)
			+ (16*2*10))
			+ 0*10;
		break;

	case 3:
		nRssi = -(RSSI_RFAGC_VAL(RFAGC, 2.6)
			+ RSSI_GVBB_VAL(GVBB, 0.4)
			+ (11*3*10))
			+ 0*10;
		break;

	default:
		break;
	}

	if (dev->rtv_1seglpmode)
		nRssiAppDelta = 0;
	else if (CH_FLAG == 0)
		nRssiAppDelta += (7 * 10);

	return nRssi + nRssiAppDelta;
}

static int mtv23x_read_status(struct dvb_frontend *fe, enum fe_status *status) 
{
	struct i2c_client*client = fe->demodulator_priv;
	struct mtv23x_dev*dev = i2c_get_clientdata(client);
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;

	int  OFDMREG = 0, TMCCL = 0, OFDML = 0;
	int lock_st = 0, rssi = 0, cnr = 0;

	rssi = rtvMTV23x_GetRSSI(dev);
	
	c->strength.len = 2;
	c->strength.stat[0].scale = FE_SCALE_DECIBEL;
	c->strength.stat[0].svalue = rssi * 100;
	
	c->strength.stat[1].scale = FE_SCALE_RELATIVE;
	c->strength.stat[1].uvalue = (1000 + rssi) * 65;


	rtv_UpdateMon(dev);
	if (dev->rtv_1seglpmode) {
		regmap_write(dev->regmap,MAP_SEL_REG,LPOFDM_PAGE);
		regmap_read(dev->regmap,0xC0,&OFDMREG);
		OFDML = OFDMREG & 0x07;
	} else {
		regmap_write(dev->regmap,MAP_SEL_REG,SHAD_PAGE);
		regmap_read(dev->regmap,0x81,&OFDMREG);
		OFDML = (OFDMREG & 0x04) >> 2;
	}

	if (OFDML & 0x01)
		lock_st = RTV_ISDBT_OFDM_LOCK_MASK;

	regmap_write(dev->regmap,MAP_SEL_REG,FEC_PAGE);
	regmap_read(dev->regmap,0x10,&TMCCL);
	
	if (TMCCL & 0x01)
		lock_st |= RTV_ISDBT_TMCC_LOCK_MASK;

//	printk("DVB: lock status is 0%x\n",lock_st);

	c->cnr.len =  1;
	c->cnr.stat[0].scale = FE_SCALE_NOT_AVAILABLE;

	if (RTV_ISDBT_CHANNEL_LOCK_OK == lock_st) {
		*status = FE_HAS_LOCK|FE_HAS_SIGNAL|FE_HAS_CARRIER|FE_HAS_VITERBI|FE_HAS_SYNC;

		cnr = rtvMTV23x_GetCNR(dev);
		c->cnr.len = 2;
		c->cnr.stat[0].scale = FE_SCALE_DECIBEL;
		c->cnr.stat[0].svalue = cnr;

		c->cnr.stat[1].scale = FE_SCALE_RELATIVE;
		c->cnr.stat[1].uvalue = (cnr/500) * 656;
		if (c->cnr.stat[1].uvalue > 0xffff)
			c->cnr.stat[1].uvalue = 0xffff;
	} else if (lock_st & RTV_ISDBT_TMCC_LOCK_MASK) {
		printk("TMCC lock \n");
	} else if (lock_st & RTV_ISDBT_OFDM_LOCK_MASK) {
		printk("OFDM lock \n");
	} else {
		*status = FE_TIMEDOUT;
	}

	return  0;
}

static int mtv23x_read_signal_strength(struct dvb_frontend *fe, u16 *strength)
{
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int i;

	*strength = 0;
	for (i=0; i < c->strength.len; i++)
	{
		if (c->strength.stat[i].scale == FE_SCALE_RELATIVE)
			*strength = (u16)c->strength.stat[i].uvalue;
		else if (c->strength.stat[i].scale == FE_SCALE_DECIBEL)
			*strength = ((100000 + (s32)c->strength.stat[i].svalue)/1000) * 656;
	}

	return 0;
}

static int mtv23x_read_snr(struct dvb_frontend *fe, u16 *snr)
{
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int i;

	*snr = 0;
	for (i=0; i < c->cnr.len; i++)
		if (c->cnr.stat[i].scale == FE_SCALE_RELATIVE)
		  *snr = (u16)c->cnr.stat[i].uvalue;
	return 0;
}

static int mtv23x_read_ber(struct dvb_frontend *fe,u32 *ber)
{
	struct i2c_client * client = fe->demodulator_priv;
	struct mtv23x_dev * dev = i2c_get_clientdata(client);
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int FECL = 0, prd0 = 0, prd1 = 0, cnt0 = 0, cnt1 = 0, cnt2 = 0;
	u32 count, period,ber_temp=10000;


	regmap_write(dev->regmap,MAP_SEL_REG,FEC_PAGE);
	regmap_read(dev->regmap,0x10,&FECL);

	if (FECL & 0x20) {
		regmap_read(dev->regmap,0x28,&prd0);
		regmap_read(dev->regmap,0x29,&prd1);
		period = (prd0<<8) | prd1;

		regmap_read(dev->regmap,0x31,&cnt0);
		regmap_read(dev->regmap,0x32,&cnt1);
		regmap_read(dev->regmap,0x33,&cnt2);
		count = ((cnt0&0x7f)<<16) | (cnt1<<8) | cnt2;
	} else
		period = 0;

	c->post_bit_error.len = c->post_bit_count.len = 1;
	c->post_bit_error.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	c->post_bit_count.stat[0].scale = FE_SCALE_NOT_AVAILABLE;

	if (period) {
		ber_temp= (count * 100000) / (period*8*204);
		c->post_bit_error.stat[0].scale = FE_SCALE_COUNTER;
		c->post_bit_error.stat[0].uvalue = count;
		c->post_bit_count.stat[0].scale = FE_SCALE_COUNTER;
		c->post_bit_count.stat[0].uvalue = period*8*204;
	}
	
	*ber = ber_temp/1000;
	return 0;

}

static struct dvb_frontend_ops mtv23x_ops = {
	.delsys = {SYS_ISDBT},
	.info 	= {
		.name = "RAONTECH MTV23X",
		.frequency_min_hz = 76 * MHz,
		.frequency_max_hz = 858 * MHz,
		.frequency_stepsize_hz = 166667,
		.caps =	FE_CAN_FEC_1_2 | FE_CAN_FEC_2_3 | FE_CAN_FEC_3_4 |
				FE_CAN_FEC_5_6 | FE_CAN_FEC_7_8 | FE_CAN_FEC_AUTO |
				FE_CAN_QPSK | FE_CAN_QAM_16 |
				FE_CAN_QAM_64 | FE_CAN_QAM_AUTO |
				FE_CAN_TRANSMISSION_MODE_AUTO |
				FE_CAN_GUARD_INTERVAL_AUTO |
				FE_CAN_HIERARCHY_AUTO |
				FE_CAN_RECOVER |
				FE_CAN_MUTE_TS
	},

	.init = mtv23x_init,
	.set_frontend = mtv23x_set_frontend,
	.get_frontend = mtv23x_get_frontend,
	.read_status  = mtv23x_read_status,
	.read_signal_strength = mtv23x_read_signal_strength,
	.read_snr = mtv23x_read_snr,
	.read_ber = mtv23x_read_ber,
};
static int mtv23x_probe(struct i2c_client*client,
						const struct i2c_device_id *id)
{
	struct mtv23x_config *cfg = client->dev.platform_data;
	struct mtv23x_dev *dev ;
	int ret,temp;
		
	static const struct regmap_config regmap_config = {
		.reg_bits = 8,
		.val_bits = 8,
	};
	dev = kzalloc(sizeof(*dev),GFP_KERNEL);
	if(!dev){
		ret = -ENOMEM;
		goto err;
	}
	dev->i2c_wr_max = cfg->i2c_wr_max?cfg->i2c_wr_max:~0;
	dev->client = client;
	dev->clk_freq = cfg->clk_freq;
	dev->ts_mode = cfg->ts_mode;
	dev->rtv_1seglpmode = 0;
	dev->regmap = regmap_init_i2c(dev->client,&regmap_config);
	if(IS_ERR(dev->regmap)){
		ret = PTR_ERR(dev->regmap);
		goto err_kfree;
	}

	/*check the i2c */
	ret = regmap_read(dev->regmap,0x20,&temp);
	if(ret)
		goto err_regmap_exit;
	ret = regmap_write(dev->regmap,0x20,0xAA);
	if(ret)
		goto err_regmap_exit;
	ret = regmap_read(dev->regmap,0x20,&temp);
	if(temp!=0xAA)
		goto err_regmap_exit;

	/* create a dvb frontend*/
	memcpy(&dev->fe.ops,&mtv23x_ops,sizeof(struct dvb_frontend_ops));
	dev->fe.demodulator_priv = client;
	*cfg->fe	= &dev->fe;
	i2c_set_clientdata(client,dev);
	
	dev_info(&client->dev, "RAONTECH MTV23X successfully identified\n");	

	return 0;
	
err_regmap_exit:
	regmap_exit(dev->regmap);
err_kfree:
	kfree(dev);
err:
	dev_dbg(&client->dev,"failed = %d\n",ret);
	return ret;
}
static int mtv23x_remove(struct i2c_client*client)
{
	struct mtv23x_dev*dev = i2c_get_clientdata(client);

	regmap_exit(dev->regmap);
	kfree(dev);

	return 0;
}

static const struct i2c_device_id mtv23x_id_table[] ={
		{"mtv23x",0},
			{}
};

MODULE_DEVICE_TABLE(i2c,mtv23x_id_table);

static struct i2c_driver mtv23x_driver = {

	.driver = {
		.name = "mtv23x",
	},
	.probe = mtv23x_probe,
	.remove = mtv23x_remove,
	.id_table = mtv23x_id_table,

};

module_i2c_driver(mtv23x_driver);


MODULE_AUTHOR("Davin <smiledavin@gmail.com>");
MODULE_DESCRIPTION(" ISDB-T Demodulator driver");
MODULE_LICENSE("GPL");

