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

#ifndef TAS2101_PRIV_H
#define TAS2101_PRIV_H

struct tas2101_priv {
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
	const struct tas2101_config *cfg;

};

/* demod registers */
enum tas2101_reg_addr {
	ID_0		= 0x00,
	ID_1		= 0x01,
	REG_04		= 0x04,
	REG_06		= 0x06,
	LNB_CTRL	= 0x10,
	LNB_STATUS	= 0x16,
	DISEQC_BUFFER	= 0x20,
	REG_30		= 0x30,
	DEMOD_STATUS	= 0x31,
	REG_34		= 0x34,
	SIGSTR_0	= 0x42,
	SIGSTR_1	= 0x43,
	GET_SRATE0	= 0x5c,
	GET_SRATE1	= 0x5d,
	SET_SRATE0	= 0x73,
	SET_SRATE1	= 0x74,
	FREQ_OS0	= 0x75,
	FREQ_OS1	= 0x76,
	SNR_0		= 0x92,
	SNR_1		= 0x93,
	S1_BER_0	= 0xd1,
	S1_BER_1	= 0xd2,
	S1_BER_2	= 0xd3,
	S1_BER_3	= 0xd4,
	S2_BER_0	= 0xec,
	S2_BER_1	= 0xed,
	MODFEC_0	= 0xee,
	MODFEC_1	= 0xef,
};

#define I2C_GATE		0x80

#define VSEL13_18		0x40
#define DISEQC_CMD_LEN_MASK	0x38
#define DISEQC_CMD_MASK		0x07



enum tas2101_diseqc_cmd {
	TONE_OFF	= 0x00,
	TONE_ON		= 0x01,
	DISEQC_BURST_A	= 0x02,
	DISEQC_BURST_B	= 0x03,
	DISEQC_SEND_MSG	= 0x04,
};

#define DISEQC_BUSY		0x10

#define DEMOD_STATUS_MASK	0x75
#define DEMOD_LOCKED		0x75


enum tas2101_lnb_power {
	LNB_OFF = 0,
	LNB_ON  = 1,
};

struct tas2101_regtable {
	u8 addr;
	u8 setmask;
	u8 clrmask;
	int sleep;
};

static struct tas2101_regtable tas2101_initfe0[] = {
	{REG_30, 0x02, 0x00, 0},
	{0x56, 0x00, 0x02, 0},
	{0x05, 0x04, 0x00, 0},
	{0x05, 0x00, 0x04, 60},
	{0x08, 0x80, 0x00, 0},
	{0x09, 0x3b, 0xff, 0},
	{0x08, 0x00, 0x80, 60},
	{0x0a, 0x80, 0x00, 0},
	{0x0b, 0x47, 0xff, 0},
	{0x0a, 0x00, 0x80, 40},
	{0x03, 0xa9, 0xff, 40},
	{0x0e, 0x05, 0xff, 0},
	{0x0f, 0x06, 0xff, 40},
	{0x70, 0x82, 0xff, 0},
	{0x71, 0x8b, 0xff, 0},
	{0x72, 0x01, 0xff, 0},
	{0x0d, 0x00, 0xc0, 40},
	{0x0d, 0xc0, 0x00, 0},
};

static struct tas2101_regtable tas2100_initfe0[] = {
	{REG_30, 0x02, 0x00, 0},
	{0x08, 0x00, 0x80, 60},
	{0x0b, 0x55, 0xff, 0},
	{0x0a, 0x00, 0x80, 40},
	{0x0e, 0x04, 0xff, 0},
	{0x0f, 0x05, 0xff, 40},
	{0x70, 0x98, 0xff, 0},
	{0x71, 0x66, 0xff, 0},
	{0x72, 0x01, 0xff, 0},
	{0x0d, 0x00, 0xc0, 40},
	{0x0d, 0xc0, 0x00, 0},
};

static struct tas2101_regtable tas2101_initfe1[] = {
/*	{0xe0, 0x33, 0xff, 0},	depends on tsmode ( 0xb1 tsmode=1 ) */
	{0x56, 0x81, 0x00, 0},
	{0x05, 0x00, 0x08, 0},
	{0x36, 0x00, 0x40, 0},
	{0x91, 0x00, 0xf0, 0},
	{0x35, 0x75, 0xff, 0},
	{REG_04, 0x00, 0x80, 0},
	{0x0d, 0x80, 0x00, 0},
	{0x30, 0x01, 0x00, 0},
	{0x05, 0x00, 0x80, 0},
	{REG_06, 0, I2C_GATE, 0},
	{0x41, 0x1c, 0x3f, 0},
	{0x46, 0xdc, 0xff, 0},
	{0x11, 0x7f, 0xff, 0},
	{0x12, 0x04, 0x07, 0},
	{0x1f, 0x00, 0x01, 0},
	{REG_34, 0x00, 0x40, 0},
	{0xd0, 0x05, 0x7f, 0},
	{0xe3, 0x02, 0x03, 0},
	{0x58, 0x60, 0xe0, 0},
	{0x50, 0x64, 0xff, 0},
	{0x9e, 0x08, 0x3f, 0},
	{0x9d, 0x07, 0x00, 0},
	{0x49, 0xa0, 0xf0, 0},
	{0x87, 0x70, 0xf0, 0},
	{0x90, 0x04, 0xff, 0},
	{0x9d, 0x07, 0x00, 0},
	{0x9e, 0x20, 0x3f, 0},
	{REG_06, 0x00, 0x1f, 0},
	{0x46, 0x18, 0x1f, 0},
	{0x40, 0x04, 0x07, 0},
};


static struct tas2101_regtable tas2101_initfe2[] = {
	{0xfa, 0x01, 0x03, 0},
	{0xfb, 0x02, 0xff, 0},
};

static struct tas2101_regtable tas2100_initfe1[] = {
	{0x56, 0x81, 0x00, 0},
	{0x05, 0x00, 0x08, 0},
	{0x36, 0x00, 0x40, 0},
	{0x91, 0x22, 0xff, 0},
	{0x35, 0x75, 0xff, 0},
	{REG_04, 0x30, 0xff, 0},
	{0x30, 0x01, 0x00, 0},
	{0x05, 0x00, 0x80, 0},
	{REG_06, 0, I2C_GATE, 0},
	{0x41, 0x1c, 0x3f, 0},
	{0x46, 0xdc, 0xff, 0},
	{0x11, 0x13, 0xff, 0},
	{0x12, 0x04, 0x07, 0},
	{REG_34, 0x00, 0x40, 0},
	{0xd0, 0x05, 0x7f, 0},
	{0xe3, 0x02, 0x03, 0},
	{0x58, 0x60, 0xe0, 0},
	{0x50, 0x64, 0xff, 0},
	{0x9e, 0x20, 0x3f, 0},
	{0x9d, 0x07, 0x00, 0},
	{0x49, 0x90, 0xf0, 0},
	{0x87, 0xd0, 0xf0, 0},
	{0x90, 0x10, 0xff, 0},
	{0x9d, 0x07, 0x00, 0},
	{0x9e, 0x20, 0x3f, 0},
	{REG_06, 0x00, 0x1f, 0},
};

static struct tas2101_regtable tas2101_setfe[] = {
	{REG_04, 0x08, 0x00, 0},
	{0x36, 0x01, 0x00, 0},
	{0x56, 0x01, 0x81, 0},
	{0x05, 0x08, 0x00, 0},
	{0x36, 0x40, 0x00, 0},
	{0x58, 0x60, 0xe0, 0},
};

struct tas2101_snrtable_pair {
	u16 snr;
	u16 raw;
};

static struct tas2101_snrtable_pair tas2101_snrtable[] =  {
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

struct tas2101_dbmtable_pair {
	s32 dbm;
	u16 raw;
};

static struct tas2101_dbmtable_pair tas2101_dbmtable[] =  {
	{ -1000, 0xfff},
	{ -900, 0x778},
	{ -800, 0x621},
	{ -700, 0x55c},  
	{ -600, 0x40e},
	{ -500, 0x343},
	{ -400, 0x2b7},
	{ -300, 0x231},
	{ -200, 0x1a1},
	{ 0, 0},
};

/* modfec (modulation and FEC) lookup table */
struct tas2101_modfec {
	enum fe_delivery_system delivery_system;
	enum fe_modulation modulation;
	enum fe_code_rate fec;
};

static struct tas2101_modfec tas2101_modfec_modes[] = {
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

#endif /* TAS2101_PRIV_H */
