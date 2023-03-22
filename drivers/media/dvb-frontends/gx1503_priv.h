#ifndef GX1503_PRIV_H
#define GX1503_PRIV_H

#include <media/dvb_frontend.h>
#include "gx1503.h"
#include <linux/firmware.h>
#include <linux/i2c-mux.h>
#include <linux/regmap.h>

#define GX1503_FIRMWARE "dvb-demod-gx1503B.fw"

struct gx1503_dev {
	/*for i2c repeater*/
	struct mutex i2c_mutex;
#if	LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
	struct i2c_mux_core *muxc;
#endif
	struct i2c_adapter *tuner_adapter;
	struct regmap *regmap;
	u16 i2c_wr_max;
	
	struct dvb_frontend fe;
	int ts_mode;	
	int clk_freq;
	bool fw_loaded;
	bool active;
	
};

/*-- Register Address Definition begin ---------------*/
#define   	T_RST						0x00
#define 	GX1503B_I2C_REPEAT			0x04
#define		SYSCLK_DIV2_L				0x05
#define		SYSCLK_DIV2_M				0x06
#define		SYSCLK_DIV2_H				0x07
#define		IF_FREQ_L					0x08
#define		IF_FREQ_H					0x09		
#define		ALL_OK						0x03
#define		AUTO_TPS0					0x0B
#define		AUTO_TPS1					0x0C
#define		H_POW_L						0x10
#define		H_POW_H						0x11
#define  	NOISE_L						0x12
#define		NOISE_H						0x13	
#define		INT_FREQ_L					0x14
#define		INT_FREQ_M					0x15
#define		INT_FREQ_H	    			0x16
#define   	cfg_int_parm 		 	  	0x17
#define		IF_AGC_H					0x4A
#define		RF_AGC_H					0x4B
#define		DUAL_AGC					0x41
#define		ATV_CONF					0x78
#define		ERR_H						0xDD
#define		ERR_M						0xDC
#define		ERR_L						0xDB
#define		PKT_SUM_PAR					0xD8
#define		CHIP_ADDR					0xF0
#define		I2C_RPT						0xF7
#define 	DevAddr	   					0x60		
#define   	CHIP_ID    					0x45    
#define 	CHIP_ID_ADDR				0xf0
#define 	RFAddr_si248				0xC0


#define GX1503B_CFG_TS_0 0xD2
#define GX1503B_CFG_TS_2 0xD3
#define GX1503B_CFG_TS_4 0xD4
#define GX1503B_CFG_TS_6 0xD5
#define GX1503B_CFG_TS_8 0xD6
#define GX1503B_CFG_TS_A 0xD7

#endif
