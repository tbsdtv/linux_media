//SPX-License-Identifier: GPL-2.0-or-later
/*
 * Montage Technology M88rs6060 demodulator and tuner drivers
 * some code form 
 * Copyright (c) 2021 Davin zhang <Davin@tbsdtv.com> www.Turbosight.com
 *
*/

#ifndef _M88RS6060_H_
#define _M88RS6060_H_
#include <linux/dvb/frontend.h>

#define MT_FE_MCLK_KHZ   96000

/*
* 
*/

enum m88rs6060_ts_mode {
	MtFeTsOutMode_Unknown = 0,
	MtFeTsOutMode_Serial,
	MtFeTsOutMode_Parallel,
	MtFeTsOutMode_Common,
};

enum MT_FE_CODE_RATE {
	MtFeCodeRate_Undef =
	    0, MtFeCodeRate_1_4, MtFeCodeRate_1_3, MtFeCodeRate_2_5,
	    MtFeCodeRate_1_2, MtFeCodeRate_3_5, MtFeCodeRate_2_3,
	    MtFeCodeRate_3_4, MtFeCodeRate_4_5, MtFeCodeRate_5_6,
	    MtFeCodeRate_7_8, MtFeCodeRate_8_9, MtFeCodeRate_9_10
	    //,MtFeCodeRate_1_2L
	    //,MtFeCodeRate_3_5L
	    //,MtFeCodeRate_2_3L
	    , MtFeCodeRate_5_9
	    //,MtFeCodeRate_5_9L
	    , MtFeCodeRate_7_9, MtFeCodeRate_4_15, MtFeCodeRate_7_15,
	    MtFeCodeRate_8_15
	    //,MtFeCodeRate_8_15L
	    , MtFeCodeRate_11_15
	    //,MtFeCodeRate_11_15L
	    , MtFeCodeRate_13_18, MtFeCodeRate_9_20, MtFeCodeRate_11_20,
	    MtFeCodeRate_23_36, MtFeCodeRate_25_36, MtFeCodeRate_11_45,
	    MtFeCodeRate_13_45, MtFeCodeRate_14_45, MtFeCodeRate_26_45
	    //,MtFeCodeRate_26_45L
	    , MtFeCodeRate_28_45, MtFeCodeRate_29_45
	    //,MtFeCodeRate_29_45L
	    , MtFeCodeRate_31_45
	    //,MtFeCodeRate_31_45L
	    , MtFeCodeRate_32_45
	    //,MtFeCodeRate_32_45L
	, MtFeCodeRate_77_90
};

enum MT_FE_ROLL_OFF {
	MtFeRollOff_Undef =
	    0, MtFeRollOff_0p35, MtFeRollOff_0p25, MtFeRollOff_0p20,
	    MtFeRollOff_0p15, MtFeRollOff_0p10, MtFeRollOff_0p05
} MT_FE_ROLL_OFF;

enum MT_FE_SPECTRUM_MODE {
	MtFeSpectrum_Undef = 0, MtFeSpectrum_Normal, MtFeSpectrum_Inversion
};

enum MT_FE_TYPE {
	MtFeType_Undef = 0,
	MtFeType_DVBC = 0x10,
	MtFeType_DVBT = 0x20,
	MtFeType_DVBT2 = 0x21,
	MtFeType_DTMB = 0x30,
	MtFeType_DvbS = 0x40,
	MtFeType_DvbS2 = 0x41,
	MtFeType_DvbS2X = 0x42,
	MtFeType_ABS = 0x50,
	MtFeType_TMS = 0x51,
	MtFeType_DTV_Unknown = 0xFE,
	MtFeType_DTV_Checked = 0xFF
};

enum MT_FE_MOD_MODE {
	MtFeModMode_Undef = 0,
	MtFeModMode_4Qam,
	MtFeModMode_4QamNr,
	MtFeModMode_16Qam,
	MtFeModMode_32Qam,
	MtFeModMode_64Qam,
	MtFeModMode_128Qam,
	MtFeModMode_256Qam,
	MtFeModMode_Qpsk,
	MtFeModMode_8psk,
	MtFeModMode_16Apsk,
	MtFeModMode_32Apsk,
	MtFeModMode_64Apsk,
	MtFeModMode_128Apsk,
	MtFeModMode_256Apsk,
	MtFeModMode_8Apsk_L,
	MtFeModMode_16Apsk_L,
	MtFeModMode_32Apsk_L,
	MtFeModMode_64Apsk_L,
	MtFeModMode_128Apsk_L,
	MtFeModMode_256Apsk_L,
	MtFeModMode_Auto
};
enum MT_FE_LOCK_STATE {
	MtFeLockState_Undef = 0,
	MtFeLockState_Unlocked,
	MtFeLockState_Locked,
	MtFeLockState_Waiting
};

struct m88rs6060_cfg {
	struct dvb_frontend **fe;
	u8 demod_adr;
	u8 tuner_adr;
	enum m88rs6060_ts_mode ts_mode;	// 1:serial 2: parallel 3:common
	/* select ts output pin order
	 * for serial ts mode, swap pin D0 &D7
	 * for parallel or CI mode ,swap the order of D0 ~D7
	 */
	bool ts_pinswitch;
	bool ts_autoclock;
	u32 clk;
	u16 i2c_wr_max;
	u8 envelope_mode;	//for diseqc   default 0
	//0x11 or 0x12 0x11 : there is only one i2c_STOP flag. 0x12 ther are two I2C_STOP flag.        
	u8 repeater_value;
	bool disable_22k; //for 6909se tuner 1,3,5,7 
	u8 num; // for ci setting;
	bool HAS_CI; // for 6910se ci
	
	int clk_port; //for si5351

	int (*SetCIClock)(struct i2c_adapter *i2c, int tuner);  //set the CI clock for 6910se
	void (*SetTimes)(struct i2c_adapter * i2c, int tuner,int times);
	
	void (*write_properties)(struct i2c_adapter * i2c, u8 reg, u32 buf);
	void (*read_properties)(struct i2c_adapter * i2c, u8 reg, u32 * buf);
	void (*write_eeprom) (struct i2c_adapter *i2c,u8 reg, u8 buf);
	void (*read_eeprom) (struct i2c_adapter *i2c,u8 reg, u8 *buf);
	/*rf switch for 6590se*/
	void (*RF_switch)(struct i2c_adapter * i2c,u8 rf_in,u8 flag);
};

#endif
