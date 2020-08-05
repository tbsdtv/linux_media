/*
 * Silicon Labs Si2183(2) DVB-T/T2/C/C2/S/S2 demodulator driver
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
 */

#ifndef SI2183_H
#define SI2183_H

#include <linux/dvb/frontend.h>
/*
 * I2C address
 * 0x64
 */
struct si2183_config {
	/*
	 * frontend
	 * returned by driver
	 */
	struct dvb_frontend **fe;

	/*
	 * tuner I2C adapter
	 * returned by driver
	 */
	struct i2c_adapter **i2c_adapter;

	/* TS mode */
#define SI2183_TS_PARALLEL	0x06
#define SI2183_TS_SERIAL	0x03
	u8 ts_mode;

	/* TS clock inverted */
	bool ts_clock_inv;

	int  start_clk_mode;  //0 terrestrial mode 1: satellite mode
	
	/* TS clock gapped */
	bool ts_clock_gapped;
	/*agc*/
	u8 agc_mode;

	/*rf switch*/
	void (*RF_switch)(struct i2c_adapter * i2c,u8 rf_in,u8 flag);
	/*rf no.*/
	u8 rf_in;

	void (*TS_switch)(struct i2c_adapter * i2c,u8 flag);
	void (*LED_switch)(struct i2c_adapter * i2c,u8 flag);
	//update the FW.
	void (*write_properties) (struct i2c_adapter *i2c,u8 reg, u32 buf);
	void (*read_properties) (struct i2c_adapter *i2c,u8 reg, u32 *buf);
	// EEPROM access
	void (*write_eeprom) (struct i2c_adapter *i2c,u8 reg, u8 buf);
	void (*read_eeprom) (struct i2c_adapter *i2c,u8 reg, u8 *buf);
};

#endif
