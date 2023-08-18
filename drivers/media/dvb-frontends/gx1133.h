/*
    Tmax gx1133 - DVBS/S2 Satellite demod/tuner driver

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

#ifndef gx1133_H
#define gx1133_H

#include <linux/kconfig.h>
#include <linux/dvb/frontend.h>

enum Demod_TS_Inr
{
	data_0		=	0x0	,
	data_1		=	0x1	,
	data_2		=	0x2	,
	data_3		=	0x3	,
	data_4		=	0x4	,
	data_5		=	0x5	,
	data_6		=	0x6	,
	data_7		=	0x7	,
	ts_clk		=	0x8	,
	ts_valid	=	0x9	,
	ts_sync		=	0xa	,
	ts_err		=	0xb	,
	s2_ok_clk	=	0xc	,
	mcu_txd		=	0xd	,
	vcc		=	0xe	,
	gnd		=	0xf

};

struct Demod_TS_Pin_cfg
{
	enum Demod_TS_Inr	TS_0	;
	enum Demod_TS_Inr	TS_1	;
	enum Demod_TS_Inr	TS_2	;
	enum Demod_TS_Inr	TS_3	;
	enum Demod_TS_Inr	TS_4	;
	enum Demod_TS_Inr	TS_5	;
	enum Demod_TS_Inr	TS_6	;
	enum Demod_TS_Inr	TS_7	;
	enum Demod_TS_Inr	TS_8	;
	enum Demod_TS_Inr	TS_9	;
	enum Demod_TS_Inr	TS_10	;
	enum Demod_TS_Inr	TS_11	;
};


struct gx1133_config {
	/* demodulator i2c address */
	u8 i2c_address;
	u8 ts_mode;   //parallel_port = 0 ; serial_port = 1;
	struct Demod_TS_Pin_cfg ts_cfg;

	/* demod hard reset */
	void (*reset_demod)(struct dvb_frontend *fe);
	/* lnb power */
	void (*lnb_power)(struct dvb_frontend *fe, int onoff);

	//spi flash op
	void (*write_properties) (struct i2c_adapter *i2c,u8 reg, u32 buf);  
	void (*read_properties) (struct i2c_adapter *i2c,u8 reg, u32 *buf);

	void (*mcuWrite_properties) (struct i2c_adapter *i2c,u32 bassaddr,u8 reg, u32 buf);  
	void (*mcuRead_properties) (struct i2c_adapter *i2c,u32 bassaddr,u8 reg, u32 *buf);	
	void (*i2cRead_properties) (struct i2c_adapter *i2c,u8 chip_addr,u8 reg, u8 num, u8 *buf);
	void (*i2cwrite_properties) (struct i2c_adapter *i2c,u8 chip_addr,u8 reg, u8 num, u8 *buf);

};



#if IS_REACHABLE(CONFIG_DVB_GX1133)
extern struct dvb_frontend *gx1133_attach(
	const struct gx1133_config *cfg,
	struct i2c_adapter *i2c);
extern struct i2c_adapter *gx1133_get_i2c_adapter(struct dvb_frontend *fe, int bus);
#else
static inline struct dvb_frontend *gx1133_attach(
	const struct gx1133_config *cfg,
	struct i2c_adapter *i2c)
{
	dev_warn(&i2c->dev, "%s: driver disabled by Kconfig\n", __func__);
	return NULL;
}
static struct i2c_adapter *gx1133_get_i2c_adapter(struct dvb_frontend *fe, int bus)
{
	return NULL;
}
#endif

#endif /* gx1133_H */
