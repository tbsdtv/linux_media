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



struct gx1133_config {
	/* demodulator i2c address */
	u8 i2c_address;

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
