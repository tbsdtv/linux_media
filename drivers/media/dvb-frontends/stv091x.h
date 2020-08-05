/*
 * Driver for the ST STV091x DVB-S/S2 demodulator.
 *
 * Copyright (C) 2014-2015 Ralph Metzler <rjkm@metzlerbros.de>
 *                         Marcus Metzler <mocm@metzlerbros.de>
 *                         developed for Digital Devices GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 only, as published by the Free Software Foundation.
 *
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 * Or, point your browser to http://www.gnu.org/copyleft/gpl.html
 */

#ifndef _STV091X_H_
#define _STV091X_H_

#include <linux/types.h>
#include <linux/i2c.h>

struct stv091x_cfg {
	u32 clk;
	u8  adr;
	u8  parallel;
	u8  rptlvl;
	u8  dual_tuner;

	/* Hook for Lock LED */
	void (*set_lock_led) (struct dvb_frontend *fe, int offon);

	//update the FW.
	void (*write_properties) (struct i2c_adapter *i2c,u8 reg, u32 buf);
	void (*read_properties) (struct i2c_adapter *i2c,u8 reg, u32 *buf);
	// EEPROM access
	void (*write_eeprom) (struct i2c_adapter *i2c,u8 reg, u8 buf);
	void (*read_eeprom) (struct i2c_adapter *i2c,u8 reg, u8 *buf);
};

#if IS_REACHABLE(CONFIG_DVB_STV091X)
extern struct dvb_frontend *stv091x_attach(struct i2c_adapter *i2c,
					   struct stv091x_cfg *cfg, int nr);
#else
static inline struct dvb_frontend *stv091x_attach(struct i2c_adapter *i2c,
						  struct stv091x_cfg *cfg,
						  int nr)
{
	pr_warn("%s: driver disabled by Kconfig\n", __func__);
	return NULL;
}

#endif

#endif
