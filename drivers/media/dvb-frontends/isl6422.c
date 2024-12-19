/*
	Intersil ISL6422 SEC and LNB Power supply controller

	Created based on isl6423 from Manu Abraham <abraham.manu@gmail.com>

	Copyright (C) Luis Alves <ljalvs@gmail.com>

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

#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>

#include <media/dvb_frontend.h>
#include "isl6422.h"

static unsigned int verbose;
module_param(verbose, int, 0644);
MODULE_PARM_DESC(verbose, "Set Verbosity level");

#define FE_ERROR				0
#define FE_NOTICE				1
#define FE_INFO					2
#define FE_DEBUG				3
#define FE_DEBUGREG				4

#define dprintk(__y, __z, format, arg...) do {						\
	if (__z) {									\
		if	((verbose > FE_ERROR) && (verbose > __y))			\
			printk(KERN_ERR "%s: " format "\n", __func__ , ##arg);		\
		else if	((verbose > FE_NOTICE) && (verbose > __y))			\
			printk(KERN_NOTICE "%s: " format "\n", __func__ , ##arg);	\
		else if ((verbose > FE_INFO) && (verbose > __y))			\
			printk(KERN_INFO "%s: " format "\n", __func__ , ##arg);		\
		else if ((verbose > FE_DEBUG) && (verbose > __y))			\
			printk(KERN_DEBUG "%s: " format "\n", __func__ , ##arg);	\
	} else {									\
		if (verbose > __y)							\
			printk(format, ##arg);						\
	}										\
} while (0)

struct isl6422_dev {
	const struct isl6422_config	*config;
	struct i2c_adapter		*i2c;

	u8 reg_3;
	u8 reg_4;

	unsigned int verbose;
};

static int isl6422_write(struct isl6422_dev *isl6422, u8 reg)
{
	struct i2c_adapter *i2c = isl6422->i2c;
	u8 addr			= isl6422->config->addr;
	int err = 0;

	struct i2c_msg msg = { .addr = addr, .flags = 0, .buf = &reg, .len = 1 };

	dprintk(FE_DEBUG, 1, "write reg %02X", reg);
	err = i2c_transfer(i2c, &msg, 1);
	if (err < 0)
		goto exit;
	return 0;

exit:
	dprintk(FE_ERROR, 1, "I/O error <%d>", err);
	return err;
}

static int isl6422_set_modulation(struct dvb_frontend *fe)
{
	struct isl6422_dev *isl6422		= (struct isl6422_dev *) fe->sec_priv;
	const struct isl6422_config *config	= isl6422->config;
	int err = 0;
	u8 reg_2 = 0;

	reg_2 = 0x01 << 5;

	if (config->mod_extern)
		reg_2 |= (1 << 3);
	else
		reg_2 |= (1 << 4);

	err = isl6422_write(isl6422, reg_2 | ((config->id & 1) << 7));
	if (err < 0)
		goto exit;
	return 0;

exit:
	dprintk(FE_ERROR, 1, "I/O error <%d>", err);
	return err;
}

static int isl6422_voltage_boost(struct dvb_frontend *fe, long arg)
{
	struct isl6422_dev *isl6422 = (struct isl6422_dev *) fe->sec_priv;
	const struct isl6422_config *config	= isl6422->config;
	u8 reg_3 = isl6422->reg_3;
	u8 reg_4 = isl6422->reg_4;
	int err = 0;

	if (arg) {
		/* EN = 1, VSPEN = 1, VBOT = 1 */
		reg_4 |= (1 << 4);
		reg_4 |= 0x1;
		reg_3 |= (1 << 3);
	} else {
		/* EN = 1, VSPEN = 1, VBOT = 0 */
		reg_4 |= (1 << 4);
		reg_4 &= ~0x1;
		reg_3 |= (1 << 3);
	}
	err = isl6422_write(isl6422, reg_3 | ((config->id & 1) << 7));
	if (err < 0)
		goto exit;

	err = isl6422_write(isl6422, reg_4 | ((config->id & 1) << 7));
	if (err < 0)
		goto exit;

	isl6422->reg_3 = reg_3;
	isl6422->reg_4 = reg_4;

	return 0;
exit:
	dprintk(FE_ERROR, 1, "I/O error <%d>", err);
	return err;
}


static int isl6422_set_voltage(struct dvb_frontend *fe,
			       enum fe_sec_voltage voltage)
{
	struct isl6422_dev *isl6422 = (struct isl6422_dev *) fe->sec_priv;
	const struct isl6422_config *config	= isl6422->config;
	u8 reg_3 = isl6422->reg_3;
	u8 reg_4 = isl6422->reg_4;
	int err = 0;

	switch (voltage) {
	case SEC_VOLTAGE_OFF:
		/* EN = 0 */
		reg_4 &= ~(1 << 4);
		break;

	case SEC_VOLTAGE_13:
		/* EN = 1, VSPEN = 1, VTOP = 0, VBOT = 0 */
		reg_4 |= (1 << 4);
		reg_4 &= ~0x3;
		reg_3 |= (1 << 3);
		break;

	case SEC_VOLTAGE_18:
		/* EN = 1, VSPEN = 1, VTOP = 1, VBOT = 0 */
		reg_4 |= (1 << 4);
		reg_4 |=  0x2;
		reg_4 &= ~0x1;
		reg_3 |= (1 << 3);
		break;

	default:
		break;
	}
	err = isl6422_write(isl6422, reg_3 | ((config->id & 1) << 7));
	if (err < 0)
		goto exit;

	err = isl6422_write(isl6422, reg_4 | ((config->id & 1) << 7));
	if (err < 0)
		goto exit;

	isl6422->reg_3 = reg_3;
	isl6422->reg_4 = reg_4;

	return 0;
exit:
	dprintk(FE_ERROR, 1, "I/O error <%d>", err);
	return err;
}

static int isl6422_set_current(struct dvb_frontend *fe)
{
	struct isl6422_dev *isl6422		= (struct isl6422_dev *) fe->sec_priv;
	u8 reg_3 = isl6422->reg_3;
	const struct isl6422_config *config	= isl6422->config;
	int err = 0;

	reg_3 &= ~0x7;

	switch (config->current_max) {
	case SEC_CURRENT_305m:
		/* 305mA */
		/* ISELR = 0, ISELH = X, ISELL = X */
		break;

	case SEC_CURRENT_388m:
		/* 388mA */
		/* ISELR = 1, ISELH = 0, ISELL = 0 */
		reg_3 |=  0x4;
		break;

	case SEC_CURRENT_570m:
		/* 570mA */
		/* ISELR = 1, ISELH = 0, ISELL = 1 */
		reg_3 |=  0x5;
		break;

	case SEC_CURRENT_705m:
		/* 705mA */
		/* ISELR = 1, ISELH = 1, ISELL = 0 */
		reg_3 |=  0x6;
		break;

	case SEC_CURRENT_890m:
		/* 890mA */
		/* ISELR = 1, ISELH = 1, ISELL = 1 */
		reg_3 |= 0x7;
		break;
	}

	err = isl6422_write(isl6422, reg_3 | ((config->id & 1) << 7));
	if (err < 0)
		goto exit;

	switch (config->curlim) {
	case SEC_CURRENT_LIM_ON:
		/* DCL = 0 */
		reg_3 &= ~0x10;
		break;

	case SEC_CURRENT_LIM_OFF:
		/* DCL = 1 */
		reg_3 |= 0x10;
		break;
	}

	err = isl6422_write(isl6422, reg_3 | ((config->id & 1) << 7));
	if (err < 0)
		goto exit;

	isl6422->reg_3 = reg_3;

	return 0;
exit:
	dprintk(FE_ERROR, 1, "I/O error <%d>", err);
	return err;
}

static void isl6422_release(struct dvb_frontend *fe)
{
	isl6422_set_voltage(fe, SEC_VOLTAGE_OFF);

	kfree(fe->sec_priv);
	fe->sec_priv = NULL;
}

struct dvb_frontend *isl6422_attach(struct dvb_frontend *fe,
				    struct i2c_adapter *i2c,
				    const struct isl6422_config *config)
{
	struct isl6422_dev *isl6422;

	isl6422 = kzalloc(sizeof(struct isl6422_dev), GFP_KERNEL);
	if (!isl6422)
		return NULL;

	isl6422->config	= config;
	isl6422->i2c	= i2c;
	fe->sec_priv	= isl6422;

	/* SR3H = 0, SR3M = 1, SR3L = 0 */
	isl6422->reg_3 = 0x02 << 5;
	/* SR4H = 0, SR4M = 1, SR4L = 1 */
	isl6422->reg_4 = 0x03 << 5;

	if (isl6422_set_current(fe))
		goto exit;

	if (isl6422_set_modulation(fe))
		goto exit;

	fe->ops.release_sec		= isl6422_release;
	fe->ops.set_voltage		= isl6422_set_voltage;
	fe->ops.enable_high_lnb_voltage = isl6422_voltage_boost;
	isl6422->verbose		= verbose;

	return fe;

exit:
	kfree(isl6422);
	fe->sec_priv = NULL;
	return NULL;
}
EXPORT_SYMBOL_GPL(isl6422_attach);

MODULE_DESCRIPTION("ISL6422 SEC");
MODULE_AUTHOR("Luis Alves");
MODULE_LICENSE("GPL");
