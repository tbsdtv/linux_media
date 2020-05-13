/*
    Tmax TAS2101 - DVBS/S2 Satellite demodulator driver

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

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/i2c-mux.h>

#include <media/dvb_frontend.h>

#include "tas2971.h"
#include "tas2971_priv.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#if IS_ENABLED(CONFIG_I2C_MUX)
#define TAS2971_USE_I2C_MUX
#endif
#endif

LIST_HEAD(stvlist);

/* write multiple (continuous) registers */
/* the first value is the starting address */
static int tas2101_wrm(struct tas2971_priv *priv, u8 *buf, int len)
{
	return 0;

}

/* write one register */
static int tas2101_wr(struct tas2971_priv *priv, u8 addr, u8 data)
{
	return 0;

}

/* read multiple (continuous) registers starting at addr */
static int tas2101_rdm(struct tas2971_priv *priv, u8 addr, u8 *buf, int len)
{
	return 0;

}

/* read one register */
static int tas2101_rd(struct tas2971_priv *priv, u8 addr, u8 *data)
{
	return 0;

}

static int tas2101_regmask(struct tas2971_priv *priv,
	u8 reg, u8 setmask, u8 clrmask)
{
	return 0;

}

static int tas2101_wrtable(struct tas2971_priv *priv,
	struct tas2101_regtable *regtable, int len)
{	
	return 0;

}

static int tas2101_read_ber(struct dvb_frontend *fe, u32 *ber)
{

*ber = 0;
return 0;

}

static int tas2101_read_signal_strength(struct dvb_frontend *fe,
	u16 *signal_strength)
{

	*signal_strength = 62940;
	return 0;
	
}

static int tas2101_read_snr(struct dvb_frontend *fe, u16 *snr)
{
 
	*snr = 26896;
	return 0;


}

/* unimplemented */
static int tas2101_read_ucblocks(struct dvb_frontend *fe, u32 *ucblocks)
{
	return 0;
}

static int tas2101_read_status(struct dvb_frontend *fe, enum fe_status *status)
{
*status = FE_HAS_SIGNAL | FE_HAS_CARRIER |
			FE_HAS_VITERBI | FE_HAS_SYNC | FE_HAS_LOCK;
return 0;

}
static void tas2101_spi_read(struct dvb_frontend *fe, struct ecp3_info *ecp3inf)
{

	struct tas2971_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->base->i2c;
	if (priv->cfg->read_properties)
		priv->cfg->read_properties(adapter,ecp3inf->reg, &(ecp3inf->data));
	return;
}
static void tas2101_spi_write(struct dvb_frontend *fe,struct ecp3_info *ecp3inf)
{
	struct tas2971_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->base->i2c;
	if (priv->cfg->write_properties)
		priv->cfg->write_properties(adapter,ecp3inf->reg, ecp3inf->data);
	return ;
}
static void tas2101_mcu_read(struct dvb_frontend *fe, struct mcu24cxx_info *mcu24cxxinf)
{

	struct tas2971_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->base->i2c;
	if (priv->cfg->mcuRead_properties)
		priv->cfg->mcuRead_properties(adapter,mcu24cxxinf->bassaddr,mcu24cxxinf->reg, &(mcu24cxxinf->data));
	return;
}
static void tas2101_mcu_write(struct dvb_frontend *fe,struct mcu24cxx_info *mcu24cxxinf)
{
	struct tas2971_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->base->i2c;
	if (priv->cfg->mcuWrite_properties)
		priv->cfg->mcuWrite_properties(adapter,mcu24cxxinf->bassaddr, mcu24cxxinf->reg, mcu24cxxinf->data);
	return ;
}

static void tas2101_reg_i2c_read(struct dvb_frontend *fe, struct usbi2c_access *pi2cinf)
{

	struct tas2971_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->base->i2c;
	if (priv->cfg->i2cRead_properties)
		priv->cfg->i2cRead_properties(adapter,pi2cinf->chip_addr,pi2cinf->reg, pi2cinf->num, pi2cinf->buf);
	return;
}
static void tas2101_reg_i2c_write(struct dvb_frontend *fe,struct usbi2c_access *pi2cinf)
{
	struct tas2971_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->base->i2c;
	if (priv->cfg->i2cwrite_properties)
		priv->cfg->i2cwrite_properties(adapter,pi2cinf->chip_addr,pi2cinf->reg, pi2cinf->num, pi2cinf->buf);
	return ;
}

static int tas2101_set_voltage(struct dvb_frontend *fe,
	enum fe_sec_voltage voltage)
{
	return 0;
	
}

static int tas2101_set_tone(struct dvb_frontend *fe,
	enum fe_sec_tone_mode tone)
{
	return 0;
	
}

static int tas2101_send_diseqc_msg(struct dvb_frontend *fe,
	struct dvb_diseqc_master_cmd *d)
{
	return 0;

}

static int tas2101_diseqc_send_burst(struct dvb_frontend *fe,
	enum fe_sec_mini_cmd burst)
{
	return 0;
}

static void tas2101_release(struct dvb_frontend *fe)
{
	struct tas2971_priv *priv = fe->demodulator_priv;

	dev_dbg(&priv->base->i2c->dev, "%s\n", __func__);
#ifdef TAS2971_USE_I2C_MUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	i2c_mux_del_adapters(priv->base->muxc);
#else
	i2c_del_mux_adapter(priv->base->i2c_demod);
	i2c_del_mux_adapter(priv->base->i2c_tuner);
#endif
#endif
	
	priv->base->count--;
	if(priv->base->count == 0){
	list_del(&priv->base->stvlist);
	kfree(priv->base);

	kfree(priv);
	}
}

#ifdef TAS2971_USE_I2C_MUX
/* channel 0: demod */
/* channel 1: tuner */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
static int tas2101_i2c_select(struct i2c_mux_core *muxc, u32 chan_id)
{
	return 0;

#else
static int tas2101_i2c_select(struct i2c_adapter *adap,
	void *mux_priv, u32 chan_id)
{
	return 0;
#endif
}
#endif

static struct dvb_frontend_ops tas2101_ops;

static struct tas2971_base *match_base(struct i2c_adapter  *i2c)
{
	struct tas2971_base *p;

	list_for_each_entry(p, &stvlist, stvlist)
		if (p->i2c == i2c)
			return p;
	return NULL;
}

struct dvb_frontend *tas2971_attach(const struct tas2101_config *cfg,
	struct i2c_adapter *i2c)
{
	struct tas2971_priv *priv = NULL;
	struct tas2971_base *base = NULL;
	int ret;
	u8 id[2];
	printk(KERN_INFO "begin Attaching frontend\n");
	dev_dbg(&i2c->dev, "%s: Attaching frontend\n", KBUILD_MODNAME);

	priv = kzalloc(sizeof(struct tas2971_priv), GFP_KERNEL);
	if (priv == NULL)
		goto err;

	base = match_base(i2c);
	if(base){
		base->count++;
		priv->base = base;
	}
	else{
	/* allocate memory for the priv data */
	base = kzalloc(sizeof(struct tas2971_base), GFP_KERNEL);
	if (priv == NULL)
		goto err;
	base->count =1;
	list_add(&base->stvlist, &stvlist);
	
	base->i2c = i2c;
	base->i2c_ch = 0;

#ifdef TAS2971_USE_I2C_MUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	/* create mux i2c adapter for tuner */
	base->muxc = i2c_mux_alloc(i2c, &i2c->dev,
				  2, 0, I2C_MUX_LOCKED,
				  tas2101_i2c_select, NULL);

	if (!base->muxc) {
		ret = -ENOMEM;
		goto err1;
	}
	base->muxc->priv = priv;
	ret = i2c_mux_add_adapter(base->muxc, 0, 0, 0);
	if (ret)
		goto err1;
	ret = i2c_mux_add_adapter(base->muxc, 0, 1, 0);
	if (ret)
		goto err1;
	base->i2c_demod = base->muxc->adapter[0];
	base->i2c_tuner = base->muxc->adapter[1];
#else
	/* create muxed i2c adapter for the demod */
	base->i2c_demod = i2c_add_mux_adapter(i2c, &i2c->dev, priv, 0, 0, 0,
		tas2101_i2c_select, NULL);
	if (base->i2c_demod == NULL)
		goto err1;
	/* create muxed i2c adapter for the tuner */
	base->i2c_tuner = i2c_add_mux_adapter(i2c, &i2c->dev, priv, 0, 1, 0,
		tas2101_i2c_select, NULL);
	if (base->i2c_tuner == NULL)
		goto err2;
#endif
#else
	base->i2c_demod = i2c;
	base->i2c_tuner = i2c;
#endif
	priv->base = base;
	}
	
	priv->cfg = cfg;
	/* create dvb_frontend */
	memcpy(&priv->fe.ops, &tas2101_ops,
		sizeof(struct dvb_frontend_ops));
	priv->fe.demodulator_priv = priv;
	/* reset demod */
	if (cfg->reset_demod)
		cfg->reset_demod(&priv->fe);

	msleep(100);

	/* check if demod is alive */
	//ret = tas2101_rdm(priv, ID_0, id, 2);
	//if ((id[0] != 0x44) || (id[1] != 0x4c))
	//	ret |= -EIO;
	//if (ret)
		//goto err3;
	

	printk(KERN_INFO "end Attaching frontend\n");
	return &priv->fe;

err3:
#ifdef TAS2971_USE_I2C_MUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	i2c_mux_del_adapters(base->muxc);
#else
	i2c_del_mux_adapter(base->i2c_tuner);
err2:
	i2c_del_mux_adapter(base->i2c_demod);
#endif
#endif
err1:
	kfree(base);
	kfree(priv);
err:
	dev_err(&i2c->dev, "%s: Error attaching frontend\n", KBUILD_MODNAME);

	return NULL;
}
EXPORT_SYMBOL_GPL(tas2971_attach);

static int tas2101_initfe(struct dvb_frontend *fe)
{
	return 0;

}

static int tas2101_sleep(struct dvb_frontend *fe)
{

	return 0;
}

static int tas2101_set_frontend(struct dvb_frontend *fe)
{
	return 0;

}

static int tas2101_get_frontend(struct dvb_frontend *fe,
				struct dtv_frontend_properties *c)
{
c->fec_inner = 1;
c->modulation = 0;
c->delivery_system = 5;
c->inversion = 2;
c->symbol_rate = 41260000;
	return 0;

	
}

static int tas2101_tune(struct dvb_frontend *fe, bool re_tune,
	unsigned int mode_flags, unsigned int *delay, enum fe_status *status)
{	
	
return tas2101_read_status(fe, status);//lucy
	
}

static enum dvbfe_algo tas2101_get_algo(struct dvb_frontend *fe)
{
	return DVBFE_ALGO_HW;
}

#ifndef TAS2101_USE_I2C_MUX
static int tas2101_i2c_gate_ctrl(struct dvb_frontend* fe, int enable)
{
	return 0;
	
}
#endif

static struct dvb_frontend_ops tas2101_ops = {
	.delsys = { SYS_DVBS, SYS_DVBS2 },
	.info = {
		.name = "Tmax TAS2101",
		.frequency_min_hz	=  950 * MHz,
		.frequency_max_hz	= 2150 * MHz,
		.symbol_rate_min	= 1000000,
		.symbol_rate_max	= 45000000,
		.caps = FE_CAN_INVERSION_AUTO |
			FE_CAN_FEC_1_2 | FE_CAN_FEC_2_3 | FE_CAN_FEC_3_4 |
			FE_CAN_FEC_4_5 | FE_CAN_FEC_5_6 | FE_CAN_FEC_6_7 |
			FE_CAN_FEC_7_8 | FE_CAN_FEC_AUTO |
			FE_CAN_2G_MODULATION |
			FE_CAN_QPSK | FE_CAN_RECOVER
	},
	.release = tas2101_release,

	.init = tas2101_initfe,
	.sleep = tas2101_sleep,
#ifndef TAS2971_USE_I2C_MUX
	.i2c_gate_ctrl = tas2101_i2c_gate_ctrl,
#endif
	.read_status = tas2101_read_status,
	.read_ber = tas2101_read_ber,
	.read_signal_strength = tas2101_read_signal_strength,
	.read_snr = tas2101_read_snr,
	.read_ucblocks = tas2101_read_ucblocks,

	.set_tone = tas2101_set_tone,
	.set_voltage = tas2101_set_voltage,
	.diseqc_send_master_cmd = tas2101_send_diseqc_msg,
	.diseqc_send_burst = tas2101_diseqc_send_burst,
	.get_frontend_algo = tas2101_get_algo,
	.tune = tas2101_tune,

	.set_frontend = tas2101_set_frontend,
	.get_frontend = tas2101_get_frontend,

	.spi_read			= tas2101_spi_read,
	.spi_write			= tas2101_spi_write,
	.mcu_read			= tas2101_mcu_read,
	.mcu_write			= tas2101_mcu_write,
	.reg_i2cread			= tas2101_reg_i2c_read,
	.reg_i2cwrite			= tas2101_reg_i2c_write,

};

//
//lock status: 1
//debug: - Bit error rate: 0
//debug: - Signal strength: 62940
//debug: - SNR: 26896


MODULE_DESCRIPTION("DVB Frontend module for Tmax TAS2101");
MODULE_AUTHOR("Luis Alves (ljalvs@gmail.com)");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

