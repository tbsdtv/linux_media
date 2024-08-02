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

#include "tas2101.h"
#include "tas2101_priv.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#if IS_ENABLED(CONFIG_I2C_MUX)
// #define TAS2101_USE_I2C_MUX
#endif
#endif

/* return i2c adapter */
/* bus = 0   master   */
/* bus = 1   demod    */
/* bus = 2   tuner    */
struct i2c_adapter *tas2101_get_i2c_adapter(struct dvb_frontend *fe, int bus)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	switch (bus) {
	case 0:
	default:
		return priv->i2c;
	case 1:
		return priv->i2c_demod;
	case 2:
		return priv->i2c_tuner;
	}
}
EXPORT_SYMBOL_GPL(tas2101_get_i2c_adapter);

/* write multiple (continuous) registers */
/* the first value is the starting address */
static int tas2101_wrm(struct tas2101_priv *priv, u8 *buf, int len)
{
	int ret;
	struct i2c_msg msg = {
		.addr = priv->cfg->i2c_address,
		.flags = 0, .buf = buf, .len = len };

	dev_dbg(&priv->i2c->dev, "%s() i2c wrm @0x%02x (len=%d)\n",
		__func__, buf[0], len);

	ret = i2c_transfer(priv->i2c_demod, &msg, 1);
	if (ret < 0) {
		dev_warn(&priv->i2c->dev,
			"%s: i2c wrm err(%i) @0x%02x (len=%d)\n",
			KBUILD_MODNAME, ret, buf[0], len);
		return ret;
	}
	return 0;
}

/* write one register */
static int tas2101_wr(struct tas2101_priv *priv, u8 addr, u8 data)
{
	u8 buf[] = { addr, data };
	return tas2101_wrm(priv, buf, 2);
}

/* read multiple (continuous) registers starting at addr */
static int tas2101_rdm(struct tas2101_priv *priv, u8 addr, u8 *buf, int len)
{
	int ret;
	struct i2c_msg msg[] = {
		{ .addr = priv->cfg->i2c_address, .flags = 0,
			.buf = &addr, .len = 1 },
		{ .addr = priv->cfg->i2c_address, .flags = I2C_M_RD,
			.buf = buf, .len = len }
	};

	dev_dbg(&priv->i2c->dev, "%s() i2c rdm @0x%02x (len=%d)\n",
		__func__, addr, len);

	ret = i2c_transfer(priv->i2c_demod, msg, 2);
	if (ret < 0) {
		dev_warn(&priv->i2c->dev,
			"%s: i2c rdm err(%i) @0x%02x (len=%d)\n",
			KBUILD_MODNAME, ret, addr, len);
		return ret;
	}
	return 0;
}

/* read one register */
static int tas2101_rd(struct tas2101_priv *priv, u8 addr, u8 *data)
{
	return tas2101_rdm(priv, addr, data, 1);
}

static int tas2101_regmask(struct tas2101_priv *priv,
	u8 reg, u8 setmask, u8 clrmask)
{
	int ret;
	u8 b = 0;
	if (clrmask != 0xff) {
		ret = tas2101_rd(priv, reg, &b);
		if (ret)
			return ret;
		b &= ~clrmask;
	}
	return tas2101_wr(priv, reg, b | setmask);
}

static int tas2101_wrtable(struct tas2101_priv *priv,
	struct tas2101_regtable *regtable, int len)
{
	int ret, i;

	for (i = 0; i < len; i++) {
		ret = tas2101_regmask(priv, regtable[i].addr,
			regtable[i].setmask, regtable[i].clrmask);
		if (ret)
			return ret;
		if (regtable[i].sleep)
			msleep(regtable[i].sleep);
	}
	return 0;
}

static int tas2101_read_status(struct dvb_frontend *fe, enum fe_status *status)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret, i;
	long val;
	u16 raw;
	u8 buf[2];

	*status = 0;

	ret = tas2101_rd(priv, DEMOD_STATUS, buf);
	if (ret)
		return ret;

	buf[0] &= DEMOD_STATUS_MASK;
	if (buf[0] == DEMOD_LOCKED) {
		*status = FE_HAS_SIGNAL | FE_HAS_CARRIER |
			FE_HAS_VITERBI | FE_HAS_SYNC | FE_HAS_LOCK;

		ret = tas2101_rd(priv, REG_04, buf);
		if (ret)
			return ret;
		if (buf[0] & 0x08)
			ret = tas2101_wr(priv, REG_04, buf[0] & ~0x08);
	}

	val = -1000;
	c->strength.len = 1;
	c->strength.stat[0].scale = FE_SCALE_NOT_AVAILABLE;

	/* Read signal strength */
	ret = tas2101_rdm(priv, SIGSTR_0, buf, 2);
	if (ret)
		return ret;

	raw = (((u16)buf[1] & 0xf0) << 4) | buf[0];

	for (i = 0; i < ARRAY_SIZE(tas2101_dbmtable) - 1; i++)
		if (tas2101_dbmtable[i].raw < raw)
			break;
	if( i == 0 )
		val = tas2101_dbmtable[i].dbm;
	else
	{
		/* linear interpolation between two calibrated values */
		val = (raw - tas2101_dbmtable[i].raw) * tas2101_dbmtable[i-1].dbm;
		val += (tas2101_dbmtable[i-1].raw - raw) * tas2101_dbmtable[i].dbm;
		val /= (tas2101_dbmtable[i-1].raw - tas2101_dbmtable[i].raw);
	}

	c->strength.len = 2;
	c->strength.stat[0].scale = FE_SCALE_DECIBEL;
	c->strength.stat[0].svalue = val *100;

	c->strength.stat[1].scale = FE_SCALE_RELATIVE;
	c->strength.stat[1].uvalue = (100 + val/10) * 656;

	val = 0;
	c->cnr.len = 1;
	c->cnr.stat[0].scale = FE_SCALE_NOT_AVAILABLE;

	/* Read snr */
	ret = tas2101_rdm(priv, SNR_0, buf, 2);
	if (ret)
		return ret;

	raw = (((u16)buf[1] & 0x0f) << 8) | buf[0];

	for (i = 0; i < ARRAY_SIZE(tas2101_snrtable) - 1; i++)
		if (tas2101_snrtable[i].raw < raw)
			break;

	if( i == 0 )
		val = tas2101_snrtable[i].snr;
	else
	{
		/* linear interpolation between two calibrated values */
		val = (raw - tas2101_snrtable[i].raw) * tas2101_snrtable[i-1].snr;
		val += (tas2101_snrtable[i-1].raw - raw) * tas2101_snrtable[i].snr;
		val /= (tas2101_snrtable[i-1].raw - tas2101_snrtable[i].raw);
	}

	c->cnr.len = 2;
	c->cnr.stat[0].scale = FE_SCALE_DECIBEL;
	c->cnr.stat[0].uvalue = 100 * (s64) val;

	c->cnr.stat[1].scale = FE_SCALE_RELATIVE;
	c->cnr.stat[1].uvalue = (u16) val * 328;
	if (c->cnr.stat[1].uvalue > 0xffff)
		c->cnr.stat[1].uvalue = 0xffff;

	return ret;
}

static int tas2101_read_signal_strength(struct dvb_frontend *fe,
	u16 *strength)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;
	int i;

	*strength = 0;
	for (i=0; i < p->strength.len; i++)
	{
		if (p->strength.stat[i].scale == FE_SCALE_RELATIVE)
			*strength = (u16)p->strength.stat[i].uvalue;
		else if (p->strength.stat[i].scale == FE_SCALE_DECIBEL)
			*strength = ((100000 + (s32)p->strength.stat[i].svalue)/1000) * 656;
	}

	return 0;
}


static int tas2101_read_snr(struct dvb_frontend *fe, u16 *snr)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;
	int i;

	*snr = 0;
	for (i=0; i < p->cnr.len; i++)
		if (p->cnr.stat[i].scale == FE_SCALE_RELATIVE)
		  *snr = (u16)p->cnr.stat[i].uvalue;

	return 0;
}

static int tas2101_read_ber(struct dvb_frontend *fe, u32 *ber)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret;
	u8 buf[4];

	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	switch (c->delivery_system) {
		case SYS_DVBS:
			ret = tas2101_rdm(priv, S1_BER_0, buf, 4);
			if (ret)
				return ret;

			*ber = ((((u32) buf[3] & 3) << 24) | (((u32) buf[2]) << 16)
				| (((u32) buf[1]) << 8) | ((u32) buf[0]));
			break;

		case SYS_DVBS2:
			ret = tas2101_rdm(priv, S2_BER_0, buf, 2);
			if (ret)
				return ret;

			*ber = ((((u32) buf[1]) << 8) | ((u32) buf[0]));
			break;

		default:
			*ber = 0;
			break;
	}

	dev_dbg(&priv->i2c->dev, "%s() ber = %d\n", __func__, *ber);
	return 0;
}

/* unimplemented */
static int tas2101_read_ucblocks(struct dvb_frontend *fe, u32 *ucblocks)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);
	*ucblocks = 0;
	return 0;
}

static void tas2101_spi_read(struct dvb_frontend *fe, struct ecp3_info *ecp3inf)
{

	struct tas2101_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->i2c;
	if (priv->cfg->read_properties)
		priv->cfg->read_properties(adapter,ecp3inf->reg, &(ecp3inf->data));
	return;
}
static void tas2101_spi_write(struct dvb_frontend *fe,struct ecp3_info *ecp3inf)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->i2c;
	if (priv->cfg->write_properties)
		priv->cfg->write_properties(adapter,ecp3inf->reg, ecp3inf->data);
	return ;
}

static void tas2101_eeprom_read(struct dvb_frontend *fe, struct eeprom_info *eepinf)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->i2c;

	if (priv->cfg->read_eeprom)
		priv->cfg->read_eeprom(adapter,eepinf->reg, &(eepinf->data));
	return ;
}

static void tas2101_eeprom_write(struct dvb_frontend *fe,struct eeprom_info *eepinf)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->i2c;

	if (priv->cfg->write_eeprom)
		priv->cfg->write_eeprom(adapter,eepinf->reg, eepinf->data);
	return ;
}

static int tas2101_set_voltage(struct dvb_frontend *fe,
	enum fe_sec_voltage voltage)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	int ret = 0;
	
	dev_dbg(&priv->i2c->dev, "%s() %s\n", __func__,
		voltage == SEC_VOLTAGE_13 ? "SEC_VOLTAGE_13" :
		voltage == SEC_VOLTAGE_18 ? "SEC_VOLTAGE_18" :
		"SEC_VOLTAGE_OFF");

	switch (voltage) {
		case SEC_VOLTAGE_13:
			if (priv->cfg->lnb_power)
				priv->cfg->lnb_power(fe, LNB_ON);
			ret = tas2101_regmask(priv, LNB_CTRL,
				0, VSEL13_18);
			break;
		case SEC_VOLTAGE_18:
			if (priv->cfg->lnb_power)
				priv->cfg->lnb_power(fe, LNB_ON);
			ret = tas2101_regmask(priv, LNB_CTRL,
				VSEL13_18, 0);
			break;
		default: /* OFF */
			if (priv->cfg->lnb_power)
				priv->cfg->lnb_power(fe, LNB_OFF);
			break;
	}
	return ret;
}

static int tas2101_set_tone(struct dvb_frontend *fe,
	enum fe_sec_tone_mode tone)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	int ret = -EINVAL;

	dev_dbg(&priv->i2c->dev, "%s() %s\n", __func__,
		tone == SEC_TONE_ON ? "SEC_TONE_ON" : "SEC_TONE_OFF");

	switch (tone) {
	case SEC_TONE_ON:
		ret = tas2101_regmask(priv, LNB_CTRL,
			TONE_ON, DISEQC_CMD_MASK);
		break;
	case SEC_TONE_OFF:
		ret = tas2101_regmask(priv, LNB_CTRL,
			TONE_OFF, DISEQC_CMD_MASK);
		break;
	default:
		dev_warn(&priv->i2c->dev, "%s() invalid tone (%d)\n",
			__func__, tone);
		break;
	}
	return ret;
}

static int tas2101_send_diseqc_msg(struct dvb_frontend *fe,
	struct dvb_diseqc_master_cmd *d)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	int ret, i;
	u8 bck, buf[9];

	/* dump DiSEqC message */
	dev_dbg(&priv->i2c->dev, "%s() ( ", __func__);
	for (i = 0; i < d->msg_len; i++)
		dev_dbg(&priv->i2c->dev, "0x%02x ", d->msg[i]);
	dev_dbg(&priv->i2c->dev, ")\n");

	/* backup LNB tone state */
	ret = tas2101_rd(priv, LNB_CTRL, &bck);
	if (ret)
		return ret;

	ret = tas2101_regmask(priv, REG_34, 0, 0x40);
	if (ret)
		goto exit;

	/* setup DISEqC message to demod */
	buf[0] = DISEQC_BUFFER;
	memcpy(&buf[1], d->msg, 8);
	ret = tas2101_wrm(priv, buf, d->msg_len + 1);
	if (ret)
		goto exit;

	/* send DISEqC send command */
	buf[0] = (bck & ~(DISEQC_CMD_LEN_MASK | DISEQC_CMD_MASK)) |
		DISEQC_SEND_MSG | ((d->msg_len - 1) << 3);
	ret = tas2101_wr(priv, LNB_CTRL, buf[0]);
	if (ret)
		goto exit;

	/* wait at least diseqc typical tx time */
	msleep(54);

	/* Wait for busy flag to clear */
	for (i = 0; i < 10; i++) {
		ret = tas2101_rd(priv, LNB_STATUS, &buf[0]);
		if (ret)
			break;
		if (buf[0] & DISEQC_BUSY)
			goto exit;
		msleep(20);
	}

	/* try to restore the tone setting but return a timeout error */
	ret = tas2101_wr(priv, LNB_CTRL, bck);
	dev_warn(&priv->i2c->dev, "%s() timeout sending burst\n", __func__);
	return -ETIMEDOUT;
exit:
	/* restore tone setting */
	return tas2101_wr(priv, LNB_CTRL, bck);
}

static int tas2101_diseqc_send_burst(struct dvb_frontend *fe,
	enum fe_sec_mini_cmd burst)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	int ret, i;
	u8 bck, r;

	if ((burst != SEC_MINI_A) && (burst != SEC_MINI_B)) {
		dev_err(&priv->i2c->dev, "%s() invalid burst(%d)\n",
			__func__, burst);
		return -EINVAL;
	}

	dev_dbg(&priv->i2c->dev, "%s() %s\n", __func__,
		burst == SEC_MINI_A ? "SEC_MINI_A" : "SEC_MINI_B");

	/* backup LNB tone state */
	ret = tas2101_rd(priv, LNB_CTRL, &bck);
	if (ret)
		return ret;

	ret = tas2101_regmask(priv, REG_34, 0, 0x40);
	if (ret)
		goto exit;

	/* set tone burst cmd */
	r = (bck & ~DISEQC_CMD_MASK) |
		(burst == SEC_MINI_A) ? DISEQC_BURST_A : DISEQC_BURST_B;

	ret = tas2101_wr(priv, LNB_CTRL, r);
	if (ret)
		goto exit;

	/* spec = around 12.5 ms for the burst */
	for (i = 0; i < 10; i++) {
		ret = tas2101_rd(priv, LNB_STATUS, &r);
		if (ret)
			break;
		if (r & DISEQC_BUSY)
			goto exit;
		msleep(20);
	}

	/* try to restore the tone setting but return a timeout error */
	ret = tas2101_wr(priv, LNB_CTRL, bck);
	dev_warn(&priv->i2c->dev, "%s() timeout sending burst\n", __func__);
	return -ETIMEDOUT;
exit:
	/* restore tone setting */
	return tas2101_wr(priv, LNB_CTRL, bck);
}

static void tas2101_release(struct dvb_frontend *fe)
{
	struct tas2101_priv *priv = fe->demodulator_priv;

	dev_dbg(&priv->i2c->dev, "%s\n", __func__);
#ifdef TAS2101_USE_I2C_MUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	i2c_mux_del_adapters(priv->muxc);
#else
	i2c_del_mux_adapter(priv->i2c_demod);
	i2c_del_mux_adapter(priv->i2c_tuner);
#endif
#endif
	kfree(priv);
}

#ifdef TAS2101_USE_I2C_MUX
/* channel 0: demod */
/* channel 1: tuner */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
static int tas2101_i2c_select(struct i2c_mux_core *muxc, u32 chan_id)
{
	struct tas2101_priv *priv = i2c_mux_priv(muxc);
	struct i2c_adapter *adap = priv->i2c;
#else
static int tas2101_i2c_select(struct i2c_adapter *adap,
	void *mux_priv, u32 chan_id)
{
	struct tas2101_priv *priv = mux_priv;
#endif
	int ret;
	u8 buf[2];
	struct i2c_msg msg_wr[] = {
		{ .addr = priv->cfg->i2c_address, .flags = 0,
			.buf = buf, .len = 2 }
	};
	struct i2c_msg msg_rd[] = {
		{ .addr = priv->cfg->i2c_address, .flags = 0,
			.buf = &buf[0], .len = 1 },
		{ .addr = priv->cfg->i2c_address, .flags = I2C_M_RD,
			.buf = &buf[1], .len = 1 }
	};

	dev_dbg(&priv->i2c->dev, "%s() ch=%d\n", __func__, chan_id);

	if (priv->i2c_ch == chan_id)
		return 0;

	buf[0] = REG_06;
	ret = __i2c_transfer(adap, msg_rd, 2);
	if (ret != 2)
		goto err;

	if (chan_id == 0)
		buf[1] &= ~I2C_GATE;
	else
		buf[1] |= I2C_GATE;

	ret = __i2c_transfer(adap, msg_wr, 1);
	if (ret != 1)
		goto err;

	priv->i2c_ch = chan_id;

	return 0;
err:
	dev_dbg(&priv->i2c->dev, "%s() failed=%d\n", __func__, ret);
	return -EREMOTEIO;
}
#endif

static struct dvb_frontend_ops tas2101_ops;

struct dvb_frontend *tas2101_attach(const struct tas2101_config *cfg,
	struct i2c_adapter *i2c)
{
	struct tas2101_priv *priv = NULL;
	int ret;
	u8 id[2];

	dev_dbg(&i2c->dev, "%s: Attaching frontend\n", KBUILD_MODNAME);

	/* allocate memory for the priv data */
	priv = kzalloc(sizeof(struct tas2101_priv), GFP_KERNEL);
	if (priv == NULL)
		goto err;

	priv->cfg = cfg;
	priv->i2c = i2c;
	priv->i2c_ch = 0;

#ifdef TAS2101_USE_I2C_MUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	/* create mux i2c adapter for tuner */
	priv->muxc = i2c_mux_alloc(i2c, &i2c->dev,
				  2, 0, I2C_MUX_LOCKED,
				  tas2101_i2c_select, NULL);
	if (!priv->muxc) {
		ret = -ENOMEM;
		goto err1;
	}
	priv->muxc->priv = priv;
	ret = i2c_mux_add_adapter(priv->muxc, 0, 0);
	if (ret)
		goto err1;
	ret = i2c_mux_add_adapter(priv->muxc, 0, 1);
	if (ret)
		goto err1;
	priv->i2c_demod = priv->muxc->adapter[0];
	priv->i2c_tuner = priv->muxc->adapter[1];
#else
	/* create muxed i2c adapter for the demod */
	priv->i2c_demod = i2c_add_mux_adapter(i2c, &i2c->dev, priv, 0, 0, 0,
		tas2101_i2c_select, NULL);
	if (priv->i2c_demod == NULL)
		goto err1;

	/* create muxed i2c adapter for the tuner */
	priv->i2c_tuner = i2c_add_mux_adapter(i2c, &i2c->dev, priv, 0, 1, 0,
		tas2101_i2c_select, NULL);
	if (priv->i2c_tuner == NULL)
		goto err2;
#endif
#else
	priv->i2c_demod = i2c;
	priv->i2c_tuner = i2c;
#endif

	/* create dvb_frontend */
	memcpy(&priv->fe.ops, &tas2101_ops,
		sizeof(struct dvb_frontend_ops));
	priv->fe.demodulator_priv = priv;

	/* reset demod */
	if (cfg->reset_demod)
		cfg->reset_demod(&priv->fe);

	msleep(100);

	/* check if demod is alive */
	ret = tas2101_rdm(priv, ID_0, id, 2);
	if ((id[0] != 0x44) || (id[1] != 0x4c))
		ret |= -EIO;
	if (ret)
		goto err3;

	return &priv->fe;

err3:
#ifdef TAS2101_USE_I2C_MUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	i2c_mux_del_adapters(priv->muxc);
#else
	i2c_del_mux_adapter(priv->i2c_tuner);
err2:
	i2c_del_mux_adapter(priv->i2c_demod);
#endif
#endif
err1:
	kfree(priv);
err:
	dev_err(&i2c->dev, "%s: Error attaching frontend\n", KBUILD_MODNAME);
	return NULL;
}
EXPORT_SYMBOL_GPL(tas2101_attach);

static int tas2101_initfe(struct dvb_frontend *fe)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	struct tas2101_regtable *t;
	u8 buf[7], size;
	int ret;

	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	if (priv->cfg->id == ID_TAS2101) {
		t = tas2101_initfe0;
		size = ARRAY_SIZE(tas2101_initfe0);
	} else {
		t = tas2100_initfe0;
		size = ARRAY_SIZE(tas2100_initfe0);
	}
	ret = tas2101_wrtable(priv, t, size);
	if (ret)
		return ret;

	buf[0] = 0xe6;
	memcpy(&buf[1], priv->cfg->init, 6);
	ret = tas2101_wrm(priv, buf, 7);
	if (ret)
		return ret;

	ret = tas2101_regmask(priv, 0xe0, priv->cfg->init[6], 0xff);
	if (ret)
		return ret;

	if (priv->cfg->id == ID_TAS2101) {
		t = tas2101_initfe1;
		size = ARRAY_SIZE(tas2101_initfe1);
	} else {
		t = tas2100_initfe1;
		size = ARRAY_SIZE(tas2100_initfe1);
	}
	ret = tas2101_wrtable(priv, t, size);
	if (ret)
		return ret;

	if (priv->cfg->init2) {
		t = tas2101_initfe2;
		size = ARRAY_SIZE(tas2101_initfe2);
		ret = tas2101_wrtable(priv, t, size);
		if (ret)
			return ret;
	}

	return 0;
}

static int tas2101_sleep(struct dvb_frontend *fe)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);
	return 0;
}

static int tas2101_set_frontend(struct dvb_frontend *fe)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	enum fe_status tunerstat;
	int ret, i;
	u32 s;
	u8 buf[3];

	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	/* do some basic parameter validation */
	switch (c->delivery_system) {
	case SYS_DVBS:
		dev_dbg(&priv->i2c->dev, "%s() DVB-S\n", __func__);
		/* Only QPSK is supported for DVB-S */
		if (c->modulation != QPSK) {
			dev_dbg(&priv->i2c->dev,
				"%s() unsupported modulation (%d)\n",
				__func__, c->modulation);
			return -EINVAL;
		}
		break;
	case SYS_DVBS2:
		dev_dbg(&priv->i2c->dev, "%s() DVB-S2\n", __func__);
		break;
	default:
		dev_warn(&priv->i2c->dev,
			"%s() unsupported delivery system (%d)\n",
			__func__, c->delivery_system);
		return -EINVAL;
	}

	ret = tas2101_wrtable(priv, tas2101_setfe, ARRAY_SIZE(tas2101_setfe));
	if (ret)
		return ret;

	/* set symbol rate */
	s = c->symbol_rate / 1000;
	buf[0] = SET_SRATE0;
	buf[1] = (u8) s;
	buf[2] = (u8) (s >> 8);
	ret = tas2101_wrm(priv, buf, 3);
	if (ret)
		return ret;

	/* clear freq offset */
	buf[0] = FREQ_OS0;
	buf[1] = 0;
	buf[2] = 0;
	ret = tas2101_wrm(priv, buf, 3);
	if (ret)
		return ret;

	if (fe->ops.tuner_ops.set_params) {
#ifndef TAS2101_USE_I2C_MUX
		if (fe->ops.i2c_gate_ctrl)
			fe->ops.i2c_gate_ctrl(fe, 1);
#endif
		fe->ops.tuner_ops.set_params(fe);
#ifndef TAS2101_USE_I2C_MUX
		if (fe->ops.i2c_gate_ctrl)
			fe->ops.i2c_gate_ctrl(fe, 0);
#endif
	}

	ret = tas2101_regmask(priv, REG_30, 0x01, 0);
	if (ret)
		return ret;

	for (i = 0; i<15; i++) {
		ret = tas2101_read_status(fe, &tunerstat);
		if (tunerstat & FE_HAS_LOCK)
			return 0;
		msleep(20);
	}
	return -EINVAL;
}

static int tas2101_get_frontend(struct dvb_frontend *fe,
				struct dtv_frontend_properties *c)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	int ret;
	u8 reg, buf[2];

	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	ret = tas2101_rd(priv, MODFEC_0, &reg);
	if (ret)
		return ret;

	if ((reg >> 6) == 0) {
		/* DVB-S */
		reg &= 0x07;
	} else {
		/* DVB-S2 */
		ret = tas2101_rd(priv, MODFEC_1, &reg);
		if (ret)
			return ret;
		reg += 5;
	}

	if (reg > 33) {
		dev_dbg(&priv->i2c->dev, "%s() Unable to get current delivery"
			" system and mode.\n", __func__);
		reg = 0;
	}

	c->fec_inner = tas2101_modfec_modes[reg].fec;
	c->modulation = tas2101_modfec_modes[reg].modulation;
	c->delivery_system = tas2101_modfec_modes[reg].delivery_system;
	c->inversion = INVERSION_AUTO;

	/* symbol rate */
	ret = tas2101_rdm(priv, GET_SRATE0, buf, 2);
	if (ret)
		return ret;
	c->symbol_rate = ((buf[1] << 8) | buf[0]) * 1000;

	return 0;
}

static int tas2101_tune(struct dvb_frontend *fe, bool re_tune,
	unsigned int mode_flags, unsigned int *delay, enum fe_status *status)
{
	struct tas2101_priv *priv = fe->demodulator_priv;

	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	*delay = HZ / 5;
	if (re_tune) {
		int ret = tas2101_set_frontend(fe);
		if (ret)
			return ret;
	}
	return tas2101_read_status(fe, status);
}

static enum dvbfe_algo tas2101_get_algo(struct dvb_frontend *fe)
{
	return DVBFE_ALGO_HW;
}

#ifndef TAS2101_USE_I2C_MUX
static int tas2101_i2c_gate_ctrl(struct dvb_frontend* fe, int enable)
{
	struct tas2101_priv *priv = fe->demodulator_priv;
	int ret;

	if (enable)
		ret = tas2101_regmask(priv, REG_06, I2C_GATE, 0);
	else
		ret = tas2101_regmask(priv, REG_06, 0, I2C_GATE);

	return ret;
}
#endif

static struct dvb_frontend_ops tas2101_ops = {
	.delsys = { SYS_DVBS, SYS_DVBS2 },
	.info = {
		.name = "Tmax TAS2101",
		.frequency_min_hz = 950 * MHz,
		.frequency_max_hz = 2150 * MHz,
		.symbol_rate_min = 1000000,
		.symbol_rate_max = 45000000,
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
#ifndef TAS2101_USE_I2C_MUX
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
	.eeprom_read		= tas2101_eeprom_read,
	.eeprom_write		= tas2101_eeprom_write,
};

MODULE_DESCRIPTION("DVB Frontend module for Tmax TAS2101");
MODULE_AUTHOR("Luis Alves (ljalvs@gmail.com)");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

