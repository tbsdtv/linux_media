/*
 * TurboSight (TBS) Qbox DVB-S2 CI driver
 *
 * Copyright (c) 2010 Konstantin Dimitrov <kosio.dimitrov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, version 2.
 *
 */

#include <linux/version.h>
#include "tbs-qbox2ci.h"
#include "stv6110x.h"
#include "stv090x.h"
#include "stb6100.h"
#include "stb6100_cfg.h"

#include <media/dvb_ca_en50221.h>

#define TBSQBOX_READ_MSG 0
#define TBSQBOX_WRITE_MSG 1
#define TBSQBOX_LED_CTRL (0x1b00)

/* on my own*/
#define TBSQBOX_VOLTAGE_CTRL (0x1800)
#define TBSQBOX_RC_QUERY (0x1a00)

struct tbsqbox2ci_state {
	struct dvb_ca_en50221 ca;
	struct mutex ca_mutex;
};

/* debug */
static int dvb_usb_tbsqbox2ci_debug;
module_param_named(debug, dvb_usb_tbsqbox2ci_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))." 
							DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbsqbox2ci_op_rw(struct usb_device *dev, u8 request, u16 value,
				u16 index, u8 * data, u16 len, int flags)
{
	int ret;
	void *u8buf;

	unsigned int pipe = (flags == TBSQBOX_READ_MSG) ?
				usb_rcvctrlpipe(dev, 0) : usb_sndctrlpipe(dev, 0);
	u8 request_type = (flags == TBSQBOX_READ_MSG) ? USB_DIR_IN : USB_DIR_OUT;

	u8buf = kmalloc(len, GFP_KERNEL);
	if (!u8buf)
		return -ENOMEM;

	if (flags == TBSQBOX_WRITE_MSG)
		memcpy(u8buf, data, len);
	ret = usb_control_msg(dev, pipe, request, request_type | USB_TYPE_VENDOR,
				value, index , u8buf, len, 2000);

	if (flags == TBSQBOX_READ_MSG)
		memcpy(data, u8buf, len);
	kfree(u8buf);
	return ret;
}

static int tbsqbox2ci_read_attribute_mem(struct dvb_ca_en50221 *ca,
                                                	int slot, int address)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbsqbox2ci_state *state = (struct tbsqbox2ci_state *)d->priv;
	u8 buf[4], rbuf[3];
	int ret;

	if (0 != slot)
		return -EINVAL;

	buf[0] = 1;
	buf[1] = 0;
	buf[2] = (address >> 8) & 0x0f;
	buf[3] = address;

	//msleep(10);

	mutex_lock(&state->ca_mutex);

	ret = tbsqbox2ci_op_rw(d->udev, 0xa4, 0, 0,
						buf, 4, TBSQBOX_WRITE_MSG);

	//msleep(1);

	ret = tbsqbox2ci_op_rw(d->udev, 0xa5, 0, 0,
						rbuf, 1, TBSQBOX_READ_MSG);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return rbuf[0];
}

static int tbsqbox2ci_write_attribute_mem(struct dvb_ca_en50221 *ca,
						int slot, int address, u8 value)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbsqbox2ci_state *state = (struct tbsqbox2ci_state *)d->priv;
	u8 buf[5];//, rbuf[1];
	int ret;

	if (0 != slot)
		return -EINVAL;

	buf[0] = 1;
	buf[1] = 0;
	buf[2] = (address >> 8) & 0x0f;
	buf[3] = address;
	buf[4] = value;

	mutex_lock(&state->ca_mutex);

	ret = tbsqbox2ci_op_rw(d->udev, 0xa2, 0, 0,
						buf, 5, TBSQBOX_WRITE_MSG);

	//msleep(1);

	//ret = tbsqbox2ci_op_rw(d->udev, 0xa5, 0, 0,
	//					rbuf, 1, TBSQBOX_READ_MSG);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return 0;
}

static int tbsqbox2ci_read_cam_control(struct dvb_ca_en50221 *ca, int slot, 
								u8 address)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbsqbox2ci_state *state = (struct tbsqbox2ci_state *)d->priv;
	u8 buf[4], rbuf[1];
	int ret;

	if (0 != slot)
		return -EINVAL;

	buf[0] = 1;
	buf[1] = 1;
	buf[2] = (address >> 8) & 0x0f;
	buf[3] = address;

	mutex_lock(&state->ca_mutex);

	ret = tbsqbox2ci_op_rw(d->udev, 0xa4, 0, 0,
						buf, 4, TBSQBOX_WRITE_MSG);

	//msleep(10);

	ret = tbsqbox2ci_op_rw(d->udev, 0xa5, 0, 0,
						rbuf, 1, TBSQBOX_READ_MSG);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return rbuf[0];
}

static int tbsqbox2ci_write_cam_control(struct dvb_ca_en50221 *ca, int slot, 
							u8 address, u8 value)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbsqbox2ci_state *state = (struct tbsqbox2ci_state *)d->priv;
	u8 buf[5];//, rbuf[1];
	int ret;

	if (0 != slot)
		return -EINVAL;

	buf[0] = 1;
	buf[1] = 1;
	buf[2] = (address >> 8) & 0x0f;
	buf[3] = address;
	buf[4] = value;

	mutex_lock(&state->ca_mutex);

	ret = tbsqbox2ci_op_rw(d->udev, 0xa2, 0, 0,
						buf, 5, TBSQBOX_WRITE_MSG);

	//msleep(1);

	//ret = tbsqbox2ci_op_rw(d->udev, 0xa5, 0, 0,
	//					rbuf, 1, TBSQBOX_READ_MSG);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return 0;
}

static int tbsqbox2ci_set_video_port(struct dvb_ca_en50221 *ca, 
							int slot, int enable)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbsqbox2ci_state *state = (struct tbsqbox2ci_state *)d->priv;
	u8 buf[2];
	int ret;

	if (0 != slot)
		return -EINVAL;

	buf[0] = 2;
	buf[1] = enable;

	mutex_lock(&state->ca_mutex);

	ret = tbsqbox2ci_op_rw(d->udev, 0xa6, 0, 0,
						buf, 2, TBSQBOX_WRITE_MSG);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	if (enable != buf[1]) {
		err("CI not %sabled.", enable ? "en" : "dis");
		return -EIO;
	}

	info("CI %sabled.", enable ? "en" : "dis");
	return 0;
}

static int tbsqbox2ci_slot_shutdown(struct dvb_ca_en50221 *ca, int slot)
{
	return tbsqbox2ci_set_video_port(ca, slot, /* enable */ 0);
}

static int tbsqbox2ci_slot_ts_enable(struct dvb_ca_en50221 *ca, int slot)
{
	return tbsqbox2ci_set_video_port(ca, slot, /* enable */ 1);
}

static int tbsqbox2ci_slot_reset(struct dvb_ca_en50221 *ca, int slot)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbsqbox2ci_state *state = (struct tbsqbox2ci_state *)d->priv;
	u8 buf[2];
	int ret;

	if (0 != slot) {
		return -EINVAL;
	}

	buf[0] = 1;
	buf[1] = 0;

	mutex_lock (&state->ca_mutex);

	ret = tbsqbox2ci_op_rw(d->udev, 0xa6, 0, 0,
						buf, 2, TBSQBOX_WRITE_MSG);

	msleep (5);

	buf[1] = 1;

	ret = tbsqbox2ci_op_rw(d->udev, 0xa6, 0, 0,
						buf, 2, TBSQBOX_WRITE_MSG);

	msleep (1400);

	mutex_unlock (&state->ca_mutex);

	if (ret < 0)
		return ret;

	return 0;
}

static int tbsqbox2ci_poll_slot_status(struct dvb_ca_en50221 *ca,
							int slot, int open)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbsqbox2ci_state *state = (struct tbsqbox2ci_state *)d->priv;
	u8 buf[3];

	if (0 != slot)
		return -EINVAL;

	mutex_lock(&state->ca_mutex);

	tbsqbox2ci_op_rw(d->udev, 0xa8, 0, 0,
					buf, 3, TBSQBOX_READ_MSG);

	mutex_unlock(&state->ca_mutex);

	if ((1 == buf[2]) && (1 == buf[1]) && (0xa9 == buf[0])) {
				return (DVB_CA_EN50221_POLL_CAM_PRESENT |
						DVB_CA_EN50221_POLL_CAM_READY);
	} else {
		return 0;
	}
}

static void tbsqbox2ci_uninit(struct dvb_usb_device *d)
{
	struct tbsqbox2ci_state *state;

	if (NULL == d)
		return;

	state = (struct tbsqbox2ci_state *)d->priv;
	if (NULL == state)
		return;

	if (NULL == state->ca.data)
		return;

	/* Error ignored. */
	tbsqbox2ci_set_video_port(&state->ca, /* slot */ 0, /* enable */ 0);

	dvb_ca_en50221_release(&state->ca);

	memset(&state->ca, 0, sizeof(state->ca));
}

static int tbsqbox2ci_init(struct dvb_usb_adapter *a)
{

	struct dvb_usb_device *d = a->dev;
	struct tbsqbox2ci_state *state = (struct tbsqbox2ci_state *)d->priv;
	int ret;

	state->ca.owner = THIS_MODULE;
	state->ca.read_attribute_mem = tbsqbox2ci_read_attribute_mem;
	state->ca.write_attribute_mem = tbsqbox2ci_write_attribute_mem;
	state->ca.read_cam_control = tbsqbox2ci_read_cam_control;
	state->ca.write_cam_control = tbsqbox2ci_write_cam_control;
	state->ca.slot_reset = tbsqbox2ci_slot_reset;
	state->ca.slot_shutdown = tbsqbox2ci_slot_shutdown;
	state->ca.slot_ts_enable = tbsqbox2ci_slot_ts_enable;
	state->ca.poll_slot_status = tbsqbox2ci_poll_slot_status;
	state->ca.data = d;

	ret = dvb_ca_en50221_init (&a->dvb_adap, &state->ca,
						/* flags */ 0, /* n_slots */ 1);

	if (0 != ret) {
		err ("Cannot initialize CI: Error %d.", ret);
		memset (&state->ca, 0, sizeof (state->ca));
		return ret;
	}

	info ("CI initialized.");

	ret = tbsqbox2ci_poll_slot_status(&state->ca, 0, 0);
	if (0 == ret)
		tbsqbox2ci_set_video_port(&state->ca, /* slot */ 0, /* enable */ 0);

	return 0;
}

/* I2C */
static int tbsqbox2ci_i2c_transfer(struct i2c_adapter *adap, 
					struct i2c_msg msg[], int num)
{
	struct dvb_usb_device *d = i2c_get_adapdata(adap);
	struct tbsqbox2ci_state *state = (struct tbsqbox2ci_state *)d->priv;
	int i = 0;
	u8 buf6[20];
	u8 inbuf[20];

	if (!d)
		return -ENODEV;

	mutex_lock(&state->ca_mutex);

	if (mutex_lock_interruptible(&d->i2c_mutex) < 0)
		return -EAGAIN;

	switch (num) {
	case 2:
		buf6[0]=msg[1].len;//lenth
		buf6[1]=msg[0].addr<<1;//demod addr
		//register
		buf6[2] = msg[0].buf[0];
		buf6[3] = msg[0].buf[1];

		tbsqbox2ci_op_rw(d->udev, 0x92, 0, 0,
					buf6, 4, TBSQBOX_WRITE_MSG);
		//msleep(5);
		tbsqbox2ci_op_rw(d->udev, 0x91, 0, 0,
					inbuf, msg[1].len, TBSQBOX_READ_MSG);
		memcpy(msg[1].buf, inbuf, msg[1].len);
		break;
	case 1:
		switch (msg[0].addr) {
		case 0x6a:
		case 0x61:
		case 0x60:
			if (msg[0].flags == 0) {
				buf6[0] = msg[0].len+1;//lenth
				buf6[1] = msg[0].addr<<1;//addr
				for(i=0;i<msg[0].len;i++) {
					buf6[2+i] = msg[0].buf[i];//register
				}
				tbsqbox2ci_op_rw(d->udev, 0x80, 0, 0,
					buf6, msg[0].len+2, TBSQBOX_WRITE_MSG);
			} else {
				buf6[0] = msg[0].len;//length
				buf6[1] = msg[0].addr<<1;//addr
				buf6[2] = 0x00;
				tbsqbox2ci_op_rw(d->udev, 0x90, 0, 0,
						buf6, 3, TBSQBOX_WRITE_MSG);
				//msleep(5);
				tbsqbox2ci_op_rw(d->udev, 0x91, 0, 0,
					inbuf, buf6[0], TBSQBOX_READ_MSG);
				memcpy(msg[0].buf, inbuf, msg[0].len);
			}
			//msleep(3);
			break;
		case (TBSQBOX_RC_QUERY):
			tbsqbox2ci_op_rw(d->udev, 0xb8, 0, 0,
					buf6, 4, TBSQBOX_READ_MSG);
			msg[0].buf[0] = buf6[2];
			msg[0].buf[1] = buf6[3];
			//msleep(3);
			//info("TBSQBOX_RC_QUERY %x %x %x %x\n",
			//		buf6[0],buf6[1],buf6[2],buf6[3]);
			break;
		case (TBSQBOX_VOLTAGE_CTRL):
			buf6[0] = 3;
			buf6[1] = msg[0].buf[0];
			tbsqbox2ci_op_rw(d->udev, 0x8a, 0, 0,
					buf6, 2, TBSQBOX_WRITE_MSG);
			break;
		case (TBSQBOX_LED_CTRL):
			buf6[0] = 5;
			buf6[1] = msg[0].buf[0];
			tbsqbox2ci_op_rw(d->udev, 0x8a, 0, 0,
					buf6, 2, TBSQBOX_WRITE_MSG);
			break;
		}

		break;
	}

	mutex_unlock(&d->i2c_mutex);
	mutex_unlock(&state->ca_mutex);
	return num;
}

static u32 tbsqbox2ci_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}

static void tbsqbox2ci_led_ctrl(struct dvb_frontend *fe, int offon)
{
	static u8 led_off[] = { 0 };
	static u8 led_on[] = { 1 };
	struct i2c_msg msg = {
		.addr = TBSQBOX_LED_CTRL,
		.flags = 0,
		.buf = led_off,
		.len = 1
	};
	struct dvb_usb_adapter *udev_adap =
		(struct dvb_usb_adapter *)(fe->dvb->priv);

	if (offon)
		msg.buf = led_on;
	i2c_transfer(&udev_adap->dev->i2c_adap, &msg, 1);
}

static struct stv090x_config earda_config = {
	.device         = STV0903,
	.demod_mode     = STV090x_SINGLE,
	.clk_mode       = STV090x_CLK_EXT,

	.xtal           = 27000000,
	.address        = 0x6a,

	.ts1_mode       = STV090x_TSMODE_DVBCI,
	.ts2_mode       = STV090x_TSMODE_SERIAL_CONTINUOUS,
	
	.repeater_level         = STV090x_RPTLEVEL_16,

	.tuner_get_frequency    = stb6100_get_frequency,
	.tuner_set_frequency    = stb6100_set_frequency,
	.tuner_set_bandwidth    = stb6100_set_bandwidth,
	.tuner_get_bandwidth    = stb6100_get_bandwidth,

	.set_lock_led = tbsqbox2ci_led_ctrl,
};

static struct stb6100_config qbox2_stb6100_config = {
	.tuner_address  = 0x60,
	.refclock       = 27000000,
};

static struct i2c_algorithm tbsqbox2ci_i2c_algo = {
	.master_xfer = tbsqbox2ci_i2c_transfer,
	.functionality = tbsqbox2ci_i2c_func,
};

static int tbsqbox2ci_earda_tuner_attach(struct dvb_usb_adapter *adap)
{
	if (!dvb_attach(stb6100_attach, adap->fe_adap->fe, &qbox2_stb6100_config,
		&adap->dev->i2c_adap))
		return -EIO;

	return 0;
}
static int tbsqbox2ci_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{
	int i,ret;
	u8 ibuf[3] = {0, 0,0};
	u8 eeprom[256], eepromline[16];

	for (i = 0; i < 256; i++) {
		ibuf[0]=1;//lenth
		ibuf[1]=0xa0;//eeprom addr
		ibuf[2]=i;//register
		ret = tbsqbox2ci_op_rw(d->udev, 0x90, 0, 0,
					ibuf, 3, TBSQBOX_WRITE_MSG);
		ret = tbsqbox2ci_op_rw(d->udev, 0x91, 0, 0,
					ibuf, 1, TBSQBOX_READ_MSG);
			if (ret < 0) {
				err("read eeprom failed.");
				return -1;
			} else {
				eepromline[i%16] = ibuf[0];
				eeprom[i] = ibuf[0];
			}
			
			if ((i % 16) == 15) {
				deb_xfer("%02x: ", i - 15);
				debug_dump(eepromline, 16, deb_xfer);
			}
	}
	memcpy(mac, eeprom + 16, 6);
	return 0;
};

static int tbsqbox2ci_set_voltage(struct dvb_frontend *fe, 
						enum fe_sec_voltage voltage)
{
	static u8 command_13v[1] = {0x00};
	static u8 command_18v[1] = {0x01};
	struct i2c_msg msg[] = {
		{.addr = TBSQBOX_VOLTAGE_CTRL, .flags = 0,
			.buf = command_13v, .len = 1},
	};
	
	struct dvb_usb_adapter *udev_adap =
		(struct dvb_usb_adapter *)(fe->dvb->priv);
	if (voltage == SEC_VOLTAGE_18)
		msg[0].buf = command_18v;
	//info("tbsqbox2ci_set_voltage %d",voltage);
	i2c_transfer(&udev_adap->dev->i2c_adap, msg, 1);
	return 0;
}

static struct dvb_usb_device_properties tbsqbox2ci_properties;

static int tbsqbox2ci_frontend_attach(struct dvb_usb_adapter *d)
{
	struct dvb_usb_device *u = d->dev;
	struct tbsqbox2ci_state *state = (struct tbsqbox2ci_state *)u->priv;
	u8 buf[20];

	mutex_init(&state->ca_mutex);

	if (tbsqbox2ci_properties.adapter->fe->tuner_attach == &tbsqbox2ci_earda_tuner_attach) {
		d->fe_adap->fe = dvb_attach(stv090x_attach, &earda_config,
				&u->i2c_adap, STV090x_DEMODULATOR_0);
		if (d->fe_adap->fe != NULL) {
			d->fe_adap->fe->ops.set_voltage = tbsqbox2ci_set_voltage;

			buf[0] = 7;
			buf[1] = 1;
			tbsqbox2ci_op_rw(u->udev, 0x8a, 0, 0,
					buf, 2, TBSQBOX_WRITE_MSG);

			buf[0] = 1;
			buf[1] = 1;
			tbsqbox2ci_op_rw(u->udev, 0x8a, 0, 0,
					buf, 2, TBSQBOX_WRITE_MSG);
			
			buf[0] = 6;
			buf[1] = 1;
			tbsqbox2ci_op_rw(u->udev, 0x8a, 0, 0,
					buf, 2, TBSQBOX_WRITE_MSG);

			tbsqbox2ci_init(d);

			strscpy(d->fe_adap->fe->ops.info.name,u->props.devices[0].name,52);
			return 0;
		}
	}

	return -EIO;
}

static void tbsqbox2ci2_usb_disconnect (struct usb_interface * intf)
{
	struct dvb_usb_device *d = usb_get_intfdata (intf);
	
	tbsqbox2ci_uninit (d);
	dvb_usb_device_exit (intf);
}

static int tbsqbox2ci_rc_query(struct dvb_usb_device *d)
{
	u8 key[2];
	struct i2c_msg msg = {
		.addr = TBSQBOX_RC_QUERY,
		.flags = I2C_M_RD,
		.buf = key,
		.len = 2
	};

	if (d->props.i2c_algo->master_xfer(&d->i2c_adap, &msg, 1) == 1) {
		if (key[1] != 0xff) {
			deb_xfer("RC code: 0x%02X !\n", key[1]);
			rc_keydown(d->rc_dev, RC_PROTO_UNKNOWN, key[1],
				   0);
		}
	}

	return 0;
}

static struct usb_device_id tbsqbox2ci_table[] = {
	{USB_DEVICE(0x734c, 0x5980)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbsqbox2ci_table);

static int tbsqbox2ci_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	switch (dev->descriptor.idProduct) {
	case 0x5980:
		ret = request_firmware(&fw, tbsqbox2ci_properties.firmware, &dev->dev);
		if (ret != 0) {
			err("did not find the firmware file. (%s) "
			"Please see linux/Documentation/dvb/ for more details "
			"on firmware-problems.", tbsqbox2ci_properties.firmware);
			return ret;
		}
		break;
	default:
		fw = frmwr;
		break;
	}
	info("start downloading TBSQBOX2CI firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbsqbox2ci_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBSQBOX_WRITE_MSG);
	tbsqbox2ci_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBSQBOX_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbsqbox2ci_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBSQBOX_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret || tbsqbox2ci_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBSQBOX_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret || tbsqbox2ci_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBSQBOX_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	return ret;
}

static struct dvb_usb_device_properties tbsqbox2ci_properties = {
	.caps = DVB_USB_IS_AN_I2C_ADAPTER,
	.usb_ctrl = DEVICE_SPECIFIC,
	.firmware = "dvb-usb-tbsqbox-id5980.fw",
	.size_of_priv = sizeof(struct tbsqbox2ci_state),
	.no_reconnect = 1,

	.i2c_algo = &tbsqbox2ci_i2c_algo,
	.rc.core = {
		.rc_interval = 150,
		.rc_codes = RC_MAP_TBS_NEC,
		.module_name = KBUILD_MODNAME,
		.allowed_protos   = RC_PROTO_BIT_NEC,
		.rc_query = tbsqbox2ci_rc_query,
	},

	.generic_bulk_ctrl_endpoint = 0x81,
	/* parameter for the MPEG2-data transfer */
	.num_adapters = 1,
	.download_firmware = tbsqbox2ci_load_firmware,
	.read_mac_address = tbsqbox2ci_read_mac_address,
	.adapter = {{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbsqbox2ci_frontend_attach,
			.streaming_ctrl = NULL,
			.tuner_attach = tbsqbox2ci_earda_tuner_attach,
			.stream = {
				.type = USB_BULK,
				.count = 8,
				.endpoint = 0x82,
				.u = {
					.bulk = {
						.buffersize = 4096,
					}
				}
			},
		} },
	} },

	.num_device_descs = 1,
	.devices = {
		{"TurboSight TBS QBOX2-CI DVB-S/S2",
			{&tbsqbox2ci_table[0], NULL},
			{NULL},
		}
	}
};

static int tbsqbox2ci_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	if (0 == dvb_usb_device_init(intf, &tbsqbox2ci_properties,
			THIS_MODULE, NULL, adapter_nr)) {
		return 0;
	}
	return -ENODEV;
}

static struct usb_driver tbsqbox2ci_driver = {
	.name = "tbsqbox2ci",
	.probe = tbsqbox2ci_probe,
	.disconnect = tbsqbox2ci2_usb_disconnect,
	.id_table = tbsqbox2ci_table,
};

static int __init tbsqbox2ci_module_init(void)
{
	int ret =  usb_register(&tbsqbox2ci_driver);
	if (ret)
		err("usb_register failed. Error number %d", ret);

	return ret;
}

static void __exit tbsqbox2ci_module_exit(void)
{
	usb_deregister(&tbsqbox2ci_driver);
}

module_init(tbsqbox2ci_module_init);
module_exit(tbsqbox2ci_module_exit);

MODULE_AUTHOR("Konstantin Dimitrov <kosio.dimitrov@gmail.com>");
MODULE_DESCRIPTION("TurboSight (TBS) Qbox DVB-S2 CI driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
