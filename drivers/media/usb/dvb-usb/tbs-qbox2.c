/* DVB USB framework compliant Linux driver for the
*	TBS QBOX
*
* Copyright (C) 2008 Bob Liu (Bob@Turbosight.com)
* Igor M. Liplianin (liplianin@me.by)
*
* Konstantin Dimitrov <kosio.dimitrov@gmail.com>
* 	August 2009
* 	Add QBOX II STV0903 support
*
*	This program is free software; you can redistribute it and/or modify it
*	under the terms of the GNU General Public License as published by the
*	Free Software Foundation, version 2.
*
* see Documentation/dvb/README.dvb-usb for more information
*/
#include <linux/version.h>
#include "tbs-qbox2.h"
#include "stv6110x.h"
#include "stv090x.h"
#include "stb6100.h"
#include "stb6100_cfg.h"

#define TBSQBOX_READ_MSG 0
#define TBSQBOX_WRITE_MSG 1

/* on my own*/
#define TBSQBOX_VOLTAGE_CTRL (0x1800)
#define TBSQBOX_RC_QUERY (0x1a00)
#define TBSQBOX_LED_CTRL (0x1b00)

struct tbsqbox2_state {
	u8 initialized;
};

/* debug */
static int dvb_usb_tbsqbox2_debug;
module_param_named(debug, dvb_usb_tbsqbox2_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))." DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbsqbox2_op_rw(struct usb_device *dev, u8 request, u16 value,
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

/* I2C */
static int tbsqbox2_i2c_transfer(struct i2c_adapter *adap, struct i2c_msg msg[],
		int num)
{
struct dvb_usb_device *d = i2c_get_adapdata(adap);
	int i = 0;
	u8 buf6[20];
	u8 inbuf[20];

	if (!d)
		return -ENODEV;
	if (mutex_lock_interruptible(&d->i2c_mutex) < 0)
		return -EAGAIN;

	switch (num) {
	case 2:
		buf6[0]=msg[1].len;//lenth
		buf6[1]=msg[0].addr<<1;//demod addr
		//register
		buf6[2] = msg[0].buf[0];
		buf6[3] = msg[0].buf[1];

		tbsqbox2_op_rw(d->udev, 0x92, 0, 0,
					buf6, 4, TBSQBOX_WRITE_MSG);
		//msleep(5);
		tbsqbox2_op_rw(d->udev, 0x91, 0, 0,
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
				tbsqbox2_op_rw(d->udev, 0x80, 0, 0,
							buf6, msg[0].len+2, TBSQBOX_WRITE_MSG);
			} else {
				buf6[0] = msg[0].len;//length
				buf6[1] = msg[0].addr<<1;//addr
				buf6[2] = 0x00;
				tbsqbox2_op_rw(d->udev, 0x90, 0, 0,
							buf6, 3, TBSQBOX_WRITE_MSG);
				//msleep(5);
				tbsqbox2_op_rw(d->udev, 0x91, 0, 0,
							inbuf, buf6[0], TBSQBOX_READ_MSG);
				memcpy(msg[0].buf, inbuf, msg[0].len);
			}
			//msleep(3);
			break;
		case (TBSQBOX_RC_QUERY):
			tbsqbox2_op_rw(d->udev, 0xb8, 0, 0,
					buf6, 4, TBSQBOX_READ_MSG);
			msg[0].buf[0] = buf6[2];
			msg[0].buf[1] = buf6[3];
			msleep(3);
			//info("TBSQBOX_RC_QUERY %x %x %x %x\n",buf6[0],buf6[1],buf6[2],buf6[3]);
			break;
		case (TBSQBOX_VOLTAGE_CTRL):
			buf6[0] = 3;
			buf6[1] = msg[0].buf[0];
			tbsqbox2_op_rw(d->udev, 0x8a, 0, 0,
					buf6, 2, TBSQBOX_WRITE_MSG);
			break;
		case (TBSQBOX_LED_CTRL):
			buf6[0] = 5;
			buf6[1] = msg[0].buf[0];
			tbsqbox2_op_rw(d->udev, 0x8a, 0, 0,
					buf6, 2, TBSQBOX_WRITE_MSG);
			break;
		}

		break;
	}

	mutex_unlock(&d->i2c_mutex);
	return num;
}

static u32 tbsqbox2_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}

static void tbsqbox2_led_ctrl(struct dvb_frontend *fe, int offon)
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

	.set_lock_led = tbsqbox2_led_ctrl,
};

static struct stb6100_config qbox2_stb6100_config = {
	.tuner_address  = 0x60,
	.refclock       = 27000000,
};

static struct i2c_algorithm tbsqbox2_i2c_algo = {
	.master_xfer = tbsqbox2_i2c_transfer,
	.functionality = tbsqbox2_i2c_func,
};

static int tbsqbox2_earda_tuner_attach(struct dvb_usb_adapter *adap)
{
	if (!dvb_attach(stb6100_attach, adap->fe_adap->fe, &qbox2_stb6100_config,
		&adap->dev->i2c_adap))
		return -EIO;

	return 0;
}
static int tbsqbox2_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{
	int i,ret;
	u8 ibuf[3] = {0, 0,0};
	u8 eeprom[256], eepromline[16];

	for (i = 0; i < 256; i++) {
		ibuf[0]=1;//lenth
		ibuf[1]=0xa0;//eeprom addr
		ibuf[2]=i;//register
		ret = tbsqbox2_op_rw(d->udev, 0x90, 0, 0,
					ibuf, 3, TBSQBOX_WRITE_MSG);
		ret = tbsqbox2_op_rw(d->udev, 0x91, 0, 0,
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

static int tbsqbox2_set_voltage(struct dvb_frontend *fe, enum fe_sec_voltage voltage)
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
	//info("tbsqbox2_set_voltage %d",voltage);
	i2c_transfer(&udev_adap->dev->i2c_adap, msg, 1);
	return 0;
}

static struct dvb_usb_device_properties tbsqbox2_properties;

static int tbsqbox2_frontend_attach(struct dvb_usb_adapter *d)
{
	struct dvb_usb_device *u = d->dev;
	u8 buf[20];

	if (tbsqbox2_properties.adapter->fe->tuner_attach == &tbsqbox2_earda_tuner_attach) {
		d->fe_adap->fe = dvb_attach(stv090x_attach, &earda_config,
					&u->i2c_adap, STV090x_DEMODULATOR_0);
		if (d->fe_adap->fe != NULL) {
			d->fe_adap->fe->ops.set_voltage = tbsqbox2_set_voltage;

			buf[0] = 7;
			buf[1] = 1;
			tbsqbox2_op_rw(u->udev, 0x8a, 0, 0,
					buf, 2, TBSQBOX_WRITE_MSG);

			strscpy(d->fe_adap->fe->ops.info.name,u->props.devices[0].name,52);
			return 0;
		}
	}

	return -EIO;
}

static int tbsqbox2_rc_query(struct dvb_usb_device *d)
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

static struct usb_device_id tbsqbox2_table[] = {
	{USB_DEVICE(0x734c, 0x2601)},
	{USB_DEVICE(0x734c, 0x5920)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbsqbox2_table);

static int tbsqbox2_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	switch (dev->descriptor.idProduct) {
	case 0x5920:
		ret = request_firmware(&fw, tbsqbox2_properties.firmware, &dev->dev);
		if (ret != 0) {
			err("did not find the firmware file. (%s) "
			"Please see linux/Documentation/dvb/ for more details "
			"on firmware-problems.", tbsqbox2_properties.firmware);
			return ret;
		}
		break;
	default:
		fw = frmwr;
		break;
	}
	info("start downloading TBSQBOX2 firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbsqbox2_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBSQBOX_WRITE_MSG);
	tbsqbox2_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBSQBOX_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbsqbox2_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBSQBOX_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret || tbsqbox2_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBSQBOX_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret || tbsqbox2_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBSQBOX_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	return ret;
}

static struct dvb_usb_device_properties tbsqbox2_properties = {
	.caps = DVB_USB_IS_AN_I2C_ADAPTER,
	.usb_ctrl = DEVICE_SPECIFIC,
	.firmware = "dvb-usb-tbsqbox-id5920.fw",
	.size_of_priv = sizeof(struct tbsqbox2_state),
	.no_reconnect = 1,

	.i2c_algo = &tbsqbox2_i2c_algo,
	.rc.core = {
		.rc_interval = 150,
		.rc_codes = RC_MAP_TBS_NEC,
		.module_name = KBUILD_MODNAME,
		.allowed_protos   = RC_PROTO_BIT_NEC,
		.rc_query = tbsqbox2_rc_query,
	},

	.generic_bulk_ctrl_endpoint = 0x81,
	/* parameter for the MPEG2-data transfer */
	.num_adapters = 1,
	.download_firmware = tbsqbox2_load_firmware,
	.read_mac_address = tbsqbox2_read_mac_address,
	.adapter = {{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbsqbox2_frontend_attach,
			.streaming_ctrl = NULL,
			.tuner_attach = tbsqbox2_earda_tuner_attach,
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
		{"TurboSight TBS QBOX2 DVB-S/S2",
			{&tbsqbox2_table[1], NULL},
			{NULL},
		}
	}
};

static int tbsqbox2_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	if (0 == dvb_usb_device_init(intf, &tbsqbox2_properties,
			THIS_MODULE, NULL, adapter_nr)) {
		return 0;
	}
	return -ENODEV;
}

static struct usb_driver tbsqbox2_driver = {
	.name = "tbsqbox2",
	.probe = tbsqbox2_probe,
	.disconnect = dvb_usb_device_exit,
	.id_table = tbsqbox2_table,
};

static int __init tbsqbox2_module_init(void)
{
	int ret =  usb_register(&tbsqbox2_driver);
	if (ret)
		err("usb_register failed. Error number %d", ret);

	return ret;
}

static void __exit tbsqbox2_module_exit(void)
{
	usb_deregister(&tbsqbox2_driver);
}

module_init(tbsqbox2_module_init);
module_exit(tbsqbox2_module_exit);

MODULE_AUTHOR("Bob Liu <Bob@turbosight.com>");
MODULE_DESCRIPTION("Driver for TBS QBOX2 STV0903");
MODULE_VERSION("0.3");
MODULE_LICENSE("GPL");
