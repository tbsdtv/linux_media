/* DVB USB framework compliant Linux driver for the
*	TBS QBOX
*
* Copyright (C) 2008 Bob Liu (Bob@Turbosight.com)
* Igor M. Liplianin (liplianin@me.by)
*
*	This program is free software; you can redistribute it and/or modify it
*	under the terms of the GNU General Public License as published by the
*	Free Software Foundation, version 2.
*
* see Documentation/dvb/README.dvb-usb for more information
*/

/* 
* History:
*
* December 2011 Konstantin Dimitrov <kosio.dimitrov@gmail.com>
* remove QBOXS3 support
* add QBOX22 support
*/

#include <linux/version.h>
#include "tbs-qbox22.h"
#include "tas2101.h"
#include "av201x.h"

#ifndef USB_PID_TBSQBOX_1
#define USB_PID_TBSQBOX_1 0x5922
#endif

#define TBSQBOX_READ_MSG 0
#define TBSQBOX_WRITE_MSG 1

/* on my own*/
#define TBSQBOX_VOLTAGE_CTRL (0x1800)
#define TBSQBOX_RC_QUERY (0x1a00)

struct tbsqbox22_state {
	u8 initialized;
};

/* debug */
static int dvb_usb_tbsqbox22_debug;
module_param_named(debug, dvb_usb_tbsqbox22_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))." DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbsqbox22_op_rw(struct usb_device *dev, u8 request, u16 value,
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
static int tbsqbox22_i2c_transfer(struct i2c_adapter *adap, struct i2c_msg msg[],
		int num)
{
	struct dvb_usb_device *d = i2c_get_adapdata(adap);
	int i = 0;
	u8 buf[20];

	if (!d)
		return -ENODEV;
	if (mutex_lock_interruptible(&d->i2c_mutex) < 0)
		return -EAGAIN;

	switch (num) {
	case 2:
		/* read */
		buf[0] = msg[1].len;
		buf[1] = msg[0].addr << 1;
		buf[2] = msg[0].buf[0];

		tbsqbox22_op_rw(d->udev, 0x90, 0, 0,
				buf, 3, TBSQBOX_WRITE_MSG);
		msleep(5);
		tbsqbox22_op_rw(d->udev, 0x91, 0, 0,
				buf, msg[1].len, TBSQBOX_READ_MSG);
		memcpy(msg[1].buf, buf, msg[1].len);
		break;
	case 1:
		switch (msg[0].addr) {
		case 0x68:
		case 0x63:
			/* write to register */
			buf[0] = msg[0].len + 1; //lenth
			buf[1] = msg[0].addr << 1; //demod addr
			for(i=0; i < msg[0].len; i++)
				buf[2+i] = msg[0].buf[i]; //register
			tbsqbox22_op_rw(d->udev, 0x80, 0, 0,
						buf, msg[0].len+2, TBSQBOX_WRITE_MSG);
			//msleep(3);
			break;
		case (TBSQBOX_RC_QUERY):
			tbsqbox22_op_rw(d->udev, 0xb8, 0, 0,
					buf, 4, TBSQBOX_READ_MSG);
			msg[0].buf[0] = buf[2];
			msg[0].buf[1] = buf[3];
			msleep(3);
			//info("TBSQBOX_RC_QUERY %x %x %x %x\n",buf6[0],buf6[1],buf6[2],buf6[3]);
			break;
		case (TBSQBOX_VOLTAGE_CTRL):
			break;
		default:
			break;
		}

		break;
	default:
		break;
	}

	mutex_unlock(&d->i2c_mutex);
	return num;
}

static u32 tbsqbox22_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}


static struct i2c_algorithm tbsqbox22_i2c_algo = {
	.master_xfer = tbsqbox22_i2c_transfer,
	.functionality = tbsqbox22_i2c_func,
};


static int tbsqbox22_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{
	int i,ret;
	u8 buf[3];
	u8 eeprom[256], eepromline[16];

	for (i = 0; i < 256; i++) {
		buf[0] = 1; //lenth
		buf[1] = 0xa0; //eeprom addr
		buf[2] = i; //register
		ret = tbsqbox22_op_rw(d->udev, 0x90, 0, 0,
					buf, 3, TBSQBOX_WRITE_MSG);
		ret = tbsqbox22_op_rw(d->udev, 0x91, 0, 0,
					buf, 1, TBSQBOX_READ_MSG);
			if (ret < 0) {
				err("read eeprom failed");
				return -1;
			} else {
				eepromline[i % 16] = buf[0];
				eeprom[i] = buf[0];
			}
			
			if ((i % 16) == 15) {
				deb_xfer("%02x: ", i - 15);
				debug_dump(eepromline, 16, deb_xfer);
			}
	}
	memcpy(mac, eeprom + 16, 6);
	return 0;
};

static struct dvb_usb_device_properties tbsqbox22_properties;


static struct tas2101_config tbs5922_cfg = {
	.i2c_address   = 0x68,
	.id            = ID_TAS2100,
	.reset_demod   = NULL,
	.lnb_power     = NULL,
	.init          = {0xb8, 0x67, 0x45, 0x23, 0x01, 0x9a, 0x33},
	.init2         = 0,
};

static struct av201x_config tbs5922_av201x_cfg = {
	.i2c_address = 0x63,
	.id          = ID_AV2012,
	.xtal_freq   = 27000,		/* kHz */
};

static int tbsqbox22_frontend_attach(struct dvb_usb_adapter *d)
{
	struct dvb_usb_device *u = d->dev;
	u8 buf[20];

	d->fe_adap->fe = dvb_attach(tas2101_attach, &tbs5922_cfg,
				&u->i2c_adap);
	if (d->fe_adap->fe == NULL)
		goto err;

	if (dvb_attach(av201x_attach, d->fe_adap->fe, &tbs5922_av201x_cfg,
			tas2101_get_i2c_adapter(d->fe_adap->fe, 2)) == NULL) {
		dvb_frontend_detach(d->fe_adap->fe);
		d->fe_adap->fe = NULL;
		goto err;
	}

	buf[0] = 7;
	buf[1] = 1;
	tbsqbox22_op_rw(u->udev, 0x8a, 0, 0, buf, 2, TBSQBOX_WRITE_MSG);

	buf[0] = 1;
	buf[1] = 1;
	tbsqbox22_op_rw(u->udev, 0x8a, 0, 0, buf, 2, TBSQBOX_WRITE_MSG);

	buf[0] = 6;     
	buf[1] = 1;
	tbsqbox22_op_rw(u->udev, 0x8a, 0, 0, buf, 2, TBSQBOX_WRITE_MSG);
	
	strscpy(d->fe_adap->fe->ops.info.name,u->props.devices[0].name,52);

	return 0;
err:
	return -ENODEV;
}

static int tbsqbox22_rc_query(struct dvb_usb_device *d)
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

static struct usb_device_id tbsqbox22_table[] = {
	{USB_DEVICE(0x734c, 0x5922)},
	{USB_DEVICE(USB_VID_CYPRESS, USB_PID_TBSQBOX_1)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbsqbox22_table);

static int tbsqbox22_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	const char *filename = "dvb-usb-tbsqbox-id5922.fw";
	switch (dev->descriptor.idProduct) {
	case 0x5922:
		ret = request_firmware(&fw, filename, &dev->dev);
		if (ret != 0) {
			err("did not find the firmware file. (%s) "
			"Please see linux/Documentation/dvb/ for more details "
			"on firmware-problems.", filename);
			return ret;
		}
		break;
	default:
		fw = frmwr;
		break;
	}
	info("start downloading TBSQBOX firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbsqbox22_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBSQBOX_WRITE_MSG);
	tbsqbox22_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBSQBOX_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbsqbox22_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBSQBOX_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret || tbsqbox22_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBSQBOX_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret || tbsqbox22_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBSQBOX_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	return ret;
}

static struct dvb_usb_device_properties tbsqbox22_properties = {
	.caps = DVB_USB_IS_AN_I2C_ADAPTER,
	.usb_ctrl = DEVICE_SPECIFIC,
	.firmware = "dvb-usb-tbsqbox-id5922.fw",
	.size_of_priv = sizeof(struct tbsqbox22_state),
	.no_reconnect = 1,

	.i2c_algo = &tbsqbox22_i2c_algo,
	.rc.core = {
		.rc_interval = 150,
		.rc_codes = RC_MAP_TBS_NEC,
		.module_name = KBUILD_MODNAME,
		.allowed_protos   = RC_PROTO_BIT_NEC,
		.rc_query = tbsqbox22_rc_query,
	},

	.generic_bulk_ctrl_endpoint = 0x81,
	/* parameter for the MPEG2-data transfer */
	.num_adapters = 1,
	.download_firmware = tbsqbox22_load_firmware,
	.read_mac_address = tbsqbox22_read_mac_address,
	.adapter = {{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbsqbox22_frontend_attach,
			.streaming_ctrl = NULL,
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
		}},
	}},
	.num_device_descs = 1,
	.devices = {
		{"TurboSight QBOX3 DVB-S/S2",
			{&tbsqbox22_table[0], NULL},
			{NULL},
		}
	}
};

static int tbsqbox22_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	if (0 == dvb_usb_device_init(intf, &tbsqbox22_properties,
			THIS_MODULE, NULL, adapter_nr)) {
		return 0;
	}
	return -ENODEV;
}

static struct usb_driver tbsqbox22_driver = {
	.name = "tbsqbox22",
	.probe = tbsqbox22_probe,
	.disconnect = dvb_usb_device_exit,
	.id_table = tbsqbox22_table,
};

static int __init tbsqbox22_module_init(void)
{
	int ret =  usb_register(&tbsqbox22_driver);
	if (ret)
		err("usb_register failed. Error number %d", ret);

	return ret;
}

static void __exit tbsqbox22_module_exit(void)
{
	usb_deregister(&tbsqbox22_driver);
}

module_init(tbsqbox22_module_init);
module_exit(tbsqbox22_module_exit);

MODULE_AUTHOR("Bob Liu <Bob@turbosight.com>");
MODULE_DESCRIPTION("Driver for TBS QBOX22");
MODULE_VERSION("0.2");
MODULE_LICENSE("GPL");
