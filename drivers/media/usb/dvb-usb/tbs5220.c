/*
 * TurboSight TBS 5220  driver
 *
 * Copyright (c) 2013 Konstantin Dimitrov <kosio.dimitrov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, version 2.
 *
 */

#include <linux/version.h>
#include "tbs5220.h"
#include "si2168.h"
#include "si2157.h"

#define TBS5220_READ_MSG 0
#define TBS5220_WRITE_MSG 1

#define TBS5220_RC_QUERY (0x1a00)

struct tbs5220_state {
	struct i2c_client *i2c_client_demod;
	struct i2c_client *i2c_client_tuner; 
};

/* debug */
static int dvb_usb_tbs5220_debug;
module_param_named(debug, dvb_usb_tbs5220_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))." 
							DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbs5220_op_rw(struct usb_device *dev, u8 request, u16 value,
				u16 index, u8 * data, u16 len, int flags)
{
	int ret;
	void *u8buf;

	unsigned int pipe = (flags == TBS5220_READ_MSG) ?
			usb_rcvctrlpipe(dev, 0) : usb_sndctrlpipe(dev, 0);
	u8 request_type = (flags == TBS5220_READ_MSG) ? USB_DIR_IN : USB_DIR_OUT;
	u8buf = kmalloc(len, GFP_KERNEL);
	if (!u8buf)
		return -ENOMEM;

	if (flags == TBS5220_WRITE_MSG)
		memcpy(u8buf, data, len);
	ret = usb_control_msg(dev, pipe, request, request_type | USB_TYPE_VENDOR,
				value, index , u8buf, len, 2000);

	if (flags == TBS5220_READ_MSG)
		memcpy(data, u8buf, len);
	kfree(u8buf);
	return ret;
}

/* I2C */
static int tbs5220_i2c_transfer(struct i2c_adapter *adap, 
					struct i2c_msg msg[], int num)
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

		tbs5220_op_rw(d->udev, 0x90, 0, 0,
					buf6, 3, TBS5220_WRITE_MSG);
		//msleep(5);
		tbs5220_op_rw(d->udev, 0x91, 0, 0,
					inbuf, buf6[0], TBS5220_READ_MSG);
		memcpy(msg[1].buf, inbuf, msg[1].len);
		break;
	case 1:
		switch (msg[0].addr) {
		case 0x64:
		case 0x60:
			if (msg[0].flags == 0) {
				buf6[0] = msg[0].len+1;//lenth
				buf6[1] = msg[0].addr<<1;//addr
				for(i=0;i<msg[0].len;i++) {
					buf6[2+i] = msg[0].buf[i];//register
				}
				tbs5220_op_rw(d->udev, 0x80, 0, 0,
					buf6, msg[0].len+2, TBS5220_WRITE_MSG);
			} else {
				buf6[0] = msg[0].len;//length
				buf6[1] = (msg[0].addr<<1) | 0x01;//addr
				tbs5220_op_rw(d->udev, 0x93, 0, 0,
						buf6, 2, TBS5220_WRITE_MSG);
				//msleep(5);
				tbs5220_op_rw(d->udev, 0x91, 0, 0,
					inbuf, buf6[0], TBS5220_READ_MSG);
				memcpy(msg[0].buf, inbuf, msg[0].len);
			}
			//msleep(3);
			break;
		case (TBS5220_RC_QUERY):
			tbs5220_op_rw(d->udev, 0xb8, 0, 0,
					buf6, 4, TBS5220_READ_MSG);
			msg[0].buf[0] = buf6[2];
			msg[0].buf[1] = buf6[3];
			//msleep(3);
			//info("TBS5220_RC_QUERY %x %x %x %x\n",
			//		buf6[0],buf6[1],buf6[2],buf6[3]);
			break;
		}

		break;
	}

	mutex_unlock(&d->i2c_mutex);
	return num;
}

static u32 tbs5220_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}

static struct i2c_algorithm tbs5220_i2c_algo = {
	.master_xfer = tbs5220_i2c_transfer,
	.functionality = tbs5220_i2c_func,
};

static int tbs5220_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{
	int i,ret;
	u8 ibuf[3] = {0, 0,0};
	u8 eeprom[256], eepromline[16];

	for (i = 0; i < 256; i++) {
		ibuf[0]=1;//lenth
		ibuf[1]=0xa0;//eeprom addr
		ibuf[2]=i;//register
		ret = tbs5220_op_rw(d->udev, 0x90, 0, 0,
					ibuf, 3, TBS5220_WRITE_MSG);
		ret = tbs5220_op_rw(d->udev, 0x91, 0, 0,
					ibuf, 1, TBS5220_READ_MSG);
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

static struct dvb_usb_device_properties tbs5220_properties;

static int tbs5220_frontend_attach(struct dvb_usb_adapter *adap)
{
	struct dvb_usb_device *d = adap->dev;
	struct tbs5220_state *st = d->priv;
	struct i2c_adapter *adapter;
	struct i2c_client *client_demod;
	struct i2c_client *client_tuner;
	struct i2c_board_info info;
	struct si2168_config si2168_config;
	struct si2157_config si2157_config;
	u8 buf[20];

	/* attach frontend */
	memset(&si2168_config, 0, sizeof(si2168_config));
	si2168_config.i2c_adapter = &adapter;
	si2168_config.fe = &adap->fe_adap[0].fe;
	si2168_config.ts_mode = SI2168_TS_PARALLEL;
	si2168_config.ts_clock_gapped = true;
	memset(&info, 0, sizeof(struct i2c_board_info));
	strlcpy(info.type, "si2168", I2C_NAME_SIZE);
	info.addr = 0x64;
	info.platform_data = &si2168_config;
	request_module(info.type);
	client_demod = i2c_new_client_device(&d->i2c_adap, &info);
	if (!i2c_client_has_driver(client_demod))
		return -ENODEV;

	if (!try_module_get(client_demod->dev.driver->owner)) {
		i2c_unregister_device(client_demod);
		return -ENODEV;
	}

	/* attach tuner */
	memset(&si2157_config, 0, sizeof(si2157_config));
	si2157_config.fe = adap->fe_adap[0].fe;
	si2157_config.if_port = 1;
	memset(&info, 0, sizeof(struct i2c_board_info));
	strlcpy(info.type, "si2157", I2C_NAME_SIZE);
	info.addr = 0x60;
	info.platform_data = &si2157_config;
	request_module(info.type);
	client_tuner = i2c_new_client_device(adapter, &info);
	if (!i2c_client_has_driver(client_tuner)) {
		module_put(client_demod->dev.driver->owner);
		i2c_unregister_device(client_demod);
		return -ENODEV;
	}
	if (!try_module_get(client_tuner->dev.driver->owner)) {
		i2c_unregister_device(client_tuner);
		module_put(client_demod->dev.driver->owner);
		i2c_unregister_device(client_demod);
		return -ENODEV;
	}

	st->i2c_client_demod = client_demod;
	st->i2c_client_tuner = client_tuner;

	buf[0] = 0;
	buf[1] = 0;
	tbs5220_op_rw(d->udev, 0xb7, 0, 0,
			buf, 2, TBS5220_WRITE_MSG);
	buf[0] = 8;
	buf[1] = 1;
	tbs5220_op_rw(d->udev, 0x8a, 0, 0,
			buf, 2, TBS5220_WRITE_MSG);

	buf[0] = 7;
	buf[1] = 1;
	tbs5220_op_rw(d->udev, 0x8a, 0, 0,
			buf, 2, TBS5220_WRITE_MSG);

	buf[0] = 6;
	buf[1] = 1;
	tbs5220_op_rw(d->udev, 0x8a, 0, 0,
		buf, 2, TBS5220_WRITE_MSG);

	strlcpy(adap->fe_adap->fe->ops.info.name,d->props.devices[0].name,52);

	return 0;
}

static int tbs5220_rc_query(struct dvb_usb_device *d)
{
	u8 key[2];
	struct i2c_msg msg = {
		.addr = TBS5220_RC_QUERY,
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

static struct usb_device_id tbs5220_table[] = {
	{USB_DEVICE(0x734c, 0x5220)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbs5220_table);

static int tbs5220_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	switch (dev->descriptor.idProduct) {
	case 0x5220:
		ret = request_firmware(&fw, tbs5220_properties.firmware, &dev->dev);
		if (ret != 0) {
			err("did not find the firmware file. (%s) "
			"Please see linux/Documentation/dvb/ for more details "
			"on firmware-problems.", tbs5220_properties.firmware);
			return ret;
		}
		break;
	default:
		fw = frmwr;
		break;
	}
	info("start downloading TBS5220 firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbs5220_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBS5220_WRITE_MSG);
	tbs5220_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBS5220_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbs5220_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBS5220_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret || tbs5220_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBS5220_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret || tbs5220_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBS5220_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	return ret;
}

static struct dvb_usb_device_properties tbs5220_properties = {
	.caps = DVB_USB_IS_AN_I2C_ADAPTER,
	.usb_ctrl = DEVICE_SPECIFIC,
	.firmware = "dvb-usb-tbsqbox-id5220.fw",
	.size_of_priv = sizeof(struct tbs5220_state),
	.no_reconnect = 1,

	.i2c_algo = &tbs5220_i2c_algo,
	.rc.core = {
		.rc_interval = 150,
		.rc_codes = RC_MAP_TBS_NEC,
		.module_name = KBUILD_MODNAME,
		.allowed_protos   = RC_PROTO_BIT_NEC,
		.rc_query = tbs5220_rc_query,
	},

	.generic_bulk_ctrl_endpoint = 0x81,
	/* parameter for the MPEG2-data transfer */
	.num_adapters = 1,
	.download_firmware = tbs5220_load_firmware,
	.read_mac_address = tbs5220_read_mac_address,
	.adapter = {{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbs5220_frontend_attach,
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
		{"TurboSight TBS 5220 DVB-T/T2/C",
			{&tbs5220_table[0], NULL},
			{NULL},
		}
	}
};

static int tbs5220_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	if (0 == dvb_usb_device_init(intf, &tbs5220_properties,
			THIS_MODULE, NULL, adapter_nr)) {
		return 0;
	}
	return -ENODEV;
}

static void tbs5220_disconnect(struct usb_interface *intf)
{
#if 0
	struct dvb_usb_device *d = usb_get_intfdata(intf);
	struct tbs5220_state *st = d->priv;
	struct i2c_client *client;

	/* remove I2C client for tuner */
	client = st->i2c_client_tuner;
	if (client) {
		module_put(client->dev.driver->owner);
		i2c_unregister_device(client);
	}

	/* remove I2C client for demodulator */
	client = st->i2c_client_demod;
	if (client) {
		module_put(client->dev.driver->owner);
		i2c_unregister_device(client);
	}
#endif
	dvb_usb_device_exit(intf);
}

static struct usb_driver tbs5220_driver = {
	.name = "tbs5220",
	.probe = tbs5220_probe,
	.disconnect = tbs5220_disconnect,
	.id_table = tbs5220_table,
};

static int __init tbs5220_module_init(void)
{
	int ret =  usb_register(&tbs5220_driver);
	if (ret)
		err("usb_register failed. Error number %d", ret);

	return ret;
}

static void __exit tbs5220_module_exit(void)
{
	usb_deregister(&tbs5220_driver);
}

module_init(tbs5220_module_init);
module_exit(tbs5220_module_exit);

MODULE_AUTHOR("Konstantin Dimitrov <kosio.dimitrov@gmail.com>");
MODULE_DESCRIPTION("TurboSight TBS 5220 driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
