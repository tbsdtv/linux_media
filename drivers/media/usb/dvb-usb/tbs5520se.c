/*
 * TurboSight TBS 5520se  driver
 *
 * Copyright (c) 2017 Davin <smailedavin@hotmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, version 2.
 *
 */

#include <linux/version.h>
#include "tbs5520se.h"
#include "si2183.h"
#include "si2157.h"
#include "av201x.h"

#define TBS5520SE_READ_MSG 0
#define TBS5520SE_WRITE_MSG 1

#define TBS5520SE_RC_QUERY (0x1a00)
#define TBS5520SE_VOLTAGE_CTRL (0x1800)

struct tbs5520se_state {
	struct i2c_client *i2c_client_demod;
	struct i2c_client *i2c_client_tuner; 
	u32 last_key_pressed;
};

static struct av201x_config tbs5520se_av201x_cfg = {
	.i2c_address = 0x62,
	.id          = ID_AV2018,
	.xtal_freq   = 27000,
};

/* debug */
static int dvb_usb_tbs5520se_debug;
module_param_named(debug, dvb_usb_tbs5520se_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))." 
							DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbs5520se_op_rw(struct usb_device *dev, u8 request, u16 value,
				u16 index, u8 * data, u16 len, int flags)
{
	int ret;
	void *u8buf;

	unsigned int pipe = (flags == TBS5520SE_READ_MSG) ?
			usb_rcvctrlpipe(dev, 0) : usb_sndctrlpipe(dev, 0);
	u8 request_type = (flags == TBS5520SE_READ_MSG) ? USB_DIR_IN : USB_DIR_OUT;
	u8buf = kmalloc(len, GFP_KERNEL);
	if (!u8buf)
		return -ENOMEM;

	if (flags == TBS5520SE_WRITE_MSG)
		memcpy(u8buf, data, len);
	ret = usb_control_msg(dev, pipe, request, request_type | USB_TYPE_VENDOR,
				value, index , u8buf, len, 2000);

	if (flags == TBS5520SE_READ_MSG)
		memcpy(data, u8buf, len);
	kfree(u8buf);
	return ret;
}

/* I2C */
static int tbs5520se_i2c_transfer(struct i2c_adapter *adap, 
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

		tbs5520se_op_rw(d->udev, 0x90, 0, 0,
					buf6, 3, TBS5520SE_WRITE_MSG);
		//msleep(5);
		tbs5520se_op_rw(d->udev, 0x91, 0, 0,
					inbuf, buf6[0], TBS5520SE_READ_MSG);
		memcpy(msg[1].buf, inbuf, msg[1].len);

		break;
	case 1:
		switch (msg[0].addr) {
		case 0x67:
		case 0x62:
		case 0x61:
			if (msg[0].flags == 0) {
				buf6[0] = msg[0].len+1;//lenth
				buf6[1] = msg[0].addr<<1;//addr
				for(i=0;i<msg[0].len;i++) {
					buf6[2+i] = msg[0].buf[i];//register
				}
				tbs5520se_op_rw(d->udev, 0x80, 0, 0,
					buf6, msg[0].len+2, TBS5520SE_WRITE_MSG);
			} else {
				buf6[0] = msg[0].len;//length
				buf6[1] = (msg[0].addr<<1) | 0x01;//addr
				tbs5520se_op_rw(d->udev, 0x93, 0, 0,
						buf6, 2, TBS5520SE_WRITE_MSG);
				//msleep(5);
				tbs5520se_op_rw(d->udev, 0x91, 0, 0,
					inbuf, buf6[0], TBS5520SE_READ_MSG);
				memcpy(msg[0].buf, inbuf, msg[0].len);
			}
			//msleep(3);
		break;
		case (TBS5520SE_VOLTAGE_CTRL):
			buf6[0] = 3;
			buf6[1] = msg[0].buf[0];
			tbs5520se_op_rw(d->udev, 0x8a, 0, 0,
					buf6, 2, TBS5520SE_WRITE_MSG);
			break;
		case (TBS5520SE_RC_QUERY):
			tbs5520se_op_rw(d->udev, 0xb8, 0, 0,
					buf6, 4, TBS5520SE_READ_MSG);
			msg[0].buf[0] = buf6[2];
			msg[0].buf[1] = buf6[3];
			//msleep(3);
			//info("TBS5520SE_RC_QUERY %x %x %x %x\n",
			//		buf6[0],buf6[1],buf6[2],buf6[3]);
			break;
		}

		break;
	}

	mutex_unlock(&d->i2c_mutex);
	return num;
}

static u32 tbs5520se_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}

static struct i2c_algorithm tbs5520se_i2c_algo = {
	.master_xfer = tbs5520se_i2c_transfer,
	.functionality = tbs5520se_i2c_func,
};

static int tbs5520se_set_voltage(struct dvb_frontend *fe, 
						enum fe_sec_voltage voltage)
{
	static u8 command_13v[1] = {0x00};
	static u8 command_18v[1] = {0x01};
	struct i2c_msg msg[] = {
		{.addr = TBS5520SE_VOLTAGE_CTRL, .flags = 0,
			.buf = command_13v, .len = 1},
	};
	
	struct dvb_usb_adapter *udev_adap =
		(struct dvb_usb_adapter *)(fe->dvb->priv);
	if (voltage == SEC_VOLTAGE_18)
		msg[0].buf = command_18v;

	//info("tbs5520se_set_voltage %d",voltage);
	i2c_transfer(&udev_adap->dev->i2c_adap, msg, 1);
	
	return 0;
}

static int tbs5520se_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{
	int i,ret;
	u8 ibuf[3] = {0, 0,0};
	u8 eeprom[256], eepromline[16];

	for (i = 0; i < 256; i++) {
		ibuf[0]=1;//lenth
		ibuf[1]=0xa0;//eeprom addr
		ibuf[2]=i;//register
		ret = tbs5520se_op_rw(d->udev, 0x90, 0, 0,
					ibuf, 3, TBS5520SE_WRITE_MSG);
		ret = tbs5520se_op_rw(d->udev, 0x91, 0, 0,
					ibuf, 1, TBS5520SE_READ_MSG);
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

static struct dvb_usb_device_properties tbs5520se_properties;

static int tbs5520se_frontend_attach(struct dvb_usb_adapter *adap)
{
	struct dvb_usb_device *d = adap->dev;
	struct tbs5520se_state *st = d->priv;
	struct i2c_adapter *adapter;
	struct i2c_client *client_demod;
	struct i2c_client *client_tuner;
	struct i2c_board_info info;
	struct si2183_config si2183_config;
	struct si2157_config si2157_config;
	u8 buf[20];


	/* attach frontend */
	memset(&si2183_config,0,sizeof(si2183_config));
	si2183_config.i2c_adapter = &adapter;
	si2183_config.fe = &adap->fe_adap[0].fe;	
	si2183_config.ts_mode = SI2183_TS_PARALLEL;
	si2183_config.ts_clock_gapped = true;
	si2183_config.rf_in = 0;
	si2183_config.RF_switch = NULL;
	si2183_config.agc_mode = 0x5 ;
	memset(&info, 0, sizeof(struct i2c_board_info));
	strlcpy(info.type, "si2183", I2C_NAME_SIZE);
	info.addr = 0x67;
	info.platform_data = &si2183_config;
	request_module(info.type);
	client_demod = i2c_new_client_device(&d->i2c_adap, &info);
	if (client_demod == NULL || client_demod->dev.driver == NULL)
		return -ENODEV;

	if (!try_module_get(client_demod->dev.driver->owner)) {
		i2c_unregister_device(client_demod);
		return -ENODEV;
	}

	st->i2c_client_demod = client_demod;

	/* dvb core doesn't support 2 tuners for 1 demod so
	   we split the adapter in 2 frontends */

	adap->fe_adap[0].fe2 = &adap->fe_adap[0]._fe2;
	memcpy(adap->fe_adap[0].fe2, adap->fe_adap[0].fe, sizeof(struct dvb_frontend));

	/* terrestrial tuner */
	memset(adap->fe_adap[0].fe->ops.delsys, 0, MAX_DELSYS);
	adap->fe_adap[0].fe->ops.delsys[0] = SYS_DVBT;
	adap->fe_adap[0].fe->ops.delsys[1] = SYS_DVBT2;
	adap->fe_adap[0].fe->ops.delsys[2] = SYS_DVBC_ANNEX_A;
	adap->fe_adap[0].fe->ops.delsys[3] = SYS_ISDBT;
	adap->fe_adap[0].fe->ops.delsys[4] = SYS_DVBC_ANNEX_B;

	/* attach ter tuner */
	memset(&si2157_config, 0, sizeof(si2157_config));
	si2157_config.fe = adap->fe_adap[0].fe;
	si2157_config.if_port = 1;
	memset(&info, 0, sizeof(struct i2c_board_info));
	strlcpy(info.type, "si2157", I2C_NAME_SIZE);
	info.addr = 0x61;
	info.platform_data = &si2157_config;
	request_module(info.type);
	client_tuner = i2c_new_client_device(adapter, &info);
	if (client_tuner == NULL || client_tuner->dev.driver == NULL) {
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

	st->i2c_client_tuner = client_tuner;

	memset(adap->fe_adap[0].fe2->ops.delsys, 0, MAX_DELSYS);
	adap->fe_adap[0].fe2->ops.delsys[0] = SYS_DVBS;
	adap->fe_adap[0].fe2->ops.delsys[1] = SYS_DVBS2;
	adap->fe_adap[0].fe2->ops.delsys[2] = SYS_DSS;
	adap->fe_adap[0].fe2->id = 1;

	if (dvb_attach(av201x_attach, adap->fe_adap[0].fe2, &tbs5520se_av201x_cfg,
			adapter) == NULL) {
		return -ENODEV;
	}
	else {
		buf[0] = 1;
		buf[1] = 0;
		tbs5520se_op_rw(d->udev, 0x8a, 0, 0,
					buf, 2, TBS5520SE_WRITE_MSG);
		
		adap->fe_adap[0].fe2->ops.set_voltage = tbs5520se_set_voltage;
		
	}

	buf[0] = 0;
	buf[1] = 0;
	tbs5520se_op_rw(d->udev, 0xb7, 0, 0,
			buf, 2, TBS5520SE_WRITE_MSG);
	buf[0] = 8;
	buf[1] = 1;
	tbs5520se_op_rw(d->udev, 0x8a, 0, 0,
			buf, 2, TBS5520SE_WRITE_MSG);

	strlcpy(adap->fe_adap[0].fe->ops.info.name,d->props.devices[0].name,52);
	strcat(adap->fe_adap[0].fe->ops.info.name," DVB-T/T2/C/C2/ISDB-T");
	strlcpy(adap->fe_adap[0].fe2->ops.info.name,d->props.devices[0].name,52);
	strcat(adap->fe_adap[0].fe2->ops.info.name," DVB-S/S2/S2X");

	return 0;
}

static struct usb_device_id tbs5520se_table[] = {
	{USB_DEVICE(0x734c, 0x5521)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbs5520se_table);

static int tbs5520se_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	switch (dev->descriptor.idProduct) {
	case 0x5521:
		ret = request_firmware(&fw, tbs5520se_properties.firmware, &dev->dev);
		if (ret != 0) {
			err("did not find the firmware file. (%s) "
			"Please see linux/Documentation/dvb/ for more details "
			"on firmware-problems.", tbs5520se_properties.firmware);
			return ret;
		}
		break;
	default:
		fw = frmwr;
		break;
	}
	info("start downloading TBS5520se firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbs5520se_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBS5520SE_WRITE_MSG);
	tbs5520se_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBS5520SE_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbs5520se_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBS5520SE_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret || tbs5520se_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBS5520SE_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret || tbs5520se_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBS5520SE_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	return ret;
}

static struct dvb_usb_device_properties tbs5520se_properties = {
	.caps = DVB_USB_IS_AN_I2C_ADAPTER,
	.usb_ctrl = DEVICE_SPECIFIC,
	.firmware = "dvb-usb-id5520se.fw",
	.size_of_priv = sizeof(struct tbs5520se_state),
	.no_reconnect = 1,

	.i2c_algo = &tbs5520se_i2c_algo,

	.generic_bulk_ctrl_endpoint = 0x81,
	/* parameter for the MPEG2-data transfer */
	.num_adapters = 1,
	.download_firmware = tbs5520se_load_firmware,
	.read_mac_address = tbs5520se_read_mac_address,
	.adapter = {{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbs5520se_frontend_attach,
			.streaming_ctrl = NULL,
			.tuner_attach = NULL,
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
		},
/*			{
				.frontend_attach = tbs5520se_satfrontend_attach,
				.streaming_ctrl = NULL,
				.tuner_attach = NULL,
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
			},*/

		},
		
	}},

	.num_device_descs = 1,
	.devices = {
		{"TurboSight TBS 5520SE",
			{&tbs5520se_table[0], NULL},
			{NULL},
		}
	}
};

static int tbs5520se_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	if (0 == dvb_usb_device_init(intf, &tbs5520se_properties,
			THIS_MODULE, NULL, adapter_nr)) {
		return 0;
	}
	return -ENODEV;
}

static void tbs5520se_disconnect(struct usb_interface *intf)
{
#if 0
	struct dvb_usb_device *d = usb_get_intfdata(intf);
	struct tbs5520se_state *st = d->priv;
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

static struct usb_driver tbs5520se_driver = {
	.name = "tbs5520se",
	.probe = tbs5520se_probe,
	.disconnect = tbs5520se_disconnect,
	.id_table = tbs5520se_table,
};

static int __init tbs5520se_module_init(void)
{
	int ret =  usb_register(&tbs5520se_driver);
	if (ret)
		err("usb_register failed. Error number %d", ret);

	return ret;
}

static void __exit tbs5520se_module_exit(void)
{
	usb_deregister(&tbs5520se_driver);
}

module_init(tbs5520se_module_init);
module_exit(tbs5520se_module_exit);

MODULE_AUTHOR("Davin  <smiledavin@hotmail.com>");
MODULE_DESCRIPTION("TurboSight TBS 5520SE driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
