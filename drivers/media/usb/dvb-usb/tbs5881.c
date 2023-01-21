/*
 * TurboSight TBS 5881 CI driver
 *
 * Copyright (c) 2013 Konstantin Dimitrov <kosio.dimitrov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, version 2.
 *
 */

#include <linux/version.h>
#include "tbs5881.h"
#include "si2168.h"
#include "si2157.h"

#include <media/dvb_ca_en50221.h>

#define TBS5881_READ_MSG 0
#define TBS5881_WRITE_MSG 1

#define TBS5881_RC_QUERY (0x1a00)

struct tbs5881_state {
	struct i2c_client *i2c_client_demod;
	struct i2c_client *i2c_client_tuner;
	struct dvb_ca_en50221 ca;
	struct mutex ca_mutex;
};

/*struct tbs5881_rc_keys {
	u32 keycode;
	u32 event;
};*/

/* debug */
static int dvb_usb_tbs5881_debug;
module_param_named(debug, dvb_usb_tbs5881_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))." 
							DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbs5881_op_rw(struct usb_device *dev, u8 request, u16 value,
				u16 index, u8 * data, u16 len, int flags)
{
	int ret;
	void *u8buf;

	unsigned int pipe = (flags == TBS5881_READ_MSG) ?
			usb_rcvctrlpipe(dev, 0) : usb_sndctrlpipe(dev, 0);
	u8 request_type = (flags == TBS5881_READ_MSG) ? USB_DIR_IN : USB_DIR_OUT;
	u8buf = kmalloc(len, GFP_KERNEL);
	if (!u8buf)
		return -ENOMEM;

	if (flags == TBS5881_WRITE_MSG)
		memcpy(u8buf, data, len);
	ret = usb_control_msg(dev, pipe, request, request_type | USB_TYPE_VENDOR,
				value, index , u8buf, len, 2000);

	if (flags == TBS5881_READ_MSG)
		memcpy(data, u8buf, len);
	kfree(u8buf);
	return ret;
}

static int tbs5881_read_attribute_mem(struct dvb_ca_en50221 *ca,
                                                	int slot, int address)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbs5881_state *state = (struct tbs5881_state *)d->priv;
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

	ret = tbs5881_op_rw(d->udev, 0xa4, 0, 0,
						buf, 4, TBS5881_WRITE_MSG);

	//msleep(1);

	ret = tbs5881_op_rw(d->udev, 0xa5, 0, 0,
						rbuf, 1, TBS5881_READ_MSG);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return rbuf[0];
}

static int tbs5881_write_attribute_mem(struct dvb_ca_en50221 *ca,
						int slot, int address, u8 value)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbs5881_state *state = (struct tbs5881_state *)d->priv;
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

	ret = tbs5881_op_rw(d->udev, 0xa2, 0, 0,
						buf, 5, TBS5881_WRITE_MSG);

	//msleep(1);

	//ret = tbs5881_op_rw(d->udev, 0xa5, 0, 0,
	//					rbuf, 1, TBS5881_READ_MSG);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return 0;
}

static int tbs5881_read_cam_control(struct dvb_ca_en50221 *ca, int slot, 
								u8 address)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbs5881_state *state = (struct tbs5881_state *)d->priv;
	u8 buf[4], rbuf[1];
	int ret;

	if (0 != slot)
		return -EINVAL;

	buf[0] = 1;
	buf[1] = 1;
	buf[2] = (address >> 8) & 0x0f;
	buf[3] = address;

	mutex_lock(&state->ca_mutex);

	ret = tbs5881_op_rw(d->udev, 0xa4, 0, 0,
						buf, 4, TBS5881_WRITE_MSG);

	//msleep(10);

	ret = tbs5881_op_rw(d->udev, 0xa5, 0, 0,
						rbuf, 1, TBS5881_READ_MSG);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return rbuf[0];
}

static int tbs5881_write_cam_control(struct dvb_ca_en50221 *ca, int slot, 
							u8 address, u8 value)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbs5881_state *state = (struct tbs5881_state *)d->priv;
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

	ret = tbs5881_op_rw(d->udev, 0xa2, 0, 0,
						buf, 5, TBS5881_WRITE_MSG);

	//msleep(1);

	//ret = tbs5881_op_rw(d->udev, 0xa5, 0, 0,
	//					rbuf, 1, TBS5881_READ_MSG);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return 0;
}

static int tbs5881_set_video_port(struct dvb_ca_en50221 *ca, 
							int slot, int enable)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbs5881_state *state = (struct tbs5881_state *)d->priv;
	u8 buf[2];
	int ret;

	if (0 != slot)
		return -EINVAL;

	buf[0] = 2;
	buf[1] = enable;

	mutex_lock(&state->ca_mutex);

	ret = tbs5881_op_rw(d->udev, 0xa6, 0, 0,
						buf, 2, TBS5881_WRITE_MSG);

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

static int tbs5881_slot_shutdown(struct dvb_ca_en50221 *ca, int slot)
{
	return tbs5881_set_video_port(ca, slot, /* enable */ 0);
}

static int tbs5881_slot_ts_enable(struct dvb_ca_en50221 *ca, int slot)
{
	return tbs5881_set_video_port(ca, slot, /* enable */ 1);
}

static int tbs5881_slot_reset(struct dvb_ca_en50221 *ca, int slot)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbs5881_state *state = (struct tbs5881_state *)d->priv;
	u8 buf[2];
	int ret;

	if (0 != slot) {
		return -EINVAL;
	}

	buf[0] = 1;
	buf[1] = 0;

	mutex_lock (&state->ca_mutex);

	ret = tbs5881_op_rw(d->udev, 0xa6, 0, 0,
						buf, 2, TBS5881_WRITE_MSG);

	msleep (5);

	buf[1] = 1;

	ret = tbs5881_op_rw(d->udev, 0xa6, 0, 0,
						buf, 2, TBS5881_WRITE_MSG);

	msleep (1400);

	mutex_unlock (&state->ca_mutex);

	if (ret < 0)
		return ret;

	return 0;
}

static int tbs5881_poll_slot_status(struct dvb_ca_en50221 *ca,
							int slot, int open)
{
	struct dvb_usb_device *d = (struct dvb_usb_device *)ca->data;
	struct tbs5881_state *state = (struct tbs5881_state *)d->priv;
	u8 buf[3];

	if (0 != slot)
		return -EINVAL;

	mutex_lock(&state->ca_mutex);

	tbs5881_op_rw(d->udev, 0xa8, 0, 0,
					buf, 3, TBS5881_READ_MSG);

	mutex_unlock(&state->ca_mutex);

	if ((1 == buf[2]) && (1 == buf[1]) && (0xa9 == buf[0])) {
		return (DVB_CA_EN50221_POLL_CAM_PRESENT |
				DVB_CA_EN50221_POLL_CAM_READY);
	} else {
		return 0;
	}
}

static void tbs5881_uninit(struct dvb_usb_device *d)
{
	struct tbs5881_state *state;

	if (NULL == d)
		return;

	state = (struct tbs5881_state *)d->priv;
	if (NULL == state)
		return;

	if (NULL == state->ca.data)
		return;

	/* Error ignored. */
	tbs5881_set_video_port(&state->ca, /* slot */ 0, /* enable */ 0);

	dvb_ca_en50221_release(&state->ca);

	memset(&state->ca, 0, sizeof(state->ca));
}

static int tbs5881_init(struct dvb_usb_adapter *a)
{

	struct dvb_usb_device *d = a->dev;
	struct tbs5881_state *state = (struct tbs5881_state *)d->priv;
	int ret;

	state->ca.owner = THIS_MODULE;
	state->ca.read_attribute_mem = tbs5881_read_attribute_mem;
	state->ca.write_attribute_mem = tbs5881_write_attribute_mem;
	state->ca.read_cam_control = tbs5881_read_cam_control;
	state->ca.write_cam_control = tbs5881_write_cam_control;
	state->ca.slot_reset = tbs5881_slot_reset;
	state->ca.slot_shutdown = tbs5881_slot_shutdown;
	state->ca.slot_ts_enable = tbs5881_slot_ts_enable;
	state->ca.poll_slot_status = tbs5881_poll_slot_status;
	state->ca.data = d;

	ret = dvb_ca_en50221_init (&a->dvb_adap, &state->ca,
						/* flags */ 0, /* n_slots */ 1);

	if (0 != ret) {
		err ("Cannot initialize CI: Error %d.", ret);
		memset (&state->ca, 0, sizeof (state->ca));
		return ret;
	}

	info ("CI initialized.");

	ret = tbs5881_poll_slot_status(&state->ca, 0, 0);
	if (0 == ret)
		tbs5881_set_video_port(&state->ca, /* slot */ 0, /* enable */ 0);

	return 0;
}

/* I2C */
static int tbs5881_i2c_transfer(struct i2c_adapter *adap, 
					struct i2c_msg msg[], int num)
{
	struct dvb_usb_device *d = i2c_get_adapdata(adap);
	struct tbs5881_state *state = (struct tbs5881_state *)d->priv;
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

		tbs5881_op_rw(d->udev, 0x90, 0, 0,
					buf6, 3, TBS5881_WRITE_MSG);
		//msleep(5);
		tbs5881_op_rw(d->udev, 0x91, 0, 0,
					inbuf, 1, TBS5881_READ_MSG);
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
				tbs5881_op_rw(d->udev, 0x80, 0, 0,
					buf6, msg[0].len+2, TBS5881_WRITE_MSG);
			} else {
				buf6[0] = msg[0].len;//length
				buf6[1] = (msg[0].addr<<1) | 0x01;//addr
				tbs5881_op_rw(d->udev, 0x93, 0, 0,
						buf6, 2, TBS5881_WRITE_MSG);
				//msleep(5);
				tbs5881_op_rw(d->udev, 0x91, 0, 0,
					inbuf, buf6[0], TBS5881_READ_MSG);
				memcpy(msg[0].buf, inbuf, msg[0].len);
			}
			//msleep(3);
			break;
		case (TBS5881_RC_QUERY):
			tbs5881_op_rw(d->udev, 0xb8, 0, 0,
					buf6, 4, TBS5881_READ_MSG);
			msg[0].buf[0] = buf6[2];
			msg[0].buf[1] = buf6[3];
			//msleep(3);
			//info("TBS5881_RC_QUERY %x %x %x %x\n",
			//		buf6[0],buf6[1],buf6[2],buf6[3]);
			break;
		}

		break;
	}

	mutex_unlock(&d->i2c_mutex);
	mutex_unlock(&state->ca_mutex);
	return num;
}

static u32 tbs5881_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}

static struct i2c_algorithm tbs5881_i2c_algo = {
	.master_xfer = tbs5881_i2c_transfer,
	.functionality = tbs5881_i2c_func,
};

static int tbs5881_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{
	int i,ret;
	u8 ibuf[3] = {0, 0,0};
	u8 eeprom[256], eepromline[16];

	for (i = 0; i < 256; i++) {
		ibuf[0]=1;//lenth
		ibuf[1]=0xa0;//eeprom addr
		ibuf[2]=i;//register
		ret = tbs5881_op_rw(d->udev, 0x90, 0, 0,
					ibuf, 3, TBS5881_WRITE_MSG);
		ret = tbs5881_op_rw(d->udev, 0x91, 0, 0,
					ibuf, 1, TBS5881_READ_MSG);
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

static struct dvb_usb_device_properties tbs5881_properties;

static int tbs5881_frontend_attach(struct dvb_usb_adapter *adap)
{
	struct dvb_usb_device *d = adap->dev;
	struct tbs5881_state *st = (struct tbs5881_state *)d->priv;
	struct i2c_adapter *adapter;
	struct i2c_client *client_demod;
	struct i2c_client *client_tuner;
	struct i2c_board_info info;
	struct si2168_config si2168_config;
	struct si2157_config si2157_config;
	u8 buf[20];

	mutex_init(&st->ca_mutex);

	/* attach frontend */
	memset(&si2168_config, 0, sizeof(si2168_config));
	si2168_config.i2c_adapter = &adapter;
	si2168_config.fe = &adap->fe_adap[0].fe;
	si2168_config.ts_mode = SI2168_TS_SERIAL;
	si2168_config.ts_clock_gapped = true;
	si2168_config.ts_clock_inv = true;
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
	tbs5881_op_rw(d->udev, 0xb7, 0, 0,
			buf, 2, TBS5881_WRITE_MSG);

	buf[0] = 8;
	buf[1] = 1;
	tbs5881_op_rw(d->udev, 0x8a, 0, 0,
			buf, 2, TBS5881_WRITE_MSG);

	buf[0] = 7;
	buf[1] = 1;
	tbs5881_op_rw(d->udev, 0x8a, 0, 0,
			buf, 2, TBS5881_WRITE_MSG);

	buf[0] = 6;
	buf[1] = 1;
	tbs5881_op_rw(d->udev, 0x8a, 0, 0,
					buf, 2, TBS5881_WRITE_MSG);

	tbs5881_init(adap);
	strlcpy(adap->fe_adap->fe->ops.info.name,d->props.devices[0].name,52);
	return 0;
}

static void tbs5881_usb_disconnect (struct usb_interface * intf)
{
	struct dvb_usb_device *d = usb_get_intfdata (intf);
#if 0
	struct tbs5881_state *st = d->priv;
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
	tbs5881_uninit (d);
	dvb_usb_device_exit (intf);
}

static int tbs5881_rc_query(struct dvb_usb_device *d)
{
	u8 key[2];
	struct i2c_msg msg = {
		.addr = TBS5881_RC_QUERY,
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

static struct usb_device_id tbs5881_table[] = {
	{USB_DEVICE(0x734c, 0x5881)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbs5881_table);

static int tbs5881_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	switch (dev->descriptor.idProduct) {
	case 0x5881:
		ret = request_firmware(&fw, tbs5881_properties.firmware, &dev->dev);
		if (ret != 0) {
			err("did not find the firmware file. (%s) "
			"Please see linux/Documentation/dvb/ for more details "
			"on firmware-problems.", tbs5881_properties.firmware);
			return ret;
		}
		break;
	default:
		fw = frmwr;
		break;
	}
	info("start downloading TBS5881 CI firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbs5881_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBS5881_WRITE_MSG);
	tbs5881_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBS5881_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbs5881_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBS5881_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret || tbs5881_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBS5881_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret || tbs5881_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBS5881_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	return ret;
}

static struct dvb_usb_device_properties tbs5881_properties = {
	.caps = DVB_USB_IS_AN_I2C_ADAPTER,
	.usb_ctrl = DEVICE_SPECIFIC,
	.firmware = "dvb-usb-tbsqbox-id5881.fw",
	.size_of_priv = sizeof(struct tbs5881_state),
	.no_reconnect = 1,

	.i2c_algo = &tbs5881_i2c_algo,
	.rc.core = {
		.rc_interval = 150,
		.rc_codes = RC_MAP_TBS_NEC,
		.module_name = KBUILD_MODNAME,
		.allowed_protos   = RC_PROTO_BIT_NEC,
		.rc_query = tbs5881_rc_query,
	},

	.generic_bulk_ctrl_endpoint = 0x81,
	/* parameter for the MPEG2-data transfer */
	.num_adapters = 1,
	.download_firmware = tbs5881_load_firmware,
	.read_mac_address = tbs5881_read_mac_address,
	.adapter = {{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbs5881_frontend_attach,
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
		{"TurboSight TBS 5881 DVB-T/T2/C + CI",
			{&tbs5881_table[0], NULL},
			{NULL},
		}
	}
};

static int tbs5881_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	if (0 == dvb_usb_device_init(intf, &tbs5881_properties,
			THIS_MODULE, NULL, adapter_nr)) {
		return 0;
	}
	return -ENODEV;
}

static struct usb_driver tbs5881_driver = {
	.name = "tbs5881",
	.probe = tbs5881_probe,
	.disconnect = tbs5881_usb_disconnect,
	.id_table = tbs5881_table,
};

static int __init tbs5881_module_init(void)
{
	int ret =  usb_register(&tbs5881_driver);
	if (ret)
		err("usb_register failed. Error number %d", ret);

	return ret;
}

static void __exit tbs5881_module_exit(void)
{
	usb_deregister(&tbs5881_driver);
}

module_init(tbs5881_module_init);
module_exit(tbs5881_module_exit);

MODULE_AUTHOR("Konstantin Dimitrov <kosio.dimitrov@gmail.com>");
MODULE_DESCRIPTION("TurboSight TBS 5881 CI driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
