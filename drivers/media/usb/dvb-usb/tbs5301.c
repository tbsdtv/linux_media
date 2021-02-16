/* DVB USB framework compliant Linux driver for the
*	TBS 5301
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
#include "tbs5301.h"
#include "tas2971.h"


#define TBS5301_READ_MSG 0
#define TBS5301_WRITE_MSG 1

/* on my own*/
#define TBS5301_VOLTAGE_CTRL (0x1800)
#define TBS5301_RC_QUERY (0x1a00)

struct tbs5301_state {
	u32 last_key_pressed;
};
struct tbs5301_rc_keys {
	u32 keycode;
	u32 event;
};

/* debug */
static int dvb_usb_tbs5301_debug;
module_param_named(debug, dvb_usb_tbs5301_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))." DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbs5301_op_rw(struct usb_device *dev, u8 request, u16 value,
			u16 index, u8 * data, u16 len, int flags)
{
	int ret;
	void *u8buf;

	unsigned int pipe = (flags == TBS5301_READ_MSG) ?
			usb_rcvctrlpipe(dev, 0) : usb_sndctrlpipe(dev, 0);
	u8 request_type = (flags == TBS5301_READ_MSG) ? USB_DIR_IN : USB_DIR_OUT;
	u8buf = kmalloc(len, GFP_KERNEL);
	if (!u8buf)
		return -ENOMEM;

	if (flags == TBS5301_WRITE_MSG)
		memcpy(u8buf, data, len);
	ret = usb_control_msg(dev, pipe, request, request_type | USB_TYPE_VENDOR,
				value, index , u8buf, len, 2000);

	if (flags == TBS5301_READ_MSG)
		memcpy(data, u8buf, len);
	kfree(u8buf);
	return ret;
}

/* I2C */
static int tbs5301_i2c_transfer(struct i2c_adapter *adap, struct i2c_msg msg[],
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

		tbs5301_op_rw(d->udev, 0x90, 0, 0,
				buf, 3, TBS5301_WRITE_MSG);
		msleep(5);
		tbs5301_op_rw(d->udev, 0x91, 0, 0,
				buf, msg[1].len, TBS5301_READ_MSG);
		memcpy(msg[1].buf, buf, msg[1].len);
		break;
	case 1:
		switch (msg[0].addr) {
		case 0x28:
			/* write to register */
			buf[0] = msg[0].len + 1; //lenth
			buf[1] = msg[0].addr << 1; //demod addr
			for(i=0; i < msg[0].len; i++)
				buf[2+i] = msg[0].buf[i]; //register
			tbs5301_op_rw(d->udev, 0x80, 0, 0,
						buf, msg[0].len+2, TBS5301_WRITE_MSG);
			//msleep(3);
			break;
		case (TBS5301_RC_QUERY):
			tbs5301_op_rw(d->udev, 0xb8, 0, 0,
					buf, 4, TBS5301_READ_MSG);
			msg[0].buf[0] = buf[2];
			msg[0].buf[1] = buf[3];
			msleep(3);
			//info("TBS5301_RC_QUERY %x %x %x %x\n",buf6[0],buf6[1],buf6[2],buf6[3]);
			break;
		case (TBS5301_VOLTAGE_CTRL):
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

static u32 tbs5301_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}


static struct i2c_algorithm tbs5301_i2c_algo = {
	.master_xfer = tbs5301_i2c_transfer,
	.functionality = tbs5301_i2c_func,
};


static int tbs5301_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{
	int i,ret;
	u8 buf[3];
	u8 eeprom[256], eepromline[16];

	for (i = 0; i < 256; i++) {
		buf[0] = 1; //lenth
		buf[1] = 0xa0; //eeprom addr
		buf[2] = i; //register
		ret = tbs5301_op_rw(d->udev, 0x90, 0, 0,
					buf, 3, TBS5301_WRITE_MSG);
		ret = tbs5301_op_rw(d->udev, 0x91, 0, 0,
					buf, 1, TBS5301_READ_MSG);
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

static struct dvb_usb_device_properties tbs5301_properties;

static void reg_i2cread(struct i2c_adapter *i2c,u8 chip_addr,u8 reg, u8 num, u8 *buf)
{	
	struct dvb_usb_device *d = i2c_get_adapdata(i2c);
	u8 data[20];

	if (!d)
		return;
	if (mutex_lock_interruptible(&d->i2c_mutex) < 0)
		return;

	/* read */
	data[0] = num;
	data[1] = chip_addr;
	data[2] = reg;

	tbs5301_op_rw(d->udev, 0x90, 0, 0,
			data, 3, TBS5301_WRITE_MSG);
	msleep(5);
	tbs5301_op_rw(d->udev, 0x91, 0, 0,
			data, num, TBS5301_READ_MSG);
	memcpy(buf, data, num);

	mutex_unlock(&d->i2c_mutex);

	return ;
}
static void reg_i2cwrite(struct i2c_adapter *i2c,u8 chip_addr,u8 reg, u8 num, u8 *buf)
{
	struct dvb_usb_device *d = i2c_get_adapdata(i2c);
	u8 data[20];
	int i=0;

	if (!d)
		return;
	if (mutex_lock_interruptible(&d->i2c_mutex) < 0)
		return;
	/* write to register */
	data[0] = num + 2; //lenth
	data[1] = chip_addr; //chip addr
	data[2] = reg; //reg addr
	for(i=0; i < num; i++)
		data[3+i] = buf[i]; //register
	tbs5301_op_rw(d->udev, 0x80, 0, 0,
				data, num+3, TBS5301_WRITE_MSG);

	mutex_unlock(&d->i2c_mutex);

	return ;
}

static struct tas2101_config tbs5301_cfg = {
	.i2c_address   = 0x28,
	.id            = ID_TAS2101,
	.reset_demod   = NULL,
	.lnb_power     = NULL,
	.init          = {0x67, 0x45, 0xba, 0x23, 0x01, 0x98, 0x33},
	.init2         = 1,

	.i2cwrite_properties = reg_i2cwrite,  
	.i2cRead_properties = reg_i2cread,
};

static int tbs5301_frontend_attach(struct dvb_usb_adapter *d)
{
	struct dvb_usb_device *u = d->dev;
	u8 buf[20];
	u8 temp1,temp2;
	int chip_id =0;
	int ret;

	d->fe_adap->fe = dvb_attach(tas2971_attach, &tbs5301_cfg,
				&u->i2c_adap);
	if (d->fe_adap->fe == NULL)
		goto err;

	//read id 
	buf[0] = 1; //lenth
	buf[1] = 0x50; //chip addr
	buf[2] = 0; //register
	ret = tbs5301_op_rw(u->udev, 0x90, 0, 0,
				buf, 3, TBS5301_WRITE_MSG);
	msleep(5);
	ret = tbs5301_op_rw(u->udev, 0x91, 0, 0,
				&temp2, 1, TBS5301_READ_MSG);


	buf[0] = 1; //lenth
	buf[1] = 0x50; //chip addr
	buf[2] = 1; //register
	ret = tbs5301_op_rw(u->udev, 0x90, 0, 0,
				buf, 3, TBS5301_WRITE_MSG);
	msleep(5);
	ret = tbs5301_op_rw(u->udev, 0x91, 0, 0,
				&temp1, 1, TBS5301_READ_MSG);

	chip_id = ((temp2<<8)|temp1);
	printk("tbs5301 chip id %x\n",chip_id);

	// get the ctl of chip
	buf[0] = 3; //lenth
	buf[1] = 0x50; //chip addr
	buf[2] = 0x02; //register
	buf[3] = 0x55; //get:0x55, release:0xaa
	ret = tbs5301_op_rw(u->udev, 0x80, 0, 0,
				buf, 4, TBS5301_WRITE_MSG);
	
	strlcpy(d->fe_adap->fe->ops.info.name,u->props.devices[0].name,52);

	return 0;
err:
	return -ENODEV;
}



static struct rc_map_table tbs5301_rc_keys[] = {
	{ 0xff84, KEY_POWER2},		/* power */
	{ 0xff94, KEY_MUTE},		/* mute */
	{ 0xff87, KEY_1},
	{ 0xff86, KEY_2},
	{ 0xff85, KEY_3},
	{ 0xff8b, KEY_4},
	{ 0xff8a, KEY_5},
	{ 0xff89, KEY_6},
	{ 0xff8f, KEY_7},
	{ 0xff8e, KEY_8},
	{ 0xff8d, KEY_9},
	{ 0xff92, KEY_0},
	{ 0xff96, KEY_CHANNELUP},	/* ch+ */
	{ 0xff91, KEY_CHANNELDOWN},	/* ch- */
	{ 0xff93, KEY_VOLUMEUP},	/* vol+ */
	{ 0xff8c, KEY_VOLUMEDOWN},	/* vol- */
	{ 0xff83, KEY_RECORD},		/* rec */
	{ 0xff98, KEY_PAUSE},		/* pause, yellow */
	{ 0xff99, KEY_OK},		/* ok */
	{ 0xff9a, KEY_CAMERA},		/* snapshot */
	{ 0xff81, KEY_UP},
	{ 0xff90, KEY_LEFT},
	{ 0xff82, KEY_RIGHT},
	{ 0xff88, KEY_DOWN},
	{ 0xff95, KEY_FAVORITES},	/* blue */
	{ 0xff97, KEY_SUBTITLE},	/* green */
	{ 0xff9d, KEY_ZOOM},
	{ 0xff9f, KEY_EXIT},
	{ 0xff9e, KEY_MENU},
	{ 0xff9c, KEY_EPG},
	{ 0xff80, KEY_PREVIOUS},	/* red */
	{ 0xff9b, KEY_MODE},
	{ 0xffdd, KEY_TV },
	{ 0xffde, KEY_PLAY },
	{ 0xffdc, KEY_STOP },
	{ 0xffdb, KEY_REWIND },
	{ 0xffda, KEY_FASTFORWARD },
	{ 0xffd9, KEY_PREVIOUS },	/* replay */
	{ 0xffd8, KEY_NEXT },		/* skip */
	{ 0xffd1, KEY_NUMERIC_STAR },
	{ 0xffd2, KEY_NUMERIC_POUND },
	{ 0xffd4, KEY_DELETE },		/* clear */
};



static int tbs5301_rc_query(struct dvb_usb_device *d, u32 *event, int *state)
{
	struct rc_map_table *keymap = d->props.rc.legacy.rc_map_table;
	int keymap_size = d->props.rc.legacy.rc_map_size;
	
	struct tbs5301_state *st = d->priv;
	u8 key[2];
	struct i2c_msg msg[] = {
		{.addr = TBS5301_RC_QUERY, .flags = I2C_M_RD, .buf = key,
		.len = 2},
	};
	int i;

	*state = REMOTE_NO_KEY_PRESSED;
	if (tbs5301_i2c_transfer(&d->i2c_adap, msg, 1) == 1) {
		//info("key: %x %x\n",msg[0].buf[0],msg[0].buf[1]); 
		for (i = 0; i < keymap_size; i++) {
			if (rc5_data(&keymap[i]) == msg[0].buf[1]) {
				*state = REMOTE_KEY_PRESSED;
				*event = keymap[i].keycode;
				st->last_key_pressed =
					keymap[i].keycode;
				break;
			}
		st->last_key_pressed = 0;
		}
	}
	 
	return 0;
}

static struct usb_device_id tbs5301_table[] = {
	{USB_DEVICE(0x734c, 0x5301)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbs5301_table);

static int tbs5301_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	const char *filename = "dvb-usb-id5301.fw";
	switch (dev->descriptor.idProduct) {
	case 0x5301:
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
	info("start downloading TBS5301 firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbs5301_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBS5301_WRITE_MSG);
	tbs5301_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBS5301_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbs5301_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBS5301_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret || tbs5301_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBS5301_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret || tbs5301_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBS5301_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	return ret;
}

static struct dvb_usb_device_properties tbs5301_properties = {
	.caps = DVB_USB_IS_AN_I2C_ADAPTER,
	.usb_ctrl = DEVICE_SPECIFIC,
	.firmware = "dvb-usb-id5301.fw",
	.size_of_priv = sizeof(struct tbs5301_state),
	.no_reconnect = 1,

	.i2c_algo = &tbs5301_i2c_algo,
	.rc.legacy = {
		.rc_map_table = tbs5301_rc_keys,
		.rc_map_size = ARRAY_SIZE(tbs5301_rc_keys),
		.rc_interval = 150,
		.rc_query = tbs5301_rc_query,
	},

	.generic_bulk_ctrl_endpoint = 0x81,
	/* parameter for the MPEG2-data transfer */
	.num_adapters = 1,
	.download_firmware = tbs5301_load_firmware,
	.read_mac_address = tbs5301_read_mac_address,
	.adapter = {{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbs5301_frontend_attach,
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
		{"TurboSight TBS 5301 HDMI Capture",
			{&tbs5301_table[0], NULL},
			{NULL},
		}
	}
};

static int tbs5301_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	if (0 == dvb_usb_device_init(intf, &tbs5301_properties,
			THIS_MODULE, NULL, adapter_nr)) {
		return 0;
	}
	return -ENODEV;
}
static void tbs5301_disconnect(struct usb_interface *intf)
{

	struct dvb_usb_device *u = usb_get_intfdata(intf);
	u8 buf[20];
	int ret;

	// release the ctl of chip
	buf[0] = 3; //lenth
	buf[1] = 0x50; //chip addr
	buf[2] = 0x02; //register
	buf[3] = 0xaa; //get:0x55, release:0xaa
	ret = tbs5301_op_rw(u->udev, 0x80, 0, 0,
				buf, 4, TBS5301_WRITE_MSG);
	printk("release tbs5301 usb ctl!\n");

	dvb_usb_device_exit(intf);
}

static struct usb_driver tbs5301_driver = {
	.name = "tbs5301",
	.probe = tbs5301_probe,
	.disconnect = tbs5301_disconnect,
	.id_table = tbs5301_table,
};

static int __init tbs5301_module_init(void)
{
	int ret =  usb_register(&tbs5301_driver);
	if (ret)
		err("usb_register failed. Error number %d", ret);

	return ret;
}

static void __exit tbs5301_module_exit(void)
{
	usb_deregister(&tbs5301_driver);
}

module_init(tbs5301_module_init);
module_exit(tbs5301_module_exit);

MODULE_AUTHOR("Bob Liu <Bob@turbosight.com>");
MODULE_DESCRIPTION("Driver for TBS 5301");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL");
