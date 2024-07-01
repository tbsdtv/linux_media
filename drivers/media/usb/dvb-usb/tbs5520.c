/*
 * TurboSight TBS 5520  driver
 *
 * Copyright (c) 2013 Konstantin Dimitrov <kosio.dimitrov@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, version 2.
 *
 */

#include <linux/version.h>
#include "tbs5520.h"

#include "avl6882.h"
#include "r848.h"

#ifndef USB_PID_TBS5520
#define USB_PID_TBS5520 0x5520
#endif

#define TBS5520_READ_MSG 0
#define TBS5520_WRITE_MSG 1

#define TBS5520_RC_QUERY (0x1a00)

struct tbs5520_state {
	u8 initialized;
};

/* debug */
static int dvb_usb_tbs5520_debug;
module_param_named(debug, dvb_usb_tbs5520_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))."
							DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbs5520_op_rw(struct usb_device *dev, u8 request, u16 value,
				u16 index, u8 *data, u16 len, int flags)
{
	int ret;
	void *u8buf;

	unsigned int pipe = (flags == TBS5520_READ_MSG) ?
			usb_rcvctrlpipe(dev, 0) : usb_sndctrlpipe(dev, 0);
	u8 request_type = (flags == TBS5520_READ_MSG) ? USB_DIR_IN : USB_DIR_OUT;
	u8buf = kmalloc(len, GFP_KERNEL);
	if (!u8buf)
		return -ENOMEM;

	if (flags == TBS5520_WRITE_MSG)
		memcpy(u8buf, data, len);
	ret = usb_control_msg(dev, pipe, request, request_type | USB_TYPE_VENDOR,
				value, index , u8buf, len, 2000);

	if (flags == TBS5520_READ_MSG)
		memcpy(data, u8buf, len);
	kfree(u8buf);
	return ret;
}

/* I2C */

#define MAX_I2C_LEN	62

static int tbs5520_i2c_transfer(struct i2c_adapter *adap,
				struct i2c_msg msg[], int num)
{
	struct dvb_usb_device *d = i2c_get_adapdata(adap);
	int i;
	u8 txbuf[64];

	if (msg[0].addr == TBS5520_RC_QUERY)
		return -ENODEV;

	if (!d)
		return -ENODEV;

	if (mutex_lock_interruptible(&d->i2c_mutex) < 0)
		return -EAGAIN;

	for (i = 0; i < num; i++) {
		if (msg[i].len > MAX_I2C_LEN)
			break;
		if (msg[i].buf == NULL)
			break;

		if (msg[i].flags & I2C_M_RD) {
			//printk("RD: saddr=%02x len=%d:", msg[i].addr, msg[i].len);
			/* read */
			txbuf[0] = msg[i].len;
			txbuf[1] = (msg[i].addr << 1) | 1;
			tbs5520_op_rw(d->udev, 0x93, 0, 0, txbuf, 2, TBS5520_WRITE_MSG);
			tbs5520_op_rw(d->udev, 0x91, 0, 0, msg[i].buf, msg[i].len, TBS5520_READ_MSG);
			//for (j = 0; j < msg[i].len; j++)
			//	printk(" %02x", msg[i].buf[j]);
			//printk("\n");
		} else {
			//printk("WR: saddr=%02x len=%d:", msg[i].addr, msg[i].len);
			//for (j = 0; j < msg[i].len; j++)
			//	printk(" %02x", msg[i].buf[j]);
			//printk("\n");
			txbuf[0] = msg[i].len + 1;
			txbuf[1] = msg[i].addr << 1;
			memcpy(&txbuf[2], msg[i].buf, msg[i].len);
			tbs5520_op_rw(d->udev, 0x80, 0, 0, txbuf, msg[i].len + 2, TBS5520_WRITE_MSG);
		}
	}

	//printk("msg=%d\n", i);
#if 0

	switch (num) {
	case 2:
		printk("wr-rd: adr=%02x rd_len=%02x", msg[0].addr, msg[1].len);
		buf6[0] = msg[1].len;         // lenth
		buf6[1] = (msg[0].addr<<1)+1; // slave addr


		//register
		//buf6[2] = 0;

		/* wr,rd  | 0x90 -> 0x91
		   wr     | 0x80
		   rd     | 0x90 -> 0x91
		*/

		/* request 0x80 = i2c write (data=[wr_len+1, slave_addr, buf...] len=wr_len+2) */
		/* request 0x82 = i2c write (data=buf, len=64) -- no i2c stop? -- */

		/* request 0x90 = i2c read n bytes (data=[rd_len, slave_addr, x?]; len=2+x?) */
		/* request 0x91 = i2c grab received data (data=buf, len=rd_len) */

		/* request 0x92 = i2c read n bytes 16bit reg? (data=[rd_len, slave_addr, r1, r2]; len=4) */
		/* request 0x93 = i2c read n bytes (data=[rd_len, slave_addr | 1]; len=2) */

		/* tbs5520_op_rw(struct usb_device *dev, u8 request, u16 value, u16 index, u8 * data, u16 len, int flags) */

		tbs5520_op_rw(d->udev, 0x93, 0, 0, buf6, 2, TBS5520_WRITE_MSG);
		//msleep(5);
		tbs5520_op_rw(d->udev, 0x91, 0, 0, inbuf, buf6[0], TBS5520_READ_MSG);
		memcpy(msg[1].buf, inbuf, msg[1].len);

		for (i = 0; i < msg[1].len; i++)
			printk(" %02x", inbuf[i]);

	printk("\n");
		break;
	case 1:
		switch (msg[0].addr) {
		case 0x14:
		case 0x7a:
			if (msg[0].flags == 0) {
				buf6[0] = msg[0].len+1;//lenth
				buf6[1] = msg[0].addr<<1;//addr
				for(i=0;i<msg[0].len;i++) {
					buf6[2+i] = msg[0].buf[i];//register
				}
				printk("wr_0:");
				for (i = 0; i < msg[0].len+2; i++)
					printk(" %02x", buf6[i]);
				tbs5520_op_rw(d->udev, 0x80, 0, 0, buf6, msg[0].len+2, TBS5520_WRITE_MSG);
			} else {
				printk("wr_1:");
				for (i = 0; i < msg[0].len; i++)
					printk(" %02x", msg[0].buf[i]);
				tbs5520_op_rw(d->udev, 0x82, 0, 0, msg[0].buf, 64, TBS5520_WRITE_MSG);
			}
	printk("\n");

			//msleep(3);
			break;
			
		case (TBS5520_RC_QUERY):
			tbs5520_op_rw(d->udev, 0xb8, 0, 0,
					buf6, 4, TBS5520_READ_MSG);
			msg[0].buf[0] = buf6[2];
			msg[0].buf[1] = buf6[3];
			//msleep(3);
			//info("TBS5520_RC_QUERY %x %x %x %x\n",
			//		buf6[0],buf6[1],buf6[2],buf6[3]);
			break;
		}

		break;
	}

#endif
	mutex_unlock(&d->i2c_mutex);
	return i;
}

static u32 tbs5520_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static struct r848_config r848_config = {
	.i2c_address = 0x7a,
	.xtal = 16000000,

	.R848_DetectTfType = 0, //R848_UL_USING_BEAD,
	.R848_Xtal_Pwr = 3, //XTAL_SMALL_HIGHEST,
	.R848_Xtal_Pwr_tmp = 4, //XTAL_LARGE_HIGHEST,

	/* dvb t/c */
	.R848_SetTfType = 1, //R848_TF_BEAD,
};


static struct avl6882_config avl6882_config = {
	.demod_address = 0x14,
};

static struct i2c_algorithm tbs5520_i2c_algo = {
	.master_xfer = tbs5520_i2c_transfer,
	.functionality = tbs5520_i2c_func,
};

static int tbs5520_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{

	int i,ret;


	u8 ibuf[3] = {0, 0,0};
	u8 eeprom[256], eepromline[16];

return 0;

	for (i = 0; i < 256; i++) {
		ibuf[0]=1;//lenth
		ibuf[1]=0xa0;//eeprom addr
		ibuf[2]=i;//register
		ret = tbs5520_op_rw(d->udev, 0x90, 0, 0,
					ibuf, 3, TBS5520_WRITE_MSG);
		ret = tbs5520_op_rw(d->udev, 0x91, 0, 0,
					ibuf, 1, TBS5520_READ_MSG);
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

static struct dvb_usb_device_properties tbs5520_properties;

static int tbs5520_frontend_attach(struct dvb_usb_adapter *d)
{
	u8 buf[2];

	d->fe_adap->fe = dvb_attach(avl6882_attach, &avl6882_config,
		&d->dev->i2c_adap);
	if (d->fe_adap->fe == NULL)
		goto err;

	if (dvb_attach(r848_attach, d->fe_adap->fe, &r848_config,
			&d->dev->i2c_adap) == NULL) {
		dvb_frontend_detach(d->fe_adap->fe);
		d->fe_adap->fe = NULL;
		printk("TBS5520: tuner attach failed\n");
		goto err;
	}

	info("TBS5520: frontend attached\n");
	buf[0] = 7;
	buf[1] = 1;
	tbs5520_op_rw(d->dev->udev, 0x8a, 0, 0,
		buf, 2, TBS5520_WRITE_MSG);

	buf[0] = 6;
	buf[1] = 1;
	tbs5520_op_rw(d->dev->udev, 0x8a, 0, 0,
		buf, 2, TBS5520_WRITE_MSG);

	strscpy(d->fe_adap->fe->ops.info.name,d->dev->props.devices[0].name,52);
	return 0;
err:
	printk("TBS5520: frontend attach failed\n");
	return -ENODEV;
}

static int tbs5520_rc_query(struct dvb_usb_device *d)
{
	u8 key[2];
	struct i2c_msg msg = {
		.addr = TBS5520_RC_QUERY,
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

static struct usb_device_id tbs5520_table[] = {
	{USB_DEVICE(0x734c, 0x5520)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbs5520_table);

static int tbs5520_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	const char *filename = "dvb-usb-tbs5520-01.fw";
	switch (dev->descriptor.idProduct) {
	case 0xdc02:
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
	info("start downloading tbs5520 firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbs5520_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBS5520_WRITE_MSG);
	tbs5520_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBS5520_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbs5520_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBS5520_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret |= tbs5520_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBS5520_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret |= tbs5520_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBS5520_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	info("end downloading tbs5520 firmware");
	return ret;
}

static struct dvb_usb_device_properties tbs5520_properties = {
	.caps = DVB_USB_IS_AN_I2C_ADAPTER,
	.usb_ctrl = DEVICE_SPECIFIC,
	.firmware = "dvb-usb-tbs5520-01.fw",
	.download_firmware = tbs5520_load_firmware,
	.size_of_priv = sizeof(struct tbs5520_state),
	.no_reconnect = 1,

	.i2c_algo = &tbs5520_i2c_algo,
	.rc.core = {
		.rc_interval = 150,
		.rc_codes = RC_MAP_TBS_NEC,
		.module_name = KBUILD_MODNAME,
		.allowed_protos   = RC_PROTO_BIT_NEC,
		.rc_query = tbs5520_rc_query,
	},

	.generic_bulk_ctrl_endpoint = 0x81,
	/* parameter for the MPEG2-data transfer */
	.num_adapters = 1,

	.read_mac_address = tbs5520_read_mac_address,
	.adapter = {{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbs5520_frontend_attach,
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
		}},
	}},
	.num_device_descs = 1,
	.devices = {
		{"TurboSight TBS 5520 DVB-S/S2/T/T2/C/ISDB-T", {&tbs5520_table[0], NULL}, {NULL}, },
	}
};


static int tbs5520_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	if (0 == dvb_usb_device_init(intf, &tbs5520_properties,
			THIS_MODULE, NULL, adapter_nr)) {
		return 0;
	}
	return -ENODEV;
}

static struct usb_driver tbs5520_driver = {
	.name = "tbs5520",
	.probe = tbs5520_probe,
	.disconnect = dvb_usb_device_exit,
	.id_table = tbs5520_table,
};

static int __init tbs5520_module_init(void)
{
	int ret =  usb_register(&tbs5520_driver);
	if (ret)
		err("usb_register failed. Error number %d", ret);

	return ret;
}

static void __exit tbs5520_module_exit(void)
{
	usb_deregister(&tbs5520_driver);
}

module_init(tbs5520_module_init);
module_exit(tbs5520_module_exit);

MODULE_AUTHOR("Konstantin Dimitrov <kosio.dimitrov@gmail.com>");
MODULE_DESCRIPTION("TurboSight TBS 5520 driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
