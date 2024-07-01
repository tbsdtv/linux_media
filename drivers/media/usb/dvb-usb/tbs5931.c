/*
 * TurboSight TBS 5930 lite  driver
 *
 * Copyright (c) 2017 Davin <davin@tbsdtv.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, version 2.
 *
 */

#include <linux/version.h>
#include "tbs5931.h"
#include "gx1133.h"
#include "tas2101.h"
#include "av201x.h"

#define TBS5931_READ_MSG 0
#define TBS5931_WRITE_MSG 1

#define TBS5931_RC_QUERY (0x1a00)
#define TBS5931_VOLTAGE_CTRL (0x1800)

struct tbs5931_state {
	u8 initialized;
};


static struct tas2101_config gx1132_cfg = {	
	.i2c_address   = 0x60,
	.id            = ID_TAS2101,
	.init          = {0x10, 0x32, 0x54, 0x76, 0xA8, 0x9B, 0x33},
	.init2         = 0,	

};

static struct gx1133_config gx1133_cfg = {	
	.i2c_address   = 0x52,
	.ts_mode 	   = 0,	
	.ts_cfg		= {data_0,data_1,data_2,data_3,data_4,data_5,data_6,  \
				data_7,ts_sync,ts_err,ts_clk,ts_valid},
};

static struct av201x_config av201x_cfg = {
	.i2c_address = 0x62,
	.id 		 = ID_AV2012,
	.xtal_freq	 = 27000,		/* kHz */
};


/* debug */
static int dvb_usb_tbs5931_debug;
module_param_named(debug, dvb_usb_tbs5931_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))." 
							DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbs5931_op_rw(struct usb_device *dev, u8 request, u16 value,
				u16 index, u8 * data, u16 len, int flags)
{
	int ret;
	void *u8buf;

	unsigned int pipe = (flags == TBS5931_READ_MSG) ?
			usb_rcvctrlpipe(dev, 0) : usb_sndctrlpipe(dev, 0);
	u8 request_type = (flags == TBS5931_READ_MSG) ? USB_DIR_IN : USB_DIR_OUT;
	u8buf = kmalloc(len, GFP_KERNEL);
	if (!u8buf)
		return -ENOMEM;

	if (flags == TBS5931_WRITE_MSG)
		memcpy(u8buf, data, len);
	ret = usb_control_msg(dev, pipe, request, request_type | USB_TYPE_VENDOR,
				value, index , u8buf, len, 2000);

	if (flags == TBS5931_READ_MSG)
		memcpy(data, u8buf, len);
	kfree(u8buf);
	return ret;
}

/* I2C */
static int tbs5931_i2c_transfer(struct i2c_adapter *adap, 
					struct i2c_msg msg[], int num)
{
	struct dvb_usb_device *d = i2c_get_adapdata(adap);
	int i = 0;
	u8 buf6[35];
	u8 inbuf[35];

	if (!d)
		return -ENODEV;
	if (mutex_lock_interruptible(&d->i2c_mutex) < 0)
		return -EAGAIN;
   		
	switch (num) {
	case 2:
		switch(msg[0].addr){
		case 0x60:
		case 0x62:
			buf6[0]=msg[1].len;//lenth
			buf6[1]=msg[0].addr<<1;//demod addr
			//register
			buf6[2] = msg[0].buf[0];

			tbs5931_op_rw(d->udev, 0x90, 0, 0,
						buf6, 3, TBS5931_WRITE_MSG);
			msleep(1);
			tbs5931_op_rw(d->udev, 0x91, 0, 0,
						inbuf, buf6[0], TBS5931_READ_MSG);
			memcpy(msg[1].buf, inbuf, msg[1].len);
		break;
		case 0x52:
			buf6[0]=msg[1].len;//lenth
			buf6[1]=msg[0].addr<<1;//demod addr
			//register
			memcpy(buf6+2,msg[0].buf,msg[0].len);
			
			tbs5931_op_rw(d->udev,  0x92, 0, 0,
						buf6, msg[0].len+2, TBS5931_WRITE_MSG);
			msleep(1);
			tbs5931_op_rw(d->udev, 0x91, 0, 0,
						inbuf, msg[1].len, TBS5931_READ_MSG);
			
			memcpy(msg[1].buf, inbuf, msg[1].len);

			break;
			}
		break;
	case 1:
		buf6[0] = msg[0].len+1;//lenth
		buf6[1] = msg[0].addr<<1;//addr
		for(i=0;i<msg[0].len;i++) {
			buf6[2+i] = msg[0].buf[i];//register
		}
		tbs5931_op_rw(d->udev, 0x80, 0, 0,
			buf6, msg[0].len+2, TBS5931_WRITE_MSG);
		break;
	}
		
	mutex_unlock(&d->i2c_mutex);
	return num;
}

static u32 tbs5931_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}

static struct i2c_algorithm tbs5931_i2c_algo = {
	.master_xfer = tbs5931_i2c_transfer,
	.functionality = tbs5931_i2c_func,
};

static int tbs5931_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{
	int i,ret;
	u8 ibuf[3] = {0, 0,0};
	u8 eeprom[256], eepromline[16];

	for (i = 0; i < 256; i++) {
		ibuf[0]=1;//lenth
		ibuf[1]=0xA0;//eeprom addr
		ibuf[2]=i;//register
		ret = tbs5931_op_rw(d->udev, 0x90, 0, 0,
					ibuf, 3, TBS5931_WRITE_MSG);
		ret = tbs5931_op_rw(d->udev, 0x91, 0, 0,
					ibuf, 1, TBS5931_READ_MSG);
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

static struct dvb_usb_device_properties tbs5931_properties;

static int tbs5931_frontend_attach(struct dvb_usb_adapter *adap)
{
	struct dvb_usb_device *d = adap->dev;

	u8 buf[20];
	u8 a = 0,b = 0;
	u16 id;
	//read the id to deceted the chip
	buf[0]= 1;//lenth
	buf[1]= 0xC0;//demod addr
	//register
	buf[2] = 0x01;
	tbs5931_op_rw(d->udev, 0x90, 0, 0,
				buf, 3, TBS5931_WRITE_MSG);
	msleep(1);
	tbs5931_op_rw(d->udev, 0x91, 0, 0,
				&a, buf[0], TBS5931_READ_MSG);
	msleep(5);

	buf[2] = 0x00;
	tbs5931_op_rw(d->udev, 0x90, 0, 0,
				buf, 3, TBS5931_WRITE_MSG);
	msleep(1);
	tbs5931_op_rw(d->udev, 0x91, 0, 0,
				&b, buf[0], TBS5931_READ_MSG);
	id = (b<<8|a);
	if(id==0x444c){   //gx1132
		adap->fe_adap->fe = dvb_attach(tas2101_attach,&gx1132_cfg,&d->i2c_adap);
		if(adap->fe_adap->fe ==NULL)
			goto err;

		if(dvb_attach(av201x_attach,adap->fe_adap->fe,&av201x_cfg,
			tas2101_get_i2c_adapter(adap->fe_adap->fe,2))==NULL){
			dvb_frontend_detach(adap->fe_adap->fe);
			adap->fe_adap->fe = NULL;
			goto err;
		}
	}
	else{
	id = 0;
	a = 0;
	b = 0;
	
	buf[0]= 1;//lenth
	buf[1]= 0xA4;//demod addr
	//register
	buf[2] = 0xff;
	buf[3] = 0xf1;
	tbs5931_op_rw(d->udev, 0x92, 0, 0,
				buf, 4, TBS5931_WRITE_MSG);
	msleep(1);
	tbs5931_op_rw(d->udev, 0x91, 0, 0,
				&a, buf[0], TBS5931_READ_MSG);
	msleep(5);

	buf[3] = 0xf0;
	tbs5931_op_rw(d->udev, 0x92, 0, 0,
				buf, 4, TBS5931_WRITE_MSG);
	msleep(1);
	tbs5931_op_rw(d->udev, 0x91, 0, 0,
				&b, buf[0], TBS5931_READ_MSG);

	id = (b<<8|a);
	 if(id==0x444c){   //gx1133
		 adap->fe_adap->fe = dvb_attach(gx1133_attach,&gx1133_cfg,&d->i2c_adap);
		 if(adap->fe_adap->fe ==NULL)
			 goto err;
		 
		 if(dvb_attach(av201x_attach,adap->fe_adap->fe,&av201x_cfg,
			 gx1133_get_i2c_adapter(adap->fe_adap->fe,2))==NULL){
			 dvb_frontend_detach(adap->fe_adap->fe);
			 adap->fe_adap->fe = NULL;
			 goto err;
		 }

	 }
	 else
	 	goto err;

	}
	
	buf[0] = 0;
	buf[1] = 0;
	tbs5931_op_rw(d->udev, 0xb7, 0, 0,
			buf, 2, TBS5931_WRITE_MSG);
	
	buf[0] = 8;
	buf[1] = 1;
	tbs5931_op_rw(d->udev, 0x8a, 0, 0,
			buf, 2, TBS5931_WRITE_MSG);
	msleep(10);
	
	strscpy(adap->fe_adap->fe->ops.info.name,d->props.devices[0].name,52);
	
	return 0;
	
err:
	return -ENODEV;
}

static struct usb_device_id tbs5931_table[] = {
	{USB_DEVICE(0x734c, 0x5931)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbs5931_table);

static int tbs5931_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	switch (dev->descriptor.idProduct) {
	case 0x5931:
		ret = request_firmware(&fw, tbs5931_properties.firmware, &dev->dev);
		if (ret != 0) {
			err("did not find the firmware file. (%s) "
			"Please see linux/Documentation/dvb/ for more details "
			"on firmware-problems.", tbs5931_properties.firmware);
			return ret;
		}
		break;
	default:
		fw = frmwr;
		break;
	}
	info("start downloading TBS5931 firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbs5931_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBS5931_WRITE_MSG);
	tbs5931_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBS5931_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbs5931_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBS5931_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret || tbs5931_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBS5931_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret || tbs5931_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBS5931_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	return ret;
}

static struct dvb_usb_device_properties tbs5931_properties = {
	.caps = DVB_USB_IS_AN_I2C_ADAPTER,
	.usb_ctrl = DEVICE_SPECIFIC,
	.firmware = "dvb-usb-id5931.fw",
	.size_of_priv = sizeof(struct tbs5931_state),
	.no_reconnect = 1,

	.i2c_algo = &tbs5931_i2c_algo,

	.generic_bulk_ctrl_endpoint = 0x81,
	/* parameter for the MPEG2-data transfer */
	.num_adapters = 1,
	.download_firmware = tbs5931_load_firmware,
	.read_mac_address = tbs5931_read_mac_address,
	.adapter = {{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbs5931_frontend_attach,
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
		}

		},
		
	}},

	.num_device_descs = 1,
	.devices = {
		{"TurboSight TBS 5930 lite DVB-S/S2",
			{&tbs5931_table[0], NULL},
			{NULL},
		}
	}
};

static int tbs5931_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	if (0 == dvb_usb_device_init(intf, &tbs5931_properties,
			THIS_MODULE, NULL, adapter_nr)) {
		return 0;
	}
	return -ENODEV;
}


static struct usb_driver tbs5931_driver = {
	.name = "tbs5931",
	.probe = tbs5931_probe,
	.disconnect = dvb_usb_device_exit,
	.id_table = tbs5931_table,
};

static int __init tbs5931_module_init(void)
{
	int ret =  usb_register(&tbs5931_driver);
	if (ret)
		err("usb_register failed. Error number %d", ret);

	return ret;
}

static void __exit tbs5931_module_exit(void)
{
	usb_deregister(&tbs5931_driver);
}

module_init(tbs5931_module_init);
module_exit(tbs5931_module_exit);

MODULE_AUTHOR("Davin zhang<Davin@tbsdtv.com>");
MODULE_DESCRIPTION("TurboSight TBS 5931/5903lite driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
