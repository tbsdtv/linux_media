/*
 * TurboSight TBS 5230  driver
 *
 * Copyright (c) 2022/06 Davin zhang<Davin@tbsdtv.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, version 2.
 *
 */


#include <linux/version.h>
#include "tbs5230.h"
#include "cxd2878.h"


#define TBS5230_READ_MSG 0
#define TBS5230_WRITE_MSG 1

struct tbs5230_state {
	u8 initialized;
};
/* debug */
static int dvb_usb_tbs5230_debug;
module_param_named(debug, dvb_usb_tbs5230_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))." 
							DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbs5230_op_rw(struct usb_device *dev, u8 request, u16 value,
				u16 index, u8 * data, u16 len, int flags)
{
	int ret;
	void *u8buf;

	unsigned int pipe = (flags == TBS5230_READ_MSG) ?
			usb_rcvctrlpipe(dev, 0) : usb_sndctrlpipe(dev, 0);
	u8 request_type = (flags == TBS5230_READ_MSG) ? USB_DIR_IN : USB_DIR_OUT;
	u8buf = kmalloc(len, GFP_KERNEL);
	if (!u8buf)
		return -ENOMEM;

	if (flags == TBS5230_WRITE_MSG)
		memcpy(u8buf, data, len);
	ret = usb_control_msg(dev, pipe, request, request_type | USB_TYPE_VENDOR,
				value, index , u8buf, len, 2000);

	if (flags == TBS5230_READ_MSG)
		memcpy(data, u8buf, len);
	kfree(u8buf);
	return ret;
}

/* I2C */
static int tbs5230_i2c_transfer(struct i2c_adapter *adap, 
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
		buf6[0]=msg[1].len;//lenth
		buf6[1]=msg[0].addr<<1;//demod addr
		//register
		buf6[2] = msg[0].buf[0];

		tbs5230_op_rw(d->udev, 0x90, 0, 0,
					buf6, 3, TBS5230_WRITE_MSG);
		//msleep(5);
		tbs5230_op_rw(d->udev, 0x91, 0, 0,
					inbuf, buf6[0], TBS5230_READ_MSG);
		memcpy(msg[1].buf, inbuf, msg[1].len);

		break;
	case 1:
		buf6[0] = msg[0].len+1;//lenth
		buf6[1] = msg[0].addr<<1;//addr
		for(i=0;i<msg[0].len;i++) {
			buf6[2+i] = msg[0].buf[i];//register
		}
		tbs5230_op_rw(d->udev, 0x80, 0, 0,
			buf6, msg[0].len+2, TBS5230_WRITE_MSG);
		break;
	}
		
	mutex_unlock(&d->i2c_mutex);
	return num;
}

static u32 tbs5230_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}

static struct i2c_algorithm tbs5230_i2c_algo = {
	.master_xfer = tbs5230_i2c_transfer,
	.functionality = tbs5230_i2c_func,
};

static int tbs5230_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{
	int i,ret;
	u8 ibuf[3] = {0, 0,0};
	u8 eeprom[256], eepromline[16];

	for (i = 0; i < 256; i++) {
		ibuf[0]=1;//lenth
		ibuf[1]=0xa0;//eeprom addr
		ibuf[2]=i;//register
		ret = tbs5230_op_rw(d->udev, 0x90, 0, 0,
					ibuf, 3, TBS5230_WRITE_MSG);
		ret = tbs5230_op_rw(d->udev, 0x91, 0, 0,
					ibuf, 1, TBS5230_READ_MSG);
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

static struct dvb_usb_device_properties tbs5230_properties;

static struct cxd2878_config tbs5230_cfg = {
	
		.addr_slvt = 0x64,
		.xtal      = SONY_DEMOD_XTAL_24000KHz,
		.tuner_addr = 0x60,
		.tuner_xtal = SONY_ASCOT3_XTAL_24000KHz,
		.ts_mode	= 1,
		.ts_ser_data = 0,
		.ts_clk = 1,
		.ts_clk_mask= 1,
		.ts_valid = 0,
		.atscCoreDisable = 0,
		.lock_flag = 1,
		.write_properties = NULL, 
		.read_properties = NULL,	
	};

static int tbs5230_frontend_attach(struct dvb_usb_adapter*adap)
{

	struct dvb_usb_device *d = adap->dev;

	adap->fe_adap[0].fe = dvb_attach(cxd2878_attach, &tbs5230_cfg, &d->i2c_adap);

	if(adap->fe_adap[0].fe!=NULL){
	 strlcpy(adap->fe_adap[0].fe->ops.info.name,d->props.devices[0].name,52);
			return 0;
		}
	return -EIO;
}

static struct usb_device_id tbs5230_table[] = {
	{USB_DEVICE(0x734c, 0x5230)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbs5230_table);

static int tbs5230_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	switch (dev->descriptor.idProduct) {
	case 0x5230:
		ret = request_firmware(&fw, tbs5230_properties.firmware, &dev->dev);
		if (ret != 0) {
			err("did not find the firmware file. (%s) "
			"Please see linux/Documentation/dvb/ for more details "
			"on firmware-problems.", tbs5230_properties.firmware);
			return ret;
		}
		break;
	default:
		fw = frmwr;
		break;
	}
	info("start downloading TBS5230 firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbs5230_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBS5230_WRITE_MSG);
	tbs5230_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBS5230_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbs5230_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBS5230_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret || tbs5230_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBS5230_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret || tbs5230_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBS5230_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	return ret;
}

static struct dvb_usb_device_properties tbs5230_properties = {
		.caps = DVB_USB_IS_AN_I2C_ADAPTER,
		.usb_ctrl = DEVICE_SPECIFIC,
		.firmware = "dvb-usb-id5230.fw",
		.size_of_priv = sizeof(struct tbs5230_state),
		.no_reconnect = 1,

		.i2c_algo = &tbs5230_i2c_algo,
		.generic_bulk_ctrl_endpoint = 0x81,
		.num_adapters = 1,
		.download_firmware = tbs5230_load_firmware,
		.read_mac_address	= tbs5230_read_mac_address,

		.adapter = {{
			.num_frontends = 1,
			.fe = {{
				.frontend_attach = tbs5230_frontend_attach,
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
			{"TurboSight TBS 5230 DVB-T2/T/C(j83-a/b/c),ISDB-T,ATSC1.0",
				{&tbs5230_table[0], NULL},
				{NULL},
			}
		}		
};
static int tbs5230_probe(struct usb_interface *intf,
					const struct usb_device_id*id)
{
	if(0 == dvb_usb_device_init(intf,&tbs5230_properties,
		THIS_MODULE,NULL,adapter_nr)){
		return 0;
	}
	return -ENODEV;
}
static struct usb_driver tbs5230_driver ={
		.name = "tbs5230",
		.probe = tbs5230_probe,
		.disconnect = dvb_usb_device_exit,
		.id_table	= tbs5230_table,

};
static int __init tbs5230_module_init(void)
{
	int ret = usb_register(&tbs5230_driver);
	if(ret)
		err("usb_register failed.Error number %d",ret);

	return ret;
}

static void __exit tbs5230_module_exit(void)
{
	usb_deregister(&tbs5230_driver);
}

module_init(tbs5230_module_init);
module_exit(tbs5230_module_exit);

MODULE_AUTHOR("TBSDTV,Davin<Davin@tbsdtv.com>");
MODULE_DESCRIPTION("Turbosight TBS5230 drivers");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
	
