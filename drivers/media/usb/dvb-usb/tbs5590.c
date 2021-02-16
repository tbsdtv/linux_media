/*
 * TurboSight TBS 5590  driver
 *
 * Copyright (c) 2017 Davin <smailedavin@hotmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation, version 2.
 *
 */

#include <linux/version.h>
#include "tbs5590.h"
#include "si2183.h"
#include "si2157.h"
#include "av201x.h"
#include "tbs_priv.h"

#define TBS5590_READ_MSG 0
#define TBS5590_WRITE_MSG 1

#define TBS5590_RC_QUERY (0x1a00)
#define TBS5590_VOLTAGE_CTRL (0x1800)


#define ecp3_addr 0x50
#define ecp3_base_addr 0x8000
#define ecp3_lnb 0x50
#define ecp3_rfctrl 0x48
#define ecp3_tsctrl 0x38
#define ecp3_ledctrl 0x58

struct tbs5590_state {
	struct i2c_client *i2c_client_demod;
	struct i2c_client *i2c_client_tuner; 
	u32 last_key_pressed;
};

static struct av201x_config tbs5590_av201x_cfg = {
	.i2c_address = 0x62,
	.id          = ID_AV2018,
	.xtal_freq   = 27000,
};

/* debug */
static int dvb_usb_tbs5590_debug;
module_param_named(debug, dvb_usb_tbs5590_debug, int, 0644);
MODULE_PARM_DESC(debug, "set debugging level (1=info 2=xfer (or-able))." 
							DVB_USB_DEBUG_STATUS);

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static int tbs5590_op_rw(struct usb_device *dev, u8 request, u16 value,
				u16 index, u8 * data, u16 len, int flags)
{
	int ret;
	void *u8buf;

	unsigned int pipe = (flags == TBS5590_READ_MSG) ?
			usb_rcvctrlpipe(dev, 0) : usb_sndctrlpipe(dev, 0);
	u8 request_type = (flags == TBS5590_READ_MSG) ? USB_DIR_IN : USB_DIR_OUT;
	u8buf = kmalloc(len, GFP_KERNEL);
	if (!u8buf)
		return -ENOMEM;

	if (flags == TBS5590_WRITE_MSG)
		memcpy(u8buf, data, len);
	ret = usb_control_msg(dev, pipe, request, request_type | USB_TYPE_VENDOR,
				value, index , u8buf, len, 2000);

	if (flags == TBS5590_READ_MSG)
		memcpy(data, u8buf, len);
	kfree(u8buf);
	return ret;
}

/* I2C */
static int tbs5590_i2c_transfer(struct i2c_adapter *adap, 
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

		tbs5590_op_rw(d->udev, 0x90, 0, 0,
					buf6, 3, TBS5590_WRITE_MSG);
		//msleep(5);
		tbs5590_op_rw(d->udev, 0x91, 0, 0,
					inbuf, buf6[0], TBS5590_READ_MSG);
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
				tbs5590_op_rw(d->udev, 0x80, 0, 0,
					buf6, msg[0].len+2, TBS5590_WRITE_MSG);
			} else {
				buf6[0] = msg[0].len;//length
				buf6[1] = (msg[0].addr<<1) | 0x01;//addr
				tbs5590_op_rw(d->udev, 0x93, 0, 0,
						buf6, 2, TBS5590_WRITE_MSG);
				//msleep(5);
				tbs5590_op_rw(d->udev, 0x91, 0, 0,
					inbuf, buf6[0], TBS5590_READ_MSG);
				memcpy(msg[0].buf, inbuf, msg[0].len);
			}
			//msleep(3);
		break;
		case (TBS5590_VOLTAGE_CTRL):
			buf6[0] = 3;
			buf6[1] = msg[0].buf[0];
			tbs5590_op_rw(d->udev, 0x8a, 0, 0,
					buf6, 2, TBS5590_WRITE_MSG);
			break;
		case (TBS5590_RC_QUERY):
			tbs5590_op_rw(d->udev, 0xb8, 0, 0,
					buf6, 4, TBS5590_READ_MSG);
			msg[0].buf[0] = buf6[2];
			msg[0].buf[1] = buf6[3];
			//msleep(3);
			//info("TBS5590_RC_QUERY %x %x %x %x\n",
			//		buf6[0],buf6[1],buf6[2],buf6[3]);
			break;
		}

		break;
	}

	mutex_unlock(&d->i2c_mutex);
	return num;
}

static int ecp3_read(struct i2c_adapter *adap,unsigned char chipaddr,u16 regAddr,
							unsigned char num,unsigned char *buf)
{
	struct dvb_usb_device *d = i2c_get_adapdata(adap);

	unsigned char reg[2]={(regAddr>>8)&0xff,regAddr&0xff};
	unsigned char tmp[8];

	tmp[0] = 2+2;   //lenth
	tmp[1] = chipaddr; //chipaddr
	tmp[2] = 0x6  ;    //ecp3 register addr
	tmp[3] = reg[0];
	tmp[4] = reg[1];
	tbs5590_op_rw(d->udev, 0x80, 0, 0,
		tmp, 5, TBS5590_WRITE_MSG);

	tmp[0] = 1+2;   //lenth
	tmp[1] = chipaddr; //chipaddr
	tmp[2] = 0x3 ;     //ecp3 register addr
	tmp[3] = 0x88;    //read flag
	tbs5590_op_rw(d->udev, 0x80, 0, 0,
		tmp, 4, TBS5590_WRITE_MSG);

//	read	
	tmp[0] = num;//lenth
	tmp[1] = chipaddr;//demod addr
	//register
	tmp[2] = 0x8;
	
	tbs5590_op_rw(d->udev, 0x90, 0, 0,
				tmp, 3, TBS5590_WRITE_MSG);
	//msleep(5);
	tbs5590_op_rw(d->udev, 0x91, 0, 0,
				buf, tmp[0], TBS5590_READ_MSG);


	return 0;
}

static int ecp3_write(struct i2c_adapter *adap,unsigned char chipaddr,u16 regAddr,
							unsigned char num,unsigned char *buf)
{
	struct dvb_usb_device *d = i2c_get_adapdata(adap);
	int i;
	unsigned char reg[2]={(regAddr>>8)&0xff,regAddr&0xff};
	unsigned char tmp[12];

	tmp[0] = 2+2;   //lenth
	tmp[1] = chipaddr; //chipaddr
	tmp[2] = 0x6 ;     //ecp3 register addr
	tmp[3] = reg[0];
	tmp[4] = reg[1];
	tbs5590_op_rw(d->udev, 0x80, 0, 0,
		tmp, 5, TBS5590_WRITE_MSG);


	tmp[0] = num+2;   //lenth
	tmp[1] = chipaddr; //chipaddr
	tmp[2] = 0x8 ;     //ecp3 register addr
	for(i=0; i<num;i++)
	{
	 tmp[3+i]=buf[i];
	}
	tbs5590_op_rw(d->udev, 0x80, 0, 0,
		tmp, tmp[0]+3 , TBS5590_WRITE_MSG);	

	tmp[0] = 1+2;   //lenth
	tmp[1] = chipaddr; //chipaddr
	tmp[2] = 0x3 ;     //ecp3 register addr
	tmp[3] = 0x80;    //write flag
	tbs5590_op_rw(d->udev, 0x80, 0, 0,
		tmp, 4, TBS5590_WRITE_MSG);

	return 0;
}
static u32 tbs5590_i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C;
}

static struct i2c_algorithm tbs5590_i2c_algo = {
	.master_xfer = tbs5590_i2c_transfer,
	.functionality = tbs5590_i2c_func,
};

static int tbs5590_set_voltage(struct dvb_frontend *fe, 
						enum fe_sec_voltage voltage)
{
	struct dvb_usb_adapter *udev_adap =
		(struct dvb_usb_adapter *)(fe->dvb->priv);
	unsigned char iobuffer[8];
	
	ecp3_read(&udev_adap->dev->i2c_adap,ecp3_addr,(ecp3_base_addr+ecp3_lnb),8,iobuffer);
	switch(voltage){
	     case SEC_VOLTAGE_OFF:
		 		iobuffer[2] = (iobuffer[2]&0xfe)|0x1;
		 	break;
		 case SEC_VOLTAGE_13:
		 		iobuffer[2] = iobuffer[2]&0xfe;
				iobuffer[1] = iobuffer[1]&0xfe;
		 	break;
		 case SEC_VOLTAGE_18:
		 		iobuffer[2] = iobuffer[2]&0xfe;
				iobuffer[1] = (iobuffer[1]&0xfe)|0x1;
		 	break;
		default:
			return -EINVAL;
	}

	ecp3_write(&udev_adap->dev->i2c_adap,ecp3_addr,(ecp3_base_addr+ecp3_lnb),8,iobuffer);
	
	return 0;
}

static void tbs5590_RF_ctrl(struct i2c_adapter *i2c,u8 rf_in,u8 flag)
{
	unsigned char iobuffer[8];
	
	ecp3_read(i2c,ecp3_addr,(ecp3_base_addr+ecp3_rfctrl),8,iobuffer);
	
	if(flag)
		iobuffer[0] = (iobuffer[0]&0xfe)|0x1;
	else
		iobuffer[0] = iobuffer[0]&0xfe;
	
	ecp3_write(i2c,ecp3_addr,(ecp3_base_addr+ecp3_rfctrl),8,iobuffer);

	return ;
}
static void tbs5590_TS_ctrl(struct i2c_adapter*i2c,u8 flag)
{
	unsigned char iobuffer[8];
	
	ecp3_read(i2c,ecp3_addr,(ecp3_base_addr+ecp3_tsctrl),8,iobuffer);
	
	if(flag)
		iobuffer[2] = (iobuffer[2]&0xfe)|0x1;
	else
		iobuffer[2] = iobuffer[2]&0xfe;
	
	ecp3_write(i2c,ecp3_addr,(ecp3_base_addr+ecp3_tsctrl),8,iobuffer);

	return ;

}
static void tbs5590_LED_ctrl(struct i2c_adapter*i2c,u8 flag)
{
	unsigned char iobuffer[8];
	
	ecp3_read(i2c,ecp3_addr,(ecp3_base_addr+ecp3_ledctrl),8,iobuffer);
	switch(flag){
		default:
		case 2:
			iobuffer[0] = (iobuffer[0]&0xE0)|0x1;
			break;
		case 1:
			iobuffer[0] = (iobuffer[0]&0xE0)|0x4;
			break;
		case 4:
		case 6:
		case 7:
			iobuffer[0] = (iobuffer[0]&0xE0)|0x2;
			break;
		case 5:
			iobuffer[0] = (iobuffer[0]&0xE0)|0x8;
			break;
		case 8:
			iobuffer[0] = (iobuffer[0]&0xE0)|0x10;
			break;

	}
	ecp3_write(i2c,ecp3_addr,(ecp3_base_addr+ecp3_ledctrl),8,iobuffer);

	return ;
}
static int tbs5590_read_mac_address(struct dvb_usb_device *d, u8 mac[6])
{
	int i,ret;
	u8 ibuf[3] = {0, 0,0};
	u8 eeprom[256], eepromline[16];

	for (i = 0; i < 256; i++) {
		ibuf[0]=1;//lenth
		ibuf[1]=0xa0;//eeprom addr
		ibuf[2]=i;//register
		ret = tbs5590_op_rw(d->udev, 0x90, 0, 0,
					ibuf, 3, TBS5590_WRITE_MSG);
		ret = tbs5590_op_rw(d->udev, 0x91, 0, 0,
					ibuf, 1, TBS5590_READ_MSG);
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

static struct dvb_usb_device_properties tbs5590_properties;

static struct tbs_cfg tbs5590_tbs_cfg = {
		.adr = 0x88,
		.flag = 1,		
		.rf = 0,			
		.TS_switch = tbs5590_TS_ctrl,
		.LED_switch = tbs5590_LED_ctrl,
			
		.write_properties = NULL , 
		.read_properties = NULL ,

} ;

static int tbs5590_frontend_attach(struct dvb_usb_adapter *adap)
{
	struct dvb_usb_device *d = adap->dev;
	struct tbs5590_state *st = d->priv;
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
	si2183_config.RF_switch = tbs5590_RF_ctrl;
	si2183_config.TS_switch = tbs5590_TS_ctrl;
	si2183_config.LED_switch = tbs5590_LED_ctrl;
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

	if (dvb_attach(av201x_attach, adap->fe_adap[0].fe2, &tbs5590_av201x_cfg,
			adapter) == NULL) {
		return -ENODEV;
	}
	else {
		buf[0] = 1;
		buf[1] = 0;
		tbs5590_op_rw(d->udev, 0x8a, 0, 0,
					buf, 2, TBS5590_WRITE_MSG);
		
		adap->fe_adap[0].fe2->ops.set_voltage = tbs5590_set_voltage;
		
	}



	buf[0] = 0;
	buf[1] = 0;
	tbs5590_op_rw(d->udev, 0xb7, 0, 0,
			buf, 2, TBS5590_WRITE_MSG);
	buf[0] = 8;
	buf[1] = 1;
	tbs5590_op_rw(d->udev, 0x8a, 0, 0,
			buf, 2, TBS5590_WRITE_MSG);

	buf[0] = 1+2;   //lenth
	buf[1] = 0x50; //chipaddr
	buf[2] = 0x2;      //ecp3 register addr
	buf[3] = 0x55;
	tbs5590_op_rw(d->udev, 0x80, 0, 0,
		buf, 4, TBS5590_WRITE_MSG);

	//	read	
	buf[0] = 2;//lenth
	buf[1] = 0x50;//demod addr
	//register
	buf[2] = 0x0;
	
	tbs5590_op_rw(d->udev, 0x90, 0, 0,
				buf, 3, TBS5590_WRITE_MSG);
	//msleep(5);
	tbs5590_op_rw(d->udev, 0x91, 0, 0,
				buf, buf[0], TBS5590_READ_MSG);
	
	

	deb_xfer("Get ecp3ID High Bit 0x%x  Low Bit 0x%x \n",buf[0],buf[1]);
	
	strlcpy(adap->fe_adap[0].fe->ops.info.name,d->props.devices[0].name,52);
	strcat(adap->fe_adap[0].fe->ops.info.name," DVB-T/T2/C/C2/ISDB-T");
	strlcpy(adap->fe_adap[0].fe2->ops.info.name,d->props.devices[0].name,52);
	strcat(adap->fe_adap[0].fe2->ops.info.name," DVB-S/S2/S2X");

	return 0;
}

static int tbs5590_ASI_attach(struct dvb_usb_adapter *adap)
{
	struct dvb_usb_device *u = adap->dev;

	adap->fe_adap[0].fe = dvb_attach(tbs_attach,&u->i2c_adap, &tbs5590_tbs_cfg,0);
			
	if ( adap->fe_adap[0].fe == NULL) {
		return -ENODEV;
	}
	
	strlcpy(adap->fe_adap[0].fe->ops.info.name,u->props.devices[0].name,52);
	strcat(adap->fe_adap[0].fe->ops.info.name," ASI-IN");

	return 0;

}

static struct usb_device_id tbs5590_table[] = {
	{USB_DEVICE(0x734c, 0x5590)},
	{ }
};

MODULE_DEVICE_TABLE(usb, tbs5590_table);

static int tbs5590_load_firmware(struct usb_device *dev,
			const struct firmware *frmwr)
{
	u8 *b, *p;
	int ret = 0, i;
	u8 reset;
	const struct firmware *fw;
	switch (dev->descriptor.idProduct) {
	case 0x5521:
		ret = request_firmware(&fw, tbs5590_properties.firmware, &dev->dev);
		if (ret != 0) {
			err("did not find the firmware file. (%s) "
			"Please see linux/Documentation/dvb/ for more details "
			"on firmware-problems.", tbs5590_properties.firmware);
			return ret;
		}
		break;
	default:
		fw = frmwr;
		break;
	}
	info("start downloading TBS5590 firmware");
	p = kmalloc(fw->size, GFP_KERNEL);
	reset = 1;
	/*stop the CPU*/
	tbs5590_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1, TBS5590_WRITE_MSG);
	tbs5590_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1, TBS5590_WRITE_MSG);

	if (p != NULL) {
		memcpy(p, fw->data, fw->size);
		for (i = 0; i < fw->size; i += 0x40) {
			b = (u8 *) p + i;
			if (tbs5590_op_rw(dev, 0xa0, i, 0, b , 0x40,
					TBS5590_WRITE_MSG) != 0x40) {
				err("error while transferring firmware");
				ret = -EINVAL;
				break;
			}
		}
		/* restart the CPU */
		reset = 0;
		if (ret || tbs5590_op_rw(dev, 0xa0, 0x7f92, 0, &reset, 1,
					TBS5590_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}
		if (ret || tbs5590_op_rw(dev, 0xa0, 0xe600, 0, &reset, 1,
					TBS5590_WRITE_MSG) != 1) {
			err("could not restart the USB controller CPU.");
			ret = -EINVAL;
		}

		msleep(100);
		kfree(p);
	}
	return ret;
}

static struct dvb_usb_device_properties tbs5590_properties = {
	.caps = DVB_USB_IS_AN_I2C_ADAPTER,
	.usb_ctrl = DEVICE_SPECIFIC,
	.firmware = "dvb-usb-id5590.fw",
	.size_of_priv = sizeof(struct tbs5590_state),
	.no_reconnect = 1,

	.i2c_algo = &tbs5590_i2c_algo,

	.generic_bulk_ctrl_endpoint = 0x81,
	/* parameter for the MPEG2-data transfer */
	.num_adapters = 2,
	.download_firmware = tbs5590_load_firmware,
	.read_mac_address = tbs5590_read_mac_address,
	.adapter = {{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbs5590_frontend_attach,
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
		},},
			
	},{
		.num_frontends = 1,
		.fe = {{
			.frontend_attach = tbs5590_ASI_attach,
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
		}}
}},

	.num_device_descs = 1,
	.devices = {
		{"TurboSight TBS 5590",
			{&tbs5590_table[0], NULL},
			{NULL},
		}
	}
};

static int tbs5590_probe(struct usb_interface *intf,
		const struct usb_device_id *id)
{
	if (0 == dvb_usb_device_init(intf, &tbs5590_properties,
			THIS_MODULE, NULL, adapter_nr)) {
		return 0;
	}
	return -ENODEV;
}

static void tbs5590_disconnect(struct usb_interface *intf)
{
#if 0
	struct dvb_usb_device *d = usb_get_intfdata(intf);
	struct tbs5590_state *st = d->priv;
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

static struct usb_driver tbs5590_driver = {
	.name = "tbs5590",
	.probe = tbs5590_probe,
	.disconnect = tbs5590_disconnect,
	.id_table = tbs5590_table,
};

static int __init tbs5590_module_init(void)
{
	int ret =  usb_register(&tbs5590_driver);
	if (ret)
		err("usb_register failed. Error number %d", ret);

	return ret;
}

static void __exit tbs5590_module_exit(void)
{
	usb_deregister(&tbs5590_driver);
}

module_init(tbs5590_module_init);
module_exit(tbs5590_module_exit);

MODULE_AUTHOR("Davin  <smiledavin@hotmail.com>");
MODULE_DESCRIPTION("TurboSight TBS 5590 driver");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");
