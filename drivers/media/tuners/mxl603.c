#include "mxl603_priv.h"

static const struct dvb_tuner_ops si2168_ops;

static int reg_read(struct i2c_client *client,u8 reg_addr,u8 *val)
{
	int ret;
	u8 reg_buf[2] = {0xFB,reg_addr};

	struct i2c_msg msg[] = {
			{.addr = client->addr,.flags = 0 , .buf = reg_buf, .len = 2},
			{.addr = client->addr, .flags = I2C_M_RD, .buf = val, .len = 1},

	};

	ret = i2c_transfer(client->adapter,msg,2);
	
	if(ret!=2)
	{
		pr_warn("i2c read reg error !!");
		if (ret < 0)
			return ret;
		else
			return -EREMOTEIO;
	}
	return 0 ;	

}

static int reg_write(struct i2c_client *client,u8 reg_addr,u8 val)
{
	int ret;
	u8 buf[2]={reg_addr,val};
	struct i2c_msg msg ={.addr = client->addr, .flags = 0, .buf = buf, .len = 2}; 

	if((ret = i2c_transfer (client->adapter,&msg,1))!=1){
		pr_warn("%s: i2c write error (addr 0x%02x, ret == %i)\n",
			__func__, reg_addr, ret);
		return -EREMOTEIO;
	}
	return 0;
}

static int mxl603_ctrl_programRegisters(struct i2c_client *client, PMXL603_REG_CTRL_INFO_T ctrlRegInfoPtr)
{
	struct mxl603_dev* dev = i2c_get_clientdata(client);
	int ret = 0;
	u8 tmp =0 ;
	u16 i = 0;
		
	while (!ret)
	{
		if ((ctrlRegInfoPtr[i].regAddr == 0) && (ctrlRegInfoPtr[i].mask == 0) && (ctrlRegInfoPtr[i].data == 0)) break;

		// Check if partial bits of register were updated
		if (ctrlRegInfoPtr[i].mask != 0xFF)  
		{
			ret = reg_read(dev->client,ctrlRegInfoPtr[i].regAddr, (int)&tmp);
			if (ret) break;;
		}

		tmp &= (u8) ~ctrlRegInfoPtr[i].mask;
		tmp |= (u8) ctrlRegInfoPtr[i].data;

		ret = reg_write(dev->client,ctrlRegInfoPtr[i].regAddr, tmp);
		if (ret) break;

		i++;
	}


	return ret;

}

static int mxl603_init(struct dvb_frontend *fe)
{
	struct i2c_client*client = fe->tuner_priv;
	struct mxl603_dev*dev = i2c_get_clientdata(client);

	int ret;
	u8 readData;
	u8 dfeRegData;
	u8 control = 0;
	u16 ifFcw;
	MXL603_REG_CTRL_INFO_T MxL603_OverwriteDefaults[] = 
	{
	  {0x14, 0xFF, 0x13},
	  {0x6D, 0xFF, 0x8A},
	  {0x6D, 0xFF, 0x0A},
	  {0xDF, 0xFF, 0x19},
	  {0x45, 0xFF, 0x1B},
	  {0xA9, 0xFF, 0x59},
	  {0xAA, 0xFF, 0x6A},
	  {0xBE, 0xFF, 0x4C},
	  {0xCF, 0xFF, 0x25},
	  {0xD0, 0xFF, 0x34},
	  {0x77, 0xFF, 0xE7},
	  {0x78, 0xFF, 0xE3},
	  {0x6F, 0xFF, 0x51},
	  {0x7B, 0xFF, 0x84},
	  {0x7C, 0xFF, 0x9F},
	  {0x56, 0xFF, 0x41},
	  {0xCD, 0xFF, 0x64},
	  {0xC3, 0xFF, 0x2C},
	  {0x9D, 0xFF, 0x61},
	  {0xF7, 0xFF, 0x52},
	  {0x58, 0xFF, 0x81},
	  {0x00, 0xFF, 0x01},
	  {0x62, 0xFF, 0x02},
	  {0x00, 0xFF, 0x00},
	  {0,	 0,    0}
	};

	 /*reset the chip*/
	ret = reg_write(dev->client,AIC_RESET_REG, 0x00);

	ret = mxl603_ctrl_programRegisters(client,MxL603_OverwriteDefaults);
	ret |= reg_write(dev->client,0x00,0x01);
	ret |= reg_read(dev->client,0x31,&readData);
	if(ret)
		goto err;
	
	readData &= 0x2F;
	readData |= 0xD0;

	ret = reg_write(dev->client,0x31,readData);
	ret |= reg_write(dev->client,0x0,0x0);

	/*If Single supply 3.3v is used */
	ret |= reg_write(dev->client,MAIN_REG_AMP,0x04);

	/**setup xtal**/
	
	control = ((dev->xtalFreqSel << 5) | (dev->xtalCap & 0x1F));  
	control |= (1 << 7);
	ret = reg_write(dev->client, XTAL_CAP_CTRL_REG, control);
		
	// program Clock out div & Xtal sharing
	ret |= reg_write(dev->client, XTAL_ENABLE_DIV_REG, 0x40); 
	
	// Main regulator re-program
	ret |= reg_write(client, MAIN_REG_AMP, 0x14);
	if(ret)
		goto err;

	/*setup IF out*/
	ret = reg_read(client,IF_FREQ_SEL_REG, &readData);
	if(dev->manualIFFreqSet)
	{
		// IF out manual setting : bit<5>
		readData |= 0x20;
		ret = reg_write(client, IF_FREQ_SEL_REG, readData);

		// Manual IF freq set
		ifFcw = (u16)(dev->manualIFOutFreqInKHz * 8192 / 216000);
		control = (ifFcw & 0xFF); // Get low 8 bit 
		ret |= reg_write(client, IF_FCW_LOW_REG, control); 

		control = ((ifFcw >> 8) & 0x0F); // Get high 4 bit 
		ret |= reg_write(client, IF_FCW_HIGH_REG, control);
	}
	else
	{
		readData &= 0xC0;
		// IF Freq <4:0>
		readData |= dev->ifOutFreq;
		ret |= reg_write(client, IF_FREQ_SEL_REG, readData);
	}

	// Set spectrum invert, gain level and IF path 
	// Spectrum invert indication is bit<7:6>

	// Gain level is bit<3:0> 
	control = (dev->gainLevel & 0x0F);
	control |= 0x20; // Enable IF out
	ret |= reg_write(client, IF_PATH_GAIN_REG, control);

	if(ret)
		goto err;

	/*5.setup AGC  agctye :0 self ;1:externel */
	// AGC selecton <3:2> and mode setting <0>
	ret = reg_read(dev->client, AGC_CONFIG_REG, &readData); 
	readData &= 0xF2; // Clear bits <3:2> & <0>
	readData = (u8) (readData | (dev->agcType << 2) | 0x01);
	ret |= reg_write(dev->client, AGC_CONFIG_REG, readData);
	
	// AGC set point <6:0>
	ret |= reg_read(dev->client, AGC_SET_POINT_REG, &readData);
	readData &= 0x80; // Clear bit <6:0>
	readData |= dev->setagcPoint;
	ret |= reg_write(dev->client, AGC_SET_POINT_REG, readData);
	
	// AGC Polarity <4>
	ret |= reg_read(dev->client, AGC_FLIP_REG, &readData);
	readData &= 0xEF; // Clear bit <4>
	readData |= (0 << 4);
	ret |= reg_write(dev->client, AGC_FLIP_REG, readData);

	if(ret)
		goto err;
 
	
	dev->active = true;
	return ret;
err:
	pr_err("%s_failed = %d",__FUNCTION__,ret);
	return ret;
}

static int mxl603_set_params(struct dvb_frontend *fe)
{
	struct i2c_client *client =fe->tuner_priv;
	struct mxl603_dev *dev = i2c_get_clientdata(client);
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;

	int ret;
	u8 signalMode,regData,agcData,dfeTuneData,dfeCdcData;
	u32 freq = 0;
	u8 tmp;
	
	pr_info("delivery_system=%d frequency=%d\n",
			c->delivery_system, c->frequency);
	if (!dev->active) {
		ret = -EAGAIN;
		goto err;
	}
	MXL603_REG_CTRL_INFO_T MxL603_DigitalDvbc[] = 
	{
	  {0x0C, 0xFF, 0x00},
	  {0x13, 0xFF, 0x04},
	  {0x53, 0xFF, 0x7E},
	  {0x57, 0xFF, 0x91},
	  {0x5C, 0xFF, 0xB1},
	  {0x62, 0xFF, 0xF2},
	  {0x6E, 0xFF, 0x03},
	  {0x6F, 0xFF, 0xD1},
	  {0x87, 0xFF, 0x77},
	  {0x88, 0xFF, 0x55},
	  {0x93, 0xFF, 0x33},
	  {0x97, 0xFF, 0x03},
	  {0xBA, 0xFF, 0x40},
	  {0x98, 0xFF, 0xAF},
	  {0x9B, 0xFF, 0x20},
	  {0x9C, 0xFF, 0x1E},
	  {0xA0, 0xFF, 0x18},
	  {0xA5, 0xFF, 0x09},
	  {0xC2, 0xFF, 0xA9},
	  {0xC5, 0xFF, 0x7C},
	  {0xCD, 0xFF, 0x64},
	  {0xCE, 0xFF, 0x7C},
	  {0xD5, 0xFF, 0x05},
	  {0xD9, 0xFF, 0x00},
	  {0xEA, 0xFF, 0x00},
	  {0xDC, 0xFF, 0x1C},
	  {0,	 0,    0}
	};
	
	 MXL603_REG_CTRL_INFO_T MxL603_DigitalIsdbtAtsc[] = 
	{
	  {0x0C, 0xFF, 0x00},
	  {0x13, 0xFF, 0x04},
	  {0x53, 0xFF, 0xFE},
	  {0x57, 0xFF, 0x91},
	  {0x62, 0xFF, 0xC2},
	  {0x6E, 0xFF, 0x01},
	  {0x6F, 0xFF, 0x51},
	  {0x87, 0xFF, 0x77},
	  {0x88, 0xFF, 0x55},
	  {0x93, 0xFF, 0x22},
	  {0x97, 0xFF, 0x02},
	  {0xBA, 0xFF, 0x30},
	  {0x98, 0xFF, 0xAF},
	  {0x9B, 0xFF, 0x20},
	  {0x9C, 0xFF, 0x1E},
	  {0xA0, 0xFF, 0x18},
	  {0xA5, 0xFF, 0x09},
	  {0xC2, 0xFF, 0xA9},
	  {0xC5, 0xFF, 0x7C},
	  {0xCD, 0xFF, 0xEB},
	  {0xCE, 0xFF, 0x7F},
	  {0xD5, 0xFF, 0x03},
	  {0xD9, 0xFF, 0x04},
	  {0,	 0,    0}
	};

	switch (c->delivery_system) {
	case SYS_ATSC:
		 signalMode = 1;
		ret = mxl603_ctrl_programRegisters(client, MxL603_DigitalIsdbtAtsc);
	
		if (dev->ifOutFreqinKHz < HIGH_IF_35250_KHZ)
		{
			// Low power
			ret |= reg_write(dev->client, DIG_ANA_IF_CFG_0, 0xF9);
			ret |= reg_write(dev->client, DIG_ANA_IF_CFG_1, 0x18);
			ret |= reg_write(dev->client, DIG_ANA_IF_PWR, 0xF1);
		}
		else
		{
			// High power
			ret |= reg_write(dev->client, DIG_ANA_IF_CFG_0, 0xD9);
			ret |= reg_write(dev->client, DIG_ANA_IF_CFG_1, 0x16);
			ret |= reg_write(dev->client, DIG_ANA_IF_PWR, 0xB1);
		}
		
		if (MXL603_XTAL_16MHz == dev->xtalFreqSel) tmp = 0x0D;
		if (MXL603_XTAL_24MHz == dev->xtalFreqSel) tmp = 0x0E;
		
		
		ret |= reg_write(dev->client, DFE_CSF_SS_SEL, tmp);
		
		tmp = 0;
		switch(dev->gainLevel)
		{
		case 0x09: tmp = 0x44; break;
		case 0x08: tmp = 0x43; break;
		case 0x07: tmp = 0x42; break;
		case 0x06: tmp = 0x41; break;
		case 0x05: tmp = 0x40; break;
		default: break;
		}
		ret |= reg_write(dev->client, DFE_DACIF_GAIN, tmp);
	
			break;
	case SYS_DVBC_ANNEX_B:
	case SYS_DVBC_ANNEX_A:
	case SYS_DVBC_ANNEX_C:
		if(c->delivery_system == SYS_DVBC_ANNEX_B)signalMode = 3;
		else
			signalMode = 0;
		ret = mxl603_ctrl_programRegisters(dev->client, MxL603_DigitalDvbc);

		if (dev->ifOutFreqinKHz < HIGH_IF_35250_KHZ)
		{
			// Low power
			ret |= reg_write(dev->client, DIG_ANA_IF_CFG_0, 0xFE);
			ret |= reg_write(dev->client, DIG_ANA_IF_CFG_1, 0x10);
		}
		else
		{
			// High power
			ret |= reg_write(dev->client, DIG_ANA_IF_CFG_0, 0xD9);
			ret |= reg_write(dev->client, DIG_ANA_IF_CFG_1, 0x16);
		}

		if (dev->xtalFreqSel == MXL603_XTAL_16MHz) tmp = 0x0D;
		if (dev->xtalFreqSel == MXL603_XTAL_24MHz) tmp = 0x0E;
	

		ret |= reg_write(dev->client, DFE_CSF_SS_SEL, tmp);
			break;
	default:
			ret = -EINVAL;
			goto err;
	}

	// XTAL calibration
	ret |= reg_write(dev->client, XTAL_CALI_SET_REG, 0x00);   
	ret |= reg_write(dev->client, XTAL_CALI_SET_REG, 0x01);

	msleep(50);

	ret = reg_write(dev->client, START_TUNE_REG, 0x00); 
	
	// RF Frequency VCO Band Settings 
	if (c->frequency < 700000000) 
	{
		ret |= reg_write(dev->client, 0x7C, 0x1F);
		if ((signalMode == MXL603_DIG_DVB_C) || (signalMode == MXL603_DIG_J83B)) 
			regData = 0xC1;
		else
			regData = 0x81;

	}
	else 
	{
		ret |= reg_write(dev->client, 0x7C, 0x9F);
		if ((signalMode == MXL603_DIG_DVB_C) || (signalMode == MXL603_DIG_J83B)) 
			regData = 0xD1;
		else
			regData = 0x91;

	}

	ret |= reg_write(dev->client, 0x00, 0x01);
	ret |= reg_write(dev->client, 0x31, regData);
	ret |= reg_write(dev->client, 0x00, 0x00);

	// Bandwidth <7:0>
	
	ret |= reg_write(dev->client, CHAN_TUNE_BW_REG, 0x20);

	/* Calculate RF Channel = DIV(64*RF(Hz), 1E6) */
	freq = (u32)((c->frequency/1000000)*64); 	
	// Set RF  
	ret |= reg_write(dev->client, CHAN_TUNE_LOW_REG, (u8)(freq & 0xFF));
	ret |= reg_write(dev->client, CHAN_TUNE_HI_REG, (u8)((freq >> 8 ) & 0xFF));


	// Power up tuner module
	ret |= reg_write(dev->client, TUNER_ENABLE_REG, 0x01);

	// Start Sequencer settings
	ret |= reg_write(dev->client, PAGE_CHANGE_REG, 0x01); 
	ret |= reg_read(dev->client, DIG_ANA_GINJO_LT_REG, &regData);
	ret |= reg_write(dev->client, PAGE_CHANGE_REG, 0x00); 

	ret |= reg_read(dev->client, 0xB6, &agcData);
	ret |= reg_write(dev->client, PAGE_CHANGE_REG, 0x01); 
	ret |= reg_read(dev->client, 0x60, &dfeTuneData);
	ret |= reg_read(dev->client, 0x5F, &dfeCdcData);

			// Check if LT is enabled
	if ((regData & 0x10) == 0x10)
	{
		// dfe_agc_auto = 0 & dfe_agc_rf_bo_w = 14
		agcData &= 0xBF;
		agcData |= 0x0E;

		// dfe_seq_tune_rf1_bo = 14
		dfeTuneData &= 0xC0;
		dfeTuneData |= 0x0E;

		// dfe_seq_cdc_rf1_bo = 14
		dfeCdcData &= 0xC0;
		dfeCdcData |= 0x0E;
	}
	else
	{
		// dfe_agc_auto = 1 & dfe_agc_rf_bo_w = 0
		agcData |= 0x40;
		agcData &= 0xC0;

		// dfe_seq_tune_rf1_bo = 55
		dfeTuneData &= 0xC0;
		dfeTuneData |= 0x37;

		// dfe_seq_cdc_rf1_bo = 55
		dfeCdcData &= 0xC0;
		dfeCdcData |= 0x37;
	}

	ret |= reg_write(dev->client, 0x60, dfeTuneData); 
	ret |= reg_write(dev->client, 0x5F, dfeCdcData); 
	ret |= reg_write(dev->client, PAGE_CHANGE_REG, 0x00); 
	ret |= reg_write(dev->client, 0xB6, agcData); 

	// Bit <0> 1 : start , 0 : abort calibrations
	ret |= reg_write(dev->client, START_TUNE_REG, 0x01); 

	// Sleep 15 ms
	msleep(15);

	// dfe_agc_auto = 1 
	agcData = (agcData | 0x40);
	ret |= reg_write(dev->client, 0xB6, agcData); 
	if(ret)
		goto err;

	return ret;

err:
	pr_err("failed = %d ",ret);
	return ret;
}

static int mxl603_get_status(struct dvb_frontend *fe,u32*status)
{
	struct i2c_client *client =fe->tuner_priv;
	struct mxl603_dev *dev = i2c_get_clientdata(client);
	int ret;
	u8 regData;
	
	ret = reg_read(dev->client, RF_REF_STATUS_REG, &regData);  

	if((regData & 0x03) == 0x03)
		*status = 1;
	else
		*status = 0;

	return ret;

}

static const struct dvb_tuner_ops mxl603_ops ={
	.info = {
		.name = "MaxLinear tuner MXL603",
		.frequency_min_hz = 44 * MHz,
		.frequency_max_hz = 1002 * MHz,
	},
	.init = mxl603_init,
	.set_params = mxl603_set_params,
	.get_status = mxl603_get_status,

};

static int mxl603_probe(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	struct mxl603_config *cfg = client->dev.platform_data;
	struct dvb_frontend *fe = cfg->fe;
	struct mxl603_dev *dev;
	
	int ret;
	u8 utemp;

	dev = kzalloc(sizeof(*dev),GFP_KERNEL);
	if(!dev){
		ret = -ENOMEM;
		dev_err(&client->dev,"kzalloc failed\n");
		goto err;
	}

	dev->fe = cfg->fe;
	dev->xtalFreqSel = cfg->xtalFreqSel;
	dev->agcType = cfg->agcType;
	dev->ifOutFreq = cfg->ifOutFreq;
	dev->manualIFFreqSet = cfg->manualIFFreqSet;
	dev->manualIFOutFreqInKHz = cfg->manualIFOutFreqInKHz;
	dev->ifOutFreqinKHz = 5000;
	dev->xtalCap = 31;
	dev->gainLevel = 11;
	dev->setagcPoint =66;
	dev->client = client;
	dev->active= false;

	/*check chip answers with correct chip iD*/
	ret = reg_read(dev->client,CHIP_ID_REQ_REG,&utemp);
	if (ret)
		goto err_kfree;
	
	pr_info("chip id = 0x%x \n",utemp);
	
	if(utemp!=0x1){
		ret = -ENODEV;
		goto err_kfree;
	}
	ret = reg_write(dev->client,0x10,0x99);

	ret = reg_read(dev->client,0x10,&utemp)	;

	/**/
	memcpy(&fe->ops.tuner_ops,&mxl603_ops,sizeof(struct dvb_tuner_ops));
	fe->tuner_priv = client;
	i2c_set_clientdata(client, dev);
		
	return 0;


err_kfree:
	kfree(dev);
err:
	pr_err("%s___failed=%d\n",__FUNCTION__, ret);
	return ret;
}

static void mxl603_remove(struct i2c_client *client)
{
	struct mxl603_dev *dev = i2c_get_clientdata(client);

	kfree(dev);
}

static const struct i2c_device_id mxl603_id_table[] = {
	{"mxl603", 0},
	{}
};
MODULE_DEVICE_TABLE(i2c, mxl603_id_table);

static struct i2c_driver mxl603_driver = {
	.driver = {
		.name	= "mxl603",
	},
	.probe		= mxl603_probe,
	.remove		= mxl603_remove,
	.id_table	= mxl603_id_table,
};

module_i2c_driver(mxl603_driver);

MODULE_AUTHOR("Davin <smiledavin@gmail.com>");
MODULE_DESCRIPTION("Panasonic MN88436 ATSC/QAMB demodulator driver");
MODULE_LICENSE("GPL");
