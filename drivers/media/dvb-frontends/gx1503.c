#include "gx1503_priv.h"

static int GX1503_100Log(int iNumber_N)
{
	int iLeftMoveCount_M = 0;
	int iChangeN_Y = 0;
	int iBuMaY_X = 0;
	int iReturn_value = 0;
	int iTemp = 0, iResult = 0, k = 0;

	iChangeN_Y = iNumber_N;
	for(iLeftMoveCount_M=0; iLeftMoveCount_M<16; iLeftMoveCount_M++)
	{
		if (iChangeN_Y >= 0x8000)
			break;
		else
			iChangeN_Y = iNumber_N << iLeftMoveCount_M;
	}
	iBuMaY_X = 65536 - iChangeN_Y;	
	k = iBuMaY_X * 10000  /65536;		
	iTemp = k + (k*k)/20000 + ((k*k/10000)*(k*33/100))/10000 + ((k*k/100000)*(k*k/100000))/400;
	iResult = 48165 - (iTemp * 10000 / 23025);	
	k = iResult - 3010 * (iLeftMoveCount_M - 1);
	iReturn_value = (k/100);
	
	return iReturn_value;
}

static int GX1503_WriteRegWithMask(struct i2c_client *client,unsigned int regAddr,unsigned int value,unsigned int bit_H,unsigned int bit_L)
{
	struct gx1503_dev *dev = i2c_get_clientdata(client);
	unsigned int value_wid     ;
	unsigned int mask          ;
	unsigned int value_mask    ;
	unsigned int readback_value;

	value_wid = bit_H - bit_L + 1;
	if(value_wid==8)
		mask = 0xff;
	else
		mask = (1<<value_wid)-1;
	value_mask = (value & mask);
	regmap_read(dev->regmap,regAddr,&readback_value);
	readback_value = (readback_value & (~(mask << bit_L))) | (value_mask << bit_L);
	regmap_write(dev->regmap,regAddr,readback_value);

	return 0;	
	

}
static int gx1503_init(struct dvb_frontend *fe)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct gx1503_dev *dev = i2c_get_clientdata(client);
	int ret,temp,i ;
	const struct firmware *fw;
	const char *fw_name = GX1503_FIRMWARE;

	ret = regmap_read(dev->regmap,0xf5,&temp);
	ret = regmap_write(dev->regmap,0xf5,temp&(~0x10));
	if(ret)
		goto err;
	ret = regmap_read(dev->regmap,0xf7,&temp);
	ret = regmap_write(dev->regmap,0xf7,temp&0xFB);
	ret = regmap_read(dev->regmap,0xf5,&temp);
	ret = regmap_write(dev->regmap,0xf5,(temp&0xCF)|0x10);
	ret = regmap_read(dev->regmap,0xf5,&temp);
	ret = regmap_write(dev->regmap,0xf5,temp|0x04);
	ret = regmap_read(dev->regmap,0xf5,&temp);
	ret = regmap_write(dev->regmap,0xf5,temp&(~0x04));
	if(ret)
		goto err;
	if(!dev->fw_loaded){
	/*download FW*/
	ret = request_firmware(&fw,fw_name, &client->dev);
	if(ret){
		dev_err(&client->dev,
				"firmware file '%s' not found\n",
				fw_name);

		goto err_release_firmware;

	}
	
	dev_info(&client->dev, "downloading firmware from file '%s'\n",
			fw_name);
	for(i = 0;i<fw->size;i++)
		 ret = regmap_write(dev->regmap,0xF6,fw->data[i]);

	release_firmware(fw);
	
	dev->fw_loaded = true;
	}

	ret = regmap_read(dev->regmap,0xf7,&temp);
	ret = regmap_write(dev->regmap,0xf7,temp|0x10);
	if(ret)
		goto err;

	dev->active = true;
	
	return 0;
	
err_release_firmware:
	release_firmware(fw);

err:
	dev_dbg(&client->dev,"failed = %d\n",ret);
	return ret;	
}

static int GX1503_Set_Clock(struct i2c_client *client, int fs)
{
	struct gx1503_dev *dev = i2c_get_clientdata(client);
	int ret;
	unsigned int temp;
	unsigned int SysClk_div_L;
	unsigned int SysClk_div_M;
	unsigned int SysClk_div_H;
	
	temp = (unsigned int)(fs*1000/4);
	SysClk_div_L = (temp & 0xff);
	SysClk_div_M = ((temp>>8)& 0xff);
	SysClk_div_H = ((temp>>16)& 0xff);

	ret = regmap_write(dev->regmap,0x05,SysClk_div_L);
	ret |= regmap_write(dev->regmap,0x06,SysClk_div_M);
	ret |= regmap_write(dev->regmap,0x07,SysClk_div_H);
	if(ret)
		goto err;

	return 0;

err:
	dev_dbg(&client->dev,"set clock failed = %d\n",ret);
	return ret;

}

static int GX1503_Set_BandWidth(struct i2c_client *client,int Band)
{
	struct gx1503_dev *dev = i2c_get_clientdata(client);
	unsigned int BW;
	int ret, fs ;
	int fs_H,fs_M,fs_L;
	int INT_PARM;
	BW = Band;
	fs = (int)(3780000 * BW / 8);
	fs_L = fs & 0xff;
	fs_M = (fs>>8) & 0xff;
	if(BW ==8)
		fs_H = ((fs>>16) & 0x7f);
	else
		fs_H = ((fs>>16) & 0x7f) | 0x80;
	
	ret = regmap_write(dev->regmap,INT_FREQ_L,fs_L);
	ret = regmap_write(dev->regmap,INT_FREQ_M,fs_M);
	ret = regmap_write(dev->regmap,INT_FREQ_H,fs_H);
	INT_PARM = (int)(8 / BW * 128);
	ret = regmap_write(dev->regmap,cfg_int_parm,INT_PARM);
	if(ret)
		goto err;

	return 0;

err:
	dev_dbg(&client->dev,"set clock failed = %d\n",ret);
	return ret;

}

static int GX1503_Set_IntFrq(struct i2c_client *client,int int_frq, int fs)
{
	struct gx1503_dev *dev = i2c_get_clientdata(client);
	int temp,ret;
	int IF_freq_L;
	int IF_freq_H;
	
	temp = (int)(int_frq*1000/1024);
	IF_freq_L = (temp& 0xff);
	IF_freq_H = ((temp>>8)& 0xff);
	
	ret = regmap_write(dev->regmap,IF_FREQ_L,IF_freq_L);
	ret = regmap_write(dev->regmap,IF_FREQ_H,IF_freq_H);
	if(ret)
		goto err;

	return 0;

err:
	dev_dbg(&client->dev,"set intfreq failed = %d\n",ret);
	return ret;

}
static int gx1503_set_frontend(struct dvb_frontend *fe)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct gx1503_dev *dev = i2c_get_clientdata(client);
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret,temp;
	int bandwidth,fs;
		
	dev_dbg(&client->dev,
			" modulation=%u frequency=%u bandwidth_hz=%u \n",
			 c->modulation, c->frequency,c->bandwidth_hz);

	 
			
	if(!dev->active){
		ret = -EAGAIN;
		goto err;
	}

	if (fe->ops.tuner_ops.set_params) {
		c->delivery_system = SYS_DTMB;
		ret = fe->ops.tuner_ops.set_params(fe);
		if (ret)
			goto err;
	}

	bandwidth = c->bandwidth_hz/1000;
	bandwidth = bandwidth/1000;
	if(bandwidth==0)
		bandwidth = 8;

	GX1503_WriteRegWithMask(client,0xF5,1,6,6); 
	GX1503_WriteRegWithMask(client,0xF5,0,6,6);
	msleep(50);
	if(dev->clk_freq==24000)
		fs = 30750;
	else
		fs = dev->clk_freq;
	
	if(fs==30750)
		GX1503_WriteRegWithMask(client,0xF4,0x28,6,0); //NF
	else if(fs==30400)
		GX1503_WriteRegWithMask(client,0xF4,0x1F,6,0); //NF

	GX1503_WriteRegWithMask(client,0xF3,0x3,1,0 ); //NOO
	GX1503_WriteRegWithMask(client,0xF3,0x1,6,2);  //NR

	//set the ADC clk source
	if(fs==30750)
		GX1503_WriteRegWithMask(client,0xF7,0x0,3,3); //1-XO 0-PLL
	else if(fs==30400)
		GX1503_WriteRegWithMask(client,0xF7,0x1,3,3); //1-XO 0-PLL

	//set channle mode
	GX1503_WriteRegWithMask(client,0xf5,0x1,5,4); //dtmb mode
	GX1503_WriteRegWithMask(client,0xF7,0x0,2,2); //control dtmb

	//ADC configuration
	GX1503_WriteRegWithMask(client,0xFA,0x2,3,1); //adc bctrl   - bias control
	GX1503_WriteRegWithMask(client,0xFA,0x0,4,4); //adc chn sel - I channel
	GX1503_WriteRegWithMask(client,0xF9,0x0,0,0); //adc ppsel   - single channel
	GX1503_WriteRegWithMask(client,0x0A,0x0,6,6); //dual ADC	  - single ADC input
	GX1503_WriteRegWithMask(client,0x0A,0x0,2,2); //AdcChnSel   - data from I channel
	GX1503_WriteRegWithMask(client,0xF9,0x3,7,6); //adc opm	  - 3-active 0-powerdown

	//set fsample clock freq - 30.75MHz or 30.4MHz	
	ret = GX1503_Set_Clock(client,fs);
	if(ret)
		goto err;
	//set AGC
	regmap_read(dev->regmap,0x41,&temp);
	temp = temp & 0x7F;
	temp = temp|(0<<7);
	regmap_write(dev->regmap,0x41,temp);

	GX1503_Set_BandWidth(client,bandwidth);

	//set IF freq
	GX1503_Set_IntFrq(client,5000,fs);
	
	//Open TS port
	GX1503_WriteRegWithMask(client,0xD1,1,7,7		);// ts_out_ena

	regmap_read(dev->regmap,0xd0,&temp);
	if(dev->ts_mode)
		temp = temp |0x40;
	else
		temp = temp &0xbf;

	regmap_write(dev->regmap,0xd0,temp);
	
	regmap_write(dev->regmap,GX1503B_CFG_TS_0,0x10);
	regmap_write(dev->regmap,GX1503B_CFG_TS_2,0x32);
			
	regmap_write(dev->regmap,GX1503B_CFG_TS_4,0x54);
	regmap_write(dev->regmap,GX1503B_CFG_TS_6,0x76);
	regmap_write(dev->regmap,GX1503B_CFG_TS_8,0x9A);
	regmap_write(dev->regmap,GX1503B_CFG_TS_A,0x8B);

	//Open sdram port
	GX1503_WriteRegWithMask(client,0x0A,0,1,1 	);

	//init the inner register
	GX1503_WriteRegWithMask(client,0x90,0,7,7 	);// constellation valid
	GX1503_WriteRegWithMask(client,0xC5,30,7,0	);// cfg_imp_thres
	GX1503_WriteRegWithMask(client,0x9D,9,3,0 	);// cfg_path_delta
	GX1503_WriteRegWithMask(client,0x93,1,6,6 	);// cfg_h_det
	GX1503_WriteRegWithMask(client,0x9E,3,3,2 	);// cfg_noise_sel
	GX1503_WriteRegWithMask(client,0xa1,1,7,7 	);// cfg_pn_zero == 1;
	GX1503_WriteRegWithMask(client,0xE5,7,3,0 	);// cfg_disnum_sel 
	//dwp initialization
	GX1503_WriteRegWithMask(client,0xB2,255,7,0	);// h distance
	GX1503_WriteRegWithMask(client,0xB7,0,7,6 	);// h far gain
	GX1503_WriteRegWithMask(client,0xB8,0,2,0 	);// ceq_config_self
	GX1503_WriteRegWithMask(client,0xB4,8,7,0 	);// wnp_base_amp
	GX1503_WriteRegWithMask(client,0xB5,16,7,0	);// wnp_check_amp
	GX1503_WriteRegWithMask(client,0xB6,20,7,0	);// wnp_check595_amp
	GX1503_WriteRegWithMask(client,0xB0,2,3,2 	);// peak_iir_mode
	GX1503_WriteRegWithMask(client,0x50,1,1,1 	);

	ret = regmap_read(dev->regmap,0xf5,&temp);
	ret = regmap_write(dev->regmap,0xf5,temp|0x01);
	if(ret)
		goto err;

	ret = regmap_read(dev->regmap,0x00,&temp);
    ret = regmap_write(dev->regmap,0x00,temp|0x20);
	if(ret)
		goto err;

	return 0;
	
err:
	dev_dbg(&client->dev,"failed = %d\n",ret);
	return ret;	
}
static int gx1503_read_status(struct dvb_frontend *fe, enum fe_status *status)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct gx1503_dev *dev = i2c_get_clientdata(client);
	int ret,temp;

	*status = 0;
	
	if (!dev->active) {
		ret = -EAGAIN;
		goto err;
	}

	ret = regmap_read(dev->regmap,ALL_OK,&temp);
	if(ret)
		goto err;

	if((temp & 0x02)==0x02)
		*status = FE_HAS_SIGNAL | FE_HAS_CARRIER | FE_HAS_VITERBI |
				FE_HAS_SYNC | FE_HAS_LOCK;
	else
		*status = FE_HAS_SIGNAL | FE_HAS_CARRIER;

	return 0;
err:
	dev_dbg(&client->dev,"failed = %d\n",ret);
	return ret;	
}

static int gx1503_read_snr(struct dvb_frontend * fe,u16 * snr)
{
	struct i2c_client *client = fe->demodulator_priv;
	struct gx1503_dev *dev = i2c_get_clientdata(client);
	unsigned int Hl,Hh;
	unsigned int Nl,Nh;
	unsigned int	log_data=0	;
	int SNR = 0;
	int H_pow;
	int Noise_pow;
	int gi_mode;
	int gi_len[3]   = {420,595,945};
	int snr_mod[3]  = {2.6,0,2.2};
	int temp;

	regmap_read(dev->regmap,H_POW_L,&Hl);
	regmap_read(dev->regmap,H_POW_H,&Hh);
	regmap_read(dev->regmap,NOISE_L,&Nl);
	regmap_read(dev->regmap,NOISE_H,&Nh);
	
	regmap_read(dev->regmap,AUTO_TPS0,&temp);
	gi_mode = (temp & 0x0c)>>2;
	if(gi_mode<0 || gi_mode>2)gi_mode = 0;
					
	H_pow	  = (Hl + Hh*256);
	Noise_pow = (Nh*256+Nl);
	
	if(Noise_pow==0)
	   Noise_pow = 1;
	
	log_data = H_pow * 2048 / gi_len[gi_mode] * 64 / Noise_pow ;
	SNR = GX1503_100Log(log_data)/10 - snr_mod[gi_mode] - 10;	
	if(SNR <= 0)
		SNR = 0;

	*snr = SNR;

	return 0;
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
static int gx1503_select(struct i2c_mux_core *muxc,u32 chan)
{
	struct i2c_client *client = i2c_mux_priv(muxc);
#else
static int gx1503_select(struct i2c_adapter *dap,void *mux_priv,u32 chan)
{
	struct i2c_client *client = mux_priv;
#endif
	struct gx1503_dev *dev = i2c_get_clientdata(client);
	int ret,temp;
	ret = regmap_read(dev->regmap,I2C_RPT,&temp);
	ret |= regmap_write(dev->regmap,I2C_RPT,(temp|0x80));
	if(ret)
		goto err;

	return 0;

err:
	dev_dbg(&client->dev,"failed = %d\n",ret);
	return ret;

}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0)
static int gx1503_deselect(struct i2c_mux_core *muxc,u32 chan)
{
	struct i2c_client *client = i2c_mux_priv(muxc);
#else
static int gx1503_deselect(struct i2c_adapter *dap,void *mux_priv,u32 chan)
{
	struct i2c_client *client = mux_priv;
#endif
	struct gx1503_dev *dev = i2c_get_clientdata(client);
	int ret,temp;
	ret = regmap_read(dev->regmap,I2C_RPT,&temp);
	ret |= regmap_write(dev->regmap,I2C_RPT,(temp&0x7F));
	if(ret)
		goto err;

	return 0;

err:
	dev_dbg(&client->dev,"failed = %d\n",ret);
	return ret;
}

static const struct dvb_frontend_ops gx1503_ops = {
		.delsys = {SYS_DVBT},
		.info = {
			.name = "NationalChip gx1503",
			.frequency_min_hz = 474 * MHz,
			.frequency_max_hz = 858 * MHz,
			.frequency_stepsize_hz = 10 * kHz,
			.caps = 
				FE_CAN_FEC_AUTO |
				FE_CAN_QAM_AUTO |
                FE_CAN_TRANSMISSION_MODE_AUTO |
                FE_CAN_GUARD_INTERVAL_AUTO
		},

		.init    = gx1503_init,
		.set_frontend = gx1503_set_frontend,
		.read_status = gx1503_read_status,
		.read_snr = gx1503_read_snr,
		
};
static int gx1503_probe( struct i2c_client *client,
		const struct i2c_device_id *id)
{
	struct gx1503_config *cfg = client->dev.platform_data;
	struct gx1503_dev *dev;
	int ret,temp;

	static const struct regmap_config regmap_config = {
		.reg_bits = 8,
		.val_bits = 8,
	};

	dev = kzalloc(sizeof(*dev),GFP_KERNEL);
	if(!dev){
		ret = -ENOMEM;
		dev_err(&client->dev,"kzalloc() failed \n");
		goto err;
	}
	dev->i2c_wr_max = cfg->i2c_wr_max ? cfg->i2c_wr_max:~0;

	dev->regmap = regmap_init_i2c(client,&regmap_config);
	if(IS_ERR(dev->regmap)){
		ret = PTR_ERR(dev->regmap);
		goto err_free;
	}
	/*check i2c*/
	ret = regmap_read(dev->regmap,CHIP_ADDR,&temp);
	if(ret)
		goto err_regmap_exit;
	
	dev_info(&client->dev,"read the chip id is %x",temp);
	if(temp!=0x45){
		dev_err(&client->dev,"the chip id error!");
		goto err_regmap_exit;
		}
	else
		dev_info(&client->dev,"Deceted the gx1503 chip");
	
	i2c_set_clientdata(client,dev);
	mutex_init(&dev->i2c_mutex);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	dev->muxc = i2c_mux_alloc(client->adapter,&client->dev,
		1,0,I2C_MUX_LOCKED,
	    gx1503_select, gx1503_deselect);
	if(!dev->muxc){
		ret = -ENOMEM;
		goto err_regmap_exit;
	}
	dev->muxc->priv = client;
	ret = i2c_mux_add_adapter(dev->muxc,0,0,0);
	if(ret)
		goto err_regmap_exit;
	
	*cfg->i2c_adapter = dev->muxc->adapter[0];
#else
	dev->tuner_adapter = i2c_add_mux_adapter(client->adapter,&client->dev,
							client,0,0,0,
							gx1503_select, gx1503_deselect);
	if(!dev->tuner_adapter){
		ret = -ENOMEM;
		goto err_regmap_exit;
	}
	*cfg->i2c_adapter = dev->tuner_adapter;

#endif
	/*create dvb frontend*/
	memcpy(&dev->fe.ops,&gx1503_ops,sizeof(struct dvb_frontend_ops));
	dev->fe.demodulator_priv = client;
	*cfg->fe = &dev->fe;
	dev->ts_mode = cfg->ts_mode;
	dev->clk_freq = cfg->clk_freq;
	dev->fw_loaded = false;
	dev->active = false;
		
	return 0;
	
	
err_regmap_exit:
	regmap_exit(dev->regmap);
err_free:
	kfree(dev);
err:
	dev_dbg(&client->dev,"failed = %d\n",ret);
	return ret;
}
static int gx1503_remove(struct i2c_client *client)
{
	struct gx1503_dev*dev = i2c_get_clientdata(client);
	
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	i2c_mux_del_adapters(dev->muxc);
#else	
	i2c_del_mux_adapter(dev->tuner_adapter);
#endif
	regmap_exit(dev->regmap);
	
	dev->fe.ops.release = NULL;
	dev->fe.demodulator_priv = NULL;
	kfree(dev);

	return 0;

}
static const struct i2c_device_id gx1503_id_table[] = {
			{"gx1503",0},
			{}
};

MODULE_DEVICE_TABLE(i2c,gx1503_id_table);

static struct i2c_driver gx1503_driver = {
	.driver = {
		.name = "gx1503",
	},
	.probe = gx1503_probe,
	.remove = gx1503_remove,
	.id_table = gx1503_id_table,
};

module_i2c_driver(gx1503_driver);

MODULE_AUTHOR("Davin<smiledavin@gmail.com>");
MODULE_DESCRIPTION("gx1503 DTMB(GB20600-2006) driver");
MODULE_LICENSE("GPL");
