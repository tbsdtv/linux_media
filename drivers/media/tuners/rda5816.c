#include <linux/bitrev.h>
#include "rda5816.h"

struct rda5816_priv{
	struct i2c_adapter*i2c;
	struct rda5816_config*cfg;
	bool init_done;
};

/* write multiple (continuous) registers */
static int rda5816_wrm(struct rda5816_priv *priv, u8 *buf, int len)
{
	int ret;
	struct i2c_msg msg = {
		.addr = priv->cfg->i2c_adr,
		.flags = 0, .buf = buf, .len = len };

	dev_dbg(&priv->i2c->dev, "%s() i2c wrm @0x%02x (len=%d) ",
		__func__, buf[0], len);

	ret = i2c_transfer(priv->i2c, &msg, 1);
	if (ret < 0) {
		dev_warn(&priv->i2c->dev,
			"%s: i2c wrm err(%i) @0x%02x (len=%d)\n",
			KBUILD_MODNAME, ret, buf[0], len);
		return ret;
	}
	return 0;
}

/* write one register */
static int rda5816_wr(struct rda5816_priv *priv, u8 addr, u8 data)
{
	u8 buf[] = { addr, data };
	return rda5816_wrm(priv, buf, 2);
}

/* read multiple (continuous) registers starting at addr */
static int rda5816_rdm(struct rda5816_priv *priv, u8 addr, u8 *buf, int len)
{
	int ret;
	struct i2c_msg msg[] = {
		{ .addr = priv->cfg->i2c_adr, .flags = 0,
			.buf = &addr, .len = 1 },
		{ .addr = priv->cfg->i2c_adr, .flags = I2C_M_RD,
			.buf = buf, .len = len }
	};

	dev_dbg(&priv->i2c->dev, "%s() i2c rdm @0x%02x (len=%d)\n",
		__func__, addr, len);

	ret = i2c_transfer(priv->i2c, msg, 2);
	if (ret < 0) {
		dev_warn(&priv->i2c->dev,
			"%s: i2c rdm err(%i) @0x%02x (len=%d)\n",
			KBUILD_MODNAME, ret, addr, len);
		return ret;
	}
	return 0;
}

/* read one register */
static int rda5816_rd(struct rda5816_priv *priv, u8 addr, u8 *data)
{
	return rda5816_rdm(priv, addr, data, 1);
}

static int rda5816_init(struct dvb_frontend *fe)
{
	struct rda5816_priv *priv = fe->tuner_priv;
	u8 buffer;
	dev_dbg(&priv->i2c->dev,"%s()\n",__func__);


	if(priv->init_done)
		return 0;
	 msleep(1);  //Wait 1ms. 

	 // Chip register soft reset	 
	 rda5816_wr(priv,0x04,0x04);
	 rda5816_wr(priv,0x04,0x05); 

	 // Initial configuration start
	 msleep(2);  //Wait 1ms. 
	 
	 // pll setting 
	 rda5816_wr(priv,0x2b,0x97); //clk_interface_27m=1
	 rda5816_wr(priv,0x1a,0x13);
	 rda5816_wr(priv,0x41,0x53);
	 rda5816_wr(priv,0x38,0x9B);
	 rda5816_wr(priv,0x39,0x15);
	 rda5816_wr(priv,0x3A,0x00);
	 rda5816_wr(priv,0x3B,0x00);
	 rda5816_wr(priv,0x3C,0x0c);
	 rda5816_wr(priv,0x0c,0xE2);
	 rda5816_wr(priv,0x2e,0x6F);
	 rda5816_wr(priv,0x5b,0x20);
	 rda5816_wr(priv,0x2f,0x57);
	 rda5816_wr(priv,0x0d,0x70);
	 rda5816_wr(priv,0x16,0x03);
	 rda5816_wr(priv,0x18,0x4B);
	 rda5816_wr(priv,0x30,0xFF);
	 rda5816_wr(priv,0x5c,0xFF);
	 rda5816_wr(priv,0x6c,0xFF);
	 rda5816_wr(priv,0x6e,0xFF);
	 rda5816_wr(priv,0x65,0xD4);	 // v0.1.beta
	 rda5816_wr(priv,0x70,0x3F);
	 rda5816_wr(priv,0x71,0x3F);

	if(priv->cfg->xtal){	 //27M
	 rda5816_wr(priv,0x75,0x06);
	 rda5816_wr(priv,0x76,0x40);
	 rda5816_wr(priv,0x77,0x89);
	 }
	else{    //24M
	 rda5816_wr(priv,0x75,0x07);
	 rda5816_wr(priv,0x76,0x10);
	 rda5816_wr(priv,0x77,0x9A);
	 }

	 rda5816_wr(priv,0x53,0xA8);
	 rda5816_wr(priv,0x46,0x21);
	 rda5816_wr(priv,0x47,0x84);
	 rda5816_wr(priv,0x48,0x10);
	 rda5816_wr(priv,0x49,0x08);
	 rda5816_wr(priv,0x60,0x80);
	 rda5816_wr(priv,0x61,0x80);
	 rda5816_wr(priv,0x6A,0x08);
	 rda5816_wr(priv,0x6B,0x63);
	 rda5816_wr(priv,0x69,0xF8);
	 rda5816_wr(priv,0x57,0x64);
	 rda5816_wr(priv,0x05,0x55);
	 rda5816_wr(priv,0x06,0x65);
	 rda5816_wr(priv,0x15,0xFF);	 // v0.1.beta
	 rda5816_wr(priv,0x4a,0xBB);
	 rda5816_wr(priv,0x4b,0xDB);

	 if(priv->cfg->xtal){	//27M
	 //th1=901M  
	 rda5816_wr(priv,0x79,0x04);
	 rda5816_wr(priv,0x7a,0x2A);
	 rda5816_wr(priv,0x7b,0xAA);
	 rda5816_wr(priv,0x7c,0xAB);
	 //th2=1580M   
	 rda5816_wr(priv,0x72,0x07);
	 rda5816_wr(priv,0x73,0x40);
	 rda5816_wr(priv,0x74,0x74);
	 }

	 if(!priv->cfg->xtal){// Xtal_24M
	 //th1=901M  
	 rda5816_wr(priv,0x79,0x04);
	 rda5816_wr(priv,0x7a,0xB0);
	 rda5816_wr(priv,0x7b,0x00);
	 rda5816_wr(priv,0x7c,0x00);
	 //th2=1580M   
	 rda5816_wr(priv,0x72,0x08);
	 rda5816_wr(priv,0x73,0x00);
	 rda5816_wr(priv,0x74,0x80);
	 } 
	 //agc setting
	 rda5816_wr(priv,0x4f,0x40);
	 rda5816_wr(priv,0x5b,0x20);
	 rda5816_rd(priv,0x01,&buffer); 	 // v1.1

 // for blocker
	 rda5816_wr(priv,0x16,0x0C);	 // stage setting
	 rda5816_wr(priv,0x18,0x0C);
	 rda5816_wr(priv,0x30,0x1C);
	 rda5816_wr(priv,0x5c,0x2C);
	 rda5816_wr(priv,0x6c,0x2C);
	 rda5816_wr(priv,0x6e,0xAC);
	 rda5816_wr(priv,0x1b,0xBC);
	 rda5816_wr(priv,0x1d,0xBD);
	 rda5816_wr(priv,0x1f,0xBD);
	 rda5816_wr(priv,0x21,0xBE);
	 rda5816_wr(priv,0x23,0xFE);
	 rda5816_wr(priv,0x25,0xFE);
	 rda5816_wr(priv,0x27,0xFF);
	 rda5816_wr(priv,0x29,0xFF);
	 rda5816_wr(priv,0xb3,0xFF);
	 rda5816_wr(priv,0xb5,0xFF);

	 rda5816_wr(priv,0x17,0xF0);
	 rda5816_wr(priv,0x19,0xF0);
	 rda5816_wr(priv,0x31,0xF0);
	 rda5816_wr(priv,0x5d,0xF0);
	 rda5816_wr(priv,0x6d,0xF1);
	 rda5816_wr(priv,0x6f,0xF1);
	 rda5816_wr(priv,0x1c,0xF1);
	 rda5816_wr(priv,0x1e,0xF5);
	 rda5816_wr(priv,0x20,0xF6);
	 rda5816_wr(priv,0x22,0xFA);
	 rda5816_wr(priv,0x24,0xFA);
	 rda5816_wr(priv,0x26,0xFB);
	 rda5816_wr(priv,0x28,0xFF);
	 rda5816_wr(priv,0x2a,0xFF);
	 rda5816_wr(priv,0xb4,0xFF);
	 rda5816_wr(priv,0xb6,0xFF);  

	 rda5816_wr(priv,0xb7,0x00);//start0	 
	 rda5816_wr(priv,0xb9,0x42);//start1			 
	 rda5816_wr(priv,0xbb,0x4B);//start2			 
	 rda5816_wr(priv,0xbd,0x4A);//start3			 
	 rda5816_wr(priv,0xbf,0x5E);//start4	 
	 rda5816_wr(priv,0xc1,0x44);//start5	 
	 rda5816_wr(priv,0xc3,0x45);//start6	 
	 rda5816_wr(priv,0xc5,0x47);//start7	 
	 rda5816_wr(priv,0xa3,0x48);//start8			 
	 rda5816_wr(priv,0xa5,0x46);//start9	 
	 rda5816_wr(priv,0xa7,0x46);//start10		 
	 rda5816_wr(priv,0xa9,0x43);//start11		 
	 rda5816_wr(priv,0xab,0x24);//start12		 
	 rda5816_wr(priv,0xad,0x34);//start13		 
	 rda5816_wr(priv,0xaf,0x63);//start14		 
	 rda5816_wr(priv,0xb1,0x95);//start15		 

	 rda5816_wr(priv,0xb8,0x43);//end0			 
	 rda5816_wr(priv,0xba,0x78);//end1		 
	 rda5816_wr(priv,0xbc,0x78);//end2		 
	 rda5816_wr(priv,0xbe,0x87);//end3		 
	 rda5816_wr(priv,0xc0,0x8A);//end4		 
	 rda5816_wr(priv,0xc2,0x72);//end5		 
	 rda5816_wr(priv,0xc4,0x73);//end6		 
	 rda5816_wr(priv,0xc6,0x75);//end7		 
	 rda5816_wr(priv,0xa4,0x76);//end8	 
	 rda5816_wr(priv,0xa6,0x74);//end9		 
	 rda5816_wr(priv,0xa8,0x6D);//end10 	 
	 rda5816_wr(priv,0xaa,0x6A);//end11 	 
	 rda5816_wr(priv,0xac,0x35);//end12 	 
	 rda5816_wr(priv,0xae,0x63);//end13 	 
	 rda5816_wr(priv,0xb0,0x95);//end14 	  
	 rda5816_wr(priv,0xb2,0xCA);//end15 	  

	 rda5816_wr(priv,0x81,0x7F);//rise0 			 
	 rda5816_wr(priv,0x82,0xA7);//rise1 	 
	 rda5816_wr(priv,0x83,0xB6);//rise2 	 
	 rda5816_wr(priv,0x84,0xB5);//rise3  
	 rda5816_wr(priv,0x85,0xB8);//rise4 	 
	 rda5816_wr(priv,0x86,0xA3);//rise5 	 
	 rda5816_wr(priv,0x87,0xA3);//rise6 	 
	 rda5816_wr(priv,0x88,0xA5);//rise7 	 
	 rda5816_wr(priv,0x89,0xA6);//rise8 	 
	 rda5816_wr(priv,0x8a,0x9E);//rise9 	 
	 rda5816_wr(priv,0x8b,0x8A);//rise10	 
	 rda5816_wr(priv,0x8c,0xc1);//rise11	 
	 rda5816_wr(priv,0x8d,0x6A);//rise12	 
	 rda5816_wr(priv,0x8e,0x9C);//rise13	 
	 rda5816_wr(priv,0x8f,0xD1);//rise14	 

	 rda5816_wr(priv,0x90,0x00);//fall1 	 
	 rda5816_wr(priv,0x91,0x0A);//fall2 	 
	 rda5816_wr(priv,0x92,0x13);//fall3 	 
	 rda5816_wr(priv,0x93,0x17);//fall4  
	 rda5816_wr(priv,0x94,0x0B);//fall5  
	 rda5816_wr(priv,0x95,0x0C);//fall6  
	 rda5816_wr(priv,0x96,0x0F);//fall7 	 
	 rda5816_wr(priv,0x97,0x10);//fall8 	 
	 rda5816_wr(priv,0x98,0x0E);//fall9 	 
	 rda5816_wr(priv,0x99,0x0E);//fall10		 
	 rda5816_wr(priv,0x9a,0x14);//fall11		 
	 rda5816_wr(priv,0x9b,0x00);//fall12	 
	 rda5816_wr(priv,0x9c,0x1C);//fall13	 
	 rda5816_wr(priv,0x9d,0x2C);//fall14	 
	 rda5816_wr(priv,0x9e,0x5B);//fall15	 

   	 msleep(10); //Wait 10ms;

	 rda5816_wr(priv,0x04,0x85);  // enable current channel of dual-channel tuner
	if(priv->cfg->i2c_adr==0x8){ 
	 priv->cfg->i2c_adr=0x9;
	 rda5816_rd(priv,0x04,&buffer);   //address^0x02
	 rda5816_wr(priv,0x04,(buffer|0x80));  // address^0x02 enable adjacent channel of dual-channel tuner
	 priv->cfg->i2c_adr=0x8;
 	}

 	msleep(10); //Wait 10ms;

	// rfsel set rf switch
	if(priv->cfg->i2c_adr==0x8){
	  rda5816_rd(priv,0x65,&buffer);	 
	  rda5816_wr(priv,0x65,(buffer|0x6)); 
	  priv->cfg->i2c_adr=0x9; 
	  rda5816_rd(priv,0x65,&buffer); 	
	  rda5816_wr(priv,0x65,(buffer&0xF9)); 
	  priv->cfg->i2c_adr=0x8;
	}
	priv->init_done = 1;
	
	return 0;

}
static int rda5816_set_params(struct dvb_frontend *fe)
{
	struct rda5816_priv *priv = fe->tuner_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	u8 buffer; 
	u8 Filter_bw_control_bit;	
	int i;
	u32 fPLL, bw,fSym,temp_value = 0;

	dev_dbg(&priv->i2c->dev, "%s() delivery_system=%d frequency=%d " \
			"symbol_rate=%d\n", __func__,
			c->delivery_system, c->frequency, c->symbol_rate);

	
	printk("%s() delivery_system=%d frequency=%d " \
			"symbol_rate=%d\n", __func__,
			c->delivery_system, c->frequency, c->symbol_rate);


 	fPLL = c->frequency/1000;
	fSym = c->symbol_rate/1000;

	 rda5816_wr(priv,0x04,0xc1); 
	 //set frequency start
	 if(fPLL>1075)
	 {
		 rda5816_rd(priv,0x65,&buffer);
		 buffer &= 0xF7;
		 buffer |= 0x10;
		 rda5816_wr(priv,0x65,buffer);
	 }
	 else
	 {
		 rda5816_rd(priv,0x65,&buffer);
		 buffer &= 0xEF;
		 buffer |= 0x08;
		 rda5816_wr(priv,0x65,buffer);
		 fPLL = fPLL * 2;
	 }

 	if(priv->cfg->xtal)
	 	temp_value = (unsigned long)fPLL* 77672;	 //((2^21) / RDA5816sw__XTALFREQ);
 	else
		temp_value = (unsigned long)fPLL* 87381;

	 buffer = ((unsigned char)((temp_value>>24)&0xff));
	 rda5816_wr(priv,0x07,buffer);
	 buffer = ((unsigned char)((temp_value>>16)&0xff));  
	 rda5816_wr(priv,0x08,buffer);	 
	 buffer = ((unsigned char)((temp_value>>8)&0xff));
	 rda5816_wr(priv,0x09,buffer);	 
	 buffer = ((unsigned char)( temp_value&0xff));
	 rda5816_wr(priv,0x0a,buffer);
	 //set frequency end
	 // set Filter bandwidth start
	 bw=fSym;
	 Filter_bw_control_bit = (unsigned char)((bw*135/200+4000)/1000);
	 if(Filter_bw_control_bit<4)
		 Filter_bw_control_bit = 4; 	 // MHz
	 else if(Filter_bw_control_bit>40)
		 Filter_bw_control_bit = 40; // MHz

 	 Filter_bw_control_bit &= 0x3f;
	 Filter_bw_control_bit |= 0x40;
	 rda5816_wr(priv,0x0b,Filter_bw_control_bit);
	 // set Filter bandwidth end
	 rda5816_wr(priv,0x04,0xc3);

 	 msleep(5);	 //Wait 5ms;

	 for(i=0; i<130; i++)
	 
	 { 
		 rda5816_rd(priv,0x03,&buffer); 
		 if((buffer & 0x03) == 0x03)break; 
		 msleep(2);
	 }
	 
	 if((buffer & 0x03) != 0x03){
	
		 printk("rda5816 unlocked!!\n"); //unlocked
	 } 
	 else{
	 
		printk("rda5816 locked...\n"); //locked 
		}

 	 return 0;

}
static int rda5816_get_status(struct dvb_frontend *fe, u32 *status)
{
	struct rda5816_priv *priv = fe->tuner_priv;

	u8 buffer ;
	int i;

	for(i=0; i<130; i++)

	{

		rda5816_rd(priv,0x03,&buffer);

		if((buffer & 0x03) == 0x03)break;

		msleep(2);

	}

	if((buffer & 0x03) != 0x03){

		*status = 0; //unlocked
	} 
	else{

	   
	   *status = 1;   //locked

	   }
	return 0;
}
static  int   RDA5816_agc         [] = {     0,  82,   100,  116,  140,  162,  173,  187,  210,  223,  254,  255};
static  int   RDA5816_level_dBm_10[] = {    90, -50,  -263, -361, -463, -563, -661, -761, -861, -891, -904, -910};

static int rda5816_get_rf_strength(struct dvb_frontend *fe, u16 *st)
{
	struct rda5816_priv *priv = fe->tuner_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int   if_agc, index, table_length, slope, *x, *y;

	if_agc = *st;
	x = RDA5816_agc;
	y = RDA5816_level_dBm_10;
	table_length = sizeof(RDA5816_agc)/sizeof(int);

	
	/* Finding in which segment the if_agc value is */
	for (index = 0; index < table_length; index ++)
		if (x[index] > if_agc ) break;

	/* Computing segment slope */
	slope =  ((y[index]-y[index-1])*1000)/(x[index]-x[index-1]);
	/* Linear approximation of rssi value in segment (rssi values will be in 0.1dBm unit: '-523' means -52.3 dBm) */
	*st = 1000 + ((y[index-1] + ((if_agc - x[index-1])*slope + 500)/1000))/10;

	c->strength.len = 1;
	c->strength.stat[0].scale = FE_SCALE_DECIBEL;
	c->strength.stat[0].svalue = ((y[index-1] + ((if_agc - x[index-1])*slope + 500)/1000)) * 100;

	return 0;

}
static void rda5816_release(struct dvb_frontend* fe)
{
	struct rda5816_priv*priv = fe->tuner_priv;

	kfree(priv);
	priv= NULL;
}
static const struct dvb_tuner_ops rda5816_tuner_ops = {
	.info = {
		.name           = "RDA5816",
		.frequency_min_hz = 850 * MHz,
		.frequency_max_hz = 2300 * MHz,
	},

	.release = rda5816_release,

	.init = rda5816_init,
	.get_status = rda5816_get_status,
	.set_params = rda5816_set_params,
	.get_rf_strength = rda5816_get_rf_strength,
};

struct dvb_frontend *rda5816_attach(struct dvb_frontend *fe,
		struct rda5816_config *cfg, struct i2c_adapter *i2c)
{
	struct rda5816_priv *priv = NULL;
	int ret;
	u8 buffer,buffer1;
	int Chip_ID,Revision_ID;

	priv = kzalloc(sizeof(struct rda5816_priv), GFP_KERNEL);
	if (priv == NULL) {
		dev_dbg(&i2c->dev, "%s() attach failed\n", __func__);
		return NULL;
	}

	priv->cfg = cfg;
	priv->i2c = i2c;
	priv->init_done = 0;
	dev_info(&priv->i2c->dev,
		"%s: RDA5816 successfully attached\n",
		KBUILD_MODNAME);

	memcpy(&fe->ops.tuner_ops, &rda5816_tuner_ops,
			sizeof(struct dvb_tuner_ops));

	fe->tuner_priv = priv;


 	ret = rda5816_rd(priv,0x00,&buffer);
 	ret = rda5816_rd(priv,0x01,&buffer1);
	Chip_ID = (buffer<<4)|(buffer1>>4);
	Revision_ID = buffer1&0x0f;

 	printk("read tuner id is 0x%x : Revision %d\n",Chip_ID,Revision_ID);

	return fe;
}


EXPORT_SYMBOL(rda5816_attach);

MODULE_DESCRIPTION("RDA 5816 tuner driver");
MODULE_AUTHOR("Davin<smiledavin@gmail.com>");
MODULE_LICENSE("GPL");

