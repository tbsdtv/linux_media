//SPX-License-Identifier: GPL-2.0-or-later
/*
Sony cxd2878 family
Copyright (c) 2021 Davin zhang <Davin@tbsdtv.com> www.Turbosight.com
*/
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <media/dvb_frontend.h>
#include <linux/mutex.h>

#include "cxd2878.h"
#include "cxd2878_priv.h"


static LIST_HEAD(cxdlist);

struct cxd_base{
	struct list_head cxdlist;
	struct i2c_adapter *i2c;
	struct mutex i2c_lock; //for two adapter at the same i2c bus
	u8 adr		;		// 
	u32 count	;		//
	struct cxd2878_config *config;	

};

struct cxd2878_dev{
	struct cxd_base *base;
	bool warm; //start
	struct dvb_frontend fe;
	enum sony_dtv_system_t system;
	enum sony_dtv_bandwidth_t bandwidth;
	enum sony_demod_state_t state;
	u8 slvt;  //for slvt addr;
	u8 slvx;	//addr
	u8 slvr;	//addr
	u8 slvm;	//addr
	u8 tuner_addr;
	enum sony_demod_chip_id_t chipid;
	enum sony_ascot3_chip_id_t tunerid;
	struct sony_demod_iffreq_config_t iffreqConfig;

	u32 atscNoSignalThresh;
	u32 atscSignalThresh;
	u32 tune_time;
	
 };
/* For CXD2856 or newer generation ICs */
static	struct sony_ascot3_adjust_param_t g_param_table_ascot3i[SONY_ASCOT3_TV_SYSTEM_NUM] = {
	/*
	OUTLMT	  IF_BPF_GC 										  BW			  BW_OFFSET 		IF_OUT_SEL
	  |  RF_GAIN  | 	RFOVLD_DET_LV1	  IFOVLD_DET_LV  IF_BPF_F0 |   FIF_OFFSET	  | 	   AGC_SEL |  IS_LOWERLOCAL
	  | 	|	  |    (VL)  (VH)  (U)	 (VL)  (VH)  (U)	|	   |	   |		  | 		 |	   |	 |			*/
	{0x00, AUTO, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, BW_6,	OFFSET(0),	OFFSET(0),	AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_TV_SYSTEM_UNKNOWN */
	/* Analog */
	{0x00, AUTO, 0x05, 0x03, 0x06, 0x03, 0x01, 0x01, 0x01, 0x00, BW_6,	OFFSET(0),	OFFSET(1),	AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_ATV_MN_EIAJ   (System-M (Japan)) */
	{0x00, AUTO, 0x05, 0x03, 0x06, 0x03, 0x01, 0x01, 0x01, 0x00, BW_6,	OFFSET(0),	OFFSET(1),	AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_ATV_MN_SAP	  (System-M (US)) */
	{0x00, AUTO, 0x05, 0x03, 0x06, 0x03, 0x01, 0x01, 0x01, 0x00, BW_6,	OFFSET(3),	OFFSET(1),	AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_ATV_MN_A2	  (System-M (Korea)) */
	{0x00, AUTO, 0x05, 0x03, 0x06, 0x03, 0x01, 0x01, 0x01, 0x00, BW_7,	OFFSET(11), OFFSET(5),	AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_ATV_BG		  (System-B/G) */
	{0x00, AUTO, 0x05, 0x03, 0x06, 0x03, 0x01, 0x01, 0x01, 0x00, BW_8,	OFFSET(2),	OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_ATV_I		  (System-I) */
	{0x00, AUTO, 0x05, 0x03, 0x06, 0x03, 0x01, 0x01, 0x01, 0x00, BW_8,	OFFSET(2),	OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_ATV_DK		  (System-D/K) */
	{0x00, AUTO, 0x03, 0x04, 0x0A, 0x04, 0x04, 0x04, 0x04, 0x00, BW_8,	OFFSET(2),	OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_ATV_L		  (System-L) */
	{0x00, AUTO, 0x03, 0x04, 0x0A, 0x04, 0x04, 0x04, 0x04, 0x00, BW_8,	OFFSET(-1), OFFSET(4),	AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_ATV_L_DASH	  (System-L DASH) */
	/* Digital */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x03, 0x03, 0x03, 0x00, BW_6,	OFFSET(-6), OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_8VSB	  (ATSC 8VSB) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_6,	OFFSET(-6), OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_QAM 	  (US QAM) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_6,	OFFSET(-9), OFFSET(-5), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_ISDBT_6   (ISDB-T 6MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_7,	OFFSET(-7), OFFSET(-6), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_ISDBT_7   (ISDB-T 7MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_8,	OFFSET(-5), OFFSET(-7), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_ISDBT_8   (ISDB-T 8MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_6,	OFFSET(-8), OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBT_5	  (DVB-T 5MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_6,	OFFSET(-8), OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBT_6	  (DVB-T 6MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_7,	OFFSET(-6), OFFSET(-5), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBT_7	  (DVB-T 7MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_8,	OFFSET(-4), OFFSET(-6), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBT_8	  (DVB-T 8MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_1_7,OFFSET(-10),OFFSET(-10),AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBT2_1_7 (DVB-T2 1.7MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_6,	OFFSET(-8), OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBT2_5   (DVB-T2 5MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_6,	OFFSET(-8), OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBT2_6   (DVB-T2 6MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_7,	OFFSET(-6), OFFSET(-5), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBT2_7   (DVB-T2 7MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_8,	OFFSET(-4), OFFSET(-6), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBT2_8   (DVB-T2 8MHzBW) */
	{0x00, AUTO, 0x04, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x00, BW_6,	OFFSET(-6), OFFSET(-4), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBC_6	  (DVB-C 6MHzBW) */
	{0x00, AUTO, 0x04, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x00, BW_8,	OFFSET(-2), OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBC_8	  (DVB-C 8MHzBW) */
	{0x00, AUTO, 0x02, 0x09, 0x09, 0x09, 0x02, 0x02, 0x02, 0x00, BW_6,	OFFSET(-6), OFFSET(-2), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBC2_6   (DVB-C2 6MHzBW) */
	{0x00, AUTO, 0x02, 0x09, 0x09, 0x09, 0x02, 0x02, 0x02, 0x00, BW_8,	OFFSET(-2), OFFSET(0),	AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_DVBC2_8   (DVB-C2 8MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_6,	OFFSET(-8), OFFSET(-3), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_ATSC3_6   (ATSC 3.0 6MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_7,	OFFSET(-6), OFFSET(-5), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_ATSC3_7   (ATSC 3.0 7MHzBW) */
	{0x00, AUTO, 0x08, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_8,	OFFSET(-4), OFFSET(-6), AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_ATSC3_8   (ATSC 3.0 8MHzBW) */
	{0x00, AUTO, 0x04, 0x02, 0x02, 0x02, 0x01, 0x01, 0x01, 0x00, BW_6,	OFFSET(-5), OFFSET(2),	AUTO, AUTO, 0x00}, /**< SONY_ASCOT3_DTV_J83B_5_6  (J.83B 5.6Msps) */
	{0x00, AUTO, 0x03, 0x0B, 0x0B, 0x0B, 0x02, 0x02, 0x02, 0x00, BW_8,	OFFSET(2),	OFFSET(1),	AUTO, AUTO, 0x00}  /**< SONY_ASCOT3_DTV_DTMB	  (DTMB) */
};

static const u8 log2LookUp[] = {
    0, /* 0 */ 4,               /* 0.04439 */
    9, /* 0.08746 */ 13,        /* 0.12928 */
    17, /* 0.16993 */ 21,       /* 0.20945 */
    25, /* 0.24793 */ 29,       /* 0.28540 */
    32, /* 0.32193 */ 36,       /* 0.35755 */
    39, /* 0.39232 */ 43,       /* 0.42627 */
    46, /* 0.45943 */ 49,       /* 0.49185 */
    52, /* 0.52356 */ 55,       /* 0.55249 */
    58, /* 0.58496 */ 61,       /* 0.61471 */
    64, /* 0.64386 */ 67,       /* 0.67246 */
    70, /* 0.70044 */ 73,       /* 0.72792 */
    75, /* 0.75489 */ 78,       /* 0.78136 */
    81, /* 0.80736 */ 83,       /* 0.83289 */
    86, /* 0.85798 */ 88,       /* 0.88264 */
    91, /* 0.90689 */ 93,       /* 0.93074 */
    95, /* 0.95420 */ 98        /* 0.97728 */
};

static u32 sony_math_log2 (u32 x)
{

    u8 count = 0;
    u8 index = 0;
    u32 xval = x;

    /* Get the MSB position. */
    for (x >>= 1; x > 0; x >>= 1) {
        count++;
    }

    x = count * 100;

    if (count > 0) {
        if (count <= MAX_BIT_PRECISION) {
            /* Mask the bottom bits. */
            index = (u8) (xval << (MAX_BIT_PRECISION - count)) & FRAC_BITMASK;
            x += log2LookUp[index];
        }
        else {
            /* Mask the bits just below the radix. */
            index = (u8) (xval >> (count - MAX_BIT_PRECISION)) & FRAC_BITMASK;
            x += log2LookUp[index];
        }
    }

    return (x);
}
static u32 sony_math_log10 (u32 x)
{
    /* log10(x) = log2 (x) / log2 (10) */
    /* Note uses: logN (x) = logM (x) / logM (N) */
    return ((100 * sony_math_log2 (x) + LOG2_10_100X / 2) / LOG2_10_100X);
}
static u32 sony_math_log (u32 x)
{
    /* ln (x) = log2 (x) / log2(e) */
    return ((100 * sony_math_log2 (x) + LOG2_E_100X / 2) / LOG2_E_100X);
}
/*write multi registers*/
static int cxd2878_wrm(struct cxd2878_dev *dev,u8 addr, u8 reg,u8*buf,u8 len)
{
	int ret ;
	u8 b0[50];
	b0[0] = reg;
	memcpy(&b0[1],buf,len);
	struct i2c_msg msg = {
		.addr = addr,
		.flags = 0,
		.buf = b0,
		.len = len+1,
	};
	ret = i2c_transfer(dev->base->i2c,&msg,1);
	if(ret<0){
		dev_warn(&dev->base->i2c->dev,
			"%s: i2c wrm err(%i) @0x%02x (len=%d)\n",
			KBUILD_MODNAME, ret, reg, len);
		return ret;
		}
	
	//printk("wrm : addr = 0x%x args=%*ph\n",addr*2,len+1,b0);
	return 0;

}
/*write one register*/
static int cxd2878_wr(struct cxd2878_dev *dev,u8 addr, u8 reg,u8 data)
{
	return cxd2878_wrm(dev,addr,reg,&data,1);
}
/*read one or more registers*/
static int cxd2878_rdm(struct cxd2878_dev *dev,u8 addr, u8 reg, u8* buf, u32 len)
{
	int ret;
	struct i2c_msg msg[]={
			{.addr = addr,.flags = 0 ,.buf = &reg,.len=1},
			{.addr = addr,.flags = I2C_M_RD,.buf = buf,.len=len}
	};

	ret = i2c_transfer(dev->base->i2c, msg, 2);
	if (ret < 0) {
		dev_warn(&dev->base->i2c->dev,
			"%s: i2c rdm err(%i) @0x%02x (len=%d)\n",
			KBUILD_MODNAME, ret, addr, len);
		return ret;
	}

	//printk("rdm :addr = 0x%x,reg =0x%x data=%*ph\n",addr*2,reg,len,buf);

	return 0;

}
static int cxd2878_SetRegisterBits(struct cxd2878_dev*dev,
										u8 slaveaddress,u8 registerAddr,u8 data,u8 mask)
{
	int ret;
	u8 rdata = 0x00;

	if(mask==0)
		return 0;

	if(mask!=0xFF){
	    ret = cxd2878_rdm( dev,slaveaddress, registerAddr, &rdata, 1);
        if(ret) 
			return ret; 
		data = ((data & mask) | (rdata & (mask ^ 0xFF)));
	}

//	printk("%s: data = 0x%x",__FUNCTION__,data);
	ret = cxd2878_wr(dev,slaveaddress,registerAddr,data);

	if(ret)
		goto err;

	 return 0;
err:
	dev_err(&dev->base->i2c->dev,"set bank and registerbits error.\n");
	return ret;

}
static int cxd2878_SetBankAndRegisterBits(struct cxd2878_dev*dev,u8 slaveAddress,
					u8 bank,u8 registerAddress,u8 value,u8 bitMask)
{
	int ret;

	ret = cxd2878_wr(dev,slaveAddress,0x00,bank);
	if(ret)
		goto err;

	ret = cxd2878_SetRegisterBits(dev,slaveAddress, registerAddress, value, bitMask);
	if(ret)
		goto err;

	return 0;
err:
	dev_err(&dev->base->i2c->dev,"set bank and registerbits error.\n");
	return ret;
}
static int cxd2878_atsc_SlaveRWriteRegister (struct cxd2878_dev*dev,
                                                   u8  bank,
                                                   u8  registerAddress,
                                                   u8  value,
                                                   u8  bitMask)
{
		int ret = 0 ;
		u8 cmd[6];
		u8 rdata[6];
		int waittime = 0;
 /*  Write Register Command
     *  byte0:COMMANDID_WRITE_REG 0xC5
     *  byte1:Bank
     *  byte2:SubAddress
     *  byte3:Write Data
     *  byte4:Mask
     *  byte5:Reserved(0x00)
     */
    cmd[0] = 0xC5;
    cmd[1] = bank;
    cmd[2] = registerAddress;
    cmd[3] = value;
    cmd[4] = bitMask;
    cmd[5] = 0;

	ret = cxd2878_wrm(dev,dev->slvr,0x0A,cmd,6);
	
    for(;;){
   	
	ret = cxd2878_rdm(dev,dev->slvr,0x0A,rdata,6);
	if(rdata[0]==0x00){
		msleep(10);
		waittime += 10;
		}
		else{
		 if(rdata[5]== cmd[0])
		 	break;
		 else {
		 	ret = -1;
		 	goto err;
			}
		}

		if(waittime>1000){
			ret = -1;
			goto err;}
	  }
   	if(rdata[0]&0x3F!=0x30){
		ret = -1;
		goto err;
   	}
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"cxd2878_atscSlaveRWriteRegister error.\n");
	return ret;		
}

static int slaveRWriteMultiRegisters (struct cxd2878_dev * dev,
                                                u8  bank,
                                                u8  registerAddress,
                                                u8* pData,
                                                u8  size)
{
	u8 wtimes = 0;
	int ret = 0 ;

	for(wtimes = 0;wtimes<size;wtimes++){
		ret = cxd2878_atsc_SlaveRWriteRegister(dev,bank,registerAddress + wtimes, *(pData + wtimes), 0xFF);
		if(ret)
			goto err;
	}
	
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"slaveRWriteMultiRegisters error.\n");
	return ret;

	
}

static int cxd2878_atsc_softreset(struct cxd2878_dev *dev)
{
	int ret,waittime;
	u8 data[6],rdata[6];
	ret = cxd2878_wr(dev,dev->slvr,0x00,0x01);  //demodabort
	ret |= cxd2878_wr(dev,dev->slvr,0x48,0x01); // atsccpustate = IDLE
	if(ret)
		goto err;

	data[0] = 0xB3;
	data[1] = 0x10; //8vsb = 0x10 ,qam64=0x11 256qam=0x12 auto=0x16
	data[2] = 0;
	data[3] = 0;
	data[4] = 0;
	data[5] = 0;

	ret = cxd2878_wrm(dev,dev->slvr,0x0A,data,6);
	
    for(;;){
   	
	ret = cxd2878_rdm(dev,dev->slvr,0x0A,rdata,6);
	
	if(rdata[0]==0x00){
		msleep(10);
		waittime += 10;
		}
		else{
		 if(rdata[5]== 0xB3)
		 	break;
		 else {
		 	ret = -1;
		 	goto err;
			}
		}

		if(waittime>1000){
			ret = -1;
			goto err;}
	  }	

	 if(rdata[0]&0x3F!=0x30){
		ret = -1;
		goto err;
   	 }
	return 0;

err:
	dev_err(&dev->base->i2c->dev,"%s :cxd2878_atsc_softreset error! \n",KBUILD_MODNAME);
	return ret;	
}
static int cxd2878_i2c_repeater(struct cxd2878_dev *dev,bool enable)
{
	int ret;

	ret = cxd2878_wr(dev,dev->slvx,0x08,enable?1:0);
	if(ret)
		goto err;

	msleep(20);

	return 0;

err:
	dev_err(&dev->base->i2c->dev,"%s : %sable thee repeater failed! \n",KBUILD_MODNAME,enable?"en":"dis");
	return ret;
}

static int ascot3_read_rssi(struct cxd2878_dev*dev,u32 frequency,s32 *rssi)
{
	int ret = 0;
	u8 ifagc,rfagc,tmp;
	s32 ifgain=0,rfgain=0;
	u8 data[2];
	s32 if_bpf_gc_table[]={0,0,0,0,2,4,6,8,10,12,14,16,18,20,20,20};
	s32 if_bpf_gc_x100 = 0;
	s32 agcreg_x140 = 0,maxagcreg_x140 = 0,rfgainmax_100 = 0;
	
	data[0] = 0xc4;
	data[1] = 0x41; //(x87 x88)
	ret = cxd2878_wrm(dev,dev->tuner_addr,0x87,data,2);
	if(ret)goto err;

	//connect ifagc,startADC
	data[0] = 0x05;
	data[1] = 0x01;
	ret = cxd2878_wrm(dev,dev->tuner_addr,0x59,data,2);
	if(ret)goto err;
		
	ret|=cxd2878_rdm(dev,dev->tuner_addr,0x5B,&ifagc,1);

	//connect rfagc,startADC
	data[0] = 0x03;
	data[1] = 0x01;
	ret |= cxd2878_wrm(dev,dev->tuner_addr,0x59,data,2);
	
	ret|=cxd2878_rdm(dev,dev->tuner_addr,0x5B,&rfagc,1);
	if(ret)goto err;

	ret |= cxd2878_wr(dev,dev->tuner_addr,0x59,0x04);
	ret |= cxd2878_wr(dev,dev->tuner_addr,0x88,0x04);
	ret |= cxd2878_wr(dev,dev->tuner_addr,0x87,0xC0);
	if(ret)goto err;

	agcreg_x140 = ifagc*140;
	
	cxd2878_rdm(dev,dev->tuner_addr,0x69,&tmp,1);
	if_bpf_gc_x100 = if_bpf_gc_table[tmp&0xF]*100;
	
	if(agcreg_x140>9945)
		ifgain = 870+if_bpf_gc_x100;
	else
		ifgain = 870+if_bpf_gc_x100+(769*(9945-agcreg_x140)+1275)/2550;

	if(ifagc>rfagc)
		maxagcreg_x140 = ifagc*140;
	else
		maxagcreg_x140 = rfagc*140;

	if(frequency>700000)
		rfgainmax_100 = 4150;
	else if(frequency>600000)
		rfgainmax_100 = 4130;
	else if(frequency>532000)
		rfgainmax_100 = 4170;
	else if(frequency>464000)
		rfgainmax_100 = 4050;
	else if(frequency>400000)
		rfgainmax_100 = 4280;
	else if(frequency>350000)
		rfgainmax_100 = 4260;
	else if(frequency>320000)
		rfgainmax_100 = 4110;
	else if(frequency>285000)
		rfgainmax_100 = 4310;
	else if(frequency>215000)
		rfgainmax_100 = 4250;
	else if(frequency>184000)
		rfgainmax_100 = 4020;
	else if(frequency>172000)
		rfgainmax_100 = 3920;
	else if(frequency>150000)
		rfgainmax_100 = 4080;
	else if(frequency>86000)
		rfgainmax_100 = 4180;
	else if(frequency>65000)
		rfgainmax_100 = 4200;
	else if(frequency>50000)
		rfgainmax_100 = 4020;
	else
		rfgainmax_100 = 4020;

	
	if(maxagcreg_x140<4896)
		rfgain = rfgainmax_100;
	else if(maxagcreg_x140<5457)
		rfgain = rfgainmax_100-(70*(maxagcreg_x140-4896)+127)/255;
	else if(maxagcreg_x140<8823)
		rfgain = rfgainmax_100-154;
	else if(maxagcreg_x140<24786)
		rfgain = rfgainmax_100 -154 -(70*(maxagcreg_x140-8823)+127)/255;
	else if(maxagcreg_x140<30090)
		rfgain = rfgainmax_100 -4536 -(57*(maxagcreg_x140-24786)+127)/255;
	else 
		rfgain = rfgainmax_100 -4536-1186 -(160*(maxagcreg_x140-30090)+127)/255;

	*rssi = -ifgain-rfgain;

//	printk("frequency= %d,rssi = %d\n",frequency,*rssi);
	return 0;

err:
	dev_err(&dev->base->i2c->dev,"%s : ascot3_read_rssi failed! \n",KBUILD_MODNAME);
	return ret;
}
static int ascot3_tune(struct cxd2878_dev*dev,u32 frequency)
{
	int ret;
	enum sony_ascot3_tv_system_t aSystem;
    /* Convert system, bandwidth into dtv system. */
    switch (dev->system) {
    case SONY_DTV_SYSTEM_DVBC:
        switch (dev->bandwidth) {
        case SONY_DTV_BW_6_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBC_6;
            break;
        case SONY_DTV_BW_7_MHZ:
            /* 7MHZ BW setting is the same as 8MHz BW */
        case SONY_DTV_BW_8_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBC_8;
            break;
        }
        break;

    case SONY_DTV_SYSTEM_DVBT:
        switch (dev->bandwidth) {
        case SONY_DTV_BW_5_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBT_5;
            break;
        case SONY_DTV_BW_6_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBT_6;
            break;
        case SONY_DTV_BW_7_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBT_7;
            break;
        case SONY_DTV_BW_8_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBT_8;
            break;
        }
        break;

    case SONY_DTV_SYSTEM_DVBT2:
        switch (dev->bandwidth) {
        case SONY_DTV_BW_1_7_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBT2_1_7;
            break;
        case SONY_DTV_BW_5_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBT2_5;
            break;
        case SONY_DTV_BW_6_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBT2_6;
            break;
        case SONY_DTV_BW_7_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBT2_7;
            break;
        case SONY_DTV_BW_8_MHZ:
            aSystem = SONY_ASCOT3_DTV_DVBT2_8;
            break;
        }
        break;

    case SONY_DTV_SYSTEM_ISDBT:
        switch (dev->bandwidth) {
        case SONY_DTV_BW_6_MHZ:
            aSystem = SONY_ASCOT3_DTV_ISDBT_6;
            break;
        case SONY_DTV_BW_7_MHZ:
            aSystem = SONY_ASCOT3_DTV_ISDBT_7;
            break;
        case SONY_DTV_BW_8_MHZ:
            aSystem = SONY_ASCOT3_DTV_ISDBT_8;
            break;
        }
        break;

    case SONY_DTV_SYSTEM_ISDBC:
        aSystem = SONY_ASCOT3_DTV_DVBC_6; /* ISDB-C uses DVB-C 6MHz BW setting */
        break;

    case SONY_DTV_SYSTEM_ATSC:
        aSystem = SONY_ASCOT3_DTV_8VSB;
        break;


    case SONY_DTV_SYSTEM_J83B:
        switch (dev->bandwidth) {
        case SONY_DTV_BW_J83B_5_06_5_36_MSPS:
            aSystem = SONY_ASCOT3_DTV_DVBC_6; /* J.83B (5.057, 5.361Msps commonly used in US) uses DVB-C 6MHz BW setting */
            break;
        case SONY_DTV_BW_J83B_5_60_MSPS:
            aSystem = SONY_ASCOT3_DTV_J83B_5_6; /* J.83B (5.6Msps used in Japan) uses special setting */
            break;
        }
        break;

    /* Intentional fall-through */
    case SONY_DTV_SYSTEM_UNKNOWN:
    default:
        return 1;
    }
	
	/* Disable IF signal output (IF_OUT_SEL setting) (0x74) */
	cxd2878_SetRegisterBits( dev,dev->tuner_addr, 0x74, 0x02, 0x03);

	u8 cdata[2] = {0xC4,0x40};
	cxd2878_wrm(dev,dev->tuner_addr,0x87,cdata,2);
	
	u8 data[2];	
	/* Initial setting for internal analog block (0x91, 0x92) */
	if((aSystem== SONY_ASCOT3_DTV_DVBC_6) || (aSystem == SONY_ASCOT3_DTV_DVBC_8) || (aSystem == SONY_ASCOT3_DTV_J83B_5_6)){
		data[0] = 0x16;
		data[1] = 0x26;
	}else{
		data[0] = 0x10;
		data[1] = 0x20;
	}
	cxd2878_wrm(dev,dev->tuner_addr,0x91,data,2);
    u8 data1[2];
    data1[0] = 0x00;
    data1[1] = (u8)(g_param_table_ascot3i[aSystem].IS_LOWERLOCAL &0x01);
	cxd2878_wrm(dev,dev->tuner_addr,0x9c,data1,2); 
	
	u8 data2[9];
    /* Enable for analog block (0x5E, 0x5F, 0x60) */
    data2[0] = 0xEE;
    data2[1] = 0x02;
    data2[2] = 0x1E;

    /* Tuning setting for CPU (0x61) */ 
     data2[3] = 0x67;
    	
	if((dev->tunerid == SONY_ASCOT3_CHIP_ID_2871A)
            && ((aSystem== SONY_ASCOT3_DTV_DVBC_6) || (aSystem== SONY_ASCOT3_DTV_DVBC_8) || (aSystem== SONY_ASCOT3_DTV_J83B_5_6))){
            /* DVB-C (ASCOT3I) (Fref = 1MHz) */
            switch(dev->base->config->tuner_xtal){
            case SONY_ASCOT3_XTAL_16000KHz:
                data2[4] = 0x10;
                break;
            case SONY_ASCOT3_XTAL_20500KHz:
                data2[4] = 0x14;
                break;
            case SONY_ASCOT3_XTAL_24000KHz:
                data2[4] = 0x18;
                break;
            case SONY_ASCOT3_XTAL_41000KHz:
                data2[4] = 0x28;
                break;
            }
        }else{
            /* Digital (Fref = 8MHz) */
            switch(dev->base->config->tuner_xtal){
            case SONY_ASCOT3_XTAL_16000KHz:
                data2[4] = 0x02;
                break;
            case SONY_ASCOT3_XTAL_20500KHz:
                data2[4] = 0x02;
                break;
            case SONY_ASCOT3_XTAL_24000KHz:
                data2[4] = 0x03;
                break;
            case SONY_ASCOT3_XTAL_41000KHz:
                data2[4] = 0x05;
                break;
            }
        }
		if((aSystem == SONY_ASCOT3_DTV_DVBC_6) || (aSystem == SONY_ASCOT3_DTV_DVBC_8) || (aSystem == SONY_ASCOT3_DTV_J83B_5_6)){
                if(dev->base->config->tuner_xtal == SONY_ASCOT3_XTAL_20500KHz){
                    data2[5] = 0x1C;
                }else{
                    data2[5] = 0x1C;
                }
                data2[6] = 0x78;
                data2[7] = 0x08;
                data2[8] = 0x1C;
            }else{
                if(dev->base->config->tuner_xtal == SONY_ASCOT3_XTAL_20500KHz){
                    data2[5] = 0x8C;
                }else{
                    data2[5] = 0xB4;
                }
                data2[6] = 0x78;
                data2[7] = 0x08;
                data2[8] = 0x30;
            }
			cxd2878_wrm( dev,dev->tuner_addr,0x5E, data2, 9);
			cxd2878_SetRegisterBits(dev,dev->tuner_addr,0x67,0x00,0x06);
			u8 data3[17];
			data3[0] = g_param_table_ascot3i[aSystem].OUTLMT&0x03;
			if(g_param_table_ascot3i[aSystem].RF_GAIN == AUTO)
				data3[1] = 0x80;
			else
				data3[1] = (u8)((g_param_table_ascot3i[aSystem].RF_GAIN<<4) &0x70);
			
			data3[1]|= (u8)(g_param_table_ascot3i[aSystem].IF_BPF_GC&0x0F);
			data3[2] = 0x00;

			if(frequency <= 172000){
				data3[3] = (u8)(g_param_table_ascot3i[aSystem].RFOVLD_DET_LV1_VL & 0x0F);
				data3[4] = (u8)(g_param_table_ascot3i[aSystem].IFOVLD_DET_LV_VL & 0x07);
			}else if(frequency<= 464000){
				data3[3] = (u8)(g_param_table_ascot3i[aSystem].RFOVLD_DET_LV1_VH & 0x0F);
				data3[4] = (u8)(g_param_table_ascot3i[aSystem].IFOVLD_DET_LV_VH & 0x07);
			}else{
				data3[3] = (u8)(g_param_table_ascot3i[aSystem].RFOVLD_DET_LV1_U & 0x0F);
				data3[4] = (u8)(g_param_table_ascot3i[aSystem].IFOVLD_DET_LV_U & 0x07);
			}
			data3[4] |= 0x20;
			
			/* Setting for IF frequency and bandwidth */
			
			/* IF filter center frequency offset (IF_BPF_F0) (0x6D) */
			data3[5] = (u8)((g_param_table_ascot3i[aSystem].IF_BPF_F0 << 4) & 0x30);
			
			/* IF filter band width (BW) (0x6D) */
			data3[5] |= (u8)(g_param_table_ascot3i[aSystem].BW & 0x03);
			
			/* IF frequency offset value (FIF_OFFSET) (0x6E) */
			data3[6] = (u8)(g_param_table_ascot3i[aSystem].FIF_OFFSET & 0x1F);
			
			/* IF band width offset value (BW_OFFSET) (0x6F) */
			data3[7] = (u8)(g_param_table_ascot3i[aSystem].BW_OFFSET & 0x1F);
			
			/* RF tuning frequency setting (0x70, 0x71, 0x72) */
			data3[8]  = (u8)(frequency & 0xFF);		   /* FRF_L */
			data3[9]  = (u8)((frequency >> 8) & 0xFF);  /* FRF_M */
			data3[10] = (u8)((frequency >> 16) & 0x0F); /* FRF_H (bit[3:0]) */

			data3[11] = 0xFF;
			data3[12] = 0x11;
			
			if( (aSystem == SONY_ASCOT3_DTV_DVBC_6) || (aSystem == SONY_ASCOT3_DTV_DVBC_8) || (aSystem == SONY_ASCOT3_DTV_J83B_5_6)){
	
					data3[13] = 0xD9;
					data3[14] = 0x0F;
					data3[15] = 0x24;
					data3[16] = 0x87;
				
			}else{
					data3[13] = 0x99;
					data3[14] = 0x00;
					data3[15] = 0x24;
					data3[16] = 0x87;			
			}
			cxd2878_wrm( dev,dev->tuner_addr,0x68, data3, 17);	

			msleep(50);

			cxd2878_wr(dev,dev->tuner_addr,0x88,0x00);
			cxd2878_wr(dev,dev->tuner_addr,0x87,0xC0);
			msleep(10);
			return 0;
}
static int ascot3_init(struct cxd2878_dev*dev)
{
	int ret;
	u8 data = 0;
	ret = cxd2878_rdm(dev,dev->tuner_addr,0x7F,&data,1);
	if(ret)
		goto err;
	switch(data&0xF0){
		case 0xC0:/* ASCOT3 ES1 */
		case 0xD0:/* ASCOT3 ES2 */
			dev->tunerid = SONY_ASCOT3_CHIP_ID_UNKNOWN;
			break;
		case 0xE0:  /* ASCOT3I */
			dev_info(&dev->base->i2c->dev," Deceted the Tuner chip ASCOT3 ,ID 2878A ");
			dev->tunerid = SONY_ASCOT3_CHIP_ID_2871A;
			break;
		}
	//x_pon
	 u8 cdata[2] ={0x7A,0x01};
	cxd2878_wrm(dev,dev->tuner_addr,0x99,cdata,2);

	u8 adata[20];
	switch(dev->base->config->tuner_xtal){
        case SONY_ASCOT3_XTAL_16000KHz:
            adata[0] = 0x10;
            break;
        case SONY_ASCOT3_XTAL_20500KHz:
            adata[0] = 0xD4;
            break;
        case SONY_ASCOT3_XTAL_24000KHz:
            adata[0] = 0x18;
            break;
        case SONY_ASCOT3_XTAL_41000KHz:
            adata[0] = 0x69;
            break;
        }
	
	 adata[1] = 0x84; 
	 adata[2] = 0xA8;
	 adata[3] = 0x82; ///* REFOUT_EN = 1, REFOUT_CNT = 2 */
     /* GPIO0, GPIO1 port setting (0x85, 0x86) */
     /* GPIO setting should be done by sony_ascot3_SetGPO after initialization */
     adata[4] = 0x00;
     adata[5] = 0x00;
 
     /* Clock enable for internal logic block (0x87) */
     adata[6] = 0xC4;
 
     /* Start CPU boot-up (0x88) */
     adata[7] = 0x40;
 
     /* For burst-write (0x89) */
     adata[8] = 0x10;
 
     /* Setting for internal RFAGC (0x8A, 0x8B, 0x8C) */
     adata[9] = 0x00;
   	adata[10] = 0x45;
 	//data[10] = 0x01;  
     adata[11] = 0x75;
   //  data[11] = 0x56;
 
     /* Setting for analog block (0x8D) */
     adata[12] = 0x07;

    /* Initial setting for internal analog block (0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94) */
     adata[13] = 0x1C;
     adata[14] = 0x3F;
     adata[15] = 0x02;
     adata[16] = 0x10;
     adata[17] = 0x20;
     adata[18] = 0x0A;
     adata[19] = 0x00;

	 cxd2878_wrm(dev,dev->tuner_addr,0x81,adata,sizeof(adata));

	 cxd2878_wr(dev,dev->tuner_addr,0x9B,0x00);
	 
	 msleep(10);
	 
	 u8 rdata;
	 cxd2878_rdm(dev,dev->tuner_addr,0x1A,&rdata,1);
	 if(rdata != 0)
	 	return rdata;
	 
	  /* Chip ID auto detection (for CXD2871/2872/2875) */
     if(dev->tunerid == SONY_ASCOT3_CHIP_ID_UNKNOWN){
		 u8 cdata[2] = {0x8C,0x06};
		
		 cxd2878_wrm(dev,dev->tuner_addr,0x17,cdata,sizeof(cdata));
		 msleep(1);
		 cxd2878_rdm(dev,dev->tuner_addr, 0x19, &data, 1);
		 if(data&0x08)
		 	dev->tunerid = SONY_ASCOT3_CHIP_ID_2875;

		 if(dev->tunerid == SONY_ASCOT3_CHIP_ID_UNKNOWN){
			  u8 cdata[2] = {0x96, 0x06}; /* 0x17, 0x18 */
			 cxd2878_wrm(dev,dev->tuner_addr,0x17,cdata,sizeof(cdata));
			 msleep(1);
			 cxd2878_rdm(dev,dev->tuner_addr, 0x19, &data, 1);
			 if(data&0x40)
			 	dev->tunerid = SONY_ASCOT3_CHIP_ID_2871;
			 else
			 	dev->tunerid = SONY_ASCOT3_CHIP_ID_2872;

		 }
	 } 
	  /* VCO current setting */
	  if(dev->tunerid ==SONY_ASCOT3_CHIP_ID_2871A){
	  	 u8 cdata[2] = {0x2A, 0x0E}; /* 0x17, 0x18 */
		 cxd2878_wrm(dev,dev->tuner_addr,0x17,cdata,sizeof(cdata));
		 msleep(1);
		 cxd2878_rdm(dev,dev->tuner_addr, 0x19, &data, 1);
		 cxd2878_wr(dev,dev->tuner_addr,0x95, (data&0x0F));
	  }
	  else{
		  u8 cdata[2] = {0x8D, 0x06};
		  cxd2878_wrm(dev,dev->tuner_addr,0x17,cdata,sizeof(cdata));
		  msleep(1);
		  cxd2878_rdm(dev,dev->tuner_addr, 0x19, &data, 1);
		  cxd2878_wr(dev,dev->tuner_addr,0x95, (u8)(data>>4));

	  }
	  if(dev->tunerid ==SONY_ASCOT3_CHIP_ID_2871A){ 
		  cxd2878_wr(dev,dev->tuner_addr, 0xB0, 0x00);	  
		  cxd2878_wr(dev,dev->tuner_addr, 0x30, 0xE0);
		  cxd2878_wr(dev,dev->tuner_addr, 0xB1, 0x1E);	  
		  cxd2878_wr(dev,dev->tuner_addr, 0xB3, 0x02);
		  msleep(1);
		  cxd2878_rdm(dev,dev->tuner_addr, 0xB4, &data, 1);	  
		  cxd2878_wr(dev,dev->tuner_addr, 0xB3, 0x00);
		  msleep(1);
		  cxd2878_wr(dev,dev->tuner_addr, 0xB1, 0x00);
		  cxd2878_wr(dev,dev->tuner_addr, 0x30, 0xE1);	  
		  cxd2878_wr(dev,dev->tuner_addr, 0xB0, 0x01);
	  }

	  //x_fine
	    /* Keep RF_EXT bit */
      cxd2878_SetRegisterBits(dev,dev->tuner_addr, 0x67, 0x00, 0xFE);
	      /* Disable IF signal output (IF_OUT_SEL setting) (0x74) */
      cxd2878_SetRegisterBits(dev,dev->tuner_addr, 0x74, 0x02, 0x03);

	  u8 cdata1[3]={0x15, 0x00, 0x00};
	  cxd2878_wrm(dev,dev->tuner_addr,0x5E,cdata1,sizeof(cdata1));
      /* Standby setting for CPU (0x88) */
      cxd2878_wr(dev,dev->tuner_addr, 0x88, 0x00);
    
      /* Standby setting for internal logic block (0x87) */
      cxd2878_wr(dev,dev->tuner_addr, 0x87, 0xC0);
      /* Load capacitance control setting for crystal oscillator (0x80) */
      cxd2878_wr(dev,dev->tuner_addr, 0x80, 0x01);	

	  return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: Tuner ASCOT3 i2c error !",KBUILD_MODNAME);
	return ret;
}
static int cxd2878_setstreamoutput(struct cxd2878_dev*dev,int enable)
{
	int ret;
	u8 data = 0;
    /* slave    Bank    Addr    Bit    default    Name
     * ---------------------------------------------------
     * <SLV-T>  00h     A9h     [1:0]  2'b0       OREG_TSTLVALPSEL
     */

    /* Set SLV-T Bank : 0x00 */
    if (cxd2878_wr (dev,dev->slvt , 0x00, 0x00) != 0) {
       goto err;
    }
    if (cxd2878_rdm (dev,dev->slvt, 0xA9, &data, 1) != 0) {
        goto err;
    }

    if ((data & 0x03) == 0x00) {
        /* TS output */
        /* Set SLV-T Bank : 0x00 */
        if (cxd2878_wr (dev,dev->slvt , 0x00, 0x00) != 0) {
            goto err;
        }
        /* Enable TS output */
        if (cxd2878_wr (dev,dev->slvt , 0xC3, enable ? 0x00 : 0x01) != 0) {
            goto err;
        }
    }
		return 0;
	err:
		dev_err(&dev->base->i2c->dev,"%s: cxd2878_setstreamoutput error !",KBUILD_MODNAME);
		return ret; 

}
static int cxd2878_setTSClkModeAndFreq(struct cxd2878_dev *dev)
{
	int ret;
	u8 serialTS;
	u8 tsRateCtrlOff = 0;
	
    struct  sony_demod_ts_clk_configuration_t tsClkConfiguration;
   
    struct sony_demod_ts_clk_configuration_t serialTSClkSettings [2][6] =
    {{ /* Gated Clock */
       /* OSERCKMODE  OSERDUTYMODE  OTSCKPERIOD  OREG_CKSEL_TSTLVIF                         */
        {      3,          1,            8,             0        }, /* High Freq, full rate */
        {      3,          1,            8,             1        }, /* Mid Freq,  full rate */
        {      3,          1,            8,             2        }, /* Low Freq,  full rate */
        {      0,          2,            16,            0        }, /* High Freq, half rate */
        {      0,          2,            16,            1        }, /* Mid Freq,  half rate */
        {      0,          2,            16,            2        }  /* Low Freq,  half rate */
    },
    {  /* Continuous Clock */
       /* OSERCKMODE  OSERDUTYMODE  OTSCKPERIOD  OREG_CKSEL_TSTLVIF                         */
        {      1,          1,            8,             0        }, /* High Freq, full rate */
        {      1,          1,            8,             1        }, /* Mid Freq,  full rate */
        {      1,          1,            8,             2        }, /* Low Freq,  full rate */
        {      2,          2,            16,            0        }, /* High Freq, half rate */
        {      2,          2,            16,            1        }, /* Mid Freq,  half rate */
        {      2,          2,            16,            2        }  /* Low Freq,  half rate */
    }};

    struct sony_demod_ts_clk_configuration_t parallelTSClkSetting =
    {  /* OSERCKMODE  OSERDUTYMODE  OTSCKPERIOD  OREG_CKSEL_TSTLVIF */
               0,          0,            8,             1
    };
    /* NOTE: For ISDB-S3, OREG_CKSEL_TSTLVIF should be 1 */

//    struct sony_demod_ts_clk_configuration_t backwardsCompatibleSerialTSClkSetting [2] =
 //   {  /* OSERCKMODE  OSERDUTYMODE  OTSCKPERIOD  OREG_CKSEL_TSTLVIF                         */
 //       {      3,          1,            8,             1        }, /* Gated Clock          */
  //      {      1,          1,            8,             1        }  /* Continuous Clock     */
 //   };

//    struct sony_demod_ts_clk_configuration_t backwardsCompatibleParallelTSClkSetting =
//    {  /* OSERCKMODE  OSERDUTYMODE  OTSCKPERIOD  OREG_CKSEL_TSTLVIF */
//               0,          0,            8,             1
 //   };	
	
	ret = cxd2878_wr(dev,dev->slvt,0x00,0x00);
	if(ret)
		goto err;
	ret = cxd2878_rdm(dev,dev->slvt, 0xC4, &serialTS, 1);
	if(ret)
		goto err;
	if((dev->system ==SONY_DTV_SYSTEM_ISDBT)||(dev->system == SONY_DTV_SYSTEM_ISDBC)||(dev->system == SONY_DTV_SYSTEM_ATSC))
		tsRateCtrlOff = 1;
	
	cxd2878_SetRegisterBits(dev,dev->slvt,0xD3, tsRateCtrlOff, 0x01);
	cxd2878_SetRegisterBits(dev,dev->slvt,0xDE, 0x00, 0x01);
	cxd2878_SetRegisterBits(dev,dev->slvt,0xDA, 0x00, 0x01);	
	if (serialTS & 0x80) {
	        /* Serial TS */
	        /* Intentional fall through */
	        tsClkConfiguration = serialTSClkSettings[1][1];
	    }
	    else {
	        /* Parallel TS */
	        tsClkConfiguration = parallelTSClkSetting;
	        tsClkConfiguration.tsClkPeriod = 0x08;
	    }	

	  	if (serialTS & 0x80) {
	  		/* Serial TS, so set serial TS specific registers */
	  
	  		/* slave	Bank	Addr	Bit    default	  Name
	  		 * -----------------------------------------------------
	  		 * <SLV-T>	00h 	C4h 	[1:0]  2'b01	  OSERCKMODE
	  		 */
	  		cxd2878_SetRegisterBits(dev,dev->slvt, 0xC4, tsClkConfiguration.serialClkMode, 0x03);
	  
	  
	  		/* slave	Bank	Addr	Bit    default	  Name
	  		 * -------------------------------------------------------
	  		 * <SLV-T>	00h 	D1h 	[1:0]  2'b01	  OSERDUTYMODE
	  		 */
	  		cxd2878_SetRegisterBits(dev,dev->slvt, 0xD1, tsClkConfiguration.serialDutyMode, 0x03);
	  	}

	ret = cxd2878_wr(dev,dev->slvt,0xD9, tsClkConfiguration.tsClkPeriod);
	if(ret)
		goto err;
    /* Disable TS IF Clock */
    /* slave    Bank    Addr    Bit    default    Name
     * -------------------------------------------------------
     * <SLV-T>  00h     32h     [0]    1'b1       OREG_CK_TSTLVIF_EN
     */
    cxd2878_SetRegisterBits(dev,dev->slvt, 0x32, 0x00, 0x01);


    /* slave    Bank    Addr    Bit    default    Name
     * -------------------------------------------------------
     * <SLV-T>  00h     33h     [1:0]  2'b01      OREG_CKSEL_TSTLVIF
     */
    cxd2878_SetRegisterBits(dev,dev->slvt, 0x33, tsClkConfiguration.clkSelTSIf, 0x03);

    /* Enable TS IF Clock */
    /* slave    Bank    Addr    Bit    default    Name
     * -------------------------------------------------------
     * <SLV-T>  00h     32h     [0]    1'b1       OREG_CK_TSTLVIF_EN
     */
    cxd2878_SetRegisterBits(dev,dev->slvt, 0x32, 0x01, 0x01);
         /* Set parity period enable / disable based on backwards compatible TS configuration.
         * These registers are set regardless of broadcasting system for simplicity.
         */
            /* Enable parity period for DVB-T */
        /* Set SLV-T Bank : 0x10 */
		 ret = cxd2878_wr(dev,dev->slvt,0x00, 0x10);
		 if(ret)
			 goto err;

        /* slave    Bank    Addr    Bit    default    Name
         * ---------------------------------------------------------------
         * <SLV-T>  10h     66h     [0]    1'b1       OREG_TSIF_PCK_LENGTH
         */
       cxd2878_SetRegisterBits(dev,dev->slvt, 0x66, 0x01, 0x01);
 
        /* Enable parity period for DVB-C (but affect to ISDB-C/J.83B) */
        /* Set SLV-T Bank : 0x40 */
		ret = cxd2878_wr(dev,dev->slvt,0x00, 0x40);
		if(ret)
			goto err;

        /* slave    Bank    Addr    Bit    default    Name
         * ---------------------------------------------------------------
         * <SLV-T>  40h     66h     [0]    1'b1       OREG_TSIF_PCK_LENGTH
         */
       cxd2878_SetRegisterBits(dev,dev->slvt, 0x66, 0x01, 0x01);

	 return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: set TSClkModeAndFreq error !",KBUILD_MODNAME);
	return ret;

}
static int cxd2878_setTSDataPinHiZ(struct cxd2878_dev*dev,u8 enable)
{
	u8 data = 0,tsDataMask = 0;
	int ret = 0;

    /* slave    Bank    Addr    Bit    default    Name
     * ---------------------------------------------------
     * <SLV-T>  00h     A9h     [0]    1'b0       OREG_TSTLVSEL
     *
     * <SLV-T>  00h     C4h     [7]    1'b0       OSERIALEN
     * <SLV-T>  00h     C4h     [3]    1'b1       OSEREXCHGB7
     *
     * <SLV-T>  01h     C1h     [7]    1'b0       OTLV_SERIALEN
     * <SLV-T>  01h     C1h     [3]    1'b1       OTLV_SEREXCHGB7
     * <SLV-T>  01h     CFh     [0]    1'b0       OTLV_PAR2SEL
     * <SLV-T>  01h     EAh     [6:4]  3'b1       OTLV_PAR2_B1SET
     * <SLV-T>  01h     EAh     [2:0]  3'b0       OTLV_PAR2_B0SET
     */	
	/* Set SLV-T Bank : 0x00 */
	if (cxd2878_wr(dev,dev->slvt, 0x00, 0x00) != 0) {
		goto err;
	}
	
	if (cxd2878_rdm(dev,dev->slvt, 0xA9, &data, 1) != 0) {
		goto err;
	}
	
	if (data & 0x01) {
		/* TLV output */
		/* Set SLV-T Bank : 0x01 */
		if (cxd2878_wr(dev,dev->slvt, 0x00, 0x01) != 0) {
			goto err;
		}
	
		if (cxd2878_rdm (dev,dev->slvt, 0xC1, &data, 1) != 0) {
			goto err;
		}
	
		switch (data & 0x88) {
		case 0x80:
			/* Serial TLV, output from TSDATA0 */
			tsDataMask = 0x01;
			break;
		case 0x88:
			/* Serial TLV, output from TSDATA7 */
			tsDataMask = 0x80;
			break;
		case 0x08:
		case 0x00:
		default:
			/* Parallel TLV */
			if (cxd2878_rdm (dev,dev->slvt, 0xCF, &data, 1) != 0) {
				goto err;
			}
			if (data & 0x01) {
				/* TLV 2bit-parallel */
				if (cxd2878_rdm (dev,dev->slvt, 0xEA, &data, 1) != 0) {
					goto err;
				}
				tsDataMask = (0x01 << (data & 0x07)); /* LSB pin */
				tsDataMask |= (0x01 << ((data >> 4) & 0x07)); /* MSB pin */
			} else {
				/* TLV 8bit-parallel */
				tsDataMask = 0xFF;
			}
			break;
		}
	} else
	
	{
		/* TS output */
		if (cxd2878_rdm ( dev,dev->slvt, 0xC4, &data, 1) != 0) {
			goto err;
		}
	
		switch (data & 0x88) {
		case 0x80:
			/* Serial TS, output from TSDATA0 */
			tsDataMask = 0x01;
			break;
		case 0x88:
			/* Serial TS, output from TSDATA7 */
			tsDataMask = 0x80;
			break;
		case 0x08:
		case 0x00:
		default:
			/* Parallel TS */
			tsDataMask = 0xFF;
			break;
		}
	}
	/* slave	Bank	Addr	Bit    default	  Name
	 * ---------------------------------------------------
	 * <SLV-T>	 00h	81h    [7:0]	8'hFF	OREG_TSDATA_HIZ
	 */
	/* Set SLV-T Bank : 0x00 */
	if (cxd2878_wr (dev,dev->slvt ,0x00, 0x00) != 0) {
		goto err;
	}
	
	if (cxd2878_SetRegisterBits (dev,dev->slvt, 0x81, (u8) (enable ? 0xFF : 0x00), tsDataMask) != 0) {
		goto err;
	}

	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: cxd2878_setTSDataPinHiZ error !",KBUILD_MODNAME);
	return ret;	
	
}
static int cxd2878_sleep(struct cxd2878_dev *dev)
{

	if(dev->state == SONY_DEMOD_STATE_ACTIVE){
		
		cxd2878_setstreamoutput(dev,0);
		cxd2878_wr(dev,dev->slvt,0x00,0x00);
		cxd2878_SetRegisterBits(dev,dev->slvt,0x80, 0x1F, 0x1F);
		cxd2878_setTSDataPinHiZ(dev,1);
	

        switch (dev->system) {
        case SONY_DTV_SYSTEM_DVBT:
			/* Cancel DVB-T Demod parameter setting*/
            	cxd2878_wr(dev,dev->slvt,0x00,0x17);
				u8 data[2] = {0x01,0x02};
				cxd2878_wrm(dev,dev->slvt,0x38,data,2);
				cxd2878_wr(dev,dev->slvt,0x00,0x18);
				cxd2878_wr(dev,dev->slvt,0x31,0x00);
            break;
        case SONY_DTV_SYSTEM_DVBT2:
            //sony_demod_dvbt2_Sleep (dev);
            // Cancel DVB-T2 setting
            cxd2878_wr(dev,dev->slvt,0x00,0x10);
			cxd2878_wr(dev,dev->slvt,0xA5,0x01);
			cxd2878_wr(dev,dev->slvt,0x00,0x13);
			cxd2878_wr(dev,dev->slvt,0x83,0x40);
			cxd2878_wr(dev,dev->slvt,0x86,0x21);
			cxd2878_wr(dev,dev->slvt,0x9F,0xFB);
            break;
        case SONY_DTV_SYSTEM_DVBC:
            //cancel DVB-C Demod parameter setting
            cxd2878_wr(dev,dev->slvt,0x00,0x11);
			cxd2878_wr(dev,dev->slvt,0xA3,0x00);
			cxd2878_wr(dev,dev->slvt,0x00,0x48);
			cxd2878_wr(dev,dev->slvt,0x2C,0x01);
            break;
        case SONY_DTV_SYSTEM_ISDBT:
           // sony_demod_isdbt_Sleep (dev);
           cxd2878_wr(dev,dev->slvt,0x00,0x10);
		   cxd2878_wr(dev,dev->slvt,0x69,0x05);
		   cxd2878_wr(dev,dev->slvt,0x6B,0x07);
		   cxd2878_wr(dev,dev->slvt,0x9D,0x14);
		   cxd2878_wr(dev,dev->slvt,0xD3,0x00);
		   cxd2878_wr(dev,dev->slvt,0xED,0x01);
		   cxd2878_wr(dev,dev->slvt,0xE2,0x4E);
		   cxd2878_wr(dev,dev->slvt,0xF2,0x03);
		   cxd2878_wr(dev,dev->slvt,0xDE,0x32);
		   cxd2878_wr(dev,dev->slvt,0x00,0x15);
		   cxd2878_wr(dev,dev->slvt,0xDE,0x03);
		   cxd2878_wr(dev,dev->slvt,0x00,0x17);
		   u8 data0[2] = {0x01,0x02};
		   cxd2878_wrm(dev,dev->slvt,0x38,data0,2);
		   cxd2878_wr(dev,dev->slvt,0x00,0x1E);
		   cxd2878_wr(dev,dev->slvt,0x73,0x00);
		   cxd2878_wr(dev,dev->slvt,0x00,0x63);
		   cxd2878_wr(dev,dev->slvt,0x81,0x01);
            break;
        case SONY_DTV_SYSTEM_ISDBC:
           cxd2878_wr(dev,dev->slvt,0x00,0x11);
		   cxd2878_wr(dev,dev->slvt,0xA3,0x00);
		   cxd2878_wr(dev,dev->slvt,0x00,0x48);
		   cxd2878_wr(dev,dev->slvt,0x2C,0x01);
		   cxd2878_wr(dev,dev->slvt,0x00,0x40);
		   cxd2878_wr(dev,dev->slvt,0x14,0x1F);
		   cxd2878_wr(dev,dev->slvt,0x1E,0x00);
            break;
        case SONY_DTV_SYSTEM_J83B:
           cxd2878_wr(dev,dev->slvt,0x00,0x11);
		   cxd2878_wr(dev,dev->slvt,0xA3,0x00);
		   cxd2878_wr(dev,dev->slvt,0x00,0x40);
		   cxd2878_wr(dev,dev->slvt,0x21,0x00);
		   cxd2878_wr(dev,dev->slvt,0xC3,0x00);
		   cxd2878_wr(dev,dev->slvt,0xB3,0x02);
		   cxd2878_wr(dev,dev->slvt,0x1E,0x00);
		   cxd2878_wr(dev,dev->slvt,0x8E,0x0E);
		   cxd2878_wr(dev,dev->slvt,0x00,0x41);
		   cxd2878_wr(dev,dev->slvt,0xCF,0x77);
		   cxd2878_wr(dev,dev->slvt,0x00,0x40);
		   cxd2878_wr(dev,dev->slvt,0x14,0x1F);
		   u8 data1[4]={0x09,0x9A,0x00,0xEE};
		   cxd2878_wrm(dev,dev->slvt,0x26,data1,4);
            break;

        case SONY_DTV_SYSTEM_ATSC:          
		   cxd2878_wr(dev,dev->slvr,0x00,0x01);          
		   cxd2878_wr(dev,dev->slvr,0x48,0x01);		   
		   cxd2878_wr(dev,dev->slvt,0x00,0x00);	   
		   cxd2878_wr(dev,dev->slvt,0xD3,0x00);
            break;
        }
	}
	 /* Set SLV-X Bank : 0x00 */
	cxd2878_wr(dev,dev->slvx,0x00,0x00);
	/* TADC setting */
	cxd2878_wr(dev,dev->slvx,0x18,0x01);
	/* Set SLV-T Bank : 0x00 */
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	/* TADC setting */
	cxd2878_wr(dev,dev->slvt,0x49,0x33);
	/* TADC setting */
	cxd2878_wr(dev,dev->slvt,0x4B,0x21);
	/* Demodulator SW reset */
	cxd2878_wr(dev,dev->slvt,0xFE,0x01);
	/* Disable demodulator clock */
	cxd2878_wr(dev,dev->slvt,0x2C,0x00);
	/* Set tstlv mode to default */	
	cxd2878_wr(dev,dev->slvt,0xA9,0x00);
	/* Set demodulator mode to default */
	cxd2878_wr(dev,dev->slvx,0x17,0x01);
	
    dev->state = SONY_DEMOD_STATE_SLEEP;
    dev->system = SONY_DTV_SYSTEM_UNKNOWN;	

	return 0;
}
static int cxd2878_tuneEnd(struct cxd2878_dev *dev)
{
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	cxd2878_wr(dev,dev->slvt,0xFE,0x01);
	cxd2878_setstreamoutput(dev,1);
	
	return 0;
}
static int SLtoAT_BandSetting(struct cxd2878_dev *dev)
{
	int ret = 0;
	u8 bandtmp[3];
	u8 regD7 = 0;
	u8 nominalRate_8M[5] = {0x15,0x00,0x00,0x00,0x00};
 	u8 itbCoef_8M[14] = {
            /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
                0x2F,  0xBA,  0x28,  0x9B,  0x28,  0x9D,  0x28,  0xA1,  0x29,  0xA5,  0x2A,  0xAC,  0x29,  0xB5
            };
	u8 nominalRate_7M[5] = {
        /* TRCG Nominal Rate [37:0] */
        0x18, 0x00, 0x00, 0x00, 0x00
    };
	u8 itbCoef_7M[14] = {
    /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
        0x30,  0xB1,  0x29,  0x9A,  0x28,  0x9C,  0x28,  0xA0,  0x29,  0xA2,  0x2B,  0xA6,  0x2B,  0xAD
    };
	u8 nominalRate_6M[5] = {
                /* TRCG Nominal Rate [37:0] */
                0x1C, 0x00, 0x00, 0x00, 0x00
            };
	u8 itbCoef_6M[14] = {
			/*	COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
				0x31,  0xA8,  0x29,  0x9B,	0x27,  0x9C,  0x28,  0x9E,	0x29,  0xA4,  0x29,  0xA2,	0x29,  0xA8
			};
	u8 nominalRate_5M[5] = {
        /* TRCG Nominal Rate [37:0] */
        0x21, 0x99, 0x99, 0x99, 0x99
    };
	u8 itbCoef_5M[14] = {
        /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
            0x31,  0xA8,  0x29,  0x9B,  0x27,  0x9C,  0x28,  0x9E,  0x29,  0xA4,  0x29,  0xA2,  0x29,  0xA8
        };
	ret = cxd2878_wr(dev,dev->slvt,0x00,0x13);
	if(ret)goto err;
	
	u8 data[2]={0x01,0x14};
	cxd2878_wrm(dev,dev->slvt,0x9C,data,2);

	cxd2878_wr(dev,dev->slvt,0x00,0x10);

	switch(dev->bandwidth){
	case SONY_DTV_BW_8_MHZ:
        cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_8M,5);      
		cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_8M,14);	
		
		bandtmp[0] = (u8)((dev->iffreqConfig.configDVBT_8>>16)&0xFF);
		bandtmp[1] = (u8) ((dev->iffreqConfig.configDVBT_8 >> 8) & 0xFF);
        bandtmp[2] = (u8) (dev->iffreqConfig.configDVBT_8 & 0xFF);
		
		cxd2878_wrm(dev,dev->slvt,0xB6,bandtmp,3); //if freq setting
		cxd2878_wr(dev,dev->slvt,0xD7,0x00); //system bandwith setting
		u8 dataxD9[2] = {0x15,0x28};
		cxd2878_wrm(dev,dev->slvt,0xD9,dataxD9,2);
		cxd2878_wr(dev,dev->slvt,0x00,0x17);
		u8 datax38[2] = {0x01,0x02};
		cxd2878_wrm(dev,dev->slvt,0x38,datax38,2);		
		break;
	case SONY_DTV_BW_7_MHZ:
		cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_7M,5);
		cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_7M,14);
		
		bandtmp[0] = (u8)((dev->iffreqConfig.configDVBT_7>>16)&0xFF);
		bandtmp[1] = (u8) ((dev->iffreqConfig.configDVBT_7 >> 8) & 0xFF);
        bandtmp[2] = (u8) (dev->iffreqConfig.configDVBT_7 & 0xFF);
		cxd2878_wrm(dev,dev->slvt,0xB6,bandtmp,3); //if freq setting
		
		cxd2878_wr(dev,dev->slvt,0xD7,0x02); //system bandwith setting
		u8 dataxD9_1[2] = {0x1F,0xF8};
		cxd2878_wrm(dev,dev->slvt,0xD9,dataxD9_1,2);
		cxd2878_wr(dev,dev->slvt,0x00,0x17);
		u8 datax38_1[2] = {0x00,0x03};
		cxd2878_wrm(dev,dev->slvt,0x38,datax38_1,2);
		break;
	case SONY_DTV_BW_6_MHZ:

		cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_6M,5);
		cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_6M,14);	

		bandtmp[0] = (u8)((dev->iffreqConfig.configDVBT_6>>16)&0xFF);
		bandtmp[1] = (u8) ((dev->iffreqConfig.configDVBT_6 >> 8) & 0xFF);
        bandtmp[2] = (u8) (dev->iffreqConfig.configDVBT_6 & 0xFF);
		cxd2878_wrm(dev,dev->slvt,0xB6,bandtmp,3); //if freq setting
		
		cxd2878_wr(dev,dev->slvt,0xD7,0x04); //system bandwith setting
		u8 dataxD9_2[2] = {0x25,0x4C};
		cxd2878_wrm(dev,dev->slvt,0xD9,dataxD9_2,2);
		cxd2878_wr(dev,dev->slvt,0x00,0x17);
		u8 datax38_2[2] = {0x00,0x03};
		cxd2878_wrm(dev,dev->slvt,0x38,datax38_2,2);
		break;
	case SONY_DTV_BW_5_MHZ:
		cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_5M,5);
		cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_5M,14);	
		bandtmp[0] = (u8)((dev->iffreqConfig.configDVBT_6>>16)&0xFF);
		bandtmp[1] = (u8) ((dev->iffreqConfig.configDVBT_6 >> 8) & 0xFF);
        bandtmp[2] = (u8) (dev->iffreqConfig.configDVBT_6 & 0xFF);
		cxd2878_wrm(dev,dev->slvt,0xB6,bandtmp,3); //if freq setting
		cxd2878_wr(dev,dev->slvt,0xD7,0x06); //system bandwith setting
		u8 dataxD9_3[2] = {0x2C,0xC2};
		cxd2878_wrm(dev,dev->slvt,0xD9,dataxD9_3,2);
		cxd2878_wr(dev,dev->slvt,0x00,0x17);
		u8 datax38_3[2] = {0x00,0x03};
		cxd2878_wrm(dev,dev->slvt,0x38,datax38_3,2);
		break;
	default:
		goto err;
	}

	
	return 0;
	
err:
	dev_err(&dev->base->i2c->dev,"%s: SLtoAT_BandSetting error !",KBUILD_MODNAME);
	return ret;		
}
static int SLtoAT(struct cxd2878_dev*dev)
{
	int ret = 0;
	ret = cxd2878_setTSClkModeAndFreq(dev);
	if(ret)
		goto err;

	ret = cxd2878_wr(dev,dev->slvx,0x00,0x00);
	if(ret)goto err;
	
	cxd2878_wr(dev,dev->slvx,0x17,0x01);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	cxd2878_wr(dev,dev->slvt,0xA9,0x00);
	cxd2878_wr(dev,dev->slvt,0x2C,0x01);
	cxd2878_wr(dev,dev->slvt,0x4B,0x74);
	cxd2878_wr(dev,dev->slvt,0x49,0x00);
	cxd2878_wr(dev,dev->slvx,0x18,0x00);
	cxd2878_wr(dev,dev->slvt,0x00,0x11);
	cxd2878_wr(dev,dev->slvt,0x6A,0x50);
	cxd2878_wr(dev,dev->slvt,0x00,0x10);
	cxd2878_wr(dev,dev->slvt,0xA5,0x01);
	cxd2878_wr(dev,dev->slvt,0x00,0x18);
	cxd2878_wr(dev,dev->slvt,0x31,0x01);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);

	u8 data[] = {0x01,0x01};
	cxd2878_wrm(dev,dev->slvt,0xCE,data,2);
	
	cxd2878_wr(dev,dev->slvt,0x00,0x11);
	u8 datax33[]= {0x00,0x03,0x3B};
	cxd2878_wrm(dev,dev->slvt,0x33,datax33,3);
	
	ret |= SLtoAT_BandSetting(dev);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);

	ret |= cxd2878_SetRegisterBits(dev,dev->slvt,0x80,0x08,0x1F);
	ret |= cxd2878_setTSDataPinHiZ(dev,0);
	if(ret)
		goto err;
	
	return 0;
	
err:
	dev_err(&dev->base->i2c->dev,"%s: SLtoAT error !",KBUILD_MODNAME);
	return ret;	
}
static int cxd2878_set_dvbt(struct dvb_frontend *fe)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret= 0;

	dev->bandwidth = (enum sony_dtv_bandwidth_t)(c->bandwidth_hz/1000000);
	

	ret = cxd2878_wr(dev,dev->slvt,0x00,0x10);
	if(ret)
		goto err;
	// dvbt hierarchy setting
	ret = cxd2878_wr(dev,dev->slvt,0x67,0x00);
	if(ret)
		goto err;	
    if ((dev->state == SONY_DEMOD_STATE_ACTIVE) && (dev->system == SONY_DTV_SYSTEM_DVBT)) {
        /* Demodulator Active and set to DVB-T mode */
		ret |= cxd2878_setstreamoutput(dev,0);
		ret |= SLtoAT_BandSetting(dev);

		if (ret)goto err;
    }
    else if((dev->state == SONY_DEMOD_STATE_ACTIVE) && (dev->system != SONY_DTV_SYSTEM_DVBT)){
        /* Demodulator Active but not DVB-T mode */
		ret |= cxd2878_sleep(dev);
        dev->system = SONY_DTV_SYSTEM_DVBT;
        ret |= SLtoAT (dev);

		if(ret)goto err;

    }
    else if (dev->state == SONY_DEMOD_STATE_SLEEP) {
        /* Demodulator in Sleep mode */
        dev->system = SONY_DTV_SYSTEM_DVBT;

        ret |=  SLtoAT (dev);
		if(ret)
			goto err;
    }
    else {
       goto err;
    }

    /* Update demodulator state */
    dev->state = SONY_DEMOD_STATE_ACTIVE;

		
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: set dvbt error !",KBUILD_MODNAME);
	return ret;

}
static int SLtoAT2_BandSetting(struct cxd2878_dev*dev)
{
	int ret = 0;
	u8 data[3];
	u8	 nominalRate_8m[5] = {
		 /* TRCG Nominal Rate [37:0] */
		 0x15, 0x00, 0x00, 0x00, 0x00
	 };
	u8	 itbCoef_8m[14] = {
			 /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
				 0x2F,	0xBA,  0x28,  0x9B,  0x28,	0x9D,  0x28,  0xA1,  0x29,	0xA5,  0x2A,  0xAC,  0x29,	0xB5
			 };	
	u8	nominalRate_7m[5] = {
				 /* TRCG Nominal Rate [37:0] */
				 0x18, 0x00, 0x00, 0x00, 0x00
			 };

	u8	itbCoef_7m[14] = {
			 /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
				 0x30,	0xB1,  0x29,  0x9A,  0x28,	0x9C,  0x28,  0xA0,  0x29,	0xA2,  0x2B,  0xA6,  0x2B,	0xAD
			 };	
	u8	nominalRate_6m[5] = {
			 /* TRCG Nominal Rate [37:0] */
			 0x1C, 0x00, 0x00, 0x00, 0x00
		 };
	u8	itbCoef_6m[14] = {
		 /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
			 0x31,	0xA8,  0x29,  0x9B,  0x27,	0x9C,  0x28,  0x9E,  0x29,	0xA4,  0x29,  0xA2,  0x29,	0xA8
		 };
	u8	nominalRate_5m[5] = {
				 /* TRCG Nominal Rate [37:0] */
				 0x21, 0x99, 0x99, 0x99, 0x99
			 };
	u8	itbCoef_5m[14] = {
			 /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
				 0x31,	0xA8,  0x29,  0x9B,  0x27,	0x9C,  0x28,  0x9E,  0x29,	0xA4,  0x29,  0xA2,  0x29,	0xA8
			 };
	ret = cxd2878_wr(dev,dev->slvt,0x00,0x20);
	if(ret)
		goto err;
	
	switch(dev->bandwidth){
		case SONY_DTV_BW_8_MHZ:
			 cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_8m,5);
			 cxd2878_wr(dev,dev->slvt,0x00,0x27); 
			 cxd2878_wr(dev,dev->slvt,0x7A,0x00);
			 cxd2878_wr(dev,dev->slvt,0x00,0x10); 
			 cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_8m,14); 
  			 cxd2878_wr(dev,dev->slvt,0xA5,0x01); 
			 data[0] = (u8) ((dev->iffreqConfig.configDVBT2_8 >> 16) & 0xFF);
			 data[1] = (u8) ((dev->iffreqConfig.configDVBT2_8 >> 8) & 0xFF);
			 data[2] = (u8) (dev->iffreqConfig.configDVBT2_8 & 0xFF);

  			 cxd2878_wrm(dev,dev->slvt,0xB6,data,3); 
  			 cxd2878_wr(dev,dev->slvt,0xD7,0); 		
		break;
		case SONY_DTV_BW_7_MHZ:
			 cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_7m,5);
			 cxd2878_wr(dev,dev->slvt,0x00,0x27); 
			 cxd2878_wr(dev,dev->slvt,0x7A,0x00);
			 cxd2878_wr(dev,dev->slvt,0x00,0x10); 
			 cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_7m,14); 
			 cxd2878_wr(dev,dev->slvt,0xA5,0x01);		 
			 data[0] = (u8) ((dev->iffreqConfig.configDVBT2_7 >> 16) & 0xFF);
			 data[1] = (u8) ((dev->iffreqConfig.configDVBT2_7 >> 8) & 0xFF);
			 data[2] = (u8) (dev->iffreqConfig.configDVBT2_7 & 0xFF);

			 cxd2878_wrm(dev,dev->slvt,0xB6,data,3); 
			 cxd2878_wr(dev,dev->slvt,0xD7,0x02); 	
		break;			
		case SONY_DTV_BW_6_MHZ:	
			 cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_6m,5);
 			 cxd2878_wr(dev,dev->slvt,0x00,0x27); 
 			 cxd2878_wr(dev,dev->slvt,0x7A,0x00);
 			 cxd2878_wr(dev,dev->slvt,0x00,0x10); 
 			 cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_6m,14); 
 			 cxd2878_wr(dev,dev->slvt,0xA5,0x01);
			 data[0] = (u8) ((dev->iffreqConfig.configDVBT2_6 >> 16) & 0xFF);
			 data[1] = (u8) ((dev->iffreqConfig.configDVBT2_6 >> 8) & 0xFF);
			 data[2] = (u8) (dev->iffreqConfig.configDVBT2_6 & 0xFF);
			 cxd2878_wrm(dev,dev->slvt,0xB6,data,3); 
			 cxd2878_wr(dev,dev->slvt,0xD7,0x04); 
		break;			
		case SONY_DTV_BW_5_MHZ:
			 cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_5m,5);
			 cxd2878_wr(dev,dev->slvt,0x00,0x27); 
			 cxd2878_wr(dev,dev->slvt,0x7A,0x00);
			 cxd2878_wr(dev,dev->slvt,0x00,0x10); 
			 cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_5m,14); 
			 cxd2878_wr(dev,dev->slvt,0xA5,0x01);
			 data[0] = (u8) ((dev->iffreqConfig.configDVBT2_5 >> 16) & 0xFF);
			 data[1] = (u8) ((dev->iffreqConfig.configDVBT2_5 >> 8) & 0xFF);
			 data[2] = (u8) (dev->iffreqConfig.configDVBT2_5 & 0xFF);
			 cxd2878_wrm(dev,dev->slvt,0xB6,data,3); 
			 cxd2878_wr(dev,dev->slvt,0xD7,0x06); 
		break;
		 default:
		 goto err;		

	}

	
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: SLtoAT2_BandSetting error !",KBUILD_MODNAME);
	return ret;		
}
static int SLtoAT2(struct cxd2878_dev*dev)
{
	int ret = 0;

	ret = cxd2878_setTSClkModeAndFreq(dev);
	if(ret)
		goto err;
	
	ret = cxd2878_wr(dev,dev->slvx,0x00,0x00);
	if(ret)
		goto err;
	/* Set demod mode */
	if (cxd2878_wr(dev,dev->slvx, 0x17, 0x02) != 0) {
		goto err;
	}
	/* Set SLV-T Bank : 0x00 */
	if (cxd2878_wr(dev,dev->slvt, 0x00, 0x00) != 0) {
		goto err;
	}
	/* Set TS/TLV mode */
	if (cxd2878_wr(dev,dev->slvt, 0xA9, 0x00) != 0) {
		goto err;
	}
	/* Enable demod clock */
	if (cxd2878_wr(dev,dev->slvt, 0x2C, 0x01) != 0) {
		goto err;
	}
	
	/* TADC setting */
	if (cxd2878_wr(dev,dev->slvt, 0x4B, 0x74) != 0) {
		goto err;
	}
	
	/* TADC setting */
	if (cxd2878_wr(dev,dev->slvt, 0x49, 0x00) != 0) {
		goto err;
	}
	
	/* TADC setting */
	if (cxd2878_wr(dev,dev->slvx, 0x18, 0x00) != 0) {
		goto err;
	}
	
	/* Set SLV-T Bank : 0x11 */
	if (cxd2878_wr(dev,dev->slvt, 0x00, 0x11) != 0) {
		goto err;
	}
	
	/* BBAGC TARGET level setting
	 * slave	Bank	Addr	Bit    default	   Value		  Name
	 * ----------------------------------------------------------------------------------
	 * <SLV-T>	 11h	 6Ah	[7:0]	  8'h50 	 8'h50		OREG_ITB_DAGC_TRGT[7:0]
	 */
	if (cxd2878_wr(dev,dev->slvt, 0x6A, 0x50) != 0) {
		goto err;
	}
	
	/* Set SLV-T Bank : 0x00 */
	if (cxd2878_wr(dev,dev->slvt, 0x00, 0x00) != 0) {
		goto err;
	}
	
	/* TSIF setting
	 * slave	 Bank	 Addr	Bit 	default    Value	  Name
	 * ----------------------------------------------------------------------------------
	 * <SLV-T>	 00h	 CEh	 [0]	  8'h01 	 8'h01		ONOPARITY
	 * <SLV-T>	 00h	 CFh	 [0]	  8'h01 	 8'h01		ONOPARITY_MANUAL_ON
	 */
	{
		 u8 data[] = { 0x01, 0x01 };
	
		if (cxd2878_wrm(dev ,dev->slvt, 0xCE, data, sizeof (data)) != 0) {
			goto err;
		}
	}
	
	/* DVB-T2 initial setting
	 * slave	 Bank	 Addr	Bit 	default    Value	  Name
	 * ----------------------------------------------------------------------------------
	 * <SLV-T>	 13h	 83h	[7:0]	  8'h40 	 8'h10		OREG_ISIC_POSPROTECT[7:0]
	 * <SLV-T>	 13h	 86h	[7:0]	  8'h21 	 8'h34		OREG_ISIC_CFNRMOFFSET
	 * <SLV-T>	 13h	 9Fh	[7:0]	  8'hFB 	 8'hD8		OREG_CFUPONTHRESHOLDMAX[7:0]
	 * <SLV-T>	 23h	 DBh	 [0]	  8'h00 	 8'h01		OREG_FP_PLP_ALWAYS_MATCH
	 */
	/* Set SLV-T Bank : 0x13 */
	if (cxd2878_wr(dev,dev->slvt, 0x00, 0x13) != 0) {
		goto err;
	}
	
	if (cxd2878_wr(dev,dev->slvt, 0x83, 0x10) != 0) {
		goto err;
	}
	
	if (cxd2878_wr(dev,dev->slvt, 0x86, 0x34) != 0) {
		goto err;
	}
	
	if (cxd2878_wr(dev,dev->slvt, 0x9F, 0xD8) != 0) {
		goto err;
	}
	
	/* Set SLV-T Bank : 0x23 */
	if (cxd2878_wr(dev,dev->slvt, 0x00, 0x23) != 0) {
		goto err;
	}
	
	if (cxd2878_wr(dev,dev->slvt, 0xDB, 0x01) != 0) {
		goto err;
	}
	
	/* Set SLV-T Bank : 0x11 */
	if (cxd2878_wr(dev,dev->slvt, 0x00, 0x11) != 0) {
		goto err;
	}
	
	{
		/* DVB-T2 24MHz Xtal setting
		 * Slave	 Bank	 Addr	Bit 	  Default	 Value		Name
		 * ---------------------------------------------------------------------------------
		 * <SLV-T>	 11h	 33h	[7:0]	  8'hC8 	 8'h00		OCTL_IFAGC_INITWAIT[7:0]
		 * <SLV-T>	 11h	 34h	[7:0]	  8'h02 	 8'h03		OCTL_IFAGC_MINWAIT[7:0]
		 * <SLV-T>	 11h	 35h	[7:0]	  8'h32 	 8'h3B		OCTL_IFAGC_MAXWAIT[7:0]
		 */
		 u8 data[3] = { 0x00, 0x03, 0x3B };
		if (cxd2878_wrm (dev,dev->slvt, 0x33, data, sizeof (data)) != 0) {
			goto err;
		}
	}
	
	/* Set tuner and bandwidth specific settings */
	ret = SLtoAT2_BandSetting (dev);
	
	
	/* Set SLV-T Bank : 0x00 */
	if (cxd2878_wr(dev,dev->slvt, 0x00, 0x00) != 0) {
		goto err;
	}
	
	/* Disable HiZ Setting 1 (TAGC, SAGC(Hi-Z), TSVALID, TSSYNC, TSCLK) */
	if (cxd2878_SetRegisterBits (dev,dev->slvt, 0x80, 0x08, 0x1F) != 0) {
		goto err;
	}
	/* Disable HiZ Setting 2 */
	ret = cxd2878_setTSDataPinHiZ(dev, 0);
	if(ret)goto err;

	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: SLtoAT2 error !",KBUILD_MODNAME);
	return ret;		
}
static int cxd2878_set_dvbt2(struct dvb_frontend *fe)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret= 0;


	dev->bandwidth = (enum sony_dtv_bandwidth_t)(c->bandwidth_hz/1000000);

	/* Configure for manual PLP selection. */
	ret = cxd2878_wr(dev,dev->slvt,0x00,0x23);
	if(ret)
		goto err;
	ret = cxd2878_wr(dev,dev->slvt,0xAF,c->stream_id & 0xFF);
	if(ret)
		goto err;
	ret = cxd2878_wr(dev,dev->slvt,0xAD,0x1);
	if(ret)
		goto err;

	// set profile
	ret = cxd2878_wr(dev,dev->slvt,0x00,0x2E);
	if(ret)
		goto err;
	ret = cxd2878_wr(dev,dev->slvt,0x10,0x00);
	if(ret)
		goto err;
	ret = cxd2878_wr(dev,dev->slvt,0x00,0x2B);
	if(ret)
		goto err;
	ret = cxd2878_wr(dev,dev->slvt,0x9D,0x2E);
	if(ret)
		goto err;
	
	//tune
	if((dev->state == SONY_DEMOD_STATE_ACTIVE)&&(dev->system ==SONY_DTV_SYSTEM_DVBT2))
	{
	    cxd2878_setstreamoutput(dev,0);
		SLtoAT2_BandSetting(dev);
	}
	else if((dev->state == SONY_DEMOD_STATE_ACTIVE)&&(dev->system !=SONY_DTV_SYSTEM_DVBT2))
	{
		cxd2878_sleep(dev);
		dev->system = SONY_DTV_SYSTEM_DVBT2;
		SLtoAT2(dev);

	}
	else if(dev->state == SONY_DEMOD_STATE_SLEEP)
	{
		dev->system = SONY_DTV_SYSTEM_DVBT2;
		SLtoAT2(dev);
	}
	else 
		goto err;

	dev->state = SONY_DEMOD_STATE_ACTIVE;

	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: set dvbt2 error !",KBUILD_MODNAME);
	return ret;	
}

static int SLtoAC_BandSetting(struct cxd2878_dev *dev)
{
	int  ret = 0;
	u8 data[3];
	u8 itbCoef_8[14] = {
	 /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
		 0x29,	0x9A,  0x28,  0x9E,  0x2F,	0xB9,  0x27,  0xA5,  0x28,	0xA9,  0x2B,  0xB0,  0x08,	0xD6
	 };
	u8 symRate_8[4] = {
	 /*  tsrate1 tsrate2 tsrate3 tsrate4 */
		 0x09,	 0x9A,	 0x00,	 0xEE
	 };
	u8	itbCoef_7[14] = {
	 /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
		 0x29,	0x9A,  0x28,  0x9E,  0x2F,	0xB9,  0x27,  0xA5,  0x28,	0xA9,  0x2B,  0xB0,  0x08,	0xD6
	 };
	u8 symRate_7[4] = {
	 /*  tsrate1 tsrate2 tsrate3 tsrate4 */
		 0x08,	 0x66,	 0x00,	 0xEE
	 };
	u8 	itbCoef_6[14] = {
	 /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
		 0x31,	0xA8,  0x29,  0x9B,  0x27,	0x9C,  0x28,  0x9E,  0x29,	0xA4,  0x29,  0xA2,  0x29,	0xA8
	 };
	u8 symRate_6[4] = {
	 /*  tsrate1 tsrate2 tsrate3 tsrate4 */
		 0x07,	 0x33,	 0x00,	 0xEE
	 };
	ret = cxd2878_wr(dev,dev->slvt,0x00,0x10);
	if(ret)
		goto err;

	switch(dev->bandwidth){
		case SONY_DTV_BW_8_MHZ:
			 cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_8,14);	
			 data[0] = (u8) ((dev->iffreqConfig.configDVBC_8 >> 16) & 0xFF);
			 data[1] = (u8) ((dev->iffreqConfig.configDVBC_8 >> 8) & 0xFF);
			 data[2] = (u8) (dev->iffreqConfig.configDVBC_8 & 0xFF);
			 cxd2878_wrm(dev,dev->slvt,0xB6,data,3);
			 cxd2878_wr(dev,dev->slvt,0x00,0x11);
			 cxd2878_wr(dev,dev->slvt,0xA3,0);
			 cxd2878_wr(dev,dev->slvt,0x00,0x40);
			 cxd2878_wrm(dev,dev->slvt,0x26,symRate_8,4); //set symbol rate search range

			break;
		case SONY_DTV_BW_7_MHZ:
			 cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_7,14);
			 data[0] = (u8) ((dev->iffreqConfig.configDVBC_7 >> 16) & 0xFF);
			 data[1] = (u8) ((dev->iffreqConfig.configDVBC_7 >> 8) & 0xFF);
			 data[2] = (u8) (dev->iffreqConfig.configDVBC_7 & 0xFF);
		     cxd2878_wrm(dev,dev->slvt,0xB6,data,3);
			 cxd2878_wr(dev,dev->slvt,0x00,0x11);
			 cxd2878_wr(dev,dev->slvt,0xA3,0);
			 cxd2878_wr(dev,dev->slvt,0x00,0x40);
			 cxd2878_wrm(dev,dev->slvt,0x26,symRate_7,4); //set symbol rate search range

			break;	
		case SONY_DTV_BW_6_MHZ:
			 cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_6,14);
			 data[0] = (u8) ((dev->iffreqConfig.configDVBC_6 >> 16) & 0xFF);
			 data[1] = (u8) ((dev->iffreqConfig.configDVBC_6 >> 8) & 0xFF);
			 data[2] = (u8) (dev->iffreqConfig.configDVBC_6 & 0xFF);
			 cxd2878_wrm(dev,dev->slvt,0xB6,data,3);
			 cxd2878_wr(dev,dev->slvt,0x00,0x11);
			 cxd2878_wr(dev,dev->slvt,0xA3,0x14);
			 cxd2878_wr(dev,dev->slvt,0x00,0x40);
			 cxd2878_wrm(dev,dev->slvt,0x26,symRate_6,4); //set symbol rate search range
			break;
		default:
			goto err;
	 }
	
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: set SLtoAC_BandSetting error !",KBUILD_MODNAME);
	return ret;		
}
static int SLtoAC(struct cxd2878_dev *dev)
{
	int ret = 0;

	ret = cxd2878_setTSClkModeAndFreq(dev);
	if(ret)
		goto err;
	ret = cxd2878_wr(dev,dev->slvx,0x00,0x00);
	if(ret)
		goto err;
	cxd2878_wr(dev,dev->slvx,0x17,0x04);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	cxd2878_wr(dev,dev->slvt,0xA9,0x00);
	cxd2878_wr(dev,dev->slvt,0x2C,0x01);
	cxd2878_wr(dev,dev->slvt,0x4B,0x74);
	cxd2878_wr(dev,dev->slvt,0x49,0x00);
	cxd2878_wr(dev,dev->slvx,0x18,0x00);
	cxd2878_wr(dev,dev->slvt,0x00,0x11);
	cxd2878_wr(dev,dev->slvt,0x6A,0x48);
	cxd2878_wr(dev,dev->slvt,0x00,0x10);
	cxd2878_wr(dev,dev->slvt,0xA5,0x01);
	cxd2878_wr(dev,dev->slvt,0x00,0x11);
	
	u8 datax33[3] = { 0x00, 0x03, 0x3B };
	cxd2878_wrm(dev,dev->slvt,0x33,datax33,3);
	cxd2878_wr(dev,dev->slvt,0x00,0x48);
	cxd2878_wr(dev,dev->slvt,0x2C,0x03);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	u8 dataxce[2] = { 0x01, 0x01 };
	cxd2878_wrm(dev,dev->slvt,0xCE,dataxce,2);

	ret = SLtoAC_BandSetting(dev);
	if(ret)goto err;
	cxd2878_wr(dev,dev->slvt,0x00,0x00);

	cxd2878_SetRegisterBits(dev,dev->slvt,0x80,0x08,0x1F);

	ret = cxd2878_setTSDataPinHiZ(dev,0);
	if(ret)
		goto err;
	
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: set SLtoAC error !",KBUILD_MODNAME);
	return ret;

}
static int cxd2878_set_dvbc(struct dvb_frontend *fe)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret= 0;
	
	dev->bandwidth = SONY_DTV_BW_8_MHZ;
	if ((dev->state == SONY_DEMOD_STATE_ACTIVE) && (dev->system == SONY_DTV_SYSTEM_DVBC)) {

		/* Demodulator Active and set to DVB-C mode */
		ret |= cxd2878_setstreamoutput(dev,0);
		ret |= SLtoAC_BandSetting(dev);
		if(ret)
			goto err;

	}
	else if((dev->state == SONY_DEMOD_STATE_ACTIVE) && (dev->system != SONY_DTV_SYSTEM_DVBC)){
		/* Demodulator Active but not DVB-C mode */
		ret |= cxd2878_sleep(dev) ;
		dev->system = SONY_DTV_SYSTEM_DVBC;
		ret |= SLtoAC (dev);
		if(ret)
			goto err;

	}
	else if (dev->state == SONY_DEMOD_STATE_SLEEP) {
		/* Demodulator in Sleep mode */
		dev->system = SONY_DTV_SYSTEM_DVBC;
	
		ret |= SLtoAC (dev);
		if(ret)
			goto err;
	}
	else {
		goto err;
	}
	
	/* Update demodulator state */
	dev->state = SONY_DEMOD_STATE_ACTIVE;
	

	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: set dvbc error !",KBUILD_MODNAME);
	return ret;

}
static int SLtoAIT_BandSetting(struct cxd2878_dev *dev)
{
	int ret = 0;
	u8 data[3],dataxd9[2];

	u8 nominalRate_8[5] = {
                /* TRCG Nominal Rate [37:0] */
                0x11, 0xB8, 0x00, 0x00, 0x00
            };
		 
	u8	itbCoef_8[14] = {
					 /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
						 0x2F,	0xBA,  0x28,  0x9B,  0x28,	0x9D,  0x28,  0xA1,  0x29,	0xA5,  0x2A,  0xAC,  0x29,	0xB5
					 };

	u8	nominalRate_7[5] = {
                /* TRCG Nominal Rate [37:0] */
                0x14, 0x40, 0x00, 0x00, 0x00
            };
	u8	itbCoef_7[14] = {
            /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
                0x30,  0xB1,  0x29,  0x9A,  0x28,  0x9C,  0x28,  0xA0,  0x29,  0xA2,  0x2B,  0xA6,  0x2B,  0xAD
            };
	u8	nominalRate_6[5] = {
                /* TRCG Nominal Rate [37:0] */
                0x17, 0xA0, 0x00, 0x00, 0x00
            };
	u8	itbCoef_6[14] = {
            /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
                0x31,  0xA8,  0x29,  0x9B,  0x27,  0x9C,  0x28,  0x9E,  0x29,  0xA4,  0x29,  0xA2,  0x29,  0xA8
            };
	ret = cxd2878_wr(dev,dev->slvt,0x00,0x10);
	if(ret)
		goto err;
	switch(dev->bandwidth){
	case SONY_DTV_BW_8_MHZ:
	  	  cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_8,5);
		  cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_8,14);
		  data[0] = (u8) ((dev->iffreqConfig.configISDBT_8 >> 16) & 0xFF);
          data[1] = (u8) ((dev->iffreqConfig.configISDBT_8 >> 8) & 0xFF);
          data[2] = (u8) (dev->iffreqConfig.configISDBT_8 & 0xFF);
		  cxd2878_wrm(dev,dev->slvt,0xB6,data,3);
		  cxd2878_wr(dev,dev->slvt,0xD7,0x00);
		  dataxd9[0]=0x13;
		  dataxd9[1] = 0xFC;
		  cxd2878_wrm(dev,dev->slvt,0xD9,dataxd9,2);
		  cxd2878_wr(dev,dev->slvt,0x00,0x12);
		  cxd2878_wr(dev,dev->slvt,0x71,3);
		  cxd2878_wr(dev,dev->slvt,0x00,0x15);
		  cxd2878_wr(dev,dev->slvt,0xBE,3);
	   	break;
	case SONY_DTV_BW_7_MHZ:
		  cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_7,5);
		  cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_7,14);

		  data[0] = (u8) ((dev->iffreqConfig.configISDBT_7 >> 16) & 0xFF);
          data[1] = (u8) ((dev->iffreqConfig.configISDBT_7 >> 8) & 0xFF);
          data[2] = (u8) (dev->iffreqConfig.configISDBT_7 & 0xFF);
		  cxd2878_wrm(dev,dev->slvt,0xB6,data,3);
		  cxd2878_wr(dev,dev->slvt,0xD7,0x00);
		  dataxd9[0]=0x1A;
		  dataxd9[1]=0xFA;
		  cxd2878_wrm(dev,dev->slvt,0xD9,dataxd9,2);
		  cxd2878_wr(dev,dev->slvt,0x00,0x12);
		  cxd2878_wr(dev,dev->slvt,0x71,3);
		  cxd2878_wr(dev,dev->slvt,0x00,0x15);
		  cxd2878_wr(dev,dev->slvt,0xBE,2);
		 break;
	case SONY_DTV_BW_6_MHZ:
		  cxd2878_wrm(dev,dev->slvt,0x9F,nominalRate_6,5);
		  cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef_6,14);
		  data[0] = (u8) ((dev->iffreqConfig.configISDBT_6 >> 16) & 0xFF);
          data[1] = (u8) ((dev->iffreqConfig.configISDBT_6 >> 8) & 0xFF);
          data[2] = (u8) (dev->iffreqConfig.configISDBT_6 & 0xFF);
	 	  cxd2878_wrm(dev,dev->slvt,0xB6,data,3);
		  cxd2878_wr(dev,dev->slvt,0xD7,0x00);
		  dataxd9[0]=0x1F;
		  dataxd9[1]=0x79;
		  cxd2878_wrm(dev,dev->slvt,0xD9,dataxd9,2);
		  cxd2878_wr(dev,dev->slvt,0x00,0x12);
		  cxd2878_wr(dev,dev->slvt,0x71,7);
		  cxd2878_wr(dev,dev->slvt,0x00,0x15);
		  cxd2878_wr(dev,dev->slvt,0xBE,2);
		  break;
	default:
		goto err;

	}

	
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: SLtoAIT_BandSetting error !",KBUILD_MODNAME);
	return ret;
}
static int SLtoAIT(struct cxd2878_dev *dev)
{
	int ret = 0;

	ret = cxd2878_setTSClkModeAndFreq(dev);
	if(ret)
		goto err;
	ret = cxd2878_wr(dev,dev->slvx,0x00,0x00);
	if(ret)
		goto err;
	cxd2878_wr(dev,dev->slvx,0x17,0x06);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	cxd2878_wr(dev,dev->slvt,0xA9,0x00);
	cxd2878_wr(dev,dev->slvt,0x2C,0x01);
	cxd2878_wr(dev,dev->slvt,0x4B,0x74);
	cxd2878_wr(dev,dev->slvt,0x49,0x00);
	cxd2878_wr(dev,dev->slvx,0x18,0x00);
	
	cxd2878_wr(dev,dev->slvt,0x00,0x11); //  SLtoAIT commonsetting
	cxd2878_wr(dev,dev->slvt,0x6A,0x50);
	cxd2878_wr(dev,dev->slvt,0x00,0x10);
	cxd2878_wr(dev,dev->slvt,0xA5,0x01);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	
	u8 dataxce[2]={0x00,0x00};
	cxd2878_wrm(dev,dev->slvt,0xCE,dataxce,2);
	cxd2878_wr(dev,dev->slvt,0x00,0x10);
	cxd2878_wr(dev,dev->slvt,0x69,0x04);
	cxd2878_wr(dev,dev->slvt,0x6B,0x03);
	cxd2878_wr(dev,dev->slvt,0x9D,0x50);
	cxd2878_wr(dev,dev->slvt,0xD3,0x06);
	cxd2878_wr(dev,dev->slvt,0xED,0x00);
	cxd2878_wr(dev,dev->slvt,0xE2,0xCE);
	cxd2878_wr(dev,dev->slvt,0xF2,0x13);
	cxd2878_wr(dev,dev->slvt,0xDE,0x2E);
	cxd2878_wr(dev,dev->slvt,0x00,0x15);
	cxd2878_wr(dev,dev->slvt,0xDE,0x02);
	cxd2878_wr(dev,dev->slvt,0x00,0x17);
	
	u8 datax38[2] = {0x00,0x03};
	cxd2878_wrm(dev,dev->slvt,0x38,datax38,2);
	cxd2878_wr(dev,dev->slvt,0x00,0x1E);
	cxd2878_wr(dev,dev->slvt,0x73,0x68);
	cxd2878_wr(dev,dev->slvt,0x00,0x63);
	cxd2878_wr(dev,dev->slvt,0x81,0x00);
	cxd2878_wr(dev,dev->slvt,0x00,0x11);

	u8 datax33[3] = {0x00,0x03,0x3B};
	cxd2878_wrm(dev,dev->slvt,0x33,datax33,3);
	cxd2878_wr(dev,dev->slvt,0x00,0x60);
	
	u8 dataxa8[2] = {0xB7,0x1B};
	cxd2878_wrm(dev,dev->slvt,0xA8,dataxa8,2); //end

	SLtoAIT_BandSetting(dev);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);	
	cxd2878_SetRegisterBits(dev,dev->slvt,0x80,0x08,0x1F);

	cxd2878_setTSDataPinHiZ(dev,0);
	
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: SLtoAIT error !",KBUILD_MODNAME);
	return ret;	
}
static int cxd2878_set_isdbt(struct dvb_frontend *fe)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret= 0;

	dev->bandwidth = (enum sony_dtv_bandwidth_t)(c->bandwidth_hz/1000000);
    if ((dev->state == SONY_DEMOD_STATE_ACTIVE) && (dev->system == SONY_DTV_SYSTEM_ISDBT)) {
        /* Demodulator Active and set to ISDB-T mode */
        cxd2878_wr(dev,dev->slvt,0x00,0x00);    
        cxd2878_wr(dev,dev->slvt,0xc3,0x01);
        SLtoAIT_BandSetting(dev);    

    }
    else if((dev->state == SONY_DEMOD_STATE_ACTIVE) && (dev->system != SONY_DTV_SYSTEM_ISDBT)){
        /* Demodulator Active but not ISDB-T mode */
        cxd2878_sleep( dev);
        dev->system = SONY_DTV_SYSTEM_ISDBT;
         SLtoAIT (dev);

    }
    else if (dev->state == SONY_DEMOD_STATE_SLEEP) {
        /* Demodulator in Sleep mode */
        dev->system = SONY_DTV_SYSTEM_ISDBT;
		
        SLtoAIT (dev);

    }
    else {
        goto err;
    }

    /* Update demodulator state */
    dev->state = SONY_DEMOD_STATE_ACTIVE;

	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: set isdbt error !",KBUILD_MODNAME);
	return ret;

}

static int SLtoACC_BandSetting(struct cxd2878_dev *dev)
{
	int ret = 0;
	u8 datax14;
	u8 data[3];
	u8 symRate[4];

	ret = cxd2878_wr(dev,dev->slvt,0x00,0x10);
	if(ret)
		goto err;

	switch(dev->bandwidth){
		case SONY_DTV_BW_J83B_5_06_5_36_MSPS:
			symRate[0] = 0x07;
			symRate[1] = 0x26;
			symRate[2] = 0x06;
			symRate[3] = 0xBE;
			data[0] = (u8) ((dev->iffreqConfig.configJ83B_5_06_5_36 >> 16) & 0xFF);
            data[1] = (u8) ((dev->iffreqConfig.configJ83B_5_06_5_36 >> 8) & 0xFF);
            data[2] = (u8) (dev->iffreqConfig.configJ83B_5_06_5_36 & 0xFF);
			datax14 = 0x14;
			break;
		case SONY_DTV_BW_J83B_5_60_MSPS:
			symRate[0] = 0x07;
			symRate[1] = 0x77;
			symRate[2] = 0x07;
			symRate[3] = 0x77; 
			data[0] = (u8) ((dev->iffreqConfig.configJ83B_5_60>> 16) & 0xFF);
            data[1] = (u8) ((dev->iffreqConfig.configJ83B_5_60 >> 8) & 0xFF);
            data[2] = (u8) (dev->iffreqConfig.configJ83B_5_60 & 0xFF); 
			datax14 = 0x10;
			break;
		default:
			goto err;
	}

	cxd2878_wrm(dev,dev->slvt,0xB6,data,3);
	cxd2878_wr(dev,dev->slvt,0x00,0x40);
	cxd2878_wr(dev,dev->slvt,0x14,datax14);
	cxd2878_wrm(dev,dev->slvt,0x26,symRate,4);
	
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s:  SLtoACC_BandSetting error !",KBUILD_MODNAME);
	return ret;	
}
static int SLtoACC(struct cxd2878_dev *dev)
{
	int ret = 0;
	
	ret = cxd2878_setTSClkModeAndFreq(dev);
	if(ret)
		goto err;
	cxd2878_wr(dev,dev->slvx,0x00,0x00);
	cxd2878_wr(dev,dev->slvx,0x17,0x08);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	cxd2878_wr(dev,dev->slvt,0xA9,0x00);
	cxd2878_wr(dev,dev->slvt,0x2C,0x01);	
	cxd2878_wr(dev,dev->slvt,0x4B,0x74);
	cxd2878_wr(dev,dev->slvt,0x49,0x00);
	cxd2878_wr(dev,dev->slvx,0x18,0x00);
	cxd2878_wr(dev,dev->slvt,0x00,0x11);	
	cxd2878_wr(dev,dev->slvt,0x6A,0x48);	
	cxd2878_wr(dev,dev->slvt,0x00,0x10);
	cxd2878_wr(dev,dev->slvt,0xA5,0x01);
	cxd2878_wr(dev,dev->slvt,0x00,0x40);
	cxd2878_wr(dev,dev->slvt,0x21,0x04);
	cxd2878_wr(dev,dev->slvt,0xB3,0x05);
	cxd2878_wr(dev,dev->slvt,0x1E,0x80);
	cxd2878_wr(dev,dev->slvt,0x8E,0x58);
	cxd2878_wr(dev,dev->slvt,0x00,0x41);
	cxd2878_wr(dev,dev->slvt,0xCF,0x99);
	cxd2878_wr(dev,dev->slvt,0x00,0x11);
	cxd2878_wr(dev,dev->slvt,0xA3,0x14);
	
	u8 datax33[3] = { 0x00, 0x03, 0x3B };
	cxd2878_wrm(dev,dev->slvt,0x33,datax33,3);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	u8 dataxce[2] = {0x01,0x01};
	cxd2878_wrm(dev,dev->slvt,0xCE,dataxce,2);

	cxd2878_wr(dev,dev->slvt,0x00,0x10);
	
	u8 itbCoef[14] = {
        /*  COEF01 COEF02 COEF11 COEF12 COEF21 COEF22 COEF31 COEF32 COEF41 COEF42 COEF51 COEF52 COEF61 COEF62 */
            0x31,  0xA8,  0x29,  0x9B,  0x27,  0x9C,  0x28,  0x9E,  0x29,  0xA4,  0x29,  0xA2,  0x29,  0xA8
        };
	cxd2878_wrm(dev,dev->slvt,0xA6,itbCoef,14);

	SLtoACC_BandSetting(dev);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	cxd2878_SetRegisterBits(dev,dev->slvt,0x80,0x08,0x1F);
	cxd2878_setTSDataPinHiZ(dev,0);
	
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: set SLtoACC error !",KBUILD_MODNAME);
	return ret;	
}
static int cxd2878_set_mcns(struct dvb_frontend *fe)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret= 0;

	dev->bandwidth = SONY_DTV_BW_J83B_5_06_5_36_MSPS; // < For J.83B. 5.06/5.36Msps auto selection commonly used in US. 

	if(c->symbol_rate>=5600000) //< For J.83B. 5.6Msps used by SKY PerfecTV! Hikari in Japan. 
		dev->bandwidth = SONY_DTV_BW_J83B_5_60_MSPS;

    if ((dev->state == SONY_DEMOD_STATE_ACTIVE) && (dev->system == SONY_DTV_SYSTEM_J83B)) {
        /* Demodulator Active and set to J.83B mode */
    	ret = cxd2878_setstreamoutput(dev,0);
		ret |= SLtoACC_BandSetting(dev);
		if(ret)
			goto err;

    }
    else if((dev->state == SONY_DEMOD_STATE_ACTIVE) && (dev->system != SONY_DTV_SYSTEM_J83B)){
        /* Demodulator Active but not J.83B mode */
        ret = cxd2878_sleep(dev);
    
        dev->system = SONY_DTV_SYSTEM_J83B;
 
        ret |= SLtoACC (dev);
		if(ret)
			goto err;

    }
    else if (dev->state == SONY_DEMOD_STATE_SLEEP) {
        /* Demodulator in Sleep mode */
        dev->system = SONY_DTV_SYSTEM_J83B;
   
        ret = SLtoACC (dev);
		if(ret)
			goto err;
    }
    else {
     goto err;
    }

    /* Update demodulator state */
    dev->state = SONY_DEMOD_STATE_ACTIVE;

	
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: set mcns error !",KBUILD_MODNAME);
	return ret;

}

static int SLtoAA(struct cxd2878_dev *dev)
{
	int ret = 0;
	u8 data[4];
	u8 noSignalThresh[3];
	u8 signalThresh[3];


	ret = cxd2878_setTSClkModeAndFreq(dev);
	if(ret)
		goto err;	

	cxd2878_wr(dev,dev->slvx,0x00,0x00);
	cxd2878_wr(dev,dev->slvx,0x17,0x0F);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	cxd2878_wr(dev,dev->slvt,0xA9,0x00);
	cxd2878_wr(dev,dev->slvt,0x2C,0x01);
	cxd2878_wr(dev,dev->slvt,0x4B,0x74);
	cxd2878_wr(dev,dev->slvt,0x49,0x00);
	cxd2878_wr(dev,dev->slvx,0x18,0x00);

	cxd2878_wr(dev,dev->slvr,0x00,0x01);  //demodabort
	cxd2878_wr(dev,dev->slvr,0x48,0x01); // atsccpustate = IDLE

	data[0] = (u8) ( dev->iffreqConfig.configATSC		 & 0xFF);
	data[1] = (u8) ((dev->iffreqConfig.configATSC >> 8)  & 0xFF);
	data[2] = (u8) ((dev->iffreqConfig.configATSC >> 16) & 0xFF);
	data[3] = (u8) ((dev->iffreqConfig.configATSC >> 24) & 0xFF);

	slaveRWriteMultiRegisters(dev,0xA3,0xA1,data,4);

	cxd2878_atsc_SlaveRWriteRegister (dev, 0xA0, 0x13, 0x03, 0x03);

	u8 data1[14] = { 0x31, 0xA5, 0x2E, 0x9F, 0x2B, 0x99, 0x00, 0xCD, 0x00, 0xCD, 0x00, 0x00, 0x2B, 0x9D };
	slaveRWriteMultiRegisters (dev, 0x06, 0xA0, data1, sizeof(data1));

	noSignalThresh[0] = (u8)(dev->atscNoSignalThresh & 0xFF);
	noSignalThresh[1] = (u8)((dev->atscNoSignalThresh >> 8) & 0xFF);
	noSignalThresh[2] = (u8)((dev->atscNoSignalThresh >> 16) & 0xFF);
	signalThresh[0] = (u8)(dev->atscSignalThresh & 0xFF);
	signalThresh[1] = (u8)((dev->atscSignalThresh >> 8) & 0xFF);
	signalThresh[2] = (u8)((dev->atscSignalThresh >> 16) & 0xFF);
	slaveRWriteMultiRegisters (dev, 0xA0, 0x6F, noSignalThresh, sizeof(noSignalThresh));

	slaveRWriteMultiRegisters (dev, 0x09, 0x80, noSignalThresh, sizeof(noSignalThresh));

	slaveRWriteMultiRegisters (dev, 0xA0, 0x73, signalThresh, sizeof(signalThresh));

	slaveRWriteMultiRegisters (dev, 0x09, 0x83, signalThresh, sizeof(signalThresh));

	cxd2878_atsc_SlaveRWriteRegister (dev, 0x06, 0x71, 0x05, 0x07);
	cxd2878_atsc_SlaveRWriteRegister (dev, 0xA3, 0xA0, 0x10, 0x10);
	cxd2878_wr(dev,dev->slvt,0x00,0x00);
	cxd2878_SetRegisterBits( dev,dev->slvt,0x80, 0x08, 0x1F);

	cxd2878_setTSDataPinHiZ(dev,0);
	
	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: SLtoAA error !",KBUILD_MODNAME);
	return ret;

}

static int cxd2878_set_atsc(struct dvb_frontend *fe)
{	
	struct cxd2878_dev *dev = fe->demodulator_priv;
	int ret= 0;

	dev->bandwidth = SONY_DTV_BW_6_MHZ;

    if ((dev->state == SONY_DEMOD_STATE_ACTIVE) && (dev->system == SONY_DTV_SYSTEM_ATSC)) {
        /* Demodulator Active and set to ATSC mode */
		cxd2878_setstreamoutput(dev,0);
    } else if ((dev->state == SONY_DEMOD_STATE_ACTIVE) && (dev->system != SONY_DTV_SYSTEM_ATSC)) {
        /* Demodulator Active but not ATSC mode */
        cxd2878_sleep(dev);

        dev->system = SONY_DTV_SYSTEM_ATSC;

         SLtoAA (dev);

    } else if (dev->state == SONY_DEMOD_STATE_SLEEP) {
        /* Demodulator in Sleep mode */
        dev->system = SONY_DTV_SYSTEM_ATSC;
		
        SLtoAA (dev);

    } else {
        goto err;
    }

    /* Update demodulator state */
    dev->state = SONY_DEMOD_STATE_ACTIVE;


	return 0;
err:
	dev_err(&dev->base->i2c->dev,"%s: set atsc error !",KBUILD_MODNAME);
	return ret;

}
//GPIO2 for output lock_flag 1:locked 0:unlocked
static void cxd2878_lock_flag(struct cxd2878_dev *dev,bool enable)  
{
	
	cxd2878_SetBankAndRegisterBits(dev,dev->slvx,0x00, 0xA5, 0x00, 0x0F); 
	cxd2878_SetBankAndRegisterBits(dev,dev->slvx,0x00, 0x82, 1, 0x4);
	cxd2878_SetBankAndRegisterBits(dev,dev->slvx,0x00, 0xA2, enable?0x07:0x00, 0x4); 
	
	return;
}
static int cxd2878_init(struct dvb_frontend *fe)
{
	struct cxd2878_dev*dev = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	
	int ret;
	
	mutex_lock(&dev->base->i2c_lock);

	if(dev->warm)
		goto warm_start;
	//clear all registers
	ret = cxd2878_wr(dev,dev->slvx,0x02,0x00);
	if(ret)
		goto err;

	 msleep(4);
	 
	 cxd2878_wr(dev,dev->slvx,0x00,0x00);
	//init setting for crystal oscillator
	 cxd2878_wr(dev,dev->slvx,0x1D,0x00);
	 /* Clock mode setting */
	 cxd2878_wr(dev,dev->slvx,0x14,dev->base->config->xtal);
	 msleep(2);
	 cxd2878_wr(dev,dev->slvx,0x50,0x00);
	 
	 if(dev->base->config->atscCoreDisable)/* ATSC 1.0 core disable setting */
	 	 cxd2878_wr(dev,dev->slvx,0x90,0x00);
	 
	 msleep(2);
	 cxd2878_wr(dev,dev->slvx,0x10,0x00); 

	if(dev->base->config->atscCoreDisable)
		msleep(1);
	else
		msleep(21);
	
	if(dev->chipid == SONY_DEMOD_CHIP_ID_CXD6802){
		u8 data[] = {0x00, 0x00, 0x00, 0x00};
		
		cxd2878_wr(dev,dev->slvt,0x00,0x9C); 
		cxd2878_wrm(dev,dev->slvt,0x10,data,4);
	}

	dev->state = SONY_DEMOD_STATE_SLEEP;
	
	/*setup tuner i2c bus*/
	cxd2878_SetBankAndRegisterBits(dev,dev->slvx,0x00,0x1A,0x01,0xFF);
	msleep(2);

	//init internal tuner
	cxd2878_i2c_repeater(dev,1);
	ascot3_init(dev);
	cxd2878_i2c_repeater(dev,0);


	//set the ts mode
	
    cxd2878_SetBankAndRegisterBits(dev,dev->slvt, 0x00, 0xC4,  (dev->base->config->ts_mode? 0x00 : 0x80), 0x80);
    cxd2878_SetBankAndRegisterBits(dev,dev->slvt, 0x02, 0xE4,  ((dev->base->config->ts_mode == 2) ? 0x01 : 0x00), 0x01);
    if(dev->base->config->ts_mode==0){
    cxd2878_SetBankAndRegisterBits(dev,dev->slvt,0x00, 0xC4,  (dev->base->config->ts_ser_data ? 0x08 : 0x00), 0x08);   
    cxd2878_SetBankAndRegisterBits(dev,dev->slvt,0x00, 0xC4, 0x00, 0x10);
}
    if(dev->base->config->ts_clk_mask){
     cxd2878_SetBankAndRegisterBits(dev,dev->slvt,0x00, 0xC6, dev->base->config->ts_clk_mask, 0x1F); 
     cxd2878_SetBankAndRegisterBits(dev,dev->slvt,0x60, 0x52, dev->base->config->ts_clk_mask, 0x1F);
    }

    if(dev->base->config->lock_flag)//for usb device led light
    {
    	cxd2878_lock_flag(dev,0);//unlocked 
    }
	//cxd2878_wr(dev,dev->slvt,0xC4,0xa1);
warm_start:	
	dev->warm = 1;
	
    c->cnr.len = 1;
	c->cnr.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	c->post_bit_error.len = 1;
	c->post_bit_error.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	c->post_bit_count.len = 1;
	c->post_bit_count.stat[0].scale = FE_SCALE_NOT_AVAILABLE;
	
	mutex_unlock(&dev->base->i2c_lock);

	return 0;
err:
	mutex_unlock(&dev->base->i2c_lock);
	dev_err(&dev->base->i2c->dev,"%s:Init failed!",KBUILD_MODNAME);

	return ret;
}

static int cxd2878_read_status(struct dvb_frontend *fe,
											enum fe_status *status)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret = 0;
	u8 data = 0;
	u8 syncstat ,tslockstat,unlockdetected,vqlockstat=0;
	u32 ifout,per = 0;
	u8 tmp[2],qam = 0;
	u16 tmp16 = 0;
	s32  rflevel,snr=0;
	
	mutex_lock(&dev->base->i2c_lock);
	
	*status = 0;
	switch (c->delivery_system){
		case SYS_DVBT:   // miss dvbt EchoOptimization
			ifout = 400;
			cxd2878_wr(dev,dev->slvt,0x00,0x10);
			cxd2878_rdm(dev,dev->slvt,0x10,&data,1);
			syncstat = data & 0x07;
		 	tslockstat = ((data & 0x20) ? 1 : 0);
		 	unlockdetected = ((data & 0x10) ? 1 : 0);
			if(unlockdetected)
				*status = FE_HAS_SIGNAL;
			if((syncstat>=6)&&tslockstat)
			 *status = FE_HAS_SIGNAL | FE_HAS_CARRIER | FE_HAS_VITERBI |
						FE_HAS_SYNC | FE_HAS_LOCK;
			break;
		case SYS_DVBT2:
			ifout = 400;
			cxd2878_wr(dev,dev->slvt,0x00,0x20);
			cxd2878_rdm(dev,dev->slvt,0x10,&data,1);
			syncstat = data & 0x07;
		 	tslockstat = ((data & 0x20) ? 1 : 0);
		 	unlockdetected = ((data & 0x10) ? 1 : 0);
			
			if(syncstat == 0x07)
				*status = FE_HAS_SIGNAL;
			if((tslockstat)&(!unlockdetected)&(syncstat>=6))
				*status = FE_HAS_SIGNAL | FE_HAS_CARRIER | FE_HAS_VITERBI |
						FE_HAS_SYNC | FE_HAS_LOCK;

			break;
		case SYS_DVBC_ANNEX_A:
		case SYS_DVBC_ANNEX_B:
		case SYS_DVBC_ANNEX_C:
			ifout = 150;

			cxd2878_wr(dev,dev->slvt,0x00,0x40);
			cxd2878_rdm(dev,dev->slvt,0x88,&data,1);
			syncstat = (u8) ((data & 0x01) ? 1 : 0);			
			unlockdetected= (u8) ((data & 0x02) ? 1 : 0);
			cxd2878_rdm(dev,dev->slvt,0x10,&data,1);
			tslockstat = ((data & 0x20) ? 1 : 0);
			if(syncstat==0)
			   *status = FE_HAS_SIGNAL ;
			 if(syncstat&&tslockstat)
			 	*status = FE_HAS_SIGNAL | FE_HAS_CARRIER | FE_HAS_VITERBI |
						FE_HAS_SYNC | FE_HAS_LOCK;
			break;
		case SYS_ISDBT:
			ifout = 450;
			cxd2878_wr(dev,dev->slvt,0x00,0x60);
			cxd2878_rdm(dev,dev->slvt,0x10,&data,1);
			
			unlockdetected = (u8)((data & 0x10)? 1 : 0);
    		syncstat = (u8)((data & 0x02) ? 1 : 0);
    		tslockstat = (u8)((data & 0x01) ? 1 : 0);
			
			if((!unlockdetected)&&syncstat&&tslockstat)
					*status = FE_HAS_SIGNAL | FE_HAS_CARRIER | FE_HAS_VITERBI |
						FE_HAS_SYNC | FE_HAS_LOCK;	
			else
				*status = FE_HAS_SIGNAL | FE_HAS_CARRIER;
			break;
		case SYS_ATSC:
			ifout = 500;
			cxd2878_wr(dev,dev->slvm,0x00,0x0F);
			cxd2878_rdm(dev,dev->slvm,0x11,&data,1);
			tslockstat = data&0x01;
			cxd2878_wr(dev,dev->slvm,0x00,0x09);
			cxd2878_rdm(dev,dev->slvm,0x62,&data,1);
			syncstat = (u8)((data & 0x10) ? 1 : 0);
            unlockdetected = (u8)((data & 0x40) ? 0 : 1);
			cxd2878_wr(dev,dev->slvm,0x00,0x0D);
			cxd2878_rdm(dev,dev->slvm,0x86,&data,1);
			vqlockstat = data&0x01;

			if(vqlockstat&&tslockstat)
				*status = FE_HAS_SIGNAL | FE_HAS_CARRIER | FE_HAS_VITERBI |
						FE_HAS_SYNC | FE_HAS_LOCK;
			else 
				*status = FE_HAS_SIGNAL | FE_HAS_CARRIER ;
			
			break;
		default:
			ret = -EINVAL;
			goto err;
	}

//	printk("syncstat=0x%x ,tslockstat=0x%x,unlockdetected =0x%x\n",syncstat ,tslockstat,unlockdetected);

	//lock flag

	   if(dev->base->config->lock_flag){	   
	   if(*status &FE_HAS_LOCK)
  	    	cxd2878_lock_flag(dev,1);//locked 
  	    else
  	    	cxd2878_lock_flag(dev,0);//unlocked 
	  }
	/*rf signal*/	
	ret |= cxd2878_i2c_repeater(dev,1);
	ret |= ascot3_read_rssi(dev,c->frequency/1000,&rflevel); //unit khz
	ret |= cxd2878_i2c_repeater(dev,0);
	rflevel-=ifout;
	rflevel+=200;
	c->strength.len = 2;
	c->strength.stat[0].scale = FE_SCALE_DECIBEL;
	c->strength.stat[0].svalue = rflevel*10;
	c->strength.stat[1].scale = FE_SCALE_RELATIVE;
	c->strength.stat[1].svalue = min(max(2*(rflevel/100+90),0),100);
	c->cnr.len =1;
	c->cnr.stat[0].scale = FE_SCALE_NOT_AVAILABLE;

	if(*status &FE_HAS_VITERBI){
		u8 tmp1[3];
		u32 dcl_avgerr_fine;

		switch(c->delivery_system){
		  case SYS_DVBT:
		  	cxd2878_wr(dev,dev->slvt,0x00,0x10);
			cxd2878_rdm(dev,dev->slvt,0x28,tmp,2);
			tmp16 = tmp[0]<<8 |tmp[1];
			if(tmp16>4996)
				tmp16=4996;
			snr = 10*10*((s32)sony_math_log10(tmp16)-(s32)sony_math_log10(5350-tmp16));
			snr += 28500;
			break;
		  case SYS_DVBT2:
		  	cxd2878_wr(dev,dev->slvt,0x00,0x20);
			cxd2878_rdm(dev,dev->slvt,0x28,tmp,2);
			tmp16 = tmp[0]<<8 |tmp[1];
			if(tmp16>10876)
				tmp16=10876;
			snr = 10*10*((s32)sony_math_log10(tmp16)-(s32)sony_math_log10(12600-tmp16));
			snr += 32000;
			break;
		  case SYS_DVBC_ANNEX_A:
		  case SYS_DVBC_ANNEX_C:
		  case SYS_DVBC_ANNEX_B:

			cxd2878_wr(dev,dev->slvt,0x00,0x40);
			cxd2878_rdm(dev,dev->slvt,0x19,&data,1);
	  		qam = data&0x07;
			cxd2878_rdm(dev,dev->slvt,0x4c,tmp,2);
			tmp16 = ((tmp[0]&0x1F)<<8)|tmp[1];
			switch(qam){
			 default:
			  case 0: //16qam
			  case 2: //64qam
			  case 4: //256qam
			  if(tmp16<126)
			  	tmp16 = 126;
			  snr = -95*(s32)sony_math_log(tmp16)+95941;
			  break;
			  case 1:  //32qam
			  case 3:	//128qam
			  if(tmp16<69)
			  	tmp16 = 69;
			  snr = -88*(s32)sony_math_log(tmp16) + 8699;
			  	break;
			}
		  	break;
		  case SYS_ATSC:
			
			cxd2878_wr(dev,dev->slvm,0x00,0x0D);
			cxd2878_rdm(dev,dev->slvm,0x70,tmp1,3);
			dcl_avgerr_fine = ((u32)(tmp1[2]&0x7F)<<16)|((u32)(tmp1[1]&0xFF)<<8)|tmp1[0];
			snr = (s32)(70418 - (100*sony_math_log10(dcl_avgerr_fine)));
			break;
		  case SYS_ISDBT:
		  	cxd2878_wr(dev,dev->slvt,0x00,0x60);
			cxd2878_rdm(dev,dev->slvt,0x28,tmp,2);	
			tmp16 = tmp[0]<<8 |tmp[1];
			snr = 100*(s32)sony_math_log10(tmp16) - 9031;
		  	break;
		default:
			break;
		}
		c->cnr.len = 2;
		c->cnr.stat[0].scale = FE_SCALE_DECIBEL;
		c->cnr.stat[0].uvalue = snr-1500;
		c->cnr.stat[1].scale = FE_SCALE_RELATIVE;
		c->cnr.stat[1].uvalue = (30-((snr-1500)/1000))*10;
		c->cnr.stat[1].uvalue = min(max((snr-1500)/1000*24/10,0),100);
		if(c->cnr.stat[1].uvalue>0xffff)
			c->cnr.stat[1].uvalue = 0xffff;

	}

	if(*status &FE_HAS_LOCK){
		u8 rdata[4]; 
		u32 packeterr=0,period = 0,Q = 0,R=0;
		u8 datapacketerr[6],datapacketnum[2];

		switch(c->delivery_system){
		  case SYS_DVBT:
		    cxd2878_wr(dev,dev->slvt,0x00,0x10);
			cxd2878_rdm(dev,dev->slvt,0x5C,rdata,4);	
			packeterr = rdata[2]<<8 |rdata[3];
			period = 1U<<(rdata[0]&0x0F);
			Q = (packeterr*1000)/period;
			R = (packeterr*1000)%period;
			R*=1000;
			Q = Q*1000+R/period;
			R = R%period;
			if((period !=1)&&(R>=period/2))
				per =Q+1;
			else
				per = Q;
			
		  	break;
		case SYS_DVBT2:
			cxd2878_wr(dev,dev->slvt,0x00,0x24);
			cxd2878_rdm(dev,dev->slvt,0xFA,rdata,3);	
			packeterr = rdata[1]<<8 |rdata[2];
			cxd2878_rdm(dev,dev->slvt,0xDC,rdata,1);	
			period = 1U<<(rdata[0]&0x0F);
			Q = (packeterr*1000)/period;
			R = (packeterr*1000)%period;
			R*=1000;
			Q = Q*1000+R/period;
			R = R%period;
			if((period !=1)&&(R>=period/2))
				per =Q+1;
			else
				per = Q;
			
			break;
		  case SYS_DVBC_ANNEX_A:
		  case SYS_DVBC_ANNEX_C:
		  case SYS_DVBC_ANNEX_B:
		    cxd2878_wr(dev,dev->slvt,0x00,0x40);
			cxd2878_rdm(dev,dev->slvt,0x5C,rdata,4);	
			packeterr = ((rdata[1]&0x03)<<16)|(rdata[2]<<8) |rdata[3];
			period = (rdata[0]&0x1F);
			if(period == 0)
				per = packeterr*1000000;
			else if(period>6)
				per = (packeterr*15625+(1<<(period-7)))>>(period -6);
			else
				per = (packeterr*1000000+(1<<(period-1)))>>period;
			break;
			case SYS_ISDBT:
		   		cxd2878_wr(dev,dev->slvt,0x00,0x40);
				cxd2878_rdm(dev,dev->slvt,0x1F,datapacketerr,6);
				cxd2878_rdm(dev,dev->slvt,0x5B,datapacketnum,2);
				period = ((u32) datapacketnum[0]<<8) + datapacketnum[1];
				packeterr = ((u32)datapacketerr[0]<<8)+datapacketerr[1];
				Q = (packeterr*1000)/period;
				R = (packeterr*1000)%period;
				R*=1000;
				Q = Q*1000+R/period;
				R = R%period;
				if((period !=1)&&(R>=period/2))
					per =Q+1;
				else
					per = Q;

				break;
			case SYS_ATSC:
			   	cxd2878_wr(dev,dev->slvm,0x00,0x0D);
				cxd2878_rdm(dev,dev->slvm,0x82,rdata,1);
				if(rdata[0]&0x01)
					per = rdata[0];
				else
					per = 0;
				break;
				default:
				break;
				}
		c->post_bit_error.stat[0].scale = FE_SCALE_COUNTER;
		c->post_bit_error.stat[0].uvalue = per;
		c->post_bit_count.stat[0].scale = FE_SCALE_COUNTER;
		c->post_bit_count.stat[0].uvalue = per;
		}
		
		c->post_bit_count.len = 1;
		c->post_bit_error.len = 1;

	mutex_unlock(&dev->base->i2c_lock);

	return 0;
err:
	mutex_unlock(&dev->base->i2c_lock);
	dev_err(&dev->base->i2c->dev,"%s:read status failed!",KBUILD_MODNAME);
	return ret;
}

static int cxd2878_set_frontend(struct dvb_frontend *fe)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret = 0;

	dev_dbg(&dev->base->i2c->dev,
		"delivery_system=%u modulation=%u frequency=%u bandwidth_hz=%u symbol_rate=%u inversion=%u stream_id=%d\n",
		c->delivery_system, c->modulation, c->frequency,
		c->bandwidth_hz, c->symbol_rate, c->inversion,
		c->stream_id);
	
		mutex_lock(&dev->base->i2c_lock);

	if(!dev->warm)
	    cxd2878_init(fe);
			
	if(dev->base->config->RF_switch)
		dev->base->config->RF_switch(dev->base->i2c,dev->base->config->rf_port,0);
	
	 switch(c->delivery_system){
		case SYS_DVBT:
			ret = cxd2878_set_dvbt(fe);
			break;
		case SYS_DVBT2:
			ret = cxd2878_set_dvbt2(fe);
			break;
		case SYS_DVBC_ANNEX_A:
		case SYS_DVBC_ANNEX_C:
			ret = cxd2878_set_dvbc(fe);
			break;
		case SYS_DVBC_ANNEX_B:
			ret = cxd2878_set_mcns(fe);
			break;
		case SYS_ISDBT:
			ret = cxd2878_set_isdbt(fe);
			break;
		case SYS_ATSC:
			ret = cxd2878_set_atsc(fe);
			break;
		default:
			goto err;
		}

		// set tuner
	ret |= cxd2878_i2c_repeater(dev,1);
	ret |= ascot3_tune(dev,c->frequency/1000); //unit khz
	ret |= cxd2878_i2c_repeater(dev,0);
	if(c->delivery_system!=SYS_ATSC)
		ret |= cxd2878_tuneEnd(dev);
	else
	{
		ret |= cxd2878_atsc_softreset(dev);
		ret |= cxd2878_setstreamoutput(dev,1);

	}

	if(ret)
		goto err;
	
	mutex_unlock(&dev->base->i2c_lock);

	msleep(20);

	return 0;
err:
	mutex_unlock(&dev->base->i2c_lock);
	dev_err(&dev->base->i2c->dev,"%s:set frontend failed!",KBUILD_MODNAME);
	return ret; 
}
static int cxd2878_tune(struct dvb_frontend*fe,bool re_tune,
	unsigned int mode_flags,unsigned int *delay,enum fe_status*status)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;
	int ret = 0;
	
	if(re_tune){
		 ret = cxd2878_set_frontend(fe);
		if(ret)
			return ret;
		dev->tune_time = jiffies;
	}
	*delay = HZ;
	
	ret = cxd2878_read_status(fe,status);
	if(ret)
		ret;
	
	if (*status & FE_HAS_LOCK)
			return 0;
	
	return 0;
}

static int cxd2878_set_property(struct dvb_frontend*fe,
		u32 cmd,u32 data)
{
	int ret = 0;
	switch(cmd){
		case DTV_DELIVERY_SYSTEM:
			switch (data){
				default:
				case SYS_DVBT:
				case SYS_DVBT2:
					fe->ops.info.frequency_min_hz = 174*MHz;
					fe->ops.info.frequency_max_hz = 868*MHz;
					fe->ops.info.frequency_stepsize_hz = 250000;				
					break;
				case SYS_ISDBT:
					fe->ops.info.frequency_min_hz = 42*MHz;
					fe->ops.info.frequency_max_hz = 1002*MHz;
					fe->ops.info.frequency_stepsize_hz = 0;
					break;
				case SYS_DVBC_ANNEX_A:
				case SYS_DVBC_ANNEX_B:
				case SYS_DVBC_ANNEX_C:
					fe->ops.info.frequency_min_hz = 47*MHz;
					fe->ops.info.frequency_max_hz = 862*MHz;
					fe->ops.info.frequency_stepsize_hz = 62500;
					fe->ops.info.symbol_rate_min = 1700000;
					fe->ops.info.symbol_rate_max = 7200000;
					break;
				case SYS_ATSC:
					fe->ops.info.frequency_min_hz = 54*MHz;
					fe->ops.info.frequency_max_hz = 858*MHz;
					fe->ops.info.frequency_stepsize_hz = 62500;
					break;
			}
		}

	return ret;
}
static enum dvbfe_algo cxd2878_get_algo(struct dvb_frontend *fe)
{
	return DVBFE_ALGO_HW;
}
static int cxd2878_read_ber(struct dvb_frontend *fe ,
							u32 *ber)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;

	if ( p->post_bit_error.stat[0].scale == FE_SCALE_COUNTER &&
		p->post_bit_count.stat[0].scale == FE_SCALE_COUNTER )
		*ber = (u32)p->post_bit_count.stat[0].uvalue ? (u32)p->post_bit_error.stat[0].uvalue /
					(u32)p->post_bit_count.stat[0].uvalue : 0;

	
	return 0;
}
static int cxd2878_read_signal_strength(struct dvb_frontend*fe,
							u16*strength)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;
	int i;

	*strength = 0;
	for (i=0; i < p->strength.len; i++)
		if (p->strength.stat[i].scale == FE_SCALE_RELATIVE)
			*strength = (u16)p->strength.stat[i].uvalue*656;
	
	return 0;
}
static int cxd2878_read_snr(struct dvb_frontend *fe,
							u16*snr)
{
	struct dtv_frontend_properties *p = &fe->dtv_property_cache;
	int i;

	*snr = 0;
	for (i=0; i < p->cnr.len; i++)
		if (p->cnr.stat[i].scale == FE_SCALE_RELATIVE)
		  *snr = (u16)p->cnr.stat[i].uvalue*655;

	return 0;
}

static int cxd2878_read_ucblocks(struct dvb_frontend *fe,u32 *ucblocks)
{
	*ucblocks = 0;

	return 0;
}
static void cxd2878_spi_read(struct dvb_frontend *fe, struct ecp3_info *ecp3inf)
{

	struct cxd2878_dev *dev = fe->demodulator_priv;


	if (dev->base->config->read_properties)
		dev->base->config->read_properties(dev->base->i2c,ecp3inf->reg, &(ecp3inf->data));

	return ;
}

static void cxd2878_spi_write(struct dvb_frontend *fe,struct ecp3_info *ecp3inf)
{

	struct cxd2878_dev *dev = fe->demodulator_priv;


	if (dev->base->config->write_properties)
		dev->base->config->write_properties(dev->base->i2c,ecp3inf->reg, ecp3inf->data);
	return ;
}
static void cxd2878_eeprom_read(struct dvb_frontend *fe, struct eeprom_info *eepinf)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;

	if (dev->base->config->read_eeprom)
		dev->base->config->read_eeprom(dev->base->i2c,eepinf->reg, &(eepinf->data));
	return ;
}

static void cxd2878_eeprom_write(struct dvb_frontend *fe,struct eeprom_info *eepinf)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;

	if (dev->base->config->write_eeprom)
		dev->base->config->write_eeprom(dev->base->i2c,eepinf->reg, eepinf->data);

	return ;
}
static void cxd2878_release (struct dvb_frontend*fe)
{
	struct cxd2878_dev *dev = fe->demodulator_priv;
	dev->base->count--;
	if(dev->base->count == 0){
		list_del(&dev->base->cxdlist);
		kfree(dev->base);
		}
	kfree(dev);
}

static const struct dvb_frontend_ops cxd2878_ops = {
	.delsys = {SYS_DVBT,SYS_DVBT2,SYS_ISDBT,
		SYS_DVBC_ANNEX_A,SYS_DVBC_ANNEX_B,SYS_DVBC_ANNEX_C,
		SYS_ATSC},
	.info = {
			.name = "sony cxd2878 familly",
			.frequency_min_hz = 45*MHz,
			.frequency_max_hz = 868*MHz,
			.frequency_stepsize_hz = 1 * kHz,
		    .caps = FE_CAN_INVERSION_AUTO |
				FE_CAN_FEC_1_2 |
				FE_CAN_FEC_2_3 |
				FE_CAN_FEC_3_4 |
				FE_CAN_FEC_4_5 |
				FE_CAN_FEC_5_6	|
				FE_CAN_FEC_7_8	|
				FE_CAN_FEC_AUTO |
				FE_CAN_QAM_16 |
				FE_CAN_QAM_32 |
				FE_CAN_QAM_64 |
				FE_CAN_QAM_128 |
				FE_CAN_QAM_256 |
				FE_CAN_QAM_AUTO |
				FE_CAN_TRANSMISSION_MODE_AUTO |
				FE_CAN_GUARD_INTERVAL_AUTO |
				FE_CAN_2G_MODULATION |
				FE_CAN_RECOVER |
				FE_CAN_MUTE_TS,
	},

			.init 					= cxd2878_init,
			.release			= cxd2878_release,
			.set_frontend			= cxd2878_set_frontend,
			.tune					= cxd2878_tune,
			.get_frontend_algo		= cxd2878_get_algo,
			
			.read_status 			= cxd2878_read_status,
			.read_signal_strength   = cxd2878_read_signal_strength,
			.read_ber  				= cxd2878_read_ber,
			.read_snr				= cxd2878_read_snr,
			.read_ucblocks			= cxd2878_read_ucblocks,

			.set_property			= cxd2878_set_property,
			
			.spi_read				= cxd2878_spi_read,
			.spi_write				= cxd2878_spi_write,
			.eeprom_read		= cxd2878_eeprom_read,
			.eeprom_write		= cxd2878_eeprom_write,
};

static struct cxd_base *match_base(struct i2c_adapter *i2c,u8 adr)
{
	struct cxd_base*p;

	list_for_each_entry(p,&cxdlist,cxdlist)
	if(p->i2c==i2c &&p->adr!=adr)
		return p;
	return NULL;
}
struct dvb_frontend*cxd2878_attach(const struct cxd2878_config*config,
					   struct i2c_adapter*i2c)
{
	struct cxd2878_dev *dev;
	struct cxd_base *base;

	int ret;
	u16 id;
	u8 data[2];
	dev = kzalloc(sizeof(struct cxd2878_dev),GFP_KERNEL);
	if(!dev)
	    goto err;
	    
	dev->slvt   = config->addr_slvt;
	dev->slvx	= config->addr_slvt+2;
	dev->slvr	= config->addr_slvt-0x20;
	dev->slvm	= config->addr_slvt-0x54;
	dev->tuner_addr = config->tuner_addr;

	dev->state	= SONY_DEMOD_STATE_UNKNOWN;
	dev->system	= SONY_DTV_SYSTEM_UNKNOWN;
	
	dev->iffreqConfig.configDVBT_5 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(3.6);
	dev->iffreqConfig.configDVBT_6 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(3.6);
	dev->iffreqConfig.configDVBT_7 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(4.2);
	dev->iffreqConfig.configDVBT_8 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(4.8);

	dev->iffreqConfig.configDVBT2_1_7 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(3.5);
	dev->iffreqConfig.configDVBT2_5 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(3.6);
	dev->iffreqConfig.configDVBT2_6 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(3.6);
	dev->iffreqConfig.configDVBT2_7 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(4.2);
	dev->iffreqConfig.configDVBT2_8 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(4.8);

	dev->iffreqConfig.configDVBC_6 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(3.7);
	dev->iffreqConfig.configDVBC_7 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(4.9);
	dev->iffreqConfig.configDVBC_8 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(4.9);

	dev->iffreqConfig.configATSC = SONY_DEMOD_ATSC_MAKE_IFFREQ_CONFIG(3.7);

	dev->iffreqConfig.configISDBT_6 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(3.55);
	dev->iffreqConfig.configISDBT_7 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(4.15);
	dev->iffreqConfig.configISDBT_8 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(4.75);

	dev->iffreqConfig.configJ83B_5_06_5_36 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(3.7);
	dev->iffreqConfig.configJ83B_5_60 = SONY_DEMOD_MAKE_IFFREQ_CONFIG(3.75);

	dev->atscNoSignalThresh = 0x7FFB61;
	dev->atscSignalThresh = 0x7C4926;
	dev->warm	 = 0;
	
	
	memcpy(&dev->fe.ops,&cxd2878_ops,sizeof(struct dvb_frontend_ops));
	dev->fe.demodulator_priv = dev;
	
	base = match_base(i2c,config->addr_slvt);
	if(base){
		base->count++;
		dev->base = base;
	}else{
		base = kzalloc(sizeof(struct cxd_base),GFP_KERNEL);
		if(!base)
			goto err1;
		base->i2c =i2c;
		base->config = config;
		base->adr =config->addr_slvt;
		base->count = 1;
		mutex_init(&base->i2c_lock);
		dev->base = base;
		list_add(&base->cxdlist,&cxdlist);
	}
	cxd2878_wr(dev,dev->slvx,0x00,0x00);
	cxd2878_rdm(dev,dev->slvx, 0xFB, &data[0], 1);
	cxd2878_rdm(dev,dev->slvx, 0xFD, &data[1], 1);
	
	id = ((data[0] & 0x03) << 8) | data[1];
	
	switch(id){ 
		
		case SONY_DEMOD_CHIP_ID_CXD2856 :  /**< CXD2856 / CXD6800(SiP) */
			dev_info(&i2c->dev,"Detect CXD2856/CXD6800(SiP) chip.");
			break;
		
		case SONY_DEMOD_CHIP_ID_CXD2857 :  /**< CXD2857 */
			dev_info(&i2c->dev,"Detect CXD2857 chip.");
			break;
		case SONY_DEMOD_CHIP_ID_CXD2878 :  /**< CXD2878 / CXD6801(SiP) */
			dev_info(&i2c->dev,"Detect CXD2878/CXD6801(SiP) chip.");
			break;
		case SONY_DEMOD_CHIP_ID_CXD2879 :  /**< CXD2879 */
			dev_info(&i2c->dev,"Detect CXD2879 chip.");
			break;
		case SONY_DEMOD_CHIP_ID_CXD6802	: /**< CXD6802(SiP) */
			dev_info(&i2c->dev,"Detect CXD2878/CXD6802(SiP) chip.");
			break;
		default:
		case SONY_DEMOD_CHIP_ID_UNKNOWN: /**< Unknown */		
			dev_err(&i2c->dev,"%s:Can not decete the chip.\n",KBUILD_MODNAME);
			goto err1;
			break;
	}
	dev->chipid = id;
	
	dev_dbg(&i2c->dev,"%s: attaching frontend successfully.\n",KBUILD_MODNAME);
	
	return &dev->fe;

err1:
	kfree(dev);
err:
	dev_err(&i2c->dev,"%s:error attaching frontend.\n",KBUILD_MODNAME);
	return NULL;

	
}

EXPORT_SYMBOL_GPL(cxd2878_attach);

MODULE_AUTHOR("Davin zhang<Davin@tbsdtv.com>");
MODULE_DESCRIPTION("sony cxd2878 family demodulator driver");
MODULE_LICENSE("GPL");


