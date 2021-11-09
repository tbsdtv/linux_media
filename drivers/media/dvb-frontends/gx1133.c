/*
    Tmax gx1133 - DVBS/S2 Satellite demodulator driver

    Copyright (C) 2014 Luis Alves <ljalvs@gmail.com>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/i2c-mux.h>

#include <media/dvb_frontend.h>

#include "gx1133.h"
#include "gx1133_priv.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
#if IS_ENABLED(CONFIG_I2C_MUX)
#define GX1133_USE_I2C_MUX
#endif
#endif

/* return i2c adapter */
/* bus = 0   master   */
/* bus = 1   demod    */
/* bus = 2   tuner    */
struct i2c_adapter *gx1133_get_i2c_adapter(struct dvb_frontend *fe, int bus)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	switch (bus) {
	case 0:
	default:
		return priv->i2c;
	case 1:
		return priv->i2c_demod;
	case 2:
		return priv->i2c_tuner;
	}
}
EXPORT_SYMBOL_GPL(gx1133_get_i2c_adapter);

/* write multiple (continuous) registers */
/* the first value is the starting address */
static int gx1133_wrm(struct gx1133_priv *priv, u8 *buf, int len)
{
	int ret;
	struct i2c_msg msg = {
		.addr = priv->cfg->i2c_address,
		.flags = 0, .buf = buf, .len = len };

	dev_dbg(&priv->i2c->dev, "%s() i2c wrm @0x%02x (len=%d)\n",
		__func__, buf[0], len);

	ret = i2c_transfer(priv->i2c_demod, &msg, 1);
	if (ret < 0) {
		dev_warn(&priv->i2c->dev,
			"%s: i2c wrm err(%i) @0x%02x (len=%d)\n",
			KBUILD_MODNAME, ret, buf[0], len);
		return ret;
	}
	return 0;
}

/* write one register */
static int gx1133_wr(struct gx1133_priv *priv,u8 type, u8 addr, u8 data)
{
	u8 buf[] = {type, addr, data };
	return gx1133_wrm(priv, buf, 3);
}

/* read multiple (continuous) registers starting at addr */
static int gx1133_rdm(struct gx1133_priv *priv,u8 type, u8 addr, u8 *buf, int len)
{
	int ret;
	u8 regs[2] = {type,addr};
	struct i2c_msg msg[2] = {
		{ .addr = priv->cfg->i2c_address, .flags = 0,
			.buf = regs, .len = 2 },
		{ .addr = priv->cfg->i2c_address, .flags = I2C_M_RD,
			.buf = buf, .len = len }
	};

	dev_dbg(&priv->i2c->dev, "%s() i2c rdm @0x%02x (len=%d)\n",
		__func__, addr, len);

	ret = i2c_transfer(priv->i2c_demod, msg, 2);

	if (ret < 0) {
		dev_warn(&priv->i2c->dev,
			"%s: i2c rdm err(%i) @0x%02x (len=%d)\n",
			KBUILD_MODNAME, ret, addr, len);
		return ret;
	}
	return 0;
}

/* read one register */
static int gx1133_rd(struct gx1133_priv *priv,u8 type, u8 addr, u8 *data)
{
	return gx1133_rdm(priv,type, addr, data, 1);
}


static u32 gx1133_Get_BER_S2(struct gx1133_priv *priv ) /*TOKEN_FUNCTION*/
{
	u8 err_pkt_num_1,err_pkt_num_2, e_value = 0;
	u8 pkt_len,tss,gcs,gps;
	u32 err_pkt_rate,return_value = 0;
	u32 err_pkt_num;
	u32 tot_pkt_num;
	u8 temp;

	gx1133_rd(priv,DVB_S2,0xec,&err_pkt_num_1);
	gx1133_rd(priv,DVB_S2,0xed,&err_pkt_num_2);
	err_pkt_num = (err_pkt_num_2<<8) | err_pkt_num_1;

	gx1133_rd(priv,DVB_S2,0xe3,&temp);
	pkt_len = temp&0x03;
	tss = (temp&0x04) >> 2;
	gcs = (temp&0x08) >> 3;
	gps = (temp&0x10) >> 4;

	if(~gcs)
		tot_pkt_num =  2048 *((pkt_len==0)*1+(pkt_len==1)*4+(pkt_len==2)*16+(pkt_len==3)*64);
	else
		tot_pkt_num =  32*((pkt_len==0)*1+(pkt_len==1)*4+(pkt_len==2)*16+(pkt_len==3)*64);
	if((err_pkt_num==0)||(tot_pkt_num==0))
		return 0;
	while(err_pkt_num > 0)
	{
		err_pkt_rate = 1000*err_pkt_num/tot_pkt_num;
		if (err_pkt_rate>=1000)
		{
			return_value = (err_pkt_num*100)/tot_pkt_num;
			break;
		}
		else
		{
			e_value ++;
			err_pkt_num *=10;
		}
	}
	return_value = ((return_value << 8) & 0xfff0) | e_value;
	return return_value;
}
//??????
static u32 gx1133_Get_BER_S(struct gx1133_priv *priv) /*TOKEN_FUNCTION*/
{
	int flag = 0;
	u8 Read_Value[4];
	int i=0;
	int error_type = 3;//0:before RS ber   3:after RS ber	--louhq20171012
	int divied = ((1<<(2*5+5))*(204)*8);	//(2^(2* PACKET NUM +5))*ÿ???ֽ???    ÿ???ֽ???:DTV??208,DVB??204;PACKET NUMĬ??Ϊ5
	int Error_count;
	u32 Bit_error,return_value = 0;
	u8 e_value = 0,temp = 0;

	
	gx1133_rd(priv,DVB_S2,0xD0,&temp);
	flag = (temp&0x8E)|(error_type<<4);
	gx1133_wr(priv,DVB_S2,0xD0,flag);
	gx1133_rd(priv,DVB_S2,0xD0,&temp);
	divied = (1<<((2*(temp&0x0E)>>1)+5))*204*8;
	for (i=0;i<4;i++){
//		gx1133_rd(priv,DVB_S2,0xD1 + i,&Read_Value[i]);//Read the threshold value
		}
	gx1133_rdm(priv,DVB_S2,0xD1,Read_Value,4);
	Error_count = (u32)Read_Value[0] + ((u32)Read_Value[1]<<8) + ((u32)Read_Value[2]<<16) + (((u32)Read_Value[3]&0x03)<<24);
	if((Error_count==0)||(divied==0))
		return 0;
	while(Error_count > 0)
	{
		Bit_error = 1000*(Error_count/divied);
		if (Bit_error>=1000)
		{
			return_value = (Error_count*100)/divied;
			break;
		}
		else
		{
			e_value ++;
			Error_count *=10;
		}
	}
	return_value = ((return_value << 8) & 0xfff0) | e_value;
	return return_value;
}
static void gx1133_core_rst(struct gx1133_priv *priv,Demod_CorRst_Sel type)
{
	u8 tmp;
	tmp = 0x01<<type;	
	gx1133_wr(priv,Demod_TOP,cfg_core_rst,tmp);
	gx1133_wr(priv,Demod_TOP,cfg_core_rst,0);

	return;	
}
static void gx1133_set_Pll(struct gx1133_priv *priv,u32 Osc_freq, Demod_PLL_SEL  pll, Demod_PLL_Freq  FreqSet)
{
	u8	value;
	u32 NR, NF=0, BS=0,OD=0;
	u8 pll_r,pll_f;

	pll_r = cfg_pll_r_base + (pll*2);
	pll_f = cfg_pll_f_base + (pll*2);

/*
//dem / adc
	pll_27M_to_92_81M=0,
	pll_27M_to_185_63M,//92.81x2

	pll_27M_to_91_125M,
	pll_27M_to_182_25M,//91.125x2

	pll_27M_to_96_19M,
	pll_27M_to_192_38M,//96.19x2

	pll_27M_to_101_25M,
	pll_27M_to_202_50M,//101.25x2

	pll_27M_to_102_94M,
	pll_27M_to_205_88M,//102.94x2

//dem
	pll_27M_to_123_19M,
	pll_27M_to_121_50M,

//ts_base/ fec x2
	pll_27M_to_249_75M,//(123.19+delta)x2
	pll_27M_to_297_00M


*/
	switch(FreqSet)
	{
		case pll_27M_to_162_00M :{ NF= 47;BS=1;OD=2;NR= 1;break;}//0x2fc1

		case pll_27M_to_92_81M	:{ NF= 54;BS=1;OD=3;NR= 1;break;}//0x36e1
		case pll_27M_to_185_63M :{ NF= 54;BS=1;OD=2;NR= 1;break;}//0x36c1

		case pll_27M_to_91_125M :{ NF= 53;BS=1;OD=3;NR= 1;break;}//0x35e1
		case pll_27M_to_182_25M :{ NF= 53;BS=1;OD=2;NR= 1;break;}//0x35c1

		case pll_27M_to_96_19M	:{ NF= 56;BS=1;OD=3;NR= 1;break;}//0x38e1
		case pll_27M_to_192_38M :{ NF= 56;BS=1;OD=2;NR= 1;break;}//0x38c1

		case pll_27M_to_101_25M :{ NF= 59;BS=1;OD=3;NR= 1;break;}//0x3be1
		case pll_27M_to_202_50M :{ NF= 59;BS=1;OD=2;NR= 1;break;}//0x3bc1

		case pll_27M_to_102_94M :{ NF= 60;BS=1;OD=3;NR= 1;break;}//0x3ce1
		case pll_27M_to_205_88M :{ NF= 60;BS=1;OD=2;NR= 1;break;}//0x3cc1

		case pll_27M_to_111_375M	:{ NF= 65;BS=1;OD=3;NR= 1;break;}//0x41E1
		case pll_27M_to_123_19M :{ NF= 72;BS=1;OD=3;NR= 1;break;}//0x48E1
		case pll_27M_to_121_50M :{ NF= 71;BS=1;OD=3;NR= 1;break;}//0x47E1

		case pll_27M_to_236_25M :{ NF= 69;BS=1;OD=2;NR= 1;break;}//0x45c1
		case pll_27M_to_249_75M :{ NF= 73;BS=1;OD=2;NR= 1;break;}//0x49c1
		case pll_27M_to_256_50M :{ NF= 37;BS=1;OD=1;NR= 1;break;}//0x25a1
		case pll_27M_to_297_00M :{ NF= 43;BS=1;OD=1;NR= 1;break;}//0x2BA1

		case pll_27M_to_60_75M	:{ NF= 26;BS=0;OD=3;NR= 1;break;}//0x1A61
		case pll_27M_to_45_5625M:{ NF= 35;BS=0;OD=3;NR= 1;break;}//0x2361
		case pll_27M_to_116_4375M:{ NF=68;BS=1;OD=2;NR= 1;break;}//0x44C1
		case pll_27M_to_131_625M:{ NF=38;BS=1;OD=1;NR= 1;break;}//0x26A1

		default 				: break;

	}

	value=(BS<<7)+(OD<<5)+NR;
	gx1133_wr(priv,Demod_TOP,pll_r,value);
	gx1133_wr(priv,Demod_TOP,pll_f,NF);

	return;

}
static void gx1133_set_adc(struct gx1133_priv *priv,u8 adc,u8 pp_sel,u8 fsctrl,u8 ch_sel,u8 adc_clk)  /*TOKEN_FUNCTION*/
{

//refer to application note:  [Release001_GX1801_AN_1																																																																																																																																					30412_1343_IP_control.doc]

	u8 cfg_ADC	= cfg_ADC_base + (2*adc);
	u8 temp=0;
	u8 BCTRL_R,BCTRL;


	gx1133_wr(priv,Demod_TOP,0x91,0xf3);
	//GXDemod_Write_one_Byte(GXDemodID,0x92,0x1c);
	gx1133_wr(priv,Demod_TOP,0x92,0x01);//01


	//set ch_sel ,the set value is only valid when in singlechanl mode (pp_sel == 0);
	gx1133_rd(priv,Demod_TOP,cfg_ADC+1,&temp);
	temp= (temp&0xbf) | (ch_sel << 6);
	gx1133_wr(priv,Demod_TOP,cfg_ADC+1,temp);

	//set fsctrl
	gx1133_rd(priv,Demod_TOP,cfg_ADC,&temp);
	temp= (temp&0xf3) | (fsctrl << 2)	;// adjust by luoshw 20150302
	gx1133_wr(priv,Demod_TOP,cfg_ADC,temp);

	//bctrl_R[1:0]
	//bctrl[2:0]
	BCTRL_R = 0;
	BCTRL	  = 1;
	gx1133_rd(priv,Demod_TOP,cfg_ADC+1,&temp);
	temp= (temp&0xe0) | (BCTRL_R&0x03 << 3) | (BCTRL&0x07);
	gx1133_wr(priv,Demod_TOP,cfg_ADC+1,temp);

	//add 1ms delay before adc reset,incase pll not stable yet.
	msleep(1);
	//reset adc
	gx1133_rd(priv,Demod_TOP,cfg_ADC,&temp);
	temp&= 0xfc;
	gx1133_wr(priv,Demod_TOP,cfg_ADC,temp);
	temp|= 0x03;
	gx1133_wr(priv,Demod_TOP,cfg_ADC,temp);

/*
	//add delay before PP_SEL, incase pll not stable yet.
	GXDemod_cnt_dly_adcrdy=0;
	do{
	GX_Delay_N_ms(1);
	GXDemod_cnt_dly_adcrdy ++;

	}while(((GXDemod_Read_one_Byte(cfg_ADC+1) &0x80)==0) &&(GXDemodID,GXDemod_cnt_dly_adcrdy<50));
//	print(" GXDemod_cnt_dly_adcrdy=%d\n", GXDemod_cnt_dly_adcrdy);

//	print(" adc_rdy=%x\n", GXDemod_Read_one_Byte(GXDemodID,cfg_ADC+1) );
*/

	//resynchronize bitosync by seting ppsel
	gx1133_rd(priv,Demod_TOP,cfg_ADC,&temp);
	temp=(temp&0x7f);
	gx1133_wr(priv,Demod_TOP,cfg_ADC,temp);
	temp=(temp&0x7f)|(pp_sel <<7 );
	gx1133_wr(priv,Demod_TOP,cfg_ADC,temp);

	return;
}

static void gx1133_set_work_bs_mode(struct gx1133_priv *priv,bool bs)
{
	u8 tmp,tmp1;
	
	gx1133_rd(priv,DVB_S2,GX1133_BCS_RST,&tmp);
	gx1133_rd(priv,DVB_S2,GX1133_AUTO_RST,&tmp1);

	if(!bs){
		gx1133_wr(priv,DVB_S2,GX1133_BCS_RST,tmp|0x81);
		gx1133_wr(priv,DVB_S2,GX1133_AUTO_RST,tmp1&0x9f);

	}else{
		gx1133_wr(priv,DVB_S2,GX1133_BCS_RST,(tmp&0x7f)|0x1);
		gx1133_wr(priv,DVB_S2,GX1133_AUTO_RST,tmp1|0x60);

	}
	return;	
}
static int gx1133_read_ber(struct dvb_frontend *fe, u32 *ber)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;

	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	switch (c->delivery_system) {
		case SYS_DVBS:
			*ber = gx1133_Get_BER_S(priv);
			break;

		case SYS_DVBS2:
			*ber = gx1133_Get_BER_S2(priv);
			break;

		default:
			*ber = 0;
			break;
	}

	dev_dbg(&priv->i2c->dev, "%s() ber = %d\n", __func__, *ber);
	return 0;
}

static int gx1133_read_signal_strength(struct dvb_frontend *fe,
	u16 *signal_strength)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	int ret, i;
	long val, dbm_raw;
	u8 buf[2];

	ret = gx1133_rdm(priv,DVB_S2,0x42, buf, 2);
	if (ret)
		return ret;

	dbm_raw = (((u16)(buf[1] & 0xf0)>>4) << 8) | buf[0];

	for (i = 0; i < ARRAY_SIZE(gx1133_dbmtable) - 1; i++)
		if (gx1133_dbmtable[i].raw < dbm_raw)
			break;

	if( i == 0 )
		*signal_strength = gx1133_dbmtable[i].dbm;
	else
	{
		/* linear interpolation between two calibrated values */
		val = (dbm_raw - gx1133_dbmtable[i].raw) * gx1133_dbmtable[i-1].dbm;
		val += (gx1133_dbmtable[i-1].raw - dbm_raw) * gx1133_dbmtable[i].dbm;
		val /= (gx1133_dbmtable[i-1].raw - gx1133_dbmtable[i].raw);

		*signal_strength = (u16)val;
	}

	dev_dbg(&priv->i2c->dev, "%s() strength = 0x%04x\n",
		__func__, *signal_strength);
	return 0;
}

static int gx1133_read_snr(struct dvb_frontend *fe, u16 *snr)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret, i;
	long val;
	u16 snr_raw;
	u8 buf[2];

	ret = gx1133_rdm(priv,DVB_S2, 0x92, buf, 2);
	if (ret)
		return ret;

	snr_raw = (((u16)buf[1] & 0x0f) << 8) | buf[0];

	for (i = 0; i < ARRAY_SIZE(gx1133_snrtable) - 1; i++)
		if (gx1133_snrtable[i].raw < snr_raw)
			break;

	if( i == 0 )
		val = gx1133_snrtable[i].snr;
	else
	{
		/* linear interpolation between two calibrated values */
		val = (snr_raw - gx1133_snrtable[i].raw) * gx1133_snrtable[i-1].snr;
		val += (gx1133_snrtable[i-1].raw - snr_raw) * gx1133_snrtable[i].snr;
		val /= (gx1133_snrtable[i-1].raw - gx1133_snrtable[i].raw);
	}

	c->cnr.len = 1;
	c->cnr.stat[0].scale = FE_SCALE_DECIBEL;
	c->cnr.stat[0].uvalue = 100 * (s64) val;

	*snr = (u16) val * 328; /* 20dB = 100% */

	dev_dbg(&priv->i2c->dev, "%s() snr = 0x%04x\n",
		__func__, *snr);

	return 0;
}

/* unimplemented */
static int gx1133_read_ucblocks(struct dvb_frontend *fe, u32 *ucblocks)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);
	*ucblocks = 0;
	return 0;
}

static int gx1133_read_status(struct dvb_frontend *fe, enum fe_status *status)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	int ret;
	u8 reg;

	*status = 0;

	ret = gx1133_rd(priv, DVB_S2,GX1133_ALL_OK, &reg);
	if (ret)
		return ret;

	reg &= 0x75;
	if (reg == FEC_LOCKED) {
		*status = FE_HAS_SIGNAL | FE_HAS_CARRIER |
			FE_HAS_VITERBI | FE_HAS_SYNC | FE_HAS_LOCK;		
	}

	dev_dbg(&priv->i2c->dev, "%s() status = 0x%02x\n", __func__, *status);
	return ret;
}

static void gx1133_spi_read(struct dvb_frontend *fe, struct ecp3_info *ecp3inf)
{

	struct gx1133_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->i2c;
	if (priv->cfg->read_properties)
		priv->cfg->read_properties(adapter,ecp3inf->reg, &(ecp3inf->data));
	return;
}
static void gx1133_spi_write(struct dvb_frontend *fe,struct ecp3_info *ecp3inf)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	struct i2c_adapter *adapter = priv->i2c;
	if (priv->cfg->write_properties)
		priv->cfg->write_properties(adapter,ecp3inf->reg, ecp3inf->data);
	return ;
}

static int gx1133_set_voltage(struct dvb_frontend *fe,
	enum fe_sec_voltage voltage)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	int ret = 0;
	u8 temp;
	dev_dbg(&priv->i2c->dev, "%s() %s\n", __func__,
		voltage == SEC_VOLTAGE_13 ? "SEC_VOLTAGE_13" :
		voltage == SEC_VOLTAGE_18 ? "SEC_VOLTAGE_18" :
		"SEC_VOLTAGE_OFF");

	switch (voltage) {
		case SEC_VOLTAGE_13:
			if (priv->cfg->lnb_power)
				 	priv->cfg->lnb_power(fe, 1);
				gx1133_rd(priv,DVB_S2,GX1133_DISEQC_MODE,&temp);
				temp = temp & 0xBF; //18V select
				gx1133_wr(priv,DVB_S2,GX1133_DISEQC_MODE,temp);

			break;
		case SEC_VOLTAGE_18:
			if (priv->cfg->lnb_power)
				    priv->cfg->lnb_power(fe, 1);		
				gx1133_rd(priv,DVB_S2,GX1133_DISEQC_MODE,&temp);
				temp=temp|0x40; //13V select
				gx1133_wr(priv,DVB_S2,GX1133_DISEQC_MODE,temp);	

			break;
		default: /* OFF */
			if (priv->cfg->lnb_power)
				    priv->cfg->lnb_power(fe, 0);
			break;
	}
	return ret;
}

static int gx1133_set_tone(struct dvb_frontend *fe,
	enum fe_sec_tone_mode tone)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	int ret = -EINVAL;
	u8 temp;

	dev_dbg(&priv->i2c->dev, "%s() %s\n", __func__,
		tone == SEC_TONE_ON ? "SEC_TONE_ON" : "SEC_TONE_OFF");


	//remove DiSEqC reset
	ret=gx1133_rd(priv,DVB_S2,GX1133_MODULE_RST,&temp);
	temp=temp&0xbf;
	ret=gx1133_wr(priv,DVB_S2,GX1133_MODULE_RST, temp);

	// set diseqc mode to 1 when 22k on requested.
	gx1133_rd(priv,DVB_S2,GX1133_DISEQC_MODE,&temp);
	temp &= 0xF8;
	switch (tone) {
	case SEC_TONE_ON:
		temp |= (0x01 & 1);
		break;
	case SEC_TONE_OFF:
		break;
	default:
		dev_warn(&priv->i2c->dev, "%s() invalid tone (%d)\n",
			__func__, tone);
		break;
	}	
	gx1133_wr(priv,DVB_S2,GX1133_DISEQC_MODE,temp);

	//set diseqc pin as output
	gx1133_rd(priv,DVB_S2,GX1133_DISEQC_IO_CTRL,&temp);
	temp=(temp&0xfe)|(0x01&0);
	gx1133_wr(priv,DVB_S2,GX1133_DISEQC_IO_CTRL, temp);

	return ret;
}

static int gx1133_send_diseqc_msg(struct dvb_frontend *fe,
	struct dvb_diseqc_master_cmd *d)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	int ret, i;
	u8 bck, buf[10];
	u8 temp;
	/* dump DiSEqC message */
	dev_dbg(&priv->i2c->dev, "%s() ( ", __func__);
	for (i = 0; i < d->msg_len; i++)
		dev_dbg(&priv->i2c->dev, "0x%02x ", d->msg[i]);
	dev_dbg(&priv->i2c->dev, ")\n");

	/* backup LNB tone state */
	ret = gx1133_rd(priv,DVB_S2 ,GX1133_DISEQC_MODE, &bck);
	if (ret)
		return ret;

	gx1133_rd(priv,DVB_S2,GX1133_MODULE_RST,&temp);
	temp=temp&0xbf;
	gx1133_wr(priv,DVB_S2,GX1133_MODULE_RST, temp);


	/* setup DISEqC message to demod */
	buf[0] = DVB_S2;
	buf[1] = GX1133_DISEQC_INS1;
	memcpy(&buf[2], d->msg, 8);
	ret = gx1133_wrm(priv, buf, d->msg_len + 2);
	if (ret)
		goto exit;

	/* send DISEqC send command */
	buf[0] = (bck & ~(0x38 | 7)) |
		4 | ((d->msg_len - 1) << 3);
	ret = gx1133_wr(priv,DVB_S2, GX1133_DISEQC_MODE, buf[0]);
	if (ret)
		goto exit;

	/* wait at least diseqc typical tx time */
	msleep(54);

	/* Wait for busy flag to clear */
	for (i = 0; i < 10; i++) {
		ret = gx1133_rd(priv,DVB_S2, GX1133_DISEQC_RD_INT, &buf[0]);
		if (ret)
			break;
		if (buf[0] & 0x10)
			goto exit;
		msleep(20);
	}

	/* try to restore the tone setting but return a timeout error */
	ret = gx1133_wr(priv, DVB_S2 ,GX1133_DISEQC_MODE, bck);
	dev_warn(&priv->i2c->dev, "%s() timeout sending burst\n", __func__);
	return -ETIMEDOUT;
exit:
	/* restore tone setting */
	return gx1133_wr(priv, DVB_S2 ,GX1133_DISEQC_MODE, bck);
}

static int gx1133_diseqc_send_burst(struct dvb_frontend *fe,
	enum fe_sec_mini_cmd burst)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	int ret, i;
	u8 bck, r;
	u8 temp;

	if ((burst != SEC_MINI_A) && (burst != SEC_MINI_B)) {
		dev_err(&priv->i2c->dev, "%s() invalid burst(%d)\n",
			__func__, burst);
		return -EINVAL;
	}

	dev_dbg(&priv->i2c->dev, "%s() %s\n", __func__,
		burst == SEC_MINI_A ? "SEC_MINI_A" : "SEC_MINI_B");

	/* backup LNB tone state */
	ret = gx1133_rd(priv, DVB_S2 ,GX1133_DISEQC_MODE, &bck);
	if (ret)
		return ret;

	gx1133_rd(priv,DVB_S2,GX1133_MODULE_RST,&temp);
	temp=temp&0xbf;
	gx1133_wr(priv,DVB_S2,GX1133_MODULE_RST, temp);


	/* set tone burst cmd */
	r = (bck & ~7) |
		(burst == SEC_MINI_A) ? 2 : 3;

	ret = gx1133_wr(priv, DVB_S2 ,GX1133_DISEQC_MODE, r);
	if (ret)
		goto exit;

	/* spec = around 12.5 ms for the burst */
	for (i = 0; i < 10; i++) {
		ret = gx1133_rd(priv, DVB_S2, GX1133_DISEQC_RD_INT, &r);
		if (ret)
			break;
		if (r & 0x10)
			goto exit;
		msleep(20);
	}

	/* try to restore the tone setting but return a timeout error */
	ret = gx1133_wr(priv, DVB_S2 ,GX1133_DISEQC_MODE, bck);
	dev_warn(&priv->i2c->dev, "%s() timeout sending burst\n", __func__);
	return -ETIMEDOUT;
exit:
	/* restore tone setting */
	return gx1133_wr(priv, DVB_S2 ,GX1133_DISEQC_MODE, bck);
}

static void gx1133_release(struct dvb_frontend *fe)
{
	struct gx1133_priv *priv = fe->demodulator_priv;

	dev_dbg(&priv->i2c->dev, "%s\n", __func__);
#ifdef GX1133_USE_I2C_MUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	i2c_mux_del_adapters(priv->muxc);
#else
	i2c_del_mux_adapter(priv->i2c_demod);
	i2c_del_mux_adapter(priv->i2c_tuner);
#endif
#endif
	kfree(priv);
}

#ifdef GX1133_USE_I2C_MUX
/* channel 0: demod */
/* channel 1: tuner */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
static int gx1133_i2c_select(struct i2c_mux_core *muxc, u32 chan_id)
{
	struct gx1133_priv *priv = i2c_mux_priv(muxc);
	struct i2c_adapter *adap = priv->i2c;
#else
static int gx1133_i2c_select(struct i2c_adapter *adap,
	void *mux_priv, u32 chan_id)
{
	struct gx1133_priv *priv = mux_priv;
#endif
	int ret;
	u8 temp;
	u8 buf[3];
	struct i2c_msg msg_wr = {
		.addr = priv->cfg->i2c_address,
		.flags = 0, .buf = buf, .len = 3 };

	struct i2c_msg msg_rd[2] = {
		{ .addr = priv->cfg->i2c_address, .flags = 0,
			.buf = &buf[0], .len = 2 },
		{ .addr = priv->cfg->i2c_address, .flags = I2C_M_RD,
			.buf = &buf[2], .len = 1 }
	};

	dev_dbg(&priv->i2c->dev, "%s() ch=%d\n", __func__, chan_id);
	if (priv->i2c_ch == chan_id)
		return 0;
	buf[0] = Demod_TOP;
	buf[1] = cfg_tuner_rpt;
	ret = __i2c_transfer(adap, msg_rd, 2);
	if (ret != 2)
		goto err;

	buf[2]=((buf[2]&0x7f)|(chan_id<<7));
	
	ret = __i2c_transfer(adap, &msg_wr, 1);
	if (ret != 1)
		goto err;

	priv->i2c_ch = chan_id;

	return 0;
err:
	dev_dbg(&priv->i2c->dev, "%s() failed=%d\n", __func__, ret);
	return -EREMOTEIO;
}
#endif

static struct dvb_frontend_ops gx1133_ops;

struct dvb_frontend *gx1133_attach(const struct gx1133_config *cfg,
	struct i2c_adapter *i2c)
{
	struct gx1133_priv *priv = NULL;
	int ret;
	u8 id[2];

	dev_dbg(&i2c->dev, "%s: Attaching frontend\n", KBUILD_MODNAME);
	/* allocate memory for the priv data */
	priv = kzalloc(sizeof(struct gx1133_priv), GFP_KERNEL);
	if (priv == NULL)
		goto err;

	priv->cfg = cfg;
	priv->i2c = i2c;
	priv->i2c_ch = 0;

#ifdef GX1133_USE_I2C_MUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	/* create mux i2c adapter for tuner */
	priv->muxc = i2c_mux_alloc(i2c, &i2c->dev,
				  2, 0, I2C_MUX_LOCKED,
				  gx1133_i2c_select, NULL);
	if (!priv->muxc) {
		ret = -ENOMEM;
		goto err1;
	}
	priv->muxc->priv = priv;
	ret = i2c_mux_add_adapter(priv->muxc, 0, 0, 0);
	if (ret)
		goto err1;
	ret = i2c_mux_add_adapter(priv->muxc, 0, 1, 0);
	if (ret)
		goto err1;
	priv->i2c_demod = priv->muxc->adapter[0];
	priv->i2c_tuner = priv->muxc->adapter[1];
#else
	/* create muxed i2c adapter for the demod */
	priv->i2c_demod = i2c_add_mux_adapter(i2c, &i2c->dev, priv, 0, 0, 0,
		gx1133_i2c_select, NULL);
	if (priv->i2c_demod == NULL)
		goto err1;

	/* create muxed i2c adapter for the tuner */
	priv->i2c_tuner = i2c_add_mux_adapter(i2c, &i2c->dev, priv, 0, 1, 0,
		gx1133_i2c_select, NULL);
	if (priv->i2c_tuner == NULL)
		goto err2;
#endif
#else
	priv->i2c_demod = i2c;
	priv->i2c_tuner = i2c;
#endif

	/* create dvb_frontend */
	memcpy(&priv->fe.ops, &gx1133_ops,
		sizeof(struct dvb_frontend_ops));
	priv->fe.demodulator_priv = priv;

	/* reset demod */
	if (cfg->reset_demod)
		cfg->reset_demod(&priv->fe);

	msleep(100);

	/* check if demod is alive */
	ret = gx1133_rdm(priv,Demod_TOP, 0xf0, id, 2);
	if ((id[0] != 0x44) || (id[1] != 0x4c))
		ret |= -EIO;
	if (ret)
		goto err3;

	return &priv->fe;

err3:
#ifdef GX1133_USE_I2C_MUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	i2c_mux_del_adapters(priv->muxc);
#else
	i2c_del_mux_adapter(priv->i2c_tuner);
err2:
	i2c_del_mux_adapter(priv->i2c_demod);
#endif
#endif
err1:
	kfree(priv);
err:
	dev_err(&i2c->dev, "%s: Error attaching frontend\n", KBUILD_MODNAME);
	return NULL;
}
EXPORT_SYMBOL_GPL(gx1133_attach);

static int gx1133_initfe(struct dvb_frontend *fe)
{
	struct gx1133_priv *priv = fe->demodulator_priv;

	u8 temp;
	u32 Diseqc_Ratio;
	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);
	gx1133_core_rst(priv,cor_crst_chp);
	msleep(10);
	gx1133_core_rst(priv,cor_crst_cnl);
	msleep(10);
	gx1133_core_rst(priv,cor_crst_i2c);
	msleep(10);
	gx1133_core_rst(priv,cor_crst_mcu);
	msleep(10);
	gx1133_rd(priv,Demod_TOP,cfg_i2c_sla_mode,&temp);   //set i2c sla mode
	gx1133_wr(priv,Demod_TOP,cfg_i2c_sla_mode,(temp & 0xbf) |(1<<6));
	
	gx1133_rd(priv,Demod_TOP,cfg_dejit_div,&temp);     //i2c_sla key parametersetting.
	temp= (temp&0xe0) | GXDemod_dejit_div; //cfg_dejit_div modified
	gx1133_wr(priv,Demod_TOP,cfg_dejit_div,temp);
	gx1133_rd(priv,Demod_TOP,cfg_dejit_div,&temp);  
	temp= (temp&0x9f) | ((GXDemod_rpt_free&0x03) << 5);
	gx1133_wr(priv,Demod_TOP,cfg_dejit_div,temp);

	gx1133_wr(priv,Demod_TOP,0xe5,0x1);

//	ts sequence config;
	//GXDemod_ts_config(TS_Mod_CFG);
	gx1133_rd(priv,Demod_TOP,cfg_ts_mod_ctrl,&temp); 
	temp = (temp&0xc0)|(0<<5)|(1<<4)|(0<<2)|(0<<1)|(0);	
	gx1133_wr(priv,Demod_TOP,cfg_ts_mod_ctrl,temp); 
	
	gx1133_rd(priv,Demod_TOP,cfg_TS_s_sel,&temp); 
	gx1133_wr(priv,Demod_TOP,cfg_TS_s_sel,temp&0xf7); 

	
	gx1133_wr(priv,Demod_TOP,0xc8,(1<<4)+0); 
	gx1133_wr(priv,Demod_TOP,0xc9,(3<<4)+2); 
	gx1133_wr(priv,Demod_TOP,0xca,(5<<4)+4); 
	gx1133_wr(priv,Demod_TOP,0xcb,(7<<4)+6); 
	gx1133_wr(priv,Demod_TOP,0xcc,(9<<4)+10); 
	gx1133_wr(priv,Demod_TOP,0xcd,(11<<4)+8); 

	//init chip
	gx1133_wr(priv,Demod_TOP,cfg_mcu_onoff_line,0);	
	gx1133_set_Pll(priv,27, pll_a, pll_27M_to_182_25M);  //27M 
	gx1133_set_Pll(priv,27, pll_b, pll_27M_to_91_125M);
	gx1133_set_Pll(priv,27, pll_c, pll_27M_to_256_50M);

	gx1133_wr(priv,Demod_TOP,cfg_pll_pd,(1 | 1 <<1 | 1 <<2 | 1 <<3));
	gx1133_wr(priv,Demod_TOP,cfg_pll_pd,(0 | 0 <<1 | 0 <<2 | 0 <<3));
	
	gx1133_set_adc(priv,0,1,0,0,1);

	//clock config
	gx1133_wr(priv,Demod_TOP,cfg_PathClk_en,0xff);
	gx1133_wr(priv,Demod_TOP,cfg_nogate,0);
	//AGC select
	gx1133_rd(priv,Demod_TOP,cfg_agc_a_sel,&temp);
	temp =(temp & 0xf0) | 0x02; //in GX1133 ,the value is ifxed.
	gx1133_wr(priv,Demod_TOP,cfg_agc_a_sel,temp);
	
	//cfg_adca_bitosync_inv set 0;
	//GXDemod_Write_one_Byte(GXDemodID,0xb8,0x00);
	
	gx1133_rd(priv,Demod_TOP,cfg_cnl_rst,&temp);
	gx1133_wr(priv,Demod_TOP,cfg_cnl_rst,temp|(1<<1));
	msleep(1);
	gx1133_wr(priv,Demod_TOP,cfg_cnl_rst,temp);

	//chip platform configuration end.
	
	gx1133_rd(priv,DVB_S2,GX1133_RST,&temp);
	temp|=0x02;
	gx1133_wr(priv,DVB_S2,GX1133_RST,temp);

	//diseqc, HV_select
	gx1133_rd(priv,DVB_S2,GX1133_DISEQC_MODE,&temp);
	temp&=0x7f;
	gx1133_wr(priv,DVB_S2,GX1133_DISEQC_MODE,temp);

	//GX1133_Set_Work_BS_Mode(1);
	//ok out and clk out select
	gx1133_rd(priv,DVB_S2,GX1133_CLK_OK_SEL,&temp);
	temp=(temp&0x00) | 0x75;
	gx1133_wr(priv,DVB_S2,GX1133_CLK_OK_SEL,temp);	

	gx1133_rd(priv,Demod_TOP,cfg_tuner_rpt,&temp);
	temp= (temp&0x7f) | (0 <<7);
	gx1133_wr(priv,Demod_TOP,cfg_tuner_rpt,temp);

	gx1133_rd(priv,DVB_S2,GX1133_AGC_STD,&temp);
	temp=(temp&0xc0)|(GX1133_AGC_STD_VALUE);
	gx1133_wr(priv,DVB_S2,GX1133_AGC_STD, temp);
	//AGC_ERR_GATE=28
	gx1133_rd(priv,DVB_S2,GX1133_AGC_MODE,&temp);
	temp=(temp&0xa0)|0x5c;

	if(!GX1133_AGC_POLARITY)
		{
		temp=temp&0xbf;
		}
	gx1133_wr(priv,DVB_S2,GX1133_AGC_MODE,temp);	

	//Set the freq of 22K tone
	Diseqc_Ratio=((((91125*10)/88)+5)/10)&0x07ff;
	gx1133_wr(priv,DVB_S2,GX1133_DISEQC_RATIO_L, (u8)(Diseqc_Ratio&0xff));	

	//diseqc
	gx1133_rd(priv,DVB_S2,GX1133_DISEQC_RATIO_H,&temp);
	temp=(temp&0xF8)|((u8)(((Diseqc_Ratio&0x0700)>>8)));
	gx1133_wr(priv,DVB_S2,GX1133_DISEQC_RATIO_H,temp);

	//c_min_fs=100,equals to 1.0M
	gx1133_wr(priv,DVB_S2,GX1133_MIN_FS,0x64);
	//c_ffe_lmt =32
	gx1133_rd(priv,DVB_S2,GX1133_FFE_CTRL2,&temp);
	temp=(temp&0xc0)|0x20;
	gx1133_wr(priv,DVB_S2,GX1133_FFE_CTRL2,temp);
	//c_ffe_on=7
	gx1133_rd(priv,DVB_S2,GX1133_FFE_CTRL1,&temp);
	temp=(temp&0xf8)|0x07;
	gx1133_wr(priv,DVB_S2,GX1133_FFE_CTRL1,temp);
	//LIMIT_AMP=9
	gx1133_rd(priv,DVB_S2,GX1133_AGC_AMP,&temp);
	temp=(temp&0x0f)|0x90;
	gx1133_wr(priv,DVB_S2,GX1133_AGC_AMP,temp);
	//c_tim_loop=1
	gx1133_rd(priv,DVB_S2,GX1133_TIM_LOOP_BW,&temp);
	temp = (temp & 0x8f) | (0x1<<4);  //GX1133_TIM_LOOP_BW_VALUE
	gx1133_wr(priv,DVB_S2,GX1133_TIM_LOOP_BW,temp);
	//c_start_add=1
	gx1133_rd(priv,DVB_S2,GX1133_BBC_BW_CTRL,&temp);
	temp = (temp & 0x1f) | (0x01<<5);
	gx1133_wr(priv,DVB_S2,GX1133_BBC_BW_CTRL,temp);
	//c_leak_speed=2
	gx1133_rd(priv,DVB_S2,GX1133_EQU_SPEED,&temp);
	temp = 2;
	gx1133_wr(priv,DVB_S2,GX1133_EQU_SPEED,temp);
	//c_auto_rst_bnd=3
	gx1133_rd(priv,DVB_S2,GX1133_WAIT_LENGTH,&temp);
	temp = (temp & 0x1f) | (0x03<<5);
	gx1133_wr(priv,DVB_S2,GX1133_WAIT_LENGTH,temp);
	//c_auto_rst_len=3
	gx1133_rd(priv,DVB_S2,GX1133_AUTO_RST,&temp);
	temp = (temp & 0xf1) | (0x03<<1);
	gx1133_wr(priv,DVB_S2,GX1133_AUTO_RST,temp);
	//dvbs rs err pkt
	gx1133_wr(priv,DVB_S2,GX1133_RSD_ERR_STATIC_CTRL,0x37);
	//c_fb_gain=2
	gx1133_rd(priv,DVB_S2,GX1133_FB_FSCAN,&temp);
	temp = (temp & 0x1f) | (0x02<<5);
	gx1133_wr(priv,DVB_S2,GX1133_FB_FSCAN,temp);
	//c_plh_thresh=20
	gx1133_rd(priv,DVB_S2,GX1133_PLH_THRESH,&temp);
	temp = (temp & 0xe0) | 0x14;
	gx1133_wr(priv,DVB_S2,GX1133_PLH_THRESH,temp);
	//c_wait_out=31
	gx1133_rd(priv,DVB_S2,GX1133_MSK_PLL_OK,&temp);
	temp = (temp & 0xc1) | (0x1f<<1);
	gx1133_wr(priv,DVB_S2,GX1133_MSK_PLL_OK,temp);
	//cfg_lost_rst=1,cfg_numer_adj=1---bch byte_en
	gx1133_wr(priv,DVB_S2,GX1133_LDPC_BCH_ADJ,0x81);
	//bch_low_snr_jump=1
	gx1133_rd(priv,DVB_S2,GX1133_LDPC_BCH_JUMP,&temp);
	gx1133_wr(priv,DVB_S2,GX1133_LDPC_BCH_JUMP,temp|0x01);
	//c_fs_filter=0
	gx1133_rd(priv,DVB_S2,GX1133_BCS_FS_FILT,&temp);
	temp&= 0xf7;
	gx1133_wr(priv,DVB_S2,GX1133_BCS_FS_FILT,temp);

	gx1133_wr(priv,DVB_S2,0xb3,0x30);//ca control
	gx1133_wr(priv,DVB_S2,0xb7,0xaa);//cfg_bch_ca_num
	gx1133_wr(priv,DVB_S2,0xb8,0x10);//cfg_bch_num_adj
	gx1133_wr(priv,DVB_S2,0xb9,0x01);//cfg_bch_den_adj

	//cfg_CA_dsc = 1;cfg_dsc_CA_auto=1
	gx1133_rd(priv,DVB_S2,GX1133_CA_CTRL,&temp) ;
	temp |= 0x03;
	gx1133_wr(priv,DVB_S2,GX1133_CA_CTRL,temp);

	//cfg_dsc_num_adj fixed to 0x00
	gx1133_wr(priv,DVB_S2,0xe7,0x00);//cfg_dsc_num_adj

	//cfg_dsc_ca_num set to maximum allowed
	gx1133_wr(priv,DVB_S2,0xfb,0x40);//cfg_dsc_ca_num

	//don't use 204output; dong tuse 146 output;
	gx1133_rd(priv,DVB_S2, 0xe0,&temp);
	temp&= 0x3f ;
	gx1133_wr(priv,DVB_S2,0xe0,temp);

	//disalble linear phase interpolation
	gx1133_rd(priv,DVB_S2,0x80,&temp);
	gx1133_wr(priv,DVB_S2,0x80,temp&0xfd);

	//carrier recovery loop bandwidth
	gx1133_rd(priv,DVB_S2,0x87,&temp);
	gx1133_wr(priv,DVB_S2,0x87,(temp&0x0f)|0xa0);

	//adc/dem ratio
	gx1133_wr(priv,DVB_S2,0x4e,0x11);//demod_param->dem

	//bcs_no_sig_thd=2,bcs_find_sig_thd=4
	gx1133_wr(priv,DVB_S2,0x6a,0x42);

	//c_no_60M_fs set 0
	gx1133_rd(priv,DVB_S2,0x56,&temp);
	temp = temp & 0xfd; //c_no_60M_fs set to 0, allow adc input interpolation.
	gx1133_wr(priv,DVB_S2,0x56,temp);

	//Configure Fsample(sysclk)
	gx1133_wr(priv,DVB_S2,GX1133_Fsample_Cfg_L,91125&0xff);
	gx1133_wr(priv,DVB_S2,GX1133_Fsample_Cfg_M,(91125>>8)&0xff);
	gx1133_wr(priv,DVB_S2,GX1133_Fsample_Cfg_H,(91125>>16)&0x01);

	gx1133_rd(priv,DVB_S2,0x0C,&temp);
	gx1133_wr(priv,DVB_S2,0x0C, temp&0xFE);	

	//set diseqc pin as output
	gx1133_rd(priv,DVB_S2,GX1133_DISEQC_IO_CTRL,&temp);
	temp=(temp&0xfe)|(0x01&0);
	gx1133_wr(priv,DVB_S2,GX1133_DISEQC_IO_CTRL, temp);
	
	return 0;
}

static int gx1133_sleep(struct dvb_frontend *fe)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);
	
	return 0;
}

static int gx1133_set_frontend(struct dvb_frontend *fe)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	enum fe_status tunerstat;
	int ret, i;
	u32 s;
	u8 buf[4],temp;

	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	printk("set frontends\n");
	/* do some basic parameter validation */
	switch (c->delivery_system) {
	case SYS_DVBS:
		dev_dbg(&priv->i2c->dev, "%s() DVB-S\n", __func__);
		/* Only QPSK is supported for DVB-S */
		if (c->modulation != QPSK) {
			dev_dbg(&priv->i2c->dev,
				"%s() unsupported modulation (%d)\n",
				__func__, c->modulation);
			return -EINVAL;
		}
		break;
	case SYS_DVBS2:
		dev_dbg(&priv->i2c->dev, "%s() DVB-S2\n", __func__);
		break;
	default:
		dev_warn(&priv->i2c->dev,
			"%s() unsupported delivery system (%d)\n",
			__func__, c->delivery_system);
		return -EINVAL;
	}

	gx1133_rd(priv,DVB_S2,GX1133_AUTO_RST,&temp);
	temp|=0x01;
	gx1133_wr(priv,DVB_S2,GX1133_AUTO_RST,temp);

	gx1133_set_work_bs_mode(priv,1);

	gx1133_rd(priv,DVB_S2,GX1133_BCS_OUT_ADDR,&temp);
	temp=temp&0xe0;
	gx1133_wr(priv,DVB_S2,GX1133_BCS_OUT_ADDR,temp);

	/* set symbol rate */
	s = c->symbol_rate / 1000;
	buf[0] = DVB_S2;
	buf[1] = GX1133_SYMBOL_L;
	buf[2] = (u8) s;
	buf[3] = (u8) (s >> 8);
	ret = gx1133_wrm(priv, buf, 4);
	
	if (ret)
		return ret;
	
	/* clear freq offset */
	buf[0] = DVB_S2;
	buf[1] = GX1133_FC_OFFSET_L;
	buf[2] = 0;
	buf[3] = 0;
	ret = gx1133_wrm(priv, buf, 4);
	if (ret)
		return ret;

		if (fe->ops.tuner_ops.set_params) {
#ifndef GX1133_USE_I2C_MUX
			if (fe->ops.i2c_gate_ctrl)
				fe->ops.i2c_gate_ctrl(fe, 1);
#endif
			fe->ops.tuner_ops.set_params(fe);
#ifndef GX1133_USE_I2C_MUX
			if (fe->ops.i2c_gate_ctrl)
				fe->ops.i2c_gate_ctrl(fe, 0);
#endif
		}


	gx1133_rd(priv,DVB_S2,GX1133_RST,&temp);
	temp|=0x01;
	gx1133_wr(priv,DVB_S2,GX1133_RST,temp);	

	msleep(50);

	for (i = 0; i<15; i++) {
		ret = gx1133_read_status(fe, &tunerstat);
		if (tunerstat & FE_HAS_LOCK)
			return 0;
		msleep(20);
	}
	return -EINVAL;
}

static int gx1133_get_frontend(struct dvb_frontend *fe,
				struct dtv_frontend_properties *c)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	int ret;
	u8 reg, buf[2];

	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	ret = gx1133_rd(priv,DVB_S2, GX1133_MODU_MODE, &reg);
	if (ret)
		return ret;

	if ((reg >> 6) == 0) {
		/* DVB-S */
		reg &= 0x07;
	} else {
		/* DVB-S2 */
		ret = gx1133_rd(priv, DVB_S2,GX1133_S2_MODE_CODE, &reg);
		if (ret)
			return ret;
		reg += 5;
	}

	if (reg > 33) {
		dev_dbg(&priv->i2c->dev, "%s() Unable to get current delivery"
			" system and mode.\n", __func__);
		reg = 0;
	}

	c->fec_inner = gx1133_modfec_modes[reg].fec;
	c->modulation = gx1133_modfec_modes[reg].modulation;
	c->delivery_system = gx1133_modfec_modes[reg].delivery_system;
	c->inversion = INVERSION_AUTO;

	/* symbol rate */
	ret = gx1133_rdm(priv,DVB_S2,0x5C, buf, 2);
	if (ret)
		return ret;
	c->symbol_rate = ((buf[1] << 8) | buf[0]) * 1000;

	return 0;
}

static int gx1133_tune(struct dvb_frontend *fe, bool re_tune,
	unsigned int mode_flags, unsigned int *delay, enum fe_status *status)
{
	struct gx1133_priv *priv = fe->demodulator_priv;

	dev_dbg(&priv->i2c->dev, "%s()\n", __func__);

	*delay = HZ / 5;
	if (re_tune) {
		int ret = gx1133_set_frontend(fe);
		if (ret)
			return ret;
	}
	return gx1133_read_status(fe, status);
}

static enum dvbfe_algo gx1133_get_algo(struct dvb_frontend *fe)
{
	return DVBFE_ALGO_HW;
}

#ifndef GX1133_USE_I2C_MUX
static int gx1133_i2c_gate_ctrl(struct dvb_frontend* fe, int enable)
{
	struct gx1133_priv *priv = fe->demodulator_priv;
	int ret;
	u8 tmp;
	gx1133_rd(priv,Demod_TOP,cfg_tuner_rpt,&tmp);
	tmp= (tmp&0x7f) | (enable <<7);
	gx1133_wr(priv,Demod_TOP,cfg_tuner_rpt,tmp);

	return ret;
}
#endif

static struct dvb_frontend_ops gx1133_ops = {
	.delsys = { SYS_DVBS, SYS_DVBS2 },
	.info = {
		.name = "Tmax gx1133",
		.frequency_min_hz = 950 * MHz,
		.frequency_max_hz = 2150 * MHz,
		.symbol_rate_min = 1000000,
		.symbol_rate_max = 45000000,
		.caps = FE_CAN_INVERSION_AUTO |
			FE_CAN_FEC_1_2 | FE_CAN_FEC_2_3 | FE_CAN_FEC_3_4 |
			FE_CAN_FEC_4_5 | FE_CAN_FEC_5_6 | FE_CAN_FEC_6_7 |
			FE_CAN_FEC_7_8 | FE_CAN_FEC_AUTO |
			FE_CAN_2G_MODULATION |
			FE_CAN_QPSK | FE_CAN_RECOVER
	},
	.release = gx1133_release,

	.init = gx1133_initfe,
	.sleep = gx1133_sleep,
#ifndef GX1133_USE_I2C_MUX
	.i2c_gate_ctrl = gx1133_i2c_gate_ctrl,
#endif
	.read_status = gx1133_read_status,
	.read_ber = gx1133_read_ber,
	.read_signal_strength = gx1133_read_signal_strength,
	.read_snr = gx1133_read_snr,
	.read_ucblocks = gx1133_read_ucblocks,

	.set_tone = gx1133_set_tone,
	.set_voltage = gx1133_set_voltage,
	.diseqc_send_master_cmd = gx1133_send_diseqc_msg,
	.diseqc_send_burst = gx1133_diseqc_send_burst,
	.get_frontend_algo = gx1133_get_algo,
	.tune = gx1133_tune,

	.set_frontend = gx1133_set_frontend,
	.get_frontend = gx1133_get_frontend,

	.spi_read			= gx1133_spi_read,
	.spi_write			= gx1133_spi_write,


};

MODULE_DESCRIPTION("DVB Frontend module for Nationalchip gx1133");
MODULE_AUTHOR("Davin zhang(smiledavin@gmail.com)");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

