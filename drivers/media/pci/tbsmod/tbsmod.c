#include <linux/pci.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/delay.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/mutex.h>
#include <asm/dma.h>
#include <asm/irq.h>
#include <linux/io.h>
#include <linux/uaccess.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kfifo.h>
#include <linux/dvb/frontend.h>

#include "tbsmod.h"
#include "tbsmod-io.h"
#include "mod.h"

#define TRUE 1
#define FALSE 0
#define BOOL bool

void spi_ad9789Enable(struct tbs_pcie_dev *dev, int Data)
{
	unsigned char tmpbuf[4];

	//write enable:
	tmpbuf[0] = Data;
	TBS_PCIE_WRITE(0, SPI_ENABLE, *(u32 *)&tmpbuf[0]);
}

BOOL AD4351_CheckFree(struct tbs_pcie_dev *dev, int OpbyteNum)
{
	unsigned char tmpbuf[4] = {0};
	int i, j;

	if (OpbyteNum > 2)
		j = 100;
	else
		j = 50;
	msleep(1);

	for (i = 0; (i < j) && (tmpbuf[0] != 1); i++)
	{
		*(u32 *)tmpbuf = TBS_PCIE_READ(0, SPI_AD4351);
		msleep(1);
	}
	if (tmpbuf[0] == 1)
		return TRUE;
	else
	{
		printk(("----------AD4351_CheckFree error, time out! \n"));
		return FALSE;
	}
}

BOOL ad9789_CheckFree(struct tbs_pcie_dev *dev, int OpbyteNum)
{
	unsigned char tmpbuf[4] = {0};
	int i, j;

	if (OpbyteNum > 2)
		j = 100;
	else
		j = 50;
	msleep(1);

	for (i = 0; (i < j) && (tmpbuf[0] != 1); i++)
	{
		*(u32 *)tmpbuf = TBS_PCIE_READ(0, SPI_STATUS);
		msleep(1);
	}
	if (tmpbuf[0] == 1)
		return TRUE;
	else
	{
		printk(("----------ad9789_CheckFree error, time out! \n"));
		return FALSE;
	}
}

BOOL ad9789_wt_nBytes(struct tbs_pcie_dev *dev, int length, int Reg_Addr, unsigned char *Wr_buf)
{
	unsigned char i = 0, tmpdt = 0, tmpbuf[8];

	if (length == 3)
		tmpdt = 0x40;
	else if (length == 2)
		tmpdt = 0x20;
	else if (length == 1)
		tmpdt = 0x00;
	else
		printk((" ad9789_wt_nBytes error length !\n"));

	//Reg_Addr 13bit;
	tmpbuf[0] = ((Reg_Addr >> 8) & 0x1f);
	tmpbuf[1] = (Reg_Addr & 0xff);
	tmpbuf[0] += tmpdt; //3'b0xx; write;

	for (i = 0; i < length; i++)
		tmpbuf[2 + i] = Wr_buf[i];

	TBS_PCIE_WRITE(0, SPI_COMMAND, *(u32 *)&tmpbuf[0]);
	TBS_PCIE_WRITE(0, SPI_WT_DATA, *(u32 *)&tmpbuf[4]);

	tmpbuf[0] = 0xe0; //cs low,cs high, write, no read;
	tmpbuf[1] = 0;
	tmpbuf[1] += (length + 2) * 16; // regadd + length
	TBS_PCIE_WRITE(0, SPI_CONFIG, *(u32 *)&tmpbuf[0]);

	if (ad9789_CheckFree(dev, 4) == 0)
	{
		printk((" ad9789_wt_nBytes error!	\n"));
		return FALSE;
	}

	return TRUE;
}

BOOL ad9789_rd_nBytes(struct tbs_pcie_dev *dev, int length, int Reg_Addr, unsigned char *Rd_buf)
{
	unsigned char tmpdt = 0, tmpbuf[4];

	if (length == 3)
		tmpdt = 0xc0;
	else if (length == 2)
		tmpdt = 0xa0;
	else if (length == 1)
		tmpdt = 0x80;
	else
		printk((" ad9789_rd_nBytes error length!\n"));

	//Reg_Addr 13bit;
	tmpbuf[0] = ((Reg_Addr >> 8) & 0x1f);
	tmpbuf[1] = (Reg_Addr & 0xff);
	tmpbuf[0] += tmpdt; //3'b1xx; read;

	TBS_PCIE_WRITE(0, SPI_COMMAND, *(u32 *)&tmpbuf[0]);

	tmpbuf[0] = 0xf0;	//cs low,cs high, write, read;
	tmpbuf[1] = 0x20;	// 2 bytes command for writing;
	tmpbuf[1] += length; //read n bytes data;
	TBS_PCIE_WRITE(0, SPI_CONFIG, *(u32 *)&tmpbuf[0]);

	if (ad9789_CheckFree(dev, 4) == 0)
	{
		printk((" ad9789_rd_nBytes error!   \n"));
		return FALSE;
	}

	*(u32 *)Rd_buf = TBS_PCIE_READ(0, SPI_RD_DATA);

	msleep(1);

	return TRUE;
}

BOOL ad4351_wt_nBytes(struct tbs_pcie_dev *dev, unsigned char *WR_buf, int length)
{
	unsigned char tmpbuf[4] = {0}, i;

	for (i = 0; i < length; i++)
		tmpbuf[i] = WR_buf[i];

	TBS_PCIE_WRITE(0, SPI_AD4351, *(u32 *)&tmpbuf[0]);

	if (AD4351_CheckFree(dev, 4) == 0)
	{
		printk((" ad4351_wt_nBytes error!   \n"));
		return FALSE;
	}
	return TRUE;
}

void AD9789_SETMODE(struct tbs_pcie_dev *dev, int MOD)
{
	int buf[4] = {0};
	buf[0] = MOD;
	TBS_PCIE_WRITE(0, AD9789_MODULATION, *(u32 *)&buf[0]);
	return;
}

void AD9789_Init_Configration(struct tbs_pcie_dev *dev)

{
	int i = 0;
	unsigned char buff[4] = {0};

	buff[0] = 0x9E;
	ad9789_wt_nBytes(dev, 1, AD9789_CLOCK_RECIVER_2, buff); //CLK_DIS=1;PSIGN=0;CLKP_CML=0x0F;NSIGN=0
	ad9789_rd_nBytes(dev, 1, AD9789_CLOCK_RECIVER_2, buff);

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_CONTROL_DUTY_CYCLE, buff);
	ad9789_rd_nBytes(dev, 1, AD9789_Mu_CONTROL_DUTY_CYCLE, buff);

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff);

	buff[0] = 0xCE;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_1, buff); //SEARCH_TOL=1;SEARCH_ERR=1;TRACK_ERR=0;GUARDBAND=0x0E
	ad9789_rd_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_1, buff);
	buff[0] = 0x42;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff); //MU_CLKDIS=0;SLOPE=1;MODE=0x00;MUSAMP=0;GAIN=0x01;MU_EN=1;
	ad9789_rd_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff);
	buff[0] = 0x4E;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_3, buff); //MUDLY=0x00;SEARCH_DIR=0x10;MUPHZ=0x0E;
	ad9789_rd_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_3, buff);
	buff[0] = 0x6C;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_4, buff); //MUDLY=0x9F;
	ad9789_rd_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_4, buff);

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_INT_ENABLE, buff);

	buff[0] = 0xFE;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_STATUS, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_INT_STATUS, buff);

	buff[0] = 0x0C;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_INT_ENABLE, buff);

	buff[0] = 0x43;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff); //MU_CLKDIS=0;SLOPE=1;MODE=0x00;MUSAMP=0;GAIN=0x01;MU_EN=1;
	ad9789_rd_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff);

	buff[0] = 0x01;
	ad9789_wt_nBytes(dev, 1, AD9789_BYPASS, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_BYPASS, buff);

	buff[0] = 0x26; //0x22~0x26: qam16~256
	ad9789_wt_nBytes(dev, 1, AD9789_QAM_CONFIG, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_QAM_CONFIG, buff);

	//0:DVB-C 16
	//1:DVB-C 32
	//2:DVB-C 64
	//3:DVB-C 128
	//4:DVB-C 256
	AD9789_SETMODE(dev, 4);

	buff[0] = 0x14;
	ad9789_wt_nBytes(dev, 1, AD9789_SUM_SCALAR, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_SUM_SCALAR, buff);

	buff[0] = 0x20;
	ad9789_wt_nBytes(dev, 1, AD9789_INPUT_SCALAR, buff);
	ad9789_rd_nBytes(dev, 1, AD9789_INPUT_SCALAR, buff);

	buff[2] = 0xC2;
	buff[1] = 0xF5;
	buff[0] = 0x28;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_0_FRE, buff); //NCO_0:0x55,0x55,0x55,800Mfreq
	ad9789_rd_nBytes(dev, 3, AD9789_NCO_0_FRE, buff);

	buff[2] = 0x03;
	buff[1] = 0x9D;
	buff[0] = 0x36;	
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_1_FRE, buff); //NCO_1:0x62,0xFC,0x96,808Mfreq
	ad9789_rd_nBytes(dev, 3, AD9789_NCO_1_FRE, buff);
	buff[2] = 0x44;
	buff[1] = 0x44;
	buff[0] = 0x44;	
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_2_FRE, buff); //NCO_2:0x70,0xA3,0xD7,816Mfreq
	ad9789_rd_nBytes(dev, 3, AD9789_NCO_2_FRE, buff);

	buff[2] = 0x85;
	buff[1] = 0xEB;
	buff[0] = 0x51;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_3_FRE, buff); //NCO_3:0x7E,0x4B,0x17,808Mfreq
	ad9789_rd_nBytes(dev, 3, AD9789_NCO_3_FRE, buff);

	buff[2] = 0x00;
	buff[1] = 0x00;
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 3, AD9789_RATE_CONVERT_Q, buff); 
	ad9789_rd_nBytes(dev, 3, AD9789_RATE_CONVERT_Q, buff);

	buff[2] = 0x55;
	buff[1] = 0x55;
	buff[0] = 0x53;	
	ad9789_wt_nBytes(dev, 3, AD9789_RATE_CONVERT_P, buff); 
	ad9789_rd_nBytes(dev, 3, AD9789_RATE_CONVERT_P, buff);

	buff[1] = 0xD7;
	buff[0] = 0x33;	
	ad9789_wt_nBytes(dev, 2, AD9789_CENTER_FRE_BPF, buff); 
	ad9789_rd_nBytes(dev, 2, AD9789_CENTER_FRE_BPF, buff);

	buff[0] = 0x06;
	ad9789_wt_nBytes(dev, 1, AD9789_INTERFACE_CONFIG, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_INTERFACE_CONFIG, buff);

	buff[0] = 0x61;
	ad9789_wt_nBytes(dev, 1, AD9789_DATA_CONTROL, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_DATA_CONTROL, buff);

	buff[0] = 0x10;
	ad9789_wt_nBytes(dev, 1, AD9789_DCO_FRE, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_DCO_FRE, buff);

	buff[0] = 0x62;
	ad9789_wt_nBytes(dev, 1, AD9789_INTERNAL_COLCK_ADJUST, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_INTERNAL_COLCK_ADJUST, buff);

	buff[0] = 60;
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_0_GAIN, buff);
	ad9789_rd_nBytes(dev, 1, AD9789_CHANNEL_0_GAIN, buff);

	buff[0] = 60;
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_1_GAIN, buff);
	ad9789_rd_nBytes(dev, 1, AD9789_CHANNEL_1_GAIN, buff);

	buff[0] = 60;
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_2_GAIN, buff);
	ad9789_rd_nBytes(dev, 1, AD9789_CHANNEL_2_GAIN, buff);

	buff[0] = 60;
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_3_GAIN, buff);
	ad9789_rd_nBytes(dev, 1, AD9789_CHANNEL_3_GAIN, buff);

	buff[0] = 0;
	ad9789_wt_nBytes(dev, 1, AD9789_SPEC_SHAPING, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_SPEC_SHAPING, buff);

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_FULL_SCALE_CURRENT_1, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_FULL_SCALE_CURRENT_1, buff);

	buff[0] = 0x02;
	ad9789_wt_nBytes(dev, 1, AD9789_FULL_SCALE_CURRENT_2, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_FULL_SCALE_CURRENT_2, buff);

	ad9789_rd_nBytes(dev, 1, AD9789_INT_STATUS, buff);
	for (i = 0; i < 10; i++)
	{
		if (buff[0] == 0x08)
			break;
		msleep(5);
	}

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_FRE_UPDATE, buff);

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff);

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff);

	buff[0] = 0x0F;
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff);

	buff[0] = 0x0E;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 
	ad9789_rd_nBytes(dev, 1, AD9789_INT_ENABLE, buff);

	return;
}

// freq MHZ
BOOL ad9789_setFre(struct tbs_pcie_dev *dev, unsigned long freq)
{
	unsigned long freq_0, freq_1, freq_2, freq_3;
	unsigned char buff[4] = {0};
	//config center freq
	unsigned long fcenter;

	freq = freq / 1000000;
	printk("set freq: %ld\n", freq);
	//freq_0 = (16777216 * freq)/150;
	freq_0 = div_u64(16777216ULL * freq, 150);
	buff[2] = freq_0 & 0xff;
	buff[1] = (freq_0 >> 8) & 0xff;
	buff[0] = (freq_0 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_0_FRE, buff);

	//freq_1 = (16777216 * (freq+8))/150;
	freq_1 = div_u64(16777216ULL * (freq + 8), 150);
	buff[2] = freq_1 & 0xff;
	buff[1] = (freq_1 >> 8) & 0xff;
	buff[0] = (freq_1 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_1_FRE, buff);

	//freq_2 = (16777216 * (freq+16))/150;
	freq_2 = div_u64(16777216ULL * (freq + 16), 150);
	buff[2] = freq_2 & 0xff;
	buff[1] = (freq_2 >> 8) & 0xff;
	buff[0] = (freq_2 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_2_FRE, buff);

	//freq_3 = (16777216 * (freq+24))/150;
	freq_3 = div_u64(16777216ULL * (freq + 24), 150);
	buff[2] = freq_3 & 0xff;
	buff[1] = (freq_3 >> 8) & 0xff;
	buff[0] = (freq_3 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_3_FRE, buff);

	fcenter = freq + 12;
	//fcenter = (fcenter*65536)/2400;
	fcenter = div_u64(fcenter * 65536ULL, 2400);
	buff[1] = fcenter & 0xff;
	buff[0] = (fcenter >> 8) & 0xff; 
	ad9789_wt_nBytes(dev, 2, AD9789_CENTER_FRE_BPF, buff); 

	//update
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	msleep(5);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

	return TRUE;
}

//srate Ks
void config_srate(struct tbs_pcie_dev *dev, unsigned long srate)
{
	unsigned char buff[4] = {0};
	//srate = (2400 * 1000 *16384) /srate;
	srate = srate / 1000;
	printk("set symbolrate: %ld\n", srate);
	srate = div_u64(39321600000ULL, srate);

	buff[2] = srate & 0xff;
	buff[1] = (srate >> 8) & 0xff;
	buff[0] = (srate >> 16) & 0xff;

	ad9789_wt_nBytes(dev, 3, AD9789_RATE_CONVERT_P, buff);

	//update
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	msleep(5);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

}

//qam 0~4  to qam16~256
void config_QAM(struct tbs_pcie_dev *dev, int qam)
{

	unsigned char buff[4] = {0};
	printk("set qam: %d\n", qam);
	buff[0] = 0x22 + qam;
	ad9789_wt_nBytes(dev, 1, AD9789_QAM_CONFIG, buff);
	ad9789_rd_nBytes(dev, 1, AD9789_QAM_CONFIG, buff);

	//0:DVB-C 16
	//1:DVB-C 32
	//2:DVB-C 64
	//3:DVB-C 128
	//4:DVB-C 256
	AD9789_SETMODE(dev, qam);

	//update
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	msleep(5);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

}
BOOL AD4351_Init_Configration(struct tbs_pcie_dev *dev)
{
	unsigned char ret;
	unsigned char buff[4] = {0};

	buff[3] = 0x05;
	buff[2] = 0x00;
	buff[1] = 0x58;
	buff[0] = 0x00;

	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0x3C;
	buff[2] = 0x80;
	buff[1] = 0x8C;
	buff[0] = 0x00;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}

	buff[3] = 0xB3;
	buff[2] = 0x04;
	buff[1] = 0x00;
	buff[0] = 0x00;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0x42;
	buff[2] = 0x4E;
	buff[1] = 0x00;
	buff[0] = 0x00;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0x11;
	buff[2] = 0x80;
	buff[1] = 0x00;
	buff[0] = 0x08;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0x00;
	buff[2] = 0x00;
	buff[1] = 0x30;
	buff[0] = 0x00;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}

u8 tbsmods[10];
struct tbs_pcie_dev * tbsmodsdev[10];
struct cdev		mod_cdev;
struct class	*mod_cdev_class;


u32 getbitrate(struct tbs_pcie_dev *dev,u8 index)
{
	u64 bitrate=0;
	u32 xmax;
	switch (dev->modulation)
	{
		case QAM_16:
			bitrate =4;
			break;
		case QAM_32:
			bitrate =5;
			break;
		case QAM_64:
			bitrate =6;
			break;
		case QAM_128:
			bitrate =7;
			break;
		case QAM_256:
			bitrate = 8;
			break;
		default:
			break;
	}
	if(bitrate){
		bitrate =  dev->srate * bitrate *188;
		bitrate = div_u64(bitrate, 204);
		xmax = TBS_PCIE_READ(Dmaout_adapter0+index*0x1000, DMA_DELAY);
		xmax = xmax * 188 * 8;
		//printk("bitrate:%lld xmax:%d\n",bitrate,xmax);
		if(bitrate > xmax)
			bitrate = xmax;
		return bitrate;
	}
	return 0;
}




static void start_dma_transfer(struct mod_channel *pchannel)
{
	struct tbs_pcie_dev *dev=pchannel->dev;
	u32 delay;
	u32 bitrate;
	
	bitrate = getbitrate(dev,pchannel->channel_index);
	delay = div_u64(1000000000ULL * BLOCKSIZE, bitrate);
//	printk("ioctl 0x14 delay: %d \n", delay);
	TBS_PCIE_WRITE(Dmaout_adapter0+pchannel->channel_index*0x1000, DMA_DELAY, (delay));

	TBS_PCIE_WRITE(Dmaout_adapter0+pchannel->channel_index*0x1000, DMA_SIZE, (BLOCKSIZE));
	TBS_PCIE_WRITE(Dmaout_adapter0+pchannel->channel_index*0x1000, DMA_ADDR_HIGH, 0);
	TBS_PCIE_WRITE(Dmaout_adapter0+pchannel->channel_index*0x1000, DMA_ADDR_LOW, pchannel->dmaphy);
	TBS_PCIE_WRITE(Dmaout_adapter0+pchannel->channel_index*0x1000, DMA_GO, (1));

	TBS_PCIE_WRITE(Int_adapter, 0x04, (0x00000001));
	TBS_PCIE_WRITE(Int_adapter, 0x18+pchannel->channel_index*4, (1));
}

static int tbsmod_open(struct inode *inode, struct file *filp)
{
	struct tbs_pcie_dev *dev = (struct tbs_pcie_dev * )tbsmodsdev[iminor(inode)>>2];
	struct mod_channel *pchannel =(struct mod_channel *)&dev->channnel[iminor(inode)&3];
	filp->private_data = pchannel;
	/*
	printk("%s %p\n", __func__, pchannel);
	printk("%s devno:%d\n", __func__, pchannel->devno);
	printk("%s virt:%p\n", __func__, pchannel->dmavirt);
	printk("%s phy:%llx\n", __func__, pchannel->dmaphy);
	printk("%s index:%d\n", __func__, pchannel->channel_index);


	printk("%s modules:%d\n", __func__, dev->modulation);
	printk("%s freq:%d\n", __func__, dev->frequency);
	printk("%s srate:%d\n", __func__, dev->srate);
	*/
	pchannel->dma_start_flag = 0;
	kfifo_reset(&pchannel->fifo);


	//printk("%s fifo size:%d \n", __func__, kfifo_size(&pchannel->fifo));
	//printk("%s success \n", __func__);
	return 0;
}
static ssize_t tbsmod_read(struct file *file, char __user *ptr, size_t size, loff_t *ppos)
{
//	struct mod_channel *pchannel = (struct mod_channel *)file->private_data;
//	struct tbs_pcie_dev *dev = pchannel->dev;
//	unsigned int copied;
//	unsigned int ret;
	printk("%s\n", __func__);
//	ret = kfifo_to_user(&dev->fifo, ptr, size, &copied);
	return 0;
}

static ssize_t tbsmod_write(struct file *file, const char __user *ptr, size_t size, loff_t *ppos)
{
	struct mod_channel *pchannel = (struct mod_channel *)file->private_data;
	int count;
	int i = 0;
	count = kfifo_avail(&pchannel->fifo);
	while (count < size)
	{
		if (pchannel->dma_start_flag == 0)
		{
			start_dma_transfer(pchannel);
			pchannel->dma_start_flag = 1;
		}
		msleep(10);
		count = kfifo_avail(&pchannel->fifo);
		i++;
		if (i > 100)
			return 0;
	}
	if (count >= size)
	{
		unsigned int copied;
		unsigned int ret;
		ret = kfifo_from_user(&pchannel->fifo, ptr, size, &copied);
		if (size != copied)
			printk("%s size:%d  %d\n", __func__, size, copied);
	}

	return size;
}
void spi_read(struct tbs_pcie_dev *dev, struct ecp3_info *info)
{
	info->data = TBS_PCIE_READ(0, info->reg);
	
}
void spi_write(struct tbs_pcie_dev *dev, struct ecp3_info *info)
{
	unsigned char tmpbuf[4];
	TBS_PCIE_WRITE(0,info->reg,info->data);	
}
static long tbsmod_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct mod_channel *pchannel = (struct mod_channel *)file->private_data;
	struct tbs_pcie_dev *dev = pchannel->dev;
	//struct dtv_properties *props = NULL;
	struct dtv_properties props ;
	//struct dtv_property *prop = NULL;
	struct dtv_property prop;
	
	int ret = 0;

	switch (cmd)
	{
	case FE_SET_PROPERTY:
		printk("%s FE_SET_PROPERTY\n", __func__);
		if(pchannel->channel_index){
			printk("%s FE_SET_PROPERTY not allow set\n", __func__);
			ret = -EINVAL;
			break;
		}
		//props = (struct dtv_properties *)arg;
		copy_from_user(&props , (const char*)arg, sizeof(struct dtv_properties ));
		if (props.num == 1)
		{
			//prop = props.props;
			copy_from_user(&prop , (const char*)props.props, sizeof(struct dtv_property ));
			switch (prop.cmd)
			{
			case MODULATOR_MODULATION:
				printk("MODULATOR_MODULATION:%d\n", prop.u.data);
				if (prop.u.data < QAM_16 || prop.u.data > QAM_256)
				{
					ret = -1;
					break;
				}
				dev->modulation = prop.u.data;
				config_QAM(dev,dev->modulation-1);
				break;

			case MODULATOR_SYMBOL_RATE:
				printk("MODULATOR_SYMBOL_RATE:%d\n", prop.u.data);
	
				if (prop.u.data < 1000000)
				{
					ret = EINVAL;
					break;
				}
				dev->srate = prop.u.data;
				config_srate(dev, dev->srate);

				break;

			case MODULATOR_FREQUENCY:
				printk("MODULATOR_FREQUENCY:%d\n", prop.u.data);
				{
					u32 frequency = prop.u.data;
					u32 freq = frequency / 1000000;

					if (frequency % 1000000)
						ret = -EINVAL;
					if ((freq - 114) % 8)
						ret = -EINVAL;
					if ((freq < 114) || (freq > 874))
						ret = -EINVAL;
				}
				if (ret < 0)
					break;
				dev->frequency = prop.u.data;
				ad9789_setFre(dev,dev->frequency);

				break;

			default:
				ret = -EINVAL;
				break;
			}
		}
		else
		{
			ret = -EINVAL;
		}
		break;

	case FE_GET_PROPERTY:
		printk("%s FE_GET_PROPERTY\n", __func__);
		//props = (struct dtv_properties *)arg;
		copy_from_user(&props , (const char*)arg, sizeof(struct dtv_properties ));
		if (props.num == 1)
		{		
			//prop = props.props;
			copy_from_user(&prop , (const char*)props.props, sizeof(struct dtv_property ));
			switch (prop.cmd)
			{
			case MODULATOR_MODULATION:
				prop.u.data = dev->modulation ;
				printk("MODULATOR_MODULATION:%d\n", prop.u.data);
				break;

			case MODULATOR_SYMBOL_RATE:
				prop.u.data =dev->srate ;
				printk("MODULATOR_SYMBOL_RATE:%d\n", prop.u.data);
				break;

			case MODULATOR_FREQUENCY:
				prop.u.data = dev->frequency;
				printk("MODULATOR_FREQUENCY:%d\n", prop.u.data);
				break;
			}
		}
		break;

	case FE_ECP3FW_READ:
		spi_read(dev, arg);
		break;
	case FE_ECP3FW_WRITE:
		spi_write(dev, arg);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}
static int tbsmod_mmap(struct file *file, struct vm_area_struct *vm)
{
	printk("%s\n", __func__);
	return 0;
}

static int tbsmod_release(struct inode *inode, struct file *file)
{
	struct mod_channel *pchannel = (struct mod_channel *)file->private_data;
	//printk("%s\n", __func__);
	pchannel->dma_start_flag = 0;
	return 0;
}

static const struct file_operations tbsmod_fops =
	{
		.owner = THIS_MODULE,
		.open = tbsmod_open,
		.read = tbsmod_read,
		.write = tbsmod_write,
		.unlocked_ioctl = tbsmod_ioctl,
		.mmap = tbsmod_mmap,
		.release = tbsmod_release,
};

static void tbs_adapters_init(struct tbs_pcie_dev *dev)
{
	unsigned char tmpbuf[4];
	int id2;
	BOOL ret;

	//reset 9789
	tmpbuf[0] = 1;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);

	ret = AD4351_Init_Configration(dev);
	if (ret == FALSE)
		printk("configration ad4351 false! \n");

	spi_ad9789Enable(dev, 1);

	// choose spi device for 9789
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&tmpbuf[0]);

	AD9789_Init_Configration(dev);

	//read id (54425368)
	id2 = TBS_PCIE_READ(0, SPI_RESET);
	printk("chip id2: %x\n", __swab32(id2));

	//test
	tmpbuf[0] = 0;
	ad9789_rd_nBytes(dev, 1, AD9789_HARDWARE_VERSION, tmpbuf);
	printk("hardware version: %x !\n", tmpbuf[0]);
	
	if(tmpbuf[0]==3)
		printk("TBS6004 DVBC Modulator init OK !\n");
	else
		printk("TBS6004 DVBC Modulator init failed !\n");
	
	/* disable all interrupts */
	//	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);

}

void channelprocess(struct tbs_pcie_dev *dev,u8 index){
		struct mod_channel *pchannel = (struct mod_channel *)&dev->channnel[index];
		int count = 0;
		int ret;

		TBS_PCIE_READ(Dmaout_adapter0+pchannel->channel_index*0x1000, 0x00);
		TBS_PCIE_WRITE(Int_adapter, 0x00, (0x10<<index) );
		count = kfifo_len(&pchannel->fifo);
		if (count >= BLOCKSIZE){
			//printk("dma%d status 11 %d\n",pchannel->channel_index,count);
			ret = kfifo_out(&pchannel->fifo, ((void *)(pchannel->dmavirt) ), BLOCKSIZE); 
			start_dma_transfer(pchannel);
		}else{
			//printk("dma%d status 22 %d\n", pchannel->channel_index, count);
			if (pchannel->dma_start_flag == 0){
				return ;
			}

			if (dev->srate){
				u32 delay;
				u32 bitrate;
				bitrate = getbitrate(dev,pchannel->channel_index);
				delay = div_u64(1000000000ULL * BLOCKSIZE, bitrate*3);
				//printk("%s 0x14 delayshort: %d \n", __func__,delay);
				TBS_PCIE_WRITE(Dmaout_adapter0+pchannel->channel_index*0x1000, DMA_DELAYSHORT, (delay));
				TBS_PCIE_WRITE(Int_adapter, 0x04, 0x00000001);
			}
		}
}

static irqreturn_t tbsmod_irq(int irq, void *dev_id)
{
	struct tbs_pcie_dev *dev = (struct tbs_pcie_dev *)dev_id;
	u32 stat;

	stat = TBS_PCIE_READ(Int_adapter, 0x0c);
	//printk("%s %x\n",__func__,stat);
	if (!(stat & 0xf0)){
		TBS_PCIE_WRITE(Int_adapter, 0x04, 0x00000001);
		return IRQ_HANDLED;
	}

	if (stat & 0x80){ //dma3 status
		channelprocess(dev,3);
	}

	if (stat & 0x40){ //dma2 status
		channelprocess(dev,2);
	}

	if (stat & 0x20){ //dma1 status
		channelprocess(dev,1);
	}

	if (stat & 0x10){ //dma0 status
		channelprocess(dev,0);
	}

	return IRQ_HANDLED;
}


static void tbsmod_remove(struct pci_dev *pdev)
{
	struct tbs_pcie_dev *dev =
		(struct tbs_pcie_dev *)pci_get_drvdata(pdev);
	int i;

	for(i=0;i<CHANNELS;i++){
		kfifo_free(&dev->channnel[i].fifo);
//		device_destroy(mod_cdev_class, dev->channnel[i].devno);
		if (!dev->channnel[i].dmavirt){
			pci_free_consistent(dev->pdev, DMASIZE, dev->channnel[i].dmavirt, dev->channnel[i].dmaphy);
			dev->channnel[i].dmavirt = NULL;
		}
	}
	tbsmods[dev->mod_index] =0;

	/* disable interrupts */
	free_irq(dev->pdev->irq, dev);

	if (dev->mmio)
		iounmap(dev->mmio);

	kfree(dev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static int tbsmod_probe(struct pci_dev *pdev,
						const struct pci_device_id *pci_id)
{
	struct tbs_pcie_dev *dev;
	int err = 0, ret = -ENODEV;
	u8 index=0;
	u8 i;

	
	dev = kzalloc(sizeof(struct tbs_pcie_dev), GFP_KERNEL);
	if (dev == NULL)
	{
		printk(KERN_ERR "%s ERROR: out of memory\n", __func__);
		ret = -ENOMEM;
		goto fail0;
	}

	dev->pdev = pdev;

	err = pci_enable_device(pdev);
	if (err != 0)
	{
		ret = -ENODEV;
		printk(KERN_ERR "%s ERROR: PCI enable failed (%i)\n", __func__, err);
		goto fail1;
	}

	dev->mmio = ioremap(pci_resource_start(dev->pdev, 0),
						pci_resource_len(dev->pdev, 0));
	if (!dev->mmio)
	{
		printk(KERN_ERR "%s ERROR: Mem 0 remap failed\n", __func__);
		ret = -ENODEV; /* -ENOMEM better?! */
		goto fail2;
	}

	ret = request_irq(dev->pdev->irq, tbsmod_irq, IRQF_SHARED, KBUILD_MODNAME, (void *)dev);
	if (ret < 0)
	{
		printk(KERN_ERR "%s ERROR: IRQ registration failed <%d>\n", __func__, ret);
		ret = -ENODEV;
		goto fail2;
	}

	pci_set_drvdata(pdev, dev);


//	mutex_init(&dev->ioctl_mutex);
	for(index=0;index<sizeof(tbsmods);index++){
		if(tbsmods[index] ==0 ){
			tbsmods[index] = 1;
			break;
		}
	}

	dev->mod_index = index;
	tbsmodsdev[index] = dev;

	for(i=0;i<CHANNELS;i++){
		dev->channnel[i].dmavirt = pci_alloc_consistent(dev->pdev, DMASIZE, &dev->channnel[i].dmaphy);
		if (!dev->channnel[i].dmavirt)
		{
			printk(" allocate memory failed\n");
			goto fail3;
		}
		dev->channnel[i].channel_index=i;
		dev->channnel[i].dev = dev;

		dev->channnel[i].devno = MKDEV(MAJORDEV, (index*CHANNELS+i));

	
		device_create(mod_cdev_class, NULL, dev->channnel[i].devno, &dev->channnel[i], "tbsmod%d/mod%d",dev->mod_index,i);

		ret = kfifo_alloc(&dev->channnel[i].fifo, FIFOSIZE, GFP_KERNEL);
		if (ret != 0)
			goto fail3;
	}

	tbs_adapters_init(dev);

	dev->modulation =QAM_256;
	dev->srate=7200000;
	dev->frequency=474000000;

	return 0;

fail3:
	free_irq(dev->pdev->irq, dev);
	if (dev->mmio)
		iounmap(dev->mmio);
fail2:
	pci_disable_device(pdev);
fail1:
	pci_set_drvdata(pdev, NULL);
	kfree(dev);
fail0:
	return ret;
}

#define MAKE_ENTRY(__vend, __chip, __subven, __subdev, __configptr) \
	{                                                               \
		.vendor = (__vend),                                         \
		.device = (__chip),                                         \
		.subvendor = (__subven),                                    \
		.subdevice = (__subdev),                                    \
		.driver_data = (unsigned long)(__configptr)                 \
	}

static const struct pci_device_id tbsmod_id_table[] = {
	MAKE_ENTRY(0x544d, 0x6178, 0x6004, 0x0001, NULL),
	{}};
MODULE_DEVICE_TABLE(pci, tbsmod_id_table);

static struct pci_driver tbsmod_pci_driver = {
	.name = "tbsmod",
	.id_table = tbsmod_id_table,
	.probe = tbsmod_probe,
	.remove = tbsmod_remove,
};


static __init int module_init_tbsmod(void)
{
	int stat;
	int retval;
	dev_t dev = MKDEV(MAJORDEV, 0);

	printk("%s\n",__func__);

	if ((retval = register_chrdev_region(dev, 256, "tbsmod")) != 0) {
		printk("%s register_chrdev_region failed:%x\n",__func__, retval);
		return retval;
	}

	cdev_init(&mod_cdev, &tbsmod_fops);
	mod_cdev.owner = THIS_MODULE;
	cdev_add(&mod_cdev, dev, 256);

	mod_cdev_class = class_create(THIS_MODULE, "tbsmod");
	stat = pci_register_driver(&tbsmod_pci_driver);
	return stat;
}

static __exit void module_exit_tbsmod(void)
{
	int i=0;
	printk("%s\n",__func__);
	for(i=0;i<256;i++)
		device_destroy(mod_cdev_class, MKDEV(MAJORDEV, i));
	class_destroy(mod_cdev_class);
	cdev_del(&mod_cdev);
	unregister_chrdev_region(MKDEV(MAJORDEV, 0), 256);
	pci_unregister_driver(&tbsmod_pci_driver);
}

module_init(module_init_tbsmod);
module_exit(module_exit_tbsmod);

MODULE_DESCRIPTION("tbs PCIe Bridge");
MODULE_AUTHOR("kernelcoding");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0.0");
