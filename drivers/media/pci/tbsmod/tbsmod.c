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
#include "dvbmod.h"

#define TRUE 1
#define FALSE 0
#define BOOL bool
#define PIKOTV_MBKB_THRESHOLD 210 /* PikoTV */

static bool enable_msi = true;
module_param(enable_msi, bool, 0444);
MODULE_PARM_DESC(enable_msi, "use an msi interrupt if available");

static void spi_ad9789Enable(struct tbs_pcie_dev *dev, int Data)
{
	unsigned char tmpbuf[4];

	//write enable:
	tmpbuf[0] = Data;
	TBS_PCIE_WRITE(0, SPI_ENABLE, *(u32 *)&tmpbuf[0]);
}

static BOOL AD4351_CheckFree(struct tbs_pcie_dev *dev, int OpbyteNum)
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
static BOOL MAX2871CheckFree(struct tbs_pcie_dev *dev, int OpbyteNum)
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
		*(u32 *)tmpbuf = TBS_PCIE_READ(0, SPI_MAX2871);
		msleep(1);
	}
	if (tmpbuf[0] == 1)
		return TRUE;
	else
	{
		printk(("----------MAX2871CheckFree error, time out! \n"));
		return FALSE;
	}
}


static BOOL ad9789_CheckFree(struct tbs_pcie_dev *dev, int OpbyteNum)
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

static BOOL ad9789_wt_nBytes(struct tbs_pcie_dev *dev, int length, int Reg_Addr, unsigned char *Wr_buf)
{
	unsigned char i = 0, tmpdt = 0, tmpbuf[8];
	mutex_lock(&dev->spi_mutex);

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
		mutex_unlock(&dev->spi_mutex);
		printk((" ad9789_wt_nBytes error!	\n"));
		return FALSE;
	}
	
	mutex_unlock(&dev->spi_mutex);
	return TRUE;
}

static BOOL ad9789_rd_nBytes(struct tbs_pcie_dev *dev, int length, int Reg_Addr, unsigned char *Rd_buf)
{
	unsigned char tmpdt = 0, tmpbuf[4];
	mutex_lock(&dev->spi_mutex);

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
		mutex_unlock(&dev->spi_mutex);
		return FALSE;
	}

	*(u32 *)Rd_buf = TBS_PCIE_READ(0, SPI_RD_DATA);

	msleep(1);

	mutex_unlock(&dev->spi_mutex);
	return TRUE;
}

static BOOL ad4351_wt_nBytes(struct tbs_pcie_dev *dev, unsigned char *WR_buf, int length)
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

static BOOL MAX2871WritenBytes(struct tbs_pcie_dev *dev, unsigned char *WR_buf, int length)
{
	unsigned char tmpbuf[4] = { 0 }, i;

	for (i = 0; i < length; i++)
		tmpbuf[i] = WR_buf[i];

	TBS_PCIE_WRITE(0, (0+SPI_MAX2871), *(u32 *)&tmpbuf[0]);

	if (MAX2871CheckFree(dev, 4) == 0)
	{
		printk((" Ad4351CheckFree error!   \n"));
		return FALSE;
	}
	return TRUE;
}


static BOOL GS2972_CheckFree(struct tbs_pcie_dev *dev, int OpbyteNum)
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
		*(u32 *)tmpbuf = TBS_PCIE_READ(MOD_ASI_BASEADDRESS, ASI_SPI_STATUS);
		msleep(1);
	}
	if (tmpbuf[0] == 1)
		return TRUE;
	else
	{
		printk(("----------GS2972_CheckFree error, time out! \n"));
		return FALSE;
	}
}

static BOOL GS2972_wt_nBytes(struct tbs_pcie_dev *dev, int length, int Reg_Addr, unsigned char *Wr_buf)
{
	unsigned char i = 0, tmpdt = 0, tmpbuf[8];
	mutex_lock(&dev->spi_mutex);

	if (length == 3)
		tmpdt = 0x40;
	else if (length == 2)
		tmpdt = 0x20;
	else if (length == 1)
		tmpdt = 0x00;
	else
		printk((" GS2972_wt_nBytes error length !\n"));

	//Reg_Addr 12bit;
	tmpbuf[0] = ((Reg_Addr >> 8) & 0xf);
	tmpbuf[1] = (Reg_Addr & 0xff);
	tmpbuf[0] += 0x10; // autoinc set to 1
	tmpbuf[0] += tmpdt; //3'b0xx; write;

	for (i = 0; i < length; i++)
		tmpbuf[2 + i] = Wr_buf[i];

	TBS_PCIE_WRITE(MOD_ASI_BASEADDRESS, ASI_SPI_COMMAND, *(u32 *)&tmpbuf[0]);
	TBS_PCIE_WRITE(MOD_ASI_BASEADDRESS, ASI_SPI_WT_DATA, *(u32 *)&tmpbuf[4]);

	tmpbuf[0] = 0xe0; //cs low,cs high, write, no read;
	tmpbuf[1] = 0;
	tmpbuf[1] += (length + 2) * 16; // regadd + length
	TBS_PCIE_WRITE(MOD_ASI_BASEADDRESS, ASI_SPI_CONFIG, *(u32 *)&tmpbuf[0]);

	if (GS2972_CheckFree(dev, 4) == 0)
	{
		mutex_unlock(&dev->spi_mutex);
		printk((" GS2972_wt_nBytes error!	\n"));
		return FALSE;
	}
	mutex_unlock(&dev->spi_mutex);
	return TRUE;
}

static BOOL GS2972_rd_nBytes(struct tbs_pcie_dev *dev, int length, int Reg_Addr, unsigned char *Rd_buf)
{
	unsigned char tmpdt = 0, tmpbuf[4];
	mutex_lock(&dev->spi_mutex);

	if (length == 3)
		tmpdt = 0xc0;
	else if (length == 2)
		tmpdt = 0xa0;
	else if (length == 1)
		tmpdt = 0x80;
	else
		printk((" GS2972_rd_nBytes error length!\n"));

	//Reg_Addr 12bit;
	tmpbuf[0] = ((Reg_Addr >> 8) & 0xf);
	tmpbuf[1] = (Reg_Addr & 0xff);
	tmpbuf[0] += 0x10; // autoinc set to 1
	tmpbuf[0] += tmpdt; //3'b1xx; read;

	TBS_PCIE_WRITE(MOD_ASI_BASEADDRESS, ASI_SPI_COMMAND, *(u32 *)&tmpbuf[0]);

	tmpbuf[0] = 0xf0;	//cs low,cs high, write, read;
	tmpbuf[1] = 0x20;	// 2 bytes command for writing;
	tmpbuf[1] += length; //read n bytes data;
	TBS_PCIE_WRITE(MOD_ASI_BASEADDRESS, ASI_SPI_CONFIG, *(u32 *)&tmpbuf[0]);

	if (GS2972_CheckFree(dev, 4) == 0)
	{
		mutex_unlock(&dev->spi_mutex);
		printk((" GS2972_rd_nBytes error!   \n"));
		return FALSE;
	}

	*(u32 *)Rd_buf = TBS_PCIE_READ(MOD_ASI_BASEADDRESS, ASI_SPI_RD_DATA);

	msleep(1);

	mutex_unlock(&dev->spi_mutex);
	return TRUE;
}

//qam 0~4  to qam16~256
static void config_QAM(struct tbs_pcie_dev *dev, int qam)
{

	unsigned char buf[4] = {0};
	printk("set qam: %d\n", qam);

	buf[0] = 0x22 + qam;
	ad9789_wt_nBytes(dev, 1, AD9789_QAM_CONFIG, buf);

	//0:DVB-C 16
	//1:DVB-C 32
	//2:DVB-C 64
	//3:DVB-C 128
	//4:DVB-C 256
	buf[0] = qam;
	TBS_PCIE_WRITE(0, AD9789_MODULATION, *(u32 *)&buf[0]);
	TBS_PCIE_WRITE(0, AD9789B_MODULATION, *(u32 *)&buf[0]);
	
}

static void reset_ipcore_mod(struct tbs_pcie_dev *dev)
{

	unsigned char buf[4] = {0};
	buf[0] = 1;
	TBS_PCIE_WRITE(0, MOD_RESET_IPCORE, *(u32 *)&buf[0]);

	msleep(200);
	buf[0] = 0;
	TBS_PCIE_WRITE(0, MOD_RESET_IPCORE, *(u32 *)&buf[0]);

}
// from 0--15, 11,13,15 are reserved 
static void config_qamb_ctl(struct tbs_pcie_dev *dev, int control)
{
	unsigned char buf[4] = {0};

	*(u32 *)buf = TBS_PCIE_READ(0,SPI_RESET);
	buf[1] = control;	
	TBS_PCIE_WRITE(0, AD9789_MODULATION, *(u32 *)&buf[0]);

}

//srate Ks
static void config_srate(struct tbs_pcie_dev *dev, unsigned long srate)
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


}

static void config_srate_qamb(struct tbs_pcie_dev *dev, unsigned long srate)
{
	unsigned char buff[4] = {0};
	//srate = (2160 * 1000 *16384) /srate;
	srate = srate / 1000;
	printk("set symbolrate: %ld\n", srate);
	srate = div_u64(35389440000ULL, srate);

	buff[2] = srate & 0xff;
	buff[1] = (srate >> 8) & 0xff;
	buff[0] = (srate >> 16) & 0xff;

	ad9789_wt_nBytes(dev, 3, AD9789_RATE_CONVERT_P, buff);

	//update
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff);


}

//qam ( 0:64qam  1:qam256 )
static void config_qamb(struct tbs_pcie_dev *dev, int qam)
{

	unsigned char buf[4] = {0};
	printk("set qam: %d\n", qam);
	if(qam == QAM_64)
		buf[0] = 0x10;
	else if(qam == QAM_256)
		buf[0] = 0x01;
	else
	{
		printk("set error qam to qamb: %d\n",qam);
		return;
	}	
	ad9789_wt_nBytes(dev, 1, AD9789_QAM_CONFIG, buf);

	*(u32 *)buf = TBS_PCIE_READ(0,SPI_RESET);

	if(qam == QAM_64)
		buf[0] = 0;
	else
		buf[0] = 1;
		
	TBS_PCIE_WRITE(0, AD9789_MODULATION, *(u32 *)&buf[0]);

	buf[2] = 0x00;
	buf[1] = 0x00;
	buf[0] = 0x80;
	ad9789_wt_nBytes(dev,3,AD9789_RATE_CONVERT_Q,buf);
	//config srate  
	//5056
	if(qam == QAM_64)
	{
		config_srate_qamb(dev, 5056000);

	}
	else // 5360
	{
		config_srate_qamb(dev, 5360000);
	
	}

	//update
	buf[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buf);
	buf[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buf);

	buf[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buf); 
	buf[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buf); 
	
}

//  gain: 5--120
static void config_gain(struct tbs_pcie_dev *dev, int gain)
{

	unsigned char buff[4] = {0};

	buff[0] = gain;
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_0_GAIN, buff);
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_1_GAIN, buff);
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_2_GAIN, buff);
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_3_GAIN, buff);


}

static BOOL ad9789_setFre_qamb(struct tbs_pcie_dev *dev, unsigned long freq)
{
	unsigned long freq_0, freq_1, freq_2, freq_3;
	unsigned char buff[4] = {0};
	//config center freq
	unsigned long fcenter;

	freq = freq / 1000000;
	printk("set freq: %ld\n", freq);
	//freq_0 = (16777216 * freq)/96;
	freq_0 = div_u64(16777216ULL * freq, 135);
	buff[2] = freq_0 & 0xff;
	buff[1] = (freq_0 >> 8) & 0xff;
	buff[0] = (freq_0 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_0_FRE, buff);

	//freq_1 = (16777216 * (freq+8))/96;
	freq_1 = div_u64(16777216ULL * (freq + 6), 135);
	buff[2] = freq_1 & 0xff;
	buff[1] = (freq_1 >> 8) & 0xff;
	buff[0] = (freq_1 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_1_FRE, buff);

	//freq_2 = (16777216 * (freq+16))/96;
	freq_2 = div_u64(16777216ULL * (freq + 12), 135);
	buff[2] = freq_2 & 0xff;
	buff[1] = (freq_2 >> 8) & 0xff;
	buff[0] = (freq_2 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_2_FRE, buff);

	//freq_3 = (16777216 * (freq+24))/96;
	freq_3 = div_u64(16777216ULL * (freq + 18), 135);
	buff[2] = freq_3 & 0xff;
	buff[1] = (freq_3 >> 8) & 0xff;
	buff[0] = (freq_3 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_3_FRE, buff);

	fcenter = freq + 9;
	//fcenter = (fcenter*65536)/1536;
	fcenter = div_u64(fcenter * 65536ULL, 2160);
	buff[1] = fcenter & 0xff;
	buff[0] = (fcenter >> 8) & 0xff; 
	ad9789_wt_nBytes(dev, 2, AD9789_CENTER_FRE_BPF, buff);


	//update
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff);

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

	return TRUE;
}
// freq MHZ
static BOOL ad9789_setFre_dvbc(struct tbs_pcie_dev *dev, unsigned long freq, unsigned long bw)
{
	unsigned long freq_0, freq_1, freq_2, freq_3;
	unsigned char buff[4] = {0};
	//config center freq
	unsigned long fcenter;

	freq = freq / 1000000;
	printk("set freq: %ld, bw: %d\n", freq, bw);
	//freq_0 = (16777216 * freq)/150;
	freq_0 = div_u64(16777216ULL * freq, 150);
	buff[2] = freq_0 & 0xff;
	buff[1] = (freq_0 >> 8) & 0xff;
	buff[0] = (freq_0 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_0_FRE, buff);

	//freq_1 = (16777216 * (freq+8))/150;
	freq_1 = div_u64(16777216ULL * (freq + bw), 150);
	buff[2] = freq_1 & 0xff;
	buff[1] = (freq_1 >> 8) & 0xff;
	buff[0] = (freq_1 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_1_FRE, buff);

	//freq_2 = (16777216 * (freq+16))/150;
	freq_2 = div_u64(16777216ULL * (freq + bw*2), 150);
	buff[2] = freq_2 & 0xff;
	buff[1] = (freq_2 >> 8) & 0xff;
	buff[0] = (freq_2 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_2_FRE, buff);

	//freq_3 = (16777216 * (freq+24))/150;
	freq_3 = div_u64(16777216ULL * (freq + bw*3), 150);
	buff[2] = freq_3 & 0xff;
	buff[1] = (freq_3 >> 8) & 0xff;
	buff[0] = (freq_3 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_3_FRE, buff);

	//fcenter = freq + 12;
	//fcenter = (fcenter*65536)/2400;
	fcenter = div_u64(freq * 65536ULL + (65536ULL*bw*3)/2, 2400);
	buff[1] = fcenter & 0xff;
	buff[0] = (fcenter >> 8) & 0xff; 
	ad9789_wt_nBytes(dev, 2, AD9789_CENTER_FRE_BPF, buff); 

	//update
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff);

	return TRUE;
}
/*
// freq MHZ
static BOOL ad9789_setFre_dvbc(struct tbs_pcie_dev *dev, unsigned long freq)
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

	return TRUE;
}
*/


static void AD9789_Configration_dvbc(struct tbs_pcie_dev *dev)
{
	int i = 0;
	unsigned char buff[4] = {0};

	buff[0] = 0x9E;
	ad9789_wt_nBytes(dev, 1, AD9789_CLOCK_RECIVER_2, buff); //CLK_DIS=1;PSIGN=0;CLKP_CML=0x0F;NSIGN=0

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_CONTROL_DUTY_CYCLE, buff);

	buff[0] = 0xCE;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_1, buff); //SEARCH_TOL=1;SEARCH_ERR=1;TRACK_ERR=0;GUARDBAND=0x0E
	buff[0] = 0x42;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff); //MU_CLKDIS=0;SLOPE=1;MODE=0x00;MUSAMP=0;GAIN=0x01;MU_EN=1;
	buff[0] = 0x4E;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_3, buff); //MUDLY=0x00;SEARCH_DIR=0x10;MUPHZ=0x0E;
	buff[0] = 0x6C;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_4, buff); //MUDLY=0x9F;

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 

	buff[0] = 0xFE;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_STATUS, buff); 

	buff[0] = 0x0C;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 

	buff[0] = 0x43;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff); //MU_CLKDIS=0;SLOPE=1;MODE=0x00;MUSAMP=0;GAIN=0x01;MU_EN=1;

	buff[0] = 0x01;
	ad9789_wt_nBytes(dev, 1, AD9789_BYPASS, buff); 

	//0:DVB-C 16
	//1:DVB-C 32
	//2:DVB-C 64
	//3:DVB-C 128
	//4:DVB-C 256

	config_QAM(dev, dev->modulation-1);
	
	buff[0] = 0x14;
	ad9789_wt_nBytes(dev, 1, AD9789_SUM_SCALAR, buff); 

	buff[0] = 0x20;
	ad9789_wt_nBytes(dev, 1, AD9789_INPUT_SCALAR, buff);
	
	ad9789_setFre_dvbc(dev,dev->frequency,dev->bw);
	config_srate(dev,dev->srate);

	buff[0] = 0x06;
	ad9789_wt_nBytes(dev, 1, AD9789_INTERFACE_CONFIG, buff); 

	buff[0] = 0x61;
	ad9789_wt_nBytes(dev, 1, AD9789_DATA_CONTROL, buff); 

	buff[0] = 0x10;
	ad9789_wt_nBytes(dev, 1, AD9789_DCO_FRE, buff); 

	buff[0] = 0x62;
	ad9789_wt_nBytes(dev, 1, AD9789_INTERNAL_COLCK_ADJUST, buff); 

	config_gain(dev, 60);

	buff[0] = 0;
	ad9789_wt_nBytes(dev, 1, AD9789_SPEC_SHAPING, buff); 

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_FULL_SCALE_CURRENT_1, buff); 

	buff[0] = 0x02;
	ad9789_wt_nBytes(dev, 1, AD9789_FULL_SCALE_CURRENT_2, buff); 

	for (i = 0; i < 100; i++){
		ad9789_rd_nBytes(dev, 1, AD9789_INT_STATUS, buff);
		if (buff[0] == 0x08)
			break;
		msleep(10);
	}

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff); 

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	for (i = 0; i < 100; i++) {
		ad9789_rd_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff);
		if (buff[0] == 0x80)
			break;
		msleep(10);
	}
	if (buff[0] != 0x80)
			dev_err(&dev->pdev->dev, "error updating parameters");
	
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

    buff[0] = 0x0; // disable default four channels
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff); 

	buff[0] = 0x0E;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 

	return;
}

static void AD9789_Configration_qamb(struct tbs_pcie_dev *dev)
{
	int i = 0;
	unsigned char buff[4] = {0};

	buff[0] = 0x9E;
	ad9789_wt_nBytes(dev, 1, AD9789_CLOCK_RECIVER_2, buff); //CLK_DIS=1;PSIGN=0;CLKP_CML=0x0F;NSIGN=0

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_CONTROL_DUTY_CYCLE, buff);

	buff[0] = 0xCE;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_1, buff); //SEARCH_TOL=1;SEARCH_ERR=1;TRACK_ERR=0;GUARDBAND=0x0E
	buff[0] = 0x42;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff); //MU_CLKDIS=0;SLOPE=1;MODE=0x00;MUSAMP=0;GAIN=0x01;MU_EN=1;
	buff[0] = 0x4E;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_3, buff); //MUDLY=0x00;SEARCH_DIR=0x10;MUPHZ=0x0E;
	buff[0] = 0x6C;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_4, buff); //MUDLY=0x9F;

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 

	buff[0] = 0xFE;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_STATUS, buff); 

	buff[0] = 0x0C;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 

	buff[0] = 0x43;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff); //MU_CLKDIS=0;SLOPE=1;MODE=0x00;MUSAMP=0;GAIN=0x01;MU_EN=1;

	buff[0] = 0x01;
	ad9789_wt_nBytes(dev, 1, AD9789_BYPASS, buff); 

	//0:DVB-C 64
	//1:DVB-C 256
	config_qamb(dev,dev->modulation);
	config_qamb_ctl(dev,0);

	buff[0] = 0x60;
	ad9789_wt_nBytes(dev, 1, AD9789_DATA_CONTROL, buff); 
	buff[0] = 0x39;
	ad9789_wt_nBytes(dev, 1, AD9789_INTERNAL_COLCK_ADJUST, buff); 

	buff[0] = 0x14;
	ad9789_wt_nBytes(dev, 1, AD9789_SUM_SCALAR, buff); 
	buff[0] = 0x20;
	ad9789_wt_nBytes(dev, 1, AD9789_INPUT_SCALAR, buff);
	
	ad9789_setFre_qamb(dev,dev->frequency);
	
	buff[0] = 0x06;
	ad9789_wt_nBytes(dev, 1, AD9789_INTERFACE_CONFIG, buff); 

	//buff[0] = 0x61;
	//ad9789_wt_nBytes(dev, 1, AD9789_DATA_CONTROL, buff); 

	buff[0] = 0x10;
	ad9789_wt_nBytes(dev, 1, AD9789_DCO_FRE, buff); 

	//buff[0] = 0x62;
	//ad9789_wt_nBytes(dev, 1, AD9789_INTERNAL_COLCK_ADJUST, buff); 

	config_gain(dev, 60);

	buff[0] = 0;
	ad9789_wt_nBytes(dev, 1, AD9789_SPEC_SHAPING, buff); 

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_FULL_SCALE_CURRENT_1, buff); 

	buff[0] = 0x02;
	ad9789_wt_nBytes(dev, 1, AD9789_FULL_SCALE_CURRENT_2, buff); 

	for (i = 0; i < 100; i++){
		ad9789_rd_nBytes(dev, 1, AD9789_INT_STATUS, buff);
		if (buff[0] == 0x08)
			break;
		msleep(10);
	}
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff); 

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff); 

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

	buff[0] = 0x00; // disable default four channels
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff); 

	buff[0] = 0x0E;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 


	return;
}

static BOOL MAX2871ConfigrationDvbc(struct tbs_pcie_dev *dev)
{
	unsigned char ret;
	unsigned char buff[4] = { 0 };
	//regester from 5 --0
	buff[3] = 0x05;
	buff[2] = 0x00;
	buff[1] = 0x40;
	buff[0] = 0x00;
	
	msleep(20);

	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	//buff[3] = 0xdc;//0x3C;
	//buff[2] = 0x80;//0x80;
	buff[3] = 0x3C;
	buff[2] = 0x80;
	buff[1] = 0x9e;
	buff[0] = 0x63;
	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}

	buff[3] = 0x23;
	buff[2] = 0x1f;
	buff[1] = 0x00;
	buff[0] = 0x00;
	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0x42;
	buff[2] = 0x5f;
	buff[1] = 0x00;
	buff[0] = 0x80;

	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0xe9;
	buff[2] = 0x03;
	buff[1] = 0x01;
	buff[0] = 0x40;
	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}

	//2304clk
	buff[3] = 0xa0;
	buff[2] = 0x00;
	buff[1] = 0x2e;
	buff[0] = 0x00;
	
	/*buff[3] = 0xB8;
	buff[2] = 0x81;
	buff[1] = 0x1e;
	buff[0] = 0x00;*/
	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}

	//the second regester from 5 --0
	buff[3] = 0x05;
	buff[2] = 0x00;
	buff[1] = 0x40;
	buff[0] = 0x00;
	
	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}

	//buff[3] = 0xdc;//0x3C;
	//buff[2] = 0x80;//0x80;
	buff[3] = 0x3C;
	buff[2] = 0x80;
	buff[1] = 0x9e;
	buff[0] = 0x63;
	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}

	buff[3] = 0x23;
	buff[2] = 0x1f;
	buff[1] = 0x00;
	buff[0] = 0x00;
	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0x42;
	buff[2] = 0x5f;
	buff[1] = 0x00;
	buff[0] = 0x80;

	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0xe9;
	buff[2] = 0x03;
	buff[1] = 0x01;
	buff[0] = 0x40;
	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	
	//2304clk
	buff[3] = 0xa0;
	buff[2] = 0x00;
	buff[1] = 0x2e;
	buff[0] = 0x00;
	/*
	buff[3] = 0xB8;
	buff[2] = 0x81;
	buff[1] = 0x1e;
	buff[0] = 0x00;*/

	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}

	
//enable rfa_en register 4

	buff[3] = 0xfc; //0xfc
	buff[2] = 0x80;//0x80;
	buff[1] = 0x9e;
	buff[0] = 0x63;
	ret = MAX2871WritenBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	
	return TRUE;
}

//1536
static BOOL AD4351_Configration_qamb(struct tbs_pcie_dev *dev)
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
	buff[1] = 0x9C;
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
	buff[3] = 0xC9;
	buff[2] = 0x80;
	buff[1] = 0x00;
	buff[0] = 0x08;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0xB0;
	buff[2] = 0x00;
	buff[1] = 0x3D;
	buff[0] = 0x00;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}

//2400
static BOOL AD4351_Configration_dvbc(struct tbs_pcie_dev *dev)
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
	buff[3] = 0xfc;//0x3c
	buff[2] = 0x81;//0x80
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
//2160
static BOOL AD4351_Configration_2160(struct tbs_pcie_dev *dev)
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
	buff[3] = 0x3c;
	buff[2] = 0x80;
	buff[1] = 0x9C;
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
	buff[3] = 0x29;
	buff[2] = 0x80;
	buff[1] = 0x00;
	buff[0] = 0x08;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0x20;
	buff[2] = 0x00;
	buff[1] = 0x56;
	buff[0] = 0x00;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}
static BOOL AD4351_Configration_dvbt(struct tbs_pcie_dev *dev)
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
	if(dev->bw == 8)
	{
		buff[3] = 0x3C;
		buff[2] = 0x80;
		buff[1] = 0x8C;
		buff[0] = 0x00;
	}
	else if(dev->bw == 7)
	{
		buff[3] = 0x3C;
		buff[2] = 0x80;
		buff[1] = 0x9C;
		buff[0] = 0x00;
	}
	else if(dev->bw == 6)
	{
		buff[3] = 0x3C;
		buff[2] = 0x40;
		buff[1] = 0x90;
		buff[0] = 0x00;
	}
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
	if(dev->bw == 8)
	{
		buff[3] = 0x42; 
		buff[2] = 0xCE; 
		buff[1] = 0x01; 
		buff[0] = 0x03;
	}
	else if(dev->bw == 7)
	{
		buff[3] = 0x42; 
		buff[2] = 0x4E; 
		buff[1] = 0x00; 
		buff[0] = 0x00;
	}
	else if(dev->bw == 6)
	{
		buff[3] = 0x42; 
		buff[2] = 0xCE; 
		buff[1] = 0x0D; 
		buff[0] = 0x00;
	}

	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	if(dev->bw == 8 ||dev->bw == 7)
	{
		buff[3] = 0xC9; 
		buff[2] = 0x80; 
		buff[1] = 0x00; 
		buff[0] = 0x08;
	}
	else if(dev->bw == 6)
	{
		buff[3] = 0x19; 
		buff[2] = 0x01; 
		buff[1] = 0x00; 
		buff[0] = 0x08;
	}

	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	if(dev->bw == 8)
	{
		buff[3] = 0x48; 
		buff[2] = 0x80; 
		buff[1] = 0x47; 
		buff[0] = 0x01;
	}
	else if(dev->bw == 7)
	{
		buff[3] = 0xA8; 
		buff[2] = 0x80; 
		buff[1] = 0x51; 
		buff[0] = 0x00;
	}
	else if(dev->bw == 6)
	{
		buff[3] = 0xF8; 
		buff[2] = 0x80; 
		buff[1] = 0x15; 
		buff[0] = 0x0F;
	}

	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}

	//set bw light
	buff[3] = 0x01; 
	buff[2] = 0x00; 
	buff[1] = 0x00; 
	buff[0] = 0x00;
	if(dev->bw == 6)
		buff[2] = 0x01;
	else if(dev->bw == 7)
		buff[1] = 0x01;
	else
		buff[0] = 0x01;
	TBS_PCIE_WRITE(0, SPI_BW_LIGHT, *(u32 *)&buff[0]);

	return TRUE;
}

static BOOL AD4351_Configration_isdbt(struct tbs_pcie_dev *dev)
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
	buff[3] = 0x3c;
	buff[2] = 0x80;
	buff[1] = 0x9C;
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
	buff[3] = 0x29;
	buff[2] = 0x80;
	buff[1] = 0x00;
	buff[0] = 0x08;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0x20;
	buff[2] = 0x00;
	buff[1] = 0x56;
	buff[0] = 0x00;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}

static BOOL AD4351_Configration_atsc(struct tbs_pcie_dev *dev)
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
	buff[3] = 0x3c;
	buff[2] = 0x80;
	buff[1] = 0x9C;
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
	buff[3] = 0xC9;
	buff[2] = 0x80;
	buff[1] = 0x00;
	buff[0] = 0x08;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	buff[3] = 0x20;
	buff[2] = 0x00;
	buff[1] = 0x52;
	buff[0] = 0x00;
	ret = ad4351_wt_nBytes(dev, buff, 4);
	if (ret == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}
//0:qpsk, 1: 16qam, 2: 64qam . interval : 1/32(0),1/16(1),1/8(2), 1/4(3)
//sub_carriers 0:2k, 1:8K. fec : 1/2(0),2/3(1),3/4(2),5/6(3),7/8(4)
static void config_Mod_dvbt(struct tbs_pcie_dev *dev, int qam,int carriers,int fec, int interval)
{
	unsigned char buf[4] = {0};
	//printk("set qam: %d carriers: %d,fec:%d,interval:%d\n", qam,carriers,fec,interval);
	buf[0] = 0x22;
	ad9789_wt_nBytes(dev, 1, AD9789_QAM_CONFIG, buf);
	//0:dvbt qpsk
	//1:dvbt 16qam
	//2:dvbt 64qam
	buf[0] = qam;
	buf[0]|= carriers <<2; //set sub_carriers
	buf[0]|= fec <<4; //set fec
	
	buf[1] = interval; //set g_interval
	TBS_PCIE_WRITE(0, AD9789_MODULATION, *(u32 *)&buf[0]);
	
}

static void set_Modulation_dvbt(struct tbs_pcie_dev *dev, struct dvb_modulator_parameters *params)
{
	
	int qam,carriers,fec,interval;
	switch(params->constellation)
	{
		case QPSK:
			qam = 0;
			break;
		case QAM_16:
			qam = 1;
			break;
		case QAM_64:
			qam = 2;
			break;
		default:
			qam = 2;
			break;	
	}
	switch(params->transmission_mode)
	{
		case TRANSMISSION_MODE_2K:
			carriers = 0;
			break;
		case TRANSMISSION_MODE_8K:
			carriers = 1;
			break;
		default:
			carriers = 1;
			break;	
	}
	switch (params->guard_interval)
	{
		case GUARD_INTERVAL_1_4:
			interval = 3;
			break;
		case GUARD_INTERVAL_1_8:
			interval = 2;			
			break;
		case GUARD_INTERVAL_1_16:
			interval = 1;			
			break;
		case GUARD_INTERVAL_1_32:
			interval = 0;
			break;

		default:
			interval = 0;
			break;
	}
	switch (params->code_rate_HP)
	{
		case FEC_1_2:
		    	fec = 0;
		   	break;
		case FEC_2_3:
		    	fec = 1;
		    	break;
		case FEC_3_4:
		    	fec = 2;
		   	 break;
		case FEC_5_6:
		    	fec = 3;
		    	break;
		case FEC_7_8:
		    	fec = 4;
		    	break;
		default:
		    	fec = 4;
		    	break;
        }
	config_Mod_dvbt(dev,qam,carriers,fec,interval);

}

//bandwidth:Mhz,  freq: HZ
static BOOL ad9789_setFre_dvbt (struct tbs_pcie_dev *dev, unsigned long bandwidth, unsigned long freq)
{
	unsigned long freq_0, freq_1, freq_2, freq_3;
	unsigned long fdco;
	unsigned char buff[4] = {0};
	//config center freq
	unsigned long fcenter;
	int i;

	if(bandwidth ==8)
		fdco = 146285714; //146.285714;
	else if(bandwidth ==7)
		fdco = 128000000;
	else
		fdco = 109714285; //109.714285;

	//printk("set freq: %ld\n", freq);
	//freq_0 = (16777216 * freq)/150;
	freq_0 = div_u64(16777216ULL * freq, fdco);
	buff[2] = freq_0 & 0xff;
	buff[1] = (freq_0 >> 8) & 0xff;
	buff[0] = (freq_0 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_0_FRE, buff);

	//freq_1 = (16777216 * (freq+8))/150;
	freq_1 = div_u64(16777216ULL * (freq + bandwidth *1000000), fdco);
	buff[2] = freq_1 & 0xff;
	buff[1] = (freq_1 >> 8) & 0xff;
	buff[0] = (freq_1 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_1_FRE, buff);

	//freq_2 = (16777216 * (freq+16))/150;
	freq_2 = div_u64(16777216ULL * (freq + bandwidth *2000000), fdco);
	buff[2] = freq_2 & 0xff;
	buff[1] = (freq_2 >> 8) & 0xff;
	buff[0] = (freq_2 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_2_FRE, buff);

	//freq_3 = (16777216 * (freq+24))/150;
	freq_3 = div_u64(16777216ULL * (freq + bandwidth *3000000), fdco);
	buff[2] = freq_3 & 0xff;
	buff[1] = (freq_3 >> 8) & 0xff;
	buff[0] = (freq_3 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_3_FRE, buff);

	buff[2] = 0;
	buff[1] = 0;
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 3, AD9789_RATE_CONVERT_Q, buff);

	buff[2] = 0;
	buff[1] = 0;
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 3, AD9789_RATE_CONVERT_P, buff);

	fcenter = freq + (bandwidth * 3 *1000000)/2;
	//fcenter = (fcenter*65536)/2400;
	fcenter = div_u64(fcenter * 65536ULL, 16 * fdco);
	buff[1] = fcenter & 0xff;
	buff[0] = (fcenter >> 8) & 0xff; 
	ad9789_wt_nBytes(dev, 2, AD9789_CENTER_FRE_BPF, buff); 

	if(bandwidth ==8)
		buff[0] = 0x7F;
	else
		buff[0] = 0x7E;
	//default 8M, else 0x7E
	ad9789_wt_nBytes(dev, 1, AD9789_DATA_CONTROL, buff); 

	if(bandwidth ==8)
		buff[0] = 0x52;
	else if(bandwidth ==7)
		buff[0] = 0xF7;
	else
		buff[0] = 0xA4;
 	//default 8M, else 7M:0xF7, 6M: 0xA4
	ad9789_wt_nBytes(dev, 1, AD9789_INTERNAL_COLCK_ADJUST, buff); 

	//update
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff);

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	for (i = 0; i < 100; i++) {
		ad9789_rd_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff);
		if (buff[0] == 0x80)
			break;
		msleep(10);
	}
	if (buff[0] != 0x80)
			dev_err(&dev->pdev->dev, "error updating parameters");
	
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

	return TRUE;
}
static void AD9789_Configration_dvbt(struct tbs_pcie_dev *dev)

{
	int i = 0;
	unsigned char buff[4] = {0};

	buff[0] = 0x9E;
	ad9789_wt_nBytes(dev, 1, AD9789_CLOCK_RECIVER_2, buff); //CLK_DIS=1;PSIGN=0;CLKP_CML=0x0F;NSIGN=0

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_CONTROL_DUTY_CYCLE, buff);

	buff[0] = 0xCE;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_1, buff); //SEARCH_TOL=1;SEARCH_ERR=1;TRACK_ERR=0;GUARDBAND=0x0E
	buff[0] = 0x42;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff); //MU_CLKDIS=0;SLOPE=1;MODE=0x00;MUSAMP=0;GAIN=0x01;MU_EN=1;
	buff[0] = 0x4E;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_3, buff); //MUDLY=0x00;SEARCH_DIR=0x10;MUPHZ=0x0E;
	buff[0] = 0x6C;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_4, buff); //MUDLY=0x9F;

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 

	buff[0] = 0xFE;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_STATUS, buff); 

	buff[0] = 0x0E;
	ad9789_wt_nBytes(dev, 1, AD9789_INT_ENABLE, buff); 

	buff[0] = 0x43;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff); //MU_CLKDIS=0;SLOPE=1;MODE=0x00;MUSAMP=0;GAIN=0x01;MU_EN=1;
	//buff[0] = 0x4B;   need to check here
	//ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff); //MU_CLKDIS=0;SLOPE=1;MODE=0x00;MUSAMP=0;GAIN=0x01;MU_EN=1;
	//buff[0] = 0x43;
	//ad9789_wt_nBytes(dev, 1, AD9789_Mu_DELAY_CONTROL_2, buff); //MU_CLKDIS=0;SLOPE=1;MODE=0x00;MUSAMP=0;GAIN=0x01;MU_EN=1;

	buff[0] = 0xD0;
	ad9789_wt_nBytes(dev, 1, AD9789_BYPASS, buff); 

	//set qam,fec,interval,sub_carriers
	config_Mod_dvbt(dev, 2,1,2,3);
	
	buff[0] = 0x1A;
	ad9789_wt_nBytes(dev, 1, AD9789_SUM_SCALAR, buff); 

	buff[0] = 0x32;
	ad9789_wt_nBytes(dev, 1, AD9789_INPUT_SCALAR, buff);
	
	//set freq
	ad9789_setFre_dvbt(dev, 8,474000000);

	buff[0] = 0x06;
	ad9789_wt_nBytes(dev, 1, AD9789_INTERFACE_CONFIG, buff); 

	buff[0] = 0x7F;//default 8M, else 0x7E
	ad9789_wt_nBytes(dev, 1, AD9789_DATA_CONTROL, buff); 

	buff[0] = 0x1F;
	ad9789_wt_nBytes(dev, 1, AD9789_DCO_FRE, buff); 

	buff[0] = 0x52; //default 8M, else 7M:0xF7, 6M: 0xA4
	ad9789_wt_nBytes(dev, 1, AD9789_INTERNAL_COLCK_ADJUST, buff); 

	config_gain(dev, 60);

	buff[0] = 0;
	ad9789_wt_nBytes(dev, 1, AD9789_SPEC_SHAPING, buff); 

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_FULL_SCALE_CURRENT_1, buff); 

	buff[0] = 0x02;
	ad9789_wt_nBytes(dev, 1, AD9789_FULL_SCALE_CURRENT_2, buff); 

	for (i = 0; i < 100; i++){
		ad9789_rd_nBytes(dev, 1, AD9789_INT_STATUS, buff);
		if (buff[0] == 0x08)
			break;
		msleep(10);
	}

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff); 

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	for (i = 0; i < 100; i++) {
		ad9789_rd_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff);
		if (buff[0] == 0x80)
			break;
		msleep(10);
	}
	if (buff[0] != 0x80)
			dev_err(&dev->pdev->dev, "error updating parameters");
	
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

	buff[0] = 0x00; // disable default four channels
	ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff); 

	return;
}

static void AD9789_Configration_isdbt_6m(struct tbs_pcie_dev *dev)
{
	int i = 0;
	unsigned char buff[8] = {0};
	//struct RF_Param * dvb_c = ptr;
	unsigned long freq_0 = 0,tmp = 0,fcenter = 0,p_srate = 0;
	unsigned long Freq = 0,Freq_0 = 0,Freq_1 = 0,Freq_2 = 0,Freq_3 = 0,Fcenter = 0,P_srate = 0;
	int qam =0;
	unsigned long srate = 0;
/***********************************************************************/
	//Software Reset
	buff[0] = 0x3C;
	ad9789_wt_nBytes(dev,1,AD9789_SPI_CTL,buff);
	
	//SPI Configuration
	buff[0] = 0x18;
	ad9789_wt_nBytes(dev,1,AD9789_SPI_CTL,buff);
	
	buff[0] = 0x9E;
	ad9789_wt_nBytes(dev,1,0x32,buff);

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,0x30,buff);


	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x24,buff);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,0x24,buff);

	buff[0] = 0xce;
	ad9789_wt_nBytes(dev,1,0x2f,buff);


	buff[0] = 0x42;
	ad9789_wt_nBytes(dev,1,0x33,buff);

	buff[0] = 0x4e;
	ad9789_wt_nBytes(dev,1,0x39,buff);

	buff[0] = 0x6c;
	ad9789_wt_nBytes(dev,1,0x3a,buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x03,buff);
	buff[0] = 0xfe;
	ad9789_wt_nBytes(dev,1,0x04,buff);
	buff[0] = 0x0c;
	ad9789_wt_nBytes(dev,1,0x03,buff);

	buff[0] = 0x43;
	ad9789_wt_nBytes(dev,1,0x33,buff);

	
	buff[0] = 0xc0;
	ad9789_wt_nBytes(dev,1,0x06,buff);


	buff[0] = 0x11;
	ad9789_wt_nBytes(dev,1,0x07,buff);

	buff[0] = 0x20;
	ad9789_wt_nBytes(dev,1,0x08,buff);

	buff[0] = 0x20;
	ad9789_wt_nBytes(dev,1,0x09,buff);


	buff[0] = 0x2a;
	ad9789_wt_nBytes(dev,1,0x0a,buff);

	buff[0] = 0xd8;
	ad9789_wt_nBytes(dev,1,0x0b,buff);


	buff[0] = 0x82;
	ad9789_wt_nBytes(dev,1,0x0c,buff);


	buff[0] = 0xe0;
	ad9789_wt_nBytes(dev,1,0x0d,buff);


	buff[0] = 0x38;
	ad9789_wt_nBytes(dev,1,0x0e,buff);


	buff[0] = 0x8e;
	ad9789_wt_nBytes(dev,1,0x0f,buff);

	buff[0] = 0x96;
	ad9789_wt_nBytes(dev,1,0x10,buff);

	buff[0] = 0x99;
	ad9789_wt_nBytes(dev,1,0x11,buff);

	buff[0] = 0x99;
	ad9789_wt_nBytes(dev,1,0x12,buff);
	buff[0] = 0x4c;
	ad9789_wt_nBytes(dev,1,0x13,buff);
	buff[0] = 0xf4;
	ad9789_wt_nBytes(dev,1,0x14,buff);
	buff[0] = 0xa4;
	ad9789_wt_nBytes(dev,1,0x15,buff);
	
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x16,buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x17,buff);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,0x18,buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x19,buff);
	buff[0] = 0x72;
	ad9789_wt_nBytes(dev,1,0x1a,buff);
	buff[0] = 0x42;
	ad9789_wt_nBytes(dev,1,0x1b,buff);
	buff[0] = 0x3e;
	ad9789_wt_nBytes(dev,1,0x1c,buff);
	buff[0] = 0x39;
	ad9789_wt_nBytes(dev,1,0x1d,buff);
	buff[0] = 0x04;
	ad9789_wt_nBytes(dev,1,0x20,buff);
	
	buff[0] = 0x7d;
	ad9789_wt_nBytes(dev,1,0x21,buff);
	buff[0] = 0x10;
	ad9789_wt_nBytes(dev,1,0x22,buff);

	buff[0] = 0x62;
	ad9789_wt_nBytes(dev,1,0x23,buff);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,0x25,buff);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,0x26,buff);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,0x27,buff);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,0x28,buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x29,buff);
	buff[0] = 0xda;
	ad9789_wt_nBytes(dev,1,0x3c,buff);

	buff[0] = 0x02;
	ad9789_wt_nBytes(dev,1,0x3d,buff);

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,0x1e,buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x24,buff);

	for (i = 0; i < 100; i++) {
		ad9789_rd_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff);
		if (buff[0] == 0x00)
			break;
		msleep(10);
	}
	if (buff[0] != 0x00)
		dev_err(&dev->pdev->dev, "error updating parameters\n");

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,0x24,buff);

	for (i = 0; i < 100; i++) {
		ad9789_rd_nBytes(dev, 1, 0x04, buff);
		if (buff[0] == 0x08)
			break;
		msleep(10);
	}
	if (buff[0] != 0x08)
		dev_err(&dev->pdev->dev, "22 error updating parameters\n");
	else
		printk("status lock  OK ! \n");

	
	buff[0] = 0x0f;
	ad9789_wt_nBytes(dev,1,0x05,buff);
	buff[0] = 0x0c;
	ad9789_wt_nBytes(dev,1,0x03,buff);

	return ;

}

//bandwidth:Mhz,  freq: HZ
static BOOL ad9789_setFre_atsc (struct tbs_pcie_dev *dev, unsigned long freq)
{
	unsigned long freq_0, freq_1, freq_2, freq_3;
	unsigned long fdco;
	unsigned char buff[4] = {0};
	//config center freq
	unsigned long fcenter;
	int i;

	unsigned long bandwidth = 6;

	if(bandwidth ==8)
		fdco = 128250000; //146.285714;
	else if(bandwidth ==7)
		fdco = 128250000;
	else
		fdco = 128250000; // 2052/16=128.25

	//printk("set freq: %ld\n", freq);
	//freq_0 = (16777216 * freq)/150;
	freq_0 = div_u64(16777216ULL * freq, fdco);
	buff[2] = freq_0 & 0xff;
	buff[1] = (freq_0 >> 8) & 0xff;
	buff[0] = (freq_0 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_0_FRE, buff);

	//freq_1 = (16777216 * (freq+8))/150;
	freq_1 = div_u64(16777216ULL * (freq + bandwidth *1000000), fdco);
	buff[2] = freq_1 & 0xff;
	buff[1] = (freq_1 >> 8) & 0xff;
	buff[0] = (freq_1 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_1_FRE, buff);

	//freq_2 = (16777216 * (freq+16))/150;
	freq_2 = div_u64(16777216ULL * (freq + bandwidth *2000000), fdco);
	buff[2] = freq_2 & 0xff;
	buff[1] = (freq_2 >> 8) & 0xff;
	buff[0] = (freq_2 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_2_FRE, buff);

	//freq_3 = (16777216 * (freq+24))/150;
	freq_3 = div_u64(16777216ULL * (freq + bandwidth *3000000), fdco);
	buff[2] = freq_3 & 0xff;
	buff[1] = (freq_3 >> 8) & 0xff;
	buff[0] = (freq_3 >> 16) & 0xff;
	ad9789_wt_nBytes(dev, 3, AD9789_NCO_3_FRE, buff);

	fcenter = freq + (bandwidth * 3 *1000000)/2;
	fcenter = div_u64(fcenter * 65536ULL, 16 * fdco);
	buff[1] = fcenter & 0xff;
	buff[0] = (fcenter >> 8) & 0xff; 
	ad9789_wt_nBytes(dev, 2, AD9789_CENTER_FRE_BPF, buff); 

	//update
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff);


	return TRUE;
}

static void AD9789_Configration_atsc_6m(struct tbs_pcie_dev *dev)
{
	int i = 0;
	unsigned char buff[4] = {0};

	//Software Reset
	buff[0] = 0x3C;
	ad9789_wt_nBytes(dev,1,AD9789_SPI_CTL,buff);
	
	//SPI Configuration
	buff[0] = 0x18;
	ad9789_wt_nBytes(dev,1,AD9789_SPI_CTL,buff);

	buff[0] = 0x9E;
	ad9789_wt_nBytes(dev, 1, AD9789_CLOCK_RECIVER_2, buff); //CLK_DIS=1;PSIGN=0;CLKP_CML=0x0F;NSIGN=0

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_Mu_CONTROL_DUTY_CYCLE, buff);

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,AD9789_PARAMETER_UPDATE,buff);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,AD9789_PARAMETER_UPDATE,buff);

	buff[0] = 0xce;
	ad9789_wt_nBytes(dev,1,0x2f,buff);


	buff[0] = 0x42;
	ad9789_wt_nBytes(dev,1,0x33,buff);

	buff[0] = 0x4e;
	ad9789_wt_nBytes(dev,1,0x39,buff);

	buff[0] = 0x6c;
	ad9789_wt_nBytes(dev,1,0x3a,buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x03,buff);
	buff[0] = 0xfe;
	ad9789_wt_nBytes(dev,1,0x04,buff);
	buff[0] = 0x0e;
	ad9789_wt_nBytes(dev,1,0x03,buff);

	buff[0] = 0x43;
	ad9789_wt_nBytes(dev,1,0x33,buff);

	
	buff[0] = 0xd0;
	ad9789_wt_nBytes(dev,1,0x06,buff);


	buff[0] = 0x22;
	ad9789_wt_nBytes(dev,1,0x07,buff);

	buff[0] = 0x1a;
	ad9789_wt_nBytes(dev,1,0x08,buff);

	buff[0] = 0x20;//0x32;
	ad9789_wt_nBytes(dev,1,0x09,buff);


	buff[0] = 0xe9;
	ad9789_wt_nBytes(dev,1,0x0a,buff);

	buff[0] = 0x26;
	ad9789_wt_nBytes(dev,1,0x0b,buff);


	buff[0] = 0xb2;
	ad9789_wt_nBytes(dev,1,0x0c,buff);

	buff[0] = 0xec;
	ad9789_wt_nBytes(dev,1,0x0d,buff);

	buff[0] = 0x20;
	ad9789_wt_nBytes(dev,1,0x0e,buff);

	buff[0] = 0xbe;
	ad9789_wt_nBytes(dev,1,0x0f,buff);

	buff[0] = 0xef;
	ad9789_wt_nBytes(dev,1,0x10,buff);

	buff[0] = 0x1a;
	ad9789_wt_nBytes(dev,1,0x11,buff);

	buff[0] = 0xca;
	ad9789_wt_nBytes(dev,1,0x12,buff);
	buff[0] = 0xf2;
	ad9789_wt_nBytes(dev,1,0x13,buff);
	buff[0] = 0x14;
	ad9789_wt_nBytes(dev,1,0x14,buff);
	buff[0] = 0xd6;
	ad9789_wt_nBytes(dev,1,0x15,buff);

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x16,buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x17,buff);
	buff[0] = 0x80;
	ad9789_wt_nBytes(dev,1,0x18,buff);
	buff[0] = 0x55;
	ad9789_wt_nBytes(dev,1,0x19,buff);
	buff[0] = 0x55;
	ad9789_wt_nBytes(dev,1,0x1a,buff);
	buff[0] = 0x5f;
	ad9789_wt_nBytes(dev,1,0x1b,buff);
	buff[0] = 0x42;
	ad9789_wt_nBytes(dev,1,0x1c,buff);
	buff[0] = 0x3c;
	ad9789_wt_nBytes(dev,1,0x1d,buff);
	buff[0] = 0x06;
	ad9789_wt_nBytes(dev,1,0x20,buff);
	
	buff[0] = 0x7d;
	ad9789_wt_nBytes(dev,1,0x21,buff);
	buff[0] = 0x1f;
	ad9789_wt_nBytes(dev,1,0x22,buff);

	buff[0] = 0xe6;
	ad9789_wt_nBytes(dev,1,0x23,buff);
	buff[0] = 0x60;
	ad9789_wt_nBytes(dev,1,0x25,buff);
	buff[0] = 0x60;
	ad9789_wt_nBytes(dev,1,0x26,buff);
	buff[0] = 0x60;
	ad9789_wt_nBytes(dev,1,0x27,buff);
	buff[0] = 0x60;
	ad9789_wt_nBytes(dev,1,0x28,buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x29,buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x3c,buff);

	buff[0] = 0x02;
	ad9789_wt_nBytes(dev,1,0x3d,buff);
	buff[0] = 0x08;
	ad9789_wt_nBytes(dev,1,0x04,buff);

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_FRE_UPDATE, buff); 

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 

	buff[0] = 0x80;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff); 
	for (i = 0; i < 100; i++) {
		ad9789_rd_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff);
		if (buff[0] == 0x80)
			break;
		msleep(10);
	}
	if (buff[0] != 0x80)
			dev_err(&dev->pdev->dev, "error updating parameters");

	buff[0] = 0x00;
	ad9789_wt_nBytes(dev, 1, AD9789_PARAMETER_UPDATE, buff);
	buff[0] = 0x00;
	ad9789_wt_nBytes(dev,1,0x05,buff);

	return ;
}

u8 tbsmods[10];
struct tbs_pcie_dev * tbsmodsdev[10];
struct cdev		mod_cdev;
struct class	*mod_cdev_class;

static void start_dma_transfer(struct mod_channel *pchannel)
{
	struct tbs_pcie_dev *dev=pchannel->dev;
	u32 delay;
	u32 bitrate;
	u32 speedctrl;

	/* PikoTV 20200306 */
	if(pchannel->input_bitrate){
		
		// Kbit
		if (pchannel->input_bitrate > PIKOTV_MBKB_THRESHOLD)
		{
			speedctrl = div_u64(1000000000ULL * BLOCKSIZE(dev->cardid), (pchannel->input_bitrate) * 1024);
		}
		else// Mbit
		{
			speedctrl = div_u64(1000000000ULL * BLOCKSIZE(dev->cardid), (pchannel->input_bitrate) * 1024*1024);
		}
		
		//printk("ioctl 0x20 speedctrl: %d \n", speedctrl);
		TBS_PCIE_WRITE((DMA_BASEADDRESS(pchannel->channel_index)), DMA_SPEED_CTRL, (speedctrl));
		TBS_PCIE_WRITE((DMA_BASEADDRESS(pchannel->channel_index)), DMA_INT_MONITOR, (2*speedctrl));
		if(dev->cardid == 0x690b)
		{
			//speedctrl =div_u64(speedctrl,BLOCKCEEL );
			speedctrl =div_u64(speedctrl*9,BLOCKCEEL*10 );	
			//printk("ioctl 0x24 frm: %d \n", speedctrl);
			TBS_PCIE_WRITE((DMA_BASEADDRESS(pchannel->channel_index)), DMA_FRAME_CNT, (speedctrl));
		}
		if(dev->cardid == 0x6214)
		{
			speedctrl =div_u64(speedctrl,BLOCKCEEL );	
			TBS_PCIE_WRITE((DMA_BASEADDRESS(pchannel->channel_index)), DMA_FRAME_CNT, (speedctrl));
		}

	}
	TBS_PCIE_WRITE((DMA_BASEADDRESS(pchannel->channel_index)), DMA_SIZE, (BLOCKSIZE(dev->cardid)));
	TBS_PCIE_WRITE((DMA_BASEADDRESS(pchannel->channel_index)), DMA_ADDR_HIGH, 0);
	TBS_PCIE_WRITE((DMA_BASEADDRESS(pchannel->channel_index)), DMA_ADDR_LOW, pchannel->dmaphy);
	TBS_PCIE_WRITE((DMA_BASEADDRESS(pchannel->channel_index)), DMA_GO, (1));

	TBS_PCIE_WRITE(Int_adapter, 0x04, (0x00000001));
	TBS_PCIE_WRITE(Int_adapter, 0x18+pchannel->channel_index*4, (1));
}

static int tbsmod_open(struct inode *inode, struct file *filp)
{
	//struct tbs_pcie_dev *dev = (struct tbs_pcie_dev * )tbsmodsdev[iminor(inode)>>2];
	//struct mod_channel *pchannel =(struct mod_channel *)&dev->channel[iminor(inode)&3];

	struct tbs_pcie_dev *dev = (struct tbs_pcie_dev * )tbsmodsdev[iminor(inode)>>3];
	struct mod_channel *pchannel =(struct mod_channel *)&dev->channel[iminor(inode)&7];
	filp->private_data = pchannel;
	u8 buff[4] = {0,0,0,0};
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
	spin_lock_init(&pchannel->adap_lock);
	//enable rf 
	if((dev->cardid == 0x6004)||(dev->cardid == 0x6104)||(dev->cardid == 0x6014)||(dev->cardid == 0x6034)){
		ad9789_rd_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff);
		buff[0] |= (1<<pchannel->channel_index);
		ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff);
		
	}
	else if(dev->cardid == 0x6008)
	{
		buff[0]=(pchannel->channel_index<4)?0:1;
		TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&buff[0]);

		ad9789_rd_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff);
		buff[0] |=  ((1<<(pchannel->channel_index<4 ? pchannel->channel_index:pchannel->channel_index-4)));		
		ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff);

	}

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
		{
			printk(" tbsmod_write buffer fulled!\n" );
			return 0;
		}
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
void spi_read(struct tbs_pcie_dev *dev, struct mcu24cxx_info *info)
{
	info->data = TBS_PCIE_READ(info->bassaddr, info->reg);
	//printk("%s bassaddr:%x ,reg: %x,val: %x\n", __func__, info->bassaddr, info->reg,info->data);
}
void spi_write(struct tbs_pcie_dev *dev, struct mcu24cxx_info *info)
{
	unsigned char tmpbuf[4];
	TBS_PCIE_WRITE(info->bassaddr,info->reg,info->data);	
	//printk("%s size:%x, reg: %x, val: %x\n", __func__, info->bassaddr, info->reg,info->data);
}
static long tbsmod_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct mod_channel *pchannel = (struct mod_channel *)file->private_data;
	struct tbs_pcie_dev *dev = pchannel->dev;
	//struct dtv_properties *props = NULL;
	struct dtv_properties props ;
	//struct dtv_property *prop = NULL;
	struct dtv_property prop;
	struct mcu24cxx_info wrinfo;
	int ret = 0;
	struct dvb_modulator_parameters params;
	struct dvb_frontend_info finfo;
	unsigned char buf[4] = {0};

	mutex_lock(&dev->ioctl_mutex);
	switch (cmd)
	{
	case FE_SET_PROPERTY:
		//printk("%s FE_SET_PROPERTY\n", __func__);
		//props = (struct dtv_properties *)arg;
		copy_from_user(&props , (const char*)arg, sizeof(struct dtv_properties ));
		if (props.num == 1)
		{
			//prop = props.props;
			copy_from_user(&prop , (const char*)props.props, sizeof(struct dtv_property ));
			if(dev->cardid == 0x6008)
			{
				if(pchannel->channel_index==4)
					buf[0] = 1;// choose spi device for 9789_B
				else if(pchannel->channel_index==0)	
					buf[0] = 0;// choose spi device for 9789_A	

				TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&buf[0]);
			}

			switch (prop.cmd)
			{
			case MODULATOR_MODULATION:
				if(dev->cardid == 0x690b)
					break;
				if((pchannel->channel_index)&&(pchannel->channel_index!=4)){
				//printk("%s FE_SET_PROPERTY not allow set\n", __func__);
				break;
				}
				printk("%s MODULATOR_MODULATION:%d\n", __func__,prop.u.data);
				if (prop.u.data < QAM_16 || prop.u.data > QAM_256)
				{
					ret = -1;
					break;
				}
				dev->modulation = prop.u.data;
				if((dev->cardid == 0x6004)||(dev->cardid == 0x6008))
					config_QAM(dev,dev->modulation-1);

				if(dev->cardid == 0x6014)
				{
					config_qamb(dev,dev->modulation);
					reset_ipcore_mod(dev);
				}
				break;

			case MODULATOR_SYMBOL_RATE:
				if(dev->cardid == 0x690b)
					break;
				if((pchannel->channel_index)&&(pchannel->channel_index!=4)){
				//printk("%s FE_SET_PROPERTY not allow set\n", __func__);
				break;
				}
				printk("%s MODULATOR_SYMBOL_RATE:%d\n", __func__,prop.u.data);
				if (prop.u.data < 1000000)
				{
					ret = EINVAL;
					break;
				}
				dev->srate = prop.u.data;
				config_srate(dev, dev->srate);
				break;
			case MODULATOR_BANDWIDTH:
				if((pchannel->channel_index)&&(pchannel->channel_index!=4)){
				//printk("%s FE_SET_PROPERTY not allow set\n", __func__);
				break;
				}
				printk("%s MODULATOR_BANDWIDTH:%d\n", __func__,prop.u.data);
				dev->bw = prop.u.data;

				break;
			case MODULATOR_FREQUENCY:
				if((pchannel->channel_index)&&(pchannel->channel_index!=4)){
				//printk("%s FE_SET_PROPERTY not allow set\n", __func__);
				break;
				}
				printk("%s MODULATOR_FREQUENCY:%d\n", __func__,prop.u.data);
				/*
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
				*/
				dev->frequency = prop.u.data;
				if((dev->cardid == 0x6004)||(dev->cardid == 0x6008))
					ad9789_setFre_dvbc(dev,dev->frequency,dev->bw);
				else if(dev->cardid == 0x6014)
					ad9789_setFre_qamb(dev,dev->frequency);
				else if(dev->cardid == 0x6034)
					ad9789_setFre_atsc(dev,dev->frequency);
				else 
					printk("%s not this interface for tbs%x\n", __func__,dev->cardid);
				
				break;
			case MODULATOR_GAIN:
				if((pchannel->channel_index)&&(pchannel->channel_index!=4)){
				//printk("%s FE_SET_PROPERTY not allow set\n", __func__);
				break;
				}
				printk("%s MODULATOR_GAIN:%d\n", __func__,prop.u.data);
				if (prop.u.data > 120)
				{
					printk("MODULATOR_GAIN :%d(over 120)\n", prop.u.data);
					ret = -1;
					break;
				}
				config_gain(dev, prop.u.data);
				break;
			case MODULATOR_INTERLEAVE:
				if(pchannel->channel_index){
				//printk("%s FE_SET_PROPERTY not allow set\n", __func__);
				break;
				}
				printk("%s MODULATOR_INTERLEAVE:%d\n", __func__,prop.u.data);
				if (prop.u.data > 16)
				{
					printk("MODULATOR_INTERLEAVE :%d(over 16)\n", prop.u.data);
					ret = -1;
					break;
				}
				if(dev->cardid == 0x6014)
				{
					config_qamb_ctl(dev, prop.u.data);
				}
				break;
			case MODULATOR_INPUT_BITRATE:
				{
					/* PikoTV 20200306 */
					if (prop.u.data > PIKOTV_MBKB_THRESHOLD)
					{
						// Kbit
						printk("%s MOD%d:INPUT_BITRATE:%d Kbit\n", __func__, pchannel->channel_index, prop.u.data);
						if (prop.u.data > 200*1024)
						{
							printk("MOD%d:INPUT_BITRATE :%d(over 200M)\n", pchannel->channel_index, prop.u.data);
							ret = -1;
							break;
						}
					}
					else // Mbit
					{
						printk("%s MOD%d:INPUT_BITRATE:%d Mbit\n", __func__, pchannel->channel_index, prop.u.data);
						if (prop.u.data > 200)
						{
							printk("MOD%d:INPUT_BITRATE :%d(over 200M)\n", pchannel->channel_index, prop.u.data);
							ret = -1;
							break;
						}
					}
				
					pchannel->input_bitrate = prop.u.data;
					break;
				}

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
		//printk("%s FE_GET_PROPERTY\n", __func__);
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
				printk("%s MODULATOR_MODULATION:%d\n",__func__, prop.u.data);
				break;

			case MODULATOR_SYMBOL_RATE:
				prop.u.data =dev->srate ;
				printk("%s MODULATOR_SYMBOL_RATE:%d\n", __func__,prop.u.data);
				break;

			case MODULATOR_FREQUENCY:
				prop.u.data = dev->frequency;
				printk("%s MODULATOR_FREQUENCY:%d\n", __func__,prop.u.data);
				break;
			}
		}
		break;

	case FE_GET_INFO:
		memset(&finfo, 0, sizeof(struct dvb_frontend_info));
		snprintf(finfo.name, 16, "TBS-%X:%d", dev->pdev->subsystem_vendor, dev->mod_index);
		copy_to_user((unsigned long)arg, &finfo, sizeof(struct dvb_frontend_info));
		break;

	
	case DVBMOD_SET_PARAMETERS:
	{
		if(pchannel->channel_index)
			break;
		
		copy_from_user(&params , (const char*)arg, sizeof(struct dvb_modulator_parameters ));
		printk("%s fre:%d, bw: %d, \n qam: %d, carriers: %d, fec : %d, interval: %d\n",__func__, params.frequency_khz,params.bandwidth_hz,
			params.constellation, params.transmission_mode, params.code_rate_HP, params.guard_interval);
		
		dev->frequency = params.frequency_khz *1000;
		dev->bw = params.bandwidth_hz/1000;
		AD4351_Configration_dvbt(dev);
		set_Modulation_dvbt(dev,&params);
		ad9789_setFre_dvbt(dev, dev->bw, dev->frequency);
		reset_ipcore_mod(dev);

		break;
	}


	case FE_ECP3FW_READ:
		copy_from_user(&wrinfo , (const char*)arg, sizeof(struct mcu24cxx_info ));
		spi_read(dev, &wrinfo);
		copy_to_user((unsigned long)arg, &wrinfo, sizeof(struct mcu24cxx_info ));
		break;
	case FE_ECP3FW_WRITE:
		copy_from_user(&wrinfo , (const char*)arg, sizeof(struct mcu24cxx_info ));
		spi_write(dev, &wrinfo);
		break;

	default:
		ret = -EINVAL;
		break;
	}
	mutex_unlock(&dev->ioctl_mutex);
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
	struct tbs_pcie_dev *dev=pchannel->dev;
	u8 buff[4] = {0,0,0,0};
	
	//printk("%s\n", __func__);
	TBS_PCIE_WRITE((DMA_BASEADDRESS(pchannel->channel_index)), DMA_GO, (0));
	pchannel->dma_start_flag = 0;

	//disable rf 
	if((dev->cardid == 0x6004)||(dev->cardid == 0x6104)||(dev->cardid == 0x6014)||(dev->cardid == 0x6034)){
		ad9789_rd_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff);
		buff[0] &= (~(1<<pchannel->channel_index));		
		ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff);
		
	}
	else if(dev->cardid == 0x6008)
	{
		buff[0]=(pchannel->channel_index<4)?0:1;
		TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&buff[0]);

		ad9789_rd_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff);
		buff[0] &= (~(1<<(pchannel->channel_index<4 ? pchannel->channel_index:pchannel->channel_index-4)));		
		ad9789_wt_nBytes(dev, 1, AD9789_CHANNEL_ENABLE, buff);

	}
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

static void tbs_adapters_init_dvbc(struct tbs_pcie_dev *dev)
{
	unsigned char tmpbuf[4]={0};
	int id2;
	BOOL ret;
	/*
	//reset 9789
	tmpbuf[0] = 1;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	*/
	ret = AD4351_Configration_dvbc(dev);
	if (ret == FALSE)
		printk("configration ad4351 false! \n");

	spi_ad9789Enable(dev, 1);

	// choose spi device for 9789
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&tmpbuf[0]);

	AD9789_Configration_dvbc(dev);

	//read id (54425368)
	id2 = TBS_PCIE_READ(0, SPI_RESET);
	printk("chip id2: %x\n", __swab32(id2));

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
static void tbs_adapters_init_dvbc_5862(struct tbs_pcie_dev *dev)
{
	unsigned char tmpbuf[4]={0};
	int id2;
	BOOL ret;
	

	//reset 5862
	tmpbuf[0] = 1;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	
	ret = MAX2871ConfigrationDvbc(dev);
	if (ret == FALSE)
		printk("configration MAX2871 false! \n");
	
	spi_ad9789Enable(dev, 1);

	// choose spi device for 9789_A
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&tmpbuf[0]);


	//read id (54425368)
	id2 = TBS_PCIE_READ(0, SPI_RESET);
	//printk("chip id2: %x\n", __swab32(id2));
	printk("chip id2: %x\n", id2);


	printk("TBS6008 DVBC Modulator init OK !\n");

	
}
static void tbs_adapters_init_dvbc8(struct tbs_pcie_dev *dev)
{
	unsigned char tmpbuf[4]={0};
	int id2;
	BOOL ret;
	/*

	//reset 9789
	tmpbuf[0] = 1;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	*/
	ret = AD4351_Configration_dvbc(dev);
	if (ret == FALSE)
		printk("configration ad4351 false! \n");
	
	spi_ad9789Enable(dev, 1);

	// choose spi device for 9789_A
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&tmpbuf[0]);

	AD9789_Configration_dvbc(dev);


	// choose spi device for 9789_B
	tmpbuf[0] = 1;
	TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&tmpbuf[0]);
	
	dev->frequency=530000000;
	AD9789_Configration_dvbc(dev);

	//read id (54425368)
	id2 = TBS_PCIE_READ(0, SPI_RESET);
	//printk("chip id2: %x\n", __swab32(id2));
	printk("chip id2: %x\n", id2);

	tmpbuf[0] = 0;
	ad9789_rd_nBytes(dev, 1, AD9789_HARDWARE_VERSION, tmpbuf);
	printk("hardware version: %x !\n", tmpbuf[0]);
	
	if(tmpbuf[0]==3)
		printk("TBS6008 DVBC Modulator init OK !\n");
	else
		printk("TBS6008 DVBC Modulator init failed !\n");
	
	/* disable all interrupts */
	//	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);

}
static void tbs_adapters_init_qamb(struct tbs_pcie_dev *dev)
{
	unsigned char tmpbuf[4]={0};
	//int id2;
	BOOL ret;
	/*
	//reset 9789
	tmpbuf[0] = 1;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	
	tmpbuf[0] = 0;
	tmpbuf[1] = 0;
	tmpbuf[2] = 0;
	tmpbuf[3] = 0;
	TBS_PCIE_WRITE(0, SPI_BW_LIGHT, *(u32 *)&tmpbuf[0]);
	msleep(100);
	tmpbuf[0] = 0;
	tmpbuf[1] = 0;
	tmpbuf[2] = 0;
	tmpbuf[3] = 0x1;
	TBS_PCIE_WRITE(0, SPI_BW_LIGHT, *(u32 *)&tmpbuf[0]);
	msleep(100);
	*/
	//ret = AD4351_Configration_qamb(dev);
	//ret = AD4351_Configration_dvbc(dev);
	ret = AD4351_Configration_2160(dev);
	if (ret == FALSE)
		printk("configration ad4351 false! \n");

	spi_ad9789Enable(dev, 1);

	//choose spi device for 9789
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&tmpbuf[0]);

	AD9789_Configration_qamb(dev);
	reset_ipcore_mod(dev);

	tmpbuf[0] = 0;
	ad9789_rd_nBytes(dev, 1, AD9789_HARDWARE_VERSION, tmpbuf);
	printk("hardware version: %x !\n", tmpbuf[0]);
	
	if(tmpbuf[0]==3)
		printk("TBS6014 QAMB Modulator init OK !\n");
	else
		printk("TBS6014 QAMB Modulator init failed !\n");
	
	/* disable all interrupts */
	//	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);

}

static void tbs_adapters_init_dvbt(struct tbs_pcie_dev *dev)
{
	unsigned char tmpbuf[4]={0};
	int id2;
	BOOL ret;
	/*
	//reset 9789
	tmpbuf[0] = 1;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_RESET, *(u32 *)&tmpbuf[0]);
	msleep(100);
	
	tmpbuf[0] = 0;
	tmpbuf[1] = 0;
	tmpbuf[2] = 0;
	tmpbuf[3] = 0;
	TBS_PCIE_WRITE(0, SPI_BW_LIGHT, *(u32 *)&tmpbuf[0]);
	msleep(100);
	tmpbuf[0] = 0;
	tmpbuf[1] = 0;
	tmpbuf[2] = 0;
	tmpbuf[3] = 0x1;
	TBS_PCIE_WRITE(0, SPI_BW_LIGHT, *(u32 *)&tmpbuf[0]);
	msleep(100);
	*/
	ret = AD4351_Configration_dvbt(dev);
	if (ret == FALSE)
		printk("configration ad4351 false! \n");

	spi_ad9789Enable(dev, 1);

	// choose spi device for 9789
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&tmpbuf[0]);

	AD9789_Configration_dvbt(dev);

	//read id (54425349)
	id2 = TBS_PCIE_READ(0, SPI_RESET);
	printk("chip id2: %x\n", __swab32(id2));

	tmpbuf[0] = 0;
	ad9789_rd_nBytes(dev, 1, AD9789_HARDWARE_VERSION, tmpbuf);
	printk("hardware version: %x !\n", tmpbuf[0]);
	
	if(tmpbuf[0]==3)
		printk("TBS6104 DVBT Modulator init OK !\n");
	else
		printk("TBS6104 DVBT Modulator init failed !\n");
	
	/* disable all interrupts */
	//	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);

}

static void tbs_adapters_init_isdbt(struct tbs_pcie_dev *dev)
{
	unsigned char tmpbuf[4]={0};
	int id2;
	BOOL ret;

	ret = AD4351_Configration_isdbt(dev);
	if (ret == FALSE)
		printk("configration ad4351 false! \n");

	spi_ad9789Enable(dev, 1);

	// choose spi device for 9789
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&tmpbuf[0]);

	AD9789_Configration_isdbt_6m(dev);

	tmpbuf[0] = 1;
	TBS_PCIE_WRITE(0, ISDBT_IPRST, *(u32*)&tmpbuf[0]);
	msleep(100);
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, ISDBT_IPRST, *(u32*)&tmpbuf[0]);
	msleep(100);


	//read id (54425349)
	id2 = TBS_PCIE_READ(0, SPI_RESET);
	printk("chip id2: %x\n", __swab32(id2));

	tmpbuf[0] = 0;
	ad9789_rd_nBytes(dev, 1, AD9789_HARDWARE_VERSION, tmpbuf);
	printk("hardware version: %x !\n", tmpbuf[0]);
	
	if(tmpbuf[0]==3)
		printk("TBS6214 isdbt Modulator init OK !\n");
	else
		printk("TBS6214 isdbt Modulator init failed !\n");
	
	/* disable all interrupts */
	//	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);

}

static void tbs_adapters_init_atsc(struct tbs_pcie_dev *dev)
{
	unsigned char tmpbuf[4]={0};
	int id2;
	BOOL ret;

	ret = AD4351_Configration_atsc(dev);
	if (ret == FALSE)
		printk("configration ad4351 false! \n");

	spi_ad9789Enable(dev, 1);

	// choose spi device for 9789
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, SPI_DEVICE, *(u32 *)&tmpbuf[0]);

	AD9789_Configration_atsc_6m(dev);

	tmpbuf[0] = 1;
	TBS_PCIE_WRITE(0, ISDBT_IPRST, *(u32*)&tmpbuf[0]);
	msleep(100);
	tmpbuf[0] = 0;
	TBS_PCIE_WRITE(0, ISDBT_IPRST, *(u32*)&tmpbuf[0]);
	msleep(100);


	//read id (54425349)
	id2 = TBS_PCIE_READ(0, SPI_RESET);
	printk("chip id2: %x\n", __swab32(id2));

	tmpbuf[0] = 0;
	ad9789_rd_nBytes(dev, 1, AD9789_HARDWARE_VERSION, tmpbuf);
	printk("hardware version: %x !\n", tmpbuf[0]);
	
	if(tmpbuf[0]==3)
		printk("TBS6214 atsc Modulator init OK !\n");
	else
		printk("TBS6214 atsc Modulator init failed !\n");
	
	/* disable all interrupts */
	//	TBS_PCIE_WRITE(TBS_INT_BASE, TBS_INT_ENABLE, 0x00000001);

}

static void sdi_chip_reset(struct tbs_pcie_dev *dev,int sdi_base_addr)
{
	unsigned char tmpbuf[4]={0};

	tmpbuf[0] = 0;
	TBS_PCIE_WRITE( sdi_base_addr, MOD_ASI_RST, *(u32 *)&tmpbuf[0]);

	msleep(200);

	tmpbuf[0] = 1;
	TBS_PCIE_WRITE( sdi_base_addr, MOD_ASI_RST, *(u32 *)&tmpbuf[0]);
	
	msleep(200);
}

void channelprocess(struct tbs_pcie_dev *dev,u8 index){
		struct mod_channel *pchannel = (struct mod_channel *)&dev->channel[index];
		int count = 0;
		int ret;
		u32 delay;
		
		spin_lock(&pchannel->adap_lock);
		TBS_PCIE_READ((DMA_BASEADDRESS(pchannel->channel_index)), 0x00);
		TBS_PCIE_WRITE(Int_adapter, 0x00, (0x10<<index) );
		count = kfifo_len(&pchannel->fifo);
		if (count >= BLOCKSIZE(dev->cardid)){
			//printk("dma%d status 11 %d\n",pchannel->channel_index,count);
			ret = kfifo_out(&pchannel->fifo, ((void *)(pchannel->dmavirt) ), BLOCKSIZE(dev->cardid)); 
			start_dma_transfer(pchannel);
		}else{
			//printk("dma%d status 22 %d\n", pchannel->channel_index, count);
			if (pchannel->dma_start_flag == 0){
				spin_unlock(&pchannel->adap_lock);
				return ;
			}
		
		/* PikoTV 20200306 */
		if (pchannel->input_bitrate > PIKOTV_MBKB_THRESHOLD)
		{
			// Kbit
			delay = div_u64(1000000000ULL * BLOCKSIZE(dev->cardid), (pchannel->input_bitrate) * 1024*3);
		}
		else
		{
			// Mbit
			delay = div_u64(1000000000ULL * BLOCKSIZE(dev->cardid), (pchannel->input_bitrate) * 1024*1024*3);
		}
		//printk("%s 0x18 delayshort: %d \n", __func__,delay);
		TBS_PCIE_WRITE((DMA_BASEADDRESS(pchannel->channel_index)), DMA_DELAYSHORT, (delay));
		//TBS_PCIE_WRITE(Int_adapter, 0x04, 0x00000001);
		}
		spin_unlock(&pchannel->adap_lock);
}


static irqreturn_t tbsmod_irq(int irq, void *dev_id)
{
	struct tbs_pcie_dev *dev = (struct tbs_pcie_dev *)dev_id;
	u32 stat,tmp;
	
	stat = TBS_PCIE_READ(Int_adapter, 0x0c);
	tmp = TBS_PCIE_READ(Int_adapter, 0); // clear total interrupts.
	TBS_PCIE_WRITE(Int_adapter, 0, tmp);

	TBS_PCIE_WRITE(Int_adapter, 0x04, 0x00000001);
	//printk("%s %x\n",__func__,stat);
	if (!(stat & 0xff0)){
		//TBS_PCIE_WRITE(Int_adapter, 0x04, 0x00000001);
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

	if (stat & 0x0100){ //dma4 status
		channelprocess(dev,4);
	}

	if (stat & 0x0200){ //dma5 status
		channelprocess(dev,5);
	}

	if (stat & 0x0400){ //dma6 status
		channelprocess(dev,6);
	}

	if (stat & 0x0800){ //dma7 status
		channelprocess(dev,7);
	}

	return IRQ_HANDLED;
}


static void tbsmod_remove(struct pci_dev *pdev)
{
	struct tbs_pcie_dev *dev =
		(struct tbs_pcie_dev *)pci_get_drvdata(pdev);
	int i;

	for(i=0;i<dev->mods_num;i++){
		kfifo_free(&dev->channel[i].fifo);
//		device_destroy(mod_cdev_class, dev->channel[i].devno);
		if (dev->channel[i].dmavirt){
			dma_free_coherent(&dev->pdev->dev, DMASIZE, dev->channel[i].dmavirt, dev->channel[i].dmaphy);
			dev->channel[i].dmavirt = NULL;
		}
	}
	tbsmods[dev->mod_index] =0;

	/* disable interrupts */
	free_irq(dev->pdev->irq, dev);
	if (dev->msi) {
		pci_disable_msi(pdev);
		dev->msi = false;
	}

	if (dev->mmio)
		iounmap(dev->mmio);

	kfree(dev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}

static bool tbsmod_enable_msi(struct pci_dev *pdev, struct tbs_pcie_dev *dev)
{
	int err;

	if (!enable_msi) {
		dev_warn(&dev->pdev->dev,
			"MSI disabled by module parameter 'enable_msi'\n");
		return false;
	}

	err = pci_enable_msi(pdev);
	if (err) {
		dev_err(&dev->pdev->dev,
			"Failed to enable MSI interrupt."
			" Falling back to a shared IRQ\n");
		return false;
	}

	/* no error - so request an msi interrupt */
	err = request_irq(pdev->irq, tbsmod_irq, 0,
				KBUILD_MODNAME, dev);
	if (err) {
		/* fall back to legacy interrupt */
		dev_err(&dev->pdev->dev,
			"Failed to get an MSI interrupt."
			" Falling back to a shared IRQ\n");
		pci_disable_msi(pdev);
		return false;
	}
	return true;
}

static int tbsmod_probe(struct pci_dev *pdev,
						const struct pci_device_id *pci_id)
{
	struct tbs_pcie_dev *dev;
	int err = 0, ret = -ENODEV;
	u8 index=0;
	u8 i;
	u8 mpbuf[4]={0};
	
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

	//interrupts 
	if (tbsmod_enable_msi(pdev, dev)) {
		printk("KBUILD_MODNAME : %s --MSI!\n",KBUILD_MODNAME);
		dev->msi = true;
	} else {
		printk("KBUILD_MODNAME : %s --INTx\n\n",KBUILD_MODNAME);
		ret = request_irq(pdev->irq, tbsmod_irq,
				IRQF_SHARED, KBUILD_MODNAME, dev);
		if (ret < 0) {
			printk(KERN_ERR "%s ERROR: IRQ registration failed <%d>\n", __func__, ret);
			ret = -ENODEV;
			goto fail2;
		}
		dev->msi = false;
	}

	pci_set_drvdata(pdev, dev);

	mutex_init(&dev->spi_mutex);
	mutex_init(&dev->ioctl_mutex);
	spin_lock_init(&dev->chip_lock);
	
	for(index=0;index<sizeof(tbsmods);index++){
		if(tbsmods[index] ==0 ){
			tbsmods[index] = 1;
			break;
		}
	}

	dev->mod_index = index;
	tbsmodsdev[index] = dev;
	dev->mods_num = 4;

	switch(pdev->subsystem_vendor){
	case 0x6004:
		dev->cardid = 0x6004; 
	break;
	case 0x690b:
		dev->cardid = 0x690b;
	break;
	case 0x6104:
		dev->cardid = 0x6104;
	break;
	case 0x6014:
		dev->cardid = 0x6014; 
	break;
	case 0x6008:
		dev->cardid = 0x6008; 
		dev->mods_num = 8;
	break;
	case 0x6214:
		dev->cardid = 0x6214; 
	break;
	case 0x6034:
		dev->cardid = 0x6034; 
	break;
	default:
		printk("unknow card\n");
	break;
	}

	for(i=0;i<dev->mods_num;i++){
		dev->channel[i].dmavirt = dma_alloc_coherent(&dev->pdev->dev, DMASIZE, &dev->channel[i].dmaphy, GFP_KERNEL);
		if (!dev->channel[i].dmavirt)
		{
			printk(" allocate memory failed\n");
			goto fail3;
		}
		dev->channel[i].channel_index=i;
		dev->channel[i].dev = dev;
		if((dev->cardid == 0x6004)||(dev->cardid == 0x6014)||(dev->cardid == 0x6008))
			dev->channel[i].input_bitrate = 40;
		else if(dev->cardid == 0x6104)
			dev->channel[i].input_bitrate = 30;
		else if(dev->cardid == 0x690b)
			dev->channel[i].input_bitrate = 80;
		else if(dev->cardid == 0x6214)
			dev->channel[i].input_bitrate = 30;
		else if(dev->cardid == 0x6034)
			dev->channel[i].input_bitrate = 20;//19.39
		//dev->channel[i].devno = MKDEV(MAJORDEV, (index*dev->mods_num+i));
		dev->channel[i].devno = MKDEV(MAJORDEV, (index*CHANNELS+i));

		device_create(mod_cdev_class, NULL, dev->channel[i].devno, &dev->channel[i], "tbsmod%d/mod%d",dev->mod_index,i);
		ret = kfifo_alloc(&dev->channel[i].fifo, FIFOSIZE, GFP_KERNEL);
		if (ret != 0)
			goto fail3;
	}

	dev->modulation =QAM_256;
	dev->srate=6900000;
	dev->frequency=474000000;
	dev->bw = 8;

	switch(pdev->subsystem_vendor){
	case 0x6004:
		printk("tbsmod%d:tbs6004 dvbc card\n", dev->mod_index);	
		spin_lock(&dev->chip_lock);
		tbs_adapters_init_dvbc(dev);	
		spin_unlock(&dev->chip_lock);
	break;
	
	case 0x6104:
		printk("tbsmod%d:tbs6104 dvbt card\n", dev->mod_index);	
		spin_lock(&dev->chip_lock);
		tbs_adapters_init_dvbt(dev);
		spin_unlock(&dev->chip_lock);
	break;
	
	case 0x6014:
		printk("tbsmod%d:tbs6014 qamb card\n", dev->mod_index);	
		spin_lock(&dev->chip_lock);
		tbs_adapters_init_qamb(dev);
		spin_unlock(&dev->chip_lock);
	break;

	case 0x690b:
		spin_lock(&dev->chip_lock);
		printk("tbsmod%d:tbs690b asi card\n", dev->mod_index);
		for(i=0;i<4;i++){
		mpbuf[0] = i; //0--3 :select value
		TBS_PCIE_WRITE( MOD_ASI_BASEADDRESS, MOD_ASI_DEVICE, *(u32 *)&mpbuf[0]);

		sdi_chip_reset(dev,MOD_ASI_BASEADDRESS);

		mpbuf[0] = 1; //active spi bus from "z"
		TBS_PCIE_WRITE( MOD_ASI_BASEADDRESS, ASI_SPI_ENABLE, *(u32 *)&mpbuf[0]);
		
		GS2972_rd_nBytes(dev, 2 ,0x08, mpbuf);
		if(mpbuf[1]==0x01)
			printk("GS2972 hardware is ok!\n");
		}
		spin_unlock(&dev->chip_lock);
	break;
	case 0x6008:
		printk("tbsmod%d:tbs6008 dvbc card\n", dev->mod_index);	
		spin_lock(&dev->chip_lock);
		//tbs_adapters_init_dvbc8(dev);	
		tbs_adapters_init_dvbc_5862(dev);
		spin_unlock(&dev->chip_lock);
	break;

	case 0x6214:
		printk("tbsmod%d:tbs6214 isdbt card\n", dev->mod_index);	
		spin_lock(&dev->chip_lock);
		tbs_adapters_init_isdbt(dev);
		spin_unlock(&dev->chip_lock);
	break;
	case 0x6034:
		printk("tbsmod%d:tbs6214 atsc card!!\n", dev->mod_index);	
		spin_lock(&dev->chip_lock);
		tbs_adapters_init_atsc(dev);
		spin_unlock(&dev->chip_lock);
	break;

	default:
		printk("unknow card\n");
	}
	return 0;

fail3:
	free_irq(dev->pdev->irq, dev);
	if (dev->msi) {
		pci_disable_msi(pdev);
		dev->msi = false;
	}
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

#define MAKE_ENTRY(__vend, __chip, __subven, __subdev, name) \
	{                                                               \
		.vendor = (__vend),                                         \
		.device = (__chip),                                         \
		.subvendor = (__subven),                                    \
		.subdevice = (__subdev),                                    \
		.driver_data = (unsigned long)(name)                 \
	}

static const struct pci_device_id tbsmod_id_table[] = {
	MAKE_ENTRY(0x544d, 0x6178, 0x6004, 0x0001, "tbs6004 dvbc card"),
	MAKE_ENTRY(0x544d, 0x6178, 0x690b, 0x0001, "tbs690b asi card"),
	MAKE_ENTRY(0x544d, 0x6178, 0x6104, 0x0001, "tbs6104 dvbt card"),
	MAKE_ENTRY(0x544d, 0x6178, 0x6014, 0x0001, "tbs6014 qamb card"),
	MAKE_ENTRY(0x544d, 0x6178, 0x6008, 0x0001, "tbs6008 dvbc card"),
	MAKE_ENTRY(0x544d, 0x6178, 0x6008, 0x0010, "tbs6008 dvbc card"),
	MAKE_ENTRY(0x544d, 0x6178, 0x6214, 0x0001, "tbs6214 isdtb card"),
	MAKE_ENTRY(0x544d, 0x6178, 0x6034, 0x0001, "tbs6034 atsc card"),
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
