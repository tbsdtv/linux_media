/*
    TBS ECP3 FPGA based cards PCIe driver

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "tbsecp3.h"

#include "tas2101.h"
#include "av201x.h"

#include "si2168.h"
#include "si2157.h"

#include "mxl58x.h"

#include "si2183.h"

#include "stv091x.h"
#include "stv6120.h"

#include "mn88436.h"
#include "mxl603.h"

#include "mtv23x.h"

#include "gx1503.h"
#include "r850.h"
#include "tas2971.h"

#include "stid135.h"
#include "rda5816.h"
#include "m88rs6060.h"
#include "gx1133.h"
#include "cxd2878.h"


DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);

static bool swapfe = false;
module_param(swapfe, bool, 0444);
MODULE_PARM_DESC(swapfe, "swap combo frontends order");

static bool ciclock = false;
module_param(ciclock, bool, 0444);
MODULE_PARM_DESC(ciclock, "whether to manually set ci clock. false=set by fpga,true=set by si5351");

struct sec_priv {
	struct tbsecp3_adapter *adap;
	int (*set_voltage)(struct dvb_frontend *fe,
			   enum fe_sec_voltage voltage);
};
static void ecp3_spi_read(struct i2c_adapter *i2c,u8 reg, u32 *buf)
{	
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;
	*buf = tbs_read(TBSECP3_GPIO_BASE,reg );

	//printk(" tbsecp3-dvb : ecp3_spi_read **********%x = %x*******\n",reg,*buf);

	return ;
}
static void ecp3_spi_write(struct i2c_adapter *i2c,u8 reg, u32 buf)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;
	//printk(" tbsecp3-dvb : ecp3_spi_write **********%x = %x*******\n",reg,buf);
	tbs_write(TBSECP3_GPIO_BASE, reg, buf);

	return ;
}

static void mcu_24cxx_read(struct i2c_adapter *i2c,u32 bassaddr, u8 reg, u32 *buf)
{	
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;
	*buf = tbs_read(bassaddr,reg );

	//printk(" tbsecp3-dvb : mcu_24cxx_read *****bassaddr: %x,  %x = %x*******\n",bassaddr,reg,*buf);

	return ;
}
static void mcu_24cxx_write(struct i2c_adapter *i2c,u32 bassaddr,u8 reg, u32 buf)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;
	//printk(" tbsecp3-dvb : mcu_24cxx_write ****bassaddr: %x,***%x = %x*******\n",bassaddr,reg,buf);
	tbs_write(bassaddr, reg, buf);

	return ;
}

static void ecp3_eeprom_read(struct i2c_adapter *i2c,u8 reg, u8 *buf)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;
	u8 eeprom_bus_nr = dev->info->eeprom_i2c;
	struct i2c_adapter *i2c_eep = &dev->i2c_bus[eeprom_bus_nr].i2c_adap;

	struct i2c_msg msg[] = {
		{ .addr = 0x50, .flags = 0,
		  .buf = &reg, .len = 1 },
		{ .addr = 0x50, .flags = I2C_M_RD,
		  .buf = buf, .len = 1 }
	};
	
	i2c_transfer(i2c_eep, msg, 2);

	//printk(" tbsecp3-dvb : ecp3_eeprom_read **********%x = %x*******\n",reg,*buf);

	return;
}
static void ecp3_eeprom_write(struct i2c_adapter *i2c,u8 reg, u8 data)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;
	u8 eeprom_bus_nr = dev->info->eeprom_i2c;
	struct i2c_adapter *i2c_eep = &dev->i2c_bus[eeprom_bus_nr].i2c_adap;
	u8 tmp[2] = { reg, data };

	struct i2c_msg msg[] = {
		{ .addr = 0x50, .flags = 0,
		  .buf = tmp, .len = 2 },
	};

	i2c_transfer(i2c_eep, msg, 1);
	//printk(" ecp3_eeprom_write : ecp3_spi_write **********%x = %x*******\n",reg,buf);

	return ;
}

static int tbs6302se_read_mac(struct tbsecp3_adapter *adap)
{
	struct tbsecp3_dev *dev = adap->dev;
	int ret = 1;
	int i =0;
	u32 postaddr;
	unsigned char tmpbuf[4]={0};
	unsigned char rdbuffer[8]={0};
	
	if(adap->nr)//adapter1 is equal to adapter3 in tbs6304
		postaddr =  0x80 *(adap->nr+2) +0x08;
	else//adapter0 is equal to adapter1 in tbs6304
		postaddr =  0x80 *(adap->nr+1) +0x08;

	tmpbuf[0] = 0x31; //24cxx read;
	tmpbuf[1] = 6;  //how many byte;
	tmpbuf[2] =  (postaddr>>8);
	tmpbuf[3] = (postaddr &255); //24cxx sub_address,0x08 for mac

	
	tbs_write( BASE_ADDRESS_24CXX, CMD_24CXX, *(u32 *)&tmpbuf[0] );
	//wait... until the data are received correctly;
	for(i=0;i<100;i++)
	{
		msleep(1);
		*(u32 *)tmpbuf = tbs_read( BASE_ADDRESS_24CXX, STATUS_MAC16_24CXX );
		if((tmpbuf[0]&1) == 0)
			break;
	}
	if(i==100)
	{
		ret = 0;
		//printk(" the receiver always busy !\n");
		//check mcu status
		*(u32 *)tmpbuf = tbs_read( BASE_ADDRESS_24CXX,  STATUS_MAC16_24CXX );
		if((tmpbuf[0]&0x4) == 1) // bit2==1 mcu busy
		{
			//printk("MCU status is busy!!!\n" );
			// release cs;
			tbs_write( BASE_ADDRESS_24CXX,  CS_RELEASE, *(u32 *)&tmpbuf[0] );
			ret = 0;
		}
		
	}
	// release cs;
	tbs_write(  BASE_ADDRESS_24CXX, CS_RELEASE, *(u32 *)&tmpbuf[0] );
	//check the write finished;
	for(i=0;i<100;i++)
	{
		msleep(1);
		*(u32 *)tmpbuf = tbs_read(  BASE_ADDRESS_24CXX, STATUS_MAC16_24CXX );
		if((tmpbuf[0]&1) == 1)
			break;
	}
	if(i==100)
	{
		ret = 0;
		//printk(" wait wt_24cxx_done timeout! \n");
	}
	//read back to host;
	*(u32 *)rdbuffer = tbs_read(  BASE_ADDRESS_24CXX, DATA0_24CXX );
	*(u32 *)&rdbuffer[4] = tbs_read(  BASE_ADDRESS_24CXX, DATA1_24CXX );
	if(ret!=0)
	{
		memcpy(adap->dvb_adapter.proposed_mac, rdbuffer,6);
		printk("adapter %d ,mac address: %x,%x,%x,%x,%x,%x \n",adap->dvb_adapter.num,rdbuffer[0],rdbuffer[1],rdbuffer[2],rdbuffer[3],rdbuffer[4],rdbuffer[5]);
	}

	return ret;
};

static int tbs6304_read_mac(struct tbsecp3_adapter *adap)
{
	struct tbsecp3_dev *dev = adap->dev;
	int ret = 1;
	int i =0;
	u32 postaddr;
	unsigned char tmpbuf[4]={0};
	unsigned char rdbuffer[8]={0};
	
	postaddr =  0x80 *(adap->nr) +0x08;

	tmpbuf[0] = 0x31; //24cxx read;
	tmpbuf[1] = 6;  //how many byte;
	tmpbuf[2] =  (postaddr>>8);
	tmpbuf[3] = (postaddr &255); //24cxx sub_address,0x08 for mac

	
	tbs_write( BASE_ADDRESS_24CXX, CMD_24CXX, *(u32 *)&tmpbuf[0] );
	//wait... until the data are received correctly;
	for(i=0;i<100;i++)
	{
		msleep(1);
		*(u32 *)tmpbuf = tbs_read( BASE_ADDRESS_24CXX, STATUS_MAC16_24CXX );
		if((tmpbuf[0]&1) == 0)
			break;
	}
	if(i==100)
	{
		ret = 0;
		//printk(" the receiver always busy !\n");
		//check mcu status
		*(u32 *)tmpbuf = tbs_read( BASE_ADDRESS_24CXX,  STATUS_MAC16_24CXX );
		if((tmpbuf[0]&0x4) == 1) // bit2==1 mcu busy
		{
			//printk("MCU status is busy!!!\n" );
			// release cs;
			tbs_write( BASE_ADDRESS_24CXX,  CS_RELEASE, *(u32 *)&tmpbuf[0] );
			ret = 0;
		}
		
	}
	// release cs;
	tbs_write(  BASE_ADDRESS_24CXX, CS_RELEASE, *(u32 *)&tmpbuf[0] );
	//check the write finished;
	for(i=0;i<100;i++)
	{
		msleep(1);
		*(u32 *)tmpbuf = tbs_read(  BASE_ADDRESS_24CXX, STATUS_MAC16_24CXX );
		if((tmpbuf[0]&1) == 1)
			break;
	}
	if(i==100)
	{
		ret = 0;
		//printk(" wait wt_24cxx_done timeout! \n");
	}
	//read back to host;
	*(u32 *)rdbuffer = tbs_read(  BASE_ADDRESS_24CXX, DATA0_24CXX );
	*(u32 *)&rdbuffer[4] = tbs_read(  BASE_ADDRESS_24CXX, DATA1_24CXX );
	if(ret!=0)
	{
		memcpy(adap->dvb_adapter.proposed_mac, rdbuffer,6);
		printk("adapter %d ,mac address: %x,%x,%x,%x,%x,%x \n",adap->dvb_adapter.num,rdbuffer[0],rdbuffer[1],rdbuffer[2],rdbuffer[3],rdbuffer[4],rdbuffer[5]);
	}

	return ret;
};
static void tbs_write_ext(struct tbsecp3_adapter *adap, u32 baseaddr, u8 address, u32 data)
{
    struct tbsecp3_dev *dev = adap->dev;
    int i = 0;
    u32 uAddr = baseaddr + address;
    u32 tmp = ((uAddr & 0xff00) >> 8) | ((uAddr & 0x00ff) << 8);
    tbs_write(0x1000,4, data);
    tbs_write(0x1000,0, (((tmp << 16) & 0xffff0000) + 0x00000000));

    while (0xff == tbs_read(0x1000,0)) {
	//msleep(1);
        if (10000 == i) {
           //printk("rdReg32_Extern:rdReg32(0x1000) time out\n");
           return;
        }
        i++;
    }
    return;

}

static u32 tbs_read_ext(struct tbsecp3_adapter *adap, u32 baseaddr, u8 address)
{
    struct tbsecp3_dev *dev = adap->dev;
    int i = 0;
    u32 uAddr = baseaddr + address;
    u32 tmp = ((uAddr & 0xff00) >> 8) | ((uAddr & 0x00ff) << 8);
    tbs_write(0x1000,0, (((tmp << 16) & 0xffff0000) + 0x00000080));
    while (0xff == tbs_read(0x1000,0)) {
	//msleep(1);
        if (10000 == i) {
           //printk("rdReg32_Extern:rdReg32(0x1000) time out\n");
           return 0;
        }
        i++;
    }
    return tbs_read(0x1000,4);
}

static int tbs6308_read_mac_ext(struct tbsecp3_adapter *adap)
{
	struct tbsecp3_dev *dev = adap->dev;
	int ret = 1;
	int i =0;
	u32 postaddr;
	unsigned char tmpbuf[4]={0};
	unsigned char rdbuffer[8]={0};
	
	postaddr =  0x80 *((adap->nr)%4) +0x08;

	tmpbuf[0] = 0x31; //24cxx read;
	tmpbuf[1] = 6;  //how many byte;
	tmpbuf[2] =  (postaddr>>8);
	tmpbuf[3] = (postaddr &255); //24cxx sub_address,0x08 for mac

	
	tbs_write_ext( adap, BASE_ADDRESS_24CXX, CMD_24CXX, *(u32 *)&tmpbuf[0] );
	//wait... until the data are received correctly;
	for(i=0;i<200;i++)
	{
		msleep(1);
		*(u32 *)tmpbuf = tbs_read_ext( adap, BASE_ADDRESS_24CXX, STATUS_MAC16_24CXX );
		if((tmpbuf[0]&1) == 0)
			break;
	}
	if(i==200)
	{
		//printk(" the receiver always busy !\n");
		ret = 0;
		//check mcu status
		*(u32 *)tmpbuf = tbs_read_ext(adap, BASE_ADDRESS_24CXX,  STATUS_MAC16_24CXX );
		if((tmpbuf[0]&0x4) == 1) // bit2==1 mcu busy
		{
			//printk("MCU status is busy!!!\n" );
			// release cs;
			tbs_write_ext( adap,BASE_ADDRESS_24CXX,  CS_RELEASE, *(u32 *)&tmpbuf[0] );
			ret = 0;
		}
		
	}
	// release cs;
	tbs_write_ext( adap, BASE_ADDRESS_24CXX, CS_RELEASE, *(u32 *)&tmpbuf[0] );
	//check the write finished;
	for(i=0;i<200;i++)
	{
		msleep(1);
		*(u32 *)tmpbuf = tbs_read_ext( adap, BASE_ADDRESS_24CXX, STATUS_MAC16_24CXX );
		if((tmpbuf[0]&1) == 1)
			break;
	}
	if(i==200)
	{
		//printk(" wait wt_24cxx_done timeout! \n");
		ret=0;
	}
	//read back to host;
	*(u32 *)rdbuffer = tbs_read_ext( adap, BASE_ADDRESS_24CXX, DATA0_24CXX );
	*(u32 *)&rdbuffer[4] = tbs_read_ext( adap, BASE_ADDRESS_24CXX, DATA1_24CXX );
	
	if(ret!=0)
	{
		memcpy(adap->dvb_adapter.proposed_mac, rdbuffer,6);
		printk("adapter %d ,mac address: %x,%x,%x,%x,%x,%x \n",adap->dvb_adapter.num,rdbuffer[0],rdbuffer[1],rdbuffer[2],rdbuffer[3],rdbuffer[4],rdbuffer[5]);
	}
	return ret;
};

static void tbs6301_read_mac(struct tbsecp3_adapter *adap)
{
	struct tbsecp3_dev *dev = adap->dev;

	int i =0;
	unsigned char tmpbuf[4]={0};
	unsigned char rdbuffer[8]={0};

	tmpbuf[0] = 0x31; //24cxx read;
	tmpbuf[1] = 6;  //how many byte;
	tmpbuf[2] = 0;
	tmpbuf[3] = 0x08; //24cxx sub_address,0x08 for mac

	tbs_write( BASE_ADDRESS_24CXX, CMD_24CXX, *(u32 *)&tmpbuf[0] );
	//wait... until the data are received correctly;
	for(i=0;i<100;i++)
	{
		msleep(1);
		*(u32 *)tmpbuf = tbs_read( BASE_ADDRESS_24CXX, STATUS_MAC16_24CXX );
		if((tmpbuf[0]&1) == 0)
			break;
	}
	if(i==100)
	{
		printk(" the receiver always busy !\n");
		//check mcu status
		*(u32 *)tmpbuf = tbs_read( BASE_ADDRESS_24CXX,  STATUS_MAC16_24CXX );
		if((tmpbuf[0]&0x4) == 1) // bit2==1 mcu busy
		{
			printk("MCU status is busy!!!\n" );
			// release cs;
			tbs_write( BASE_ADDRESS_24CXX,  CS_RELEASE, *(u32 *)&tmpbuf[0] );
			return;
		}
		
	}
	// release cs;
	tbs_write(  BASE_ADDRESS_24CXX, CS_RELEASE, *(u32 *)&tmpbuf[0] );
	//check the write finished;
	for(i=0;i<100;i++)
	{
		msleep(1);
		*(u32 *)tmpbuf = tbs_read(  BASE_ADDRESS_24CXX, STATUS_MAC16_24CXX );
		if((tmpbuf[0]&1) == 1)
			break;
	}
	if(i==100)
	{
		printk(" wait wt_24cxx_done timeout! \n");
	}
	//read back to host;
	*(u32 *)rdbuffer = tbs_read(  BASE_ADDRESS_24CXX, DATA0_24CXX );
	*(u32 *)&rdbuffer[4] = tbs_read(  BASE_ADDRESS_24CXX, DATA1_24CXX );
	memcpy(adap->dvb_adapter.proposed_mac, rdbuffer,6);
	printk(" tbs6301 mac address: %x,%x,%x,%x,%x,%x \n",rdbuffer[0],rdbuffer[1],rdbuffer[2],rdbuffer[3],rdbuffer[4],rdbuffer[5]);

	return ;
};


static int tbsecp3_set_voltage(struct dvb_frontend* fe,
		enum fe_sec_voltage voltage)
{
	struct sec_priv *priv = fe->sec_priv;
	struct tbsecp3_gpio_config *cfg = &priv->adap->cfg->gpio;
	struct tbsecp3_dev *dev = priv->adap->dev;

	dev_dbg(&dev->pci_dev->dev, "%s() %s\n", __func__,
		voltage == SEC_VOLTAGE_13 ? "SEC_VOLTAGE_13" :
		voltage == SEC_VOLTAGE_18 ? "SEC_VOLTAGE_18" :
		"SEC_VOLTAGE_OFF");

	switch (voltage) {
		case SEC_VOLTAGE_13:
			tbsecp3_gpio_set_pin(dev, &cfg->lnb_power, 1);
			tbsecp3_gpio_set_pin(dev, &cfg->lnb_voltage, 0);
			break;
		case SEC_VOLTAGE_18:
			tbsecp3_gpio_set_pin(dev, &cfg->lnb_power, 1);
			tbsecp3_gpio_set_pin(dev, &cfg->lnb_voltage, 1);
			break;
		default: /* OFF */
			tbsecp3_gpio_set_pin(dev, &cfg->lnb_power, 0);
			break;
	}

	if (priv->set_voltage)
		return priv->set_voltage(fe, voltage);
	else
		return 0;
}

static void tbsecp3_release_sec(struct dvb_frontend* fe)
{
	struct sec_priv *priv;

	if (fe == NULL)
		return;

	priv = fe->sec_priv;
	if (priv == NULL)
		return;

	fe->ops.set_voltage = priv->set_voltage;
	fe->sec_priv = NULL;
	kfree(priv);
}

static struct dvb_frontend *tbsecp3_attach_sec(struct tbsecp3_adapter *adap, struct dvb_frontend *fe)
{
	struct sec_priv *priv;

	priv = kzalloc(sizeof(struct sec_priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->set_voltage = fe->ops.set_voltage;
	priv->adap = adap;

//	fe->ops.release_sec = tbsecp3_release_sec;
	fe->ops.set_voltage = tbsecp3_set_voltage;
	fe->sec_priv = priv;

	return fe;
}

static int set_mac_address(struct tbsecp3_adapter *adap)
{
	struct tbsecp3_dev *dev = adap->dev;
	u8 eeprom_bus_nr = dev->info->eeprom_i2c;
	struct i2c_adapter *i2c = &dev->i2c_bus[eeprom_bus_nr].i2c_adap;
	u8 eep_addr = 0xa0;
	int ret;

	struct i2c_msg msg[] = {
		{ .addr = 0x50, .flags = 0,
		  .buf = &eep_addr, .len = 1 },
		{ .addr = 0x50, .flags = I2C_M_RD,
		  .buf = adap->dvb_adapter.proposed_mac, .len = 6 }
	};

	if (dev->info->eeprom_addr)
		eep_addr = dev->info->eeprom_addr;

	eep_addr += 0x10 * adap->nr;
	
	ret = i2c_transfer(i2c, msg, 2);
	ret = i2c_transfer(i2c, msg, 2);
	if (ret != 2) {
		dev_warn(&dev->pci_dev->dev,
			"error reading MAC address for adapter %d\n",
			adap->nr);
	} else {
		dev_info(&dev->pci_dev->dev,
			"MAC address %pM\n", adap->dvb_adapter.proposed_mac);
	}
	return 0;
};

static int start_feed(struct dvb_demux_feed *dvbdmxfeed)
{
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	struct tbsecp3_adapter *adapter = dvbdmx->priv;

	if (!adapter->feeds)
		tbsecp3_dma_enable(adapter);

	return ++adapter->feeds;
}

static int stop_feed(struct dvb_demux_feed *dvbdmxfeed)
{
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	struct tbsecp3_adapter *adapter = dvbdmx->priv;

	if (--adapter->feeds)
		return adapter->feeds;

	tbsecp3_dma_disable(adapter);
	return 0;
}

static void reset_demod(struct tbsecp3_adapter *adapter)
{
	struct tbsecp3_dev *dev = adapter->dev;
	struct tbsecp3_gpio_pin *reset = &adapter->cfg->gpio.demod_reset;

	tbsecp3_gpio_set_pin(dev, reset, 1);
	usleep_range(10000, 20000);

	tbsecp3_gpio_set_pin(dev, reset, 0);
	usleep_range(50000, 100000);
}


static struct tas2101_config tbs6902_demod_cfg[] = {
	{
		.i2c_address   = 0x60,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33},
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,	

	},
	{
		.i2c_address   = 0x68,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,
	}
};

static struct gx1133_config tbs6902_gx1133_cfg[] = {
	{
		.i2c_address   = 0x52,
		.ts_mode 	   = 0,	
		.ts_cfg		= {data_0,data_1,data_2,data_3,data_4,data_5,data_6,  \
								data_7,ts_sync,ts_valid,ts_clk,ts_err},
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,	

	},
	{
		.i2c_address   = 0x5A,
		.ts_mode 	   = 0,	
		.ts_cfg		= {data_0,data_1,data_2,data_3,data_4,data_5,data_6,  \
								data_7,ts_sync,ts_valid,ts_clk,ts_err},
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,
	}
};

static struct av201x_config tbs6902_av201x_cfg = {
		.i2c_address = 0x62,
		.id 		 = ID_AV2012,
		.xtal_freq	 = 27000,		/* kHz */
};

static struct tas2101_config tbs6301se_demod_cfg = {
		.i2c_address   = 0x60,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,

		.mcuWrite_properties = mcu_24cxx_write,  
		.mcuRead_properties = mcu_24cxx_read,

};


static struct tas2101_config tbs6302se_demod_cfg[] = {

    {
        .i2c_address   = 0x68,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,

		.mcuWrite_properties = mcu_24cxx_write,  
		.mcuRead_properties = mcu_24cxx_read,
    },    
  
    {
        .i2c_address   = 0x68,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,

		.mcuWrite_properties = mcu_24cxx_write,  
		.mcuRead_properties = mcu_24cxx_read,
    } 
};
static struct tas2101_config tbs6308_demod_cfg = {
       		 .i2c_address   = 0x60,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,

		.mcuWrite_properties = mcu_24cxx_write,  
		.mcuRead_properties = mcu_24cxx_read,    

};

static struct tas2101_config tbs6304_demod_cfg[] = {
    {
        .i2c_address   = 0x60,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,

		.mcuWrite_properties = mcu_24cxx_write,  
		.mcuRead_properties = mcu_24cxx_read,    
    },
    {
        .i2c_address   = 0x68,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,

		.mcuWrite_properties = mcu_24cxx_write,  
		.mcuRead_properties = mcu_24cxx_read,
    },    
    {
        .i2c_address   = 0x60,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,

		.mcuWrite_properties = mcu_24cxx_write,  
		.mcuRead_properties = mcu_24cxx_read,
    },    
    {
        .i2c_address   = 0x68,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,

		.mcuWrite_properties = mcu_24cxx_write,  
		.mcuRead_properties = mcu_24cxx_read,
    } 
};
static struct tas2101_config tbs6301_demod_cfg = {
		.i2c_address   = 0x60,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,

		.mcuWrite_properties = mcu_24cxx_write,  
		.mcuRead_properties = mcu_24cxx_read,

};


static struct tas2101_config tbs6304x_demod_cfg = {
		.i2c_address   = 0x60,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,

		.mcuWrite_properties = mcu_24cxx_write,  
		.mcuRead_properties = mcu_24cxx_read,

};

static struct tas2101_config tbs6904_demod_cfg[] = {
	{
		.i2c_address   = 0x60,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33}, // 0xb1
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,
	},
	{
		.i2c_address   = 0x68,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33},
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,
	},
	{
		.i2c_address   = 0x60,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33},
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,
	},
	{
		.i2c_address   = 0x68,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0x32, 0x81, 0x57, 0x64, 0x9a, 0x33},
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,
	}
};

static struct av201x_config tbs6904_av201x_cfg = {
	.i2c_address = 0x63,
	.id          = ID_AV2012,
	.xtal_freq   = 27000,		/* kHz */
};


static struct tas2101_config tbs6910_demod_cfg[] = {
	{
		.i2c_address   = 0x68,
		.id            = ID_TAS2101,
		.init          = {0x21, 0x43, 0x65, 0xb0, 0xa8, 0x97, 0xb1},
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,
	},
	{
		.i2c_address   = 0x60,
		.id            = ID_TAS2101,
		.init          = {0xb0, 0xa8, 0x21, 0x43, 0x65, 0x97, 0xb1},
		.init2         = 0,
		.write_properties = ecp3_spi_write,  
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,
	},
};

static struct av201x_config tbs6910_av201x_cfg = {
	.i2c_address = 0x62,
	.id          = ID_AV2018,
	.xtal_freq   = 27000,		/* kHz */
};


static int max_set_voltage(struct i2c_adapter *i2c,
		enum fe_sec_voltage voltage, u8 rf_in)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;

	u32 val, reg;

	//printk("set voltage on %u = %d\n", rf_in, voltage);
	
	if (rf_in > 3)
		return -EINVAL;

	reg = rf_in * 4;
	val = tbs_read(TBSECP3_GPIO_BASE, reg) & ~4;

	switch (voltage) {
	case SEC_VOLTAGE_13:
		val &= ~2;
		break;
	case SEC_VOLTAGE_18:
		val |= 2;
		break;
	case SEC_VOLTAGE_OFF:
	default:
		//val |= 4;
		break;
	}

	tbs_write(TBSECP3_GPIO_BASE, reg, val);
	return 0;
}

static int max_send_master_cmd(struct dvb_frontend *fe, struct dvb_diseqc_master_cmd *cmd)
{
	//printk("send master cmd\n");
	return 0;
}
static int max_send_burst(struct dvb_frontend *fe, enum fe_sec_mini_cmd burst)
{
	//printk("send burst: %d\n", burst);
	return 0;
}
static void RF_switch(struct i2c_adapter *i2c,u8 rf_in,u8 flag)//flag : 0: dvbs/s2 signal 1:Terrestrial and cable signal 
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;
	u32 val ,reg;

	if (flag)
		tbsecp3_gpio_set_pin(dev, &dev->adapter[rf_in].cfg->gpio.lnb_power, 0);

	reg = 0x8+rf_in*4;
	
	val = tbs_read(TBSECP3_GPIO_BASE, reg);
	if(flag)
		val |= 2;
	else
		val &= ~2;
		
	tbs_write(TBSECP3_GPIO_BASE, reg, val);

}

static struct mxl58x_cfg tbs6909_mxl58x_cfg = {
	.adr		= 0x60,
	.type		= 0x01,
	.clk		= 24000000,
	.cap		= 12,
	.fw_read	= NULL,

	.set_voltage	= max_set_voltage,
	.write_properties = ecp3_spi_write, 
	.read_properties = ecp3_spi_read,
	.write_eeprom = ecp3_eeprom_write, 
	.read_eeprom = ecp3_eeprom_read,
};

static struct stv091x_cfg tbs6903_stv0910_cfg = {
	.adr      = 0x68,
	.parallel = 1,
	.rptlvl   = 3,
	.clk      = 30000000,
	.dual_tuner = 1,
	.write_properties = ecp3_spi_write, 
	.read_properties = ecp3_spi_read,
	.write_eeprom = ecp3_eeprom_write, 
	.read_eeprom = ecp3_eeprom_read,
};

struct stv6120_cfg tbs6903_stv6120_cfg = {
	.adr      = 0x60,
	.Rdiv     = 2,
	.xtal     = 30000,
};


static struct av201x_config tbs6522_av201x_cfg[] = {
	{
		.i2c_address = 0x63,
		.id          = ID_AV2018,
		.xtal_freq   = 27000,
	},
	{
		.i2c_address = 0x62,
		.id          = ID_AV2018,
		.xtal_freq   = 27000,
	},
};

static void Set_TSsampling(struct i2c_adapter *i2c,int tuner,int time)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;

	u32 Many_cnt;
	u32 iobuffer;
	char tmp[4];

	Many_cnt = 0x3B9ACA00/8*time;
	tmp[0] = (Many_cnt>>24)&0xff;
	tmp[1] =  (Many_cnt>>16)&0xff;
	tmp[2] =  (Many_cnt>>8)&0xff;
	tmp[3] =  Many_cnt&0xff;

	iobuffer = tmp[0]|(tmp[1]<<8)|(tmp[2]<<16)|(tmp[3]<<24);
	
	tbs_write(TBSECP3_GPIO_BASE, (0xc+tuner)*4,iobuffer);
	
}

static u32  Set_TSparam(struct i2c_adapter *i2c,int tuner,int time,bool flag)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;

	u32 iobuffer;
	u32 Frm_cnt,Bit_rate,Many_cnt;
	int clk_preset;
	u8  tmp[4];

	Many_cnt = 0x3B9ACA00/8*time;

	iobuffer =  tbs_read(TBSECP3_GPIO_BASE, (0x10+tuner)*4);
	tmp[0] = (iobuffer>>24)&0xff;
	tmp[1] =  (iobuffer>>16)&0xff;
	tmp[2] =  (iobuffer>>8)&0xff;
	tmp[3] =  iobuffer&0xff;

	Bit_rate= tmp[0]|(tmp[1]<<8)|(tmp[2]<<16)|(tmp[3]<<24);

	if(!flag)
		return Bit_rate;

	Frm_cnt = Many_cnt/(Bit_rate-50) -100;

	tmp[0] =  (Frm_cnt>>24)&0xff;
	tmp[1] =  (Frm_cnt>>16)&0xff;
	tmp[2] =  (Frm_cnt>>8)&0xff;
	tmp[3] =  Frm_cnt&0xff;

	iobuffer= tmp[0]|(tmp[1]<<8)|(tmp[2]<<16)|(tmp[3]<<24);
	
	tbs_write(TBSECP3_GPIO_BASE, (0xA+tuner)*4,iobuffer);

	if( Frm_cnt==0) return 0;

	//set ci clk preset
	clk_preset = Frm_cnt/408;
	if(clk_preset>0xf)clk_preset=0xf;
	iobuffer =  tbs_read(tuner?0x7000:0x6000,0x04*4);
	iobuffer = (iobuffer&0xF0FFFFFF)|(clk_preset<<24);
	
	tbs_write(tuner?0x7000:0x6000,0x04*4,iobuffer);
		
	return 1;

}

static struct stid135_cfg tbs6903x_stid135_cfg = {
	.adr		= 0x68,
	.clk		= 27,
	.ts_mode	= TS_2PAR,
	.set_voltage	= NULL,
	.write_properties = ecp3_spi_write, 
	.read_properties = ecp3_spi_read,
	.write_eeprom = ecp3_eeprom_write, 
	.read_eeprom = ecp3_eeprom_read,
	.set_TSsampling = NULL,
	.set_TSparam = NULL,
	.vglna = 0,
	.control_22k = true,
};

static struct stid135_cfg tbs6909x_stid135_cfg = {
	.adr		= 0x68,
	.clk		= 27,
	.ts_mode	= TS_STFE,
	.set_voltage	= max_set_voltage,
	.write_properties = ecp3_spi_write, 
	.read_properties = ecp3_spi_read,
	.write_eeprom = ecp3_eeprom_write, 
	.read_eeprom = ecp3_eeprom_read,
	.set_TSsampling = NULL,
	.set_TSparam = NULL,
	.vglna = 0,
	.control_22k = true,
	
};
static struct stid135_cfg tbs6903x_V2_stid135_cfg = {
	.adr		= 0x68,
	.clk		= 27,
	.ts_mode	= TS_2PAR,
	.set_voltage	= NULL,
	.write_properties = ecp3_spi_write, 
	.read_properties = ecp3_spi_read,
	.write_eeprom = ecp3_eeprom_write, 
	.read_eeprom = ecp3_eeprom_read,
	.set_TSsampling = NULL,
	.set_TSparam = NULL,
	.vglna = 1,
	.control_22k = true,
};

static struct stid135_cfg tbs6909x_V2_stid135_cfg = {
	.adr		= 0x68,
	.clk		= 27,
	.ts_mode	= TS_STFE,
	.set_voltage	= max_set_voltage,
	.write_properties = ecp3_spi_write, 
	.read_properties = ecp3_spi_read,
	.write_eeprom = ecp3_eeprom_write, 
	.read_eeprom = ecp3_eeprom_read,
	.set_TSsampling = NULL,
	.set_TSparam = NULL,
	.vglna = 2,
	.control_22k = true,
};

static struct stid135_cfg tbs6912_stid135_cfg = {
	.adr		= 0x68,
	.clk		= 27,
	.ts_mode	= TS_2PAR,
	.set_voltage	= NULL,
	.write_properties = ecp3_spi_write, 
	.read_properties = ecp3_spi_read,
	.write_eeprom = ecp3_eeprom_write, 
	.read_eeprom = ecp3_eeprom_read,
	.set_TSsampling = Set_TSsampling,
	.set_TSparam = Set_TSparam,
	.vglna = false,
	.control_22k = true,
};

static struct stid135_cfg tbs6916_stid135_cfg[] = {
{
	.adr		= 0x68,
	.clk		= 27,
	.ts_mode	= TS_STFE,
	.set_voltage	= max_set_voltage,
	.write_properties = ecp3_spi_write, 
	.read_properties = ecp3_spi_read,
	.write_eeprom = ecp3_eeprom_write, 
	.read_eeprom = ecp3_eeprom_read,
	.set_TSsampling = NULL,
	.set_TSparam = NULL,
	.vglna   =false,
	.control_22k = true,
	},
	{
	.adr		= 0x68,
	.clk		= 27,
	.ts_mode	= TS_STFE,
	.set_voltage	= max_set_voltage,
	.write_properties = NULL, 
	.read_properties = NULL,
	.set_TSsampling = NULL,
	.set_TSparam = NULL,
	.vglna   =false,
	.control_22k = false,
	},
	
};
static struct rda5816_config rda5816_cfg[] = {
	{
		.i2c_adr = 0x8,
		.xtal   = 1,    //1=27M  0=24M
	},
	{
		.i2c_adr = 0x9,
		.xtal   = 1,
	},
};
static struct mndmd_config tbs6704_cfg={
	.tuner_address = 0x60,
};
static void SetSpeedstatus(struct i2c_adapter *i2c,int tuner)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;

	if(tuner)
		tbs_write(0x7000, 0x1c,0x11111111);
	else
		tbs_write(0x6000, 0x1c,0x01010101);
	
	return ;
}
static int GetSpeedstatus(struct i2c_adapter *i2c,int tuner)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;
	u32 iobuffer;
	u8 tmp;
	if(tuner){
	iobuffer =  tbs_read(0x7000,0x1c);
	iobuffer =  tbs_read(0x7000,0x1c);
	}
	else
	{
	iobuffer =  tbs_read(0x6000,0x1c);
	iobuffer =  tbs_read(0x6000,0x1c);		
	}
	
	tmp = iobuffer&0xff;

	return tmp;
}

static void Set_TSsamplingtimes(struct i2c_adapter *i2c,int tuner,int time)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;

	u32 Many_cnt;
	u32 iobuffer;
	char tmp[4];

	Many_cnt = time*1000000/8;
	tmp[0] = (Many_cnt>>24)&0xff;
	tmp[1] =  (Many_cnt>>16)&0xff;
	tmp[2] =  (Many_cnt>>8)&0xff;
	tmp[3] =  Many_cnt&0xff;

	iobuffer = tmp[0]|(tmp[1]<<8)|(tmp[2]<<16)|(tmp[3]<<24);
	
	tbs_write(TBSECP3_GPIO_BASE, 0x30+tuner*4,iobuffer);
	
}
static int GetTSSpeed(struct i2c_adapter *i2c,int tuner)
{
	struct tbsecp3_i2c *i2c_adap = i2c_get_adapdata(i2c);
	struct tbsecp3_dev *dev = i2c_adap->dev;
	u32 iobuffer = 0;
	u8 tmp[4];
	u32 bit_rate = 0;
	iobuffer =  tbs_read(TBSECP3_GPIO_BASE, 0x40+tuner*4);
	tmp[0] = (iobuffer>>24)&0xff;
	tmp[1] =  (iobuffer>>16)&0xff;
	tmp[2] =  (iobuffer>>8)&0xff;
	tmp[3] =  iobuffer&0xff;

	bit_rate= tmp[0]|(tmp[1]<<8)|(tmp[2]<<16)|(tmp[3]<<24);

	return bit_rate;
}
static int SetCIClock(struct i2c_adapter *i2c,int tuner)
{
		u32 clock = 0;
		int stat = 0;
		u32 speed = 0;
		msleep(50);
		SetSpeedstatus(i2c,tuner);
		msleep(50);
		while(!stat){
		 stat=GetSpeedstatus(i2c,tuner);
			msleep(10);
		}
		speed = GetTSSpeed(i2c,tuner);
		clock = ((speed*4)*204*8/1024)+500; //khz
		if(clock<42000)
			clock = 42000;
		
//		printk("clock = %d,value = %d\n",clock,value);	
	return clock;
}
static struct cxd2878_config tbs6209se_cfg[] = {
	{
		.addr_slvt = 0x64,
		.xtal      = SONY_DEMOD_XTAL_24000KHz,
		.tuner_addr = 0x60,
		.tuner_xtal = SONY_ASCOT3_XTAL_24000KHz,
		.ts_mode	= 0,
		.ts_ser_data = 0,
		.ts_clk = 1,
		.ts_valid = 0,
		.atscCoreDisable = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,	
	},
	{
		.addr_slvt = 0x6c,
		.xtal      = SONY_DEMOD_XTAL_24000KHz,
		.tuner_addr = 0x60,
		.tuner_xtal = SONY_ASCOT3_XTAL_24000KHz,
		.ts_mode	= 0,
		.ts_ser_data = 0,
		.ts_clk = 1,
		.ts_valid = 0,
		.atscCoreDisable = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,	
	},	

	{
		.addr_slvt = 0x65,
		.xtal      = SONY_DEMOD_XTAL_24000KHz,
		.tuner_addr = 0x60,
		.tuner_xtal = SONY_ASCOT3_XTAL_24000KHz,
		.ts_mode	= 0,
		.ts_ser_data = 0,
		.ts_clk = 1,
		.ts_valid = 0,
		.atscCoreDisable = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,	
	},
	{
		.addr_slvt = 0x6D,
		.xtal      = SONY_DEMOD_XTAL_24000KHz,
		.tuner_addr = 0x60,
		.tuner_xtal = SONY_ASCOT3_XTAL_24000KHz,
		.ts_mode	= 0,
		.ts_ser_data = 0,
		.ts_clk = 1,
		.ts_clk_mask = 0,
		.ts_valid = 0,
		.atscCoreDisable = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,	
	}	
};
static struct cxd2878_config tbs6216_cfg[] = {
	{
		.addr_slvt = 0x64,
		.xtal      = SONY_DEMOD_XTAL_24000KHz,
		.tuner_addr = 0x60,
		.tuner_xtal = SONY_ASCOT3_XTAL_24000KHz,
		.ts_mode	= 0,
		.ts_ser_data = 0,
		.ts_clk = 1,
		.ts_valid = 0,
		.atscCoreDisable = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,	
	},
	{
		.addr_slvt = 0x6c,
		.xtal      = SONY_DEMOD_XTAL_24000KHz,
		.tuner_addr = 0x63,
		.tuner_xtal = SONY_ASCOT3_XTAL_24000KHz,
		.ts_mode	= 0,
		.ts_ser_data = 0,
		.ts_clk = 1,
		.ts_valid = 0,
		.atscCoreDisable = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,	
	}
	
	};
static struct cxd2878_config tbsserial_cfg = {
	
		.addr_slvt = 0x64,
		.xtal      = SONY_DEMOD_XTAL_24000KHz,
		.tuner_addr = 0x60,
		.tuner_xtal = SONY_ASCOT3_XTAL_24000KHz,
		.ts_mode	= 0,
		.ts_ser_data = 0,
		.ts_clk = 1,
		.ts_clk_mask = 0,
		.ts_valid = 0,
		.atscCoreDisable = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,	
	};

static struct cxd2878_config cxd6802_parallel_cfg = {
	
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
		.lock_flag = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
	};
static struct cxd2878_config tbs6504h_cfg[] = {
	{
		.addr_slvt = 0x6c,
		.xtal      = SONY_DEMOD_XTAL_24000KHz,
		.tuner_addr = 0x60,
		.tuner_xtal = SONY_ASCOT3_XTAL_24000KHz,
		.ts_mode	= 0,
		.ts_ser_data = 0,
		.ts_clk = 1,
		.ts_valid = 0,
		.atscCoreDisable = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,	
	},
	{
		.addr_slvt = 0x64,
		.xtal      = SONY_DEMOD_XTAL_24000KHz,
		.tuner_addr = 0x60,
		.tuner_xtal = SONY_ASCOT3_XTAL_24000KHz,
		.ts_mode	= 0,
		.ts_ser_data = 0,
		.ts_clk = 1,
		.ts_valid = 0,
		.atscCoreDisable = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,	
	},	

};

static struct cxd2878_config tbs6590se_cfg[] = {
	{
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
		.lock_flag = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,
		.RF_switch = 	RF_switch,
		.rf_port = 0,
		},
		{
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
		.lock_flag = 0,
		.write_properties = ecp3_spi_write, 
		.read_properties = ecp3_spi_read,
		.write_eeprom = ecp3_eeprom_write, 
		.read_eeprom = ecp3_eeprom_read,
		.RF_switch = 	RF_switch,
		.rf_port = 1,
		}		
	};
static void tbs_octuples_reset_demod(struct tbsecp3_adapter *adapter)
{
	struct tbsecp3_dev *dev = adapter->dev;
	u32 tmp;
	u32 gpio;
	if(adapter->nr<4)
		gpio= 0x4*(adapter->nr);
	if(adapter->nr>3)
		gpio = 0x2c+0x4*(adapter->nr-4);

	tmp = tbs_read(TBSECP3_GPIO_BASE, gpio);
	tmp = tmp &0xfffffffe;
	tbs_write(TBSECP3_GPIO_BASE, gpio, tmp);	
	msleep(50);
	tmp = tmp|0x01;
	tbs_write(TBSECP3_GPIO_BASE, gpio, tmp);
	msleep(50);
}
static u32 tbs_FPGA_fireware_info(struct tbsecp3_adapter *adapter)
{
	struct tbsecp3_dev *dev = adapter->dev;
	u32 tmp;  //hardware id
	u32 data; //fw data;
	tmp = tbs_read(TBSECP3_GPIO_BASE, 0x20);
	data = tbs_read(TBSECP3_GPIO_BASE, 0x28);
	printk("the device hardware id :%x,fw data: %x \n",tmp,data);
	
	if(ciclock){
		tbs_write(0x6000, 0x10, 0); //tuner 0
		tbs_write(0x7000, 0x10, 0); //tuner 1

	}else{
		tbs_write(0x6000, 0x10, 0xffffffff);
		tbs_write(0x7000, 0x10, 0xffffffff);

	}
			
	return data;	
}
static void tbs6590se_reset_demod(struct tbsecp3_adapter *adapter) //for the cxd6802
{
	struct tbsecp3_dev *dev = adapter->dev;
	u32 tmp;
	u32 gpio;
	
	gpio= 0x08+0x4*(adapter->nr);
	
	tmp = tbs_read(TBSECP3_GPIO_BASE, gpio);
	tmp = tmp &0xfffffffe;
	tbs_write(TBSECP3_GPIO_BASE, gpio, tmp);	
	msleep(50);
	tmp = tmp|0x01;
	tbs_write(TBSECP3_GPIO_BASE, gpio, tmp);
	msleep(50);
	
	return ;
}
static unsigned char  tbsecp3_get_hwver(struct tbsecp3_adapter *adapter) //for get the hardware version
{
	struct tbsecp3_dev *dev = adapter->dev;
	u8 ver = 0;
	u32 tmp = 0;
	
	tmp = tbs_read(TBSECP3_GPIO_BASE, 0x68);
	ver = (u8) (tmp>>8)&0xff;
	
	return ver;	
	
}
static struct r850_config r850_config={

	 .i2c_address = 0x7C,
	.R850_Xtal=24000,

};
static void tbs6216_reset_demod(struct tbsecp3_adapter *adapter)
{
	struct tbsecp3_dev *dev = adapter->dev;
	u32 tmp;
	u32 gpio;
	if(adapter->nr<4)
		gpio= 0x4*(adapter->nr);
	else
		gpio = 0x30+0x4*(adapter->nr-4);

	tmp = tbs_read(TBSECP3_GPIO_BASE, gpio);
	tmp = tmp &0xfffffffe;
	tbs_write(TBSECP3_GPIO_BASE, gpio, tmp);	
	msleep(50);
	tmp = tmp|0x01;
	tbs_write(TBSECP3_GPIO_BASE, gpio, tmp);
	msleep(50);
}
static int tbsecp3_frontend_attach(struct tbsecp3_adapter *adapter)
{
	struct tbsecp3_dev *dev = adapter->dev;
	struct pci_dev *pci = dev->pci_dev;

	struct si2168_config si2168_config;
	struct si2183_config si2183_config;
	struct si2157_config si2157_config;
	//struct mn88436_config mn88436_config;
	//struct mxl603_config mxl603_config;
	struct mtv23x_config mtv23x_config;
	struct gx1503_config gx1503_config;
	struct m88rs6060_cfg m88rs6060_config;
	struct i2c_board_info info;
	struct i2c_adapter *i2c = &adapter->i2c->i2c_adap;
	struct i2c_client *client_demod, *client_tuner;


	adapter->fe = NULL;
	adapter->fe2 = NULL;
	adapter->i2c_client_demod = NULL;
	adapter->i2c_client_tuner = NULL;

	if((TBSECP3_BOARD_TBS6304 != dev->info->board_id) && (TBSECP3_BOARD_TBS6308 != dev->info->board_id) && (TBSECP3_BOARD_TBS6302SE != dev->info->board_id)&&(TBSECP3_BOARD_TBS6209SE != dev->info->board_id)&&(TBSECP3_BOARD_TBS6909SE != dev->info->board_id)&&(TBSECP3_BOARD_TBS6504H!= dev->info->board_id)&&(TBSECP3_BOARD_TBS6331!= dev->info->board_id)
	&&(TBSECP3_BOARD_TBS6216!= dev->info->board_id)){
		reset_demod(adapter);
		set_mac_address(adapter);
	}

	switch (dev->info->board_id) {
	   case TBSECP3_BOARD_TBS6910X:
		 memset(&m88rs6060_config, 0, sizeof(m88rs6060_config));
		 m88rs6060_config.fe = &adapter->fe;
		 m88rs6060_config.clk = 27000000;
		 m88rs6060_config.i2c_wr_max = 65;
		 m88rs6060_config.ts_mode = MtFeTsOutMode_Parallel;
		 m88rs6060_config.ts_pinswitch = 0;
		 m88rs6060_config.ts_autoclock = 0;	
		 m88rs6060_config.envelope_mode = 0;
		 m88rs6060_config.demod_adr = 0x69; 
		 m88rs6060_config.tuner_adr = 0x2c;
		 m88rs6060_config.repeater_value = 0x12;
		 m88rs6060_config.num = adapter->nr;
		 m88rs6060_config.HAS_CI = 0;
		 m88rs6060_config.SetCIClock= NULL;
		 m88rs6060_config.disable_22k = 0;
		 m88rs6060_config.read_properties = ecp3_spi_read;
		 m88rs6060_config.write_properties = ecp3_spi_write;
		 m88rs6060_config.read_eeprom = ecp3_eeprom_read;
		 m88rs6060_config.write_eeprom = ecp3_eeprom_write; 
		 memset(&info, 0, sizeof(struct i2c_board_info));
		 strscpy(info.type, "m88rs6060", I2C_NAME_SIZE);
		 info.addr = m88rs6060_config.demod_adr;
		 info.platform_data = &m88rs6060_config;
		 request_module(info.type);
		 client_demod = i2c_new_client_device(i2c, &info);
		 if (!i2c_client_has_driver(client_demod))
				goto frontend_atach_fail;
		 if (!try_module_get(client_demod->dev.driver->owner)) {
				i2c_unregister_device(client_demod);
					goto frontend_atach_fail;
					}
		 adapter->i2c_client_demod = client_demod;	 
 		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
		    dev_warn(&dev->pci_dev->dev,
		    			    "error attaching lnb control on adapter %d\n",
						    adapter->nr);
		} 
		if(dev->cimode==1)
			tbsecp3_ca_init(adapter, adapter->nr); 
			
		break;
	  case TBSECP3_BOARD_TBS6216:
	   	       tbs6216_reset_demod(adapter);
	   		set_mac_address(adapter);		
	   		adapter->fe = dvb_attach(cxd2878_attach, &tbs6216_cfg[(adapter->nr)%2], i2c);

		if (adapter->fe == NULL)
		    goto frontend_atach_fail;
	   break;
	   case TBSECP3_BOARD_TBS6590SE:   
	   	tbs6590se_reset_demod(adapter);
	   //	adapter->fe2 = &adapter->_fe2;
		//memcpy(adapter->fe2, adapter->fe, sizeof(struct dvb_frontend));
	   	/* terrestrial tuner */
		adapter->fe = dvb_attach(cxd2878_attach, &tbs6590se_cfg[adapter->nr], i2c);
		if (adapter->fe == NULL)
		     goto frontend_atach_fail;
		
		/* sattelite tuner */
		/* attach frontend */
	   	 memset(&m88rs6060_config, 0, sizeof(m88rs6060_config));
		 m88rs6060_config.fe = &adapter->fe2;
		 m88rs6060_config.clk = 27000000;
		 m88rs6060_config.i2c_wr_max = 65;
		 m88rs6060_config.ts_mode = MtFeTsOutMode_Parallel;
		 m88rs6060_config.ts_pinswitch = 0;
		 m88rs6060_config.HAS_CI = 0;
		 m88rs6060_config.SetCIClock= NULL;
		 m88rs6060_config.envelope_mode = 0;
		 m88rs6060_config.demod_adr = 0x69; 
		 m88rs6060_config.disable_22k = 0;
		 m88rs6060_config.tuner_adr = 0x2c;
		 m88rs6060_config.repeater_value = 0x12;
		 m88rs6060_config.num = adapter->nr;
		 m88rs6060_config.read_properties = ecp3_spi_read;
		 m88rs6060_config.write_properties = ecp3_spi_write;
		 m88rs6060_config.read_eeprom = ecp3_eeprom_read;
		 m88rs6060_config.write_eeprom = ecp3_eeprom_write;
		 m88rs6060_config.RF_switch = RF_switch; 
		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "m88rs6060", I2C_NAME_SIZE);
		info.addr = m88rs6060_config.demod_adr;
		info.platform_data = &m88rs6060_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
		    goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
		    i2c_unregister_device(client_demod);
		    goto frontend_atach_fail;
		}			
		adapter->i2c_client_demod = client_demod;
	
		tbsecp3_ca_init(adapter, adapter->nr);
	   	break;
	   case TBSECP3_BOARD_TBS6504H:
	   	 tbs_octuples_reset_demod(adapter);
	   	 set_mac_address(adapter);
	   	 
	   	if(adapter->nr<4){ //for tuner#0~#3
	   	 memset(&m88rs6060_config, 0, sizeof(m88rs6060_config));
		 m88rs6060_config.fe = &adapter->fe;
		 m88rs6060_config.clk = 27000000;
		 m88rs6060_config.i2c_wr_max = 65;
		 m88rs6060_config.ts_mode = MtFeTsOutMode_Parallel;
		 m88rs6060_config.ts_pinswitch = 0;
		 m88rs6060_config.HAS_CI = 0;
		 m88rs6060_config.SetCIClock= NULL;
		 m88rs6060_config.envelope_mode = 0;
		 m88rs6060_config.demod_adr = (adapter->nr%2)?0x6B:0x69; 
		 m88rs6060_config.disable_22k = 0;
		 m88rs6060_config.tuner_adr = 0x2c;
		 m88rs6060_config.repeater_value = 0x12;
		 m88rs6060_config.num = adapter->nr;
		 m88rs6060_config.read_properties = ecp3_spi_read;
		 m88rs6060_config.write_properties = ecp3_spi_write;
		 m88rs6060_config.read_eeprom = ecp3_eeprom_read;
		 m88rs6060_config.write_eeprom = ecp3_eeprom_write;
		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "m88rs6060", I2C_NAME_SIZE);
		info.addr = m88rs6060_config.demod_adr;
		info.platform_data = &m88rs6060_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
				goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
				i2c_unregister_device(client_demod);
					goto frontend_atach_fail;
					}
		adapter->i2c_client_demod = client_demod;
		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
			    dev_warn(&dev->pci_dev->dev,
			    			    "error attaching lnb control on adapter %d\n",
							    adapter->nr);
			}
	   	}else{
   	
	   	adapter->fe = dvb_attach(cxd2878_attach, &tbs6504h_cfg[adapter->nr%2], i2c);
	   	if (adapter->fe == NULL)
		    goto frontend_atach_fail;
	   	}
	   break;
	   case TBSECP3_BOARD_TBS6522H:
	   	if(adapter->nr<2){ //for tuner0/1 dvbt/c/isdbt/atsc
	   		adapter->fe = dvb_attach(cxd2878_attach, &cxd6802_parallel_cfg, i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;
	   	}else{ //for tuner2/3 dvbs/s2
	   	 memset(&m88rs6060_config, 0, sizeof(m88rs6060_config));
		 m88rs6060_config.fe = &adapter->fe;
		 m88rs6060_config.clk = 27000000;
		 m88rs6060_config.i2c_wr_max = 65;
		 m88rs6060_config.ts_mode = MtFeTsOutMode_Parallel;
		 m88rs6060_config.ts_pinswitch = 0;
		 m88rs6060_config.HAS_CI = 0;
		 m88rs6060_config.SetCIClock= NULL;
		 m88rs6060_config.envelope_mode = 0;
		 m88rs6060_config.demod_adr = 0x69; 
		 m88rs6060_config.disable_22k = 0;
		 m88rs6060_config.tuner_adr = 0x2c;
		 m88rs6060_config.repeater_value = 0x12;
		 m88rs6060_config.num = adapter->nr;
		 m88rs6060_config.read_properties = ecp3_spi_read;
		 m88rs6060_config.write_properties = ecp3_spi_write;
		 m88rs6060_config.read_eeprom = ecp3_eeprom_read;
		 m88rs6060_config.write_eeprom = ecp3_eeprom_write;
		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "m88rs6060", I2C_NAME_SIZE);
		info.addr = m88rs6060_config.demod_adr;
		info.platform_data = &m88rs6060_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
				goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
				i2c_unregister_device(client_demod);
					goto frontend_atach_fail;
					}
		adapter->i2c_client_demod = client_demod;
		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
			    dev_warn(&dev->pci_dev->dev,
			    			    "error attaching lnb control on adapter %d\n",
							    adapter->nr);
			}		 
	   	}
	   break;
	   case TBSECP3_BOARD_TBS6209SE:
	   		tbs_octuples_reset_demod(adapter);
	   		set_mac_address(adapter);		
	   		adapter->fe = dvb_attach(cxd2878_attach, &tbs6209se_cfg[(adapter->nr)%4], i2c);

		if (adapter->fe == NULL)
		    goto frontend_atach_fail;
	   		break;	
	   case TBSECP3_BOARD_TBS7230:
	   case TBSECP3_BOARD_TBS6290TD:
	   	   adapter->fe = dvb_attach(cxd2878_attach, &tbsserial_cfg, i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;
		 if(dev->info->board_id==TBSECP3_BOARD_TBS6290TD)
		 	tbsecp3_ca_init(adapter, adapter->nr);
		 
	   break;
	   case TBSECP3_BOARD_TBS6281TD:
	   case TBSECP3_BOARD_TBS6205SE:
	   	adapter->fe = dvb_attach(cxd2878_attach, &cxd6802_parallel_cfg, i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

	   break;
	   case TBSECP3_BOARD_TBS6910SE:
	   case TBSECP3_BOARD_TBS6904SE:
	   case TBSECP3_BOARD_TBS6902SE:
	   case TBSECP3_BOARD_TBS7901:
	   case TBSECP3_BOARD_TBS6909SE:
	   	if(dev->info->board_id == TBSECP3_BOARD_TBS6909SE){
	   		tbs_octuples_reset_demod(adapter);
	   		set_mac_address(adapter);
	   	}
	   
		 memset(&m88rs6060_config, 0, sizeof(m88rs6060_config));
		 m88rs6060_config.fe = &adapter->fe;
		 m88rs6060_config.clk = 27000000;
		 m88rs6060_config.i2c_wr_max = 65;
		 if((dev->info->board_id == TBSECP3_BOARD_TBS6910SE)||
		 (dev->info->board_id == TBSECP3_BOARD_TBS6909SE)){
		 	
			 m88rs6060_config.ts_mode = MtFeTsOutMode_Serial;
			 m88rs6060_config.ts_pinswitch = 0;

		 }else{
			 m88rs6060_config.ts_mode = MtFeTsOutMode_Parallel;
			 m88rs6060_config.ts_pinswitch = 1;
			 m88rs6060_config.ts_autoclock = 1;
		 	}
		 
		 if(dev->info->board_id == TBSECP3_BOARD_TBS6910SE){
		 	 m88rs6060_config.HAS_CI = 1;
	
		 	if(tbs_FPGA_fireware_info(adapter)==0x22082220){
				if(!ciclock)
					m88rs6060_config.HAS_CI = 0;
				
				m88rs6060_config.clk_port = adapter->nr;
				}
			else
				m88rs6060_config.clk_port = 0;				
		 	 	
			 m88rs6060_config.SetTimes= Set_TSsamplingtimes;
			 m88rs6060_config.SetCIClock= SetCIClock;
		 }else{
		 	 m88rs6060_config.HAS_CI = 0;
			 m88rs6060_config.SetCIClock= NULL;

		 }	
		
		 m88rs6060_config.envelope_mode = 0;
		 if(dev->info->board_id == TBSECP3_BOARD_TBS6909SE)
		 	m88rs6060_config.demod_adr = (adapter->nr%2)?0x6B:0x69;
		 else
		       m88rs6060_config.demod_adr = 0x69;
		
		if(m88rs6060_config.demod_adr!=0x6B)
			m88rs6060_config.disable_22k = 0;
		else
			m88rs6060_config.disable_22k = 1;
			     
		 m88rs6060_config.tuner_adr = 0x2c;
		 m88rs6060_config.repeater_value = 0x12;
		 m88rs6060_config.num = adapter->nr;
		 m88rs6060_config.read_properties = ecp3_spi_read;
		 m88rs6060_config.write_properties = ecp3_spi_write;
		 m88rs6060_config.read_eeprom = ecp3_eeprom_read;
		 m88rs6060_config.write_eeprom = ecp3_eeprom_write;
		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "m88rs6060", I2C_NAME_SIZE);
		info.addr = m88rs6060_config.demod_adr;
		info.platform_data = &m88rs6060_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
				goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
				i2c_unregister_device(client_demod);
					goto frontend_atach_fail;
					}
		adapter->i2c_client_demod = client_demod;
		//if(m88rs6060_config.demod_adr!=0x6B){ 
		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
			    dev_warn(&dev->pci_dev->dev,
			    			    "error attaching lnb control on adapter %d\n",
							    adapter->nr);
			}		    
		//}
		 if(dev->info->board_id == TBSECP3_BOARD_TBS6910SE){
			tbsecp3_ca_init(adapter, adapter->nr);
		 }
		 break; 
	   case TBSECP3_BOARD_TBS6508:
		/* attach demod */
		memset(&si2183_config, 0, sizeof(si2183_config));
		si2183_config.i2c_adapter = &i2c;
		si2183_config.fe = &adapter->fe;
		si2183_config.ts_mode = SI2183_TS_PARALLEL;
		si2183_config.ts_clock_gapped = true;
		si2183_config.rf_in = adapter->nr;
		si2183_config.RF_switch = NULL;
		si2183_config.read_properties = ecp3_spi_read;
		si2183_config.write_properties = ecp3_spi_write;
	
		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2183", I2C_NAME_SIZE);
		info.addr = (adapter->nr %2) ? 0x67 : 0x64;
		si2183_config.agc_mode = (adapter->nr %2)? 0x5 : 0x4;
		info.platform_data = &si2183_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
			goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
			i2c_unregister_device(client_demod);
			goto frontend_atach_fail;
		}
		adapter->i2c_client_demod = client_demod;
	
		/* dvb core doesn't support 2 tuners for 1 demod so
		  we split the adapter in 2 frontends */
		adapter->fe2 = &adapter->_fe2;
		memcpy(adapter->fe2, adapter->fe, sizeof(struct dvb_frontend));
	
	
		/* terrestrial tuner */
		memset(adapter->fe->ops.delsys, 0, MAX_DELSYS);
		adapter->fe->ops.delsys[0] = SYS_DVBT;
		adapter->fe->ops.delsys[1] = SYS_DVBT2;
		adapter->fe->ops.delsys[2] = SYS_DVBC_ANNEX_A;
		adapter->fe->ops.delsys[3] = SYS_ISDBT;
		adapter->fe->ops.delsys[4] = SYS_DVBC_ANNEX_B;
	
		/* attach tuner */
		memset(&si2157_config, 0, sizeof(si2157_config));
		si2157_config.fe = adapter->fe;
		si2157_config.if_port = 1;
	
		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2157", I2C_NAME_SIZE);
		info.addr = (adapter->nr %2) ? 0x60 : 0x61;
		info.platform_data = &si2157_config;
		request_module(info.type);
		client_tuner = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_tuner))
			goto frontend_atach_fail;
	
		if (!try_module_get(client_tuner->dev.driver->owner)) {
			i2c_unregister_device(client_tuner);
			goto frontend_atach_fail;
		}
		adapter->i2c_client_tuner = client_tuner;
	
	
		/* sattelite tuner */
		memset(adapter->fe2->ops.delsys, 0, MAX_DELSYS);
		adapter->fe2->ops.delsys[0] = SYS_DVBS;
		adapter->fe2->ops.delsys[1] = SYS_DVBS2;
		adapter->fe2->ops.delsys[2] = SYS_DSS;
		adapter->fe2->id = 1;
		if (dvb_attach(rda5816_attach, adapter->fe2, &rda5816_cfg[(adapter->nr %2)],
				i2c) == NULL) {
			dev_err(&dev->pci_dev->dev,
				"frontend %d tuner attach failed\n",
				adapter->nr);
			goto frontend_atach_fail;
		}
		if (tbsecp3_attach_sec(adapter, adapter->fe2) == NULL) {
			dev_warn(&dev->pci_dev->dev,
				"error attaching lnb control on adapter %d\n",
				adapter->nr);
		}
		break;		
	case TBSECP3_BOARD_TBS6904X:
		memset(&si2183_config, 0, sizeof(si2183_config));
		si2183_config.i2c_adapter = &i2c;
		si2183_config.fe = &adapter->fe;
		si2183_config.ts_mode =  SI2183_TS_PARALLEL ;
		si2183_config.ts_clock_gapped = true;
		si2183_config.rf_in = adapter->nr;
		si2183_config.RF_switch = NULL;
		si2183_config.start_clk_mode = 1;
		si2183_config.read_properties = ecp3_spi_read;
		si2183_config.write_properties = ecp3_spi_write;
		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2183", I2C_NAME_SIZE);

		info.addr = (adapter->nr %2)? 0x64 : 0x67;
		 si2183_config.agc_mode = (adapter->nr%2)? 0x4 : 0x5;
	
		info.platform_data = &si2183_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
		    goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
		    i2c_unregister_device(client_demod);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_demod = client_demod;

		memset(adapter->fe->ops.delsys, 0, MAX_DELSYS);
		adapter->fe->ops.delsys[0] = SYS_DVBS;
		adapter->fe->ops.delsys[1] = SYS_DVBS2;
		adapter->fe->ops.delsys[2] = SYS_DSS;
		
		if (dvb_attach(av201x_attach, adapter->fe, &tbs6522_av201x_cfg[(adapter->nr%2)],
			    i2c) == NULL) {
		    dvb_frontend_detach(adapter->fe);
		    adapter->fe = NULL;
		    dev_err(&dev->pci_dev->dev,
			    "frontend %d tuner attach failed\n",
			    adapter->nr);
		    goto frontend_atach_fail;
		}


		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
		    dev_warn(&dev->pci_dev->dev,
			    "error attaching lnb control on adapter %d\n",
			    adapter->nr);
		}

		break;
	case TBSECP3_BOARD_TBS6308:
		adapter->fe = dvb_attach(tas2971_attach, &tbs6308_demod_cfg, i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;
		    if(adapter->nr <4)
		    {
			    if(tbs6304_read_mac(adapter)==0)
				    tbs6304_read_mac(adapter);
		    }
		    else
		    {
			    if(tbs6308_read_mac_ext(adapter)==0)
				    tbs6308_read_mac_ext(adapter);//try again
		    }
		break;
	case TBSECP3_BOARD_TBS6308X:
		adapter->fe = dvb_attach(tas2971_attach, &tbs6308_demod_cfg, i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;
		  
		break;
	case TBSECP3_BOARD_TBS6312X:
		adapter->fe = dvb_attach(tas2971_attach, &tbs6308_demod_cfg, i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;
		  
		break;
	case TBSECP3_BOARD_TBS6304:
		adapter->fe = dvb_attach(tas2971_attach, &tbs6304_demod_cfg[adapter->nr], i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;
		if(tbs6304_read_mac(adapter)==0)
		    tbs6304_read_mac(adapter);
		break;
	case TBSECP3_BOARD_TBS6302SE:
		adapter->fe = dvb_attach(tas2971_attach, &tbs6302se_demod_cfg[adapter->nr], i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;
		if(tbs6302se_read_mac(adapter)==0)
		    tbs6302se_read_mac(adapter);
		break;
	case TBSECP3_BOARD_TBS6301:
		adapter->fe = dvb_attach(tas2971_attach, &tbs6301_demod_cfg, i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

		tbs6301_read_mac(adapter);
		break;
	case TBSECP3_BOARD_TBS6301SE:
		adapter->fe = dvb_attach(tas2971_attach, &tbs6301se_demod_cfg, i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

		break;
	case TBSECP3_BOARD_TBS6302X:
	case TBSECP3_BOARD_TBS6302T:
	case TBSECP3_BOARD_TBS6322:
	case TBSECP3_BOARD_TBS6302RV:
		adapter->fe = dvb_attach(tas2971_attach, &tbs6302se_demod_cfg[adapter->nr], i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

		break;
	case TBSECP3_BOARD_TBS6304X:
	case TBSECP3_BOARD_TBS6304T:
	case TBSECP3_BOARD_TBS6324:
	case TBSECP3_BOARD_TBS6304RV:
		adapter->fe = dvb_attach(tas2971_attach, &tbs6304x_demod_cfg, i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

		break;

	case TBSECP3_BOARD_TBS690a:
	case TBSECP3_BOARD_TBS6331:
		adapter->fe = dvb_attach(tas2971_attach, &tbs6304_demod_cfg[adapter->nr], i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

		// init asi
		int regdata;
		u8 mpbuf[4];
		mpbuf[0] = adapter->nr; //0--3 select value
		tbs_write( TBSECP3_GPIO_BASE, 0x34 , *(u32 *)&mpbuf[0]); // select chip : 13*8 =104=0x68 select address
		//u32 mpbuf = adapter->nr;
		//tbs_write( TBSECP3_GPIO_BASE, 0x34 , mpbuf); // select chip : 13*8 =104=0x68 select address
		// ==***********************************************************************

		asi_chip_reset(dev,ASI0_BASEADDRESS);  //asi chip reset;

		mpbuf[0] = 1; //active spi bus from "z"
		tbs_write( ASI0_BASEADDRESS, ASI_SPI_ENABLE, *(u32 *)&mpbuf[0]);

		regdata = asi_read16bit(dev,ASI0_BASEADDRESS,0x24);
		 printk("asi card read 0x24 = %x\n", regdata);
		//asi_write16bit(dev,ASI0_BASEADDRESS,0x24,3);	 
		//regdata = asi_read16bit(dev,ASI0_BASEADDRESS, 0x24);

		mpbuf[0] = 0; //spi disable, enter "z" state;
		tbs_write( ASI0_BASEADDRESS, ASI_SPI_ENABLE, *(u32 *)&mpbuf[0]);

		//==****************************************************************************************
		// ~~init asi
		break;

	case TBSECP3_BOARD_TBS6514:
	
		memset(&gx1503_config,0,sizeof(gx1503_config));
		unsigned char ver=tbsecp3_get_hwver(adapter);
		if(ver==0x32){
			dev->info->eeprom_i2c = 2;
			if(adapter->nr==0)
				set_mac_address(adapter);
			}
		 

		gx1503_config.i2c_adapter =&i2c;
		gx1503_config.fe = &adapter->fe;
		gx1503_config.clk_freq = 30400;//KHZ
		if(ver==0x32)
			gx1503_config.ts_config = 1;
		else
			gx1503_config.ts_config = 0;
			
		gx1503_config.ts_mode = 1;	
		gx1503_config.i2c_wr_max = 8;

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "gx1503", I2C_NAME_SIZE);
		info.addr = 0x30;
		info.platform_data = &gx1503_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c,&info);
		if(!i2c_client_has_driver(client_demod))
		    goto frontend_atach_fail;

		if (!try_module_get(client_demod->dev.driver->owner)) {
		    i2c_unregister_device(client_demod);
		    goto frontend_atach_fail;
		}

		adapter->i2c_client_demod = client_demod;
		
		if(ver==0x32)
		{
			if (dvb_attach(r850_attach, adapter->fe, &r850_config,
			i2c) == NULL) {
		   	 dvb_frontend_detach(adapter->fe);
		   	 adapter->fe = NULL;
		   	 dev_err(&dev->pci_dev->dev,
			    "frontend %d tuner attach failed\n",
			    adapter->nr);
		    goto frontend_atach_fail;
			}
		 }else{		
			/*attach tuner*/
			memset(&si2157_config, 0, sizeof(si2157_config));
			si2157_config.fe = adapter->fe;
			si2157_config.if_port = 0;

			memset(&info, 0, sizeof(struct i2c_board_info));
			strscpy(info.type, "si2157", I2C_NAME_SIZE);
			info.addr = 0x60;
			info.platform_data = &si2157_config;
			request_module(info.type);
			client_tuner = i2c_new_client_device(i2c, &info);
			if (!i2c_client_has_driver(client_tuner))
			    goto frontend_atach_fail;

			if (!try_module_get(client_tuner->dev.driver->owner)) {
			    i2c_unregister_device(client_tuner);
			    goto frontend_atach_fail;
			}
			adapter->i2c_client_tuner = client_tuner;
		}
		break;

	case TBSECP3_BOARD_TBS6814:
		memset(&mtv23x_config, 0, sizeof(mtv23x_config));
		mtv23x_config.fe = &adapter->fe;
		mtv23x_config.clk_freq = 32000;
		mtv23x_config.ts_mode  = 6;
		mtv23x_config.i2c_wr_max = 32;

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "mtv23x", I2C_NAME_SIZE);
		info.addr = (adapter->nr%2)? 0x44 : 0x43;
		info.platform_data = &mtv23x_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
		    goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
		    i2c_unregister_device(client_demod);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_demod = client_demod;
		break;

	case TBSECP3_BOARD_TBS6209:
		/* attach demod */
		memset(&si2183_config, 0, sizeof(si2183_config));
		si2183_config.i2c_adapter = &i2c;
		si2183_config.fe = &adapter->fe;
		si2183_config.ts_mode = SI2183_TS_SERIAL;
		si2183_config.ts_clock_gapped = true;
		si2183_config.rf_in = adapter->nr;
		si2183_config.RF_switch = NULL;
		si2183_config.read_properties = ecp3_spi_read;
		si2183_config.write_properties = ecp3_spi_write;
			    
		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2183", I2C_NAME_SIZE);
		info.addr = (adapter->nr%2)? 0x67 : 0x64;
		si2183_config.agc_mode = (adapter->nr%2)? 0x5 : 0x4;
		info.platform_data = &si2183_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
		    goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
		    i2c_unregister_device(client_demod);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_demod = client_demod;

		/* terrestrial tuner */
		memset(adapter->fe->ops.delsys, 0, MAX_DELSYS);
		adapter->fe->ops.delsys[0] = SYS_DVBT;
		adapter->fe->ops.delsys[1] = SYS_DVBT2;
		adapter->fe->ops.delsys[2] = SYS_DVBC_ANNEX_A;
		adapter->fe->ops.delsys[3] = SYS_ISDBT;
		adapter->fe->ops.delsys[4] = SYS_DVBC_ANNEX_B;

		/* attach tuner */
		memset(&si2157_config, 0, sizeof(si2157_config));
		si2157_config.fe = adapter->fe;
		si2157_config.if_port = 1;

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2157", I2C_NAME_SIZE);
		info.addr = (adapter->nr %2)? 0x60 : 0x63;
		info.platform_data = &si2157_config;
		request_module(info.type);
		client_tuner = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_tuner))
		    goto frontend_atach_fail;

		if (!try_module_get(client_tuner->dev.driver->owner)) {
		    i2c_unregister_device(client_tuner);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_tuner = client_tuner;
		break;

	case TBSECP3_BOARD_TBS6704:
		/* attach demod */
	adapter->fe = dvb_attach(mndmd_attach, &tbs6704_cfg, i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;
		break;

	case TBSECP3_BOARD_TBS6205:
	case TBSECP3_BOARD_TBS6281SE:
		/* attach demod */
		memset(&si2168_config, 0, sizeof(si2168_config));
		si2168_config.i2c_adapter = &i2c;
		si2168_config.fe = &adapter->fe;
		si2168_config.ts_mode = SI2168_TS_PARALLEL;
		si2168_config.ts_clock_gapped = true;

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2168", I2C_NAME_SIZE);
		info.addr = 0x64;
		info.platform_data = &si2168_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
		    goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
		    i2c_unregister_device(client_demod);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_demod = client_demod;

		/* attach tuner */
		memset(&si2157_config, 0, sizeof(si2157_config));
		si2157_config.fe = adapter->fe;
		si2157_config.if_port = 1;

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2157", I2C_NAME_SIZE);
		info.addr = 0x60;
		info.platform_data = &si2157_config;
		request_module(info.type);
		client_tuner = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_tuner))
		    goto frontend_atach_fail;

		if (!try_module_get(client_tuner->dev.driver->owner)) {
		    i2c_unregister_device(client_tuner);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_tuner = client_tuner;
		break;

	case TBSECP3_BOARD_TBS6290SE:
		/* attach demod */
		memset(&si2168_config, 0, sizeof(si2168_config));
		si2168_config.i2c_adapter = &i2c;
		si2168_config.fe = &adapter->fe;
		si2168_config.ts_mode = SI2168_TS_SERIAL;//zc2016/07/20
		si2168_config.ts_clock_gapped = true;
		si2168_config.ts_clock_inv=0;//zc2016/07/20

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2168", I2C_NAME_SIZE);
		info.addr = 0x64;
		info.platform_data = &si2168_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
		    goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
		    i2c_unregister_device(client_demod);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_demod = client_demod;

		/* attach tuner */
		memset(&si2157_config, 0, sizeof(si2157_config));
		si2157_config.fe = adapter->fe;
		si2157_config.if_port = 1;

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2157", I2C_NAME_SIZE);
		info.addr = 0x60;
		info.platform_data = &si2157_config;
		request_module(info.type);
		client_tuner = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_tuner))
		    goto frontend_atach_fail;

		if (!try_module_get(client_tuner->dev.driver->owner)) {
		    i2c_unregister_device(client_tuner);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_tuner = client_tuner;
		tbsecp3_ca_init(adapter, adapter->nr);
		break;

	case TBSECP3_BOARD_TBS6522:
	case TBSECP3_BOARD_TBS6504:
		/* attach demod */
		memset(&si2183_config, 0, sizeof(si2183_config));
		si2183_config.i2c_adapter = &i2c;
		si2183_config.fe = &adapter->fe;
		si2183_config.ts_mode = SI2183_TS_PARALLEL;
		si2183_config.ts_clock_gapped = true;
		si2183_config.rf_in = adapter->nr;
		si2183_config.RF_switch = NULL;
		si2183_config.read_properties = ecp3_spi_read;
		si2183_config.write_properties = ecp3_spi_write;

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2183", I2C_NAME_SIZE);
		info.addr = (adapter->nr %2) ? 0x64 : 0x67;
		si2183_config.agc_mode = (adapter->nr %2)? 0x4 : 0x5;
		info.platform_data = &si2183_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
		    goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
		    i2c_unregister_device(client_demod);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_demod = client_demod;

		/* dvb core doesn't support 2 tuners for 1 demod so
		  we split the adapter in 2 frontends */
		adapter->fe2 = &adapter->_fe2;
		memcpy(adapter->fe2, adapter->fe, sizeof(struct dvb_frontend));


		/* terrestrial tuner */
		memset(adapter->fe->ops.delsys, 0, MAX_DELSYS);
		adapter->fe->ops.delsys[0] = SYS_DVBT;
		adapter->fe->ops.delsys[1] = SYS_DVBT2;
		adapter->fe->ops.delsys[2] = SYS_DVBC_ANNEX_A;
		adapter->fe->ops.delsys[3] = SYS_ISDBT;
		adapter->fe->ops.delsys[4] = SYS_DVBC_ANNEX_B;

		/* attach tuner */
		memset(&si2157_config, 0, sizeof(si2157_config));
		si2157_config.fe = adapter->fe;
		si2157_config.if_port = 1;

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2157", I2C_NAME_SIZE);
		info.addr = (adapter->nr %2) ? 0x61 : 0x60;
		info.platform_data = &si2157_config;
		request_module(info.type);
		client_tuner = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_tuner))
		    goto frontend_atach_fail;

		if (!try_module_get(client_tuner->dev.driver->owner)) {
		    i2c_unregister_device(client_tuner);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_tuner = client_tuner;


		/* sattelite tuner */
		memset(adapter->fe2->ops.delsys, 0, MAX_DELSYS);
		adapter->fe2->ops.delsys[0] = SYS_DVBS;
		adapter->fe2->ops.delsys[1] = SYS_DVBS2;
		adapter->fe2->ops.delsys[2] = SYS_DSS;
		adapter->fe2->id = 1;
		if (dvb_attach(av201x_attach, adapter->fe2, &tbs6522_av201x_cfg[(adapter->nr %2)],
			    i2c) == NULL) {
		    dev_err(&dev->pci_dev->dev,
			    "frontend %d tuner attach failed\n",
			    adapter->nr);
		    goto frontend_atach_fail;
		}
		if (tbsecp3_attach_sec(adapter, adapter->fe2) == NULL) {
		    dev_warn(&dev->pci_dev->dev,
			    "error attaching lnb control on adapter %d\n",
			    adapter->nr);
		}
		break;

	case TBSECP3_BOARD_TBS6528:
	case TBSECP3_BOARD_TBS6590:
		/* attach demod */
		memset(&si2183_config, 0, sizeof(si2183_config));
		si2183_config.i2c_adapter = &i2c;
		si2183_config.fe = &adapter->fe;
		si2183_config.ts_mode = pci->subsystem_vendor==0x6528 ? SI2183_TS_PARALLEL : SI2183_TS_SERIAL;
		si2183_config.ts_clock_gapped = true;
		si2183_config.rf_in = adapter->nr;
		si2183_config.RF_switch = RF_switch;
		si2183_config.read_properties = ecp3_spi_read;
		si2183_config.write_properties = ecp3_spi_write;

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2183", I2C_NAME_SIZE);
		if(pci->subsystem_vendor==0x6528)
		{
		    info.addr = 0x67;
		    si2183_config.agc_mode = 0x5 ;
		}
		else{
		    info.addr = adapter->nr ? 0x67 : 0x64;
		    si2183_config.agc_mode = adapter->nr? 0x5 : 0x4;
		}
		info.platform_data = &si2183_config;
		request_module(info.type);
		client_demod = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_demod))
		    goto frontend_atach_fail;
		if (!try_module_get(client_demod->dev.driver->owner)) {
		    i2c_unregister_device(client_demod);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_demod = client_demod;

		/* dvb core doesn't support 2 tuners for 1 demod so
		  we split the adapter in 2 frontends */
		adapter->fe2 = &adapter->_fe2;
		memcpy(adapter->fe2, adapter->fe, sizeof(struct dvb_frontend));


		/* terrestrial tuner */
		memset(adapter->fe->ops.delsys, 0, MAX_DELSYS);
		adapter->fe->ops.delsys[0] = SYS_DVBT;
		adapter->fe->ops.delsys[1] = SYS_DVBT2;
		adapter->fe->ops.delsys[2] = SYS_DVBC_ANNEX_A;
		adapter->fe->ops.delsys[3] = SYS_ISDBT;
		adapter->fe->ops.delsys[4] = SYS_DVBC_ANNEX_B;

		/* attach tuner */
		memset(&si2157_config, 0, sizeof(si2157_config));
		si2157_config.fe = adapter->fe;
		si2157_config.if_port = 1;

		memset(&info, 0, sizeof(struct i2c_board_info));
		strscpy(info.type, "si2157", I2C_NAME_SIZE);
		if(pci->subsystem_vendor==0x6528)info.addr = 0x61;
		else
		    info.addr = adapter->nr ? 0x61 : 0x60;

		info.platform_data = &si2157_config;
		request_module(info.type);
		client_tuner = i2c_new_client_device(i2c, &info);
		if (!i2c_client_has_driver(client_tuner))
		    goto frontend_atach_fail;

		if (!try_module_get(client_tuner->dev.driver->owner)) {
		    i2c_unregister_device(client_tuner);
		    goto frontend_atach_fail;
		}
		adapter->i2c_client_tuner = client_tuner;


		/* sattelite tuner */
		memset(adapter->fe2->ops.delsys, 0, MAX_DELSYS);
		adapter->fe2->ops.delsys[0] = SYS_DVBS;
		adapter->fe2->ops.delsys[1] = SYS_DVBS2;
		adapter->fe2->ops.delsys[2] = SYS_DSS;
		adapter->fe2->id = 1;
		if(pci->subsystem_vendor==0x6528)
		{
		    if (dvb_attach(av201x_attach, adapter->fe2, &tbs6522_av201x_cfg[1],
				i2c) == NULL) {
			dev_err(&dev->pci_dev->dev,
				"frontend %d tuner attach failed\n",
				adapter->nr);
			goto frontend_atach_fail;
		    }
		}
		else{
		    if (dvb_attach(av201x_attach, adapter->fe2, &tbs6522_av201x_cfg[adapter->nr],
				i2c) == NULL) {
			dev_err(&dev->pci_dev->dev,
				"frontend %d tuner attach failed\n",
				adapter->nr);
			goto frontend_atach_fail;
		    }
		}
		if (tbsecp3_attach_sec(adapter, adapter->fe2) == NULL) {
		    dev_warn(&dev->pci_dev->dev,
			    "error attaching lnb control on adapter %d\n",
			    adapter->nr);
		}

		tbsecp3_ca_init(adapter, adapter->nr);
		break;

	case TBSECP3_BOARD_TBS6902:
		if(pci->subsystem_device!=0x0003){
			adapter->fe = dvb_attach(tas2101_attach, &tbs6902_demod_cfg[adapter->nr], i2c);

		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

		if (dvb_attach(av201x_attach, adapter->fe, &tbs6902_av201x_cfg,
			    tas2101_get_i2c_adapter(adapter->fe, 2)) == NULL) {
		    dvb_frontend_detach(adapter->fe);
		    adapter->fe = NULL;
		    dev_err(&dev->pci_dev->dev,
			    "frontend %d tuner attach failed\n",
			    adapter->nr);
		    goto frontend_atach_fail;
		}

		}else{
			adapter->fe = dvb_attach(gx1133_attach, &tbs6902_gx1133_cfg[adapter->nr], i2c);

			if (adapter->fe == NULL)
				goto frontend_atach_fail;
			
			if (dvb_attach(av201x_attach, adapter->fe, &tbs6902_av201x_cfg,
					gx1133_get_i2c_adapter(adapter->fe, 2)) == NULL) {
				dvb_frontend_detach(adapter->fe);
				adapter->fe = NULL;
				dev_err(&dev->pci_dev->dev,
					"frontend %d tuner attach failed\n",
					adapter->nr);
				goto frontend_atach_fail;
			}

		}


		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
		    dev_warn(&dev->pci_dev->dev,
			    "error attaching lnb control on adapter %d\n",
			    adapter->nr);
		}
		break;

	case TBSECP3_BOARD_TBS6903:
	case TBSECP3_BOARD_TBS6905:
	case TBSECP3_BOARD_TBS6908:
		adapter->fe = dvb_attach(stv091x_attach, i2c,
			&tbs6903_stv0910_cfg, adapter->nr & 1);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

		if (dvb_attach(stv6120_attach, adapter->fe, i2c, &tbs6903_stv6120_cfg, 1 - (adapter->nr & 1)) == NULL) {
		    dvb_frontend_detach(adapter->fe);
		    adapter->fe = NULL;
		    dev_err(&dev->pci_dev->dev,
			    "frontend %d tuner attach failed\n",
			    adapter->nr);
		    goto frontend_atach_fail;
		}
		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
		    dev_warn(&dev->pci_dev->dev,
			    "error attaching lnb control on adapter %d\n",
			    adapter->nr);
		}
		break;

	case TBSECP3_BOARD_TBS6904:
		adapter->fe = dvb_attach(tas2101_attach, &tbs6904_demod_cfg[adapter->nr], i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

		if (dvb_attach(av201x_attach, adapter->fe, &tbs6904_av201x_cfg,
			    tas2101_get_i2c_adapter(adapter->fe, 2)) == NULL) {
		    dvb_frontend_detach(adapter->fe);
		    adapter->fe = NULL;
		    dev_err(&dev->pci_dev->dev,
			    "frontend %d tuner attach failed\n",
			    adapter->nr);
		    goto frontend_atach_fail;
		}

		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
		    dev_warn(&dev->pci_dev->dev,
			    "error attaching lnb control on adapter %d\n",
			    adapter->nr);
		}
	    break;

	case TBSECP3_BOARD_TBS6909:
		/*
		  tmp = tbs_read(TBS_GPIO_BASE, 0x20);
		  printk("RD 0x20 = %x\n", tmp);
		  tbs_write(TBS_GPIO_BASE, 0x20, tmp & 0xfffe);
		  tmp = tbs_read(TBS_GPIO_BASE, 0x20);
		  printk("RD 0x20 = %x\n", tmp);

		  tmp = tbs_read(TBS_GPIO_BASE, 0x24);
		  printk("RD 0x24 = %x\n", tmp);
		  tbs_write(TBS_GPIO_BASE, 0x24, tmp & 0xfffc);
		  tmp = tbs_read(TBS_GPIO_BASE, 0x24);
		  printk("RD 0x24 = %x\n", tmp);
		  */

		adapter->fe = dvb_attach(mxl58x_attach, i2c,
			&tbs6909_mxl58x_cfg, adapter->nr);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

		//	adapter->fe->ops.diseqc_send_master_cmd = max_send_master_cmd;
		//	adapter->fe->ops.diseqc_send_burst = max_send_burst;

		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
		    dev_warn(&dev->pci_dev->dev,
			    "error attaching lnb control on adapter %d\n",
			    adapter->nr);
		}
		break;

	case TBSECP3_BOARD_TBS6910:
		adapter->fe = dvb_attach(tas2101_attach, &tbs6910_demod_cfg[adapter->nr], i2c);
		if (adapter->fe == NULL)
		    goto frontend_atach_fail;

		if (dvb_attach(av201x_attach, adapter->fe, &tbs6910_av201x_cfg,
			    tas2101_get_i2c_adapter(adapter->fe, 2)) == NULL) {
		    dvb_frontend_detach(adapter->fe);
		    adapter->fe = NULL;
		    dev_err(&dev->pci_dev->dev,
			    "frontend %d tuner attach failed\n",
			    adapter->nr);
		    goto frontend_atach_fail;
		}
		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
		    dev_warn(&dev->pci_dev->dev,
			    "error attaching lnb control on adapter %d\n",
			    adapter->nr);
		}

		tbsecp3_ca_init(adapter, adapter->nr);
		break;
	case TBSECP3_BOARD_TBS6916:
		if(adapter->nr<8)
			adapter->fe = dvb_attach(stid135_attach, i2c,
					&tbs6916_stid135_cfg[0], adapter->nr, adapter->nr/2);
		else{
		
			adapter->nr -= 8;
			adapter->fe = dvb_attach(stid135_attach, i2c,
					&tbs6916_stid135_cfg[1], adapter->nr, adapter->nr/2);	
		}
	
		if (adapter->fe == NULL)
			goto frontend_atach_fail;
		break;
	case TBSECP3_BOARD_TBS6909X:
		if(pci->subsystem_device==0x0010)
			adapter->fe = dvb_attach(stid135_attach, i2c,
				&tbs6909x_stid135_cfg, adapter->nr, adapter->nr/2);
		else
			adapter->fe = dvb_attach(stid135_attach, i2c,
				&tbs6909x_V2_stid135_cfg, adapter->nr, adapter->nr/2); 	

		if (adapter->fe == NULL)
			goto frontend_atach_fail;
		break;

	case TBSECP3_BOARD_TBS6903X:
	case TBSECP3_BOARD_TBS6912:
		if(pci->subsystem_vendor==0x6912)
			adapter->fe = dvb_attach(stid135_attach, i2c,
					&tbs6912_stid135_cfg, adapter->nr ? 2 : 0, adapter->nr ? 3 : 0);
		else if(pci->subsystem_device==0x0021)
			adapter->fe = dvb_attach(stid135_attach, i2c,
				&tbs6903x_V2_stid135_cfg, adapter->nr ? 2 : 0, adapter->nr ? 3 : 0);
		else
			adapter->fe = dvb_attach(stid135_attach, i2c,
				&tbs6903x_stid135_cfg, adapter->nr ? 2 : 0, adapter->nr ? 3 : 0);

		if (adapter->fe == NULL)
			goto frontend_atach_fail;

		if (tbsecp3_attach_sec(adapter, adapter->fe) == NULL) {
			dev_warn(&dev->pci_dev->dev,
				"error attaching lnb control on adapter %d\n",
				adapter->nr);
		}
		if(pci->subsystem_vendor==0x6912)
			tbsecp3_ca_init(adapter, adapter->nr);
		
		break;

	default:
		dev_warn(&dev->pci_dev->dev, "unknonw card\n");
		return -ENODEV;
		break;
	}
	strscpy(adapter->fe->ops.info.name,dev->info->name,52);
	if (adapter->fe2)
		strscpy(adapter->fe2->ops.info.name,dev->info->name,52);
	return 0;

frontend_atach_fail:
	tbsecp3_i2c_remove_clients(adapter);
	if (adapter->fe != NULL)
	    dvb_frontend_detach(adapter->fe);
	adapter->fe = NULL;
	dev_err(&dev->pci_dev->dev, "TBSECP3 frontend %d attach failed\n",
		adapter->nr);

	return -ENODEV;
}

int tbsecp3_dvb_init(struct tbsecp3_adapter *adapter)
{
    struct tbsecp3_dev *dev = adapter->dev;
    struct dvb_adapter *adap = &adapter->dvb_adapter;
    struct dvb_demux *dvbdemux = &adapter->demux;
    struct dmxdev *dmxdev;
    struct dvb_frontend *fe;
    struct dmx_frontend *fe_hw;
    struct dmx_frontend *fe_mem;
    int ret;

    ret = dvb_register_adapter(adap, "TBSECP3 DVB Adapter",
            THIS_MODULE,
            &adapter->dev->pci_dev->dev,
            adapter_nr);
    if (ret < 0) {
        dev_err(&dev->pci_dev->dev, "error registering adapter\n");
        if (ret == -ENFILE)
            dev_err(&dev->pci_dev->dev,
                    "increase DVB_MAX_ADAPTERS (%d)\n",
                    DVB_MAX_ADAPTERS);
        return ret;
    }

    adap->priv = adapter;
    dvbdemux->priv = adapter;
    dvbdemux->filternum = 256;
    dvbdemux->feednum = 256;
    dvbdemux->start_feed = start_feed;
    dvbdemux->stop_feed = stop_feed;
    dvbdemux->write_to_decoder = NULL;
    dvbdemux->dmx.capabilities = (DMX_TS_FILTERING |
            DMX_SECTION_FILTERING |
            DMX_MEMORY_BASED_FILTERING);

    ret = dvb_dmx_init(dvbdemux);
    if (ret < 0) {
        dev_err(&dev->pci_dev->dev, "dvb_dmx_init failed\n");
        goto err0;
    }

    dmxdev = &adapter->dmxdev;

    dmxdev->filternum = 256;
    dmxdev->demux = &dvbdemux->dmx;
    dmxdev->capabilities = 0;

    ret = dvb_dmxdev_init(dmxdev, adap);
    if (ret < 0) {
        dev_err(&dev->pci_dev->dev, "dvb_dmxdev_init failed\n");
        goto err1;
    }

    fe_hw = &adapter->fe_hw;
    fe_mem = &adapter->fe_mem;

    fe_hw->source = DMX_FRONTEND_0;
    ret = dvbdemux->dmx.add_frontend(&dvbdemux->dmx, fe_hw);
    if ( ret < 0) {
        dev_err(&dev->pci_dev->dev, "dvb_dmx_init failed");
        goto err2;
    }

    fe_mem->source = DMX_MEMORY_FE;
    ret = dvbdemux->dmx.add_frontend(&dvbdemux->dmx, fe_mem);
    if (ret  < 0) {
        dev_err(&dev->pci_dev->dev, "dvb_dmx_init failed");
        goto err3;
    }

    ret = dvbdemux->dmx.connect_frontend(&dvbdemux->dmx, fe_hw);
    if (ret < 0) {
        dev_err(&dev->pci_dev->dev, "dvb_dmx_init failed");
        goto err4;
    }

    ret = dvb_net_init(adap, &adapter->dvbnet, adapter->dmxdev.demux);
    if (ret < 0) {
        dev_err(&dev->pci_dev->dev, "dvb_net_init failed");
        goto err5;
    }

    tbsecp3_frontend_attach(adapter);
    if (adapter->fe == NULL) {
        dev_err(&dev->pci_dev->dev, "frontend attach failed\n");
        ret = -ENODEV;
        goto err6;
    }

    if (adapter->fe && adapter->fe2 && swapfe) {
        fe = adapter->fe;
        adapter->fe = adapter->fe2;
        adapter->fe2 = fe;
    }

    ret = dvb_register_frontend(adap, adapter->fe);
    if (ret < 0) {
        dev_err(&dev->pci_dev->dev, "frontend register failed\n");
        goto err7;
    }

    if (adapter->fe2 != NULL) {
        ret = dvb_register_frontend(adap, adapter->fe2);
        if (ret < 0) {
            dev_err(&dev->pci_dev->dev, "frontend2 register failed\n");
        }
    }


    return ret;

err7:
    dvb_frontend_detach(adapter->fe);
err6:
    tbsecp3_release_sec(adapter->fe);

    dvb_net_release(&adapter->dvbnet);
err5:
    dvbdemux->dmx.close(&dvbdemux->dmx);
err4:
    dvbdemux->dmx.remove_frontend(&dvbdemux->dmx, fe_mem);
err3:
    dvbdemux->dmx.remove_frontend(&dvbdemux->dmx, fe_hw);
err2:
    dvb_dmxdev_release(dmxdev);
err1:
    dvb_dmx_release(dvbdemux);
err0:
    dvb_unregister_adapter(adap);
    return ret;
}

void tbsecp3_dvb_exit(struct tbsecp3_adapter *adapter)
{
    struct dvb_adapter *adap = &adapter->dvb_adapter;
    struct dvb_demux *dvbdemux = &adapter->demux;

    if (adapter->fe) {
        tbsecp3_ca_release(adapter);
        dvb_unregister_frontend(adapter->fe);
        tbsecp3_release_sec(adapter->fe);
        dvb_frontend_detach(adapter->fe);
        adapter->fe = NULL;

        if (adapter->fe2 != NULL) {
            dvb_unregister_frontend(adapter->fe2);
            tbsecp3_release_sec(adapter->fe2);
            dvb_frontend_detach(adapter->fe2);
            adapter->fe2 = NULL;
        }
    }
    dvb_net_release(&adapter->dvbnet);
    dvbdemux->dmx.close(&dvbdemux->dmx);
    dvbdemux->dmx.remove_frontend(&dvbdemux->dmx, &adapter->fe_mem);
    dvbdemux->dmx.remove_frontend(&dvbdemux->dmx, &adapter->fe_hw);
    dvb_dmxdev_release(&adapter->dmxdev);
    dvb_dmx_release(&adapter->demux);
    dvb_unregister_adapter(adap);
}
