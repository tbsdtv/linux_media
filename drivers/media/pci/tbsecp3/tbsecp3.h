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

#ifndef _TBSECP3_H_
#define _TBSECP3_H_

#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>

#include <media/dmxdev.h>
#include <media/dvbdev.h>
#include <media/dvb_demux.h>
#include <media/dvb_frontend.h>
#include <media/dvb_ringbuffer.h>
#include <media/dvb_ca_en50221.h>
#include <media/dvb_net.h>

#include "tbsecp3-regs.h"

#define TBSECP3_VID		0x544d
#define TBSECP3_PID		0x6178

#define TBSECP3_BOARD_TBS6205 	0
#define TBSECP3_BOARD_TBS6281SE	1
#define TBSECP3_BOARD_TBS6290SE	2
#define TBSECP3_BOARD_TBS6209	3
#define TBSECP3_BOARD_TBS6522 	4
#define TBSECP3_BOARD_TBS6528	5
#define TBSECP3_BOARD_TBS6590	6
#define TBSECP3_BOARD_TBS6902	7
#define TBSECP3_BOARD_TBS6903	8
#define TBSECP3_BOARD_TBS6904	9
#define TBSECP3_BOARD_TBS6905	10
#define TBSECP3_BOARD_TBS6908	11
#define TBSECP3_BOARD_TBS6909	12
#define TBSECP3_BOARD_TBS6910	13
#define TBSECP3_BOARD_TBS6704   14
#define TBSECP3_BOARD_TBS6814	15
#define TBSECP3_BOARD_TBS6514	16
#define TBSECP3_BOARD_TBS690a	17
#define TBSECP3_BOARD_TBS6301	18
#define TBSECP3_BOARD_TBS6304	19
#define TBSECP3_BOARD_TBS6308	20
#define TBSECP3_BOARD_TBS6903X	21
#define TBSECP3_BOARD_TBS6909X	22
#define TBSECP3_BOARD_TBS6904X 	23
#define TBSECP3_BOARD_TBS6912 	24
#define TBSECP3_BOARD_TBS6504	25
#define TBSECP3_BOARD_TBS6508	26
#define TBSECP3_BOARD_TBS6302SE	27
#define TBSECP3_BOARD_TBS6902SE 28
#define TBSECP3_BOARD_TBS6904SE 29
#define TBSECP3_BOARD_TBS6301SE 30
#define TBSECP3_BOARD_TBS6910SE 31
#define TBSECP3_BOARD_TBS7901   32
#define TBSECP3_BOARD_TBS6209SE 33
#define TBSECP3_BOARD_TBS7230 34
#define TBSECP3_BOARD_TBS6302X 35
#define TBSECP3_BOARD_TBS6302T 36
#define TBSECP3_BOARD_TBS6304X	37
#define TBSECP3_BOARD_TBS6290TD	38
#define TBSECP3_BOARD_TBS6281TD	39
#define TBSECP3_BOARD_TBS6205SE	40
#define TBSECP3_BOARD_TBS6909SE	41
#define TBSECP3_BOARD_TBS6304T	42
#define TBSECP3_BOARD_TBS6522H	43
#define TBSECP3_BOARD_TBS6504H	44
#define TBSECP3_BOARD_TBS6590SE	45
#define TBSECP3_BOARD_TBS6308X	46
#define TBSECP3_BOARD_TBS6916	47
#define TBSECP3_BOARD_TBS6312X	48
#define TBSECP3_BOARD_TBS6324	49
#define TBSECP3_BOARD_TBS6322	50
#define TBSECP3_BOARD_TBS6304RV 51
#define TBSECP3_BOARD_TBS6302RV	52
#define TBSECP3_BOARD_TBS6331	53
#define TBSECP3_BOARD_TBS6216   54

#define TBSECP3_MAX_ADAPTERS	(16)
#define TBSECP3_MAX_I2C_BUS	(8)

#define TBSECP3_GPIODEF_NONE	(0)
#define TBSECP3_GPIODEF_HIGH	(1)
#define TBSECP3_GPIODEF_LOW	(2)

#define TBSECP3_DMA_BUFFERS	16
#define TBSECP3_DMA_PRE_BUFFERS	2


struct tbsecp3_dev;


struct tbsecp3_gpio_pin {
	u8 lvl;
	u8 nr;
};

struct tbsecp3_gpio_config {
	struct tbsecp3_gpio_pin lnb_power;
	struct tbsecp3_gpio_pin lnb_voltage;
	struct tbsecp3_gpio_pin demod_reset;
};

struct tbsecp3_adap_config {
        u32 ts_in;
	u8 i2c_bus_nr;
	struct tbsecp3_gpio_config gpio;
};

struct tbsecp3_board {
	u16  board_id;
	char *name;
	int adapters;
	u32 i2c_speed;
	u8 eeprom_i2c;
	u8 eeprom_addr;
	struct tbsecp3_adap_config adap_config[16];
};

struct tbsecp3_i2c {
	struct tbsecp3_dev *dev;
	u32 base;

	struct i2c_adapter i2c_adap;
	struct i2c_client i2c_client;

	struct mutex lock;
	wait_queue_head_t wq;
	bool done;
};

struct tbsecp3_dma_channel {
	u32 base;
	dma_addr_t dma_addr;
	u32 page_size;
	u32 buffer_size;
	u32 buffer_pkts;
	u8 *buf[TBSECP3_DMA_BUFFERS + 1];
	u8 offset;
	u8 cnt;
	u8 next_buffer;
};

struct tbsecp3_ca {
	int nr;
	u32 base;
	struct dvb_ca_en50221 ca;

	struct tbsecp3_adapter *adapter;
	struct mutex lock;
	int status;
};

struct tbsecp3_adapter {
	int nr;
	struct tbsecp3_adap_config *cfg;

	/* parent device */
	struct tbsecp3_dev *dev;

	/* i2c */
	struct tbsecp3_i2c *i2c;
	struct i2c_client *i2c_client_demod;
	struct i2c_client *i2c_client_tuner;

	/* dvb */
	struct dvb_adapter dvb_adapter;
	struct dvb_frontend *fe;
	struct dvb_frontend *fe2;
	struct dvb_frontend _fe2;
	struct dvb_demux demux;
	struct dmxdev dmxdev;
	struct dvb_net dvbnet;
	struct dmx_frontend fe_hw;
	struct dmx_frontend fe_mem;
	int feeds;

	/* dma */
	spinlock_t adap_lock;
	struct tasklet_struct tasklet;
	struct tbsecp3_dma_channel dma;

	/* ca interface */
	struct tbsecp3_ca *tbsca;
};

struct tbsecp3_dev {
	struct tbsecp3_board *info;

	/* pcie */
	struct pci_dev *pci_dev;
	void __iomem *lmmio;
	bool msi;

	/* dvb adapters */
	struct tbsecp3_adapter adapter[TBSECP3_MAX_ADAPTERS];

	/* i2c */
	struct tbsecp3_i2c i2c_bus[TBSECP3_MAX_I2C_BUS];
	
	u8 mac_num;
};

#define tbs_read(_b, _o)	readl(dev->lmmio + (_b + _o))
#define tbs_write(_b, _o, _v)	writel((_v), dev->lmmio + (_b + _o))


/* tbsecp3-core.c */
void tbsecp3_gpio_set_pin(struct tbsecp3_dev *dev,
			  struct tbsecp3_gpio_pin *pin, int state);

/* tbspcie-i2c.c */
extern int tbsecp3_i2c_init(struct tbsecp3_dev *dev);
extern void tbsecp3_i2c_exit(struct tbsecp3_dev *dev);
extern void tbsecp3_i2c_reg_init(struct tbsecp3_dev *dev);
extern void tbsecp3_i2c_remove_clients(struct tbsecp3_adapter *adapter);

/* tbspcie-cards.c */
extern struct tbsecp3_board tbsecp3_boards[];

/* tbspcie-dvb.c */
extern int tbsecp3_dvb_init(struct tbsecp3_adapter *adapter);
extern void tbsecp3_dvb_exit(struct tbsecp3_adapter *adapter);

/* tbsecp3-asi.c */
extern u8 asi_CheckFree(struct tbsecp3_dev *dev,int asi_base_addr, unsigned char OpbyteNum);
extern bool asi_chip_reset(struct tbsecp3_dev *dev,int asi_base_addr);
extern int asi_read16bit(struct tbsecp3_dev *dev,int asi_base_addr,int reg_addr);
extern bool asi_write16bit(struct tbsecp3_dev *dev,int asi_base_addr, int reg_addr, int data16bit);

/* tbsecp3-dma.c */
extern int tbsecp3_dma_init(struct tbsecp3_dev *dev);
extern void tbsecp3_dma_free(struct tbsecp3_dev *dev);
extern void tbsecp3_dma_reg_init(struct tbsecp3_dev *dev);
extern void tbsecp3_dma_enable(struct tbsecp3_adapter *adap);
extern void tbsecp3_dma_disable(struct tbsecp3_adapter *adap);

/* tbsecp3-ca.c */
int tbsecp3_ca_init(struct tbsecp3_adapter *adap, int nr);
void tbsecp3_ca_release(struct tbsecp3_adapter *adap);

#endif
