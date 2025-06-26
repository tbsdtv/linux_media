#ifndef _TBSMOD_H
#define _TBSMOD_H

#define TBS_PCIE_WRITE(__addr, __offst, __data)	writel((__data), (dev->mmio + (__addr + __offst)))
#define TBS_PCIE_READ(__addr, __offst)		readl((dev->mmio + (__addr + __offst)))

#define	MAJORDEV	168

#define CHANNELS	32
#define	FIFOSIZE	(2048 * 1024)

#define BLOCKSIZE(id)	(188*32)

#define FPGA_BLK	4
#define CELLSIZE	(32 * 188)
#define	DMATOTAL	(CELLSIZE * 16)


//#define BLOCKSIZE(id) ((id==0x6008)?(188*32):(188*96))
#define BLOCKCEEL	(32)
#define TBSMOD_DMA_IF(_n)	(0x0010 << _n)
#define TBSMOD_DMA_IF16(_n)	(0x10000 <<( _n -16))

struct mod_channel
{
	struct tbs_pcie_dev 	*dev;
	__le32			*dmavirt;
	dma_addr_t		dmaphy;	
	dev_t			devno;
	u8 			dma_start_flag;
	u8 			dma_num;
	struct kfifo 		fifo; 
	u8			channel_index;
	u32			input_bitrate;
	spinlock_t           	adap_lock; //  dma lock
};


struct tbs_pcie_dev {
	struct pci_dev		*pdev;
	void __iomem		*mmio;
	struct mutex           	spi_mutex; // lock spi access
	struct mutex           	ioctl_mutex; // lock ioctls access
	//spinlock_t           	chip_lock; // lock chip access
	struct mutex           	chip_lock; // lock chip access

	u8 			modulation;
	u32			frequency;
	u32			srate;
	struct mod_channel	channel[CHANNELS];
	u8			mod_index;
	u32			cardid;
	u8			mods_num;

	u8			bw;  //dvbt
	bool			msi;
	

};

static void tbs_adapters_init_dvbc(struct tbs_pcie_dev *dev);

#endif
