#ifndef _TBSMOD_H
#define _TBSMOD_H

#define TBS_PCIE_WRITE(__addr, __offst, __data)	writel((__data), (dev->mmio + (__addr + __offst)))
#define TBS_PCIE_READ(__addr, __offst)		readl((dev->mmio + (__addr + __offst)))

#define	MAJORDEV	168

#define CHANNELS	4
#define	FIFOSIZE	(2048 * 1024)
#define	DMASIZE		(32 * 1024)

#define BLOCKSIZE		(188*96)

struct mod_channel
{
	struct tbs_pcie_dev 	*dev;
	__le32					*dmavirt;
	dma_addr_t				dmaphy;	
	dev_t					devno;
	u8 						dma_start_flag;
	struct kfifo 			fifo; 
	u8						channel_index;
	
};


struct tbs_pcie_dev {
	struct pci_dev			*pdev;
	void __iomem			*mmio;
//	struct mutex           ioctl_mutex; 
//	u8						block_index;
//	struct work_struct mywork;

	u8 						modulation;
	u32						frequency;
	u32						srate;
	struct mod_channel		channnel[CHANNELS];
	u8						mod_index;

};



static void tbs_adapters_init(struct tbs_pcie_dev *dev);

#endif
