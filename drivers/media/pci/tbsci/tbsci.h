#ifndef _TBSCI_H
#define _TBSCI_H

#define TBS_PCIE_WRITE(__addr, __offst, __data)	writel((__data), (dev->mmio + (__addr + __offst)))
#define TBS_PCIE_READ(__addr, __offst)		readl((dev->mmio + (__addr + __offst)))

#define CHANNELS	2
#define FIFOSIZE (2 * 1024 * 1024)

#define	DMASIZE		(1024 * 1024)

#define TS_PACKET_SIZE		188
#define WRITE_TOTAL_SIZE	(TS_PACKET_SIZE*96)

#define READ_PKTS		(256)
#define READ_CELLS		(16)
#define READ_CELL_SIZE		(TS_PACKET_SIZE*READ_PKTS)
#define READ_TOTAL_SIZE		(READ_CELL_SIZE*READ_CELLS)


struct ca_channel
{
	struct tbs_pcie_dev 	*dev;
	u8			dma_offset;
	u8			next_buffer;
	u8			cnt;
	struct work_struct	read_work;
	struct work_struct	write_work;
	wait_queue_head_t	write_wq;
	wait_queue_head_t	read_wq;
	u8			write_ready;
	u8			read_ready;
	spinlock_t 		readlock;
	spinlock_t		writelock;

	__le32			*w_dmavirt;
	dma_addr_t		w_dmaphy;	
	__le32			*r_dmavirt;
	dma_addr_t		r_dmaphy;	
	struct kfifo 		w_fifo; 
	struct kfifo 		r_fifo; 
	u8			channel_index;
	u8			is_open;
	u8 is_open_for_read;
	//struct tasklet_struct	tasklet;

	/*ca */
	struct dvb_ca_en50221	ca;
	struct mutex 		lock;
	int 			status;

	struct dvb_device    	*ci_dev;

	/* dvb */
	struct dvb_frontend  	fe;	 
	struct dmxdev         	dmxdev;
	struct dvb_demux      	demux;
	struct dvb_net        	dvbnet;
	struct dmx_frontend 	fe_hw;
	struct dmx_frontend 	fe_mem;
	struct dtv_frontend_properties 	dvt_properties;
	int feeds;

	u32			w_bitrate;

};


struct tbs_pcie_dev {
	struct pci_dev		*pdev;
	void __iomem		*mmio;
	struct dvb_adapter	adapter;
	struct ca_channel	channnel[CHANNELS];
	bool			msi;
};


static int tbs_adapters_init(struct tbs_pcie_dev *dev);

#endif
