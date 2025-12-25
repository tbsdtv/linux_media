#include "tbsecp3.h"
#include "tbs_priv.h"

static int write_block_cell = 64;
module_param(write_block_cell, int, 0444);
MODULE_PARM_DESC(
	write_block_cell,
	" Controls the number of irq generated. 96 - x86, 80 or lower on arm64");
	
DVB_DEFINE_MOD_OPT_ADAPTER_NR(sec_nr);
	
#define FIFOSIZE (2 * 1024 * 1024)

#define	DMASIZE		(1024 * 1024)
#define TS_PACKET_SIZE	188

#define WRITE_TOTAL_SIZE	(TS_PACKET_SIZE*96)

#define READ_PKTS		(256)
#define READ_CELLS		(16)
#define READ_CELL_SIZE		(TS_PACKET_SIZE*READ_PKTS)
#define READ_TOTAL_SIZE		(READ_CELL_SIZE*READ_CELLS)
#define  MODULATOR_INPUT_BITRATE 33
	

static void start_outdma_transfer(struct tbsecp3_ci *pchannel)
{
	struct tbsecp3_adapter *adapter = pchannel->adapter;
	struct tbsecp3_dev*dev = adapter->dev;

	//printk("_%s_",__func__);
	tbs_write(TBS_RDDMA_BASE(pchannel->nr), TBSECP3_DMA_EN, (1));
	//tbs_write(TBSECP3_INT_BASE, TBSECP3_INT_EN, 0x00000001);
	tbs_write(TBSECP3_INT_BASE, TBS_RDDMA_IE(pchannel->nr), (1));
}

static void stop_outdma_transfer(struct tbsecp3_ci *pchannel)
{
	struct tbsecp3_adapter *adapter = pchannel->adapter;
	struct tbsecp3_dev*dev = adapter->dev;
	//printk("_%s_",__func__);
	tbs_read(TBS_RDDMA_BASE(pchannel->nr), TBSECP3_DMA_EN);
	tbs_write(TBSECP3_INT_BASE, TBS_RDDMA_IE(pchannel->nr), (0));
	tbs_write(TBS_RDDMA_BASE(pchannel->nr), TBSECP3_DMA_EN, (0));
}

static void start_indma_transfer(struct tbsecp3_ci *pchannel)
{
	struct tbsecp3_adapter *adapter = pchannel->adapter;
	struct tbsecp3_dev*dev = adapter->dev;
	//printk("_%s_",__func__);
	memset(pchannel->r_dmavirt,0,READ_TOTAL_SIZE);
	pchannel->cnt=0;
	pchannel->next_buffer=0;
	tbs_read(TBS_WRDMA_BASE(pchannel->nr), TBSECP3_DMA_EN);
	//tbs_write(TBSECP3_INT_BASE, TBSECP3_INT_EN, 0x00000001);
	tbs_write(TBSECP3_INT_BASE, TBS_WRDMA_IE(pchannel->nr), (1));
	tbs_write(TBS_WRDMA_BASE(pchannel->nr), TBSECP3_DMA_EN, (1));
}

static void stop_indma_transfer(struct tbsecp3_ci *pchannel)
{
	struct tbsecp3_adapter *adapter = pchannel->adapter;
	struct tbsecp3_dev*dev = adapter->dev;
	//printk("_%s_",__func__);
	tbs_read(TBS_WRDMA_BASE(pchannel->nr), TBSECP3_DMA_EN);
	tbs_write(TBSECP3_INT_BASE, TBS_WRDMA_IE(pchannel->nr), (0));
	tbs_write(TBS_WRDMA_BASE(pchannel->nr), TBSECP3_DMA_EN, (0));
}

static void write_dma_work(struct work_struct *p_work)
{
	struct tbsecp3_ci *pchannel = container_of(p_work, struct tbsecp3_ci, write_work);
	struct tbsecp3_adapter *adap = pchannel->adapter;
	struct tbsecp3_dev*dev = adap->dev;
	int count = 0;
	int ret;
	u32 delay;
	//printk("__%s__",__func__);
	spin_lock(&pchannel->writelock);
	tbs_read(TBS_RDDMA_BASE(pchannel->nr), 0x00);
	//tbs_write(TBSECP3_INT_BASE, 0x00, (0x40<<index) ); 
	count = kfifo_len(&pchannel->w_fifo); 
	if (count >= WRITE_TOTAL_SIZE){
		ret = kfifo_out(&pchannel->w_fifo, ((void *)(pchannel->w_dmavirt) ), WRITE_TOTAL_SIZE); 
		if(pchannel->is_open ){
			start_outdma_transfer(pchannel);
		}
		pchannel->write_ready = 1;
		wake_up(&pchannel->write_wq);	
	}
	else{
		delay = div_u64(1000000000ULL * WRITE_TOTAL_SIZE, (pchannel->w_bitrate )*1024*1024*3);
		//	printk("%s bitrate %d,0x18 delayshort: %d \n", __func__,pchannel->w_bitrate,delay);
		tbs_write(TBS_RDDMA_BASE(pchannel->nr), DMA_DELAYSHORT, (delay));
		//tbs_write(TBSECP3_INT_BASE, 0x04, 0x00000001);
	}
	spin_unlock(&pchannel->writelock);
		

}
// Drop the empty packets
static int copy_non_null_ts(struct tbsecp3_ci *pchannel, void *source, int size)
{
	int i, len = 0;
	uint8_t *src = (uint8_t *)source;
	int copied = 0;
	int dropped = 0;
	int count = kfifo_avail(&pchannel->r_fifo);


	for (i = 0; i < size; i += TS_PACKET_SIZE) {
		int pid = (src[i + 1] & 0x1F) * 256 + src[i + 2];
		if (pid < 0x1FFF) {
			if (pchannel->is_open_for_read) {
				if (count >= TS_PACKET_SIZE) {
					copied = kfifo_in(&pchannel->r_fifo,
							  src + i,
							  TS_PACKET_SIZE);
					count -= copied;
				} else
					dropped++;
			}
			if (pchannel->feeds) {
				dvb_dmx_swfilter_packets(&pchannel->adapter->demux,
							 src + i, 1);
			}
			len += copied;
		}
	}
	if (dropped > 0)
		printk("%s dropped: %d packets\n", __func__, dropped);
	return len;
}

static void read_dma_work(struct work_struct *p_work)
{
	struct tbsecp3_ci *pchannel = container_of(p_work, struct tbsecp3_ci, read_work);
	struct tbsecp3_adapter *adapter = pchannel->adapter;
	struct tbsecp3_dev*dev = adapter->dev;
	u32 read_buffer, next_buffer;
	int ret=0;
	u8 * data;
	int i;
	//printk("__%s__",__func__);
	spin_lock(&pchannel->readlock);
	
	if (pchannel->cnt < 2){
		next_buffer = (tbs_read(TBS_WRDMA_BASE(pchannel->nr), 0x00) +READ_CELLS-1) & (READ_CELLS-1);
		pchannel->cnt++;
	}else{
		next_buffer = (tbs_read(TBS_WRDMA_BASE(pchannel->nr), 0x00) +READ_CELLS-1) & (READ_CELLS-1);
		read_buffer = pchannel->next_buffer;
	
		while (read_buffer != next_buffer)
		{
			data = ((void *)(pchannel->r_dmavirt)+read_buffer*READ_CELL_SIZE );
	
			if (data[pchannel->dma_offset] != 0x47) {
			// Find sync byte offset with crude force (this might fail!) 
				for (i = 0; i < TS_PACKET_SIZE; i++)
					if ((data[i] == 0x47) &&
					(data[i + TS_PACKET_SIZE] == 0x47) &&
					(data[i + 2 * TS_PACKET_SIZE] == 0x47) &&
					(data[i + 4 * TS_PACKET_SIZE] == 0x47)) {
						pchannel->dma_offset = i;
						break;
				}
			}
	
			if (pchannel->dma_offset != 0) {
				// Copy remains of last packet from buffer 0 behind last one 
				if (read_buffer ==(READ_CELLS - 1)) {
					memcpy( (void*)pchannel->r_dmavirt+READ_TOTAL_SIZE,
						(void*)pchannel->r_dmavirt, pchannel->dma_offset);
				}
			}
	
			ret = copy_non_null_ts(pchannel,
						   data + pchannel->dma_offset,
						   READ_CELL_SIZE);						   
			pchannel->read_ready = 1;
			wake_up(&pchannel->read_wq);
	
			read_buffer = (read_buffer + 1) & (READ_CELLS - 1);
		}
		pchannel->next_buffer = (u8)next_buffer;
	}
	spin_unlock(&pchannel->readlock);


}
static ssize_t ts_write(struct file *file, const char __user *ptr,
			size_t size, loff_t *ppos)
{
	
	struct dvb_device *dvbdev = file->private_data;
	struct tbsecp3_ci *chan = dvbdev->priv;
	int count;
	int i=0;
	int timeout;

	//printk("%s channel index:%d \n",__func__,  chan->nr);
	count = kfifo_avail(&chan->w_fifo); 
	while (count < size)
	{
		chan->write_ready=0;
		timeout = wait_event_timeout(chan->write_wq, chan->write_ready == 1, HZ);
		if (timeout <= 0) {
			printk("ts_write buffer fulled!\n");
			return 0;
		}

		count = kfifo_avail(&chan->w_fifo); 
		i++;
		if (i > 5)
		{
			printk("ts_write buffer fulled!\n");
			return 0;
		}
	}
	if (count >= size)
	{
		unsigned int copied;
		unsigned int ret;
		ret = kfifo_from_user(&chan->w_fifo, ptr, size, &copied);
		if (size != copied)
			printk("%s write size:%lu  %u\n", __func__, size,
			       copied);
	}

	return size;

}

static ssize_t ts_read(struct file *file, char __user *ptr,
		       size_t size, loff_t *ppos)
{
	
	struct dvb_device *dvbdev = file->private_data;
	struct tbsecp3_ci *chan = dvbdev->priv;
	int count;
	unsigned int copied = -EAGAIN;

	//printk("%s channel index:%d \n",__func__,  chan->nr);
	count = kfifo_len(&chan->r_fifo); 
	while (count < TS_PACKET_SIZE)
	{
		if (file->f_flags & O_NONBLOCK)
			break;
		chan->read_ready = 0;
		if (wait_event_interruptible(chan->read_wq,
					     chan->read_ready == 1) < 0)
			break;
		count = kfifo_len(&chan->r_fifo);
	}

	if (count > size)
		count = size;
	if (count >= TS_PACKET_SIZE && kfifo_to_user(&chan->r_fifo, ptr, count, &copied))
		return -EFAULT;

	return copied;
}

static __poll_t ts_poll(struct file *file, poll_table *wait)
{
	struct dvb_device *dvbdev = file->private_data;
	struct tbsecp3_ci *chan = dvbdev->priv;

	__poll_t mask = 0;

	poll_wait(file, &chan->read_wq, wait);
	poll_wait(file, &chan->write_wq, wait);
	if (kfifo_len(&chan->r_fifo) >= TS_PACKET_SIZE)
		mask |= EPOLLIN | EPOLLRDNORM;
	if (kfifo_avail(&chan->w_fifo) >= TS_PACKET_SIZE)
		mask |= EPOLLOUT | EPOLLWRNORM;
	return mask;
}

static int ts_open(struct inode *inode, struct file *filp)
{
	struct dvb_device *dvbdev = filp->private_data;
	struct tbsecp3_ci *chan = dvbdev->priv;
	int ret;
	ret =  dvb_generic_open(inode,filp);
	//printk("%s channel index:%d \n",__func__,  chan->nr);
	kfifo_reset(&chan->w_fifo);
	kfifo_reset(&chan->r_fifo);

	if(chan->is_open <=0){
		start_outdma_transfer(chan);
		//start_indma_transfer(chan);
	}
	if ((filp->f_flags & O_ACCMODE) == O_RDONLY)
		chan->is_open_for_read = 1;
	chan->is_open++;

	return ret;
}

static int ts_release(struct inode *inode, struct file *file)
{
	struct dvb_device *dvbdev = file->private_data;
	struct tbsecp3_ci *chan = dvbdev->priv;

	//printk("%s channel index:%d \n",__func__,  chan->nr);
	chan->is_open--;
	if(chan->is_open<=0){
		//stop_indma_transfer(chan);
		stop_outdma_transfer(chan);
	}
	if ((file->f_flags & O_ACCMODE) == O_RDONLY)
		chan->is_open_for_read = 0;

	return dvb_generic_release(inode,file);
}


void spi_read(struct tbsecp3_ci *tbsci, struct mcu24cxx_info *info)
{
	struct tbsecp3_adapter *adapter =tbsci->adapter;
	struct tbsecp3_dev*dev = adapter->dev;
	
	info->data = tbs_read(info->bassaddr, info->reg);
}
void spi_write(struct tbsecp3_ci *tbsci, struct mcu24cxx_info *info)
{
	struct tbsecp3_adapter *adapter =tbsci->adapter;
	struct tbsecp3_dev*dev = adapter->dev;

	tbs_write(info->bassaddr,info->reg,info->data);	
}
static long tbsci_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{

	struct dvb_device *dvbdev = file->private_data;
	struct tbsecp3_ci *chan = dvbdev->priv;
	struct tbsecp3_adapter *adapter =chan->adapter;
	struct tbsecp3_dev*dev = adapter->dev;
	struct mcu24cxx_info wrinfo;
	struct dtv_properties props ;
	struct dtv_property prop;
	int ret = 0;
	u32 clk_freq;
	u32 clk_data;
	switch (cmd)
	{
	case FE_SET_PROPERTY:
		copy_from_user(&props , (const char*)arg, sizeof(struct dtv_properties ));
		if (props.num == 1)
		{
			copy_from_user(&prop , (const char*)props.props, sizeof(struct dtv_property ));
			switch (prop.cmd)
			{
				case MODULATOR_INPUT_BITRATE:
					printk("%s ca%d:INPUT_BITRATE:%d\n",
					       __func__, chan->nr,
					       prop.u.data);
					chan->w_bitrate = prop.u.data;
					//set clock preset 
					
					if(chan->w_bitrate<30)
						clk_data = 15;
					else if(chan->w_bitrate<=41)
						clk_data = (125*188*8)/(204*chan->w_bitrate*2)-1;
					else if(chan->w_bitrate<=70)
						clk_data = ((125*188*8)/(204*chan->w_bitrate)-1)/2;
					else if((chan->w_bitrate>70)&&(chan->w_bitrate<74))
						clk_data = 6;
					else if((chan->w_bitrate>=74)&&(chan->w_bitrate<84))
						clk_data = 0x10;
					else if((chan->w_bitrate>=84)&&(chan->w_bitrate<88))
						clk_data = 5;  //10freq
					else if((chan->w_bitrate>=88)&&(chan->w_bitrate<102))
						clk_data = 0x20;
					else if((chan->w_bitrate>=102)&&(chan->w_bitrate<110))
						clk_data = 4;//8freq
					else if((chan->w_bitrate>=110)&&(chan->w_bitrate<119))
						clk_data = 0x30;  
					else if((chan->w_bitrate>=119)&&(chan->w_bitrate<128))
						clk_data = 0x40;
					else if((chan->w_bitrate>=128)&&(chan->w_bitrate<142))
						clk_data = 0x50;
					else
						clk_data = 3 ;
					printk(" clk preset val : %d\n",clk_data);
					tbs_write(TBSECP3_CA_BASE(chan->nr), 0x20, clk_data);
					
					clk_data=tbs_read(TBSECP3_CA_BASE(chan->nr), 0x20);
					printk(" read clk preset val : %d\n",clk_data);	
					break;
				default:
					ret = -EINVAL;
					break;
			}
		}

	case FE_ECP3FW_READ:
		ret = copy_from_user(&wrinfo , (const char*)arg, sizeof(struct mcu24cxx_info ));
		spi_read(chan, &wrinfo);
		ret = copy_to_user((void *)arg, &wrinfo, sizeof(struct mcu24cxx_info ));
		break;
	case FE_ECP3FW_WRITE:
		ret = copy_from_user(&wrinfo , (const char*)arg, sizeof(struct mcu24cxx_info ));
		spi_write(chan, &wrinfo);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;

}


static const struct file_operations ci_fops = {
	.owner   = THIS_MODULE,
	.read    = ts_read,
	.write   = ts_write,
	.open    = ts_open,
	.poll    = ts_poll,
	.unlocked_ioctl = tbsci_ioctl,
	.release = ts_release,
};

struct dvb_device tbs_ci = {
	.readers = -1,
	.writers = -1,
	.users   = -1,
	.fops    = &ci_fops,
};


static int start_feed(struct dvb_demux_feed *dvbdmxfeed)
{
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	struct tbsecp3_ci *tbsca = dvbdmx->priv;
	printk("%s feeds:%d\n", __func__,tbsca->feeds);
	if (!tbsca->feeds)
		start_indma_transfer(tbsca);

	return ++tbsca->feeds;
}

static int stop_feed(struct dvb_demux_feed *dvbdmxfeed)
{
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	struct tbsecp3_ci *tbsca = dvbdmx->priv;
	printk("%s feeds:%d\n", __func__,tbsca->feeds);
	tbsca->feeds--;
	return 0;
}

int my_dvb_dmx_ts_card_init(struct dvb_demux *dvbdemux, char *id,
			    int (*start_feed)(struct dvb_demux_feed *),
			    int (*stop_feed)(struct dvb_demux_feed *),
			    void *priv)
{
//	printk("%s \n", __func__);
	dvbdemux->priv = priv;

	dvbdemux->filternum = 256;
	dvbdemux->feednum = 256;
	dvbdemux->start_feed = start_feed;
	dvbdemux->stop_feed = stop_feed;
	dvbdemux->write_to_decoder = NULL;
	dvbdemux->dmx.capabilities = (DMX_TS_FILTERING |
				      DMX_SECTION_FILTERING |
				      DMX_MEMORY_BASED_FILTERING);
	return dvb_dmx_init(dvbdemux);
}

int my_dvb_dmxdev_ts_card_init(struct dmxdev *dmxdev,
			       struct dvb_demux *dvbdemux,
			       struct dmx_frontend *hw_frontend,
			       struct dmx_frontend *mem_frontend,
			       struct dvb_adapter *dvb_adapter)
{
	int ret;
//	printk("%s \n", __func__);
	dmxdev->filternum = 256;
	dmxdev->demux = &dvbdemux->dmx;
	dmxdev->capabilities = 0;
	ret = dvb_dmxdev_init(dmxdev, dvb_adapter);
	if (ret < 0)
		return ret;

	hw_frontend->source = DMX_FRONTEND_0;
	dvbdemux->dmx.add_frontend(&dvbdemux->dmx, hw_frontend);
	mem_frontend->source = DMX_MEMORY_FE;
	dvbdemux->dmx.add_frontend(&dvbdemux->dmx, mem_frontend);
	return dvbdemux->dmx.connect_frontend(&dvbdemux->dmx, hw_frontend); 
}

static void tbsecp3_dma_register_init(struct tbsecp3_adapter *adap)
{
	
	struct tbsecp3_ci *tbsci = adap->tbsci;
	struct tbsecp3_dev*dev = adap->dev;
	u32 speedctrl;
	u32 tmp=0;
 
	 tbs_write(TBS_RDDMA_BASE(tbsci->nr), DMA_SIZE, (WRITE_TOTAL_SIZE));
	 tmp=tbs_read(TBS_RDDMA_BASE(tbsci->nr), DMA_SIZE);
	 printk("tmp = 0x%x",tmp);
	 
	 tbs_write(TBS_RDDMA_BASE(tbsci->nr), DMA_ADDR_HIGH, 0);
	 tbs_write(TBS_RDDMA_BASE(tbsci->nr), DMA_ADDR_LOW, tbsci->w_dmaphy);
	 tbs_write(TBS_RDDMA_BASE(tbsci->nr), TBSECP3_DMA_EN, 0);
	 
	 tbs_write(TBS_WRDMA_BASE(tbsci->nr), DMA_SIZE, (READ_TOTAL_SIZE));
	 tmp=tbs_read(TBS_WRDMA_BASE(tbsci->nr), DMA_SIZE);
	 printk("read tmp = 0x%x",tmp);
	 
	 tbs_write(TBS_WRDMA_BASE(tbsci->nr), DMA_ADDR_HIGH, 0);
	 tbs_write(TBS_WRDMA_BASE(tbsci->nr), DMA_ADDR_LOW, tbsci->r_dmaphy);
	 tbs_write(TBS_WRDMA_BASE(tbsci->nr), 0x10, (READ_CELL_SIZE));
	 tbs_write(TBS_WRDMA_BASE(tbsci->nr), TBSECP3_DMA_EN, 0);
	 
 if(tbsci->w_bitrate){
	 speedctrl =div_u64(1000000000ULL * WRITE_TOTAL_SIZE,(tbsci->w_bitrate )*1024*1024 );
	 tbs_write(TBS_RDDMA_BASE(tbsci->nr), DMA_SPEED_CTRL, (speedctrl));
	 tbs_write(TBS_RDDMA_BASE(tbsci->nr), DMA_INT_MONITOR, (2*speedctrl));
	 speedctrl = div_u64(speedctrl, write_block_cell);
	 tbs_write(TBS_RDDMA_BASE(tbsci->nr), DMA_FRAME_CNT, (speedctrl));
	 }	 

	
	

}

struct tbs_cfg tbs_cfg = {
	.adr = 0x88,
	.flag = 1,
	.rf = 0,
};

static int tbs_frontend_attach(struct tbsecp3_adapter *adapter)
{
	struct tbsecp3_dev *dev = adapter->dev;
	struct pci_dev *pci = dev->pci_dev;
	struct i2c_adapter *i2c = &adapter->i2c->i2c_adap;

	
	adapter->fe = dvb_attach(tbs_attach,i2c,&tbs_cfg,0);

	if(adapter->fe==NULL)
		 return -ENODEV;
	
	strscpy(adapter->fe->ops.info.name,dev->info->name,52);

	return 0;
}

void tbsecp3_ci_remove(struct tbsecp3_adapter *adap)
{
	struct tbsecp3_ci *tbsci = adap->tbsci;
	struct dvb_demux *dvbdemux;
	int i;


	kfifo_free(&tbsci->w_fifo);
	kfifo_free(&tbsci->r_fifo);
	
	if (!tbsci->w_dmavirt){
		dma_free_coherent(&adap->dev->pci_dev->dev, DMASIZE, tbsci->w_dmavirt, tbsci->w_dmaphy);
		tbsci->w_dmavirt = NULL;
	}
	if (!tbsci->r_dmavirt){
		dma_free_coherent(&adap->dev->pci_dev->dev, DMASIZE, tbsci->r_dmavirt, tbsci->r_dmaphy);
		tbsci->r_dmavirt = NULL;
	}
	
	dvbdemux = &adap->demux;
	dvb_net_release(&adap->dvbnet);
	dvbdemux->dmx.close(&dvbdemux->dmx);
	dvbdemux->dmx.remove_frontend(&dvbdemux->dmx, &adap->fe_mem);
	dvbdemux->dmx.remove_frontend(&dvbdemux->dmx, &adap->fe_hw);
	dvb_dmxdev_release(&adap->dmxdev);
	dvb_dmx_release(&adap->demux);
	dvb_unregister_frontend(adap->fe);
	dvb_unregister_device(tbsci->ci_dev);
		
}

int tbsecp3_ci_init(struct tbsecp3_adapter *adap,int nr,int cimode)
{
	int i=0;
	int ret=0;
	struct tbsecp3_dev *dev = adap->dev;
	struct tbsecp3_ci *tbsci;
	printk("__%s__",__func__);
	
	tbsci = kzalloc(sizeof(struct tbsecp3_ci),GFP_KERNEL);	
	if(tbsci==NULL)
		return -ENOMEM;

	adap->tbsci = tbsci;	
	tbsci->w_dmavirt = dma_alloc_coherent(&dev->pci_dev->dev, DMASIZE, &tbsci->w_dmaphy, GFP_KERNEL);
	if (!tbsci->w_dmavirt)
	{
		printk(" allocate write memory failed\n");
		goto fail;
	}
	tbsci->r_dmavirt = dma_alloc_coherent(&dev->pci_dev->dev, DMASIZE, &tbsci->r_dmaphy, GFP_KERNEL);
	if (!tbsci->r_dmavirt)
	{
		printk(" allocate read memory failed\n");
		goto fail;
	}
	

	tbsci->w_bitrate = 50;
	tbsci->next_buffer = 0;
	tbsci->cnt = 0;
	tbsci->nr = nr;


	
	ret = kfifo_alloc(&tbsci->w_fifo, FIFOSIZE, GFP_KERNEL);
	if (ret != 0)
		goto fail;
	ret = kfifo_alloc(&tbsci->r_fifo, FIFOSIZE, GFP_KERNEL);
	if (ret != 0)
		goto fail;

	INIT_WORK(&tbsci->read_work,read_dma_work);
	INIT_WORK(&tbsci->write_work,write_dma_work);
	init_waitqueue_head(&tbsci->write_wq);
	init_waitqueue_head(&tbsci->read_wq);
	spin_lock_init(&tbsci->readlock);
	spin_lock_init(&tbsci->writelock);

	tbsci->adapter= adap;
	tbsecp3_dma_register_init(adap); 

	ret = dvb_register_adapter(&adap->dvb_adapter, "tbsci",THIS_MODULE,&adap->dev->pci_dev->dev,sec_nr);

	ret = tbsecp3_ca_init(adap, nr);

	ret = dvb_register_device(&adap->dvb_adapter, &tbsci->ci_dev,&tbs_ci, (void *) tbsci,DVB_DEVICE_SEC,0);
	if (ret < 0) {
		printk("%s ERROR: dvb_register_device\n", __func__);;
		goto fail;
	}

	tbs_frontend_attach(adap);
	
	ret = dvb_register_frontend(&adap->dvb_adapter, adap->fe) ;
	ret = my_dvb_dmx_ts_card_init(&adap->demux, "SW demux",
					  start_feed,
					  stop_feed, adap->tbsci);
	if (ret < 0) {
		printk("%s ERROR: my_dvb_dmx_ts_card_init\n", __func__);;
		goto fail;
	}
					  
	ret = my_dvb_dmxdev_ts_card_init(&adap->dmxdev, &adap->demux,
					 &adap->fe_hw,
					 &adap->fe_mem, &adap->dvb_adapter);  
	if (ret < 0) {
		printk("%s ERROR: my_dvb_dmxdev_ts_card_init\n", __func__);;
		goto fail;
	}
	ret = dvb_net_init(&adap->dvb_adapter, &adap->dvbnet,&adap->demux.dmx);
	if (ret < 0) {
		printk("%s ERROR: dvb_net_init\n", __func__);;
		goto fail;
	}


	return 0;
	
fail :
	tbsecp3_ci_remove(adap);	
	return ret;
}

