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


#include <media/dmxdev.h>
#include <media/dvbdev.h>
#include <media/dvb_demux.h>
#include <media/dvb_ca_en50221.h>
#include <media/dvb_frontend.h>
#include <media/dvb_ringbuffer.h>
#include <media/dvb_net.h>
#include <linux/dvb/frontend.h>

#include "tbsci.h"
#include "tbsci-io.h"

DVB_DEFINE_MOD_OPT_ADAPTER_NR(adapter_nr);
struct workqueue_struct *wq;


static void start_outdma_transfer(struct ca_channel *pchannel)
{
	struct tbs_pcie_dev *dev=pchannel->dev;
	u32 speedctrl;
	//printk("%s index:%d \n",__func__,pchannel->channel_index);
	if(pchannel->w_bitrate){
		speedctrl =div_u64(1000000000ULL * WRITE_TOTAL_SIZE,(pchannel->w_bitrate )*1024*1024 );
		TBS_PCIE_WRITE(dmaout_adapter0+pchannel->channel_index*0x1000, DMA_SPEED_CTRL, (speedctrl));
		TBS_PCIE_WRITE(dmaout_adapter0+pchannel->channel_index*0x1000, DMA_INT_MONITOR, (2*speedctrl));
		speedctrl = div_u64(speedctrl , WRITE_BLOCK_CEEL);
		//speedctrl = div_u64(speedctrl*9 , WRITE_BLOCK_CEEL*10);
		TBS_PCIE_WRITE(dmaout_adapter0+pchannel->channel_index*0x1000, DMA_FRAME_CNT, (speedctrl));
	}

	TBS_PCIE_WRITE(dmaout_adapter0+pchannel->channel_index*0x1000, DMA_SIZE, (WRITE_TOTAL_SIZE));
	TBS_PCIE_WRITE(dmaout_adapter0+pchannel->channel_index*0x1000, DMA_ADDR_HIGH, 0);
	TBS_PCIE_WRITE(dmaout_adapter0+pchannel->channel_index*0x1000, DMA_ADDR_LOW, pchannel->w_dmaphy);
	TBS_PCIE_WRITE(dmaout_adapter0+pchannel->channel_index*0x1000, DMA_GO, (1));

	TBS_PCIE_WRITE(int_adapter, 0x04, 0x00000001);
	TBS_PCIE_WRITE(int_adapter, 0x20+pchannel->channel_index*4, (1));
}

static void stop_outdma_transfer(struct ca_channel *pchannel)
{
	struct tbs_pcie_dev *dev=pchannel->dev;
	TBS_PCIE_READ(dmaout_adapter0+pchannel->channel_index*0x1000, DMA_GO);
	TBS_PCIE_WRITE(int_adapter, 0x20+pchannel->channel_index*4, (0));
	TBS_PCIE_WRITE(dmaout_adapter0+pchannel->channel_index*0x1000, DMA_GO, (0));
}

static void start_indma_transfer(struct ca_channel *pchannel)
{
	struct tbs_pcie_dev *dev=pchannel->dev;
	//printk("%s index:%d \n",__func__,pchannel->channel_index);
	TBS_PCIE_WRITE(dma_wr_adapter0+pchannel->channel_index*0x1000, DMA_SIZE, (READ_TOTAL_SIZE));
	TBS_PCIE_WRITE(dma_wr_adapter0+pchannel->channel_index*0x1000, DMA_ADDR_HIGH, 0);
	TBS_PCIE_WRITE(dma_wr_adapter0+pchannel->channel_index*0x1000, DMA_ADDR_LOW, pchannel->r_dmaphy);
	TBS_PCIE_WRITE(dma_wr_adapter0+pchannel->channel_index*0x1000, 0x10, (READ_CELL_SIZE));
//	TBS_PCIE_WRITE(dma_wr_adapter0+pchannel->channel_index*0x1000, 0x14, (1));
//	TBS_PCIE_WRITE(dma_wr_adapter0+pchannel->channel_index*0x1000, 0x1c, (1));

	memset(pchannel->r_dmavirt,0,READ_TOTAL_SIZE);
	pchannel->cnt=0;
	pchannel->next_buffer=0;
	TBS_PCIE_READ(dma_wr_adapter0+pchannel->channel_index*0x1000, DMA_GO);
	TBS_PCIE_WRITE(int_adapter, 0x04, 0x00000001);
	TBS_PCIE_WRITE(int_adapter, 0x18+pchannel->channel_index*4, (1));
	TBS_PCIE_WRITE(dma_wr_adapter0+pchannel->channel_index*0x1000, DMA_GO, (1));
}

static void stop_indma_transfer(struct ca_channel *pchannel)
{
	struct tbs_pcie_dev *dev=pchannel->dev;
	TBS_PCIE_READ(dma_wr_adapter0+pchannel->channel_index*0x1000, DMA_GO);
	TBS_PCIE_WRITE(int_adapter, 0x18+pchannel->channel_index*4, (0));
	TBS_PCIE_WRITE(dma_wr_adapter0+pchannel->channel_index*0x1000, DMA_GO, (0));
}

static ssize_t ts_write(struct file *file, const char __user *ptr,
			size_t size, loff_t *ppos)
{
	
	struct dvb_device *dvbdev = file->private_data;
	struct ca_channel *chan = dvbdev->priv;
	int count;
	int i=0;
	int timeout;

//	printk("%s channel index:%d \n",__func__,  chan->channel_index);
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
			printk("%s size:%u  %u\n", __func__, size, copied);
	}

	return size;

}

static ssize_t ts_read(struct file *file, char __user *ptr,
		       size_t size, loff_t *ppos)
{
	
	struct dvb_device *dvbdev = file->private_data;
	struct ca_channel *chan = dvbdev->priv;
	int count;
	int i=0;
	int timeout;

//	printk("%s channel index:%d \n",__func__,  chan->channel_index);
	count = kfifo_len(&chan->r_fifo); 
	while (count < size)
	{
		chan->read_ready=0;
		timeout = wait_event_timeout(chan->read_wq, chan->read_ready == 1, HZ);
		if (timeout <= 0) {
			printk("ts_read buffer fulled!\n");
			return 0;
		}

		count = kfifo_len(&chan->r_fifo); 
		i++;
		if (i > 5)
		{
			printk("ts_read buffer empty !\n");
			return 0;
		}
	}
	if (count >= size){
		unsigned int copied;
		unsigned int ret;
		ret = kfifo_to_user(&chan->r_fifo, ptr, size, &copied);
		if (size != copied)
			printk("%s size:%u  %u\n", __func__, size, copied);
	}
	return size;
}

static int ts_open(struct inode *inode, struct file *filp)
{
	struct dvb_device *dvbdev = filp->private_data;
	struct ca_channel *chan = dvbdev->priv;
	int ret;
	ret =  dvb_generic_open(inode,filp);
	//printk("%s channel index:%d \n",__func__,  chan->channel_index);
	kfifo_reset(&chan->w_fifo);
	kfifo_reset(&chan->r_fifo);

	if(chan->is_open <=0){
		start_outdma_transfer(chan);
		start_indma_transfer(chan);
	}
	chan->is_open++;

	return ret;
}

static int ts_release(struct inode *inode, struct file *file)
{
	struct dvb_device *dvbdev = file->private_data;
	struct ca_channel *chan = dvbdev->priv;

	//printk("%s channel index:%d \n",__func__,  chan->channel_index);
	chan->is_open--;
	if(chan->is_open<=0){
		stop_indma_transfer(chan);
		stop_outdma_transfer(chan);
	}
	return dvb_generic_release(inode,file);
}


void spi_read(struct tbs_pcie_dev *dev, struct mcu24cxx_info *info)
{
	info->data = TBS_PCIE_READ(info->bassaddr, info->reg);
	//printk("%s bassaddr:%x ,reg: %x,val: %x\n", __func__, info->bassaddr, info->reg,info->data);
}
void spi_write(struct tbs_pcie_dev *dev, struct mcu24cxx_info *info)
{
	TBS_PCIE_WRITE(info->bassaddr,info->reg,info->data);	
	//printk("%s size:%x, reg: %x, val: %x\n", __func__, info->bassaddr, info->reg,info->data);
}
static long tbsci_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{

	struct dvb_device *dvbdev = file->private_data;
	struct ca_channel *chan = dvbdev->priv;
	struct tbs_pcie_dev *dev = chan->dev;
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
					printk("%s ca%d:INPUT_BITRATE:%d\n", __func__,chan->channel_index,prop.u.data);
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
					TBS_PCIE_WRITE(pcmcia_adapter0+chan->channel_index*0x1000, 0x10, clk_data);
					
					clk_data=TBS_PCIE_READ(pcmcia_adapter0+chan->channel_index*0x1000, 0x10);
					printk(" read clk preset val : %d\n",clk_data);	
					break;
				default:
					ret = -EINVAL;
					break;
			}
		}

	case FE_ECP3FW_READ:
		ret = copy_from_user(&wrinfo , (const char*)arg, sizeof(struct mcu24cxx_info ));
		spi_read(dev, &wrinfo);
		ret = copy_to_user((void *)arg, &wrinfo, sizeof(struct mcu24cxx_info ));
		break;
	case FE_ECP3FW_WRITE:
		ret = copy_from_user(&wrinfo , (const char*)arg, sizeof(struct mcu24cxx_info ));
		spi_write(dev, &wrinfo);
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
	.unlocked_ioctl = tbsci_ioctl,
	.release = ts_release,
};

struct dvb_device tbs_ci = {
	.readers = -1,
	.writers = -1,
	.users   = -1,
	.fops    = &ci_fops,
};

static void write_dma_work(struct work_struct *p_work)
{
	struct ca_channel *pchannel = container_of(p_work, struct ca_channel, write_work);
	struct tbs_pcie_dev *dev = pchannel->dev;
	int count = 0;
	int ret;
	u32 delay;
	
	spin_lock(&pchannel->writelock);
	TBS_PCIE_READ(dmaout_adapter0+pchannel->channel_index*0x1000, 0x00);
	//TBS_PCIE_WRITE(int_adapter, 0x00, (0x40<<index) ); 
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
		//printk("%s bitrate %d,0x18 delayshort: %d \n", __func__,pchannel->w_bitrate,delay);
		TBS_PCIE_WRITE(dmaout_adapter0+pchannel->channel_index*0x1000, DMA_DELAYSHORT, (delay));
		//TBS_PCIE_WRITE(int_adapter, 0x04, 0x00000001);
	}
	spin_unlock(&pchannel->writelock);
		
}

static void read_dma_work(struct work_struct *p_work)
{
	struct ca_channel *pchannel = container_of(p_work, struct ca_channel, read_work);
	struct tbs_pcie_dev *dev = pchannel->dev;
	int count = 0;
	u32 read_buffer, next_buffer;
	int ret=0;
	u8 * data;
	int i;

	spin_lock(&pchannel->readlock);

	if (pchannel->cnt < 2){
		next_buffer = (TBS_PCIE_READ(dma_wr_adapter0+pchannel->channel_index*0x1000, 0x00) +READ_CELLS-1) & (READ_CELLS-1);
		pchannel->cnt++;
	}else{
		next_buffer = (TBS_PCIE_READ(dma_wr_adapter0+pchannel->channel_index*0x1000, 0x00) +READ_CELLS-1) & (READ_CELLS-1);
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


			count = kfifo_avail(&pchannel->r_fifo); 
			if (count >= READ_CELL_SIZE){
				ret = kfifo_in(&pchannel->r_fifo, data+pchannel->dma_offset, READ_CELL_SIZE); 
				pchannel->read_ready = 1;
				wake_up(&pchannel->read_wq);	

			}
			if(pchannel->feeds){
				//printk("%s feeds:%d\n",__func__,pchannel->feeds);
				dvb_dmx_swfilter_packets(&pchannel->demux,data+pchannel->dma_offset,READ_PKTS);
				
			}
			read_buffer = (read_buffer + 1) & (READ_CELLS - 1);
		}
		pchannel->next_buffer = (u8)next_buffer;
	}
	spin_unlock(&pchannel->readlock);

}



static irqreturn_t tbsci_irq(int irq, void *dev_id)
{
	struct tbs_pcie_dev *dev = (struct tbs_pcie_dev *)dev_id;
	u32 stat,tmp;
	
	tmp = TBS_PCIE_READ(int_adapter, 0x0c);
	stat = TBS_PCIE_READ(int_adapter, 0x00);
	TBS_PCIE_WRITE(int_adapter, 0, stat);
	//printk("%s 0x00:%x 0xc0:%x\n",__func__,stat,tmp);
	
	TBS_PCIE_WRITE(int_adapter, 0x04, 0x00000001);
	if (!(stat & 0xf0)){
		//TBS_PCIE_WRITE(int_adapter, 0x04, 0x00000001);
		return IRQ_HANDLED;
	}

	if (stat & 0x80){ //dma3 status
		//outchannelprocess(dev,1);
		queue_work(wq,&dev->channnel[1].write_work);

	}

	if (stat & 0x40){ //dma2 status
		queue_work(wq,&dev->channnel[0].write_work);
		//outchannelprocess(dev,0);
	}

	if (stat & 0x20){ //dma1 status
		queue_work(wq,&dev->channnel[1].read_work);
		//TBS_PCIE_WRITE(int_adapter, 0x04, 0x00000001);
	}

	if (stat & 0x10){ //dma0 status
		queue_work(wq,&dev->channnel[0].read_work);
		//TBS_PCIE_WRITE(int_adapter, 0x04, 0x00000001);	
	}
	return IRQ_HANDLED;
}

int ca_read_attribute_mem(struct dvb_ca_en50221 *en50221,int slot, int address)
{
	struct ca_channel *tbsca = en50221->data;
	struct tbs_pcie_dev *dev = tbsca->dev;
	u32 data = 0;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data |= (address >> 8) & 0x7f;
	data |= (address & 0xff) << 8;
	TBS_PCIE_WRITE(pcmcia_adapter0+tbsca->channel_index*0x1000,0x00, data);
	udelay(150);

	data = TBS_PCIE_READ(pcmcia_adapter0+tbsca->channel_index*0x1000, 0x04);

	mutex_unlock(&tbsca->lock);

	return (data & 0xff);		
}

int ca_write_attribute_mem(struct dvb_ca_en50221 *en50221,int slot, int address, u8 value)
{
	struct ca_channel *tbsca = en50221->data;
	struct tbs_pcie_dev *dev = tbsca->dev;
	u32 data = 0;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data |= (address >> 8) & 0x7f;
	data |= (address & 0xff) << 8;
	data |= 0x01 << 16;
	data |= value << 24;
	TBS_PCIE_WRITE(pcmcia_adapter0+tbsca->channel_index*0x1000, 0x00, data);
	udelay(150);

	mutex_unlock(&tbsca->lock);

	return 0;

}

int ca_read_cam_control(struct dvb_ca_en50221 *en50221,int slot, u8 address)
{
	struct ca_channel *tbsca = en50221->data;
	struct tbs_pcie_dev *dev = tbsca->dev;
	u32 data = 0;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data |= (address & 3) << 8;
	data |= 0x02 << 16;
	TBS_PCIE_WRITE(pcmcia_adapter0+tbsca->channel_index*0x1000, 0x00, data);
	udelay(150);
	
	data = TBS_PCIE_READ(pcmcia_adapter0+tbsca->channel_index*0x1000,  0x08);

	mutex_unlock(&tbsca->lock);

	return (data & 0xff);		
}

int ca_write_cam_control(struct dvb_ca_en50221 *en50221,int slot, u8 address, u8 value)
{
	struct ca_channel *tbsca = en50221->data;
	struct tbs_pcie_dev *dev = tbsca->dev;
	u32 data = 0;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data |= (address & 3) << 8;
	data |= 0x03 << 16;
	data |= value << 24;
	TBS_PCIE_WRITE(pcmcia_adapter0+tbsca->channel_index*0x1000, 0x00, data);
	udelay(150);

	mutex_unlock(&tbsca->lock);

	return 0;
}

int ca_slot_reset(struct dvb_ca_en50221 *en50221, int slot)
{
	struct ca_channel *tbsca = en50221->data;
	struct tbs_pcie_dev *dev = tbsca->dev;

	if (slot != 0)
		return -EINVAL;
	
	mutex_lock(&tbsca->lock);

	TBS_PCIE_WRITE(pcmcia_adapter0+tbsca->channel_index*0x1000,  0x04, 1);
	msleep (10);

	TBS_PCIE_WRITE(pcmcia_adapter0+tbsca->channel_index*0x1000, 0x04, 0);
	msleep (2800);

	mutex_unlock (&tbsca->lock);
	return 0;		
}
int ca_slot_ctrl(struct dvb_ca_en50221 *en50221,
	int slot, int enable)
{
	struct ca_channel *tbsca = en50221->data;
	struct tbs_pcie_dev *dev = tbsca->dev;
	u32 data;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data = enable & 1;
	TBS_PCIE_WRITE(pcmcia_adapter0+tbsca->channel_index*0x1000, 0x0c, data);
	mutex_unlock(&tbsca->lock);
	return 0;
}
int ca_slot_shutdown(struct dvb_ca_en50221 *en50221, int slot)
{
		return ca_slot_ctrl(en50221, slot, 0);
}

int ca_slot_ts_enable(struct dvb_ca_en50221 *en50221, int slot)
{
		return ca_slot_ctrl(en50221, slot, 1);
}

int ca_poll_slot_status(struct dvb_ca_en50221 *en50221,int slot, int open)
{
	struct ca_channel *tbsca = en50221->data;
	struct tbs_pcie_dev *dev = tbsca->dev;
	u32 data;
	int ret;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data = TBS_PCIE_READ(pcmcia_adapter0+tbsca->channel_index*0x1000, 0x0c) & 1;
	if (tbsca->status != data){
		TBS_PCIE_WRITE(pcmcia_adapter0+tbsca->channel_index*0x1000, 0x08, !data);
		msleep(300);
		tbsca->status = data;
	}
	mutex_unlock(&tbsca->lock);

	if (data & 1)
		ret = DVB_CA_EN50221_POLL_CAM_PRESENT |
		      DVB_CA_EN50221_POLL_CAM_READY;
	else
		ret = 0;

	return ret;		
}

static int tas2101_read_ber(struct dvb_frontend *fe, u32 *ber)
{
	//printk("%s \n", __func__);
	*ber = 0;
	return 0;
}

static int tas2101_read_signal_strength(struct dvb_frontend *fe,
	u16 *signal_strength)
{
	//printk("%s \n", __func__);
	*signal_strength = 62940;
	return 0;
	
}

static int tas2101_read_snr(struct dvb_frontend *fe, u16 *snr)
{
 	//printk("%s \n", __func__);

	*snr = 26896;
	return 0;
}

/* unimplemented */
static int tas2101_read_ucblocks(struct dvb_frontend *fe, u32 *ucblocks)
{
	//printk("%s \n", __func__);
	return 0;
}

static int tas2101_read_status(struct dvb_frontend *fe, enum fe_status *status)
{
	//printk("%s \n", __func__);
	*status = FE_HAS_SIGNAL | FE_HAS_CARRIER |
			FE_HAS_VITERBI | FE_HAS_SYNC | FE_HAS_LOCK;
	return 0;

}

static int tas2101_set_voltage(struct dvb_frontend *fe,
	enum fe_sec_voltage voltage)
{
	return 0;
	
}

static int tas2101_set_tone(struct dvb_frontend *fe,
	enum fe_sec_tone_mode tone)
{
	return 0;
	
}

static int tas2101_send_diseqc_msg(struct dvb_frontend *fe,
	struct dvb_diseqc_master_cmd *d)
{
	return 0;

}

static int tas2101_diseqc_send_burst(struct dvb_frontend *fe,
	enum fe_sec_mini_cmd burst)
{
	return 0;
}

static void tas2101_release(struct dvb_frontend *fe)
{

}


static int tas2101_initfe(struct dvb_frontend *fe)
{
	return 0;

}

static int tas2101_sleep(struct dvb_frontend *fe)
{
	return 0;
}

static int tas2101_get_frontend(struct dvb_frontend *fe,struct dtv_frontend_properties *c)
{
	//printk("%s \n", __func__);
	c->fec_inner = 1;
	c->modulation = 0;
	c->delivery_system = 5;
	c->inversion = 2;
	c->symbol_rate = 41260000;
	return 0;
}

static int tas2101_tune(struct dvb_frontend *fe, bool re_tune,
	unsigned int mode_flags, unsigned int *delay, enum fe_status *status)
{	
	return tas2101_read_status(fe, status);
}

static enum dvbfe_algo tas2101_get_algo(struct dvb_frontend *fe)
{
	return DVBFE_ALGO_HW;

}


static struct dvb_frontend_ops tas2101_ops = {
	.delsys = { SYS_DVBS, SYS_DVBS2 },
	.info = {
		.name = "tbs6900 dual ci",
		.frequency_min_hz	=  950 * MHz,
		.frequency_max_hz	= 2150 * MHz,
		.symbol_rate_min	= 1000000,
		.symbol_rate_max	= 45000000,
		.caps = FE_CAN_INVERSION_AUTO |
			FE_CAN_FEC_1_2 | FE_CAN_FEC_2_3 | FE_CAN_FEC_3_4 |
			FE_CAN_FEC_4_5 | FE_CAN_FEC_5_6 | FE_CAN_FEC_6_7 |
			FE_CAN_FEC_7_8 | FE_CAN_FEC_AUTO |
			FE_CAN_2G_MODULATION |
			FE_CAN_QPSK | FE_CAN_RECOVER
	},
	.release = tas2101_release,

	.init = tas2101_initfe,
	.sleep = tas2101_sleep,

	.read_status = tas2101_read_status,
	.read_ber = tas2101_read_ber,
	.read_signal_strength = tas2101_read_signal_strength,
	.read_snr = tas2101_read_snr,
	.read_ucblocks = tas2101_read_ucblocks,

	.set_tone = tas2101_set_tone,
	.set_voltage = tas2101_set_voltage,
	.diseqc_send_master_cmd = tas2101_send_diseqc_msg,
	.diseqc_send_burst = tas2101_diseqc_send_burst,

	.get_frontend_algo = tas2101_get_algo,
	.tune = tas2101_tune,

//	.get_tune_settings = tas2101_get_tune_settings,
//	.set_frontend = tas2101_set_frontend,
	.get_frontend = tas2101_get_frontend,


};

static int start_feed(struct dvb_demux_feed *dvbdmxfeed)
{
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	struct ca_channel *tbsca = dvbdmx->priv;
	//printk("%s feeds:%d\n", __func__,tbsca->feeds);
	if (!tbsca->feeds)
		start_indma_transfer(tbsca);

	return ++tbsca->feeds;
}

static int stop_feed(struct dvb_demux_feed *dvbdmxfeed)
{
	struct dvb_demux *dvbdmx = dvbdmxfeed->demux;
	struct ca_channel *tbsca = dvbdmx->priv;
	//printk("%s feeds:%d\n", __func__,tbsca->feeds);
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


struct dvb_ca_en50221 ca_config = {
	.read_attribute_mem  = ca_read_attribute_mem,
	.write_attribute_mem = ca_write_attribute_mem,
	.read_cam_control    = ca_read_cam_control,
	.write_cam_control   = ca_write_cam_control,
	.slot_reset          = ca_slot_reset,
	.slot_shutdown       = ca_slot_shutdown,
	.slot_ts_enable      = ca_slot_ts_enable,
	.poll_slot_status    = ca_poll_slot_status
};

static void tbs_adapters_remove(struct tbs_pcie_dev *dev)
{
	struct ca_channel *tbsca;
	struct dvb_demux *dvbdemux;
	int i;
	//printk("%s \n", __func__);

	for(i=0;i<CHANNELS;i++){
		tbsca = &dev->channnel[i];
		kfifo_free(&tbsca->w_fifo);
		kfifo_free(&tbsca->r_fifo);
		if (!tbsca->w_dmavirt){
			pci_free_consistent(dev->pdev, DMASIZE, tbsca->w_dmavirt, tbsca->w_dmaphy);
			tbsca->w_dmavirt = NULL;
		}
		if (!tbsca->r_dmavirt){
			pci_free_consistent(dev->pdev, DMASIZE, tbsca->r_dmavirt, tbsca->r_dmaphy);
			tbsca->r_dmavirt = NULL;
		}
	//	tasklet_kill(&tbsca->tasklet);
	}

	for(i=0;i<CHANNELS;i++){
		tbsca = &dev->channnel[i];
		dvbdemux = &tbsca->demux;
		
		dvb_net_release(&tbsca->dvbnet);
		dvbdemux->dmx.close(&dvbdemux->dmx);
		dvbdemux->dmx.remove_frontend(&dvbdemux->dmx, &tbsca->fe_mem);
		dvbdemux->dmx.remove_frontend(&dvbdemux->dmx, &tbsca->fe_hw);
		dvb_dmxdev_release(&tbsca->dmxdev);
		dvb_dmx_release(&tbsca->demux);
		dvb_unregister_frontend(&tbsca->fe);

		dvb_ca_en50221_release(&tbsca->ca);
		dvb_unregister_device(tbsca->ci_dev);
	}
	dvb_unregister_adapter(&dev->adapter);	
}

static int tbs_adapters_init(struct tbs_pcie_dev *dev)
{
	int i=0;
	int ret=0;
		struct ca_channel *tbsca;

	for(i=0;i<CHANNELS;i++){
		tbsca = &dev->channnel[i];
		tbsca->w_dmavirt = pci_alloc_consistent(dev->pdev, DMASIZE, &tbsca->w_dmaphy);
		if (!tbsca->w_dmavirt)
		{
			printk(" allocate write memory failed\n");
			goto fail;
		}
		tbsca->r_dmavirt = pci_alloc_consistent(dev->pdev, DMASIZE, &tbsca->r_dmaphy);
		if (!tbsca->r_dmavirt)
		{
			printk(" allocate read memory failed\n");
			goto fail;
		}
		tbsca->channel_index=i;
		tbsca->dev = dev;
		tbsca->w_bitrate = 50;

		ret = kfifo_alloc(&tbsca->w_fifo, FIFOSIZE, GFP_KERNEL);
		if (ret != 0)
			goto fail;
		ret = kfifo_alloc(&tbsca->r_fifo, FIFOSIZE, GFP_KERNEL);
		if (ret != 0)
			goto fail;

		INIT_WORK(&tbsca->read_work,read_dma_work);
		INIT_WORK(&tbsca->write_work,write_dma_work);
		init_waitqueue_head(&tbsca->write_wq);
		init_waitqueue_head(&tbsca->read_wq);
		spin_lock_init(&tbsca->readlock);
		spin_lock_init(&tbsca->writelock);
	}

	ret = dvb_register_adapter(&dev->adapter, "tbsci",THIS_MODULE,&dev->pdev->dev,adapter_nr);

	for(i=0;i<CHANNELS;i++){
		tbsca = &dev->channnel[i];
		memcpy(&tbsca->ca, &ca_config, sizeof(struct dvb_ca_en50221));
		tbsca->ca.owner = THIS_MODULE;
		tbsca->ca.data = tbsca;

		tbsca->channel_index = i;
		tbsca->status = 0;
		mutex_init(&tbsca->lock);
		ret = dvb_ca_en50221_init(&dev->adapter, &tbsca->ca, 0, 1);
		if (ret < 0) {
			printk("%s ERROR: dvb_ca_en50221_init\n", __func__);;
			goto fail;
		}
		ret = dvb_register_device(&dev->adapter, &tbsca->ci_dev,&tbs_ci, (void *) tbsca,DVB_DEVICE_SEC,0);
		if (ret < 0) {
			printk("%s ERROR: dvb_register_device\n", __func__);;
			goto fail;
		}

		memcpy(&tbsca->fe.ops, &tas2101_ops,sizeof(struct dvb_frontend_ops));
		tbsca->fe.demodulator_priv = tbsca;
		ret = dvb_register_frontend(&dev->adapter, &tbsca->fe) ;
		if (ret < 0) {
			printk("%s ERROR: dvb_register_frontend\n", __func__);;
			goto fail;
		}

		ret = my_dvb_dmx_ts_card_init(&tbsca->demux, "SW demux",
					      start_feed,
					      stop_feed, tbsca);
		if (ret < 0) {
			printk("%s ERROR: my_dvb_dmx_ts_card_init\n", __func__);;
			goto fail;
		}
						  
		ret = my_dvb_dmxdev_ts_card_init(&tbsca->dmxdev, &tbsca->demux,
						 &tbsca->fe_hw,
						 &tbsca->fe_mem, &dev->adapter);  
		if (ret < 0) {
			printk("%s ERROR: my_dvb_dmxdev_ts_card_init\n", __func__);;
			goto fail;
		}
		ret = dvb_net_init(&dev->adapter, &tbsca->dvbnet,&tbsca->demux.dmx);
		if (ret < 0) {
			printk("%s ERROR: dvb_net_init\n", __func__);;
			goto fail;
		}
	}

	TBS_PCIE_WRITE(int_adapter, INT_EN, (1));
	TBS_PCIE_WRITE(int_adapter, I2C0_MASK, (1));
	TBS_PCIE_WRITE(int_adapter, I2C1_MASK, (1));
	TBS_PCIE_WRITE(int_adapter, I2C2_MASK, (1));
	TBS_PCIE_WRITE(int_adapter, I2C3_MASK, (1));
	return 0;
fail:
	tbs_adapters_remove(dev);
	return ret;
}

static void tbsci_remove(struct pci_dev *pdev)
{
	struct tbs_pcie_dev *dev =
		(struct tbs_pcie_dev *)pci_get_drvdata(pdev);
	printk("%s \n", __func__);

	tbs_adapters_remove(dev);

	/* disable interrupts */
	free_irq(dev->pdev->irq, dev);

	if (dev->mmio)
		iounmap(dev->mmio);

	kfree(dev);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
}


static int tbsci_probe(struct pci_dev *pdev,
						const struct pci_device_id *pci_id)
{
	struct tbs_pcie_dev *dev;
	int err = 0, ret = -ENODEV;
	
	dev = kzalloc(sizeof(struct tbs_pcie_dev), GFP_KERNEL);
	if (dev == NULL)
	{
		printk("%s ERROR: out of memory\n", __func__);
		ret = -ENOMEM;
		goto fail0;
	}

	dev->pdev = pdev;

	err = pci_enable_device(pdev);
	if (err != 0)
	{
		ret = -ENODEV;
		printk("%s ERROR: PCI enable failed (%i)\n", __func__, err);
		goto fail1;
	}

	dev->mmio = ioremap(pci_resource_start(dev->pdev, 0),
						pci_resource_len(dev->pdev, 0));
	if (!dev->mmio)
	{
		printk("%s ERROR: Mem 0 remap failed\n", __func__);
		ret = -ENODEV; /* -ENOMEM better?! */
		goto fail2;
	}

	ret = request_irq(dev->pdev->irq, tbsci_irq, IRQF_SHARED, KBUILD_MODNAME, (void *)dev);
	if (ret < 0)
	{
		printk("%s ERROR: IRQ registration failed <%d>\n", __func__, ret);
		ret = -ENODEV;
		goto fail2;
	}

	pci_set_drvdata(pdev, dev);

	ret = tbs_adapters_init(dev);
	if (ret < 0)
	{
		printk("%s ERROR: tbs_adapters_init <%d>\n", __func__, ret);
		ret = -ENODEV;
		goto fail3;
	}


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

static const struct pci_device_id tbsci_id_table[] = {
	MAKE_ENTRY(0x544d, 0x6178, 0x6900, 0x0001, NULL),
	{}};
MODULE_DEVICE_TABLE(pci, tbsci_id_table);

static struct pci_driver tbsci_pci_driver = {
	.name = "tbsci",
	.id_table = tbsci_id_table,
	.probe = tbsci_probe,
	.remove = tbsci_remove,
};


static __init int module_init_tbsci(void)
{
	int stat;

	//printk("%s\n",__func__);

	wq = create_singlethread_workqueue("tbs");
	stat = pci_register_driver(&tbsci_pci_driver);
	return stat;
}

static __exit void module_exit_tbsci(void)
{
	//printk("%s\n",__func__);
	if(wq)
		destroy_workqueue(wq);
	wq=NULL;
	pci_unregister_driver(&tbsci_pci_driver);
}

module_init(module_init_tbsci);
module_exit(module_exit_tbsci);

MODULE_DESCRIPTION("tbs PCIe Bridge");
MODULE_AUTHOR("kernelcoding");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0.0");
