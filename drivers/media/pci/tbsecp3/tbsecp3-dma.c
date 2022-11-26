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

static unsigned int dma_pkts[8] = {128, 128, 128, 128, 128, 128, 128, 128};
module_param_array(dma_pkts, int, NULL, 0444); /* No /sys/module write access */
MODULE_PARM_DESC(dma_pkts, "DMA buffer size in TS packets (16-256), default 128");

static int gse_dump;
module_param(gse_dump, int, 0644);
MODULE_PARM_DESC(gse_dump, "Turn on/off GSE dump (default:off).");

static int gse_tscheck;
module_param(gse_tscheck, int, 0644);
MODULE_PARM_DESC(gse_tscheck,
		"enable transport stream continuity and TEI check");

static int gse_feed_err_pkts = 1;
module_param(gse_feed_err_pkts, int, 0644);
MODULE_PARM_DESC(gse_feed_err_pkts,
		 "when set to 0, drop packets with the TEI bit set (1 by default)");

#define dprintk(fmt, arg...) \
	printk(KERN_DEBUG pr_fmt("%s: " fmt),  __func__, ##arg)

#define dprintk_gse_tscheck(x...) do {			\
	if (gse_tscheck && printk_ratelimit())	\
		dprintk(x);				\
} while (0)

#define TS_PACKET_SIZE		188
/* Maximum GSE packet length = GSE length  4095 + Minimum 2 Bytes header. */
#define GSE_MAX_PACKET_LENGTH 4097

static void tbsecp3_ts_to_gse(struct tbsecp3_adapter *adap, const u8 *buf)
{
	/*Removing SOF byte */
	u32 gse_len_in_ts = buf[7]-1;
	const u8 *buf_gse;
	u32 header_info = 0;
	u16 protocol_type = 0;
	u8 header_len = 0;
	enum gse_payload_type payload_type;
	
	if (!adap->gse_info.gse_buff)
		return;

	if(!adap->gse_info.sofi) {
		adap->gse_info.pos = 0;
		adap->gse_info.next_pkt = 0x0;
		adap->gse_info.pkt_cnt = 0x0;
	}
	if((0x80 == (buf[8]&0x80))) {

		buf_gse = &buf[9];
		header_info = *buf_gse << 24 | *(buf_gse+1)<<16 | *(buf_gse+2)<<8 | *(buf_gse +3);
		payload_type = ((enum gse_payload_type)(GSE_PAYLOAD_TYPE(header_info)));
		header_len = (payload_type == GSE_FULL_PDU) ? GSE_FULL_PDU_HEADER_LENGTH:GSE_FIRST_FRAG_HEADER_LENGTH;
		protocol_type = *(buf_gse + header_len - 2) << 8 | *(buf_gse + header_len - 1);

		if(adap->gse_info.sofi) {
			u32 gse_len = (((adap->gse_info.gse_buff[0] & 0xf) << 8) | adap->gse_info.gse_buff[1])+ 2;
			if(adap->gse_info.pos >= gse_len) {
				dvb_dmx_swfilter_gse(&adap->demux,adap->gse_info.gse_buff,gse_len);
			}
			memset(adap->gse_info.gse_buff,0x0,GSE_MAX_PACKET_LENGTH);
			adap->gse_info.pos = 0;
		}
		memcpy(adap->gse_info.gse_buff,buf+9,gse_len_in_ts);

		if (protocol_type == 0x81) {
			u32 gse_len = (((adap->gse_info.gse_buff[0] & 0xf) << 8) | adap->gse_info.gse_buff[1])+ 2;

			memset(&(adap->gse_info.gse_buff[gse_len_in_ts - 1]),0x00, 6);

			dvb_dmx_swfilter_gse(&adap->demux, adap->gse_info.gse_buff, gse_len + 6);
			memset(adap->gse_info.gse_buff, 0x0, GSE_MAX_PACKET_LENGTH);
			adap->gse_info.pos = 0;
			adap->gse_info.sofi = 0x0;
			adap->gse_info.next_pkt = 0x0;
		}
		else {
			adap->gse_info.pos += gse_len_in_ts;
			adap->gse_info.sofi = 0x1;
			adap->gse_info.next_pkt = 0x1;
			adap->gse_info.pkt_cnt = 0x0;
		}
	}
	else if (adap->gse_info.next_pkt) {
		if(buf[8] == adap->gse_info.pkt_cnt+1) {
			memcpy(adap->gse_info.gse_buff+adap->gse_info.pos,buf+9, gse_len_in_ts);
			adap->gse_info.pos += gse_len_in_ts;
			adap->gse_info.pkt_cnt++;
		}
		else {
			adap->gse_info.sofi = 0x0;
			adap->gse_info.next_pkt = 0x0;
			dprintk_gse_tscheck("TS/GSE packet count is not continous expected =%d received =%d\n",
				adap->gse_info.pkt_cnt+1,buf[8]);
		}
	}
}

static void tbsecp3_swfilter_packets(struct tbsecp3_adapter *adap, const u8 *buf, size_t count)
{
	int i;
	dvb_dmx_swfilter_packets(&adap->demux, buf, count);

	if (!adap->cfg->pusi_gse)
		return;

	while(count) {
		/* GSE PUSI packets processing */
		if((buf[0]==0x47)&&((buf[1]&0x7F)==0x41)&&(buf[2]==0x18)&&(buf[5]==0x80)) {
			if (buf[1] & 0x80) {
				dprintk_gse_tscheck("TEI detected. data1=0x%x\n", buf[1]);

				/* data in this packet cant be trusted - drop it unless
				  * module option dvb_demux_feed_err_pkts is set */
				if (!gse_feed_err_pkts)
					return;
			} else /* if TEI bit is not set, check continuity counter */
				if (gse_tscheck) {
						if (buf[3] & 0x10)
							adap->gse_info.cnt_storage =
								(adap->gse_info.cnt_storage + 1) & 0xf;

						if ((buf[3] & 0xf) != adap->gse_info.cnt_storage) {
							dprintk_gse_tscheck("TS packet counter mismatch. expected 0x%x got 0x%x\n",
								adap->gse_info.cnt_storage,
								buf[3] & 0xf);
							adap->gse_info.cnt_storage = buf[3] & 0xf;
						}
				/* end check */
				}

			/* patch because HDR modem send dummy frames with bad lenght. so we discard such packets */
			if(!((buf[8]==0xd0)&&(buf[11]==0xff)&&(buf[12]==0xff))) {
				if(gse_dump)
					for(i=0; i<1; i++)
						dprintk_gse_tscheck("buf[%03d]:%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", 20*i, buf[20*i], buf[20*i+1], buf[20*i+2], buf[20*i+3], buf[20*i+4], buf[20*i+5], buf[20*i+6], buf[20*i+7], buf[20*i+8], buf[20*i+9], buf[20*i+10], buf[20*i+11], buf[20*i+12], buf[20*i+13], buf[20*i+14], buf[20*i+15], buf[20*i+16], buf[20*i+17], buf[20*i+18], buf[20*i+19]);

				tbsecp3_ts_to_gse(adap,buf);
			}
		}
		/* Next packet */
		buf += TS_PACKET_SIZE;
		count --;
	}
}
static void tbsecp3_dma_tasklet(unsigned long adap)
{
	struct tbsecp3_adapter *adapter = (struct tbsecp3_adapter *) adap;
	struct tbsecp3_dev *dev = adapter->dev;
	u32 read_buffer, next_buffer;
	u8* data;
	int i;

	spin_lock(&adapter->adap_lock);

	if (adapter->dma.cnt < TBSECP3_DMA_PRE_BUFFERS)
	{
		next_buffer = (tbs_read(adapter->dma.base, TBSECP3_DMA_STAT) - TBSECP3_DMA_PRE_BUFFERS + 1) & (TBSECP3_DMA_BUFFERS - 1);
		adapter->dma.cnt++;
	}
        else
        {
		next_buffer = (tbs_read(adapter->dma.base, TBSECP3_DMA_STAT) - TBSECP3_DMA_PRE_BUFFERS + 1) & (TBSECP3_DMA_BUFFERS - 1);
		read_buffer = (u32)adapter->dma.next_buffer;

		while (read_buffer != next_buffer)
		{
			data = adapter->dma.buf[read_buffer];

			if (data[adapter->dma.offset] != 0x47) {
			/* Find sync byte offset with crude force (this might fail!) */
				for (i = 0; i < TS_PACKET_SIZE; i++)
					if ((data[i] == 0x47) &&
					(data[i + TS_PACKET_SIZE] == 0x47) &&
					(data[i + 2 * TS_PACKET_SIZE] == 0x47) &&
					(data[i + 4 * TS_PACKET_SIZE] == 0x47)) {
						adapter->dma.offset = i;
						break;
				}
			}

			if (adapter->dma.offset != 0) {
				data += adapter->dma.offset;
				/* Copy remains of last packet from buffer 0 behind last one */
				if (read_buffer == (TBSECP3_DMA_BUFFERS - 1)) {
					memcpy( adapter->dma.buf[TBSECP3_DMA_BUFFERS],
						adapter->dma.buf[0], adapter->dma.offset);
				}
			}
			tbsecp3_swfilter_packets(adapter, data, adapter->dma.buffer_pkts);
			read_buffer = (read_buffer + 1) & (TBSECP3_DMA_BUFFERS - 1);
		}
	}

	adapter->dma.next_buffer = (u8)next_buffer;

	spin_unlock(&adapter->adap_lock);

}

void tbsecp3_dma_enable(struct tbsecp3_adapter *adap)
{
	struct tbsecp3_dev *dev = adap->dev;

	spin_lock_irq(&adap->adap_lock);
	adap->dma.offset = 0;
	adap->dma.cnt = 0;
	adap->dma.next_buffer= 0;
	tbs_read(adap->dma.base, TBSECP3_DMA_STAT);
	tbs_write(TBSECP3_INT_BASE, TBSECP3_DMA_IE(adap->cfg->ts_in), 1); 
	tbs_write(adap->dma.base, TBSECP3_DMA_EN, 1);
	spin_unlock_irq(&adap->adap_lock);
}

void tbsecp3_dma_disable(struct tbsecp3_adapter *adap)
{
	struct tbsecp3_dev *dev = adap->dev;

	spin_lock_irq(&adap->adap_lock);
	tbs_read(adap->dma.base, TBSECP3_DMA_STAT);
	tbs_write(TBSECP3_INT_BASE, TBSECP3_DMA_IE(adap->cfg->ts_in), 0);
	tbs_write(adap->dma.base, TBSECP3_DMA_EN, 0);
	spin_unlock_irq(&adap->adap_lock);
}

void tbsecp3_dma_reg_init(struct tbsecp3_dev *dev)
{
	int i;
	struct tbsecp3_adapter *adapter = dev->adapter;

	for (i = 0; i < dev->info->adapters; i++) {
		tbs_write(adapter->dma.base, TBSECP3_DMA_EN, 0);
		tbs_write(adapter->dma.base, TBSECP3_DMA_ADDRH, 0);
		tbs_write(adapter->dma.base, TBSECP3_DMA_ADDRL, (u32) adapter->dma.dma_addr);
		tbs_write(adapter->dma.base, TBSECP3_DMA_TSIZE, adapter->dma.page_size);
		tbs_write(adapter->dma.base, TBSECP3_DMA_BSIZE, adapter->dma.buffer_size);
		adapter++;
	}
}

void tbsecp3_dma_free(struct tbsecp3_dev *dev)
{
	struct tbsecp3_adapter *adapter = dev->adapter;
	int i;
	for (i = 0; i < dev->info->adapters; i++) {
		if (adapter->dma.buf[0] == NULL)
			continue;

		dma_free_coherent(&dev->pci_dev->dev,
			adapter->dma.page_size + 0x100,
			adapter->dma.buf[0], adapter->dma.dma_addr);
		adapter->dma.buf[0] = NULL;

		if (adapter->gse_info.gse_buff)
			kfree(adapter->gse_info.gse_buff);
		adapter++;
	}
}

int tbsecp3_dma_init(struct tbsecp3_dev *dev)
{
	struct tbsecp3_adapter *adapter = dev->adapter;
	int i, j;

	for (i = 0; i < dev->info->adapters; i++) {
		if (dma_pkts[i] < 16)
			dma_pkts[i] = 16;
		if (dma_pkts[i] > 256)
			dma_pkts[i] = 256;

		adapter->dma.buffer_pkts = dma_pkts[i];
		adapter->dma.buffer_size = dma_pkts[i] * TS_PACKET_SIZE;
		adapter->dma.page_size = adapter->dma.buffer_size * TBSECP3_DMA_BUFFERS;

		adapter->dma.buf[0] = dma_alloc_coherent(&dev->pci_dev->dev,
				adapter->dma.page_size + 0x100,
				&adapter->dma.dma_addr, GFP_KERNEL);
		if (!adapter->dma.buf[0])
			goto err;

		adapter->gse_info.gse_buff = kzalloc(GSE_MAX_PACKET_LENGTH, GFP_KERNEL);

		if (!adapter->gse_info.gse_buff)
			dev_warn(&dev->pci_dev->dev, "Can't allocate GSE packet buffer !");
	
		adapter->gse_info.pos = 0;
		adapter->gse_info.pkt_cnt = 0;
		adapter->gse_info.cnt_storage = 0;
		adapter->gse_info.sofi = false;
		adapter->gse_info.next_pkt = false;

		dev_dbg(&dev->pci_dev->dev,
			"TS in %d: DMA page %d bytes, %d bytes (%d TS packets) per %d buffers\n", adapter->cfg->ts_in, 
			 adapter->dma.page_size, adapter->dma.buffer_size, adapter->dma.buffer_pkts, TBSECP3_DMA_BUFFERS);

		adapter->dma.base = TBSECP3_DMA_BASE(adapter->cfg->ts_in);
		adapter->dma.cnt = 0;
		adapter->dma.next_buffer = 0;
		for (j = 1; j < TBSECP3_DMA_BUFFERS + 1; j++)
			adapter->dma.buf[j] = adapter->dma.buf[j-1] + adapter->dma.buffer_size;

		tasklet_init(&adapter->tasklet, tbsecp3_dma_tasklet, (unsigned long) adapter);
		spin_lock_init(&adapter->adap_lock);
		adapter++;
	}
	tbsecp3_dma_reg_init(dev);
	return 0;
err:
	dev_err(&dev->pci_dev->dev, "dma: memory alloc failed\n");
	tbsecp3_dma_free(dev);
	return -ENOMEM;
}
