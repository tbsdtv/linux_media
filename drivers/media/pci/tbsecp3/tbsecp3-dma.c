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

static unsigned int dma_pkts[16] = {128, 128, 128, 128, 128, 128, 128, 128,128, 128, 128, 128, 128, 128, 128, 128};
module_param_array(dma_pkts, int, NULL, 0444); /* No /sys/module write access */
MODULE_PARM_DESC(dma_pkts, "DMA buffer size in TS packets (16-256), default 128");

#define TS_PACKET_SIZE		188

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
			dvb_dmx_swfilter_packets(&adapter->demux, data, adapter->dma.buffer_pkts);
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
