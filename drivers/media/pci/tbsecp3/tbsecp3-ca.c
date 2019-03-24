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

static int tbsecp3_ca_rd_attr_mem(struct dvb_ca_en50221 *ca,
	int slot, int address)
{
	struct tbsecp3_ca *tbsca = ca->data;
	struct tbsecp3_adapter *adapter = tbsca->adapter;
	struct tbsecp3_dev *dev = adapter->dev;
	u32 data = 0;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data |= (address >> 8) & 0x7f;
	data |= (address & 0xff) << 8;
	tbs_write(TBSECP3_CA_BASE(tbsca->nr), 0x00, data);
	udelay(150);

	data = tbs_read(TBSECP3_CA_BASE(tbsca->nr), 0x04);

	mutex_unlock(&tbsca->lock);

	return (data & 0xff);
}

static int tbsecp3_ca_wr_attr_mem(struct dvb_ca_en50221 *ca,
	int slot, int address, u8 value)
{
	struct tbsecp3_ca *tbsca = ca->data;
	struct tbsecp3_adapter *adapter =
			(struct tbsecp3_adapter *) tbsca->adapter;
	struct tbsecp3_dev *dev = adapter->dev;
	u32 data = 0;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data |= (address >> 8) & 0x7f;
	data |= (address & 0xff) << 8;
	data |= 0x01 << 16;
	data |= value << 24;
	tbs_write(TBSECP3_CA_BASE(tbsca->nr), 0x00, data);
	udelay(150);

	mutex_unlock(&tbsca->lock);

	return 0;
}

static int tbsecp3_ca_rd_cam_ctrl(struct dvb_ca_en50221 *ca, 
	int slot, u8 address)
{
	struct tbsecp3_ca *tbsca = ca->data;
	struct tbsecp3_adapter *adapter =
			(struct tbsecp3_adapter *) tbsca->adapter;
	struct tbsecp3_dev *dev = adapter->dev;
	u32 data = 0;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data |= (address & 3) << 8;
	data |= 0x02 << 16;
	tbs_write(TBSECP3_CA_BASE(tbsca->nr), 0x00, data);
	udelay(150);
	
	data = tbs_read(TBSECP3_CA_BASE(tbsca->nr), 0x08);

	mutex_unlock(&tbsca->lock);

	return (data & 0xff);
}

static int tbsecp3_ca_wr_cam_ctrl(struct dvb_ca_en50221 *ca, int slot,
	u8 address, u8 value)
{
	struct tbsecp3_ca *tbsca = ca->data;
	struct tbsecp3_adapter *adapter =
			(struct tbsecp3_adapter *) tbsca->adapter;
	struct tbsecp3_dev *dev = adapter->dev;
	u32 data = 0;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data |= (address & 3) << 8;
	data |= 0x03 << 16;
	data |= value << 24;
	tbs_write(TBSECP3_CA_BASE(tbsca->nr), 0x00, data);
	udelay(150);

	mutex_unlock(&tbsca->lock);

	return 0;
}

static int tbsecp3_ca_slot_reset(struct dvb_ca_en50221 *ca, int slot)
{
	struct tbsecp3_ca *tbsca = ca->data;
	struct tbsecp3_adapter *adapter =
			(struct tbsecp3_adapter *) tbsca->adapter;
	struct tbsecp3_dev *dev = adapter->dev;

	if (slot != 0)
		return -EINVAL;
	
	mutex_lock(&tbsca->lock);

	tbs_write(TBSECP3_CA_BASE(tbsca->nr), 0x04, 1);
	msleep (10);

	tbs_write(TBSECP3_CA_BASE(tbsca->nr), 0x04, 0);
	msleep (2800);

	mutex_unlock (&tbsca->lock);
	return 0;
}

static int tbsecp3_ca_slot_ctrl(struct dvb_ca_en50221 *ca,
	int slot, int enable)
{
	struct tbsecp3_ca *tbsca = ca->data;
	struct tbsecp3_adapter *adapter = 
			(struct tbsecp3_adapter *) tbsca->adapter;
	struct tbsecp3_dev *dev = adapter->dev;
	u32 data;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);

	data = enable & 1;
	tbs_write(TBSECP3_CA_BASE(tbsca->nr), 0x0c, data);

	mutex_unlock(&tbsca->lock);

	dev_info(&dev->pci_dev->dev, "CA slot %sabled for adapter%d\n",
		enable ? "en" : "dis",
		adapter->fe->dvb->num);

	return 0;
}

static int tbsecp3_ca_slot_shutdown(struct dvb_ca_en50221 *ca, int slot)
{
	return tbsecp3_ca_slot_ctrl(ca, slot, 0);
}

static int tbsecp3_ca_slot_ts_enable(struct dvb_ca_en50221 *ca, int slot)
{
	return tbsecp3_ca_slot_ctrl(ca, slot, 1);
}

static int tbsecp3_ca_poll_slot_status(struct dvb_ca_en50221 *ca, 
	int slot, int open)
{
	struct tbsecp3_ca *tbsca = ca->data;
	struct tbsecp3_adapter *adapter =
			(struct tbsecp3_adapter *) tbsca->adapter;
	struct tbsecp3_dev *dev = adapter->dev;
	u32 data;
	int ret;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&tbsca->lock);
	data = tbs_read(TBSECP3_CA_BASE(tbsca->nr), 0x0c) & 1;
	if (tbsca->status != data){
		tbs_write(TBSECP3_CA_BASE(tbsca->nr), 0x08, !data);
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


struct dvb_ca_en50221 ca_config = {
	.read_attribute_mem  = tbsecp3_ca_rd_attr_mem,
	.write_attribute_mem = tbsecp3_ca_wr_attr_mem,
	.read_cam_control    = tbsecp3_ca_rd_cam_ctrl,
	.write_cam_control   = tbsecp3_ca_wr_cam_ctrl,
	.slot_reset          = tbsecp3_ca_slot_reset,
	.slot_shutdown       = tbsecp3_ca_slot_shutdown,
	.slot_ts_enable      = tbsecp3_ca_slot_ts_enable,
	.poll_slot_status    = tbsecp3_ca_poll_slot_status,
};


int tbsecp3_ca_init(struct tbsecp3_adapter *adap, int nr)
{
	struct tbsecp3_dev *dev = adap->dev;
	struct tbsecp3_ca *tbsca;
	int ret;

	tbsca = kzalloc(sizeof(struct tbsecp3_ca), GFP_KERNEL);
	if (tbsca == NULL) {
		ret = -ENOMEM;
		goto error1;
	}

	adap->tbsca = tbsca;

	tbsca->nr = nr;
	tbsca->status = 0;
	tbsca->adapter = adap;
	mutex_init(&tbsca->lock);

	memcpy(&tbsca->ca, &ca_config, sizeof(struct dvb_ca_en50221));
	tbsca->ca.owner = THIS_MODULE;
	tbsca->ca.data = tbsca;

	dev_info(&dev->pci_dev->dev,
		"initializing CA slot %d on adapter %d\n",
		nr, adap->dvb_adapter.num);

	ret = dvb_ca_en50221_init(&adap->dvb_adapter, &tbsca->ca, 0, 1);
	if (ret)
		goto error2;

	return 0;

error2: 
	kfree(tbsca);
error1:
	dev_err(&dev->pci_dev->dev,
		"adapter %d CA slot initialization failed\n",
		adap->dvb_adapter.num);
	return ret;
}

void tbsecp3_ca_release(struct tbsecp3_adapter *adap)
{
	struct tbsecp3_ca *tbsca = adap->tbsca;
	if (!adap)
		return;
	if (!tbsca)
		return;
	if (!tbsca->ca.data)
		return;
	dvb_ca_en50221_release(&tbsca->ca);
	kfree(tbsca);
}

