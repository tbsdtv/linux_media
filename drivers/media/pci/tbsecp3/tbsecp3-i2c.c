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

union tbsecp3_i2c_ctrl {
	struct {
		u32 ctrl;
		u32 data;
	} raw;
	struct {
		u8 size:4;
		u8 saddr:2;
		u8 stop:1;
		u8 start:1;
		u8 read:1;
		u8 addr:7;
		u8 buf[6];
	} bits;
};

static int i2c_xfer(struct i2c_adapter *adapter, struct i2c_msg *msg, int num)
{
	struct tbsecp3_i2c *bus = i2c_get_adapdata(adapter);
	struct tbsecp3_dev *dev = bus->dev;
	union tbsecp3_i2c_ctrl i2c_ctrl;
	int i, j, retval;
	u16 len, remaining, xfer_max;
	u8 *b;

	mutex_lock(&bus->lock);
	//clear the i2c status	
	tbs_read(bus->base, 0x00);

	for (i = 0; i < num; i++) {

		b = msg[i].buf;
		remaining = msg[i].len;

		i2c_ctrl.raw.ctrl = 0;
		i2c_ctrl.bits.start = 1;
		i2c_ctrl.bits.addr = msg[i].addr;
		
		if (msg[i].flags & I2C_M_RD) {
			i2c_ctrl.bits.read = 1;
			xfer_max = 4;
		} else {
			xfer_max = 6;
		}

		do {
			if (remaining <= xfer_max)
				i2c_ctrl.bits.stop = 1;

			len = remaining > xfer_max ? xfer_max : remaining;
			i2c_ctrl.bits.size = len;

			if (!(msg[i].flags & I2C_M_RD)) {
				for (j = 0; j < len; j++)
					i2c_ctrl.bits.buf[j] = *b++;
				tbs_write(bus->base, TBSECP3_I2C_DATA, i2c_ctrl.raw.data);
			}
			bus->done = 0;
			tbs_write(bus->base, TBSECP3_I2C_CTRL, i2c_ctrl.raw.ctrl);
			retval = wait_event_timeout(bus->wq, bus->done == 1, HZ);
			if (retval == 0) {
				tbs_read(bus->base, TBSECP3_I2C_STAT); // restore iic to its original state
				dev_err(&dev->pci_dev->dev, "i2c xfer timeout\n");
				retval = -EIO;
				goto i2c_xfer_exit;
			}

			j = tbs_read(bus->base, TBSECP3_I2C_CTRL);
			if (j & 0x04) {
				dev_err(&dev->pci_dev->dev, "i2c nack (%x)\n", j);
				retval = -EIO;
				goto i2c_xfer_exit;
			}

			if (msg[i].flags & I2C_M_RD) {
				i2c_ctrl.raw.data = tbs_read(bus->base, TBSECP3_I2C_DATA);
				memcpy(b, &i2c_ctrl.raw.data, len);
				b += len;
			}
			
			i2c_ctrl.bits.start = 0;
			remaining -= len;
		} while (remaining);

	}	
	retval = num;
i2c_xfer_exit:
	mutex_unlock(&bus->lock);
	return retval;
}

static u32 i2c_functionality(struct i2c_adapter *adap)
{
	return I2C_FUNC_SMBUS_EMUL;
}

struct i2c_algorithm tbsecp3_i2c_algo_template = {
	.master_xfer   = i2c_xfer,
	.functionality = i2c_functionality,
};

static int tbsecp3_i2c_register(struct tbsecp3_i2c *bus)
{
	struct tbsecp3_dev *dev = bus->dev;
	struct i2c_adapter *adap;

	init_waitqueue_head(&bus->wq);
	mutex_init(&bus->lock);

	adap = &bus->i2c_adap;
	strcpy(adap->name, "tbsecp3");
	adap->algo = &tbsecp3_i2c_algo_template;
	adap->algo_data = (void*) bus;
	adap->dev.parent = &dev->pci_dev->dev;
	adap->owner = THIS_MODULE;
	
	strcpy(bus->i2c_client.name, "tbsecp3cli");
	bus->i2c_client.adapter = adap;

	i2c_set_adapdata(&bus->i2c_adap, bus);
	return i2c_add_adapter(&bus->i2c_adap);
}

static void tbsecp3_i2c_unregister(struct tbsecp3_i2c *bus)
{
	i2c_del_adapter(&bus->i2c_adap);
}

/* ----------------------------------------------------------------------- */

void tbsecp3_i2c_remove_clients(struct tbsecp3_adapter *adapter)
{
#if 0
	struct i2c_client *client_demod, *client_tuner;

	/* remove tuner I2C client */
	client_tuner = adapter->i2c_client_tuner;
	if (client_tuner) {
		module_put(client_tuner->dev.driver->owner);
		i2c_unregister_device(client_tuner);
		adapter->i2c_client_tuner = NULL;
	}

	/* remove demodulator I2C client */
	client_demod = adapter->i2c_client_demod;
	if (client_demod) {
		module_put(client_demod->dev.driver->owner);
		i2c_unregister_device(client_demod);
		adapter->i2c_client_demod = NULL;
	}
#endif
}

void tbsecp3_i2c_reg_init(struct tbsecp3_dev *dev)
{
	int i;
	u32 baud = dev->info->i2c_speed;

	/* default to 400kbps */
	if (!baud)
		baud = 9;

	for (i = 0; i < 4; i++) {
		tbs_write(dev->i2c_bus[i].base, TBSECP3_I2C_BAUD, baud);
		tbs_read(dev->i2c_bus[i].base, TBSECP3_I2C_STAT);
		tbs_write(TBSECP3_INT_BASE, TBSECP3_I2C_IE(i), 1);
	}
}

int tbsecp3_i2c_init(struct tbsecp3_dev *dev)
{
	int i, ret = 0;

	/* I2C Defaults / setup */
	for (i = 0; i < 4; i++) {
		dev->i2c_bus[i].base = TBSECP3_I2C_BASE(i);
		dev->i2c_bus[i].dev = dev;
		ret = tbsecp3_i2c_register(&dev->i2c_bus[i]);
		if (ret)
			break;
	}
	if (ret) {
		do {
			tbsecp3_i2c_unregister(&dev->i2c_bus[i]);
		} while (i-- > 0);
	} else {
		tbsecp3_i2c_reg_init(dev);
	}
	return ret;
}

void tbsecp3_i2c_exit(struct tbsecp3_dev *dev)
{
	int i;
	for (i = 0; i < 4; i++)
		tbsecp3_i2c_unregister(&dev->i2c_bus[i]);
}

