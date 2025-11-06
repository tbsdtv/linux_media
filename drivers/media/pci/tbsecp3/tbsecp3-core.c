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

static bool enable_msi = true;
module_param(enable_msi, bool, 0444);
MODULE_PARM_DESC(enable_msi, "use an msi interrupt if available");


void tbsecp3_gpio_set_pin(struct tbsecp3_dev *dev,
		struct tbsecp3_gpio_pin *pin, int state)
{
	u32 tmp, bank, bit;

	if (pin->lvl == TBSECP3_GPIODEF_NONE)
		return;

	if (pin->lvl == TBSECP3_GPIODEF_LOW)
		state = !state;

	bank = (pin->nr >> 3) & ~3;
	bit = pin->nr % 32;

	tmp = tbs_read(TBSECP3_GPIO_BASE, bank);
	if (state)
		tmp |= 1 << bit;
	else
		tmp &= ~(1 << bit);
	tbs_write(TBSECP3_GPIO_BASE, bank, tmp);
}

static irqreturn_t tbsecp3_irq_handler(int irq, void *dev_id)
{
	struct tbsecp3_dev *dev = (struct tbsecp3_dev *) dev_id;
	struct tbsecp3_i2c *i2c;
	int i, in;
	u32 stat = tbs_read(TBSECP3_INT_BASE, TBSECP3_INT_STAT);

	tbs_write(TBSECP3_INT_BASE, TBSECP3_INT_STAT, stat);

	if (stat & 0x000ffff0) {
		/* dma0~15 */
		for (i = 0; i < dev->info->adapters; i++) {
			in = dev->adapter[i].cfg->ts_in;
			if (stat & TBSECP3_DMA_IF(in)){
				tasklet_schedule(&dev->adapter[i].tasklet);
				}
		}
	}

	if (stat & 0x0000000f) {
		/* i2c */
		for (i = 0; i < 4; i++) {
			i2c = &dev->i2c_bus[i];
			if (stat & TBSECP3_I2C_IF(i)) {
				i2c->done = 1;
				wake_up(&i2c->wq);
			}
		}
	}
	if (stat & 0xf0000000) {
		/* i2c 4~7*/
		for (i = 4; i < 8; i++) {
			i2c = &dev->i2c_bus[i];
			if (stat & TBSECP3_I2C_IF1(i)) {
				i2c->done = 1;
				wake_up(&i2c->wq);
			}
		}
	}
	tbs_write(TBSECP3_INT_BASE, TBSECP3_INT_EN, 1);
	return IRQ_HANDLED;
}

static int tbsecp3_adapters_attach(struct tbsecp3_dev *dev)
{
	int i, ret = 0;
	for (i = 0; i < dev->info->adapters; i++) {
		ret = tbsecp3_dvb_init(&dev->adapter[i]);
		if (ret) {
			dev_err(&dev->pci_dev->dev,
				"adapter%d attach failed\n",
				dev->adapter[i].nr);
			dev->adapter[i].nr = -1;
		}
	}
	return 0;
}

static void tbsecp3_adapters_detach(struct tbsecp3_dev *dev)
{
	struct tbsecp3_adapter *adapter;
	int i;

	for (i = 0; i < dev->info->adapters; i++) {
		adapter = &dev->adapter[i];

		/* attach has failed, nothing to do */
		if (adapter->nr == -1)
			continue;

		tbsecp3_i2c_remove_clients(adapter);
		tbsecp3_dvb_exit(adapter);
	}
}

static void tbsecp3_adapters_init(struct tbsecp3_dev *dev)
{
	struct tbsecp3_adapter *adapter = dev->adapter;
	int i;

	for (i = 0; i < dev->info->adapters; i++) {
		adapter = &dev->adapter[i];
		adapter->nr = i;
		adapter->cfg = &dev->info->adap_config[i];
		adapter->dev = dev;
		adapter->i2c = &dev->i2c_bus[adapter->cfg->i2c_bus_nr];
	}
}

static void tbsecp3_adapters_release(struct tbsecp3_dev *dev)
{
	struct tbsecp3_adapter *adapter;
	int i;

	for (i = 0; i < dev->info->adapters; i++) {
		adapter = &dev->adapter[i];
		tasklet_kill(&adapter->tasklet);
	}
}


static bool tbsecp3_enable_msi(struct pci_dev *pci_dev, struct tbsecp3_dev *dev)
{
	int err;

	if (!enable_msi) {
		dev_warn(&dev->pci_dev->dev,
			"MSI disabled by module parameter 'enable_msi'\n");
		return false;
	}

	err = pci_enable_msi(pci_dev);
	if (err) {
		dev_err(&dev->pci_dev->dev,
			"Failed to enable MSI interrupt."
			" Falling back to a shared IRQ\n");
		return false;
	}

	/* no error - so request an msi interrupt */
	err = request_irq(pci_dev->irq, tbsecp3_irq_handler, 0,
				"tbsecp3", dev);
	if (err) {
		/* fall back to legacy interrupt */
		dev_err(&dev->pci_dev->dev,
			"Failed to get an MSI interrupt."
			" Falling back to a shared IRQ\n");
		pci_disable_msi(pci_dev);
		return false;
	}
	return true;
}


static int tbsecp3_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct tbsecp3_dev *dev;
	int ret = -ENODEV;

	if (pci_enable_device(pdev) < 0)
		return -ENODEV;

	if(dma_set_mask(&pdev->dev, DMA_BIT_MASK(64)))
		if(dma_set_mask(&pdev->dev, DMA_BIT_MASK(32)))
		{
			dev_err(&pdev->dev, "64/32-bit PCI DMA not supported\n");
			goto err0;	
		}
	
	pci_set_master(pdev);

	dev = kzalloc(sizeof(struct tbsecp3_dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto err0;
	}

	dev->pci_dev = pdev;
	pci_set_drvdata(pdev, dev);

	dev->info = (struct tbsecp3_board *) id->driver_data;
	dev_info(&pdev->dev, "%s\n", dev->info->name);

	dev->lmmio = ioremap(pci_resource_start(pdev, 0),
				pci_resource_len(pdev, 0));
	if (!dev->lmmio) {
		ret = -ENOMEM;
		goto err1;
	}

	tbs_write(TBSECP3_INT_BASE, TBSECP3_INT_EN, 0);
	tbs_write(TBSECP3_INT_BASE, TBSECP3_INT_STAT, 0xff);

	tbsecp3_adapters_init(dev);

	/* dma */
	ret = tbsecp3_dma_init(dev);
	if (ret < 0)
		goto err2;

	/* i2c */
	ret = tbsecp3_i2c_init(dev);
	if (ret < 0)
		goto err3;

	/* interrupts */
	if (tbsecp3_enable_msi(pdev, dev)) {
		dev->msi = true;
	} else {
		ret = request_irq(pdev->irq, tbsecp3_irq_handler,
				IRQF_SHARED, "tbsecp3", dev);
		if (ret < 0) {
			dev_err(&pdev->dev, "%s: can't get IRQ %d\n",
				dev->info->name, pdev->irq);
			goto err4;
		}
		dev->msi = false;
	}
	/* global interrupt enable */
	tbs_write(TBSECP3_INT_BASE, TBSECP3_INT_EN, 1);

	ret = tbsecp3_adapters_attach(dev);
	if (ret < 0)
		goto err5;
	
	dev_info(&pdev->dev, "%s: PCI %s, IRQ %d, MMIO 0x%lx\n",
		dev->info->name, pci_name(pdev), pdev->irq,
		(unsigned long) pci_resource_start(pdev, 0));

	//dev_info(&dev->pci_dev->dev, "%s ready\n", dev->info->name);
	return 0;

err5:
	tbsecp3_adapters_detach(dev);

	tbs_write(TBSECP3_INT_BASE, TBSECP3_INT_EN, 0);
	free_irq(dev->pci_dev->irq, dev);
	if (dev->msi) {
		pci_disable_msi(pdev);
		dev->msi = false;
	}
err4:
	tbsecp3_i2c_exit(dev);
err3:
	tbsecp3_dma_free(dev);
err2:
	tbsecp3_adapters_release(dev);
	iounmap(dev->lmmio);
err1:
	pci_set_drvdata(pdev, NULL);
	kfree(dev);
err0:
	pci_disable_device(pdev);
	dev_err(&pdev->dev, "probe error\n");
	return ret;
}

static void tbsecp3_remove(struct pci_dev *pdev)
{
	struct tbsecp3_dev *dev = pci_get_drvdata(pdev);

	/* disable interrupts */
	tbs_write(TBSECP3_INT_BASE, TBSECP3_INT_EN, 0); 
	free_irq(pdev->irq, dev);
	if (dev->msi) {
		pci_disable_msi(pdev);
		dev->msi = false;
	}
	tbsecp3_adapters_detach(dev);
	tbsecp3_adapters_release(dev);
	tbsecp3_dma_free(dev);
	tbsecp3_i2c_exit(dev);
	iounmap(dev->lmmio);
	pci_set_drvdata(pdev, NULL);
	pci_disable_device(pdev);
	kfree(dev);
}

static int tbsecp3_resume(struct pci_dev *pdev)
{
	struct tbsecp3_dev *dev = pci_get_drvdata(pdev);
	/* re-init registers */
	tbsecp3_i2c_reg_init(dev);
	tbsecp3_dma_reg_init(dev);
	tbs_write(TBSECP3_INT_BASE, TBSECP3_INT_EN, 1);
	return 0;
}

/* PCI IDs */
#define TBSECP3_ID(_board_id,_subvend,_subdev) { \
	.vendor = TBSECP3_VID, .device = TBSECP3_PID, \
	.subvendor = _subvend, .subdevice = _subdev, \
	.driver_data = (unsigned long)&tbsecp3_boards[_board_id] }

static const struct pci_device_id tbsecp3_id_table[] = {
	TBSECP3_ID(TBSECP3_BOARD_TBS6205,0x6205,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6281SE,0x6281,0x0002),
	TBSECP3_ID(TBSECP3_BOARD_TBS6290SE,0x6290,0x0002),
	TBSECP3_ID(TBSECP3_BOARD_TBS6290TD,0x6290,0x0008),
	TBSECP3_ID(TBSECP3_BOARD_TBS6209,0x6209,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6522,0x6522,0x0002),
	TBSECP3_ID(TBSECP3_BOARD_TBS6528,0x6528,PCI_ANY_ID),
	TBSECP3_ID(TBSECP3_BOARD_TBS6590,0x6590,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6902,0x6902,0x1132),
	TBSECP3_ID(TBSECP3_BOARD_TBS6902,0x6902,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6902,0x6902,0x0002),
	TBSECP3_ID(TBSECP3_BOARD_TBS6902,0x6902,0x0003),
	TBSECP3_ID(TBSECP3_BOARD_TBS6903,0x6903,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6904,0x6904,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6904,0x6904,0x1131),
	TBSECP3_ID(TBSECP3_BOARD_TBS6905,0x6905,PCI_ANY_ID),
	TBSECP3_ID(TBSECP3_BOARD_TBS6908,0x6908,PCI_ANY_ID),
	TBSECP3_ID(TBSECP3_BOARD_TBS6909,0x6909,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6910,0x6910,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6704,0x6704,PCI_ANY_ID),
	TBSECP3_ID(TBSECP3_BOARD_TBS6814,0x6814,PCI_ANY_ID),
	TBSECP3_ID(TBSECP3_BOARD_TBS6514,0x6514,PCI_ANY_ID),
	TBSECP3_ID(TBSECP3_BOARD_TBS690a,0x690a,PCI_ANY_ID),
	TBSECP3_ID(TBSECP3_BOARD_TBS6301,0x6301,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6304,0x6304,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6308,0x6308,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6308X,0x6308,0x0010),
	TBSECP3_ID(TBSECP3_BOARD_TBS6312X,0x6312,0x0010),
	TBSECP3_ID(TBSECP3_BOARD_TBS6909X,0x6909,0x0010),
	TBSECP3_ID(TBSECP3_BOARD_TBS6909X,0x6909,0x0009),
	TBSECP3_ID(TBSECP3_BOARD_TBS6909X,0x6909,0x0019),	
	TBSECP3_ID(TBSECP3_BOARD_TBS6903X,0x6903,0x0020),
	TBSECP3_ID(TBSECP3_BOARD_TBS6903X,0x6903,0x0021),
	TBSECP3_ID(TBSECP3_BOARD_TBS6903X,0x6903,0x8888),
	TBSECP3_ID(TBSECP3_BOARD_TBS6904X,0x6904,0x2000),
	TBSECP3_ID(TBSECP3_BOARD_TBS6912,0x6912,0x0020),
	TBSECP3_ID(TBSECP3_BOARD_TBS6504,0x6504,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6508,0x6508,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6302SE,0x6302,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6304,0x2605,PCI_ANY_ID),
	TBSECP3_ID(TBSECP3_BOARD_TBS6902SE,0x6902,0x0007),
	TBSECP3_ID(TBSECP3_BOARD_TBS6904SE,0x6904,0x0020),
	TBSECP3_ID(TBSECP3_BOARD_TBS6301SE,0x6301,0x0005),
	TBSECP3_ID(TBSECP3_BOARD_TBS6301SE,0x6302,0x0005),
	TBSECP3_ID(TBSECP3_BOARD_TBS6301SE,0x6301,0x0004),
	TBSECP3_ID(TBSECP3_BOARD_TBS6910SE,0x6910,0x0006),
	TBSECP3_ID(TBSECP3_BOARD_TBS7901,0x7901,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6209SE,0x6209,0x0006),	
	TBSECP3_ID(TBSECP3_BOARD_TBS7901,0x7901,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS7230,0x7230,0x0006),
	TBSECP3_ID(TBSECP3_BOARD_TBS6302X,0x6302,0x0010),	
	TBSECP3_ID(TBSECP3_BOARD_TBS6302T,0x6302,0x0009),
	TBSECP3_ID(TBSECP3_BOARD_TBS6304X,0x6304,0x0010),	
	TBSECP3_ID(TBSECP3_BOARD_TBS6205SE,0x6205,0x0003),
	TBSECP3_ID(TBSECP3_BOARD_TBS6281TD,0x6281,0x0003),
	TBSECP3_ID(TBSECP3_BOARD_TBS6909SE,0x6909,0x0066),
	TBSECP3_ID(TBSECP3_BOARD_TBS6304T,0x6304,0x0009),
	TBSECP3_ID(TBSECP3_BOARD_TBS6522H,0x6522,0x0004),
	TBSECP3_ID(TBSECP3_BOARD_TBS6504H,0x6504,0x0008),
	TBSECP3_ID(TBSECP3_BOARD_TBS6590SE,0x6590,0x0002),
	TBSECP3_ID(TBSECP3_BOARD_TBS6916,0x6916,0x0001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6324,0x6324,0x0010),
	TBSECP3_ID(TBSECP3_BOARD_TBS6322,0x6322,0x0010),
	TBSECP3_ID(TBSECP3_BOARD_TBS6304RV,0x6304,0x0008),
	TBSECP3_ID(TBSECP3_BOARD_TBS6302RV,0x6302,0x0008),
	TBSECP3_ID(TBSECP3_BOARD_TBS6331,0x6331,0xa001),
	TBSECP3_ID(TBSECP3_BOARD_TBS6216,0x6216,0x0001),				
	{0}
};
MODULE_DEVICE_TABLE(pci, tbsecp3_id_table);

static struct pci_driver tbsecp3_driver = {
	.name = "TBSECP3 driver",
	.id_table = tbsecp3_id_table,
	.probe    = tbsecp3_probe,
	.remove   = tbsecp3_remove,
	.resume   = tbsecp3_resume,
	.suspend  = NULL,
};

module_pci_driver(tbsecp3_driver);

MODULE_AUTHOR("Luis Alves <ljalvs@gmail.com>");
MODULE_DESCRIPTION("TBS ECP3 driver");
MODULE_LICENSE("GPL");
