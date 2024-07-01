/*
	TurboSight TBS CI I2C over GPIO driver
    	Copyright (C) 2011 Konstantin Dimitrov <kosio.dimitrov@gmail.com>

    	Copyright (C) 2011 TurboSight.com
*/

#include "saa716x_priv.h"
#include "saa716x_gpio.h"
#include "tbsci-i2c.h"

static void tbsci_setscl(void *data, int state)
{
	struct saa716x_adapter *adap = data;
	struct saa716x_dev *saa716x = adap->saa716x;
	struct tbsci_i2c_state *tbsci_i2c = adap->tbsci;
	
	saa716x_gpio_write(saa716x, tbsci_i2c->wscl, state);
}

static void tbsci_setsda(void *data, int state)
{
	struct saa716x_adapter *adap = data;
	struct saa716x_dev *saa716x = adap->saa716x;
	struct tbsci_i2c_state *tbsci_i2c = adap->tbsci;
	
	saa716x_gpio_write(saa716x, tbsci_i2c->wsda, state);
}

static int tbsci_getscl(void *data)
{
	struct saa716x_adapter *adap = data;
	struct saa716x_dev *saa716x = adap->saa716x;
	struct tbsci_i2c_state *tbsci_i2c = adap->tbsci;
	u32 state;
	
	state = saa716x_gpio_read(saa716x, tbsci_i2c->wscl);

	return state ? 1 : 0;
}

static int tbsci_getsda(void *data)
{
	struct saa716x_adapter *adap = data;
	struct saa716x_dev *saa716x = adap->saa716x;
	struct tbsci_i2c_state *tbsci_i2c = adap->tbsci;
	u32 state;

	state = saa716x_gpio_read(saa716x, tbsci_i2c->rsda);

	return state ? 1 : 0;
}

static const struct i2c_algo_bit_data tbsci_i2c_algo_template = {
	.setsda  = tbsci_setsda,
	.setscl  = tbsci_setscl,
	.getsda  = tbsci_getsda,
	.getscl  = tbsci_getscl,
	.udelay  = 5,
	.timeout = 200,
};

int tbsci_i2c_probe(struct saa716x_adapter *adap, int tbsci_i2c_nr)
{
	struct saa716x_dev *saa716x = adap->saa716x;
	struct saa716x_i2c *i2c0 = &saa716x->i2c[0];
	struct saa716x_i2c *i2c1 = &saa716x->i2c[1];
	struct tbsci_i2c_state *tbsci_i2c;
	int ret;

	tbsci_i2c = kzalloc(sizeof(*tbsci_i2c), GFP_KERNEL);
	if (tbsci_i2c == NULL) {
		return -ENOMEM;
	}
	adap->tbsci = tbsci_i2c;
	tbsci_i2c->nr = tbsci_i2c_nr;

	if (tbsci_i2c_nr == 3) {
		tbsci_i2c->adap = i2c1->i2c_adapter;
		return 0;
	}

	if (tbsci_i2c_nr == 4) {
		tbsci_i2c->adap = i2c0->i2c_adapter;
		return 0;
	}

	memcpy(&tbsci_i2c->algo, &tbsci_i2c_algo_template,
		sizeof(tbsci_i2c->algo));

	tbsci_i2c->adap.dev.parent = &saa716x->pdev->dev;
	strscpy(tbsci_i2c->adap.name, 
		tbsci_i2c_nr ? "TBSCI I2C Adapter 0" : "TBSCI I2C Adapter 1",
		sizeof(tbsci_i2c->adap.name));
	tbsci_i2c->adap.owner = THIS_MODULE;
	//tbsci_i2c->adap.id = I2C_HW_B_SAA716x;
	tbsci_i2c->algo.data = adap;
	i2c_set_adapdata(&tbsci_i2c->adap, saa716x);
	tbsci_i2c->adap.algo_data = &tbsci_i2c->algo;

	if (tbsci_i2c->nr == 2) {
		tbsci_i2c->wscl = 16;
		tbsci_i2c->wsda = 3;
		tbsci_i2c->rsda = 5;
	} else {
		tbsci_i2c->wscl = tbsci_i2c->nr ? 3 : 26;
		tbsci_i2c->wsda = tbsci_i2c->nr ? 5 : 15;
		tbsci_i2c->rsda = tbsci_i2c->nr ? 2 : 20;
	}

	saa716x_gpio_set_output(saa716x, tbsci_i2c->wscl);
	msleep(1);
	saa716x_gpio_set_output(saa716x, tbsci_i2c->wsda);
	msleep(1);
	saa716x_gpio_set_input(saa716x, tbsci_i2c->rsda);
	msleep(1);

	tbsci_setscl(adap, 1);
	tbsci_setsda(adap, 1);

	ret = i2c_bit_add_bus(&tbsci_i2c->adap);
	if (ret != 0) {
		printk("tbsci_i2c: %s probe failed\n", 
			tbsci_i2c_nr ? "TBSCI I2C Adapter 0" : "TBSCI I2C Adapter 1");

		kfree(adap->tbsci);
		adap->tbsci = NULL;
	}

	return ret;
}

void tbsci_i2c_remove(struct saa716x_adapter *adap)
{
	struct tbsci_i2c_state *tbsci_i2c = adap->tbsci;

	if (tbsci_i2c == NULL)
		return;

	if ((tbsci_i2c->nr != 3) && (tbsci_i2c->nr != 4))	
		i2c_del_adapter(&tbsci_i2c->adap);
		
	kfree(tbsci_i2c);
}
