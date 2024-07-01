/*
	TurboSight TBS CI driver
    	Copyright (C) 2011 Konstantin Dimitrov <kosio.dimitrov@gmail.com>

    	Copyright (C) 2011 TurboSight.com
*/

#include "tbs-ci.h"

#define TBSCI_I2C_ADDR 0x1a

struct tbsci_state {
	struct dvb_ca_en50221 ca;
	struct mutex ca_mutex;
	struct i2c_adapter *i2c_adap;
	int nr, mode;
	void *priv; /* struct saa716x_adapter *priv; */
	int status;
};

int tbsci_i2c_read(struct tbsci_state *state)
{
	int ret;
	u8 buf = 0;

	struct i2c_msg msg = { .addr = TBSCI_I2C_ADDR, .flags = I2C_M_RD,
			.buf = &buf, .len = 1 };

	if (((state->mode == 2) || (state->mode == 4) ||
			(state->mode == 6) || (state->mode == 8) || (state->mode == 9))
		&& (state->nr == 1))
		msg.addr += 1;

	if (state->mode == 10)
		msg.addr += 2;

	ret = i2c_transfer(state->i2c_adap, &msg, 1);

	if (ret != 1) {
		printk("tbsci: read error=%d\n", ret);
		return -EREMOTEIO;
	}

	return buf;
};

int tbsci_i2c_write(struct tbsci_state *state,
	u8 addr, u8* data, int len)
{
	int ret;
	unsigned char buf[len + 1];

	struct i2c_msg msg = { .addr = TBSCI_I2C_ADDR, .flags = 0,
			.buf = &buf[0], .len = len + 1 };

	if (((state->mode == 2) || (state->mode == 4) ||
			(state->mode == 6) || (state->mode == 8) || (state->mode == 9)) 
		&& (state->nr == 1))
		msg.addr += 1;

	if (state->mode == 10)
		msg.addr += 2;

	memcpy(&buf[1], data, len);
	buf[0] = addr;
	
	ret = i2c_transfer(state->i2c_adap, &msg, 1);

	if (ret != 1) {
		printk("tbsci: error=%d\n", ret);
		return -EREMOTEIO;
	}

	return 0;
};

int tbsci_read_cam_control(struct dvb_ca_en50221 *ca, 
	int slot, u8 address)
{
	struct tbsci_state *state = ca->data;
	int ret;
	unsigned char data;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&state->ca_mutex);

	data = (address & 3);
	ret = tbsci_i2c_write(state, 0x80, &data, 1);
	data = tbsci_i2c_read(state);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return data;
}

int tbsci_write_cam_control(struct dvb_ca_en50221 *ca, int slot,
	u8 address, u8 value)
{
	struct tbsci_state *state = ca->data;
	int ret;
	unsigned char data[2];

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&state->ca_mutex);

	data[0] = (address & 3);
	data[1] = value;
	ret = tbsci_i2c_write(state, 0x80, data, 2);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return 0;
}

int tbsci_read_attribute_mem(struct dvb_ca_en50221 *ca,
	int slot, int address)
{
	struct tbsci_state *state = ca->data;
	int ret;
	unsigned char data;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&state->ca_mutex);

	data = (address & 0xff);
	ret = tbsci_i2c_write(state,
		((address >> 8) & 0x7f), &data, 1);
	data = tbsci_i2c_read(state);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return data;
}

int tbsci_write_attribute_mem(struct dvb_ca_en50221 *ca,
	int slot, int address, u8 value)
{
	struct tbsci_state *state = ca->data;
	int ret;
	unsigned char data[2];

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&state->ca_mutex);

	data[0] = (address & 0xff);
	data[1] = value;
	ret = tbsci_i2c_write(state,
		((address >> 8) & 0x7f), data, 2);

	mutex_unlock(&state->ca_mutex);

	if (ret < 0)
		return ret;

	return 0;
}

static int tbsci_set_video_port(struct dvb_ca_en50221 *ca,
	int slot, int enable)
{
	struct tbsci_state *state = ca->data;
	struct saa716x_adapter *adap = state->priv;
	struct saa716x_dev *saa716x = adap->saa716x;
	unsigned char data;

	if (slot != 0)
		return -EINVAL;

	mutex_lock(&state->ca_mutex);

	switch (state->mode) {
	case 0:
	case 1:
		saa716x_gpio_set_output(saa716x, 
			state->nr ? 16 : 17);
		msleep(1);
		saa716x_gpio_write(saa716x, 
			state->nr ? 16 : 17, (enable & 1));
		msleep(100);
		break;
	case 2:
		saa716x_gpio_set_output(saa716x, 
			state->nr ? 6 : 16);
		msleep(1);
		saa716x_gpio_write(saa716x, 
			state->nr ? 6 : 16, (enable & 1));
		msleep(100);
		break;
	case 3:
	case 4:
	case 5:
	case 6:
	case 7:
	case 8:
	case 9:
		data = enable & 1;
		tbsci_i2c_write(state, 0xc0, &data, 1);
		break;
	}

	mutex_unlock(&state->ca_mutex);

	printk("tbsci: Adapter %d CI slot %sabled\n",
		adap->fe->dvb->num,
		enable ? "en" : "dis");

	return 0;
}

int tbsci_slot_shutdown(struct dvb_ca_en50221 *ca, int slot)
{
	return tbsci_set_video_port(ca, slot, /* enable */ 0);
}

int tbsci_slot_ts_enable(struct dvb_ca_en50221 *ca, int slot)
{
	return tbsci_set_video_port(ca, slot, /* enable */ 1);
}

int tbsci_slot_reset(struct dvb_ca_en50221 *ca, int slot)
{
	struct tbsci_state *state = ca->data;
	int ret;
	unsigned char data;

	if (slot != 0)
		return -EINVAL;
	
	mutex_lock (&state->ca_mutex);

	data = 1;
	ret = tbsci_i2c_write(state, 0xc1, &data, 1);
	msleep (5);

	data = 0;
	ret = tbsci_i2c_write(state, 0xc1, &data, 1);
	msleep (1400);

	mutex_unlock (&state->ca_mutex);

	if (ret != 0)
		return ret;

	return 0;
}

int tbsci_poll_slot_status(struct dvb_ca_en50221 *ca, 
	int slot, int open)
{
	struct tbsci_state *state = ca->data;
	struct saa716x_adapter *adap = state->priv;
	struct saa716x_dev *saa716x = adap->saa716x;
	unsigned char data, value;
	
	if (slot != 0)
		return -EINVAL;

	mutex_lock(&state->ca_mutex);

	switch (state->mode) {
	case 0:
		data = 0;
		tbsci_i2c_write(state, 0xc0, &data, 1);
		data = tbsci_i2c_read(state);
		break;
	case 1:
	case 2:
		data = 0;
		tbsci_i2c_write(state, 0xc2, &data, 1);
		data = tbsci_i2c_read(state);
		break;
	case 3:
		data = saa716x_gpio_read(saa716x, 3);
		if (data != saa716x_gpio_read(saa716x, 5))
			data  = 0;
		else
			data ^= 1;
		break;
	case 4:
		data = saa716x_gpio_read(saa716x, state->nr ? 3 : 14);
		if (data != saa716x_gpio_read(saa716x, state->nr ? 6 : 2))
			data  = 0;
		else
			data ^= 1;
		break;
	case 5:
		data = saa716x_gpio_read(saa716x, 6);
		if (data != saa716x_gpio_read(saa716x, 14))
			data  = 0;
		else
			data ^= 1;
		break;
	case 6:
		data = saa716x_gpio_read(saa716x, state->nr ? 17 : 5);
		if (data != saa716x_gpio_read(saa716x, state->nr ? 16 : 6))
			data  = 0;
		else
			data ^= 1;
		break;
	case 7:
		data = saa716x_gpio_read(saa716x, 3);
		if (data != saa716x_gpio_read(saa716x, 5)) {
			data  = 0;
		} else {
			data ^= 1;
		}

		if (state->status != data){
			value = !data;
			tbsci_i2c_write(state, 0xc3, &value, 1);
			saa716x_gpio_write(saa716x, 6, value);
			msleep(300);
			state->status = data;
		}

		break;
	case 8:
	case 9:
		data = saa716x_gpio_read(saa716x, state->nr ? 6 : 2);
		if (data != saa716x_gpio_read(saa716x, state->nr ? 3 : 14)) {
			data  = 0;
		} else {
			data ^= 1;
		}

		if (state->status != data)
		{
			value = !data;
			saa716x_gpio_write(saa716x, state->nr ? 17 : 20, value);
			msleep(300);
			state->status = data;
		}
		break;
	}

	mutex_unlock(&state->ca_mutex);

	if (data & 1) {
		return (DVB_CA_EN50221_POLL_CAM_PRESENT |
			DVB_CA_EN50221_POLL_CAM_READY);
	} else {
		return 0;
	}
}

int tbsci_init(struct saa716x_adapter *adap, int tbsci_nr, int tbsci_mode)
{
	struct tbsci_state *state;
	int ret;
	unsigned char data;

	/* allocate memory for the internal state */
	state = kzalloc(sizeof(struct tbsci_state), GFP_KERNEL);
	if (state == NULL) {
		ret = -ENOMEM;
		goto error1;
	}

	adap->adap_priv = state;
	
	state->nr = tbsci_nr;
	state->mode = tbsci_mode;
	state->status = 0;

	mutex_init(&state->ca_mutex);

	state->i2c_adap = &adap->tbsci->adap;
	state->ca.owner = THIS_MODULE;
	state->ca.read_attribute_mem = tbsci_read_attribute_mem;
	state->ca.write_attribute_mem = tbsci_write_attribute_mem;
	state->ca.read_cam_control = tbsci_read_cam_control;
	state->ca.write_cam_control = tbsci_write_cam_control;
	state->ca.slot_reset = tbsci_slot_reset;
	state->ca.slot_shutdown = tbsci_slot_shutdown;
	state->ca.slot_ts_enable = tbsci_slot_ts_enable;
	state->ca.poll_slot_status = tbsci_poll_slot_status;
	state->ca.data = state;
	state->priv = adap;

	if ((state->mode != 0) && (state->mode != 10)) {
		data = 1;
		tbsci_i2c_write(state, 0xc2, &data, 1);
		data = tbsci_i2c_read(state);
		switch (data) {
		case 0x55:
			printk("tbsci: Initializing TBS 6928 v11 CI slot\n");
			break;
		case 0x56:
		case 0x58:
			printk("tbsci: Initializing TBS 6991 v11 CI %d slot\n",
				tbsci_nr);
			break;
		case 0x60:
			if (state->mode != 5) {
				printk("tbsci: Initializing TBS 6928 v12 CI slot\n");
				state->mode = 3;

				data = 0;
				tbsci_i2c_write(state, 0xd0, &data, 1);

				tbsci_i2c_write(state, 0xcc, &data, 1);
				tbsci_i2c_write(state, 0xcd, &data, 1);

				data = 2;
				tbsci_i2c_write(state, 0xce, &data, 1);
			} else {
				printk("tbsci: Initializing TBS 6618 CI slot\n");
			}
			break;
		case 0x62:
				printk("tbsci: Initializing TBS 6928SE CI slot\n");
				state->mode = 7;
			break;
		case 0x66:
		case 0x68:
			if (state->mode == 8){
				printk("tbsci: Initializing TBS 6991SE CI %d slot\n",
					tbsci_nr);
				//Fix Data Rate
									
			}else
                        if (state->mode == 9) {
                                printk("tbsci: Initializing TBS 6290 CI %d slot\n",
                                        tbsci_nr);
                        } else {
			if (state->mode != 6) {
				printk("tbsci: Initializing TBS 6991 v13 CI %d slot\n",
					tbsci_nr);
				state->mode = 4;

				data = 0;
				tbsci_i2c_write(state, 0xd0, &data, 1);
				data = 1;
				tbsci_i2c_write(state, 0xcc, &data, 1);
				data = 0;
				tbsci_i2c_write(state, 0xcd, &data, 1);

				data = 2;
				tbsci_i2c_write(state, 0xce, &data, 1);
			} else {
				printk("tbsci: Initializing TBS 6680 CI %d slot\n",
					tbsci_nr);
			}}
			break;
		default:
			ret = -EREMOTEIO;
			goto error2;
		}
	}

	if (state->mode == 10) {
		data = 0xc0;
		tbsci_i2c_write(state, 0x40, &data, 1);
		data = tbsci_i2c_read(state);		
		
		data = 0x01;
		tbsci_i2c_write(state, 0xc0, &data, 1);

		data = 0xc0;
		tbsci_i2c_write(state, 0x40, &data, 1);
		data = tbsci_i2c_read(state);		

		data = 0xc1;
		tbsci_i2c_write(state, 0x40, &data, 1);
		data = tbsci_i2c_read(state);

		data = 0x01;
		tbsci_i2c_write(state, 0xc1, &data, 1);

		data = 0xc1;
		tbsci_i2c_write(state, 0x40, &data, 1);
		data = tbsci_i2c_read(state);

		data = 0xc2;
		tbsci_i2c_write(state, 0x40, &data, 1);
		data = tbsci_i2c_read(state);

		data = 0x01;
		tbsci_i2c_write(state, 0xc2, &data, 1);

		data = 0xc2;
		tbsci_i2c_write(state, 0x40, &data, 1);
		data = tbsci_i2c_read(state);

		data = 0xc3;
		tbsci_i2c_write(state, 0x40, &data, 1);
		data = tbsci_i2c_read(state);

		data = 0x01;
		tbsci_i2c_write(state, 0xc3, &data, 1);

		data = 0xc3;
		tbsci_i2c_write(state, 0x40, &data, 1);
		data = tbsci_i2c_read(state);

		return 0;
	}

	ret = dvb_ca_en50221_init(&adap->dvb_adapter, &state->ca,
		/* flags */ 0, /* n_slots */ 1);
	if (ret != 0) goto error2;

	printk("tbsci: Adapter %d CI slot initialized\n", adap->dvb_adapter.num);

	return 0;
	
error2: 
	//memset (&state->ca, 0, sizeof (state->ca)); 
	kfree(state);
error1:
	printk("tbsci: Adapter %d CI slot initialization failed\n", adap->dvb_adapter.num);
	return ret;
}

void tbsci_release(struct saa716x_adapter *adap)
{
	struct tbsci_state *state;

	if (NULL == adap) return;

	state = (struct tbsci_state *)adap->adap_priv;
	if (NULL == state) return;

	if (NULL == state->ca.data) return;

	dvb_ca_en50221_release(&state->ca);
	//memset(&state->ca, 0, sizeof(state->ca));
	kfree(state);
}
