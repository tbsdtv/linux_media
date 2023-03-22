#ifndef _GX1503_H_
#define _GX1503_H_

#include <linux/dvb/frontend.h>

struct gx1503_config{

	struct dvb_frontend **fe;

	struct i2c_adapter **i2c_adapter;

	int ts_mode; // 0 :serial  1:parallel

	u16 i2c_wr_max;

	int clk_freq;

};

#endif
