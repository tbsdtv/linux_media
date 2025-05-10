#ifndef __R850_H__
#define __R850_H__


#include <linux/kconfig.h>
#include <media/dvb_frontend.h>

struct r850_config {
	/* tuner i2c address */
	u8 i2c_address;

	u32 R850_Xtal;

};

#if IS_REACHABLE(CONFIG_MEDIA_TUNER_R850)
extern struct dvb_frontend *r850_attach(struct dvb_frontend *fe,
		struct r850_config *cfg, struct i2c_adapter *i2c);
#else
static inline struct dvb_frontend *r850_attach(struct dvb_frontend *fe,
		struct r850_config *cfg, struct i2c_adapter *i2c)
{
	printk(KERN_WARNING "%s: driver disabled by Kconfig\n", __func__);
	return NULL;
}
#endif

#endif //__R850_H__