#ifndef MN88436_H
#define MN88436_H
#include <linux/dvb/frontend.h>

struct mndmd_config {
//	u8 slvadr;
	u8 tuner_address;

//	int (*tbs6704_ctl1)(struct tbs_pcie_dev *dev, int a);
//	int (*tbs6704_ctl2)(struct tbs_pcie_dev *dev, int a, int b);
};

#if defined(CONFIG_DVB_MN88436) || \
	(defined(CONFIG_DVB_MN88436_MODULE) && defined(MODULE))
extern struct dvb_frontend* mndmd_attach(
	struct mndmd_config* config,
	struct i2c_adapter* i2c);
#else
static inline struct dvb_frontend* mndmd_attach(
	struct mndmd_config* config,
	struct i2c_adapter* i2c)
{
	printk(KERN_WARNING "%s: driver disabled by Kconfig\n", __func__);
	return NULL;
}
#endif

#endif
