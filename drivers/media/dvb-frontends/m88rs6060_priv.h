#ifndef _M88RS6060_PRIV_H_
#define _M88RS6060_PRIV_H_
#include <media/dvb_frontend.h>

#include <linux/regmap.h>
#include <linux/firmware.h>
#include <linux/math64.h>

#include "m88rs6060.h"

#define M88RS6060_FIRMWARE "dvb-demod-m88rs6060.fw"

//Improve the driver capability or not
// 0:4mA, 1:8mA,2 :12mA , 3:16mA
#define MT_FE_ENHANCE_TS_PIN_LEVEL_PARALLEL_CI  0
/*set frequency offset to tuner when symbol rate <5000KSs*/
#define FREQ_OFFSET_AT_SMALL_SYM_RATE_KHz  3000

struct m88rs6060_dev {
	struct i2c_client *demod_client;	//demod
	struct i2c_client *tuner_client;
	struct regmap *regmap;	//demod
	enum fe_status fe_status;
	struct dvb_frontend fe;
	struct m88rs6060_cfg config;

	bool warm;		// for the init and download fw
	s32 mclk;		/*main mclk */

	u32 dvbv3_ber;		/* for old DVBv3 API read_ber */

	u64 post_bit_error;
	u64 post_bit_count;

	void (*write_properties)(struct i2c_adapter * i2c, u8 reg, u32 buf);
	void (*read_properties)(struct i2c_adapter * i2c, u8 reg, u32 * buf);

};

struct m88rs6060_reg_val {
	u8 reg;
	u8 val;

};
static const struct m88rs6060_reg_val rs6060_reg_tbl_def[] = {
	{0x04, 0x00},

	{0x8a, 0x01},		//modify by Henry 20171211
	{0x16, 0xa7},

	{0x30, 0x88},
	{0x4a, 0x80},		//0x81 for fpga, and 0x80 for asic
	{0x4d, 0x91},
	{0xae, 0x09},
	{0x22, 0x01},
	{0x23, 0x00},
	{0x24, 0x00},
	{0x27, 0x07},
	{0x9c, 0x31},
	{0x9d, 0xc1},
	{0xcb, 0xf4},
	{0xca, 0x00},
	{0x7f, 0x04},
	{0x78, 0x0c},
	{0x85, 0x08},
	//for s2 mode ts out en
	{0x08, 0x47},
	{0xf0, 0x03},

	{0xfa, 0x01},
	{0xf2, 0x00},
	{0xfa, 0x00},
	{0xe6, 0x00},
	{0xe7, 0xf3},

	//for s mode vtb code rate all en
	{0x08, 0x43},
	{0xe0, 0xf8},
	{0x00, 0x00},
	{0xbd, 0x83},
	{0xbe, 0xa1}
};

struct MT_FE_PLS_INFO {
	u8 iPLSCode;
	bool bValid;
	enum MT_FE_TYPE mDvbType;
	enum MT_FE_MOD_MODE mModMode;
	enum MT_FE_CODE_RATE mCodeRate;
	bool bPilotOn;
	bool bDummyFrame;
	s8 iFrameLength;	/*0: Normal; 1: Short; 2: Medium */
};

struct MT_FE_CHAN_INFO_DVBS2 {
	u8 iPlsCode;
	enum MT_FE_TYPE type;
	enum MT_FE_MOD_MODE mod_mode;
	enum MT_FE_ROLL_OFF roll_off;
	enum MT_FE_CODE_RATE code_rate;
	bool is_pilot_on;
	enum MT_FE_SPECTRUM_MODE is_spectrum_inv;
	bool is_dummy_frame;
	s8 iVcmCycle;
	s8 iFrameLength;	/*0: Normal; 1: Short; 2: Medium */
};

#endif
