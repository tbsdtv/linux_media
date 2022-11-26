#ifndef _M88RS6060_PRIV_H_
#define _M88RS6060_PRIV_H_
#include <media/dvb_frontend.h>

#include <linux/regmap.h>
#include <linux/firmware.h>
#include <linux/math64.h>

#include "m88rs6060.h"

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif
#define M88RS6060_FIRMWARE "dvb-demod-m88rs6060.fw"

//Improve the driver capability or not
// 0:4mA, 1:8mA,2 :12mA , 3:16mA
#define MT_FE_ENHANCE_TS_PIN_LEVEL_PARALLEL_CI  0
/*set frequency offset to tuner when symbol rate <5000KSs*/
#define FREQ_OFFSET_AT_SMALL_SYM_RATE_KHz  3000


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


//for si5351
/* Define definitions */

#define SI5351_BUS_BASE_ADDR				0x60
#define SI5351_XTAL_FREQ					27000000
#define SI5351_PLL_FIXED					900000000

#define SI5351_PLL_VCO_MIN					600000000
#define SI5351_PLL_VCO_MAX					900000000
#define SI5351_MULTISYNTH_MIN_FREQ			1000000
#define SI5351_MULTISYNTH_DIVBY4_FREQ		150000000
#define SI5351_MULTISYNTH_MAX_FREQ			160000000
#define SI5351_MULTISYNTH67_MAX_FREQ		SI5351_MULTISYNTH_DIVBY4_FREQ
#define SI5351_CLKOUT_MIN_FREQ				8000
#define SI5351_CLKOUT_MAX_FREQ				SI5351_MULTISYNTH_MAX_FREQ
#define SI5351_CLKOUT67_MAX_FREQ			SI5351_MULTISYNTH67_MAX_FREQ

#define SI5351_PLL_A_MIN					15
#define SI5351_PLL_A_MAX					90
#define SI5351_PLL_B_MAX					(SI5351_PLL_C_MAX-1)
#define SI5351_PLL_C_MAX					1048575
#define SI5351_MULTISYNTH_A_MIN				6
#define SI5351_MULTISYNTH_A_MAX				1800
#define SI5351_MULTISYNTH67_A_MAX			254
#define SI5351_MULTISYNTH_B_MAX				(SI5351_MULTISYNTH_C_MAX-1)
#define SI5351_MULTISYNTH_C_MAX				1048575
#define SI5351_MULTISYNTH_P1_MAX			((1<<18)-1)
#define SI5351_MULTISYNTH_P2_MAX			((1<<20)-1)
#define SI5351_MULTISYNTH_P3_MAX			((1<<20)-1)

#define SI5351_DEVICE_STATUS				0
#define SI5351_INTERRUPT_STATUS				1
#define SI5351_INTERRUPT_MASK				2
#define  SI5351_STATUS_SYS_INIT				(1<<7)
#define  SI5351_STATUS_LOL_B				(1<<6)
#define  SI5351_STATUS_LOL_A				(1<<5)
#define  SI5351_STATUS_LOS					(1<<4)
#define SI5351_OUTPUT_ENABLE_CTRL			3
#define SI5351_OEB_PIN_ENABLE_CTRL			9
#define SI5351_PLL_INPUT_SOURCE				15
#define  SI5351_CLKIN_DIV_MASK				(3<<6)
#define  SI5351_CLKIN_DIV_1					(0<<6)
#define  SI5351_CLKIN_DIV_2					(1<<6)
#define  SI5351_CLKIN_DIV_4					(2<<6)
#define  SI5351_CLKIN_DIV_8					(3<<6)
#define  SI5351_PLLB_SOURCE					(1<<3)
#define  SI5351_PLLA_SOURCE					(1<<2)

#define SI5351_CLK0_CTRL					16
#define SI5351_CLK1_CTRL					17
#define SI5351_CLK2_CTRL					18
#define SI5351_CLK3_CTRL					19
#define SI5351_CLK4_CTRL					20
#define SI5351_CLK5_CTRL					21
#define SI5351_CLK6_CTRL					22
#define SI5351_CLK7_CTRL					23
#define  SI5351_CLK_POWERDOWN				(1<<7)
#define  SI5351_CLK_INTEGER_MODE			(1<<6)
#define  SI5351_CLK_PLL_SELECT				(1<<5)
#define  SI5351_CLK_INVERT					(1<<4)
#define  SI5351_CLK_INPUT_MASK				(3<<2)
#define  SI5351_CLK_INPUT_XTAL				(0<<2)
#define  SI5351_CLK_INPUT_CLKIN				(1<<2)
#define  SI5351_CLK_INPUT_MULTISYNTH_0_4	(2<<2)
#define  SI5351_CLK_INPUT_MULTISYNTH_N		(3<<2)
#define  SI5351_CLK_DRIVE_STRENGTH_MASK		(3<<0)
#define  SI5351_CLK_DRIVE_STRENGTH_2MA		(0<<0)
#define  SI5351_CLK_DRIVE_STRENGTH_4MA		(1<<0)
#define  SI5351_CLK_DRIVE_STRENGTH_6MA		(2<<0)
#define  SI5351_CLK_DRIVE_STRENGTH_8MA		(3<<0)

#define SI5351_CLK3_0_DISABLE_STATE			24
#define SI5351_CLK7_4_DISABLE_STATE			25
#define  SI5351_CLK_DISABLE_STATE_MASK		3
#define  SI5351_CLK_DISABLE_STATE_LOW		0
#define  SI5351_CLK_DISABLE_STATE_HIGH		1
#define  SI5351_CLK_DISABLE_STATE_FLOAT		2
#define  SI5351_CLK_DISABLE_STATE_NEVER		3

#define SI5351_PARAMETERS_LENGTH			8
#define SI5351_PLLA_PARAMETERS				26
#define SI5351_PLLB_PARAMETERS				34
#define SI5351_CLK0_PARAMETERS				42
#define SI5351_CLK1_PARAMETERS				50
#define SI5351_CLK2_PARAMETERS				58
#define SI5351_CLK3_PARAMETERS				66
#define SI5351_CLK4_PARAMETERS				74
#define SI5351_CLK5_PARAMETERS				82
#define SI5351_CLK6_PARAMETERS				90
#define SI5351_CLK7_PARAMETERS				91
#define SI5351_CLK6_7_OUTPUT_DIVIDER		92
#define  SI5351_OUTPUT_CLK_DIV_MASK			(7 << 4)
#define  SI5351_OUTPUT_CLK6_DIV_MASK		(7 << 0)
#define  SI5351_OUTPUT_CLK_DIV_SHIFT		4
#define  SI5351_OUTPUT_CLK_DIV6_SHIFT		0
#define  SI5351_OUTPUT_CLK_DIV_1			0
#define  SI5351_OUTPUT_CLK_DIV_2			1
#define  SI5351_OUTPUT_CLK_DIV_4			2
#define  SI5351_OUTPUT_CLK_DIV_8			3
#define  SI5351_OUTPUT_CLK_DIV_16			4
#define  SI5351_OUTPUT_CLK_DIV_32			5
#define  SI5351_OUTPUT_CLK_DIV_64			6
#define  SI5351_OUTPUT_CLK_DIV_128			7
#define  SI5351_OUTPUT_CLK_DIVBY4			(3<<2)

#define SI5351_SSC_PARAM0					149
#define SI5351_SSC_PARAM1					150
#define SI5351_SSC_PARAM2					151
#define SI5351_SSC_PARAM3					152
#define SI5351_SSC_PARAM4					153
#define SI5351_SSC_PARAM5					154
#define SI5351_SSC_PARAM6					155
#define SI5351_SSC_PARAM7					156
#define SI5351_SSC_PARAM8					157
#define SI5351_SSC_PARAM9					158
#define SI5351_SSC_PARAM10					159
#define SI5351_SSC_PARAM11					160
#define SI5351_SSC_PARAM12					161

#define SI5351_VXCO_PARAMETERS_LOW			162
#define SI5351_VXCO_PARAMETERS_MID			163
#define SI5351_VXCO_PARAMETERS_HIGH			164

#define SI5351_CLK0_PHASE_OFFSET			165
#define SI5351_CLK1_PHASE_OFFSET			166
#define SI5351_CLK2_PHASE_OFFSET			167
#define SI5351_CLK3_PHASE_OFFSET			168
#define SI5351_CLK4_PHASE_OFFSET			169
#define SI5351_CLK5_PHASE_OFFSET			170

#define SI5351_PLL_RESET					177
#define  SI5351_PLL_RESET_B				(1<<7)
#define  SI5351_PLL_RESET_A				(1<<5)

#define SI5351_CRYSTAL_LOAD				183
#define  SI5351_CRYSTAL_LOAD_MASK		(3<<6)
#define  SI5351_CRYSTAL_LOAD_6PF		(1<<6)
#define  SI5351_CRYSTAL_LOAD_8PF		(2<<6)
#define  SI5351_CRYSTAL_LOAD_10PF		(3<<6)

#define SI5351_FANOUT_ENABLE			187
#define  SI5351_CLKIN_ENABLE			(1<<7)
#define  SI5351_XTAL_ENABLE				(1<<6)
#define  SI5351_MULTISYNTH_ENABLE		(1<<4)

/* Enum definitions */

/*
 * enum si5351_variant - SiLabs Si5351 chip variant
 * @SI5351_VARIANT_A: Si5351A (8 output clocks, XTAL input)
 * @SI5351_VARIANT_A3: Si5351A MSOP10 (3 output clocks, XTAL input)
 * @SI5351_VARIANT_B: Si5351B (8 output clocks, XTAL/VXCO input)
 * @SI5351_VARIANT_C: Si5351C (8 output clocks, XTAL/CLKIN input)
 */
enum si5351_variant {
	SI5351_VARIANT_A = 1,
	SI5351_VARIANT_A3 = 2,
	SI5351_VARIANT_B = 3,
	SI5351_VARIANT_C = 4,
};

enum si5351_clock {SI5351_CLK0, SI5351_CLK1, SI5351_CLK2, SI5351_CLK3,
	SI5351_CLK4, SI5351_CLK5, SI5351_CLK6, SI5351_CLK7};

enum si5351_pll {SI5351_PLLA, SI5351_PLLB};

enum si5351_drive {SI5351_DRIVE_2MA, SI5351_DRIVE_4MA, SI5351_DRIVE_6MA, SI5351_DRIVE_8MA};

/* Struct definitions */

struct Si5351RegSet
{
	u32 p1;
	u32 p2;
	u32 p3;
};

struct Si5351Status
{
	u8 SYS_INIT;
	u8 LOL_B;
	u8 LOL_A;
	u8 LOS;
	u8 REVID;
};

struct Si5351IntStatus
{
	u8 SYS_INIT_STKY;
	u8 LOL_B_STKY;
	u8 LOL_A_STKY;
	u8 LOS_STKY;
};
//
#endif
