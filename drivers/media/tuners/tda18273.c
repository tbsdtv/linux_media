/*
	tda18273.c - driver for the NXP TDA18273 silicon tuner
	Copyright (C) 2014 CrazyCat <crazycat69@narod.ru>

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "tda18273.h"
#include "tda18273_priv.h"

static unsigned int verbose;
module_param(verbose, int, 0644);
MODULE_PARM_DESC(verbose, "Set Verbosity level");

#define FE_ERROR				0
#define FE_NOTICE				1
#define FE_INFO					2
#define FE_DEBUG				3
#define FE_DEBUGREG				4

#define dprintk(__y, __z, format, arg...) do {						\
	if (__z) {									\
		if	((verbose > FE_ERROR) && (verbose > __y))			\
			printk(KERN_ERR "%s: " format "\n", __func__ , ##arg);		\
		else if	((verbose > FE_NOTICE) && (verbose > __y))			\
			printk(KERN_NOTICE "%s: " format "\n", __func__ , ##arg);	\
		else if ((verbose > FE_INFO) && (verbose > __y))			\
			printk(KERN_INFO "%s: " format "\n", __func__ , ##arg);		\
		else if ((verbose > FE_DEBUG) && (verbose > __y))			\
			printk(KERN_DEBUG "%s: " format "\n", __func__ , ##arg);	\
	} else {									\
		if (verbose > __y)							\
			printk(format, ##arg);						\
	}										\
} while (0)

#define TDA18273_REG_ADD_SZ                             (0x01)
#define TDA18273_REG_DATA_MAX_SZ                        (0x01)
#define TDA18273_REG_MAP_NB_BYTES                       (0x6D)

#define TDA18273_REG_DATA_LEN(_FIRST_REG, _LAST_REG)    ( (_LAST_REG.Address - _FIRST_REG.Address) + 1)

struct tda18273_state {
	struct dvb_frontend	*fe;
	struct i2c_adapter	*i2c;
	u8	i2c_addr;
	
	unsigned int if_freq;
	unsigned int freq_hz;
	unsigned int bandwidth;
	unsigned char freq_band;
	unsigned char agc_mode;
	unsigned char pll_step;
	unsigned char pll_step_val;
	unsigned char pll_charge_pump;

	unsigned int power_state;
	unsigned char regmap[TDA18273_REG_MAP_NB_BYTES];
	
	pTDA18273Object_t	pObj;
};

TDA18273Object_t gTDA18273Instance = 
{
	0,
	0,
	0,
	TDA18273_StandardMode_Unknown,
	NULL,
   	TDA18273_INSTANCE_CUSTOM_STD_DEF
};


/* TDA18273 Register ID_byte_1 0x00 */
const TDA18273_BitField_t gTDA18273_Reg_ID_byte_1 = { 0x00, 0x00, 0x08, 0x00 };
/* MS bit(s): Indicate if Device is a Master or a Slave */
/*  1 => Master device */
/*  0 => Slave device */
const TDA18273_BitField_t gTDA18273_Reg_ID_byte_1__MS = { 0x00, 0x07, 0x01, 0x00 };
/* Ident_1 bit(s): MSB of device identifier */
const TDA18273_BitField_t gTDA18273_Reg_ID_byte_1__Ident_1 = { 0x00, 0x00, 0x07, 0x00 };


/* TDA18273 Register ID_byte_2 0x01 */
const TDA18273_BitField_t gTDA18273_Reg_ID_byte_2 = { 0x01, 0x00, 0x08, 0x00 };
/* Ident_2 bit(s): LSB of device identifier */
const TDA18273_BitField_t gTDA18273_Reg_ID_byte_2__Ident_2 = { 0x01, 0x00, 0x08, 0x00 };


/* TDA18273 Register ID_byte_3 0x02 */
const TDA18273_BitField_t gTDA18273_Reg_ID_byte_3 = { 0x02, 0x00, 0x08, 0x00 };
/* Major_rev bit(s): Major revision of device */
const TDA18273_BitField_t gTDA18273_Reg_ID_byte_3__Major_rev = { 0x02, 0x04, 0x04, 0x00 };
/* Major_rev bit(s): Minor revision of device */
const TDA18273_BitField_t gTDA18273_Reg_ID_byte_3__Minor_rev = { 0x02, 0x00, 0x04, 0x00 };


/* TDA18273 Register Thermo_byte_1 0x03 */
const TDA18273_BitField_t gTDA18273_Reg_Thermo_byte_1 = { 0x03, 0x00, 0x08, 0x00 };
/* TM_D bit(s): Device temperature */
const TDA18273_BitField_t gTDA18273_Reg_Thermo_byte_1__TM_D = { 0x03, 0x00, 0x07, 0x00 };


/* TDA18273 Register Thermo_byte_2 0x04 */
const TDA18273_BitField_t gTDA18273_Reg_Thermo_byte_2 = { 0x04, 0x00, 0x08, 0x00 };
/* TM_ON bit(s): Set device temperature measurement to ON or OFF */
/*  1 => Temperature measurement ON */
/*  0 => Temperature measurement OFF */
const TDA18273_BitField_t gTDA18273_Reg_Thermo_byte_2__TM_ON = { 0x04, 0x00, 0x01, 0x00 };


/* TDA18273 Register Power_state_byte_1 0x05 */
const TDA18273_BitField_t gTDA18273_Reg_Power_state_byte_1 = { 0x05, 0x00, 0x08, 0x00 };
/* POR bit(s): Indicates that device just powered ON */
/*  1 => POR: No access done to device */
/*  0 => At least one access has been done to device */
const TDA18273_BitField_t gTDA18273_Reg_Power_state_byte_1__POR = { 0x05, 0x07, 0x01, 0x00 };
/* AGCs_Lock bit(s): Indicates that AGCs are locked */
/*  1 => AGCs locked */
/*  0 => AGCs not locked */
const TDA18273_BitField_t gTDA18273_Reg_Power_state_byte_1__AGCs_Lock = { 0x05, 0x02, 0x01, 0x00 };
/* Vsync_Lock bit(s): Indicates that VSync is locked */
/*  1 => VSync locked */
/*  0 => VSync not locked */
const TDA18273_BitField_t gTDA18273_Reg_Power_state_byte_1__Vsync_Lock = { 0x05, 0x01, 0x01, 0x00 };
/* LO_Lock bit(s): Indicates that LO is locked */
/*  1 => LO locked */
/*  0 => LO not locked */
const TDA18273_BitField_t gTDA18273_Reg_Power_state_byte_1__LO_Lock = { 0x05, 0x00, 0x01, 0x00 };


/* TDA18273 Register Power_state_byte_2 0x06 */
const TDA18273_BitField_t gTDA18273_Reg_Power_state_byte_2 = { 0x06, 0x00, 0x08, 0x00 };
/* SM bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_state_byte_2__SM = { 0x06, 0x01, 0x01, 0x00 };
/* SM_XT bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_state_byte_2__SM_XT = { 0x06, 0x00, 0x01, 0x00 };


/* TDA18273 Register Input_Power_Level_byte 0x07 */
const TDA18273_BitField_t gTDA18273_Reg_Input_Power_Level_byte = { 0x07, 0x00, 0x08, 0x00 };
/* Power_Level bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Input_Power_Level_byte__Power_Level = { 0x07, 0x00, 0x08, 0x00 };


/* TDA18273 Register IRQ_status 0x08 */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_status = { 0x08, 0x00, 0x08, 0x00 };
/* IRQ_status bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_status__IRQ_status = { 0x08, 0x07, 0x01, 0x00 };
/* MSM_XtalCal_End bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_status__MSM_XtalCal_End = { 0x08, 0x05, 0x01, 0x00 };
/* MSM_RSSI_End bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_status__MSM_RSSI_End = { 0x08, 0x04, 0x01, 0x00 };
/* MSM_LOCalc_End bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_status__MSM_LOCalc_End = { 0x08, 0x03, 0x01, 0x00 };
/* MSM_RFCal_End bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_status__MSM_RFCal_End = { 0x08, 0x02, 0x01, 0x00 };
/* MSM_IRCAL_End bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_status__MSM_IRCAL_End = { 0x08, 0x01, 0x01, 0x00 };
/* MSM_RCCal_End bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_status__MSM_RCCal_End = { 0x08, 0x00, 0x01, 0x00 };


/* TDA18273 Register IRQ_enable 0x09 */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_enable = { 0x09, 0x00, 0x08, 0x00 };
/* IRQ_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_enable__IRQ_Enable = { 0x09, 0x07, 0x01, 0x00 };
/* MSM_XtalCal_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_enable__MSM_XtalCal_Enable = { 0x09, 0x05, 0x01, 0x00 };
/* MSM_RSSI_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_enable__MSM_RSSI_Enable = { 0x09, 0x04, 0x01, 0x00 };
/* MSM_LOCalc_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_enable__MSM_LOCalc_Enable = { 0x09, 0x03, 0x01, 0x00 };
/* MSM_RFCal_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_enable__MSM_RFCal_Enable = { 0x09, 0x02, 0x01, 0x00 };
/* MSM_IRCAL_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_enable__MSM_IRCAL_Enable = { 0x09, 0x01, 0x01, 0x00 };
/* MSM_RCCal_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_enable__MSM_RCCal_Enable = { 0x09, 0x00, 0x01, 0x00 };


/* TDA18273 Register IRQ_clear 0x0A */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_clear = { 0x0A, 0x00, 0x08, 0x00 };
/* IRQ_Clear bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_clear__IRQ_Clear = { 0x0A, 0x07, 0x01, 0x00 };
/* MSM_XtalCal_Clear bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_clear__MSM_XtalCal_Clear = { 0x0A, 0x05, 0x01, 0x00 };
/* MSM_RSSI_Clear bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_clear__MSM_RSSI_Clear = { 0x0A, 0x04, 0x01, 0x00 };
/* MSM_LOCalc_Clear bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_clear__MSM_LOCalc_Clear = { 0x0A, 0x03, 0x01, 0x00 };
/* MSM_RFCal_Clear bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_clear__MSM_RFCal_Clear = { 0x0A, 0x02, 0x01, 0x00 };
/* MSM_IRCAL_Clear bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_clear__MSM_IRCAL_Clear = { 0x0A, 0x01, 0x01, 0x00 };
/* MSM_RCCal_Clear bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_clear__MSM_RCCal_Clear = { 0x0A, 0x00, 0x01, 0x00 };


/* TDA18273 Register IRQ_set 0x0B */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_set = { 0x0B, 0x00, 0x08, 0x00 };
/* IRQ_Set bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_set__IRQ_Set = { 0x0B, 0x07, 0x01, 0x00 };
/* MSM_XtalCal_Set bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_set__MSM_XtalCal_Set = { 0x0B, 0x05, 0x01, 0x00 };
/* MSM_RSSI_Set bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_set__MSM_RSSI_Set = { 0x0B, 0x04, 0x01, 0x00 };
/* MSM_LOCalc_Set bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_set__MSM_LOCalc_Set = { 0x0B, 0x03, 0x01, 0x00 };
/* MSM_RFCal_Set bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_set__MSM_RFCal_Set = { 0x0B, 0x02, 0x01, 0x00 };
/* MSM_IRCAL_Set bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_set__MSM_IRCAL_Set = { 0x0B, 0x01, 0x01, 0x00 };
/* MSM_RCCal_Set bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IRQ_set__MSM_RCCal_Set = { 0x0B, 0x00, 0x01, 0x00 };


/* TDA18273 Register AGC1_byte_1 0x0C */
const TDA18273_BitField_t gTDA18273_Reg_AGC1_byte_1 = { 0x0C, 0x00, 0x08, 0x00 };
/* AGC1_TOP bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC1_byte_1__AGC1_TOP = { 0x0C, 0x00, 0x04, 0x00 };


/* TDA18273 Register AGC1_byte_2 0x0D */
const TDA18273_BitField_t gTDA18273_Reg_AGC1_byte_2 = { 0x0D, 0x00, 0x08, 0x00 };
/* AGC1_Top_Mode_Val bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC1_byte_2__AGC1_Top_Mode_Val = { 0x0D, 0x03, 0x02, 0x00 };
/* AGC1_Top_Mode bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC1_byte_2__AGC1_Top_Mode = { 0x0D, 0x00, 0x03, 0x00 };


/* TDA18273 Register AGC2_byte_1 0x0E */
const TDA18273_BitField_t gTDA18273_Reg_AGC2_byte_1 = { 0x0E, 0x00, 0x08, 0x00 };
/* AGC2_TOP bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC2_byte_1__AGC2_TOP = { 0x0E, 0x00, 0x03, 0x00 };


/* TDA18273 Register AGCK_byte_1 0x0F */
const TDA18273_BitField_t gTDA18273_Reg_AGCK_byte_1 = { 0x0F, 0x00, 0x08, 0x00 };
/* AGCs_Up_Step_assym bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCK_byte_1__AGCs_Up_Step_assym = { 0x0F, 0x06, 0x02, 0x00 };
/* Pulse_Shaper_Disable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCK_byte_1__Pulse_Shaper_Disable = { 0x0F, 0x04, 0x01, 0x00 };
/* AGCK_Step bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCK_byte_1__AGCK_Step = { 0x0F, 0x02, 0x02, 0x00 };
/* AGCK_Mode bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCK_byte_1__AGCK_Mode = { 0x0F, 0x00, 0x02, 0x00 };


/* TDA18273 Register RF_AGC_byte 0x10 */
const TDA18273_BitField_t gTDA18273_Reg_RF_AGC_byte = { 0x10, 0x00, 0x08, 0x00 };
/* PD_AGC_Adapt3x bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_AGC_byte__PD_AGC_Adapt3x = { 0x10, 0x06, 0x02, 0x00 };
/* RFAGC_Adapt_TOP bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_AGC_byte__RFAGC_Adapt_TOP = { 0x10, 0x04, 0x02, 0x00 };
/* RFAGC_Low_BW bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_AGC_byte__RFAGC_Low_BW = { 0x10, 0x03, 0x01, 0x00 };
/* RFAGC_Top bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_AGC_byte__RFAGC_Top = { 0x10, 0x00, 0x03, 0x00 };


/* TDA18273 Register W_Filter_byte 0x11 */
const TDA18273_BitField_t gTDA18273_Reg_W_Filter_byte = { 0x11, 0x00, 0x08, 0x00 };
/* VHF_III_mode bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_W_Filter_byte__VHF_III_mode = { 0x11, 0x07, 0x01, 0x00 };
/* RF_Atten_3dB bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_W_Filter_byte__RF_Atten_3dB = { 0x11, 0x06, 0x01, 0x00 };
/* W_Filter_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_W_Filter_byte__W_Filter_Enable = { 0x11, 0x05, 0x01, 0x00 };
/* W_Filter_Bypass bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_W_Filter_byte__W_Filter_Bypass = { 0x11, 0x04, 0x01, 0x00 };
/* W_Filter bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_W_Filter_byte__W_Filter = { 0x11, 0x02, 0x02, 0x00 };
/* W_Filter_Offset bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_W_Filter_byte__W_Filter_Offset = { 0x11, 0x00, 0x02, 0x00 };


/* TDA18273 Register IR_Mixer_byte_1 0x12 */
const TDA18273_BitField_t gTDA18273_Reg_IR_Mixer_byte_1 = { 0x12, 0x00, 0x08, 0x00 };
/* S2D_Gain bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IR_Mixer_byte_1__S2D_Gain = { 0x12, 0x04, 0x02, 0x00 };
/* IR_Mixer_Top bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IR_Mixer_byte_1__IR_Mixer_Top = { 0x12, 0x00, 0x04, 0x00 };


/* TDA18273 Register AGC5_byte_1 0x13 */
const TDA18273_BitField_t gTDA18273_Reg_AGC5_byte_1 = { 0x13, 0x00, 0x08, 0x00 };
/* AGCs_Do_Step_assym bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC5_byte_1__AGCs_Do_Step_assym = { 0x13, 0x05, 0x02, 0x00 };
/* AGC5_Ana bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC5_byte_1__AGC5_Ana = { 0x13, 0x04, 0x01, 0x00 };
/* AGC5_TOP bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC5_byte_1__AGC5_TOP = { 0x13, 0x00, 0x04, 0x00 };


/* TDA18273 Register IF_AGC_byte 0x14 */
const TDA18273_BitField_t gTDA18273_Reg_IF_AGC_byte = { 0x14, 0x00, 0x08, 0x00 };
/* IFnotchToRSSI bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IF_AGC_byte__IFnotchToRSSI = { 0x14, 0x07, 0x01, 0x00 };
/* LPF_DCOffset_Corr bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IF_AGC_byte__LPF_DCOffset_Corr = { 0x14, 0x06, 0x01, 0x00 };
/* IF_level bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IF_AGC_byte__IF_level = { 0x14, 0x00, 0x03, 0x00 };


/* TDA18273 Register IF_Byte_1 0x15 */
const TDA18273_BitField_t gTDA18273_Reg_IF_Byte_1 = { 0x15, 0x00, 0x08, 0x00 };
/* IF_HP_Fc bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IF_Byte_1__IF_HP_Fc = { 0x15, 0x06, 0x02, 0x00 };
/* IF_ATSC_Notch bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IF_Byte_1__IF_ATSC_Notch = { 0x15, 0x05, 0x01, 0x00 };
/* LP_FC_Offset bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IF_Byte_1__LP_FC_Offset = { 0x15, 0x03, 0x02, 0x00 };
/* LP_Fc bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IF_Byte_1__LP_Fc = { 0x15, 0x00, 0x03, 0x00 };


/* TDA18273 Register Reference_Byte 0x16 */
const TDA18273_BitField_t gTDA18273_Reg_Reference_Byte = { 0x16, 0x00, 0x08, 0x00 };
/* Digital_Clock_Mode bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Reference_Byte__Digital_Clock_Mode = { 0x16, 0x06, 0x02, 0x00 };
/* XTout bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Reference_Byte__XTout = { 0x16, 0x00, 0x02, 0x00 };


/* TDA18273 Register IF_Frequency_byte 0x17 */
const TDA18273_BitField_t gTDA18273_Reg_IF_Frequency_byte = { 0x17, 0x00, 0x08, 0x00 };
/* IF_Freq bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IF_Frequency_byte__IF_Freq = { 0x17, 0x00, 0x08, 0x00 };


/* TDA18273 Register RF_Frequency_byte_1 0x18 */
const TDA18273_BitField_t gTDA18273_Reg_RF_Frequency_byte_1 = { 0x18, 0x00, 0x08, 0x00 };
/* RF_Freq_1 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Frequency_byte_1__RF_Freq_1 = { 0x18, 0x00, 0x04, 0x00 };


/* TDA18273 Register RF_Frequency_byte_2 0x19 */
const TDA18273_BitField_t gTDA18273_Reg_RF_Frequency_byte_2 = { 0x19, 0x00, 0x08, 0x00 };
/* RF_Freq_2 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Frequency_byte_2__RF_Freq_2 = { 0x19, 0x00, 0x08, 0x00 };


/* TDA18273 Register RF_Frequency_byte_3 0x1A */
const TDA18273_BitField_t gTDA18273_Reg_RF_Frequency_byte_3 = { 0x1A, 0x00, 0x08, 0x00 };
/* RF_Freq_3 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Frequency_byte_3__RF_Freq_3 = { 0x1A, 0x00, 0x08, 0x00 };


/* TDA18273 Register MSM_byte_1 0x1B */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_1 = { 0x1B, 0x00, 0x08, 0x00 };
/* RSSI_Meas bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_1__RSSI_Meas = { 0x1B, 0x07, 0x01, 0x00 };
/* RF_CAL_AV bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_1__RF_CAL_AV = { 0x1B, 0x06, 0x01, 0x00 };
/* RF_CAL bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_1__RF_CAL = { 0x1B, 0x05, 0x01, 0x00 };
/* IR_CAL_Loop bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_1__IR_CAL_Loop = { 0x1B, 0x04, 0x01, 0x00 };
/* IR_Cal_Image bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_1__IR_Cal_Image = { 0x1B, 0x03, 0x01, 0x00 };
/* IR_CAL_Wanted bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_1__IR_CAL_Wanted = { 0x1B, 0x02, 0x01, 0x00 };
/* RC_Cal bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_1__RC_Cal = { 0x1B, 0x01, 0x01, 0x00 };
/* Calc_PLL bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_1__Calc_PLL = { 0x1B, 0x00, 0x01, 0x00 };


/* TDA18273 Register MSM_byte_2 0x1C */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_2 = { 0x1C, 0x00, 0x08, 0x00 };
/* XtalCal_Launch bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_2__XtalCal_Launch = { 0x1C, 0x01, 0x01, 0x00 };
/* MSM_Launch bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_MSM_byte_2__MSM_Launch = { 0x1C, 0x00, 0x01, 0x00 };


/* TDA18273 Register PowerSavingMode 0x1D */
const TDA18273_BitField_t gTDA18273_Reg_PowerSavingMode = { 0x1D, 0x00, 0x08, 0x00 };
/* PSM_AGC1 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_PowerSavingMode__PSM_AGC1 = { 0x1D, 0x07, 0x01, 0x00 };
/* PSM_Bandsplit_Filter bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_PowerSavingMode__PSM_Bandsplit_Filter = { 0x1D, 0x05, 0x02, 0x00 };
/* PSM_RFpoly bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_PowerSavingMode__PSM_RFpoly = { 0x1D, 0x04, 0x01, 0x00 };
/* PSM_Mixer bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_PowerSavingMode__PSM_Mixer = { 0x1D, 0x03, 0x01, 0x00 };
/* PSM_Ifpoly bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_PowerSavingMode__PSM_Ifpoly = { 0x1D, 0x02, 0x01, 0x00 };
/* PSM_Lodriver bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_PowerSavingMode__PSM_Lodriver = { 0x1D, 0x00, 0x02, 0x00 };


/* TDA18273 Register Power_Level_byte_2 0x1E */
const TDA18273_BitField_t gTDA18273_Reg_Power_Level_byte_2 = { 0x1E, 0x00, 0x08, 0x00 };
/* PD_PLD_read bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_Level_byte_2__PD_PLD_read = { 0x1E, 0x07, 0x01, 0x00 };
/* IR_Target bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_Level_byte_2__PLD_Temp_Slope = { 0x1E, 0x05, 0x02, 0x00 };
/* IR_GStep bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_Level_byte_2__PLD_Gain_Corr = { 0x1E, 0x00, 0x05, 0x00 };


/* TDA18273 Register Adapt_Top_byte 0x1F */
const TDA18273_BitField_t gTDA18273_Reg_Adapt_Top_byte = { 0x1F, 0x00, 0x08, 0x00 };
/* Fast_Mode_AGC bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Adapt_Top_byte__Fast_Mode_AGC = { 0x1F, 0x06, 0x01, 0x00 };
/* Range_LNA_Adapt bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Adapt_Top_byte__Range_LNA_Adapt = { 0x1F, 0x05, 0x01, 0x00 };
/* Index_K_LNA_Adapt bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Adapt_Top_byte__Index_K_LNA_Adapt = { 0x1F, 0x03, 0x02, 0x00 };
/* Index_K_Top_Adapt bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Adapt_Top_byte__Index_K_Top_Adapt = { 0x1F, 0x01, 0x02, 0x00 };
/* Ovld_Udld_FastUp bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Adapt_Top_byte__Ovld_Udld_FastUp = { 0x1F, 0x00, 0x01, 0x00 };


/* TDA18273 Register Vsync_byte 0x20 */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_byte = { 0x20, 0x00, 0x08, 0x00 };
/* Neg_modulation bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_byte__Neg_modulation = { 0x20, 0x07, 0x01, 0x00 };
/* Tracer_Step bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_byte__Tracer_Step = { 0x20, 0x05, 0x02, 0x00 };
/* Vsync_int bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_byte__Vsync_int = { 0x20, 0x04, 0x01, 0x00 };
/* Vsync_Thresh bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_byte__Vsync_Thresh = { 0x20, 0x02, 0x02, 0x00 };
/* Vsync_Len bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_byte__Vsync_Len = { 0x20, 0x00, 0x02, 0x00 };


/* TDA18273 Register Vsync_Mgt_byte 0x21 */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_Mgt_byte = { 0x21, 0x00, 0x08, 0x00 };
/* PD_Vsync_Mgt bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_Mgt_byte__PD_Vsync_Mgt = { 0x21, 0x07, 0x01, 0x00 };
/* PD_Ovld bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_Mgt_byte__PD_Ovld = { 0x21, 0x06, 0x01, 0x00 };
/* PD_Ovld_RF bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_Mgt_byte__PD_Ovld_RF = { 0x21, 0x05, 0x01, 0x00 };
/* AGC_Ovld_TOP bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_Mgt_byte__AGC_Ovld_TOP = { 0x21, 0x02, 0x03, 0x00 };
/* Up_Step_Ovld bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_Mgt_byte__Up_Step_Ovld = { 0x21, 0x01, 0x01, 0x00 };
/* AGC_Ovld_Timer bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Vsync_Mgt_byte__AGC_Ovld_Timer = { 0x21, 0x00, 0x01, 0x00 };


/* TDA18273 Register IR_Mixer_byte_2 0x22 */
const TDA18273_BitField_t gTDA18273_Reg_IR_Mixer_byte_2 = { 0x22, 0x00, 0x08, 0x00 };
/* IR_Mixer_loop_off bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IR_Mixer_byte_2__IR_Mixer_loop_off = { 0x22, 0x07, 0x01, 0x00 };
/* IR_Mixer_Do_step bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IR_Mixer_byte_2__IR_Mixer_Do_step = { 0x22, 0x05, 0x02, 0x00 };
/* Hi_Pass bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IR_Mixer_byte_2__Hi_Pass = { 0x22, 0x01, 0x01, 0x00 };
/* IF_Notch bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IR_Mixer_byte_2__IF_Notch = { 0x22, 0x00, 0x01, 0x00 };


/* TDA18273 Register AGC1_byte_3 0x23 */
const TDA18273_BitField_t gTDA18273_Reg_AGC1_byte_3 = { 0x23, 0x00, 0x08, 0x00 };
/* AGC1_loop_off bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC1_byte_3__AGC1_loop_off = { 0x23, 0x07, 0x01, 0x00 };
/* AGC1_Do_step bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC1_byte_3__AGC1_Do_step = { 0x23, 0x05, 0x02, 0x00 };
/* Force_AGC1_gain bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC1_byte_3__Force_AGC1_gain = { 0x23, 0x04, 0x01, 0x00 };
/* AGC1_Gain bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC1_byte_3__AGC1_Gain = { 0x23, 0x00, 0x04, 0x00 };


/* TDA18273 Register RFAGCs_Gain_byte_1 0x24 */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_1 = { 0x24, 0x00, 0x08, 0x00 };
/* PLD_DAC_Scale bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_1__PLD_DAC_Scale = { 0x24, 0x07, 0x01, 0x00 };
/* PLD_CC_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_1__PLD_CC_Enable = { 0x24, 0x06, 0x01, 0x00 };
/* PLD_Temp_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_1__PLD_Temp_Enable = { 0x24, 0x05, 0x01, 0x00 };
/* TH_AGC_Adapt34 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_1__TH_AGC_Adapt34 = { 0x24, 0x04, 0x01, 0x00 };
/* RFAGC_Sense_Enable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_1__RFAGC_Sense_Enable = { 0x24, 0x02, 0x01, 0x00 };
/* RFAGC_K_Bypass bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_1__RFAGC_K_Bypass = { 0x24, 0x01, 0x01, 0x00 };
/* RFAGC_K_8 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_1__RFAGC_K_8 = { 0x24, 0x00, 0x01, 0x00 };


/* TDA18273 Register RFAGCs_Gain_byte_2 0x25 */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_2 = { 0x25, 0x00, 0x08, 0x00 };
/* RFAGC_K bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_2__RFAGC_K = { 0x25, 0x00, 0x08, 0x00 };


/* TDA18273 Register AGC5_byte_2 0x26 */
const TDA18273_BitField_t gTDA18273_Reg_AGC5_byte_2 = { 0x26, 0x00, 0x08, 0x00 };
/* AGC5_loop_off bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC5_byte_2__AGC5_loop_off = { 0x26, 0x07, 0x01, 0x00 };
/* AGC5_Do_step bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC5_byte_2__AGC5_Do_step = { 0x26, 0x05, 0x02, 0x00 };
/* Force_AGC5_gain bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC5_byte_2__Force_AGC5_gain = { 0x26, 0x03, 0x01, 0x00 };
/* AGC5_Gain bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGC5_byte_2__AGC5_Gain = { 0x26, 0x00, 0x03, 0x00 };


/* TDA18273 Register RF_Cal_byte_1 0x27 */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_1 = { 0x27, 0x00, 0x08, 0x00 };
/* RFCAL_Offset_Cprog0 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_1__RFCAL_Offset_Cprog0 = { 0x27, 0x06, 0x02, 0x00 };
/* RFCAL_Offset_Cprog1 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_1__RFCAL_Offset_Cprog1 = { 0x27, 0x04, 0x02, 0x00 };
/* RFCAL_Offset_Cprog2 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_1__RFCAL_Offset_Cprog2 = { 0x27, 0x02, 0x02, 0x00 };
/* RFCAL_Offset_Cprog3 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_1__RFCAL_Offset_Cprog3 = { 0x27, 0x00, 0x02, 0x00 };


/* TDA18273 Register RF_Cal_byte_2 0x28 */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_2 = { 0x28, 0x00, 0x08, 0x00 };
/* RFCAL_Offset_Cprog4 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_2__RFCAL_Offset_Cprog4 = { 0x28, 0x06, 0x02, 0x00 };
/* RFCAL_Offset_Cprog5 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_2__RFCAL_Offset_Cprog5 = { 0x28, 0x04, 0x02, 0x00 };
/* RFCAL_Offset_Cprog6 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_2__RFCAL_Offset_Cprog6 = { 0x28, 0x02, 0x02, 0x00 };
/* RFCAL_Offset_Cprog7 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_2__RFCAL_Offset_Cprog7 = { 0x28, 0x00, 0x02, 0x00 };


/* TDA18273 Register RF_Cal_byte_3 0x29 */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_3 = { 0x29, 0x00, 0x08, 0x00 };
/* RFCAL_Offset_Cprog8 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_3__RFCAL_Offset_Cprog8 = { 0x29, 0x06, 0x02, 0x00 };
/* RFCAL_Offset_Cprog9 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_3__RFCAL_Offset_Cprog9 = { 0x29, 0x04, 0x02, 0x00 };
/* RFCAL_Offset_Cprog10 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_3__RFCAL_Offset_Cprog10 = { 0x29, 0x02, 0x02, 0x00 };
/* RFCAL_Offset_Cprog11 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Cal_byte_3__RFCAL_Offset_Cprog11 = { 0x29, 0x00, 0x02, 0x00 };


/* TDA18273 Register Bandsplit_Filter_byte 0x2A */
const TDA18273_BitField_t gTDA18273_Reg_Bandsplit_Filter_byte = { 0x2A, 0x00, 0x08, 0x00 };
/* Bandsplit_Filter_SubBand bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Bandsplit_Filter_byte__Bandsplit_Filter_SubBand = { 0x2A, 0x00, 0x02, 0x00 };


/* TDA18273 Register RF_Filters_byte_1 0x2B */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_1 = { 0x2B, 0x00, 0x08, 0x00 };
/* RF_Filter_Bypass bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_1__RF_Filter_Bypass = { 0x2B, 0x07, 0x01, 0x00 };
/* AGC2_loop_off bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_1__AGC2_loop_off = { 0x2B, 0x05, 0x01, 0x00 };
/* Force_AGC2_gain bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_1__Force_AGC2_gain = { 0x2B, 0x04, 0x01, 0x00 };
/* RF_Filter_Gv bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_1__RF_Filter_Gv = { 0x2B, 0x02, 0x02, 0x00 };
/* RF_Filter_Band bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_1__RF_Filter_Band = { 0x2B, 0x00, 0x02, 0x00 };


/* TDA18273 Register RF_Filters_byte_2 0x2C */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_2 = { 0x2C, 0x00, 0x08, 0x00 };
/* RF_Filter_Cap bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_2__RF_Filter_Cap = { 0x2C, 0x00, 0x08, 0x00 };


/* TDA18273 Register RF_Filters_byte_3 0x2D */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_3 = { 0x2D, 0x00, 0x08, 0x00 };
/* AGC2_Do_step bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_3__AGC2_Do_step = { 0x2D, 0x06, 0x02, 0x00 };
/* Gain_Taper bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Filters_byte_3__Gain_Taper = { 0x2D, 0x00, 0x06, 0x00 };


/* TDA18273 Register RF_Band_Pass_Filter_byte 0x2E */
const TDA18273_BitField_t gTDA18273_Reg_RF_Band_Pass_Filter_byte = { 0x2E, 0x00, 0x08, 0x00 };
/* RF_BPF_Bypass bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Band_Pass_Filter_byte__RF_BPF_Bypass = { 0x2E, 0x07, 0x01, 0x00 };
/* RF_BPF bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RF_Band_Pass_Filter_byte__RF_BPF = { 0x2E, 0x00, 0x03, 0x00 };


/* TDA18273 Register CP_Current_byte 0x2F */
const TDA18273_BitField_t gTDA18273_Reg_CP_Current_byte = { 0x2F, 0x00, 0x08, 0x00 };
/* LO_CP_Current bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_CP_Current_byte__LO_CP_Current = { 0x2F, 0x07, 0x01, 0x00 };
/* N_CP_Current bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_CP_Current_byte__N_CP_Current = { 0x2F, 0x00, 0x07, 0x00 };


/* TDA18273 Register AGCs_DetOut_byte 0x30 */
const TDA18273_BitField_t gTDA18273_Reg_AGCs_DetOut_byte = { 0x30, 0x00, 0x08, 0x00 };
/* Up_AGC5 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCs_DetOut_byte__Up_AGC5 = { 0x30, 0x07, 0x01, 0x00 };
/* Do_AGC5 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCs_DetOut_byte__Do_AGC5 = { 0x30, 0x06, 0x01, 0x00 };
/* Up_AGC4 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCs_DetOut_byte__Up_AGC4 = { 0x30, 0x05, 0x01, 0x00 };
/* Do_AGC4 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCs_DetOut_byte__Do_AGC4 = { 0x30, 0x04, 0x01, 0x00 };
/* Up_AGC2 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCs_DetOut_byte__Up_AGC2 = { 0x30, 0x03, 0x01, 0x00 };
/* Do_AGC2 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCs_DetOut_byte__Do_AGC2 = { 0x30, 0x02, 0x01, 0x00 };
/* Up_AGC1 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCs_DetOut_byte__Up_AGC1 = { 0x30, 0x01, 0x01, 0x00 };
/* Do_AGC1 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_AGCs_DetOut_byte__Do_AGC1 = { 0x30, 0x00, 0x01, 0x00 };


/* TDA18273 Register RFAGCs_Gain_byte_3 0x31 */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_3 = { 0x31, 0x00, 0x08, 0x00 };
/* AGC2_Gain_Read bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_3__AGC2_Gain_Read = { 0x31, 0x04, 0x02, 0x00 };
/* AGC1_Gain_Read bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_3__AGC1_Gain_Read = { 0x31, 0x00, 0x04, 0x00 };


/* TDA18273 Register RFAGCs_Gain_byte_4 0x32 */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_4 = { 0x32, 0x00, 0x08, 0x00 };
/* Cprog_Read bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_4__Cprog_Read = { 0x32, 0x00, 0x08, 0x00 };


/* TDA18273 Register RFAGCs_Gain_byte_5 0x33 */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_5 = { 0x33, 0x00, 0x08, 0x00 };
/* RFAGC_Read_K_8 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_5__RFAGC_Read_K_8 = { 0x33, 0x07, 0x01, 0x00 };
/* Do_AGC1bis bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_5__Do_AGC1bis = { 0x33, 0x06, 0x01, 0x00 };
/* AGC1_Top_Adapt_Low bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_5__AGC1_Top_Adapt_Low = { 0x33, 0x05, 0x01, 0x00 };
/* Up_LNA_Adapt bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_5__Up_LNA_Adapt = { 0x33, 0x04, 0x01, 0x00 };
/* Do_LNA_Adapt bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_5__Do_LNA_Adapt = { 0x33, 0x03, 0x01, 0x00 };
/* TOP_AGC3_Read bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_5__TOP_AGC3_Read = { 0x33, 0x00, 0x03, 0x00 };


/* TDA18273 Register RFAGCs_Gain_byte_6 0x34 */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_6 = { 0x34, 0x00, 0x08, 0x00 };
/* RFAGC_Read_K bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RFAGCs_Gain_byte_6__RFAGC_Read_K = { 0x34, 0x00, 0x08, 0x00 };


/* TDA18273 Register IFAGCs_Gain_byte 0x35 */
const TDA18273_BitField_t gTDA18273_Reg_IFAGCs_Gain_byte = { 0x35, 0x00, 0x08, 0x00 };
/* AGC5_Gain_Read bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IFAGCs_Gain_byte__AGC5_Gain_Read = { 0x35, 0x03, 0x03, 0x00 };
/* AGC4_Gain_Read bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IFAGCs_Gain_byte__AGC4_Gain_Read = { 0x35, 0x00, 0x03, 0x00 };


/* TDA18273 Register RSSI_byte_1 0x36 */
const TDA18273_BitField_t gTDA18273_Reg_RSSI_byte_1 = { 0x36, 0x00, 0x08, 0x00 };
/* RSSI bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RSSI_byte_1__RSSI = { 0x36, 0x00, 0x08, 0x00 };


/* TDA18273 Register RSSI_byte_2 0x37 */
const TDA18273_BitField_t gTDA18273_Reg_RSSI_byte_2 = { 0x37, 0x00, 0x08, 0x00 };
/* RSSI_AV bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RSSI_byte_2__RSSI_AV = { 0x37, 0x05, 0x01, 0x00 };
/* RSSI_Cap_Reset_En bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RSSI_byte_2__RSSI_Cap_Reset_En = { 0x37, 0x03, 0x01, 0x00 };
/* RSSI_Cap_Val bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RSSI_byte_2__RSSI_Cap_Val = { 0x37, 0x02, 0x01, 0x00 };
/* RSSI_Ck_Speed bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RSSI_byte_2__RSSI_Ck_Speed = { 0x37, 0x01, 0x01, 0x00 };
/* RSSI_Dicho_not bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_RSSI_byte_2__RSSI_Dicho_not = { 0x37, 0x00, 0x01, 0x00 };


/* TDA18273 Register Misc_byte 0x38 */
const TDA18273_BitField_t gTDA18273_Reg_Misc_byte = { 0x38, 0x00, 0x08, 0x00 };
/* RFCALPOR_I2C bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Misc_byte__RFCALPOR_I2C = { 0x38, 0x06, 0x01, 0x00 };
/* PD_Underload bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Misc_byte__PD_Underload = { 0x38, 0x05, 0x01, 0x00 };
/* DDS_Polarity bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Misc_byte__DDS_Polarity = { 0x38, 0x04, 0x01, 0x00 };
/* IRQ_Mode bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Misc_byte__IRQ_Mode = { 0x38, 0x01, 0x01, 0x00 };
/* IRQ_Polarity bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Misc_byte__IRQ_Polarity = { 0x38, 0x00, 0x01, 0x00 };


/* TDA18273 Register rfcal_log_0 0x39 */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_0 = { 0x39, 0x00, 0x08, 0x00 };
/* rfcal_log_0 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_0__rfcal_log_0 = { 0x39, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_1 0x3A */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_1 = { 0x3A, 0x00, 0x08, 0x00 };
/* rfcal_log_1 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_1__rfcal_log_1 = { 0x3A, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_2 0x3B */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_2 = { 0x3B, 0x00, 0x08, 0x00 };
/* rfcal_log_2 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_2__rfcal_log_2 = { 0x3B, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_3 0x3C */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_3 = { 0x3C, 0x00, 0x08, 0x00 };
/* rfcal_log_3 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_3__rfcal_log_3 = { 0x3C, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_4 0x3D */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_4 = { 0x3D, 0x00, 0x08, 0x00 };
/* rfcal_log_4 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_4__rfcal_log_4 = { 0x3D, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_5 0x3E */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_5 = { 0x3E, 0x00, 0x08, 0x00 };
/* rfcal_log_5 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_5__rfcal_log_5 = { 0x3E, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_6 0x3F */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_6 = { 0x3F, 0x00, 0x08, 0x00 };
/* rfcal_log_6 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_6__rfcal_log_6 = { 0x3F, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_7 0x40 */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_7 = { 0x40, 0x00, 0x08, 0x00 };
/* rfcal_log_7 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_7__rfcal_log_7 = { 0x40, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_8 0x41 */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_8 = { 0x41, 0x00, 0x08, 0x00 };
/* rfcal_log_8 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_8__rfcal_log_8 = { 0x41, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_9 0x42 */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_9 = { 0x42, 0x00, 0x08, 0x00 };
/* rfcal_log_9 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_9__rfcal_log_9 = { 0x42, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_10 0x43 */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_10 = { 0x43, 0x00, 0x08, 0x00 };
/* rfcal_log_10 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_10__rfcal_log_10 = { 0x43, 0x00, 0x08, 0x00 };


/* TDA18273 Register rfcal_log_11 0x44 */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_11 = { 0x44, 0x00, 0x08, 0x00 };
/* rfcal_log_11 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_rfcal_log_11__rfcal_log_11 = { 0x44, 0x00, 0x08, 0x00 };



/* TDA18273 Register Main_Post_Divider_byte 0x51 */
const TDA18273_BitField_t gTDA18273_Reg_Main_Post_Divider_byte = { 0x51, 0x00, 0x08, 0x00 };
/* LOPostDiv bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Main_Post_Divider_byte__LOPostDiv = { 0x51, 0x04, 0x03, 0x00 };
/* LOPresc bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Main_Post_Divider_byte__LOPresc = { 0x51, 0x00, 0x04, 0x00 };


/* TDA18273 Register Sigma_delta_byte_1 0x52 */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_1 = { 0x52, 0x00, 0x08, 0x00 };
/* LO_Int bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_1__LO_Int = { 0x52, 0x00, 0x07, 0x00 };


/* TDA18273 Register Sigma_delta_byte_2 0x53 */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_2 = { 0x53, 0x00, 0x08, 0x00 };
/* LO_Frac_2 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_2__LO_Frac_2 = { 0x53, 0x00, 0x07, 0x00 };


/* TDA18273 Register Sigma_delta_byte_3 0x54 */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_3 = { 0x54, 0x00, 0x08, 0x00 };
/* LO_Frac_1 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_3__LO_Frac_1 = { 0x54, 0x00, 0x08, 0x00 };


/* TDA18273 Register Sigma_delta_byte_4 0x55 */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_4 = { 0x55, 0x00, 0x08, 0x00 };
/* LO_Frac_0 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_4__LO_Frac_0 = { 0x55, 0x00, 0x08, 0x00 };


/* TDA18273 Register Sigma_delta_byte_5 0x56 */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_5 = { 0x56, 0x00, 0x08, 0x00 };
/* N_K_correct_manual bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_5__N_K_correct_manual = { 0x56, 0x01, 0x01, 0x00 };
/* LO_Calc_Disable bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Sigma_delta_byte_5__LO_Calc_Disable = { 0x56, 0x00, 0x01, 0x00 };


/* TDA18273 Register Regulators_byte 0x58 */
const TDA18273_BitField_t gTDA18273_Reg_Regulators_byte = { 0x58, 0x00, 0x08, 0x00 };
/* RF_Reg bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Regulators_byte__RF_Reg = { 0x58, 0x02, 0x02, 0x00 };


/* TDA18273 Register IR_Cal_byte_5 0x5B */
const TDA18273_BitField_t gTDA18273_Reg_IR_Cal_byte_5 = { 0x5B, 0x00, 0x08, 0x00 };
/* Mixer_Gain_Bypass bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IR_Cal_byte_5__Mixer_Gain_Bypass = { 0x5B, 0x07, 0x01, 0x00 };
/* IR_Mixer_Gain bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_IR_Cal_byte_5__IR_Mixer_Gain = { 0x5B, 0x04, 0x03, 0x00 };


/* TDA18273 Register Power_Down_byte_2 0x5F */
const TDA18273_BitField_t gTDA18273_Reg_Power_Down_byte_2 = { 0x5F, 0x00, 0x08, 0x00 };
/* PD_LNA bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_Down_byte_2__PD_LNA = { 0x5F, 0x07, 0x01, 0x00 };
/* PD_Det4 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_Down_byte_2__PD_Det4 = { 0x5F, 0x03, 0x01, 0x00 };
/* PD_Det3 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_Down_byte_2__PD_Det3 = { 0x5F, 0x02, 0x01, 0x00 };
/* PD_Det1 bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_Down_byte_2__PD_Det1 = { 0x5F, 0x00, 0x01, 0x00 };

/* TDA18273 Register Power_Down_byte_3 0x60 */
const TDA18273_BitField_t gTDA18273_Reg_Power_Down_byte_3 = { 0x60, 0x00, 0x08, 0x00 };
/* Force_Soft_Reset bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_Down_byte_3__Force_Soft_Reset = { 0x60, 0x01, 0x01, 0x00 };
/* Soft_Reset bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Power_Down_byte_3__Soft_Reset = { 0x60, 0x00, 0x01, 0x00 };

/* TDA18273 Register Charge_pump_byte 0x64 */
const TDA18273_BitField_t gTDA18273_Reg_Charge_pump_byte = { 0x64, 0x00, 0x08, 0x00 };
/* ICP_Bypass bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Charge_pump_byte__ICP_Bypass = { 0x64, 0x07, 0x01, 0x00 };
/* ICP bit(s):  */
const TDA18273_BitField_t gTDA18273_Reg_Charge_pump_byte__ICP = { 0x64, 0x00, 0x02, 0x00 };


static int tda18273_readreg(struct tda18273_state *priv, unsigned char reg, unsigned char *val)
{
	int ret = TDA_RESULT_SUCCESS;
	struct dvb_frontend *fe	= priv->fe;

	struct i2c_msg msg[2] = {
		{ .addr = priv->i2c_addr,
			.flags = 0, .buf = &reg, .len = 1},
		{ .addr = priv->i2c_addr,
			.flags = I2C_M_RD, .buf = val, .len = 1},
	};

	if (fe->ops.i2c_gate_ctrl)
		fe->ops.i2c_gate_ctrl(fe, 1);
	
	ret = i2c_transfer(priv->i2c, msg, 2);
	
	if (ret != 2) {
		dprintk(FE_ERROR, 1, "I2C read failed");
		ret = TDA_RESULT_I2C_READ_FAILURE;
	}
	
	if (fe->ops.i2c_gate_ctrl)
		fe->ops.i2c_gate_ctrl(fe, 0);
	
	return ret;
}

static int tda18273_readregs(struct tda18273_state *priv, const TDA18273_BitField_t* pBitField, unsigned char *val, tmbslFrontEndBusAccess_t eBusAccess)
{
	unsigned char RegAddr = 0;
	unsigned char RegMask = 0;
	unsigned char RegData = 0;
	unsigned char* pRegData = NULL;
	
	RegAddr = pBitField->Address;
	
	if(RegAddr < TDA18273_REG_MAP_NB_BYTES)	{
		pRegData = (unsigned char *)(&(priv->regmap)) + RegAddr;
	} else {
		pRegData = &RegData;
	}
	
	if((eBusAccess & Bus_NoRead) == 0x00) {
		if(tda18273_readreg(priv, RegAddr, pRegData) == TDA_RESULT_I2C_READ_FAILURE) {
			return TDA_RESULT_I2C_READ_FAILURE;
		}
	}
	
	*val = *pRegData;
	
	RegMask = ((1 << pBitField->WidthInBits) - 1) << pBitField->PositionInBits;
	
	*val &= RegMask;
	*val = (*val) >> pBitField->PositionInBits;

	return TDA_RESULT_SUCCESS;
}

static int tda18273_readregmap(struct tda18273_state *priv, unsigned char reg, unsigned int len)
{
	int ret, i;
	unsigned char* pRegData = NULL;
	
	if((reg < TDA18273_REG_MAP_NB_BYTES) && ((reg + len) <= TDA18273_REG_MAP_NB_BYTES)) {
		pRegData = (unsigned char *)(&(priv->regmap)) + reg;
		
		for(i=0; i<len; i++) {
			/* Read data from TDA18273 */
			ret = tda18273_readreg(priv, (reg + i), (pRegData + i));
		}
	}
	
	return 0;
}

static int tda18273_writereg(struct tda18273_state *priv, unsigned char reg, unsigned char val)
{
	int ret = TDA_RESULT_SUCCESS;
	struct dvb_frontend *fe	= priv->fe;
	unsigned char tmp[2] = {reg, val};
	
	struct i2c_msg msg = { 
		.addr = priv->i2c_addr,
		.flags = 0, .buf = tmp, .len = 2};

	if (fe->ops.i2c_gate_ctrl)
		fe->ops.i2c_gate_ctrl(fe, 1);
	
	ret = i2c_transfer(priv->i2c, &msg, 1);
	
	if (ret != 1) {
		dprintk(FE_ERROR, 1, "I2C write failed");
		ret = TDA_RESULT_I2C_READ_FAILURE;
	}
	
	if (fe->ops.i2c_gate_ctrl)
		fe->ops.i2c_gate_ctrl(fe, 0);
	
	return ret;
}

static int tda18273_writeregs(struct tda18273_state *priv, const TDA18273_BitField_t* pBitField, unsigned char val, tmbslFrontEndBusAccess_t eBusAccess)
{
	unsigned char RegAddr = 0;
	unsigned char RegData = 0;
	unsigned char RegMask = 0;
	unsigned char* pRegData = NULL;

	RegAddr = pBitField->Address;
	
	if(RegAddr < TDA18273_REG_MAP_NB_BYTES)	{
		pRegData = (unsigned char *)(&(priv->regmap)) + RegAddr;
	} else {
		pRegData = &RegData;
	}

	if((eBusAccess & Bus_NoRead) == 0x00) {
		if(tda18273_readreg(priv, RegAddr, pRegData) == TDA_RESULT_I2C_READ_FAILURE) {
			return TDA_RESULT_I2C_READ_FAILURE;
		}
	}
	
	RegMask = (1 << pBitField->WidthInBits) - 1;
	val &= RegMask;

	RegMask = RegMask << pBitField->PositionInBits;
	*pRegData &= (UInt8)(~RegMask);
	*pRegData |= val << pBitField->PositionInBits;

	if((eBusAccess & Bus_NoWrite) == 0x00) {
		if(tda18273_writereg(priv, RegAddr, *pRegData) == TDA_RESULT_I2C_READ_FAILURE) {
			return TDA_RESULT_I2C_READ_FAILURE;
		}
	}
	
	return TDA_RESULT_SUCCESS;
}

static int tda18273_writeregmap(struct tda18273_state *priv, unsigned char reg, unsigned int len)
{
	int ret, i;
	unsigned char* pRegData = NULL;
	
	if((reg < TDA18273_REG_MAP_NB_BYTES) && ((reg + len) <= TDA18273_REG_MAP_NB_BYTES)) {
		pRegData = (unsigned char *)(&(priv->regmap)) + reg;
		
		for(i=0; i<len; i++) {
			/* Write data from TDA18273 */
			ret = tda18273_writereg(priv, (reg + i), *(pRegData + i));
		}
	}
	
	return 0;
}

static void tda18273_regall_debug(struct tda18273_state *priv)
{
	int i;
	unsigned char val=0;

	for(i=0; i<0x45; i++) {
		tda18273_readreg(priv, i, &val);
		dprintk(FE_DEBUGREG, 1, "addr : 0x%02x  =>  data : 0x%02x", i, val);
	}
}

static int tda18273_get_lock_status(struct tda18273_state *priv, unsigned short *lock_status)
{
	int ret;
	unsigned char val=0;
	unsigned char val_lo=0;

	ret = tda18273_readregs(priv, &gTDA18273_Reg_Power_state_byte_1__LO_Lock, &val_lo, Bus_RW);
	ret = tda18273_readregs(priv, &gTDA18273_Reg_IRQ_status__IRQ_status, &val, Bus_RW);
	*lock_status = val & val_lo;

	dprintk(FE_INFO, 1, "lock=0x%02X/0x%02x, lock_status=0x%x", val, val_lo, *lock_status);

	return 0;
}

static int tda18273_pwr_state(struct dvb_frontend *fe, int pwr_state)
{
	struct tda18273_state *priv = fe->tuner_priv;
	int ret=0;

	if(priv->power_state != pwr_state) {
		if(pwr_state == tmPowerOn) {
			/* Set TDA18273 power state to Normal Mode */
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_Down_byte_2__PD_LNA, 0x1, Bus_RW);				/* PD LNA */
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_Down_byte_2__PD_Det1, 0x1, Bus_NoRead);			/* PD Detector AGC1 */
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC1_byte_3__AGC1_loop_off, 0x1, Bus_RW);				/* AGC1 Detector loop off */
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_state_byte_2, TDA18273_SM_NONE, Bus_RW);
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_Reference_Byte__Digital_Clock_Mode, 0x03, Bus_RW);		/* Set digital clock mode to sub-LO if normal mode is entered */
		} else if(pwr_state == tmPowerStandby) {
			/* Set TDA18273 power state to standby with Xtal ON */
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_Reference_Byte__Digital_Clock_Mode, 0x00, Bus_RW);
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_state_byte_2, 0x02, Bus_RW);
		}

		priv->power_state = pwr_state;
	}

	return 0;
}

static int tda18273_firstpass_lnapwr(struct dvb_frontend *fe)
{
	struct tda18273_state *priv = fe->tuner_priv;
	
	int ret;
	
	/* PD LNA */
    ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_Down_byte_2__PD_LNA, 0x1, Bus_RW);
	/* PD Detector AGC1 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_Down_byte_2__PD_Det1, 0x1, Bus_NoRead);
	/* AGC1 Detector loop off */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC1_byte_3__AGC1_loop_off, 0x1, Bus_RW);
        
	return 0;
}

static int tda18273_lastpass_lnapwr(struct dvb_frontend *fe)
{
	struct tda18273_state *priv = fe->tuner_priv;
	
	unsigned char val = 0;
	int ret;
	
	/* Check if LNA is PD */
    ret = tda18273_readregs(priv, &gTDA18273_Reg_Power_Down_byte_2__PD_LNA, &val, Bus_NoWrite);

	if(val == 1) {
		/* LNA is Powered Down, so power it up */
		/* Force gain to -10dB */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC1_byte_3__AGC1_Gain, 0x0, Bus_RW);
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC1_byte_3__Force_AGC1_gain, 0x1, Bus_NoRead);
		/* PD LNA */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_Down_byte_2__PD_LNA, 0x0, Bus_NoRead);
		/* Release LNA gain control */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC1_byte_3__Force_AGC1_gain, 0x0, Bus_NoRead);
		/* PD Detector AGC1 */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_Down_byte_2__PD_Det1, 0x0, Bus_NoRead);
		/* AGC1 Detector loop off */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC1_byte_3__AGC1_loop_off, 0x0, Bus_NoRead);
	}
    
	return 0;
}

static int tda18273_llpwr_state(struct dvb_frontend *fe, int llpwr_state)
{
	struct tda18273_state *priv = fe->tuner_priv;
	
	unsigned char val = 0;
	int ret;
	
	if(llpwr_state == TDA18273_PowerNormalMode) {
		/* If we come from any standby mode, then power on the IC with LNA off */
        /* Then powering on LNA with the minimal gain on AGC1 to avoid glitches at RF input will */
        /* be done during SetRF */

        /* Workaround to limit the spurs occurence on RF input, do it before entering normal mode */
        /* PD LNA */
		ret = tda18273_firstpass_lnapwr(fe);
        ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_state_byte_2, TDA18273_SM_NONE, Bus_RW);
		/* Set digital clock mode to sub-LO if normal mode is entered */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Reference_Byte__Digital_Clock_Mode, 0x03, Bus_RW);

        /* Reset val to use it as a flag for below test */
        val = 0;
	} else if(llpwr_state == TDA18273_PowerStandbyWithXtalOn) {
		val = TDA18273_SM;
	} else if(llpwr_state == TDA18273_PowerStandby) {
		/* power state not supported */
		val = TDA18273_SM|TDA18273_SM_XT;
	}
	
	if(val) {
		/* Set digital clock mode to 16 Mhz before entering standby */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Reference_Byte__Digital_Clock_Mode, 0x00, Bus_RW);
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_state_byte_2, val, Bus_RW);
	}
	
	return 0;
}

static int tda18273_check_calcpll(struct dvb_frontend *fe)
{
	struct tda18273_state *priv = fe->tuner_priv;

	int ret;
	unsigned char val;

    /* Check if Calc_PLL algorithm is in automatic mode */
    ret = tda18273_readregs(priv, &gTDA18273_Reg_Sigma_delta_byte_5__LO_Calc_Disable, &val, Bus_None);
    
    if(val != 0x00) {
        /* Enable Calc_PLL algorithm by putting PLL in automatic mode */
        ret = tda18273_writeregs(priv, &gTDA18273_Reg_Sigma_delta_byte_5__N_K_correct_manual, 0x00, Bus_None);
        ret = tda18273_writeregs(priv, &gTDA18273_Reg_Sigma_delta_byte_5__LO_Calc_Disable, 0x00, Bus_NoRead);
    } 
	
	return 0;
}

static int tda18273_set_msm(struct dvb_frontend *fe, unsigned char val, int launch)
{
	struct tda18273_state *priv = fe->tuner_priv;
	int ret;
	
	/* Set state machine and Launch it */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_MSM_byte_1, val, Bus_None);
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_MSM_byte_2__MSM_Launch, 0x01, Bus_None);
	ret = tda18273_writeregmap(priv, gTDA18273_Reg_MSM_byte_1.Address, (launch ? 0x02 : 0x01));
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_MSM_byte_2__MSM_Launch, 0x00, Bus_None);
	
	return 0;
}

static int tda18273_override_bandsplit(struct dvb_frontend *fe)
{
	struct tda18273_state *priv = fe->tuner_priv;
	
	int ret;
	unsigned char Bandsplit = 0;
	unsigned char uPrevPSM_Bandsplit_Filter = 0;
	unsigned char PSM_Bandsplit_Filter = 0;
	
	/* Setting PSM bandsplit at -3.9 mA for some RF frequencies */
	ret = tda18273_readregs(priv, &gTDA18273_Reg_Bandsplit_Filter_byte__Bandsplit_Filter_SubBand, &Bandsplit, Bus_None);
	ret = tda18273_readregs(priv, &gTDA18273_Reg_PowerSavingMode__PSM_Bandsplit_Filter, &uPrevPSM_Bandsplit_Filter, Bus_None);
	
	switch(Bandsplit)
	{
		default:
		case 0:	/* LPF0 133MHz - LPF1 206MHz - HPF0 422MHz */
				if(priv->pObj->uProgRF < 133000000) {
					/* Set PSM bandsplit at -3.9 mA */
					PSM_Bandsplit_Filter = 0x03;
				} else {
					/* Set PSM bandsplit at nominal */
					PSM_Bandsplit_Filter = 0x02;
				}
			break;
		case 1:	/* LPF0 139MHz - LPF1 218MHz - HPF0 446MHz */
				if(priv->pObj->uProgRF < 139000000) {
					/* Set PSM bandsplit at -3.9 mA */
					PSM_Bandsplit_Filter = 0x03;
				} else {
					/* Set PSM bandsplit at nominal */
					PSM_Bandsplit_Filter = 0x02;
				}
			break;
		case 2:	/* LPF0 145MHz - LPF1 230MHz - HPF0 470MHz */
				if(priv->pObj->uProgRF < 145000000) {
					/* Set PSM bandsplit at -3.9 mA */
					PSM_Bandsplit_Filter = 0x03;
				} else {
					/* Set PSM bandsplit at nominal */
					PSM_Bandsplit_Filter = 0x02;
				}
			break;
		case 3: /* LPF0 151MHz - LPF1 242MHz - HPF0 494MHz */
				if(priv->pObj->uProgRF < 151000000) {
					/* Set PSM bandsplit at -3.9 mA */
					PSM_Bandsplit_Filter = 0x03;
				} else {
					/* Set PSM bandsplit at nominal */
					PSM_Bandsplit_Filter = 0x02;
				}
			break;
	}
	
	if(uPrevPSM_Bandsplit_Filter != PSM_Bandsplit_Filter) {
		/* Write PSM bandsplit */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_PowerSavingMode__PSM_Bandsplit_Filter, PSM_Bandsplit_Filter, Bus_NoRead);
	}
    
	return 0;
}

static int tda18273_set_standardmode(struct dvb_frontend *fe, TDA18273StandardMode_t StandardMode)
{
	struct tda18273_state *priv = fe->tuner_priv;
	int ret;
	
	unsigned char wantedValue=0;
	unsigned char checked=0;
	
	priv->pObj->StandardMode = StandardMode;
	
	if((priv->pObj->StandardMode > TDA18273_StandardMode_Unknown) && (priv->pObj->StandardMode < TDA18273_StandardMode_Max)) {
		/* Update standard map pointer */
		priv->pObj->pStandard = &priv->pObj->Std_Array[priv->pObj->StandardMode - 1];
		
		/****************************************************************/
		/* IF SELECTIVITY Settings                                      */
		/****************************************************************/
		/* Set LPF */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_IF_Byte_1__LP_Fc, priv->pObj->pStandard->LPF, Bus_None);
		/* Set LPF Offset */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_IF_Byte_1__LP_FC_Offset, priv->pObj->pStandard->LPF_Offset, Bus_None);
		/* Set DC_Notch_IF_PPF */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_IR_Mixer_byte_2__IF_Notch, priv->pObj->pStandard->DC_Notch_IF_PPF, Bus_None);
		/* Enable/disable HPF */
		if(priv->pObj->pStandard->IF_HPF == TDA18273_IF_HPF_Disabled) {
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_IR_Mixer_byte_2__Hi_Pass, 0x00, Bus_None);
		} else {
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_IR_Mixer_byte_2__Hi_Pass, 0x01, Bus_None);
		    /* Set IF HPF */
		    ret = tda18273_writeregs(priv, &gTDA18273_Reg_IF_Byte_1__IF_HP_Fc, (UInt8)(priv->pObj->pStandard->IF_HPF - 1), Bus_None);
		}
		/* Set IF Notch */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_IF_Byte_1__IF_ATSC_Notch, priv->pObj->pStandard->IF_Notch, Bus_None);
		/* Set IF notch to RSSI */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_IF_AGC_byte__IFnotchToRSSI, priv->pObj->pStandard->IFnotchToRSSI, Bus_None);
				
		/****************************************************************/
		/* AGC TOP Settings                                             */
		/****************************************************************/
		/* Set AGC1 TOP I2C DN/UP */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC1_byte_1__AGC1_TOP, priv->pObj->pStandard->AGC1_TOP_I2C_DN_UP, Bus_None);
		/* Set AGC1 Adapt TOP DN/UP */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC1_byte_2__AGC1_Top_Mode_Val, priv->pObj->pStandard->AGC1_Adapt_TOP_DN_UP, Bus_None);
		/* Set AGC1 DN Time Constant */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC1_byte_3__AGC1_Do_step, priv->pObj->pStandard->AGC1_DN_Time_Constant, Bus_None);
		/* Set AGC1 mode */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC1_byte_2__AGC1_Top_Mode, priv->pObj->pStandard->AGC1_Mode, Bus_None);
		/* Set Range_LNA_Adapt */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Adapt_Top_byte__Range_LNA_Adapt, priv->pObj->pStandard->Range_LNA_Adapt, Bus_None);
		/* Set LNA_Adapt_RFAGC_Gv_Threshold */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Adapt_Top_byte__Index_K_LNA_Adapt, priv->pObj->pStandard->LNA_Adapt_RFAGC_Gv_Threshold, Bus_None);
		/* Set AGC1_Top_Adapt_RFAGC_Gv_Threshold */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Adapt_Top_byte__Index_K_Top_Adapt, priv->pObj->pStandard->AGC1_Top_Adapt_RFAGC_Gv_Threshold, Bus_None);
		/* Set AGC2 TOP DN/UP */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC2_byte_1__AGC2_TOP, priv->pObj->pStandard->AGC2_TOP_DN_UP, Bus_None);
		/* Set AGC2 DN Time Constant */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Filters_byte_3__AGC2_Do_step, priv->pObj->pStandard->AGC2_DN_Time_Constant, Bus_None);
		/* Set AGC4 TOP DN/UP */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_IR_Mixer_byte_1__IR_Mixer_Top, priv->pObj->pStandard->AGC4_TOP_DN_UP, Bus_None);
		/* Set AGC5 TOP DN/UP */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC5_byte_1__AGC5_TOP, priv->pObj->pStandard->AGC5_TOP_DN_UP, Bus_None);
		/* Set AGC3_Top_Adapt_Algorithm */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_AGC_byte__PD_AGC_Adapt3x, priv->pObj->pStandard->AGC3_Top_Adapt_Algorithm, Bus_None);
		/* Set AGC Overload TOP */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Vsync_Mgt_byte__AGC_Ovld_TOP, priv->pObj->pStandard->AGC_Overload_TOP, Bus_None);
		/* Set Adapt TOP 34 Gain Threshold */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_RFAGCs_Gain_byte_1__TH_AGC_Adapt34, priv->pObj->pStandard->TH_AGC_Adapt34, Bus_None);
		/* Set RF atten 3dB */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_W_Filter_byte__RF_Atten_3dB, priv->pObj->pStandard->RF_Atten_3dB, Bus_None);
		/* Set IF Output Level */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_IF_AGC_byte__IF_level, priv->pObj->pStandard->IF_Output_Level, Bus_None);
		/* Set S2D gain */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_IR_Mixer_byte_1__S2D_Gain, priv->pObj->pStandard->S2D_Gain, Bus_None);
		/* Set Negative modulation, write into register directly because vsync_int bit is checked afterwards */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Vsync_byte__Neg_modulation, priv->pObj->pStandard->Negative_Modulation, Bus_RW);
		
		/****************************************************************/
		/* GSK Settings                                                 */
		/****************************************************************/
		/* Set AGCK Step */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGCK_byte_1__AGCK_Step, priv->pObj->pStandard->AGCK_Steps, Bus_None);
		/* Set AGCK Time Constant */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGCK_byte_1__AGCK_Mode, priv->pObj->pStandard->AGCK_Time_Constant, Bus_None);
		/* Set AGC5 HPF */
		wantedValue = priv->pObj->pStandard->AGC5_HPF;
		if(priv->pObj->pStandard->AGC5_HPF == TDA18273_AGC5_HPF_Enabled) {
			/* Check if Internal Vsync is selected */
			ret = tda18273_readregs(priv, &gTDA18273_Reg_Vsync_byte__Vsync_int, &checked, Bus_RW);

			if(checked == 0) {
				/* Internal Vsync is OFF, so override setting to OFF */
				wantedValue = TDA18273_AGC5_HPF_Disabled;
			}
		}
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGC5_byte_1__AGC5_Ana, wantedValue, Bus_None);
		/* Set Pulse Shaper Disable */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_AGCK_byte_1__Pulse_Shaper_Disable, priv->pObj->pStandard->Pulse_Shaper_Disable, Bus_None);

		/****************************************************************/
		/* H3H5 Settings                                                */
		/****************************************************************/
		/* Set VHF_III_Mode */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_W_Filter_byte__VHF_III_mode, priv->pObj->pStandard->VHF_III_Mode, Bus_None);
		
		/****************************************************************/
		/* PLL Settings                                                 */
		/****************************************************************/
		/* Set LO_CP_Current */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_CP_Current_byte__LO_CP_Current, priv->pObj->pStandard->LO_CP_Current, Bus_None);
		
		/****************************************************************/
		/* IF Settings                                                  */
		/****************************************************************/
		/* Set IF */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_IF_Frequency_byte__IF_Freq, (UInt8)((priv->pObj->pStandard->IF - priv->pObj->pStandard->CF_Offset)/50000), Bus_None);

		/****************************************************************/
		/* MISC Settings                                                */
		/****************************************************************/
		/* Set PD Underload */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Misc_byte__PD_Underload, priv->pObj->pStandard->PD_Underload, Bus_None);

		/****************************************************************/
		/* Update Registers                                             */
		/****************************************************************/
		/* Write AGC1_byte_1 (0x0C) to IF_Byte_1 (0x15) Registers */
		ret = tda18273_writeregmap(priv, gTDA18273_Reg_AGC1_byte_1.Address, TDA18273_REG_DATA_LEN(gTDA18273_Reg_AGC1_byte_1, gTDA18273_Reg_IF_Byte_1));
		/* Write IF_Frequency_byte (0x17) Register */
		ret = tda18273_writeregmap(priv, gTDA18273_Reg_IF_Frequency_byte.Address, 1);
		/* Write Adapt_Top_byte (0x1F) Register */
		ret = tda18273_writeregmap(priv, gTDA18273_Reg_Adapt_Top_byte.Address, 1);
		/* Write Vsync_byte (0x20) to RFAGCs_Gain_byte_1 (0x24) Registers */
		ret = tda18273_writeregmap(priv, gTDA18273_Reg_Vsync_byte.Address, TDA18273_REG_DATA_LEN(gTDA18273_Reg_Vsync_byte, gTDA18273_Reg_RFAGCs_Gain_byte_1));
		/* Write RF_Filters_byte_3 (0x2D) Register */
		ret = tda18273_writeregmap(priv, gTDA18273_Reg_RF_Filters_byte_3.Address, 1);
		/* Write CP_Current_byte (0x2F) Register */
		ret = tda18273_writeregmap(priv, gTDA18273_Reg_CP_Current_byte.Address, 1);
		/* Write Misc_byte (0x38) Register */
		ret = tda18273_writeregmap(priv, gTDA18273_Reg_Misc_byte.Address, 1);
	}
	
	return 0;
}

typedef struct _TDA18273_PostDivPrescalerTableDef_
{
    unsigned int LO_max;
    unsigned int LO_min;
    unsigned char Prescaler;
    unsigned char PostDiv;
} TDA18273_PostDivPrescalerTableDef;

/* Table that maps LO vs Prescaler & PostDiv values */
static TDA18273_PostDivPrescalerTableDef PostDivPrescalerTable[35] =
{
    /* PostDiv 1 */
    {974000, 852250, 7, 1},
    {852250, 745719, 8, 1},
    {757556, 662861, 9, 1},
    {681800, 596575, 10, 1},
    {619818, 542341, 11, 1},
    {568167, 497146, 12, 1},
    {524462, 458904, 13, 1},
    /* PostDiv 2 */
    {487000, 426125, 7, 2},
    {426125, 372859, 8, 2},
    {378778, 331431, 9, 2},
    {340900, 298288, 10, 2},
    {309909, 271170, 11, 2},
    {284083, 248573, 12, 2},
    {262231, 229452, 13, 2},
    /* PostDiv 4 */
    {243500, 213063, 7, 4},
    {213063, 186430, 8, 4},
    {189389, 165715, 9, 4},
    {170450, 149144, 10, 4},
    {154955, 135585, 11, 4},
    {142042, 124286, 12, 4},
    {131115, 114726, 13, 4},
    /* PostDiv 8 */
    {121750, 106531, 7, 8},
    {106531, 93215, 8, 8},
    {94694, 82858, 9, 8},
    {85225, 74572, 10, 8},
    {77477, 67793, 11, 8},
    {71021, 62143, 12, 8},
    {65558, 57363, 13, 8},
    /* PostDiv 16 */
    {60875, 53266, 7, 16},
    {53266, 46607, 8, 16},
    {47347, 41429, 9, 16},
    {42613, 37286, 10, 16},
    {38739, 33896, 11, 16},
    {35510, 31072, 12, 16},
    {32779, 28681, 13, 16}
};

static int tda18273_calculate_postdivandprescaler(unsigned int LO, int growingOrder, unsigned char* PostDiv, unsigned char* Prescaler)
{
	int ret = 0;
	
	unsigned char index;
    unsigned char sizeTable = sizeof(PostDivPrescalerTable) / sizeof(TDA18273_PostDivPrescalerTableDef);

    if(growingOrder == 1) {
        /* Start from LO = 28.681 kHz */
        for(index=(sizeTable-1); index>=0; index--) {
            if((LO > PostDivPrescalerTable[index].LO_min) && (LO < PostDivPrescalerTable[index].LO_max)) {
                /* We are at correct index in the table */
                break;
            }
        }
    } else {
        /* Start from LO = 974000 kHz */
        for(index=0; index<sizeTable; index++) {
            if((LO > PostDivPrescalerTable[index].LO_min) && (LO < PostDivPrescalerTable[index].LO_max)) {
                /* We are at correct index in the table */
                break;
            }
        }
    }

    if((index == -1) || (index == sizeTable)) {
        ret = -1;
    } else {
        /* Write Prescaler */
        *Prescaler = PostDivPrescalerTable[index].Prescaler;

        /* Decode PostDiv */
        *PostDiv = PostDivPrescalerTable[index].PostDiv;
    }
	
	return ret;
}

/* Middle of VCO frequency excursion : VCOmin + (VCOmax - VCOmin)/2 in KHz */
#define TDA18273_MIDDLE_FVCO_RANGE ((6818000 - 5965750) / 2 + 5965750)

static int tda18273_find_postdivandprescalerwithbettermargin(unsigned int LO, unsigned char* PostDiv, unsigned char* Prescaler)
{
	int ret;
	
	unsigned char PostDivGrowing;
	unsigned char PrescalerGrowing;
	unsigned char PostDivDecreasing = 0;
	unsigned char PrescalerDecreasing = 0;
	unsigned int  FCVOGrowing = 0;
	unsigned int  DistanceFCVOGrowing = 0;
	unsigned int  FVCODecreasing = 0;
	unsigned int  DistanceFVCODecreasing = 0;
	
	/* Get the 2 possible values for PostDiv & Prescaler to find the one
	which provides the better margin on LO */
	ret = tda18273_calculate_postdivandprescaler(LO, 1, &PostDivGrowing, &PrescalerGrowing);
	if(ret != -1) {
		/* Calculate corresponding FVCO value in kHz */
		FCVOGrowing = LO * PrescalerGrowing * PostDivGrowing;
	}
	
	ret = tda18273_calculate_postdivandprescaler(LO, 0, &PostDivDecreasing, &PrescalerDecreasing);
	if(ret != -1) {
		/* Calculate corresponding FVCO value in kHz */
		FVCODecreasing = LO * PrescalerDecreasing * PostDivDecreasing;
	}

	/* Now take the values that are providing the better margin, the goal is +-2 MHz on LO */
	/* So take the point that is the nearest of (FVCOmax - FVCOmin)/2 = 6391,875 MHz */
	if(FCVOGrowing != 0) {
		if(FCVOGrowing >= TDA18273_MIDDLE_FVCO_RANGE) {
			DistanceFCVOGrowing = FCVOGrowing - TDA18273_MIDDLE_FVCO_RANGE;
		} else {
			DistanceFCVOGrowing = TDA18273_MIDDLE_FVCO_RANGE - FCVOGrowing;
		}
	}
	
	if(FVCODecreasing != 0) {
		if(FVCODecreasing >= TDA18273_MIDDLE_FVCO_RANGE) {
			DistanceFVCODecreasing = FVCODecreasing - TDA18273_MIDDLE_FVCO_RANGE;
		} else {
			DistanceFVCODecreasing = TDA18273_MIDDLE_FVCO_RANGE - FVCODecreasing;
		}
	}
	
	if(FCVOGrowing == 0) {
		if(FVCODecreasing == 0) {
			/* No value at all are found */
			ret = -1;
		} else {
			/* No value in growing mode, so take the decreasing ones */
			*PostDiv = PostDivDecreasing;
			*Prescaler = PrescalerDecreasing;
		}
	} else {
		if(FVCODecreasing == 0) {
			/* No value in decreasing mode, so take the growing ones */
			*PostDiv = PostDivGrowing;
			*Prescaler = PrescalerGrowing;
		} else {
			/* Find the value which are the nearest of the middle of VCO range */
			if(DistanceFCVOGrowing <= DistanceFVCODecreasing) {
				*PostDiv = PostDivGrowing;
				*Prescaler = PrescalerGrowing;
			} else {
				*PostDiv = PostDivDecreasing;
				*Prescaler = PrescalerDecreasing;
			}
		}
	}
	
	return ret;
}

static int tda18273_calculate_nintkint(unsigned int LO, unsigned char PostDiv, unsigned char Prescaler, unsigned int* NInt, unsigned int* KInt)
{
	/* Algorithm that calculates N_K */
    unsigned int FVCO = 0;
    unsigned int N_K_prog = 0;

    /* Algorithm that calculates N, K corrected */
    unsigned int Nprime = 0;
    unsigned int KforceK0_1 = 0;
    unsigned int K2msb = 0;
    unsigned int N0 = 0;
    unsigned int Nm1 = 0;

	/* Calculate N_K_Prog */
	FVCO = LO * Prescaler * PostDiv;
	N_K_prog = (FVCO * 128) / 125;
	
	/* Calculate N & K corrected values */
	Nprime = N_K_prog & 0xFF0000;
	
	/* Force LSB to 1 */
	KforceK0_1 = 2*(((N_K_prog - Nprime) << 7) / 2) + 1;
	
	/* Check MSB bit around 2 */
	K2msb = KforceK0_1 >> 21;
	if(K2msb < 1) {
		N0 = 1;
	} else {
		if (K2msb >= 3) {
			N0 = 1;
		} else {
			N0 = 0;
		}
	}
	
	if(K2msb < 1) {
		Nm1 = 1;
	} else {
		Nm1 = 0;
	}
	
	/* Calculate N */
	*NInt = (2 * ((Nprime >> 16) - Nm1) + N0) - 128;
	
	/* Calculate K */
	if(K2msb < 1) {
		*KInt = KforceK0_1 + (2 << 21);
	} else {
		if (K2msb >= 3) {
			*KInt = KforceK0_1 - (2 << 21);
		} else {
			*KInt = KforceK0_1;
		}
	}
	
	/* Force last 7 bits of K_int to 0x5D, as the IC is doing for spurs optimization */
	*KInt &= 0xFFFFFF80;
	*KInt |= 0x5D;
	
	return 0;
}


static int tda18273_set_pll(struct dvb_frontend *fe)
{
	struct tda18273_state *priv = fe->tuner_priv;
	
	int ret;
	
	/* LO wanted = RF wanted + IF in KHz */
    unsigned int LO = 0;

    /* Algorithm that calculates PostDiv */
    unsigned char PostDiv = 0; /* absolute value */
    unsigned char LOPostDiv = 0; /* register value */

    /* Algorithm that calculates Prescaler */
    unsigned char Prescaler = 0;

    /* Algorithm that calculates N, K */
    unsigned int N_int = 0;
    unsigned int K_int = 0;
    
	/* Calculate wanted LO = RF + IF in Hz */
	LO = (priv->pObj->uRF + priv->pObj->uIF) / 1000;
	
	/* Calculate the best PostDiv and Prescaler : the ones that provide the best margin */
	/* in case of fine tuning +-2 MHz */
	ret = tda18273_find_postdivandprescalerwithbettermargin(LO, &PostDiv, &Prescaler);
	
	if(ret != -1) {
		/* Program the PLL only if valid values are found, in that case err == TM_OK */
		/* Decode PostDiv */
		switch(PostDiv)	{
			case 1:		LOPostDiv = 1;										break;
			case 2:		LOPostDiv = 2;										break;
			case 4:		LOPostDiv = 3;										break;
			case 8:		LOPostDiv = 4;										break;
			case 16:	LOPostDiv = 5;										break;
			default:	dprintk(FE_INFO, 1, "%s *PostDiv value is wrong.", __func__);	break;
		}
		
		/* Affect register map without writing into IC */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Main_Post_Divider_byte__LOPostDiv, LOPostDiv, Bus_None);
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Main_Post_Divider_byte__LOPresc, Prescaler, Bus_None);
		/* Calculate N & K values of the PLL */
		ret = tda18273_calculate_nintkint(LO, PostDiv, Prescaler, &N_int, &K_int);
		/* Affect registers map without writing to IC */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Sigma_delta_byte_4__LO_Frac_0, (UInt8)(K_int & 0xFF), Bus_None);
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Sigma_delta_byte_3__LO_Frac_1, (UInt8)((K_int >> 8) & 0xFF), Bus_None);
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Sigma_delta_byte_2__LO_Frac_2, (UInt8)((K_int >> 16) & 0xFF), Bus_None);
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Sigma_delta_byte_1__LO_Int, (UInt8)(N_int & 0xFF), Bus_None);
		/* Force manual selection mode : 0x3 at @0x56 */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Sigma_delta_byte_5__N_K_correct_manual, 0x01, Bus_None);
		/* Force manual selection mode : 0x3 at @0x56 */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Sigma_delta_byte_5__LO_Calc_Disable, 0x01, Bus_None);
		/* Write bytes Main_Post_Divider_byte (0x51) to Sigma_delta_byte_5 (0x56) */
		ret = tda18273_writeregmap(priv, gTDA18273_Reg_Main_Post_Divider_byte.Address, TDA18273_REG_DATA_LEN(gTDA18273_Reg_Main_Post_Divider_byte, gTDA18273_Reg_Sigma_delta_byte_5));
	}
		
	return 0;
}

static int tda18273_override_icp(struct dvb_frontend *fe, unsigned int uRF)
{
	struct tda18273_state *priv = fe->tuner_priv;
	
	int ret;
	unsigned int	uIF = 0;
    unsigned char	ProgIF = 0;
    unsigned char	LOPostdiv = 0;
    unsigned char	LOPrescaler = 0;
    unsigned int	FVCO = 0;
    unsigned char	uICPBypass = 0;
    unsigned char	ICP = 0;
    unsigned char	uPrevICP = 0;
    
	/* Read PostDiv et Prescaler */
	ret = tda18273_readregs(priv, &gTDA18273_Reg_Main_Post_Divider_byte, &LOPostdiv, Bus_RW);
	/* PostDiv */
	ret = tda18273_readregs(priv, &gTDA18273_Reg_Main_Post_Divider_byte__LOPostDiv, &LOPostdiv, Bus_NoRead);
	/* Prescaler */
	ret = tda18273_readregs(priv, &gTDA18273_Reg_Main_Post_Divider_byte__LOPresc, &LOPrescaler, Bus_NoRead);
	/* IF */
	ret = tda18273_readregs(priv, &gTDA18273_Reg_IF_Frequency_byte__IF_Freq, &ProgIF, Bus_NoRead);
	/* Decode IF */
	uIF = ProgIF*50000;
	/* Decode PostDiv */
	switch(LOPostdiv) {
		case 1:		LOPostdiv = 1;		break;
		case 2:		LOPostdiv = 2;		break;
		case 3:		LOPostdiv = 4;		break;
		case 4:		LOPostdiv = 8;		break;
		case 5:		LOPostdiv = 16;		break;
		default:	ret = -1;			break;
	}
	
	if(ret != -1) {
		/* Calculate FVCO in MHz*/
		FVCO = LOPostdiv * LOPrescaler * ((uRF + uIF) / 1000000);
		/* Set correct ICP */
		if(FVCO < 6352) {
			/* Set ICP to 01 (= 150)*/
			ICP = 0x01;
		} else if(FVCO < 6592) {
			/* Set ICP to 10 (= 300)*/
			ICP = 0x02;
		} else {
			/* Set ICP to 00 (= 500)*/
			ICP = 0x00;
		}
		/* Get ICP_bypass bit */
		ret = tda18273_readregs(priv, &gTDA18273_Reg_Charge_pump_byte__ICP_Bypass, &uICPBypass, Bus_RW);
		/* Get ICP */
		ret = tda18273_readregs(priv, &gTDA18273_Reg_Charge_pump_byte__ICP, &uPrevICP, Bus_NoRead);

		if(uICPBypass == 0x0 || uPrevICP != ICP) {
			/* Set ICP_bypass bit */
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_Charge_pump_byte__ICP_Bypass, 0x01, Bus_None);
			/* Set ICP */
			ret = tda18273_writeregs(priv, &gTDA18273_Reg_Charge_pump_byte__ICP, ICP, Bus_None);
			/* Write Charge_pump_byte register */
			ret = tda18273_writeregmap(priv, gTDA18273_Reg_Charge_pump_byte.Address, 1);
		}
	}
    
	return ret;
}

static int tda18273_override_digitalclock(struct dvb_frontend *fe, unsigned int uRF)
{
	struct tda18273_state *priv = fe->tuner_priv;
	
	int ret;
	unsigned char uDigClock = 0;
    unsigned char uPrevDigClock = 0;
    unsigned char uProgIF = 0;
    
	/* LO < 55 MHz then Digital Clock set to 16 MHz else subLO */
	/* Read Current IF */
	ret = tda18273_readregs(priv, &gTDA18273_Reg_IF_Frequency_byte__IF_Freq, &uProgIF, Bus_NoWrite);
	/* Read Current Digital Clock */
	ret = tda18273_readregs(priv, &gTDA18273_Reg_Reference_Byte__Digital_Clock_Mode, &uPrevDigClock, Bus_NoWrite);
	/* LO = RF + IF */
	if((uRF + (uProgIF*50000)) < 55000000) {
		uDigClock = 0; /* '00' = 16 MHz */
	} else {
		uDigClock = 3; /* '11' = subLO */
	}
	
	if(uPrevDigClock != uDigClock) {
		/* Set Digital Clock bits */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_Reference_Byte__Digital_Clock_Mode, uDigClock, Bus_NoRead);
	}
    
    return 0;
}

static int tda18273_set_rffreq(struct dvb_frontend *fe)
{
	struct tda18273_state *priv = fe->tuner_priv;
	
	int ret;
	unsigned int uRF=priv->pObj->uProgRF;
	unsigned int uRFLocal=0;
	
	/* Set the proper settings depending on the standard & RF frequency */
	/****************************************************************/
	/* AGC TOP Settings                                             */
	/****************************************************************/
	/* Set AGC3 RF AGC Top */
	if(uRF < priv->pObj->pStandard->Freq_Start_LTE) {
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_AGC_byte__RFAGC_Top, priv->pObj->pStandard->AGC3_TOP_I2C_Low_Band, Bus_RW);
	} else {
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_AGC_byte__RFAGC_Top, priv->pObj->pStandard->AGC3_TOP_I2C_High_Band, Bus_RW);
	}
	/* Set AGC3 Adapt TOP */
	if(uRF < priv->pObj->pStandard->Freq_Start_LTE) {
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_AGC_byte__RFAGC_Adapt_TOP, priv->pObj->pStandard->AGC3_Adapt_TOP_Low_Band, Bus_NoRead);
	} else {
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_AGC_byte__RFAGC_Adapt_TOP, priv->pObj->pStandard->AGC3_Adapt_TOP_High_Band, Bus_NoRead);
	}
	/* Set IRQ_clear */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_IRQ_clear, TDA18273_IRQ_Global|TDA18273_IRQ_SetRF, Bus_NoRead);
	/* Set RF */
	uRFLocal = (uRF + 500) / 1000;
	
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Frequency_byte_1__RF_Freq_1, (unsigned char)((uRFLocal & 0x00FF0000) >> 16), Bus_None);
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Frequency_byte_2__RF_Freq_2, (unsigned char)((uRFLocal & 0x0000FF00) >> 8), Bus_None);
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Frequency_byte_3__RF_Freq_3, (unsigned char)(uRFLocal & 0x000000FF), Bus_None);
	ret = tda18273_writeregmap(priv, gTDA18273_Reg_RF_Frequency_byte_1.Address, TDA18273_REG_DATA_LEN(gTDA18273_Reg_RF_Frequency_byte_1, gTDA18273_Reg_RF_Frequency_byte_3));
	/* Set state machine and Launch it */
	ret = tda18273_set_msm(fe, TDA18273_MSM_SetRF, 0x1);
	/* Wait for IRQ to trigger */
	//ret = iTDA18273_WaitIRQ(pObj, 50, 5, TDA18273_IRQ_SetRF);
	mdelay(50);
	
	/* Override the calculated PLL to get the best margin in case fine tuning is used */
	/* which means set the PLL in manual mode that provides the best occurence of LO tuning (+-2 MHz) */
	/* without touching PostDiv and Prescaler */
	ret = tda18273_set_pll(fe);
	/* Override ICP */
	ret = tda18273_override_icp(fe, priv->pObj->uProgRF);
	/* Override Digital Clock */
	if(ret != -1) {
		ret = tda18273_override_digitalclock(fe, priv->pObj->uProgRF);
	}

	return 0;
}

static int tda18273_set_rf(struct dvb_frontend *fe, unsigned int uRF)
{
	struct tda18273_state *priv = fe->tuner_priv;

	priv->pObj->uRF = uRF;
	priv->pObj->uProgRF = priv->pObj->uRF + priv->pObj->pStandard->CF_Offset;

	tda18273_llpwr_state(fe, TDA18273_PowerNormalMode);
	tda18273_lastpass_lnapwr(fe);
	tda18273_check_calcpll(fe);
	tda18273_override_bandsplit(fe);
	tda18273_set_rffreq(fe);
	
	return 0;
}

static int tda18273_hw_reset(struct dvb_frontend *fe)
{
	struct tda18273_state *priv = fe->tuner_priv;
	int ret;
	
	tda18273_pwr_state(fe, tmPowerStandby);
	tda18273_llpwr_state(fe, TDA18273_PowerNormalMode);
	
	/* Set digital clock mode to 16 Mhz before resetting the IC to avoid unclocking the digital part */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_Reference_Byte__Digital_Clock_Mode, 0x00, Bus_RW);
	/* Perform a SW reset to reset the digital calibrations & the IC machine state */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_Down_byte_3, 0x03, Bus_RW);
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_Power_Down_byte_3, 0x00, Bus_NoRead);
	/* Set power state on */
	//ret = tda18273_llpwr_state(fe, TDA18273_PowerNormalMode);

#if 0	
	/* Only if tuner has a XTAL */
	if(1) {		//if (priv->bBufferMode == False)
		/* Reset XTALCAL_End bit */
		/* Set IRQ_clear */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_IRQ_clear, TDA18273_IRQ_Global|TDA18273_IRQ_XtalCal|TDA18273_IRQ_HwInit|TDA18273_IRQ_IrCal, Bus_NoRead);
		/* Launch XTALCAL */
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_MSM_byte_2__XtalCal_Launch, 0x01, Bus_NoRead);
		ret = tda18273_writeregs(priv, &gTDA18273_Reg_MSM_byte_2__XtalCal_Launch, 0x00, Bus_None);
		/* Wait XTALCAL_End bit */
		//ret = iTDA18273_WaitXtalCal_End(priv, 100, 10);
	}
#endif

	/* Read all bytes */
	ret = tda18273_readregmap(priv, 0x00, TDA18273_REG_MAP_NB_BYTES);
	/* Check if Calc_PLL algorithm is in automatic mode */
	ret = tda18273_check_calcpll(fe);
	/* Up_Step_Ovld: POR = 1 -> 0 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_Vsync_Mgt_byte__Up_Step_Ovld, 0x00, Bus_NoRead);
	/* PLD_CC_Enable: POR = 1 -> 0 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RFAGCs_Gain_byte_1__PLD_CC_Enable, 0x00, Bus_NoRead);
	/* RFCAL_Offset0 : 0 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Cal_byte_1__RFCAL_Offset_Cprog0, 0x00, Bus_None);
	/* RFCAL_Offset1 : 0 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Cal_byte_1__RFCAL_Offset_Cprog1, 0x00, Bus_None);
	/* RFCAL_Offset2 : 0 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Cal_byte_1__RFCAL_Offset_Cprog2, 0x00, Bus_None);
	/* RFCAL_Offset3 : 0 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Cal_byte_1__RFCAL_Offset_Cprog3, 0x00, Bus_None);
	/* RFCAL_Offset4 : 3 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Cal_byte_2__RFCAL_Offset_Cprog4, 0x03, Bus_None);
	/* RFCAL_Offset5 : 0 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Cal_byte_2__RFCAL_Offset_Cprog5, 0x00, Bus_None);
	/* RFCAL_Offset6 : 3 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Cal_byte_2__RFCAL_Offset_Cprog6, 0x03, Bus_None);
	/* RFCAL_Offset7 : 3 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Cal_byte_2__RFCAL_Offset_Cprog7, 0x03, Bus_None);
	/* RFCAL_Offset8 : 1 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RF_Cal_byte_3__RFCAL_Offset_Cprog8, 0x01, Bus_None);
	/* Write RF_Cal_byte_1 (0x27) to RF_Cal_byte_3 (0x29) Registers */
	ret = tda18273_writeregmap(priv, gTDA18273_Reg_RF_Cal_byte_1.Address, TDA18273_REG_DATA_LEN(gTDA18273_Reg_RF_Cal_byte_1, gTDA18273_Reg_RF_Cal_byte_3));
	/* PLD_Temp_Enable: POR = 1 -> 0 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_RFAGCs_Gain_byte_1__PLD_Temp_Enable, 0x00, Bus_NoRead);
	/* Power Down Vsync Management: POR = 0 -> 1 */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_Vsync_Mgt_byte__PD_Vsync_Mgt, 0x01, Bus_NoRead);
	/* Set IRQ_clear */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_IRQ_clear, TDA18273_IRQ_Global|TDA18273_IRQ_HwInit|TDA18273_IRQ_IrCal, Bus_NoRead);
	/* Set state machine (all CALs except IRCAL) and Launch it */
	ret = tda18273_set_msm(fe, TDA18273_MSM_HwInit, 0x1);
	/* Inform that init phase has started */
	/* State reached after 500 ms max */
	//ret = iTDA18273_WaitIRQ(priv, 500, 10, TDA18273_IRQ_HwInit);
	mdelay(500);
	/* Set IRQ_clear */
	ret = tda18273_writeregs(priv, &gTDA18273_Reg_IRQ_clear, TDA18273_IRQ_Global|TDA18273_IRQ_HwInit|TDA18273_IRQ_IrCal, Bus_NoRead);
	/* Launch IRCALs after all other CALs are finished */
	ret = tda18273_set_msm(fe, TDA18273_MSM_IrCal, 0x1);
	/* State reached after 500 ms max, 10 ms step due to CAL ~ 30ms */
	//ret = iTDA18273_WaitIRQ(priv, 500, 10, TDA18273_IRQ_IrCal);
	mdelay(500);

	tda18273_llpwr_state(fe, TDA18273_PowerStandbyWithXtalOn);

	return 0;
}

static int tda18273_hw_init(struct dvb_frontend *fe)
{
	tda18273_pwr_state(fe, tmPowerOn);
	
	tda18273_hw_reset(fe);

	return 0;
}

static int tda18273_init(struct dvb_frontend *fe)
{
	struct tda18273_state *priv = fe->tuner_priv;
	int ret;
	unsigned char val=0;
	unsigned short id=0;
	unsigned char major;
	unsigned char minor;
	
	ret = tda18273_readregs(priv, &gTDA18273_Reg_ID_byte_1__Ident_1, &val, Bus_RW);
	id = val << 8;
	ret = tda18273_readregs(priv, &gTDA18273_Reg_ID_byte_2__Ident_2, &val, Bus_RW);
	id |= val;
	
	if(ret == TDA_RESULT_SUCCESS) {
		if(id == TDA_DEVICE_TYPE) {
			ret = tda18273_readregs(priv, &gTDA18273_Reg_ID_byte_3__Major_rev, &major, Bus_RW);
			ret = tda18273_readregs(priv, &gTDA18273_Reg_ID_byte_3__Minor_rev, &minor, Bus_RW);
			dprintk(FE_INFO, 1, "id:%d / ver:%d.%d", id, major, minor);
		} else {
			return -1;
		}
	} else {
		return -1;
	}
	
	priv->pObj = &gTDA18273Instance;

	tda18273_hw_init(fe);

	return 0;
}

static int tda18273_get_status(struct dvb_frontend *fe, u32 *status)
{
	struct tda18273_state *priv = (struct tda18273_state*)fe->tuner_priv;
	unsigned short lock_status = 0;
	int ret = 0;

	ret = tda18273_get_lock_status(priv, &lock_status);	
	if (ret)
		goto err;
err:
	dprintk(FE_DEBUG, 1, "ret=%d", ret);
	return ret;
}
#if 0
static int tda18273_get_state(struct dvb_frontend *fe, enum tuner_param param, struct tuner_state *state)
{
	struct tda18273_state *priv		= fe->tuner_priv;
	int ret;

	switch (param) {
	case DVBFE_TUNER_FREQUENCY:
		state->frequency = priv->freq_hz;
		ret = 0;
		break;
	case DVBFE_TUNER_TUNERSTEP:
		state->tunerstep = fe->ops.tuner_ops.info.frequency_step;
		ret = 0;
		break;
	case DVBFE_TUNER_IFFREQ:
		state->ifreq = priv->if_freq;
		ret = 0;
		break;
	case DVBFE_TUNER_BANDWIDTH:
		if (fe->ops.info.type == FE_OFDM)
			state->bandwidth = priv->bandwidth;
		ret = 0;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}
#endif
static int tda18273_set_params(struct dvb_frontend *fe)
{
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	struct tda18273_state *priv = fe->tuner_priv;
	u32 delsys = c->delivery_system;
	u32 bw = c->bandwidth_hz;
	u32 freq = c->frequency;
	unsigned short lock = 0;
	int ret;

	BUG_ON(!priv);

	dprintk(FE_DEBUG, 1, "freq=%d, bw=%d", freq, bw);

	switch (delsys) {
	case SYS_ATSC:
		tda18273_set_standardmode(fe, TDA18273_ATSC_6MHz);		
		break;
	case SYS_DVBT:
	case SYS_DVBT2:
		switch (bw) {
		case 1700000:
			tda18273_set_standardmode(fe, TDA18273_DVBT_1_7MHz);
			break;
		case 6000000:
			tda18273_set_standardmode(fe, TDA18273_DVBT_6MHz);
			break;
		case 7000000:
			tda18273_set_standardmode(fe, TDA18273_DVBT_7MHz);
			break;
		case 8000000:
			tda18273_set_standardmode(fe, TDA18273_DVBT_8MHz);
			break;
		case 10000000:
			tda18273_set_standardmode(fe, TDA18273_DVBT_10MHz);
			break;
		default:
			ret = -EINVAL;
			goto err;
		}
		break;
	case SYS_DVBC_ANNEX_A:
	case SYS_DVBC_ANNEX_C:
		tda18273_set_standardmode(fe, TDA18273_QAM_8MHz);		
		break;
	case SYS_DVBC_ANNEX_B:
		tda18273_set_standardmode(fe, TDA18273_QAM_6MHz);
		break;
	}

	ret = tda18273_pwr_state(fe, tmPowerOn);	
	if (ret)
		goto err;

	dprintk(FE_DEBUG, 1, "if_freq=%d", priv->pObj->pStandard->IF);

	ret = tda18273_set_rf(fe, freq + priv->pObj->pStandard->IF);
	if (ret)
		goto err;

	msleep(100);
	tda18273_get_lock_status(priv, &lock);

	tda18273_regall_debug(priv);

	dprintk(FE_INFO, 1, "Lock status = %d", lock);
	if (lock) {
		priv->freq_hz = freq;
		priv->if_freq = priv->pObj->pStandard->IF;
		priv->bandwidth = bw;	  
	}
err:
	dprintk(FE_DEBUG, 1, "ret=%d", ret);
	return ret;
}

static int tda18273_get_freq(struct dvb_frontend *fe, u32 *frequency)
{
	struct tda18273_state *priv = fe->tuner_priv;

	*frequency = priv->freq_hz;
	return 0;
}

static int tda18273_get_if_freq(struct dvb_frontend *fe, u32 *frequency)
{
	struct tda18273_state *priv = fe->tuner_priv;

	*frequency = priv->if_freq;
	return 0;
}

static int tda18273_get_bandwidth(struct dvb_frontend *fe, u32 *bandwidth)
{
	struct tda18273_state *priv = fe->tuner_priv;

	*bandwidth = priv->bandwidth;
	return 0;
}

static void tda18273_release(struct dvb_frontend *fe)
{
	struct tda18273_state *priv = fe->tuner_priv;

	BUG_ON(!priv);

	if(priv->power_state != tmPowerOff) {
		tda18273_pwr_state(fe, tmPowerStandby);
	}
	
	fe->tuner_priv = NULL;
	kfree(priv);
}

static struct dvb_tuner_ops tda18273_ops = {
	.info = {
		.name			= "TDA18273 Silicon Tuner",
		.frequency_min_hz	=  42 * MHz,
		.frequency_max_hz	= 870 * MHz,
		.frequency_step_hz	= 5 * kHz,
	},
	.init			= tda18273_init,
//	.sleep			= tda18273_sleep,
	.get_status		= tda18273_get_status,
	.set_params		= tda18273_set_params,
	.get_frequency		= tda18273_get_freq,
	.get_bandwidth		= tda18273_get_bandwidth,
	.get_if_frequency	= tda18273_get_if_freq,
	.release		= tda18273_release
};

struct dvb_frontend *tda18273_attach(struct dvb_frontend *fe,
				     struct i2c_adapter *i2c,
				     const u8 i2c_addr)
{
	struct tda18273_state *tda18273;
	int ret;

	BUG_ON(!i2c);	

	tda18273 = kzalloc(sizeof (struct tda18273_state), GFP_KERNEL);
	if (!tda18273)
		goto err;

	tda18273->i2c		= i2c;
	tda18273->fe		= fe;
	tda18273->i2c_addr	= i2c_addr;
	tda18273->power_state = tmPowerOff;

	fe->tuner_priv		= tda18273;
	fe->ops.tuner_ops	= tda18273_ops;

	ret = tda18273_init(fe);
	 if (ret) {
		dprintk(FE_ERROR, 1, "Error Initializing!");
		goto err;
	}

	dprintk(FE_DEBUG, 1, "Done");
	return tda18273->fe;
err:
	kfree(tda18273);
	return NULL;
}
EXPORT_SYMBOL_GPL(tda18273_attach);

MODULE_AUTHOR("Manu Abraham");
MODULE_DESCRIPTION("TDA18273 Silicon tuner");
MODULE_LICENSE("GPL");
