/*
 * Availink AVL6882 demod driver
 *
 * Copyright (C) 2015 Luis Alves <ljalvs@gmail.com>
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License along
 *    with this program; if not, write to the Free Software Foundation, Inc.,
 *    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <linux/slab.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/bitrev.h>
#include <linux/firmware.h>
#include <media/dvb_frontend.h>
#include "avl6882.h"
#include "avl6882_priv.h"

#define AVL6882_FIRMWARE "dvb-demod-avl6882.fw"

static int avl6882_i2c_rd(struct avl6882_priv *priv, u8 *buf, int len)
{
	int ret;
	struct i2c_msg msg[] = {
		{
			.addr = priv->config->demod_address,
			.flags = 0,
			.len = 3,
			.buf = buf,
		},
		{
			.addr= priv->config->demod_address,
			.flags= I2C_M_RD,
			.len  = len,
			.buf  = buf,
		}
	};

	ret = i2c_transfer(priv->i2c, msg, 2);
	if (ret == 2) {
		ret = 0;
	} else {
		dev_warn(&priv->i2c->dev, "%s: i2c rd failed=%d " \
				"len=%d\n", KBUILD_MODNAME, ret, len);
		ret = -EREMOTEIO;
	}
	return ret;
}

static int avl6882_i2c_wr(struct avl6882_priv *priv, u8 *buf, int len)
{
	int ret;
	struct i2c_msg msg = {
		.addr= priv->config->demod_address,
		.flags = 0,
		.buf = buf,
		.len = len,
	};

	ret = i2c_transfer(priv->i2c, &msg, 1);
	if (ret == 1) {
		ret = 0;
	} else {
		dev_warn(&priv->i2c->dev, "%s: i2c wr failed=%d " \
				"len=%d\n", KBUILD_MODNAME, ret, len);
		ret = -EREMOTEIO;
	}
	return ret;
}
#if 0
static int avl6882_i2c_wrm(struct avl6882_priv *priv, u8 *buf, int len)
{
	int ret;
	struct i2c_msg msg = {
		.addr= priv->config->demod_address,
		.flags = 1, /* ?? */
		.buf = buf,
		.len = len,
	};

	ret = i2c_transfer(priv->i2c, &msg, 1);
	if (ret == 1) {
		ret = 0;
	} else {
		dev_warn(&priv->i2c->dev, "%s: i2c wrm failed=%d " \
				"len=%d\n", KBUILD_MODNAME, ret, len);
		ret = -EREMOTEIO;
	}
	return ret;
}
#endif
/* write 32bit words at addr */
#define MAX_WORDS_WR_LEN	((MAX_I2C_WRITE_SIZE-3) / 4)
static int avl6882_i2c_wr_data(struct avl6882_priv *priv,
				u32 addr, u32 *data, int len)
{
	int ret = 0, this_len;
	u32 buf[MAX_WORDS_WR_LEN + 1], *p;
	u8 *b = ((u8*) buf) + 1, i;


	while (len > 0) {
		p = buf;
		*(p++) = cpu_to_be32(addr);

		this_len = (len > MAX_WORDS_WR_LEN) ? MAX_WORDS_WR_LEN : len;

		for (i = 0; i < this_len; i++)
			*(p++) = cpu_to_be32(*data++);

		ret = avl6882_i2c_wr(priv, b, this_len * 4 + 3);
		if (ret)
			break;

		len -= this_len;
		if (len)
			addr += this_len * 4;

	}
	return ret;
}

static int avl6882_i2c_wr_reg(struct avl6882_priv *priv,
	u32 addr, u32 data, int reg_size)
{
	u8 buf[3 + 4];
	u8 *p = buf;

	*(p++) = (u8) (addr >> 16);
	*(p++) = (u8) (addr >> 8);
	*(p++) = (u8) (addr);

	switch (reg_size) {
	case 4:
		*(p++) = (u8) (data >> 24);
		*(p++) = (u8) (data >> 16);
	case 2:
		*(p++) = (u8) (data >> 8);
	case 1:
	default:
		*(p++) = (u8) (data);
		break;
	}

	return avl6882_i2c_wr(priv, buf, 3 + reg_size);
}

#define AVL6882_WR_REG8(_priv, _addr, _data) \
	avl6882_i2c_wr_reg(_priv, _addr, _data, 1)
#define AVL6882_WR_REG16(_priv, _addr, _data) \
	avl6882_i2c_wr_reg(_priv, _addr, _data, 2)
#define AVL6882_WR_REG32(_priv, _addr, _data) \
	avl6882_i2c_wr_reg(_priv, _addr, _data, 4)

static int avl6882_i2c_rd_reg(struct avl6882_priv *priv,
	u32 addr, u32 *data, int reg_size)
{
	int ret;
	u8 buf[3 + 4];
	u8 *p = buf;

	*(p++) = (u8) (addr >> 16);
	*(p++) = (u8) (addr >> 8);
	*(p++) = (u8) (addr);
	//ret = avl6882_i2c_wr(priv, buf, 3);
	ret = avl6882_i2c_rd(priv, buf, reg_size);

	*data = 0;
	p = buf;

	switch (reg_size) {
	case 4:
		*data |= (u32) (*(p++)) << 24;
		*data |= (u32) (*(p++)) << 16;
	case 2:
		*data |= (u32) (*(p++)) << 8;
	case 1:
	default:
		*data |= (u32) *(p);
		break;
	}
	return ret;
}

#define AVL6882_RD_REG8(_priv, _addr, _data) \
	avl6882_i2c_rd_reg(_priv, _addr, _data, 1)
#define AVL6882_RD_REG16(_priv, _addr, _data) \
	avl6882_i2c_rd_reg(_priv, _addr, _data, 2)
#define AVL6882_RD_REG32(_priv, _addr, _data) \
	avl6882_i2c_rd_reg(_priv, _addr, _data, 4)

inline static int avl6882_gpio_set(struct avl6882_priv *priv, u8 pin, u8 val)
{
	return AVL6882_WR_REG32(priv, AVLREG_GPIO_BASE + pin, val);
}

static int avl6882_setup_pll(struct avl6882_priv *priv)
{
	int ret;

	/* sys_pll */
	ret  = AVL6882_WR_REG32(priv, AVLREG_PLL_sys_pll_divr, 2);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_sys_pll_divf, 99);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_sys_pll_divq, 7);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_sys_pll_range, 1);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_sys_pll_divq2, 11);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_sys_pll_divq3, 13);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_sys_pll_enable2, 0);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_sys_pll_enable3, 0);

	/* mpeg_pll */
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_mpeg_pll_divr, 0);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_mpeg_pll_divf, 35);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_mpeg_pll_divq, 7);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_mpeg_pll_range, 3);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_mpeg_pll_divq2, 11);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_mpeg_pll_divq3, 13);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_mpeg_pll_enable2, 0);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_mpeg_pll_enable3, 0);

	/* adc_pll */
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_adc_pll_divr, 2);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_adc_pll_divf, 99);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_adc_pll_divq, 7);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_adc_pll_range, 1);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_adc_pll_divq2, 11);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_adc_pll_divq3, 13);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_adc_pll_enable2, 1);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_adc_pll_enable3, 1);

	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_RESET, 0);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_RESET, 1);
	msleep(20);

	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_dll_out_phase, 96);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_dll_rd_phase, 0);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_deglitch_mode, 1);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_dll_init, 1);
	ret |= AVL6882_WR_REG32(priv, AVLREG_PLL_dll_init, 0);
	return ret;
}

#define DEMOD_WAIT_RETRIES	(10)
#define DEMOD_WAIT_MS		(20)
static int avl6882_wait_demod(struct avl6882_priv *priv)
{
	u32 cmd = 0;
	int ret, retry = DEMOD_WAIT_RETRIES;

	do {
		ret = AVL6882_RD_REG16(priv, 0x200 + rc_fw_command_saddr_offset, &cmd);
		if ((ret == 0) && (cmd == 0))
			return ret;
		else
			msleep(DEMOD_WAIT_MS);
	} while (--retry);
	ret = -EBUSY;
	return ret;
}

/* TODO remove one of the waits */
static int avl6882_exec_n_wait(struct avl6882_priv *priv, u8 cmd)
{
	int ret;

	ret = avl6882_wait_demod(priv);
	if (ret)
		return ret;
	ret = AVL6882_WR_REG16(priv, 0x200 + rc_fw_command_saddr_offset, (u32) cmd);
	if (ret)
		return ret;
	return avl6882_wait_demod(priv);
}


#define DMA_MAX_TRIES	(20)
static int avl6882_patch_demod(struct avl6882_priv *priv, u32 *patch)
{
	int ret = 0;
	u8 unary_op, binary_op, addr_mode_op;
	u32 cmd, num_cmd_words, next_cmd_idx, num_cond_words, num_rvs;
	u32 condition = 0;
	u32 value = 0;
	u32 operation;
	u32 tmp_top_valid, core_rdy_word;
	u32 exp_crc_val, crc_result;
	u32 data = 0;
	u32 type, ref_addr, ref_size;
	u32 data_section_offset;
	u32 args_addr, src_addr, dest_addr, data_offset, length;
	u32 idx, len, i;
	u32 variable_array[PATCH_VAR_ARRAY_SIZE];

	for(i=0; i < PATCH_VAR_ARRAY_SIZE; i++)
		variable_array[i] = 0;


	printk("PATCHING---------\n");

	//total_patch_len = patch[1];
	//standard = patch[2];
	idx = 3;
	args_addr = patch[idx++];
	data_section_offset = patch[idx++];
	/* reserved length */
	len = patch[idx++];
	idx += len;
	/* script length */
	len = patch[idx++];
	len += idx;

	while (idx < len) {
		num_cmd_words = patch[idx++];
		next_cmd_idx = idx + num_cmd_words - 1;
		num_cond_words = patch[idx++];
		if (num_cond_words == 0) {
			condition = 1;
		} else {
			for (i = 0; i < num_cond_words; i++) {
				operation = patch[idx++];
				value = patch[idx++];
				unary_op = (operation >> 8) & 0xff;
				binary_op = operation & 0xff;
				addr_mode_op = ((operation >> 16) & 0x3);

				if ((addr_mode_op == PATCH_OP_ADDR_MODE_VAR_IDX) &&
				    (binary_op != PATCH_OP_BINARY_STORE)) {
					value = variable_array[value]; //grab variable value
				}

				switch(unary_op) {
				case PATCH_OP_UNARY_LOGICAL_NEGATE:
					value = !value;
					break;
				case PATCH_OP_UNARY_BITWISE_NEGATE:
					value = ~value;
					break;
				default:
					break;
				}
				switch(binary_op) {
				case PATCH_OP_BINARY_LOAD:
					condition = value;
					break;
				case PATCH_OP_BINARY_STORE:
					variable_array[value] = condition;
					break;
				case PATCH_OP_BINARY_AND:
					condition = condition && value;
					break;
				case PATCH_OP_BINARY_OR:
					condition = condition || value;
					break;
				case PATCH_OP_BINARY_BITWISE_AND:
					condition = condition & value;
					break;
				case PATCH_OP_BINARY_BITWISE_OR:
					condition = condition | value;
					break;
				case PATCH_OP_BINARY_EQUALS:
					condition = condition == value;
					break;
				case PATCH_OP_BINARY_NOT_EQUALS:
					condition = condition != value;
					break;
				default:
					break;
				}
			}
		}

		AVL6882_RD_REG32(priv, 0x29A648, &tmp_top_valid);
		AVL6882_RD_REG32(priv, 0x0A0, &core_rdy_word);

		if (condition) {
			cmd = patch[idx++];
			switch(cmd) {
			case PATCH_CMD_PING:
				ret = avl6882_exec_n_wait(priv, AVL_FW_CMD_PING);
				num_rvs = patch[idx++];
				i = patch[idx];
				variable_array[i] = (ret == 0);
				break;
			case PATCH_CMD_VALIDATE_CRC:
				exp_crc_val = patch[idx++];
				src_addr = patch[idx++];
				length = patch[idx++];
				AVL6882_WR_REG32(priv,0x200 + rc_fw_command_args_addr_iaddr_offset, args_addr);
				AVL6882_WR_REG32(priv,args_addr+0, src_addr);
				AVL6882_WR_REG32(priv,args_addr+4, length);
				ret = avl6882_exec_n_wait(priv, AVL_FW_CMD_CALC_CRC);
				AVL6882_RD_REG32(priv,args_addr+8, &crc_result);
				num_rvs = patch[idx++];
				i = patch[idx];
				variable_array[i] = (crc_result == exp_crc_val);
				break;
			case PATCH_CMD_LD_TO_DEVICE:
				length = patch[idx++];
				dest_addr = patch[idx++];
				data_offset = patch[idx++];
				data_offset += data_section_offset;
				ret = avl6882_i2c_wr_data(priv, dest_addr, &patch[data_offset], length);
				num_rvs = patch[idx++];
				break;
			case PATCH_CMD_LD_TO_DEVICE_IMM:
				length = patch[idx++];
				dest_addr = patch[idx++];
				data = patch[idx++];
				ret = avl6882_i2c_wr_reg(priv, dest_addr, data, length);
				num_rvs = patch[idx++];
				break;
			case PATCH_CMD_RD_FROM_DEVICE:
				length = patch[idx++];
				src_addr = patch[idx++];
				num_rvs = patch[idx++];
				ret = avl6882_i2c_rd_reg(priv, src_addr, &data, length);
				i = patch[idx];
				variable_array[i] = data;
				break;
			case PATCH_CMD_DMA:
				dest_addr = patch[idx++];
				length = patch[idx++];
				if (length > 0)
					ret = avl6882_i2c_wr_data(priv, dest_addr, &patch[idx], length * 3);
				AVL6882_WR_REG32(priv,0x200 + rc_fw_command_args_addr_iaddr_offset, dest_addr);
				ret = avl6882_exec_n_wait(priv,AVL_FW_CMD_DMA);
				idx += length * 3;
				num_rvs = patch[idx++];
				break;
			case PATCH_CMD_DECOMPRESS:
				type = patch[idx++];
				src_addr = patch[idx++];
				dest_addr = patch[idx++];
				if(type == PATCH_CMP_TYPE_ZLIB) {
					ref_addr = patch[idx++];
					ref_size = patch[idx++];
				}
				AVL6882_WR_REG32(priv,0x200 + rc_fw_command_args_addr_iaddr_offset, args_addr);
				AVL6882_WR_REG32(priv,args_addr+0, type);
				AVL6882_WR_REG32(priv,args_addr+4, src_addr);
				AVL6882_WR_REG32(priv,args_addr+8, dest_addr);
				if(type == PATCH_CMP_TYPE_ZLIB) {
					AVL6882_WR_REG32(priv,args_addr+12, ref_addr);
					AVL6882_WR_REG32(priv,args_addr+16, ref_size);
				}
				ret = avl6882_exec_n_wait(priv,AVL_FW_CMD_DECOMPRESS);
				num_rvs = patch[idx++];
				break;
			case PATCH_CMD_ASSERT_CPU_RESET:
				ret |= AVL6882_WR_REG32(priv,0x110840, 1);
				num_rvs = patch[idx++];
				break;
			case PATCH_CMD_RELEASE_CPU_RESET:
				AVL6882_WR_REG32(priv, 0x110840, 0);
				num_rvs = patch[idx++];
				break;
			case PATCH_CMD_DMA_HW:
				dest_addr = patch[idx++];
				length = patch[idx++];
				if (length > 0)
					ret = avl6882_i2c_wr_data(priv, dest_addr, &patch[idx], length * 3);
				i = 0;
				do {
					if (i++ > DMA_MAX_TRIES)
						return -ENODEV;
					ret |= AVL6882_RD_REG32(priv, 0x110048, &data);
				} while (!(0x01 & data));

				if (data)
					ret |= AVL6882_WR_REG32(priv, 0x110050, dest_addr);
				idx += length * 3;
				num_rvs = patch[idx++];
				break;
			case PATCH_CMD_SET_COND_IMM:
				data = patch[idx++];
				num_rvs = patch[idx++];
				i = patch[idx];
				variable_array[i] = data;
				break;
			default:
				return -ENODEV;
				break;
			}
			idx += num_rvs;
		} else {
			idx = next_cmd_idx;
			continue;
		}
	}

	return ret;
}

#define DEMOD_WAIT_RETRIES_BOOT	(100)
#define DEMOD_WAIT_MS_BOOT	(20)
static int avl6882_wait_demod_boot(struct avl6882_priv *priv)
{
	int ret, retry = DEMOD_WAIT_RETRIES_BOOT;
	u32 ready_code = 0;
	u32 status = 0;

	do {
		ret = AVL6882_RD_REG32(priv, 0x110840, &status);
		ret |= AVL6882_RD_REG32(priv, rs_core_ready_word_iaddr_offset, &ready_code);
		if ((ret == 0) && (status == 0) && (ready_code == 0x5aa57ff7))
			return ret;
		else
			msleep(DEMOD_WAIT_MS_BOOT);
	} while (--retry);
	ret = -EBUSY;
	return ret;
}


/* firmware loader */
static int avl6882_load_firmware(struct avl6882_priv *priv)
{
	struct avl6882_fw *fw;
	int ret = 0;

	switch (priv->delivery_system) {
	case SYS_DVBC_ANNEX_A:
		fw = &priv->fw[AVL6882_FW_DVBC];
		break;
	case SYS_DVBS:
	case SYS_DVBS2:
		fw = &priv->fw[AVL6882_FW_DVBS];
		break;
	case SYS_DVBT:
	case SYS_DVBT2:
	default:
		fw = &priv->fw[AVL6882_FW_DVBT];
		break;
	}

	ret |= AVL6882_WR_REG32(priv, 0x110010, 1);
	ret |= avl6882_setup_pll(priv);
	if (ret)
		goto err;
	ret |= AVL6882_WR_REG32(priv, 0x0a4 + rs_core_ready_word_iaddr_offset, 0x00000000);
	ret |= AVL6882_WR_REG32(priv, 0x110010, 0);

	/* check patch version - only v1 supported */
	if ((fw->data[0] & 0xff) != 1)
		return -EINVAL;

	ret |= avl6882_patch_demod(priv, fw->data);
	if (ret)
		return ret;
	ret = avl6882_wait_demod_boot(priv);
err:
	return ret;
}



int  ErrorStatMode_Demod( struct avl6882_priv *priv,AVL_ErrorStatConfig stErrorStatConfig )
{
	int r = AVL_EC_OK;
	u64 time_tick_num = 270000 *  stErrorStatConfig.uiTimeThresholdMs;

	r = AVL6882_WR_REG32(priv,0x132050 + esm_mode_offset,(u32) stErrorStatConfig.eErrorStatMode);
	r |= AVL6882_WR_REG32(priv,0x132050 + tick_type_offset,(u32) stErrorStatConfig.eAutoErrorStatType);

	r |= AVL6882_WR_REG32(priv,0x132050 + time_tick_low_offset, (u32) (time_tick_num));
	r |= AVL6882_WR_REG32(priv,0x132050 + time_tick_high_offset, (u32) (time_tick_num >> 32));

	r |= AVL6882_WR_REG32(priv,0x132050 + byte_tick_low_offset, stErrorStatConfig.uiTimeThresholdMs);
	r |= AVL6882_WR_REG32(priv,0x132050 + byte_tick_high_offset, 0);//high 32-bit is not used

	if(stErrorStatConfig.eErrorStatMode == AVL_ERROR_STAT_AUTO)//auto mode
	{
		//reset auto error stat
		r |= AVL6882_WR_REG32(priv,0x132050 + tick_clear_offset,0);
		r |= AVL6882_WR_REG32(priv,0x132050 + tick_clear_offset,1);
		r |= AVL6882_WR_REG32(priv,0x132050 + tick_clear_offset,0);
	}

	return (r);
}


int  ResetPER_Demod(  struct avl6882_priv *priv)
{
	int r = AVL_EC_OK;
	u32 uiTemp = 0;

	r |= AVL6882_RD_REG32(priv,0x132050 + esm_cntrl_offset, &uiTemp);
	uiTemp |= 0x00000001;
	r |= AVL6882_WR_REG32(priv,0x132050 + esm_cntrl_offset, uiTemp);

	r |= AVL6882_RD_REG32(priv,0x132050 + esm_cntrl_offset, &uiTemp);
	uiTemp |= 0x00000008;
	r |= AVL6882_WR_REG32(priv,0x132050 + esm_cntrl_offset, uiTemp);
	uiTemp |= 0x00000001;
	r |= AVL6882_WR_REG32(priv,0x132050 + esm_cntrl_offset, uiTemp);
	uiTemp &= 0xFFFFFFFE;
	r |= AVL6882_WR_REG32(priv,0x132050 + esm_cntrl_offset, uiTemp);

	return r;
}

static int InitErrorStat_Demod( struct avl6882_priv *priv )
{
	int r = AVL_EC_OK;
	AVL_ErrorStatConfig stErrorStatConfig;

	stErrorStatConfig.eErrorStatMode = AVL_ERROR_STAT_AUTO;
	stErrorStatConfig.eAutoErrorStatType = AVL_ERROR_STAT_TIME;
	stErrorStatConfig.uiTimeThresholdMs = 3000;
	stErrorStatConfig.uiNumberThresholdByte = 0;

	r = ErrorStatMode_Demod(priv,stErrorStatConfig);
	r |= ResetPER_Demod(priv);

	return r;
}





static int avl6882_init_diseqc( struct avl6882_priv *priv,AVL_Diseqc_Para *pDiseqcPara)
{
	int r;
	u32 i1 = 0;

	r = AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_srst_offset, 1);

	r |= AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_samp_frac_n_offset, 2000000); 	  //2M=200*10kHz
	r |= AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_samp_frac_d_offset, 166666667);  //uiDDCFrequencyHz  166666667

	r |= AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_tone_frac_n_offset, ((pDiseqcPara->uiToneFrequencyKHz)<<1));
	r |= AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_tone_frac_d_offset, (166666667/1000));//uiDDCFrequencyHz  166666667

	// Initialize the tx_control
	r |= AVL6882_RD_REG32(priv,0x16c000 + hw_diseqc_tx_cntrl_offset, &i1);
	i1 &= 0x00000300;
	i1 |= 0x20; 	//reset tx_fifo
	i1 |= ((u32)(pDiseqcPara->eTXGap) << 6);
	i1 |= ((u32)(pDiseqcPara->eTxWaveForm) << 4);
	i1 |= (1<<3);			//enable tx gap.
	r |= AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_tx_cntrl_offset, i1);
	i1 &= ~(0x20);	//release tx_fifo reset
	r |= AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_tx_cntrl_offset, i1);

	// Initialize the rx_control
	i1 = ((u32)(pDiseqcPara->eRxWaveForm) << 2);
	i1 |= (1<<1);	//active the receiver
	i1 |= (1<<3);	//envelop high when tone present
	r |= AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_rx_cntrl_offset, i1);
	i1 = (u32)(pDiseqcPara->eRxTimeout);
	r |= AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_rx_msg_tim_offset, i1);

	r |= AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_srst_offset, 0);

	return r;
}


static int avl6882_init_dvbs(struct dvb_frontend *fe)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	int ret;
	AVL_Diseqc_Para stDiseqcConfig;

	ret = AVL6882_WR_REG16(priv, 0xe00 + rc_DVBSx_int_mpeg_clk_MHz_saddr_offset,27000);
	ret |= AVL6882_WR_REG16(priv, 0xe00 + rc_DVBSx_int_fec_clk_MHz_saddr_offset,25000);

	ret |= AVL6882_WR_REG16(priv, 0xe00 + rc_DVBSx_int_adc_clk_MHz_saddr_offset,12500);// uiADCFrequencyHz  125000000
	ret |= AVL6882_WR_REG16(priv, 0xe00 + rc_DVBSx_int_dmd_clk_MHz_saddr_offset,166666667/10000); //uiDDCFrequencyHz  166666667

	ret |= AVL6882_WR_REG32(priv, 0xe00 + rc_DVBSx_rfagc_pol_iaddr_offset,AVL_AGC_INVERTED);

	ret |= AVL6882_WR_REG32(priv, 0xe00 + rc_DVBSx_format_iaddr_offset, AVL_OFFBIN);//Offbin
	ret |= AVL6882_WR_REG32(priv, 0xe00 + rc_DVBSx_input_iaddr_offset, AVL_ADC_IN);//ADC in

	ret |= AVL6882_WR_REG16(priv, 0xe00 + rc_DVBSx_IF_Offset_10kHz_saddr_offset,0);

	/* enble agc */
	ret |= avl6882_gpio_set(priv, GPIO_AGC_DVBS, GPIO_AGC_ON);

	stDiseqcConfig.eRxTimeout = AVL_DRT_150ms;
	stDiseqcConfig.eRxWaveForm = AVL_DWM_Normal;
	stDiseqcConfig.uiToneFrequencyKHz = 22;
	stDiseqcConfig.eTXGap = AVL_DTXG_15ms;
	stDiseqcConfig.eTxWaveForm = AVL_DWM_Normal;

	ret |= avl6882_init_diseqc(priv, &stDiseqcConfig);
	return ret;
}


static int avl6882_init_dvbc(struct dvb_frontend *fe)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	int ret;

	ret = AVL6882_WR_REG32(priv, 0x600 + rc_DVBC_dmd_clk_Hz_iaddr_offset, 250000000);
	ret |= AVL6882_WR_REG32(priv, 0x600 + rc_DVBC_fec_clk_Hz_iaddr_offset, 250000000);
	ret |= AVL6882_WR_REG8(priv, 0x600 + rc_DVBC_rfagc_pol_caddr_offset,AVL_AGC_NORMAL);
	ret |= AVL6882_WR_REG32(priv, 0x600 + rc_DVBC_if_freq_Hz_iaddr_offset, 5000000);
	ret |= AVL6882_WR_REG8(priv, 0x600 + rc_DVBC_adc_sel_caddr_offset, (u8) AVL_IF_Q);
	ret |= AVL6882_WR_REG32(priv, 0x600 + rc_DVBC_symbol_rate_Hz_iaddr_offset, 6875000);
	ret |= AVL6882_WR_REG8(priv, 0x600 + rc_DVBC_j83b_mode_caddr_offset, AVL_DVBC_J83A);

	//DDC configuration
	ret |= AVL6882_WR_REG8(priv, 0x600 + rc_DVBC_input_format_caddr_offset, AVL_ADC_IN); //ADC in
	ret |= AVL6882_WR_REG8(priv, 0x600 + rc_DVBC_input_select_caddr_offset, AVL_OFFBIN); //RX_OFFBIN
	ret |= AVL6882_WR_REG8(priv, 0x600 + rc_DVBC_tuner_type_caddr_offset, AVL_DVBC_IF); //IF

	//ADC configuration
	ret |= AVL6882_WR_REG8(priv, 0x600 + rc_DVBC_adc_use_pll_clk_caddr_offset, 0);
	ret |= AVL6882_WR_REG32(priv, 0x600 + rc_DVBC_sample_rate_Hz_iaddr_offset, 30000000);

	/* enable agc */
    	ret |= avl6882_gpio_set(priv, GPIO_AGC_DVBTC, GPIO_AGC_ON);
	return ret;
}


static int avl6882_init_dvbt(struct dvb_frontend *fe)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	int ret;

	ret = AVL6882_WR_REG32(priv, 0xa00 + rc_DVBTx_sample_rate_Hz_iaddr_offset, 30000000);
	ret |= AVL6882_WR_REG32(priv, 0xa00 + rc_DVBTx_mpeg_clk_rate_Hz_iaddr_offset, 270000000);

	/* DDC configuration */
	ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_input_format_caddr_offset, AVL_OFFBIN);
	ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_input_select_caddr_offset, AVL_ADC_IN);
	ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_tuner_type_caddr_offset, AVL_DVBTX_REAL_IF);
	ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_rf_agc_pol_caddr_offset, 0);
	ret |= AVL6882_WR_REG32(priv, 0xa00 + rc_DVBTx_nom_carrier_freq_Hz_iaddr_offset, 5000000);

	/* ADC configuration */
	ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_adc_sel_caddr_offset, (u8)AVL_IF_Q);
	ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_adc_use_pll_clk_caddr_offset, 0);

	/* enable agc */
    	ret |= avl6882_gpio_set(priv, GPIO_AGC_DVBTC, GPIO_AGC_ON);
	return ret;
}


static int avl6882_read_status(struct dvb_frontend *fe, enum fe_status *status)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	int ret;
	u32 reg;

	*status = 0;

	switch (priv->delivery_system) {
	case SYS_DVBC_ANNEX_A:
		ret = AVL6882_RD_REG32(priv,0x400 + rs_DVBC_mode_status_iaddr_offset, &reg);
		if ((reg & 0xff) == 0x15)
			reg = 1;
		else
		  	reg = 0;
		break;
	case SYS_DVBS:
	case SYS_DVBS2:
		ret = AVL6882_RD_REG16(priv, 0xc00 + rs_DVBSx_fec_lock_saddr_offset, &reg);
		break;
	case SYS_DVBT:
	case SYS_DVBT2:
	default:
		ret = AVL6882_RD_REG8(priv, 0x800 + rs_DVBTx_fec_lock_caddr_offset, &reg);
		break;
	}
	if (ret) {
	  	*status = 0;
		return ret;
	}

	if (reg)
		*status = FE_HAS_SIGNAL | FE_HAS_CARRIER |
			FE_HAS_VITERBI | FE_HAS_SYNC | FE_HAS_LOCK;

	return ret;
}


static int avl6882_i2c_gate_ctrl(struct dvb_frontend *fe, int enable)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	int ret;

	dev_dbg(&priv->i2c->dev, "%s: %d\n", __func__, enable);

	if (enable) {
		ret = AVL6882_WR_REG32(priv,0x118000 + tuner_i2c_bit_rpt_cntrl_offset, 0x07);
	} else
		ret = AVL6882_WR_REG32(priv,0x118000 + tuner_i2c_bit_rpt_cntrl_offset, 0x06);

	return ret;
}


static int avl6882_set_dvbs(struct dvb_frontend *fe)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret;

	//printk("[avl6882_set_dvbs] Freq:%d Mhz,sym:%d Khz\n", c->frequency, c->symbol_rate);

	ret = AVL6882_WR_REG16(priv, 0xc00 + rs_DVBSx_fec_lock_saddr_offset, 0);
	ret |= AVL6882_WR_REG16(priv, 0xe00 + rc_DVBSx_decode_mode_saddr_offset, 0x14);
	ret |= AVL6882_WR_REG16(priv, 0xe00 + rc_DVBSx_fec_bypass_coderate_saddr_offset, 0); //DVBS auto lock
	ret |= AVL6882_WR_REG16(priv, 0xe00 + rc_DVBSx_iq_mode_saddr_offset, 1); //enable spectrum auto detection
	ret |= AVL6882_WR_REG16(priv, 0xe00 + rc_DVBSx_decode_mode_saddr_offset, 0x14);
	ret |= AVL6882_WR_REG16(priv, 0xe00 + rc_DVBSx_fec_bypass_coderate_saddr_offset, 0);
	ret |= AVL6882_WR_REG32(priv, 0xe00 + rc_DVBSx_int_sym_rate_MHz_iaddr_offset, c->symbol_rate);
	ret |= avl6882_exec_n_wait(priv,AVL_FW_CMD_ACQUIRE);
	return ret;
}


static int avl6882_set_dvbc(struct dvb_frontend *fe)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret;

	//printk("[avl6882_set_dvbc] Freq:%d Mhz,sym:%d\n", c->frequency, c->symbol_rate);

	ret = AVL6882_WR_REG32(priv, 0x600 + rc_DVBC_qam_mode_scan_control_iaddr_offset, 0x0101);
	ret |= AVL6882_WR_REG32(priv, 0x600 + rc_DVBC_symbol_rate_Hz_iaddr_offset, c->symbol_rate);
	ret |= avl6882_exec_n_wait(priv, AVL_FW_CMD_ACQUIRE);
	return ret;
}


static int avl6882_set_dvbt(struct dvb_frontend *fe)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	u32 bw_fft;
	int ret;

	//printk("[avl6882_set_dvbtx] Freq:%d bw:%d\n", c->frequency, c->bandwidth_hz);

	/* set bandwidth */
	if(c->bandwidth_hz <= 1700000) {
		bw_fft = 1845070;
	} else if(c->bandwidth_hz <= 5000000) {
		bw_fft = 5714285;
	} else if(c->bandwidth_hz <= 6000000) {
		bw_fft = 6857143;
	} else if(c->bandwidth_hz <= 7000000) {
		bw_fft = 8000000;
	} else { // if(c->bandwidth_hz <= 8000) {
		bw_fft = 9142857;
	}
    	ret = AVL6882_WR_REG32(priv, 0xa00 + rc_DVBTx_fund_rate_Hz_iaddr_offset, bw_fft);
	ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_l1_proc_only_caddr_offset, 0);

	/* spectrum inversion */
	ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_spectrum_invert_caddr_offset, AVL_SPECTRUM_AUTO);

	switch (c->delivery_system) {
	case SYS_DVBT:
		ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_acquire_mode_caddr_offset, (u8) AVL_DVBTx_LockMode_T_ONLY);
		ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_dvbt_layer_select_caddr_offset, 0);
		ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_data_PLP_ID_caddr_offset, 0);
		ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_common_PLP_ID_caddr_offset, 0);
		ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_common_PLP_present_caddr_offset, 0);
		break;
	case SYS_DVBT2:
	default:
		ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_acquire_mode_caddr_offset, AVL_DVBTx_LockMode_ALL);
		ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_data_PLP_ID_caddr_offset, c->stream_id);
		ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_common_PLP_ID_caddr_offset, 0);
		ret |= AVL6882_WR_REG8(priv, 0xa00 + rc_DVBTx_common_PLP_present_caddr_offset, 2);
		break;
	}
	ret |= avl6882_exec_n_wait(priv, AVL_FW_CMD_ACQUIRE);
	return ret;
}

static int avl6882_read_ucblocks(struct dvb_frontend *fe, u32 *ucblocks)
{
	//printk("%s()\n", __func__);
	*ucblocks = 0x00;
	return 0;
}

static void avl6882_release(struct dvb_frontend *fe)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	int i;
	//printk("%s()\n", __func__);
	for (i = 0; i < AVL6882_FW_COUNT; i++)
		kfree(priv->fw[i].data);
	kfree(priv);
}

static int avl6882_read_ber(struct dvb_frontend *fe, u32 *ber)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret = 0;
	u32 tmp;

	switch (c->delivery_system) {
	case SYS_DVBT:
	case SYS_DVBT2:
	default:
		ret = AVL6882_RD_REG16(priv,
			0x800 + rs_DVBTx_post_viterbi_BER_estimate_x10M_iaddr_offset,
			&tmp);
		break;
	case SYS_DVBS:
	case SYS_DVBS2:
		ret = AVL6882_RD_REG16(priv,
			0xc00 + rs_DVBSx_post_viterbi_BER_estimate_x10M_iaddr_offset,
			&tmp);
		break;
	case SYS_DVBC_ANNEX_A:
		ret = AVL6882_RD_REG16(priv,
			0x400 + rs_DVBC_post_viterbi_BER_estimate_x10M_iaddr_offset,
			&tmp);
		break;
	}

	*ber = tmp;
	return ret;
}

static int avl6882_burst(struct dvb_frontend *fe, enum fe_sec_mini_cmd burst)
{
	//printk("%s()\n", __func__);
	return 0;
}

static int avl6882_set_tone(struct dvb_frontend* fe, enum fe_sec_tone_mode tone)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	int ret;
	u32 reg;

	ret = AVL6882_RD_REG32(priv, 0x16c000 + hw_diseqc_tx_cntrl_offset, &reg);
	if (ret)
		return ret;

	switch(tone) {
	case SEC_TONE_ON:
		reg &= 0xfffffff8;
		reg |= 0x3;	// continuous mode
		reg |= (1<<10);	// on
		break;
	case SEC_TONE_OFF:
		reg &= 0xfffff3ff;
		break;
	default:
		return -EINVAL;
	}
	return AVL6882_WR_REG32(priv,0x16c000 + hw_diseqc_tx_cntrl_offset, reg);
}

static int avl6882_set_voltage(struct dvb_frontend* fe, enum fe_sec_voltage voltage)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	u32 pwr, vol;
	int ret;

	switch (voltage) {
	case SEC_VOLTAGE_OFF:
		pwr = GPIO_1;
		vol = GPIO_0;
		break;
	case SEC_VOLTAGE_13:
		pwr = GPIO_0;
		vol = GPIO_0;
		break;
	case SEC_VOLTAGE_18:
		pwr = GPIO_0;
		vol = GPIO_Z;
		break;
	default:
		return -EINVAL;
	}
    	ret  = avl6882_gpio_set(priv, GPIO_LNB_PWR, pwr);
    	ret |= avl6882_gpio_set(priv, GPIO_LNB_VOLT, vol);
	return ret;
}

/* diseqc master command */
static int avl6882_diseqc_send_master_cmd(struct dvb_frontend *fe,
	struct dvb_diseqc_master_cmd *d)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	u8 tx_done, tx_remain, continuous_flag = 0;
	int i, ret, timeout = 0;
	u32 reg, tmp;

	if (d->msg_len > 8)
		return -EINVAL;

	// reset rx_fifo
	ret = AVL6882_RD_REG32(priv, 0x16c000 + hw_diseqc_rx_cntrl_offset, &tmp);
	ret |= AVL6882_WR_REG32(priv, 0x16c000 + hw_diseqc_rx_cntrl_offset, tmp | 1);
	ret |= AVL6882_WR_REG32(priv, 0x16c000 + hw_diseqc_rx_cntrl_offset, tmp & ~1);

	ret = AVL6882_RD_REG32(priv,0x16c000 + hw_diseqc_tx_cntrl_offset, &reg);
	if (reg & 0x400) {
		/* remember tone setting */
		continuous_flag = 1;
		/* turn off tone */
		reg &= 0xfffff3ff;
	}

	// set to modulation mode and load FIFO
	reg &= 0xfffffff8;
	ret |= AVL6882_WR_REG32(priv, 0x16c000 + hw_diseqc_tx_cntrl_offset, reg);
	for (i = 0; i < d->msg_len; i++)
		ret |= AVL6882_WR_REG32(priv, 0x16c000 + hw_tx_fifo_map_offset, (u32) d->msg[i]);
	msleep(20);

	// start tx
	reg |= 4;
	ret |= AVL6882_WR_REG32(priv, 0x16c000 + hw_diseqc_tx_cntrl_offset, reg);
	do {
		ret |= AVL6882_RD_REG32(priv, 0x16c000 + hw_diseqc_tx_st_offset, &tmp);
		tx_done = (u8) ((tmp & 0x00000040) >> 6);
		tx_remain = (u8) ((tmp & 0x0000003c) >> 2);
		msleep(20);
		if (++timeout > 25)
			ret = -ETIMEDOUT;
	} while ((tx_done == 0) || ret);

	if (continuous_flag) {
		/* restore tone */
		reg &= 0xfffffff8;
		reg |= 0x403;
		ret |= AVL6882_WR_REG32(priv, 0x16c000 + hw_diseqc_tx_cntrl_offset, reg);
	}
	return ret;
}


static int avl6882_init(struct dvb_frontend *fe)
{
	return 0;
}


#define I2C_RPT_DIV ((0x2A)*(250000)/(240*1000))	//m_CoreFrequency_Hz 250000000

static int avl6882_set_dvbmode(struct dvb_frontend *fe,
		enum fe_delivery_system delsys)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	int ret;
	u32 reg;

	/* these modes use the same fw / config */
	if (delsys == SYS_DVBS2)
		delsys = SYS_DVBS;
	else if (delsys == SYS_DVBT2)
		delsys = SYS_DVBT;

	/* already in the requested mode */
	if (priv->delivery_system == delsys)
		return 0;

	priv->delivery_system = delsys;
	//printk("initing demod for delsys=%d\n", delsys);

	ret = avl6882_load_firmware(priv);

	// Load the default configuration
	ret |= avl6882_exec_n_wait(priv, AVL_FW_CMD_LD_DEFAULT);
	ret |= avl6882_exec_n_wait(priv, AVL_FW_CMD_INIT_SDRAM);
	ret |= avl6882_exec_n_wait(priv, AVL_FW_CMD_INIT_ADC);

	switch (priv->delivery_system) {
	case SYS_DVBC_ANNEX_A:
		ret |= avl6882_init_dvbc(fe);
		break;
	case SYS_DVBS:
	case SYS_DVBS2:
		ret |= avl6882_init_dvbs(fe);
		break;
	case SYS_DVBT:
	case SYS_DVBT2:
	default:
		ret |= avl6882_init_dvbt(fe);
		break;
	}

	/* set gpio / turn off lnb, set 13V */
    	ret  = avl6882_gpio_set(priv, GPIO_LNB_PWR, GPIO_1);
    	ret |= avl6882_gpio_set(priv, GPIO_LNB_VOLT, GPIO_0);

	/* set TS mode */
	ret |= AVL6882_WR_REG8(priv, 0x200 + rc_ts_serial_caddr_offset, AVL_TS_PARALLEL);
	ret |= AVL6882_WR_REG8(priv, 0x200 + rc_ts_clock_edge_caddr_offset, AVL_MPCM_RISING);
	ret |= AVL6882_WR_REG8(priv, 0x200 + rc_enable_ts_continuous_caddr_offset, AVL_TS_CONTINUOUS_ENABLE);

	/* TS serial pin */
	ret |= AVL6882_WR_REG8(priv, 0x200 + rc_ts_serial_outpin_caddr_offset, AVL_MPSP_DATA0);
	/* TS serial order */
	ret |= AVL6882_WR_REG8(priv, 0x200 + rc_ts_serial_msb_caddr_offset, AVL_MPBO_MSB);
	/* TS serial sync pulse */
	ret |= AVL6882_WR_REG8(priv, 0x200 + rc_ts_sync_pulse_caddr_offset, AVL_TS_SERIAL_SYNC_1_PULSE);
	/* TS error pol */
	ret |= AVL6882_WR_REG8(priv, 0x200 + rc_ts_error_polarity_caddr_offset, AVL_MPEP_Normal);
	/* TS valid pol */
	ret |= AVL6882_WR_REG8(priv, 0x200 + rc_ts_valid_polarity_caddr_offset, AVL_MPVP_Normal);
	/* TS packet len */
	ret |= AVL6882_WR_REG8(priv, 0x200 + rc_ts_packet_len_caddr_offset, AVL_TS_188);
	/* TS parallel order */
	ret |= AVL6882_WR_REG8(priv, 0x200 + rc_ts_packet_order_caddr_offset, AVL_TS_PARALLEL_ORDER_NORMAL);
	/* TS parallel phase */
	ret |= AVL6882_WR_REG8(priv, 0x200 + ts_clock_phase_caddr_offset, AVL_TS_PARALLEL_PHASE_0);

	/* TS output enable */
	ret |= AVL6882_WR_REG32(priv, AVLREG_TS_OUTPUT, TS_OUTPUT_ENABLE);

	/* init tuner i2c repeater */
	/* hold in reset */
	ret |= AVL6882_WR_REG32(priv, 0x118000 + tuner_i2c_srst_offset, 1);
	/* close gate */
	ret |= avl6882_i2c_gate_ctrl(fe, 0);
	//ret |= AVL6882_WR_REG32(priv, 0x118000 + tuner_i2c_bit_rpt_cntrl_offset, 0x6);
	ret |= AVL6882_RD_REG32(priv, 0x118000 + tuner_i2c_cntrl_offset, &reg);
	reg &= 0xfffffffe;
	ret |= AVL6882_WR_REG32(priv, 0x118000 + tuner_i2c_cntrl_offset, reg);
	/* set bit clock */
	ret |= AVL6882_WR_REG32(priv, 0x118000 + tuner_i2c_bit_rpt_clk_div_offset, I2C_RPT_DIV);
	/* release from reset */
	ret |= AVL6882_WR_REG32(priv, 0x118000 + tuner_i2c_srst_offset, 0);

	ret |= InitErrorStat_Demod(priv);

	if (ret) {
		dev_err(&priv->i2c->dev, "%s: demod init failed",
				KBUILD_MODNAME);
	}

	return ret;
}

static int avl6882_sleep(struct dvb_frontend *fe)
{
	//printk("%s()\n", __func__);
	return 0;
}


static int avl6882fe_strength(struct dvb_frontend *fe, u16 *signal_strength)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	int ret;
	u32 tmp;
	ret = AVL6882_RD_REG16(priv,0x0a4 + rs_rf_agc_saddr_offset, &tmp);

	*signal_strength = (u16) tmp;
	return 0;
}

static int avl6882fe_snr(struct dvb_frontend *fe, u16 *snr)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	int ret = 0;
	u32 tmp;

	switch (c->delivery_system) {
	case SYS_DVBT:
	case SYS_DVBT2:
	default:
		ret = AVL6882_RD_REG16(priv,
			0x800 + rs_DVBTx_snr_dB_x100_saddr_offset,
			&tmp);
		break;
	case SYS_DVBS:
	case SYS_DVBS2:
		ret = AVL6882_RD_REG32(priv,
			0xc00 + rs_DVBSx_int_SNR_dB_iaddr_offset,
			&tmp);
		break;
	case SYS_DVBC_ANNEX_A:
		//reg = 0x400 + rs_DVBC_snr_dB_x100_saddr_offset;
		break;
	}

	if (tmp > 10000)
		*snr = 0;
	else
		*snr = (u16) (tmp * 10);
	return ret;
}

static enum dvbfe_algo avl6882fe_algo(struct dvb_frontend *fe)
{
	return DVBFE_ALGO_HW;
}

static int avl6882_set_frontend(struct dvb_frontend *fe)
{
	struct avl6882_priv *priv = fe->demodulator_priv;
	struct dtv_frontend_properties *c = &fe->dtv_property_cache;
	u32 demod_mode;
	int ret;

	//printk("%s() mode=%d\n", __func__, c->delivery_system);

	/* check that mode is correctly set */
	ret = AVL6882_RD_REG32(priv, 0x200 + rs_current_active_mode_iaddr_offset, &demod_mode);
	if (ret)
		return ret;

	/* setup tuner */
	if (fe->ops.tuner_ops.set_params) {
		if (fe->ops.i2c_gate_ctrl)
			fe->ops.i2c_gate_ctrl(fe, 1);
		ret = fe->ops.tuner_ops.set_params(fe);
		if (fe->ops.i2c_gate_ctrl)
			fe->ops.i2c_gate_ctrl(fe, 0);

		if (ret)
			return ret;
	}
	//printk("%s() demod_mode=%d\n", __func__, demod_mode);

	switch (c->delivery_system) {
	case SYS_DVBT:
	case SYS_DVBT2:
		if (demod_mode != AVL_DVBTX) {
			dev_err(&priv->i2c->dev, "%s: failed to enter DVBTx mode",
				KBUILD_MODNAME);
			ret = -EAGAIN;
			break;
		}
		ret = avl6882_set_dvbt(fe);
		break;
	case SYS_DVBC_ANNEX_A:
		if (demod_mode != AVL_DVBC) {
			dev_err(&priv->i2c->dev, "%s: failed to enter DVBC mode",
				KBUILD_MODNAME);
			ret = -EAGAIN;
			break;
		}
		ret = avl6882_set_dvbc(fe);
		break;
	case SYS_DVBS:
	case SYS_DVBS2:
		if (demod_mode != AVL_DVBSX) {
			dev_err(&priv->i2c->dev, "%s: failed to enter DVBSx mode",
				KBUILD_MODNAME);
			ret = -EAGAIN;
			break;
		}
		ret = avl6882_set_dvbs(fe);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int avl6882_tune(struct dvb_frontend *fe, bool re_tune,
	unsigned int mode_flags, unsigned int *delay, enum fe_status *status)
{
	*delay = HZ / 5;
	if (re_tune) {
		int ret = avl6882_set_frontend(fe);
		if (ret)
			return ret;
	}
	return avl6882_read_status(fe, status);
}

static int avl6882_get_frontend(struct dvb_frontend *fe,
				struct dtv_frontend_properties *c)
{
	return 0;
}

static int avl6882_set_property(struct dvb_frontend *fe,
		u32 cmd, u32 data)
{
	int ret = 0;

	switch (cmd) {
	case DTV_DELIVERY_SYSTEM:
		//printk("DTV_set_prop delsys %d\n", data);
		ret = avl6882_set_dvbmode(fe, data);
		if (ret) {
			printk("error set_dvbmode\n");
		}
		switch (data) {
		case SYS_DVBC_ANNEX_A:
			fe->ops.info.frequency_min_hz = 47 * MHz;
			fe->ops.info.frequency_max_hz = 862 * MHz;
			fe->ops.info.frequency_stepsize_hz = 62500;
			break;
		case SYS_DVBS:
		case SYS_DVBS2:
			fe->ops.info.frequency_min_hz = 950 * MHz;
			fe->ops.info.frequency_max_hz = 2150 * MHz;
			fe->ops.info.frequency_stepsize_hz = 0;
			break;
		case SYS_DVBT:
		case SYS_DVBT2:
		default:
			fe->ops.info.frequency_min_hz = 174 * MHz;
			fe->ops.info.frequency_max_hz = 862 * MHz;
			fe->ops.info.frequency_stepsize_hz = 250000;
			break;
		}

		break;
	default:
		break;
	}

	return ret;
}

static struct dvb_frontend_ops avl6882_ops = {
	.delsys = {SYS_DVBT, SYS_DVBT2, SYS_DVBC_ANNEX_A, SYS_DVBS, SYS_DVBS2},
	.info = {
		.name			= "Availink AVL6882",
		.frequency_min_hz	= 0,
		.frequency_max_hz	= 0,
		.frequency_stepsize_hz	= 0,
		.frequency_tolerance_hz	= 0,
		.symbol_rate_min	= 1000000,
		.symbol_rate_max	= 45000000,
		.caps = FE_CAN_FEC_1_2                 |
			FE_CAN_FEC_2_3                 |
			FE_CAN_FEC_3_4                 |
			FE_CAN_FEC_4_5                 |
			FE_CAN_FEC_5_6                 |
			FE_CAN_FEC_6_7                 |
			FE_CAN_FEC_7_8                 |
			FE_CAN_FEC_AUTO                |
			FE_CAN_QPSK                    |
			FE_CAN_QAM_16                  |
			FE_CAN_QAM_32                  |
			FE_CAN_QAM_64                  |
			FE_CAN_QAM_128                 |
			FE_CAN_QAM_256                 |
			FE_CAN_QAM_AUTO                |
			FE_CAN_TRANSMISSION_MODE_AUTO  |
			FE_CAN_GUARD_INTERVAL_AUTO     |
			FE_CAN_HIERARCHY_AUTO          |
			FE_CAN_MUTE_TS                 |
			FE_CAN_2G_MODULATION           |
			FE_CAN_MULTISTREAM             |
			FE_CAN_INVERSION_AUTO
	},

	.release			= avl6882_release,
	.init				= avl6882_init,

	.sleep				= avl6882_sleep,
	.i2c_gate_ctrl			= avl6882_i2c_gate_ctrl,

	.read_status			= avl6882_read_status,
	.read_ber = avl6882_read_ber,
	.read_signal_strength		= avl6882fe_strength,
	.read_snr			= avl6882fe_snr,
	.read_ucblocks = avl6882_read_ucblocks,
	.set_tone			= avl6882_set_tone,
	.set_voltage			= avl6882_set_voltage,
	.diseqc_send_master_cmd 	= avl6882_diseqc_send_master_cmd,
	.diseqc_send_burst = avl6882_burst,
	.get_frontend_algo		= avl6882fe_algo,
	.tune				= avl6882_tune,

	.set_property			= avl6882_set_property,
	.set_frontend			= avl6882_set_frontend,
	.get_frontend = avl6882_get_frontend,
};


static int avl6882_setup_firmware(struct avl6882_priv *priv)
{
	const struct firmware *fw;
	struct avl6882_fw *afw = priv->fw;
	int ret, i;
	u32 *ptr, size = 0;

	ret = request_firmware(&fw, AVL6882_FIRMWARE, priv->i2c->dev.parent);
	if (ret) {
		dev_err(&priv->i2c->dev, "Error loading firmware: %s "
			"(timeout or file not found?)\n", AVL6882_FIRMWARE);
		goto err1;
	}
	if (fw->size < AVL6882_FW_HEADER_SIZE) {
		dev_err(&priv->i2c->dev, "Error loading firmware: %s "
			"(invalid file size?)\n", AVL6882_FIRMWARE);
		ret = -EINVAL;
		goto err2;
	}

	ptr = (u32*) fw->data;

	for (i = 0; i < AVL6882_FW_COUNT; i++) {
		afw[i].offset = le32_to_cpu(*ptr++);
		afw[i].size = le32_to_cpu(*ptr++) & 0xfffffffc;
		size += afw[i].size;
	}

	if (size != fw->size - AVL6882_FW_HEADER_SIZE) {
		dev_err(&priv->i2c->dev, "Error loading firmware: %s "
			"(invalid fw size?)\n", AVL6882_FIRMWARE);
		ret = -EINVAL;
		goto err2;
	}

	for (i = 0; i < AVL6882_FW_COUNT; i++) {
		afw[i].data = kzalloc(afw[i].size, GFP_KERNEL);
		if (afw[i].data == NULL) {
			dev_err(&priv->i2c->dev, "Error loading firmware: %s "
				"(not enough mem)\n", AVL6882_FIRMWARE);
			ret = -ENOMEM;
			goto err3;
		}
		ptr = (u32*) &fw->data[afw[i].offset];
		for (size = 0; size < afw[i].size / 4; size++)
			afw[i].data[size] = be32_to_cpu(*ptr++);
		/* check valid FW */
		if ((afw[i].data[0] & 0xf0000000) != 0x10000000) {
			dev_err(&priv->i2c->dev, "Error loading firmware: %s "
				"(invalid fw)\n", AVL6882_FIRMWARE);
			ret = -EINVAL;
			goto err3;
		}
	}

	return ret;
err3:
	while (--i >= 0)
		kfree(afw[i].data);
err2:
	release_firmware(fw);
err1:
	return ret;
}

struct dvb_frontend *avl6882_attach(struct avl6882_config *config,
					struct i2c_adapter *i2c)
{
	struct avl6882_priv *priv;
	int ret;
	u32 id, fid;


	priv = kzalloc(sizeof(struct avl6882_priv), GFP_KERNEL);
	if (priv == NULL)
		goto err;

	memcpy(&priv->frontend.ops, &avl6882_ops,
		sizeof(struct dvb_frontend_ops));

	priv->frontend.demodulator_priv = priv;
	priv->config = config;
	priv->i2c = i2c;
	priv->g_nChannel_ts_total = 0,
	priv->delivery_system = -1;

	/* get chip id */
	ret = AVL6882_RD_REG32(priv, 0x108000, &id);
	/* get chip family id */
	ret |= AVL6882_RD_REG32(priv, 0x40000, &fid);
	if (ret) {
		dev_err(&priv->i2c->dev, "%s: attach failed reading id",
				KBUILD_MODNAME);
		goto err1;
	}

	if (fid != 0x68624955) {
		dev_err(&priv->i2c->dev, "%s: attach failed family id mismatch",
				KBUILD_MODNAME);
		goto err1;
	}

	dev_info(&priv->i2c->dev, "%s: found id=0x%x " \
				"family_id=0x%x", KBUILD_MODNAME, id, fid);

	/* setup firmware */
	if (avl6882_setup_firmware(priv))
		goto err1;

	return &priv->frontend;

err1:
	kfree(priv);
err:
	return NULL;
}
EXPORT_SYMBOL_GPL(avl6882_attach);

MODULE_DESCRIPTION("Availink AVL6882 DVB demodulator driver");
MODULE_AUTHOR("Luis Alves (ljalvs@gmail.com)");
MODULE_LICENSE("GPL");
MODULE_FIRMWARE(AVL6882_FIRMWARE);
