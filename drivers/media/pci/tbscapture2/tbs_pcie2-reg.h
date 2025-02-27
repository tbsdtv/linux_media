/*
    TurboSight PCIex2 HDMI capture cards driver
    Copyright (C) 2024 www.tbsdtv.com
*/

#ifndef _TBS_PCIE2_REG_H
#define _TBS_PCIE2_REG_H

#define TBS_I2C_BASE_0		0x4000
#define TBS_I2C_BASE_1		0x5000
#define TBS_I2C_BASE_2		0x6000
#define TBS_I2C_BASE_3		0x7000

#define TBS_I2C_CTRL		0x00
#define TBS_I2C_DATA		0x04

#define TBS_I2C_START_BIT	(0x00000001 <<  7)
#define TBS_I2C_STOP_BIT	(0x00000001 <<  6)

#define TBS_I2C_SADDR_2BYTE	(0x00000001 <<  5)
#define TBS_I2C_SADDR_1BYTE	(0x00000001 <<  4)

#define TBS_I2C_WRITE_BIT	(0x00000001 <<  8)

#define TBS_INT_BASE		0xc000

#define TBS_INT_STATUS		0x00
#define TBS_INT_ENABLE		0x04
#define TBS_I2C_MASK_0		0x08
#define TBS_I2C_MASK_1		0x0c
#define TBS_I2C_MASK_2		0x10
#define TBS_I2C_MASK_3		0x14

#define TBS_DMA_MASK(i)		(0x18 + ((i) * 0x04))
#define TBS_DMA_MASK_0		0x18
#define TBS_DMA_MASK_1		0x1C
#define TBS_DMA_MASK_2		0x20
#define TBS_DMA_MASK_3		0x24
#define TBS_DMA_MASK_4      0x28
#define TBS_DMA_MASK_5      0x2c
#define TBS_DMA_MASK_6      0x30
#define TBS_DMA_MASK_7      0x34

#define TBS_DMA_BASE(i)		(0x8000 + ((i)&3) * 0x1000 + ((i)>>2)*0x800 )
#define TBS_DMA_BASE_0		0x8000 //audio
#define TBS_DMA_BASE_1		0x9000 // video
#define TBS_DMA_BASE_2		0xa000
#define TBS_DMA_BASE_3		0xb000
#define TBS_DMA_BASE_4      0x8800
#define TBS_DMA_BASE_5      0x9800
#define TBS_DMA_BASE_6      0xa800
#define TBS_DMA_BASE_7      0xb800

#define TBS_DMA_START		0x00
#define TBS_DMA_STATUS		0x00
#define TBS_DMA_SIZE		0x04
#define TBS_DMA_ADDR_HIGH	0x08
#define TBS_DMA_ADDR_LOW	0x0c
#define TBS_DMA_ADDR_LOW1   0x3c
#define TBS_DMA_ADDR_LOW2   0x40
#define TBS_DMA_CELL_SIZE	0x10

#define TBS_AUDIO_CELL_SIZE (1920)
#define TBS_AUDIO_CELLS     16

#define DMA_VIDEO_CELL         ( (videodev->Interlaced==1) ? (videodev->width*videodev->height) : (videodev->width*videodev->height*2) )

#define INTERFACES  4


#endif
