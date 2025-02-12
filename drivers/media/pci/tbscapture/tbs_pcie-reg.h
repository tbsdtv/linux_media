/*
    TurboSight TBS PCIE HDMI/SDI capture driver
    Copyright (C) 2017 www.tbsdtv.com
*/

#ifndef _TBS_PCIE_REG_H
#define _TBS_PCIE_REG_H

#define TBS_GPIO_BASE		0x0000

#define TBS_GPIO_DATA(i)	((i) *4 )
#define TBS_GPIO_DATA_0		0x00	/* adapter 0 */
#define TBS_GPIO_DATA_1		0x04	/* adapter 1 */
#define TBS_GPIO_DATA_2		0x08	/* adapter 2 */
#define TBS_GPIO_DATA_3		0x0c	/* adapter 3 */

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

#define TBS_DMA_BASE(i)		(0x8000 + ((i) * 0x1000))
#define TBS_DMA_BASE_0		0x8000 //audio
#define TBS_DMA_BASE_1		0x9000 // video
#define TBS_DMA_BASE_2		0xa000
#define TBS_DMA_BASE_3		0xb000

#define TBS_DMA_START		0x00
#define TBS_DMA_STATUS		0x00
#define TBS_DMA_SIZE		0x04
#define TBS_DMA_ADDR_HIGH	0x08
#define TBS_DMA_ADDR_LOW	0x0c
#define TBS_DMA_CELL_SIZE	0x10

//#define TBS_AUDIO_CELL_SIZE 2944   //44.1k
#define TBS_AUDIO_CELL_SIZE 4096   //48k
#define DMA_VIDEO_CELL         ( (videodev->Interlaced==1) ? (videodev->width*videodev->height) : (videodev->width*videodev->height*2) )
//undefine in fpga now
#define	RISC_INT_BIT		0x08000000
#define	RISC_SYNCO		0xC0000000
#define	RISC_SYNCE		0xD0000000
#define	RISC_JUMP		0xB0000000
#define	RISC_LINESTART		0x90000000
#define	RISC_INLINE		0xA0000000

/* ASI == SDI excep baseaddress */ 
#define ASI0_BASEADDRESS  0x5000
#define ASI_CHIP_RST  	0x00
#define ASI_SPI_CONFIG  0x04
#define ASI_SPI_CMD  	0x08
#define ASI_SPI_WT_32  	0x0c
#define ASI_SPI_ENABLE  0x10

#define ASI_STATUS  	0x00
#define ASI_SPI_RD_32   0x04



#endif
