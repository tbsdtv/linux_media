#ifndef _TBSCI_IO_H
#define _TBSCI_IO_H

//spi flash
#define SPI_CONFIG      	 0x10
#define SPI_STATUS      	 0x10
#define SPI_COMMAND     	 0x14
#define SPI_WT_DATA     	 0x18
#define SPI_RD_DATA     	 0x1c
#define SPI_ENABLE       	 0x1c

#define SPI_DEVICE       	 0x20   // spi choose: 0 is for 9789, 1 is for fpga , default is 0
#define SPI_RESET       	 0x24   // spi config 9789 reset , default 0, 1 is valid.
#define SPI_AD4351       	 0x2c   // spi config ad4351 
#define AD9789_MODULATION	 0x28   // spi mod set

#define SPI_TESTREG       	 0x30   // debug

#define DMA_GO	        0x00
#define DMA_SIZE		0x04
#define DMA_ADDR_HIGH	0x08
#define DMA_ADDR_LOW	0x0c
#define DMA_DELAY		0x14
#define DMA_DELAYSHORT	0x18
#define DMA_SPEED_CTRL	0x20
#define DMA_INT_MONITOR 0x1c
#define DMA_FRAME_CNT	0x24


#define I2C0_MASK		 0x10
#define I2C1_MASK		 0x0c 	
#define I2C2_MASK		 0x08	
#define I2C3_MASK		 0x14	

#define DMA0_MASK		 0x18
#define DMA1_MASK		 0x1C
#define DMA2_MASK		 0x20
#define DMA3_MASK		 0x24

/*  INT register */
#define INT_STATUS     	 0x00
#define INT_EN    	     0x04
#define INT_MASK         0x08  
#define INT_XXX			 0x0c



#define  gpio_adapter	0x0000

#define  i2c_adapter	0x5000
#define  pcmcia_adapter0	0x6000
#define  pcmcia_adapter1	0x7000

#define	dma_wr_adapter0 0x8000
#define	dma_wr_adapter1 0x9000

#define  dmaout_adapter0 0xa000
#define  dmaout_adapter1 0xb000

#define int_adapter  0xc000

#define MODULATOR_INPUT_BITRATE	  33 
#endif
