#ifndef _TBSMOD_IO_H
#define _TBSMOD_IO_H

//spi flash
#define SPI_CONFIG      	 0x10
#define SPI_STATUS      	 0x10
#define SPI_COMMAND     	 0x14
#define SPI_WT_DATA     	 0x18
#define SPI_RD_DATA     	 0x1c
#define SPI_ENABLE       	 0x1c


#define SPI_MAX2871       	 0x2c   // spi config ad4351 

#define SPI_DEVICE       	 0x20   // spi choose: 0 is for 9789, 1 is for fpga , default is 0
#define SPI_RESET       	 0x24   // spi config 9789 reset , default 0, 1 is valid. read for qamb is mod and control
#define SPI_AD4351       	 0x2c   // spi config ad4351 
#define AD9789_MODULATION	 0x28   // spi mod set
#define AD9789B_MODULATION	 0x38   // spi mod set for tbs6008
#define SPI_9789B_RESET       	 0x34   // spi config 9789b reset , default 0, 1 is valid. read for qamb is mod and control

#define SPI_BW_LIGHT	 0x34  // spi bw light set

#define SPI_TESTREG       	 0x30   // debug
#define MOD_RESET_IPCORE       	 0x38   //qamb reset ipcore

#define ISDBT_IPRST       	 0x38

#define MOD_ASI_DEVICE		0X14
#define MOD_ASI_BASEADDRESS  0x4000
#define MOD_GPIO_BASEADDRESS  0x0000
#define MOD_ASI_RST  	0x00

//ASI spi flash
#define ASI_SPI_CONFIG      	 0x04
#define ASI_SPI_STATUS      	 0x00
#define ASI_SPI_COMMAND     	 0x08
#define ASI_SPI_WT_DATA     	 0x0c
#define ASI_SPI_RD_DATA     	 0x04
#define ASI_SPI_ENABLE       	 0x10
#define ASI_SPI_TESTREG       	 0x28   // debug

#define I2C_STATUS     	 0x00
#define I2C_COMMAND    	 0x00
#define I2C_W_DATA     	 0x04
#define I2C_R_DATA     	 0x04
#define I2C_SPEED        0x08  

#define I2C0_BASEADDRESS  0x4000
#define I2C1_BASEADDRESS  0x5000

enum{
	AD9789_SPI_CTL	 				= 0x00,
	AD9789_SATURA_CNT				= 0x01,
	AD9789_PARITY_CNT				= 0x02,
	AD9789_INT_ENABLE				= 0x03,
	AD9789_INT_STATUS				= 0x04,
	AD9789_CHANNEL_ENABLE			= 0x05,
	AD9789_BYPASS					= 0x06,
	AD9789_QAM_CONFIG				= 0x07,
	AD9789_SUM_SCALAR				= 0x08,
	AD9789_INPUT_SCALAR				= 0x09,
	AD9789_NCO_0_FRE				= 0x0C,
	AD9789_NCO_1_FRE				= 0x0F,
	AD9789_NCO_2_FRE				= 0x12,
	AD9789_NCO_3_FRE				= 0x15,
	AD9789_RATE_CONVERT_Q			= 0x18,
	AD9789_RATE_CONVERT_P			= 0x1B,
	AD9789_CENTER_FRE_BPF  			= 0x1D,
	AD9789_FRE_UPDATE				= 0x1E,
	AD9789_HARDWARE_VERSION			= 0x1F,
	AD9789_INTERFACE_CONFIG			= 0x20,
	AD9789_DATA_CONTROL				= 0x21,
	AD9789_DCO_FRE					= 0x22,
	AD9789_INTERNAL_COLCK_ADJUST	= 0x23,
	AD9789_PARAMETER_UPDATE			= 0x24,
	AD9789_CHANNEL_0_GAIN			= 0x25,
	AD9789_CHANNEL_1_GAIN			= 0x26,
	AD9789_CHANNEL_2_GAIN			= 0x27,	
	AD9789_CHANNEL_3_GAIN			= 0x28,
	AD9789_SPEC_SHAPING				= 0x29,
	AD9789_Mu_DELAY_CONTROL_1		= 0x2F,
	AD9789_Mu_CONTROL_DUTY_CYCLE	= 0x30,
	AD9789_CLOCK_RECIVER_1			= 0x31,
	AD9789_CLOCK_RECIVER_2			= 0x32,
	AD9789_Mu_DELAY_CONTROL_2		= 0x33,
	AD9789_DAC_BIAS					= 0x36,
	AD9789_DAC_DECODER				= 0x38,
	AD9789_Mu_DELAY_CONTROL_3		= 0x39,
	AD9789_Mu_DELAY_CONTROL_4		= 0x3A,
	AD9789_FULL_SCALE_CURRENT_1		= 0X3C,
	AD9789_FULL_SCALE_CURRENT_2		= 0X3D,
	AD9789_PHASE_DETECTOR_CONTROL   = 0x3E,
	AD9789_BIST_CONTROL				= 0x40,
	AD9789_BIST_STATUS				= 0x41,
	AD9789_BIST_ZERO_LENGTH			= 0x42,
	AD9789_BIST_VECTOR_LENGTH		= 0x44,
	AD9789_BIST_CLOCK_ADJUST		= 0x47,
	AD9789_SIGN_0_CONTROL			= 0x48,
	AD9789_SIGN_0_CLOCK_ADJUST		= 0x49,
	AD9789_SIGN_1_CONTROL			= 0x4A,
	AD9789_SIGN_1_CLOCK_ADJUST		= 0x4B,
	AD9789_REGFNL_0_FREQ			= 0x4C,
	AD9789_REGFNL_1_FREQ			= 0x4D,
	AD9789_BITS_SIGNATURE_0			= 0x50,
	AD9789_BITS_SIGNATURE_1			= 0x53
};

#define DMA_GO	        0x00
#define DMA_SIZE		0x04
#define DMA_ADDR_HIGH	0x08
#define DMA_ADDR_LOW	0x0c
#define DMA_DELAY		0x14
#define DMA_DELAYSHORT	0x18
#define DMA_SPEED_CTRL	0x20
#define DMA_INT_MONITOR 0x1c

#define DMA_FRAME_CNT 0x24

#define Dmaout_adapter0  0x8000
#define Dmaout_adapter1  0x9000
#define Dmaout_adapter2  0xa000
#define Dmaout_adapter3  0xb000

#define Dmaout_adapter4  0x8800
#define Dmaout_adapter5  0x9800
#define Dmaout_adapter6  0xa800
#define Dmaout_adapter7  0xb800

#define DMA_BASEADDRESS(_n) ((_n<4)?(0x8000+0x1000*_n):(0x8800+0x1000*(_n-4)))
#define DMA_MASK(_n)	(0x18 + 4*_n )
#define DMA_STATUS(_n) (0x0010<<_n)

#define Int_adapter  0xc000

#endif
