/*
    TBS ECP3 FPGA based cards PCIe driver

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _TBSECP3_REGS_H_
#define _TBSECP3_REGS_H_

/* GPIO */
#define TBSECP3_GPIO_BASE	0x0000

#define TBSECP3_GPIO_PIN(_bank, _pin)	(((_bank) << 5) + _pin)

/* I2C */
#define TBSECP3_I2C_BASE(_n)	(_n<4)?(0x4000 + 0x1000 * _n):(0x4800 + 0x1000 * (_n-4))
#define TBSECP3_I2C_STAT	0x0000
#define TBSECP3_I2C_CTRL	0x0000
#define TBSECP3_I2C_DATA	0x0004
#define TBSECP3_I2C_BAUD	0x0008

/* CA */
#define TBSECP3_CA_BASE(_n)	(0x6000 + 0x1000 * _n)

/* DMA */
//#define TBSECP3_DMA_BASE(_n)	(_n < 4) ? (0x8000 + 0x1000 * _n) : (0x8800 + 0x1000 * (_n - 4))
#define TBSECP3_DMA_BASE(_n)	(_n<8)?((_n < 4) ? (0x8000 + 0x1000 * _n) : (0x8800 + 0x1000 * (_n - 4))):  \
								((_n < 12) ? (0x8400 + 0x1000 *( _n - 8)) : (0x8C00 + 0x1000 * (_n - 12)))
#define TBSECP3_DMA_STAT	0x0000
#define TBSECP3_DMA_EN		0x0000
#define TBSECP3_DMA_TSIZE	0x0004
#define TBSECP3_DMA_ADDRH	0x0008
#define TBSECP3_DMA_ADDRL	0x000c
#define TBSECP3_DMA_BSIZE	0x0010

/* INTR */
#define TBSECP3_INT_BASE	0xc000
#define TBSECP3_INT_STAT	0x0000
#define TBSECP3_INT_EN		0x0004
#define TBSECP3_I2C_IE(_n)	(0x0008 + 4 * _n)
#define TBSECP3_I2C_IE1(_n)	(0x009C + 4 * (_n-4)) //i2c4~7
#define TBSECP3_DMA_IE(_n)	(0x0018 + 4 * _n)
#define TBSECP3_I2C_IF(_n)	(0x0001 << _n)		//for i2c0~3
#define TBSECP3_I2C_IF1(_n)	(0x10000000 << (_n-4)) //for i2c4~7
#define TBSECP3_DMA_IF(_n)	(0x0010 << _n)

//spi flash
#define SPI_CONFIG      	 0x10
#define SPI_STATUS      	 0x10
#define SPI_COMMAND     	 0x14
#define SPI_WT_DATA     	 0x18
#define SPI_RD_DATA     	 0x1c
#define SPI_ENABLE       	 0x1c

/* ASI */ 
#define ASI0_BASEADDRESS  0x4000
#define ASI_CHIP_RST  	0x00
#define ASI_SPI_CONFIG  0x04
#define ASI_SPI_CMD  	0x08
#define ASI_SPI_WT_32  	0x0c
#define ASI_SPI_ENABLE  0x10

#define ASI_STATUS  	0x00
#define ASI_SPI_RD_32   0x04

//-------------24cXX --------------------------------------------------------
#define BASE_ADDRESS_24CXX  	0x4000
#define CMD_24CXX	      0*4   //write only
#define DATA0_24CXX       1*4   //W/R
#define DATA1_24CXX       2*4   //W/R
#define CS_RELEASE        3*4   //write only

#define STATUS_MAC16_24CXX	 0*4   //read only
#define MAC32_24CXX	 		 3*4   //read only
//---------------------------------------------------------------------

#endif
