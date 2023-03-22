#ifndef MXL603_H
#define MXL603_H

#include <linux/dvb/frontend.h>

typedef enum
{
  MXL603_IF_3_65MHz  = 0,
  MXL603_IF_4MHz     = 1,
  MXL603_IF_4_1MHz   = 2,
  MXL603_IF_4_15MHz  = 3,
  MXL603_IF_4_5MHz   = 4, 
  MXL603_IF_4_57MHz  = 5,
  MXL603_IF_5MHz     = 6,
  MXL603_IF_5_38MHz  = 7, 
  MXL603_IF_6MHz     = 8,
  MXL603_IF_6_28MHz  = 9,
  MXL603_IF_7_2MHz   = 10, 
  MXL603_IF_8_25MHz  = 11,
  MXL603_IF_35_25MHz = 12,
  MXL603_IF_36MHz    = 13, 
  MXL603_IF_36_15MHz = 14, 
  MXL603_IF_36_65MHz = 15,
  MXL603_IF_44MHz    = 16
} MXL603_IF_FREQ_E; 

#define MXL603_XTAL_16MHz  0
#define MXL603_XTAL_24MHz  1

struct mxl603_config{

	u8 xtalFreqSel;

	u8 ifOutFreq;

#define MXL603_AGC_SELF 0
#define MXL603_AGC_EXTERNAL 1
	u8 agcType;

	bool manualIFFreqSet; /*enable and disable*/
	u32 manualIFOutFreqInKHz;
	
 	struct dvb_frontend *fe;

};

#endif
