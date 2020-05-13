#ifndef _UAPI_DVBMOD_H_
#define _UAPI_DVBMOD_H_

#include <linux/types.h>
#include <linux/dvb/frontend.h>
/*
struct dvb_mod_params {
	__u32 base_frequency;
	__u32 attenuator; 
};

struct dvb_mod_channel_params {
	enum fe_modulation modulation;
	__u64 input_bitrate;         // 2^-32 Hz 
	int   pcr_correction; 
};


#define DVB_MOD_SET              _IOW('o', 208, struct dvb_mod_params)
#define DVB_MOD_CHANNEL_SET      _IOW('o', 209, struct dvb_mod_channel_params)
*/
#define MODULATOR_UNDEFINED	  0
#define MODULATOR_START		  1
#define MODULATOR_STOP		  2
#define MODULATOR_FREQUENCY	  3
#define MODULATOR_MODULATION	  4   
#define MODULATOR_SYMBOL_RATE	  5   /* Hz */
#define MODULATOR_BASE_FREQUENCY  6
#define MODULATOR_ATTENUATOR     32  
#define MODULATOR_INPUT_BITRATE  33  /* Hz */
#define MODULATOR_PCR_MODE       34  /* 1=pcr correction enabled */
#define MODULATOR_GAIN           35
#define MODULATOR_RESET          36
#define MODULATOR_STATUS         37
#define MODULATOR_OUTPUT_ARI     64
#define MODULATOR_INTERLEAVE     65

#endif /*_UAPI_DVBMOD_H_*/
