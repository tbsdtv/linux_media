/* 
* This file is part of STiD135 OXFORD LLA 
* 
* Copyright (c) <2014>-<2018>, STMicroelectronics - All Rights Reserved 
* Author(s): Mathias Hilaire (mathias.hilaire@st.com), Thierry Delahaye (thierry.delahaye@st.com) for STMicroelectronics. 
* 
* License terms: BSD 3-clause "New" or "Revised" License. 
* 
* Redistribution and use in source and binary forms, with or without 
* modification, are permitted provided that the following conditions are met: 
* 
* 1. Redistributions of source code must retain the above copyright notice, this 
* list of conditions and the following disclaimer. 
* 
* 2. Redistributions in binary form must reproduce the above copyright notice, 
* this list of conditions and the following disclaimer in the documentation 
* and/or other materials provided with the distribution. 
* 
* 3. Neither the name of the copyright holder nor the names of its contributors 
* may be used to endorse or promote products derived from this software 
* without specific prior written permission. 
* 
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE 
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER 
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, 
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. 
* 
*/ 
/**                                                                            
 @File   fesat_commlla_str.h                                             
 @brief                                                                         
                                                                               
                                                                               
                                                                               
*/
#ifndef FESAT_COMMLLA_STR_H
	#define FESAT_COMMLLA_STR_H

	/*************************************************************
							INCLUDES
	*************************************************************/	
	#include "stddefs.h"    /* Standard definitions */
	#include "chip.h"
	
	/****************************************************************
						COMMON STRUCTURES AND TYPEDEF
	 ****************************************************************/		

	
enum fe_sat_search_state {
		FE_SAT_SEARCH=0,
		FE_SAT_PLH_DETECTED,
		FE_SAT_DVBS2_FOUND,
		FE_SAT_DVBS_FOUND
		
};/*Current demod search state*/

enum fe_sat_signal_type {
		FE_SAT_NOAGC1=0,
		FE_SAT_AGC1OK,
		FE_SAT_NOTIMING,
		FE_SAT_ANALOGCARRIER,
		FE_SAT_TUNER_NOSIGNAL,
		FE_SAT_TUNER_JUMP,
		FE_SAT_TIMINGOK,
		FE_SAT_NOAGC2,
		FE_SAT_AGC2OK,
		FE_SAT_NOCARRIER,
		FE_SAT_CARRIEROK,
		FE_SAT_NODATA,
		FE_SAT_DATAOK,
		FE_SAT_OUTOFRANGE,
		FE_SAT_RANGEOK
};
	
enum fe_stid135_demod {
		FE_SAT_DEMOD_1=1,
		FE_SAT_DEMOD_2,
		FE_SAT_DEMOD_3,
		FE_SAT_DEMOD_4,
		FE_SAT_DEMOD_5,
		FE_SAT_DEMOD_6,
		FE_SAT_DEMOD_7,
		FE_SAT_DEMOD_8
};		/* Current Demod */   


enum fe_sat_tracking_standard {	
		FE_SAT_DVBS1_STANDARD,					/* Found Standard*/
		FE_SAT_DVBS2_STANDARD,
		FE_SAT_DSS_STANDARD,
		FE_SAT_TURBOCODE_STANDARD,
		FE_SAT_UNKNOWN_STANDARD 
};
	
enum fe_sat_search_standard {	
		FE_SAT_AUTO_SEARCH,
		FE_SAT_SEARCH_DVBS1,				/* Search Standard*/
		FE_SAT_SEARCH_DVBS2,
		FE_SAT_SEARCH_DSS,
		FE_SAT_SEARCH_TURBOCODE
};

enum fe_sat_search_algo {	
		FE_SAT_BLIND_SEARCH,					/* offset freq and SR are Unknown */
		FE_SAT_COLD_START,						/* only the SR is known */
		FE_SAT_WARM_START						/* offset freq and SR are known */
	
};

enum fe_sat_modulation {	
		FE_SAT_MOD_QPSK,
		FE_SAT_MOD_8PSK,				
		FE_SAT_MOD_16APSK,
		FE_SAT_MOD_32APSK,
		FE_SAT_MOD_VLSNR,
		FE_SAT_MOD_64APSK,
		FE_SAT_MOD_128APSK,
		FE_SAT_MOD_256APSK,
		FE_SAT_MOD_8PSK_L,
		FE_SAT_MOD_16APSK_L,
		FE_SAT_MOD_32APSK_L,
		FE_SAT_MOD_64APSK_L,
		FE_SAT_MOD_256APSK_L,
		FE_SAT_MOD_1024APSK,
		FE_SAT_MOD_UNKNOWN
};	/* sat modulation type*/	

enum fe_sat_modcode {
    /* 
	 0x00..1F: Legacy list, DVBS2
     0x20..3F: DVBS1
     0x40..7F: DVBS2-X With:  _S: Short frame (only here to make it work compile, otherwise there will be a redefinition of enumerator)
    	_L: Linear constellation,  
	_R_xx: reserved + Modcode number hex   Pon, Poff Pilots configuration
	*/
    FE_SAT_DUMMY_PLF  = 0x00,  FE_SAT_QPSK_14   = 0x01,  FE_SAT_QPSK_13   = 0x02,  FE_SAT_QPSK_25    = 0x03,
    FE_SAT_QPSK_12    = 0x04,  FE_SAT_QPSK_35   = 0x05,  FE_SAT_QPSK_23   = 0x06,  FE_SAT_QPSK_34    = 0x07,
    FE_SAT_QPSK_45    = 0x08,  FE_SAT_QPSK_56   = 0x09,  FE_SAT_QPSK_89   = 0x0A,  FE_SAT_QPSK_910   = 0x0B,
    FE_SAT_8PSK_35    = 0x0C,  FE_SAT_8PSK_23   = 0x0D,  FE_SAT_8PSK_34   = 0x0E,  FE_SAT_8PSK_56    = 0x0F,
    FE_SAT_8PSK_89    = 0x10,  FE_SAT_8PSK_910  = 0x11,  FE_SAT_16APSK_23 = 0x12,  FE_SAT_16APSK_34  = 0x13,
    FE_SAT_16APSK_45  = 0x14,  FE_SAT_16APSK_56 = 0x15,  FE_SAT_16APSK_89 = 0x16,  FE_SAT_16APSK_910 = 0x17,
    FE_SAT_32APSK_34  = 0x18,  FE_SAT_32APSK_45 = 0x19,  FE_SAT_32APSK_56 = 0x1A,  FE_SAT_32APSK_89  = 0x1B,
    FE_SAT_32APSK_910 = 0x1C,  FE_SAT_MODCODE_UNKNOWN = 0x1D,              FE_SAT_MODCODE_UNKNOWN_1E = 0x1E,
    FE_SAT_MODCODE_UNKNOWN_1F  = 0x1F,
/* ---------------------------------------- */ 
	FE_SAT_DVBS1_QPSK_12 = 0x20, 		FE_SAT_DVBS1_QPSK_23 = 0x21, 		FE_SAT_DVBS1_QPSK_34 = 0x22,
	FE_SAT_DVBS1_QPSK_56 = 0x23, 		FE_SAT_DVBS1_QPSK_67 = 0x24, 		FE_SAT_DVBS1_QPSK_78 = 0x25,
	FE_SAT_MODCODE_UNKNOWN_26 = 0x26,	FE_SAT_MODCODE_UNKNOWN_27 = 0x27,	FE_SAT_MODCODE_UNKNOWN_28 = 0x28,
	FE_SAT_MODCODE_UNKNOWN_29 = 0x29,	FE_SAT_MODCODE_UNKNOWN_2A = 0x2A,	FE_SAT_MODCODE_UNKNOWN_2B = 0x2B,
	FE_SAT_MODCODE_UNKNOWN_2C = 0x2C,	FE_SAT_MODCODE_UNKNOWN_2D = 0x2D,
	FE_SAT_MODCODE_UNKNOWN_2E = 0x2E,	FE_SAT_MODCODE_UNKNOWN_2F = 0x2F,
	
	FE_SAT_MODCODE_UNKNOWN_30 = 0x30, 	FE_SAT_MODCODE_UNKNOWN_31 = 0x31, 	FE_SAT_MODCODE_UNKNOWN_32 = 0x32,
	FE_SAT_MODCODE_UNKNOWN_33 = 0x33, 	FE_SAT_MODCODE_UNKNOWN_34 = 0x34, 	FE_SAT_MODCODE_UNKNOWN_35 = 0x35,
	FE_SAT_MODCODE_UNKNOWN_36 = 0x36,	FE_SAT_MODCODE_UNKNOWN_37 = 0x37,	FE_SAT_MODCODE_UNKNOWN_38 = 0x38,
	FE_SAT_MODCODE_UNKNOWN_39 = 0x39,	FE_SAT_MODCODE_UNKNOWN_3A = 0x3A,	FE_SAT_MODCODE_UNKNOWN_3B = 0x3B,
	FE_SAT_MODCODE_UNKNOWN_3C = 0x3C,	FE_SAT_MODCODE_UNKNOWN_3D = 0x3D,	FE_SAT_MODCODE_UNKNOWN_3E = 0x3E,
	FE_SAT_MODCODE_UNKNOWN_3F = 0x3F,
/* ---------------------------------------- */
    FE_SATX_VLSNR1          = 0x40,  FE_SATX_VLSNR2        = 0x41,  FE_SATX_QPSK_13_45      = 0x42,  FE_SATX_QPSK_9_20     = 0x43,
    FE_SATX_QPSK_11_20      = 0x44,  FE_SATX_8APSK_5_9_L   = 0x45,  FE_SATX_8APSK_26_45_L   = 0x46,  FE_SATX_8PSK_23_36    = 0x47,
    FE_SATX_8PSK_25_36      = 0x48,  FE_SATX_8PSK_13_18    = 0x49,  FE_SATX_16APSK_1_2_L    = 0x4A,  FE_SATX_16APSK_8_15_L = 0x4B,
    FE_SATX_16APSK_5_9_L    = 0x4C,  FE_SATX_16APSK_26_45  = 0x4D,  FE_SATX_16APSK_3_5      = 0x4E,  FE_SATX_16APSK_3_5_L  = 0x4F,
    FE_SATX_16APSK_28_45    = 0x50,  FE_SATX_16APSK_23_36  = 0x51,  FE_SATX_16APSK_2_3_L    = 0x52,  FE_SATX_16APSK_25_36  = 0x53,
    FE_SATX_16APSK_13_18    = 0x54,  FE_SATX_16APSK_7_9    = 0x55,  FE_SATX_16APSK_77_90    = 0x56,  FE_SATX_32APSK_2_3_L  = 0x57,
    FE_SATX_32APSK_R_58     = 0x58,  FE_SATX_32APSK_32_45  = 0x59,  FE_SATX_32APSK_11_15    = 0x5A,  FE_SATX_32APSK_7_9    = 0x5B,
    FE_SATX_64APSK_32_45_L  = 0x5C,  FE_SATX_64APSK_11_15  = 0x5D,  FE_SATX_64APSK_R_5E     = 0x5E,  FE_SATX_64APSK_7_9    = 0x5F,
    FE_SATX_64APSK_R_60     = 0x60,  FE_SATX_64APSK_4_5    = 0x61,  FE_SATX_64APSK_R_62     = 0x62,  FE_SATX_64APSK_5_6    = 0x63,
    FE_SATX_128APSK_3_4     = 0x64,  FE_SATX_128APSK_7_9   = 0x65,  FE_SATX_256APSK_29_45_L = 0x66,  FE_SATX_256APSK_2_3_L = 0x67,
    FE_SATX_256APSK_31_45_L = 0x68,  FE_SATX_256APSK_32_45 = 0x69,  FE_SATX_256APSK_11_15_L = 0x6A,  FE_SATX_256APSK_3_4   = 0x6B,
    FE_SATX_QPSK_11_45      = 0x6C,  FE_SATX_QPSK_4_15     = 0x6D,  FE_SATX_QPSK_14_45      = 0x6E,  FE_SATX_QPSK_7_15     = 0x6F,
    FE_SATX_QPSK_8_15       = 0x70,  FE_SATX_QPSK_32_45    = 0x71,  FE_SATX_8PSK_7_15       = 0x72,  FE_SATX_8PSK_8_15     = 0x73,
    FE_SATX_8PSK_26_45      = 0x74,  FE_SATX_8PSK_32_45    = 0x75,  FE_SATX_16APSK_7_15     = 0x76,  FE_SATX_16APSK_8_15   = 0x77,
    FE_SATX_16APSK_26_45_S  = 0x78,  FE_SATX_16APSK_3_5_S  = 0x79,  FE_SATX_16APSK_32_45    = 0x7A,  FE_SATX_32APSK_2_3    = 0x7B,
    FE_SATX_32APSK_32_45_S  = 0x7C,  
/* ---------------------------------------- */    	
	FE_SATX_8PSK            = 0x7D,  FE_SATX_32APSK    = 0x7E,  FE_SATX_256APSK  	= 0x7F,  /* POFF Modes */			
	FE_SATX_16APSK   	= 0x80,	 FE_SATX_64APSK    = 0x81,  FE_SATX_1024APSK  	= 0x82,  /* PON Modes  */
    FE_SAT_MODCODE_MAX      																		 /* Only used for range checking */ 
};

/* used to determine modcode, pilots, frame evt modtype */
enum fe_sat_mod_code_ident {
	FE_SAT_MIN_LEGACY_MODCODE = FE_SAT_DUMMY_PLF,
	FE_SAT_MAX_LEGACY_MODCODE = FE_SAT_32APSK_910,
	FE_SAT_MIN_DVBS1_MODCODE = FE_SAT_DVBS1_QPSK_12,
	FE_SAT_MAX_DVBS1_MODCODE = FE_SAT_DVBS1_QPSK_78,
	
	FE_SAT_MIN_DVBS2X_MODCODE = FE_SATX_VLSNR1,
	FE_SAT_MAX_DVBS2X_MODCODE = FE_SATX_256APSK,
	/* changed to include all reachable modes */
	
	FE_SAT_MIN_SHORT_MODCODE = FE_SATX_QPSK_11_45,
	FE_SAT_MAX_SHORT_MODCODE = FE_SATX_32APSK_32_45_S,
	
	FE_SAT_MIN_POFF_MODCODE = FE_SATX_8PSK,
	FE_SAT_MAX_POFF_MODCODE = FE_SATX_256APSK,
	
	FE_SAT_MIN_PON_MODCODE = FE_SATX_16APSK,
	FE_SAT_MAX_PON_MODCODE = FE_SATX_1024APSK
};
	
enum fe_sat_rate {			/*DVBS1, DSS and turbo code puncture rate*/
		FE_SAT_PR_1_2 =0,
		FE_SAT_PR_2_3,	
		FE_SAT_PR_3_4,
		FE_SAT_PR_4_5,		/*for turbo code only*/
		FE_SAT_PR_5_6,
		FE_SAT_PR_6_7,		/*for DSS only		 */
		FE_SAT_PR_7_8,
		FE_SAT_PR_8_9,		/*for turbo code only*/
		FE_SAT_PR_UNKNOWN 	 
};

enum fe_sat_frame {
		FE_SAT_NORMAL_FRAME,
		FE_SAT_SHORT_FRAME,
		FE_SAT_LONG_FRAME  = FE_SAT_NORMAL_FRAME,
		FE_SAT_UNKNOWN_FRAME = 3
};						/*Frame Type*/
	
enum fe_sat_pilots {
		FE_SAT_PILOTS_OFF,
		FE_SAT_PILOTS_ON,
		FE_SAT_UNKNOWN_PILOTS
};
	

enum fe_sat_rolloff {
		/* same order than MATYPE_ROLLOFF field */
		FE_SAT_35,
		FE_SAT_25,
		FE_SAT_20,
		FE_SAT_10,
		FE_SAT_05,
		FE_SAT_15
};

	
enum fe_sat_search_iq_inv {
		FE_SAT_IQ_AUTO,
		FE_SAT_IQ_AUTO_NORMAL_FIRST,
		FE_SAT_IQ_FORCE_NORMAL,
		FE_SAT_IQ_FORCE_SWAPPED
};
	
enum fe_sat_iq_inversion {
		FE_SAT_IQ_NORMAL,
		FE_SAT_IQ_SWAPPED
};


	/*DiseqC configuration*/
enum fe_sat_diseqc_txmode {								
		FE_SAT_22KHZ_Continues=0,
		FE_SAT_DISEQC_2_3_PWM=2,
		FE_SAT_DISEQC_3_3_PWM=3,
		FE_SAT_DISEQC_2_3_ENVELOP=4,
		FE_SAT_DISEQC_3_3_ENVELOP=5,
		FE_SAT_22KHZ_Continues_ENVELOP=6
};

	
	/****************************************************************
						INIT STRUCTURES
			structure passed to the FE_STVXXXX_Init() function  
	 ****************************************************************/
struct fe_sat_init_params {
		void 				*pI2CHost;
		char 				demod_name[20];		/* Demod name */
		u8				demod_i2c_adr;		/* Demod I2c address */
  		u32       			demod_ref_clk;          /* Refrence,Input clock for the demodulator in MHz (27MHz,30MHz,....)*/  
		u8				internal_dcdc; /* DCDC supply either internal or external */
		u8				internal_ldo; /* LDO supply either internal or external */
		u8				rf_input_type; /* VGLNA input type, either single ended or differential */
		enum fe_sat_rolloff		roll_off;		/* NYQUIST Filter value (used for DVBS1,DSS, DVBS2 is automatic)*/
		enum fe_sat_iq_inversion	tuner_iq_inversion;	/* Tuner 1 Global IQ setting (coonction of IQ from the tuner1 to the demod */
		enum fe_sat_search_standard	standard;
		BOOL ts_nosync;
	};

	/****************************************************************
						SEARCH STRUCTURES
	 ****************************************************************/


struct fe_sat_search_params {
		u32 				frequency;		/* Transponder frequency (in KHz)				*/
		u32 				symbol_rate;		/* Transponder symbol rate  (in bds)				*/
		u32 				search_range;		/* Range of the search (in Hz)  				*/	
		enum fe_sat_search_standard	standard;		/* DVBS1,DVBS2, DSS or Turbo					*/
		enum fe_sat_modulation		modulation;		/* modulation type use	FE_MOD_UNKNOWN for auto 		*/ 
		enum fe_sat_rate		puncture_rate;		/* DVBS1,DSS and turbo puncture rate use FE_PR_UNKNOWN for auto	*/
		enum fe_sat_modcode		modcode;		/* DVBS2 modcode use FE_MODCODE_UNKNOWN for auto		*/
		enum fe_sat_search_iq_inv	iq_inversion;		/* IQ spectrum search 			   			*/
		enum fe_sat_search_algo		search_algo;		/* Search Algorithm 						*/
		s32 				tuner_index_jump;	/* contains the freq index where the rising or falling edge occurs*/
		
		u32				lo_frequency;		/* gb! Workaround til RF Frontend implementation		*/
#ifdef USER2
		enum fe_sat_rolloff		roll_off;		/* Rolloff factor (0.05, 0.1, 0.2, 0.25 or 0.35)	*/
		BOOL				man_rolloff;		/* Manual (1) or automatic (0) roll-off detection */
#endif
	};
	
struct fe_sat_search_result {
		BOOL 				locked;		/* Transponder found 			*/
		u32				frequency;	/* Found frequency	 		*/
		u32 				symbol_rate;	/* Found Symbol rate			*/
		enum fe_sat_tracking_standard	standard;	/* Found Standard DVBS1,DVBS2 or DSS	*/
		enum fe_sat_rate 		puncture_rate;	/* Found Puncture rate  For DVBS1 	*/
		enum fe_sat_modcode 		modcode;	/* Found Modcode only for DVBS2		*/
		enum fe_sat_modulation		modulation;	/* Found modulation type		*/
		enum fe_sat_pilots		pilots;		/* pilots Found for DVBS2		*/
		enum fe_sat_frame		frame_length;	/* Found frame length for DVBS2		*/
		enum fe_sat_iq_inversion	spectrum;	/* IQ specrum swap setting		*/
		enum fe_sat_rolloff		roll_off;	/* Rolloff factor (0.2, 0.25 or 0.35)	*/
	};

	/************************
		INFO STRUCTURE
	************************/
struct fe_sat_signal_info {
		BOOL 				locked;		/* Transponder locked					*/
		u32 				frequency;	/* Transponder frequency (in KHz)			*/
		u32 				symbol_rate;	/* Transponder symbol rate  (in Mbds)			*/
		enum fe_sat_tracking_standard	standard;	/* Found Standard DVBS1,DVBS2 or DSS or Turbo		*/
		enum fe_sat_rate 		puncture_rate;	/* Puncture rate 			 		*/ 
		enum fe_sat_modcode		modcode;	/* MODCODE Only for DVBS2				*/ 
		enum fe_sat_modulation		modulation;	/* Modulation type					*/
		enum fe_sat_pilots		pilots;		/* pilots on,off only for DVB-S2			*/
		enum fe_sat_frame		frame_length;	/* Found frame length only for DVB-S2			*/
		enum fe_sat_rolloff		roll_off;	/* Rolloff factor (0.2, 0.25 or 0.35)			*/
		s32 				power;		/* Power of the RF signal (dBm x1000)			*/			
		s32 				powerdBmx10;	/* Power of the RF signal (dBm x10000)			*/
		s32				band_power;	/* Power of the whole freq range signal (dBm x1000)	*/
		s32				C_N;		/* Carrier to noise ratio (dB x10)			*/
		u32				ber;		/* Bit error rate	(x10^7)				*/
		enum fe_sat_iq_inversion	spectrum;	/* IQ specrum swap setting				*/
		u8				matype;
		u8 				isi;		/* Current value of ISI 				*/
	} ;

struct fe_sat_tracking_info {
		BOOL 			locked;		/* Transponder locked			*/
		s32 			power;		/* Power of the RF signal (dBm)		*/			
		s32 			powerdBmx10;	/* Power of the RF signal (dBm x10)	*/			
		s32				band_power;	/* Power of the whole freq range signal (dBm)	*/
		s32			C_N;		/* Carrier to noise ratio (dB x10)	*/
		u32			ber;		/* Bit error rate	(x10^7)		*/
 		s32			frequency_if;
		/* Addition for ACM/VCM */ 
		enum fe_sat_modcode	modcode;	/* MODCODE Only for DVBS2		*/ 
		enum fe_sat_pilots	pilots;		/* pilots on,off only for DVB-S2	*/       
		enum fe_sat_frame	frame_length;	/* Found frame length only for DVB-S2	*/ 		
		u8			matype;
		u8 			isi; 	/*Current value of ISI */
	};

	
	
struct fe_sat_slice {
		u8			slice_id;	/* Slice ID in case of wideband signal	*/
		enum fe_sat_modcode	modcode;	/* MODCODE Only for DVBS2		*/ 
		enum fe_sat_pilots	pilots;		/* pilots on,off only for DVB-S2	*/
		enum fe_sat_frame	frame_length;	/* Found frame length only for DVB-S2	*/
	} ;

struct fe_sat_car_loop_vs_cnr {
	s32 cnrthres;
	u8 CarLoop_2;
	u8 CarLoop_10;
	u8 CarLoop_30;
	u8 CarLoop_62_5;
	u8 CarLoop_125;
	u8 CarLoop_300;
	u8 CarLoop_400;
	u8 CarLoop_500;
};
	
#endif
