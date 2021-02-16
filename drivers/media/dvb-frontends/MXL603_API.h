#ifndef _MXL603_API_H_
#define _MXL603_API_H_

typedef unsigned char        UINT8;
typedef unsigned short       UINT16;
typedef unsigned int         UINT32;
typedef unsigned long long   UINT64;
typedef char                 SINT8;
typedef short                SINT16;
typedef int                  SINT32;
typedef float                REAL32;
typedef double               REAL64;
typedef unsigned long        ULONG_32;

#ifdef _ANSI_C_SOURCE
typedef unsigned char        bool;
#endif 


#define AIC_RESET_REG                  0xFF // For MxL603 Tuner

#define PAGE_CHANGE_REG                0x00 // Page change, can configured as page 0 or page 1 
#define XTAL_CAP_CTRL_REG              0x01 // Xtal frequency and CAP register 
#define XTAL_ENABLE_DIV_REG            0x02 // Xtal enable and frequency div 4 register 
#define XTAL_CALI_SET_REG              0x03 // Xtal calibration enable register enable register 
#define IF_FREQ_SEL_REG                0x04 // IF frequency selection and manual set bypass register  
#define IF_PATH_GAIN_REG               0x05 // IF gain level and path selection register  
#define IF_FCW_LOW_REG                 0x06 // Low register of IF FCW set when manual program IF frequency   
#define IF_FCW_HIGH_REG                0x07 // High register of IF FCW set when manual program IF frequency 
#define AGC_CONFIG_REG                 0x08 // AGC configuration, include AGC select and AGC type  
#define AGC_SET_POINT_REG              0x09
#define AGC_FLIP_REG                   0x5E
#define AGC_SLOPE_REG                  0xB5
#define AGC_OFFSET_REG                 0xB4
#define GPO_SETTING_REG                0x0A // GPO set and inquiring register 
#define TUNER_ENABLE_REG               0x0B // Power up register, bit<0>
#define TUNE_MODE_REG                  0x0D
#define MAIN_REG_AMP                   0x0E
#define CHAN_TUNE_BW_REG               0x0F // Band width register 
#define CHAN_TUNE_LOW_REG              0x10 // Tune frequency set low byte 
#define CHAN_TUNE_HI_REG               0x11 // Tune frequency set high byte 
#define START_TUNE_REG                 0x12 // sequencer setting register 
#define FINE_TUNE_SET_REG              0x13 // Fine tune operation register 
#define FINE_TUNE_CTRL_REG_0           0x13 // Fine tune operation register 
#define FINE_TUNE_CTRL_REG_1           0x14 // Fine tune operation register 

#define FINE_TUNE_OFFSET_LOW_REG       0x14 // Fine tune frequency offset low byte 
#define FINE_TUNE_OFFSET_HIGH_REG      0x15 // Fine tune frequency offset high byte
#define CHIP_ID_REQ_REG                0x18 // Tuner Chip ID register 
#define CHIP_VERSION_REQ_REG           0x1A // Tuner Chip Revision register 

#define RFPIN_RB_LOW_REG               0x1D // RF power low 8 bit register 
#define RFPIN_RB_HIGH_REG              0x1E // RF power high 8 bit register 
#define SIGNAL_TYPE_REG                0x1E // Signal type

#define DFE_CTRL_ACCUM_LOW_REG         0x24 // Bit<7:0> 
#define DFE_CTRL_ACCUM_MID_REG         0x25 // Bit<7:0>
#define DFE_CTRL_ACCUM_HI_REG          0x26 // Bit<1:0>

#define DFE_CTRL_TRIG_REG              0xA0 // Bit<3>
#define DFE_CTRL_RB_HI_REG             0x7B // Bit<7:0>
#define DFE_CTRL_RB_LOW_REG            0x7A // Bit<1:0>

#define RF_REF_STATUS_REG              0x2B // RF/REF lock status register 

#define AGC_SAGCLOCK_STATUS_REG        0x2C 

#define DFE_DACIF_BYP_GAIN_REG         0x43 
#define DIG_ANA_RFRSSI_REG             0x57 

#define RSSI_RESET_REG                 0x78
#define DIG_ANA_GINJO_LT_REG           0x96 
#define FINE_TUNE_INIT1_REG            0xA9 
#define FINE_TUNE_INIT2_REG            0xAA

#define DFE_AGC_CEIL1_REG              0xB0 

#define DFE_RFLUT_BYP_REG              0xDB  // Dec: 220, bit<7>
#define DFE_RFLUT_DIV_MOD_REG          0xDB  // Dec: 221 

#define DFE_RFLUT_SWP1_REG             0x49 

#define DFE_RFSX_FRAC_MOD1_REG         0xDF
#define DFE_RFSX_FRAC_MOD2_REG         0xE0
#define DFE_RFSX_FRAC_MOD3_REG         0xE1
#define DFE_RFSX_FRAC_MOD4_REG         0xE2

#define DFE_REFLUT_BYP_REG             0xEA  // Dec: 240, bit<6>
#define DFE_REFSX_INT_MOD_REG          0xEB  // Dec: 241

#define APP_MODE_FREQ_HZ_THRESHOLD_1   358000000
#define APP_MODE_FREQ_HZ_THRESHOLD_2   625000000

#define IF_GAIN_SET_POINT1             10 
#define IF_GAIN_SET_POINT2             11 
#define IF_GAIN_SET_POINT3             12 

#define DIG_ANA_IF_CFG_0              0x5A
#define DIG_ANA_IF_CFG_1              0x5B
#define DIG_ANA_IF_PWR                0x5C

#define DFE_CSF_SS_SEL                0xEA
#define DFE_DACIF_GAIN                0xDC

#define FINE_TUNE_FREQ_INCREASE       0x01
#define FINE_TUNE_FREQ_DECREASE       0x02

#define RF_SX_FRAC_N_RANGE            0xDD

#define HIGH_IF_35250_KHZ             35250



typedef enum 
{
  MXL_TRUE = 0,
  MXL_FALSE = 1,
  MXL_SUCCESS = 0,
  MXL_FAILED,
  MXL_BUSY,
  MXL_NULL_PTR,
  MXL_INVALID_PARAMETER,
  MXL_NOT_INITIALIZED,
  MXL_ALREADY_INITIALIZED,
  MXL_BUFFER_TOO_SMALL,
  MXL_NOT_SUPPORTED,
  MXL_TIMEOUT
} MXL_STATUS;

typedef enum{
	MxL_OK					        =  0x0,
	MxL_ERR_INIT			      =  0x1,
	MxL_ERR_RFTUNE			    =  0x2,
	MxL_ERR_SET_REG			    =  0x3,
	MxL_ERR_GET_REG			    =  0x4,
	MxL_ERR_MODE			      =  0x10,
	MxL_ERR_IF_FREQ			    =  0x11,
	MxL_ERR_XTAL_FREQ		    =  0x12,
	MxL_ERR_BANDWIDTH		    =  0x13,
	MxL_GET_ID_FAIL			    =  0x14,
	MxL_ERR_DEMOD_LOCK		  =  0x20,
	MxL_NOREADY_DEMOD_LOCK	=  0x21,
	MxL_ERR_OTHERS			    =  0x0A
}MxL_ERR_MSG;

typedef enum
{
  MXL_DISABLE = 0,
  MXL_ENABLE,

  MXL_UNLOCKED = 0,
  MXL_LOCKED,

  MXL_INVALID = 0, 
  MXL_VALID,      

  MXL_PORT_LOW = 0,
  MXL_PORT_HIGH,

  MXL_START = 0,
  MXL_FINISH,

  MXL_ABORT_TUNE = 0,
  MXL_START_TUNE,

  MXL_FINE_TUNE_STEP_DOWN = 0,
  MXL_FINE_TUNE_STEP_UP

} MXL_BOOL;

typedef enum 
{
  IFX_SUCCESS = 0,
  IFX_FAILED,
  IFX_BUSY,
  IFX_NULL_PTR,
  IFX_INVALID_PARAMETER,
  IFX_BUFFER_TOO_SMALL,
  IFX_TIMEOUT  
} IFX_STATUS;



#define MXL603_VERSION_SIZE     5

#define MXL603_I2C_ADDR 0x60//(0x60<<1), for Demod to control tuner, slave address treated as normal data -- Repeator mode 

#define MXL603_MAX_NUM_DEVICES  4


 
typedef struct
{
  UINT8 chipId;                           /* OUT, Device chip ID information  */
  UINT8 chipVersion;                      /* OUT, Device chip revision  */
  UINT8 mxlwareVer[MXL603_VERSION_SIZE];  /* OUT, MxLWare version information */    
} MXL603_VER_INFO_T, *PMXL603_VER_INFO_T;

typedef enum
{
  MXL603_XTAL_16MHz = 0,
  MXL603_XTAL_24MHz
} MXL603_XTAL_FREQ_E;

typedef struct
{
  MXL603_XTAL_FREQ_E xtalFreqSel;  /* IN, XTAL Frequency, refers above */
  UINT8 xtalCap;                   /* IN, XTAL capacity, 1 LSB = 1pF, maximum is 31pF */
  MXL_BOOL clkOutEnable;           /* IN, enable or disable clock out */
  MXL_BOOL clkOutDiv;              /* IN, indicate if XTAL frequency is dived by 4 or not */
  MXL_BOOL clkOutExt;              /* IN, enable or disable external clock out*/
  MXL_BOOL singleSupply_3_3V;      /* IN, Single Supply 3.3v */
  MXL_BOOL XtalSharingMode;        /* IN, XTAL sharing mode. default Master, MXL_ENABLE to config Slave mode */
} MXL603_XTAL_SET_CFG_T, *PMXL603_XTAL_SET_CFG_T;

typedef enum
{
  MXL603_PWR_MODE_SLEEP = 0,      /* power saving mode - Sleep */
  MXL603_PWR_MODE_ACTIVE,         /* power saving mode - Active */
  MXL603_PWR_MODE_STANDBY         /* power saving mode - Standby */
} MXL603_PWR_MODE_E;    

typedef enum
{
  MXL603_GPO_LOW = 0,
  MXL603_GPO_HIGH = 1,
  MXL603_GPO_AUTO_CTRL = 2
} MXL603_GPO_STATE_E;         /* GPO control*/

typedef enum
{
  MXL603_DIG_DVB_C = 0,     /* DVB-C mode */
  MXL603_DIG_ISDBT_ATSC,    /* ATSC/ISDB-T mode */
  MXL603_DIG_DVB_T_DTMB,    /* DVB-T/DVB-T2 and DTMB mode */
  MXL603_DIG_J83B           /* J.83B mode */
} MXL603_SIGNAL_MODE_E;     /* MxL603 Application mode */

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
} MXL603_IF_FREQ_E;       /* Pre-Define IF out values */

typedef struct
{
  MXL603_SIGNAL_MODE_E signalMode;       /* IN , Tuner application mode */
  MXL603_XTAL_FREQ_E xtalFreqSel;        /* XTAL Frequency, refers above */
  UINT32 ifOutFreqinKHz;                 /* IN, IF Frequency in KHz */
  UINT8 ifOutGainLevel;                  /* IF out gain level */ 
} MXL603_TUNER_MODE_CFG_T, *PMXL603_TUNER_MODE_CFG_T;

typedef enum
{
  MXL603_AGC_SELF = 0,   
  MXL603_AGC_EXTERNAL = 1 
} MXL603_AGC_TYPE_E;

typedef struct
{
  UINT8 setPoint;                   /* IN, AGC attack point set value */
  MXL_BOOL agcPolarityInverstion;   /* IN, Config AGC Polarity inversion */  
  MXL603_AGC_TYPE_E agcType;        /* IN, AGC mode selection, self or closed loop */
} MXL603_AGC_CFG_T, *PMXL603_AGC_CFG_T;

typedef enum
{
  MXL603_CABLE_BW_6MHz = 0x00,    /* Digital Cable Mode 6 MHz */      
  MXL603_CABLE_BW_7MHz = 0x01,    /* Digital Cable Mode 7 MHz */            
  MXL603_CABLE_BW_8MHz = 0x02,    /* Digital Cable Mode 8 MHz */              
  MXL603_TERR_BW_6MHz = 0x20,     /* Digital Terrestrial Mode 6 MHz */     
  MXL603_TERR_BW_7MHz = 0x21,     /* Digital Terrestrial Mode 7 MHz */    
  MXL603_TERR_BW_8MHz = 0x22      /* Digital Terrestrial Mode 8 MHz */    
} MXL603_BW_E;

typedef struct
{
  UINT32 freqInHz;                     /* IN, Radio Frequency in Hz */ 
  MXL_BOOL startTune;                  /* IN, MXL_ENABLE to start tune, MXL_DISABLE to Abort tune */
  MXL603_BW_E bandWidth;               /* IN, band width in MHz. Refer "MXL603_BW_E" */
  MXL603_SIGNAL_MODE_E signalMode;     /* IN, Tuner application mode */
  MXL603_XTAL_FREQ_E xtalFreqSel;      /* IN, Xtal frequency */
} MXL603_CHAN_TUNE_CFG_T, *PMXL603_CHAN_TUNE_CFG_T;

typedef struct
{
  MXL603_IF_FREQ_E ifOutFreq;       /* IN, band width of IF out signal */
  MXL_BOOL manualFreqSet;           /* IN, IF out frequency is set by manual or not */ 
  MXL_BOOL ifInversion;             /* IN, IF spectrum is inverted or not */
  UINT8 gainLevel;                  /* IN, IF out gain level */
  UINT32 manualIFOutFreqInKHz;      /* IN, IF out frequency selection when manualFreqSet = 0*/
}MXL603_IF_OUT_CFG_T, *PMXL603_IF_OUT_CFG_T;

typedef struct
{
  UINT8 regAddr;
  UINT8 mask;
  UINT8 data;
} MXL603_REG_CTRL_INFO_T, *PMXL603_REG_CTRL_INFO_T;



#endif
