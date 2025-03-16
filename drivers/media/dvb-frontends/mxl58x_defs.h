/*
 * Defines for the Maxlinear MX58x family of tuners/demods
 *
 * Copyright (C) 2014 Digital Devices GmbH
 *
 * based on code:
 * Copyright (c) 2011-2013 MaxLinear, Inc. All rights reserved
 * which was released under GPL V2
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, as published by the Free Software Foundation.
 */

typedef enum 
{
  MXL_DISABLE = 0,
  MXL_ENABLE  = 1,  
        
  MXL_FALSE = 0,
  MXL_TRUE  = 1,  

  MXL_INVALID = 0,
  MXL_VALID   = 1,

  MXL_NO      = 0,
  MXL_YES     = 1,  
  
  MXL_OFF     = 0,
  MXL_ON      = 1  
} MXL_BOOL_E;

// Firmware-Host Command IDs
typedef enum
{
  //--Device command IDs--
  MXL_HYDRA_DEV_NO_OP_CMD = 0, //No OP

  MXL_HYDRA_DEV_SET_POWER_MODE_CMD = 1,
  MXL_HYDRA_DEV_SET_OVERWRITE_DEF_CMD = 2,

  // Host-used CMD, not used by firmware
  MXL_HYDRA_DEV_FIRMWARE_DOWNLOAD_CMD = 3,

  // Additional CONTROL types from DTV
  MXL_HYDRA_DEV_SET_BROADCAST_PID_STB_ID_CMD = 4,
  MXL_HYDRA_DEV_GET_PMM_SLEEP_CMD = 5,

  //--Tuner command IDs--
  MXL_HYDRA_TUNER_TUNE_CMD = 6,
  MXL_HYDRA_TUNER_GET_STATUS_CMD = 7,

  //--Demod command IDs--
  MXL_HYDRA_DEMOD_SET_PARAM_CMD = 8,
  MXL_HYDRA_DEMOD_GET_STATUS_CMD = 9,

  MXL_HYDRA_DEMOD_RESET_FEC_COUNTER_CMD = 10,

  MXL_HYDRA_DEMOD_SET_PKT_NUM_CMD = 11,

  MXL_HYDRA_DEMOD_SET_IQ_SOURCE_CMD = 12,
  MXL_HYDRA_DEMOD_GET_IQ_DATA_CMD = 13,

  MXL_HYDRA_DEMOD_GET_M68HC05_VER_CMD = 14,

  MXL_HYDRA_DEMOD_SET_ERROR_COUNTER_MODE_CMD = 15,

  //--- ABORT channel tune
  MXL_HYDRA_ABORT_TUNE_CMD = 16, // Abort current tune command.

  //--SWM/FSK command IDs--
  MXL_HYDRA_FSK_RESET_CMD = 17,
  MXL_HYDRA_FSK_MSG_CMD = 18,
  MXL_HYDRA_FSK_SET_OP_MODE_CMD = 19,

  //--DiSeqC command IDs--
  MXL_HYDRA_DISEQC_MSG_CMD = 20,
  MXL_HYDRA_DISEQC_COPY_MSG_TO_MAILBOX = 21,
  MXL_HYDRA_DISEQC_CFG_MSG_CMD = 22,

  //--- FFT Debug Command IDs--
  MXL_HYDRA_REQ_FFT_SPECTRUM_CMD = 23,

  // -- Demod scramblle code
  MXL_HYDRA_DEMOD_SCRAMBLE_CODE_CMD = 24,

  //---For host to know how many commands in total---
  MXL_HYDRA_LAST_HOST_CMD = 25,

  MXL_HYDRA_DEMOD_INTR_TYPE_CMD = 47,
  MXL_HYDRA_DEV_INTR_CLEAR_CMD = 48,
  MXL_HYDRA_TUNER_SPECTRUM_REQ_CMD = 53,
  MXL_HYDRA_TUNER_ACTIVATE_CMD = 55,
  MXL_HYDRA_DEV_CFG_POWER_MODE_CMD = 56,
  MXL_HYDRA_DEV_XTAL_CAP_CMD = 57,
  MXL_HYDRA_DEV_CFG_SKU_CMD = 58,
  MXL_HYDRA_TUNER_SPECTRUM_MIN_GAIN_CMD = 59,
  MXL_HYDRA_DISEQC_CONT_TONE_CFG = 60,
  MXL_HYDRA_DEV_RF_WAKE_UP_CMD = 61,
  MXL_HYDRA_DEMOD_CFG_EQ_CTRL_PARAM_CMD = 62,
  MXL_HYDRA_DEMOD_FREQ_OFFSET_SEARCH_RANGE_CMD = 63,
  MXL_HYDRA_DEV_REQ_PWR_FROM_ADCRSSI_CMD = 64,

  MXL_XCPU_PID_FLT_CFG_CMD = 65,
  MXL_XCPU_SHMEM_TEST_CMD = 66,
  MXL_XCPU_ABORT_TUNE_CMD = 67,
  MXL_XCPU_CHAN_TUNE_CMD = 68,
  MXL_XCPU_FLT_BOND_HDRS_CMD = 69,

  MXL_HYDRA_DEV_BROADCAST_WAKE_UP_CMD = 70,
  MXL_HYDRA_FSK_CFG_FSK_FREQ_CMD = 71,
  MXL_HYDRA_FSK_POWER_DOWN_CMD = 72,
  MXL_XCPU_CLEAR_CB_STATS_CMD = 73,
  MXL_XCPU_CHAN_BOND_RESTART_CMD = 74
} MXL_HYDRA_HOST_CMD_ID_E;

#define MXL_ENABLE_BIG_ENDIAN        (0)

#define MXL_HYDRA_OEM_MAX_BLOCK_WRITE_LENGTH   248

#define MXL_HYDRA_OEM_MAX_CMD_BUFF_LEN        (248)

#define MXL_HYDRA_CAP_MIN     10
#define MXL_HYDRA_CAP_MAX     33

#define MXL_HYDRA_PLID_REG_READ       0xFB   // Read register PLID
#define MXL_HYDRA_PLID_REG_WRITE      0xFC   // Write register PLID

#define MXL_HYDRA_PLID_CMD_READ       0xFD   // Command Read PLID
#define MXL_HYDRA_PLID_CMD_WRITE      0xFE   // Command Write PLID

#define MXL_HYDRA_REG_SIZE_IN_BYTES   4      // Hydra register size in bytes
#define MXL_HYDRA_I2C_HDR_SIZE        (2 * sizeof(u8))   // PLID + LEN(0xFF)
#define MXL_HYDRA_CMD_HEADER_SIZE     (MXL_HYDRA_REG_SIZE_IN_BYTES + MXL_HYDRA_I2C_HDR_SIZE)

#define MXL_HYDRA_SKU_ID_581 0
#define MXL_HYDRA_SKU_ID_584 1
#define MXL_HYDRA_SKU_ID_585 2
#define MXL_HYDRA_SKU_ID_544 3
#define MXL_HYDRA_SKU_ID_561 4
#define MXL_HYDRA_SKU_ID_582 5
#define MXL_HYDRA_SKU_ID_568 6

// macro for register write data buffer size (PLID + LEN (0xFF) + RegAddr + RegData)
#define MXL_HYDRA_REG_WRITE_LEN       (MXL_HYDRA_I2C_HDR_SIZE + (2 * MXL_HYDRA_REG_SIZE_IN_BYTES)) 

// maro to extract a single byte from 4-byte(32-bit) data
#define GET_BYTE(x,n)  (((x) >> (8*(n))) & 0xFF)

#define MAX_CMD_DATA 512

#define MXL_GET_REG_MASK_32(lsbLoc,numOfBits) ((0xFFFFFFFF >> (32 - (numOfBits))) << (lsbLoc))

#define GET_REG_FIELD_DATA(fieldName, dataPtr) read_by_mnemonic(state, fieldName, dataPtr);
#define SET_REG_FIELD_DATA(fieldName, data) update_by_mnemonic(state, fieldName, data);

#define FW_DL_SIGN (0xDEADBEEF)

#define MBIN_FORMAT_VERSION               '1'
#define MBIN_FILE_HEADER_ID               'M'
#define MBIN_SEGMENT_HEADER_ID            'S'
#define MBIN_MAX_FILE_LENGTH              (1<<23)

typedef struct
{
	u8 id;                 
	u8 fmtVersion;         
	u8 headerLen;          
	u8 numSegments;        
	u8 entryAddress[4];    
	u8 imageSize24[3];     
	u8 imageChecksum;      
	u8 reserved[4];        
} MBIN_FILE_HEADER_T;

typedef struct
{
	MBIN_FILE_HEADER_T  header;    
	u8 data[];                 
} MBIN_FILE_T;

typedef struct
{
	u8 id;                      
	u8 len24[3];                
	u8 address[4];              
} MBIN_SEGMENT_HEADER_T;


typedef struct
{
	MBIN_SEGMENT_HEADER_T header;  
	u8 data[];                 
} MBIN_SEGMENT_T;


typedef enum { MXL_CMD_WRITE = 0, MXL_CMD_READ} MXL_CMD_TYPE_E;

#define BUILD_HYDRA_CMD(cmdID, reqType, size, dataPtr, cmdBuff)		\
	do {								\
		cmdBuff[0] = ((reqType == MXL_CMD_WRITE) ? MXL_HYDRA_PLID_CMD_WRITE : MXL_HYDRA_PLID_CMD_READ); \
		cmdBuff[1] = (size > 251) ? 0xff : (u8) (size + 4);	\
		cmdBuff[2] = size;					\
		cmdBuff[3] = cmdID;					\
		cmdBuff[4] = 0x00;					\
		cmdBuff[5] = 0x00;					\
		convert_endian(MXL_ENABLE_BIG_ENDIAN, size, (u8 *)dataPtr); \
		memcpy((void *)&cmdBuff[6], dataPtr, size);		\
	} while(0) //;

typedef struct {
	u32 regAddr;
	u8 lsbPos;
	u8 numOfBits;
} MXL_REG_FIELD_T;

typedef struct {
	u32 dataSize;
	u8 data[MAX_CMD_DATA];
} MXL_DEV_CMD_DATA_T;

typedef enum
{
  MXL_HYDRA_SKU_TYPE_MIN = 0x00,
  MXL_HYDRA_SKU_TYPE_581 = 0x00,
  MXL_HYDRA_SKU_TYPE_584 = 0x01,
  MXL_HYDRA_SKU_TYPE_585 = 0x02,
  MXL_HYDRA_SKU_TYPE_544 = 0x03,
  MXL_HYDRA_SKU_TYPE_561 = 0x04,
  MXL_HYDRA_SKU_TYPE_5xx = 0x05,
  MXL_HYDRA_SKU_TYPE_5yy = 0x06,
  MXL_HYDRA_SKU_TYPE_511 = 0x07,
  MXL_HYDRA_SKU_TYPE_561_DE = 0x08,
  MXL_HYDRA_SKU_TYPE_582 = 0x09,
  MXL_HYDRA_SKU_TYPE_541 = 0x0A,
  MXL_HYDRA_SKU_TYPE_568 = 0x0B,
  MXL_HYDRA_SKU_TYPE_542 = 0x0C,
  MXL_HYDRA_SKU_TYPE_MAX = 0x0D,
} MXL_HYDRA_SKU_TYPE_E;

typedef struct
{
  MXL_HYDRA_SKU_TYPE_E skuType;
} MXL_HYDRA_SKU_COMMAND_T;


typedef  enum 
{
  MXL_HYDRA_DEMOD_ID_0 = 0,
  MXL_HYDRA_DEMOD_ID_1,
  MXL_HYDRA_DEMOD_ID_2,
  MXL_HYDRA_DEMOD_ID_3,
  MXL_HYDRA_DEMOD_ID_4,
  MXL_HYDRA_DEMOD_ID_5,
  MXL_HYDRA_DEMOD_ID_6,
  MXL_HYDRA_DEMOD_ID_7,
  MXL_HYDRA_DEMOD_MAX
} MXL_HYDRA_DEMOD_ID_E;

#define MXL_DEMOD_SCRAMBLE_SEQ_LEN  12

#define MAX_STEP_SIZE_24_XTAL_102_05_KHZ  195
#define MAX_STEP_SIZE_24_XTAL_204_10_KHZ  215
#define MAX_STEP_SIZE_24_XTAL_306_15_KHZ  203
#define MAX_STEP_SIZE_24_XTAL_408_20_KHZ  177

#define MAX_STEP_SIZE_27_XTAL_102_05_KHZ  195
#define MAX_STEP_SIZE_27_XTAL_204_10_KHZ  215
#define MAX_STEP_SIZE_27_XTAL_306_15_KHZ  203
#define MAX_STEP_SIZE_27_XTAL_408_20_KHZ  177

#define MXL_HYDRA_SPECTRUM_MIN_FREQ_KHZ  300000
#define MXL_HYDRA_SPECTRUM_MAX_FREQ_KHZ 2350000

typedef enum
{
  DMD_STANDARD_ADDR = 0,
  DMD_SPECTRUM_INVERSION_ADDR,
  DMD_SPECTRUM_ROLL_OFF_ADDR,
  DMD_SYMBOL_RATE_ADDR,
  DMD_MODULATION_SCHEME_ADDR,
  DMD_FEC_CODE_RATE_ADDR,
  DMD_SNR_ADDR,
  DMD_FREQ_OFFSET_ADDR,
  DMD_CTL_FREQ_OFFSET_ADDR,
  DMD_STR_FREQ_OFFSET_ADDR,
  DMD_FTL_FREQ_OFFSET_ADDR,
  DMD_STR_NBC_SYNC_LOCK_ADDR,
  DMD_CYCLE_SLIP_COUNT_ADDR,
  DMD_DISPLAY_IQ_ADDR,
  DMD_DVBS2_CRC_ERRORS_ADDR,
  DMD_DVBS2_PER_COUNT_ADDR,
  DMD_DVBS2_PER_WINDOW_ADDR,
  DMD_DVBS_CORR_RS_ERRORS_ADDR,
  DMD_DVBS_UNCORR_RS_ERRORS_ADDR,
  DMD_DVBS_BER_COUNT_ADDR,
  DMD_DVBS_BER_WINDOW_ADDR,
  DMD_TUNER_ID_ADDR,
  DMD_DVBS2_PILOT_ON_OFF_ADDR,
  DMD_FREQ_SEARCH_RANGE_IN_KHZ_ADDR,

  MXL_DEMOD_CHAN_PARAMS_BUFF_SIZE,
} MXL_DEMOD_CHAN_PARAMS_OFFSET_E;

typedef enum 
{
  MXL_HYDRA_TUNER_ID_0 = 0,
  MXL_HYDRA_TUNER_ID_1,
  MXL_HYDRA_TUNER_ID_2,
  MXL_HYDRA_TUNER_ID_3,
  MXL_HYDRA_TUNER_MAX
} MXL_HYDRA_TUNER_ID_E;

typedef enum
{
  MXL_HYDRA_DSS = 0,  
  MXL_HYDRA_DVBS,
  MXL_HYDRA_DVBS2,
} MXL_HYDRA_BCAST_STD_E;

typedef enum
{
  MXL_HYDRA_FEC_AUTO = 0,
  MXL_HYDRA_FEC_1_2,
  MXL_HYDRA_FEC_3_5,
  MXL_HYDRA_FEC_2_3,
  MXL_HYDRA_FEC_3_4, 
  MXL_HYDRA_FEC_4_5,
  MXL_HYDRA_FEC_5_6,
  MXL_HYDRA_FEC_6_7, 
  MXL_HYDRA_FEC_7_8,
  MXL_HYDRA_FEC_8_9,
  MXL_HYDRA_FEC_9_10,
} MXL_HYDRA_FEC_E;

typedef enum 
{
  MXL_HYDRA_MOD_AUTO = 0,
  MXL_HYDRA_MOD_QPSK,
  MXL_HYDRA_MOD_8PSK
} MXL_HYDRA_MODULATION_E;

typedef enum 
{
  MXL_HYDRA_SPECTRUM_AUTO = 0,
  MXL_HYDRA_SPECTRUM_INVERTED,
  MXL_HYDRA_SPECTRUM_NON_INVERTED,
} MXL_HYDRA_SPECTRUM_E;

typedef enum 
{
  MXL_HYDRA_ROLLOFF_AUTO  = 0,
  MXL_HYDRA_ROLLOFF_0_20,
  MXL_HYDRA_ROLLOFF_0_25,
  MXL_HYDRA_ROLLOFF_0_35
} MXL_HYDRA_ROLLOFF_E;

typedef enum 
{
  MXL_HYDRA_PILOTS_OFF  = 0,
  MXL_HYDRA_PILOTS_ON,
  MXL_HYDRA_PILOTS_AUTO
} MXL_HYDRA_PILOTS_E;

typedef enum
{
  MXL_HYDRA_FORMATTER = 0,
  MXL_HYDRA_LEGACY_FEC,
  MXL_HYDRA_FREQ_RECOVERY,
  MXL_HYDRA_NBC,
  MXL_HYDRA_CTL, 
  MXL_HYDRA_EQ,
} MXL_HYDRA_CONSTELLATION_SRC_E;

typedef struct
{
  int agcLock;     // AGC lock info
  int fecLock;     // Demod FEC block lock info
} MXL_HYDRA_DEMOD_LOCK_T;

typedef struct 
{
  u32 rsErrors;          // RS decoder err counter
  u32 berWindow;         // Ber Windows
  u32 berCount;          // BER count
  u32 berWindow_Iter1;   // Ber Windows - post viterbi
  u32 berCount_Iter1;    // BER count - post viterbi
} MXL_HYDRA_DEMOD_STATUS_DVBS_T;

typedef struct 
{
  u32 rsErrors;    // RS decoder err counter
  u32 berWindow;   // Ber Windows
  u32 berCount;    // BER count
} MXL_HYDRA_DEMOD_STATUS_DSS_T;

typedef struct 
{
  u32 crcErrors;         // CRC error counter
  u32 packetErrorCount;  // Number of packet errors 
  u32 totalPackets;      // Total packets   
} MXL_HYDRA_DEMOD_STATUS_DVBS2_T;

typedef struct
{
  MXL_HYDRA_BCAST_STD_E standardMask;                // Standard DVB-S, DVB-S2 or DSS

  union
  {
    MXL_HYDRA_DEMOD_STATUS_DVBS_T demodStatus_DVBS;    // DVB-S demod status
    MXL_HYDRA_DEMOD_STATUS_DVBS2_T demodStatus_DVBS2;  // DVB-S2 demod status
    MXL_HYDRA_DEMOD_STATUS_DSS_T demodStatus_DSS;      // DSS demod status
  } u;

} MXL_HYDRA_DEMOD_STATUS_T;

typedef struct
{
  s32 carrierOffsetInHz;       // CRL offset info
  s32 symbolOffsetInSymbol;    // SRL offset info 
} MXL_HYDRA_DEMOD_SIG_OFFSET_INFO_T;

typedef struct
{
  u8 scrambleSequence[MXL_DEMOD_SCRAMBLE_SEQ_LEN];   // scramble sequence
  u32 scrambleCode;                                  // scramble gold code 
} MXL_HYDRA_DEMOD_SCRAMBLE_INFO_T;

typedef enum
{
  MXL_HYDRA_STEP_SIZE_24_XTAL_102_05KHZ,  // 102.05 KHz for 24 MHz XTAL 
  MXL_HYDRA_STEP_SIZE_24_XTAL_204_10KHZ,  // 204.10 KHz for 24 MHz XTAL 
  MXL_HYDRA_STEP_SIZE_24_XTAL_306_15KHZ,  // 306.15 KHz for 24 MHz XTAL 
  MXL_HYDRA_STEP_SIZE_24_XTAL_408_20KHZ,  // 408.20 KHz for 24 MHz XTAL 

  MXL_HYDRA_STEP_SIZE_27_XTAL_102_05KHZ,  // 102.05 KHz for 27 MHz XTAL 
  MXL_HYDRA_STEP_SIZE_27_XTAL_204_35KHZ,  // 204.35 KHz for 27 MHz XTAL 
  MXL_HYDRA_STEP_SIZE_27_XTAL_306_52KHZ,  // 306.52 KHz for 27 MHz XTAL 
  MXL_HYDRA_STEP_SIZE_27_XTAL_408_69KHZ,  // 408.69 KHz for 27 MHz XTAL 

} MXL_HYDRA_SPECTRUM_STEP_SIZE_E;

typedef enum
{
  MXL_HYDRA_SPECTRUM_RESOLUTION_00_1_DB, // 0.1 dB
  MXL_HYDRA_SPECTRUM_RESOLUTION_01_0_DB, // 1.0 dB
  MXL_HYDRA_SPECTRUM_RESOLUTION_05_0_DB, // 5.0 dB
  MXL_HYDRA_SPECTRUM_RESOLUTION_10_0_DB, // 10 dB
} MXL_HYDRA_SPECTRUM_RESOLUTION_E;

typedef enum
{
    MXL_SPECTRUM_NO_ERROR,
    MXL_SPECTRUM_INVALID_PARAMETER,
    MXL_SPECTRUM_INVALID_STEP_SIZE,
    MXL_SPECTRUM_BW_CANNOT_BE_COVERED,
    MXL_SPECTRUM_DEMOD_BUSY,
    MXL_SPECTRUM_TUNER_NOT_ENABLED,
 
} MXL_HYDRA_SPECTRUM_ERROR_CODE_E;

typedef struct
{
  u32 tunerIndex;        // TUNER Ctrl: one of MXL58x_TUNER_ID_E 
  u32 demodIndex;        // DEMOD Ctrl: one of MXL58x_DEMOD_ID_E  
  MXL_HYDRA_SPECTRUM_STEP_SIZE_E stepSizeInKHz;
  u32 startingFreqInkHz;
  u32 totalSteps;
  MXL_HYDRA_SPECTRUM_RESOLUTION_E spectrumDivision;
} MXL_HYDRA_SPECTRUM_REQ_T;

typedef enum
{
 MXL_HYDRA_SEARCH_MAX_OFFSET = 0, // DMD searches for max freq offset (i.e. 5MHz)
 MXL_HYDRA_SEARCH_BW_PLUS_ROLLOFF, // DMD searches for BW + ROLLOFF/2
} MXL_HYDRA_SEARCH_FREQ_OFFSET_TYPE_E;

typedef struct
{
  u32 demodIndex;
  MXL_HYDRA_SEARCH_FREQ_OFFSET_TYPE_E searchType;
} MXL58x_CFG_FREQ_OFF_SEARCH_RANGE_T;




// there are two slices
// slice0 - TS0, TS1, TS2 & TS3
// slice1 - TS4, TS5, TS6 & TS7
#define MXL_HYDRA_TS_SLICE_MAX  2

#define MAX_FIXED_PID_NUM   32

#define MXL_HYDRA_NCO_CLK   418 // 418 MHz

#define MXL_HYDRA_MAX_TS_CLOCK  139 // 139 MHz

#define MXL_HYDRA_TS_FIXED_PID_FILT_SIZE          32

#define MXL_HYDRA_SHARED_PID_FILT_SIZE_DEFAULT    33   // Shared PID filter size in 1-1 mux mode
#define MXL_HYDRA_SHARED_PID_FILT_SIZE_2_TO_1     66   // Shared PID filter size in 2-1 mux mode
#define MXL_HYDRA_SHARED_PID_FILT_SIZE_4_TO_1     132  // Shared PID filter size in 4-1 mux mode

typedef enum
{
  MXL_HYDRA_SOFTWARE_PID_BANK = 0,
  MXL_HYDRA_HARDWARE_PID_BANK,
} MXL_HYDRA_PID_BANK_TYPE_E;

typedef enum
{
  MXL_HYDRA_TS_MUX_PID_REMAP = 0,   
  MXL_HYDRA_TS_MUX_PREFIX_EXTRA_HEADER = 1,   
} MXL_HYDRA_TS_MUX_MODE_E;

typedef enum
{
  MXL_HYDRA_TS_MUX_DISABLE = 0,  // No Mux ( 1 TSIF to 1 TSIF)
  MXL_HYDRA_TS_MUX_2_TO_1,       // Mux 2 TSIF to 1 TSIF
  MXL_HYDRA_TS_MUX_4_TO_1,       // Mux 4 TSIF to 1 TSIF
} MXL_HYDRA_TS_MUX_TYPE_E;

typedef enum
{
  MXL_HYDRA_TS_GROUP_0_3 = 0,     // TS group 0 to 3 (TS0, TS1, TS2 & TS3)
  MXL_HYDRA_TS_GROUP_4_7,         // TS group 0 to 3 (TS4, TS5, TS6 & TS7)
} MXL_HYDRA_TS_GROUP_E;

typedef enum
{
  MXL_HYDRA_TS_PIDS_ALLOW_ALL = 0,    // Allow all pids
  MXL_HYDRA_TS_PIDS_DROP_ALL,         // Drop all pids
  MXL_HYDRA_TS_INVALIDATE_PID_FILTER, // Delete current PD filter in the device

} MXL_HYDRA_TS_PID_FLT_CTRL_E;

typedef enum
{ 
  MXL_HYDRA_TS_PID_FIXED = 0,
  MXL_HYDRA_TS_PID_REGULAR,
} MXL_HYDRA_TS_PID_TYPE_E;

typedef struct
{
	u16 originalPid;           // pid from TS
	u16 remappedPid;           // remapped pid
	MXL_BOOL_E enable;            // enable or disable pid
	MXL_BOOL_E allowOrDrop;       // allow or drop pid
	MXL_BOOL_E enablePidRemap;    // enable or disable pid remap
	u8 bondId;                 // Bond ID in A0 always 0 - Only for 568 Sku
	u8 destId;                 // Output port ID for the PID - Only for 568 Sku
} MXL_HYDRA_TS_PID_T;

typedef struct
{  
  MXL_BOOL_E enable;
  u8 numByte;
  u8 header[12];
} MXL_HYDRA_TS_MUX_PREFIX_HEADER_T;

typedef enum
{
  MXL_HYDRA_PID_BANK_A = 0,
  MXL_HYDRA_PID_BANK_B,
} MXL_HYDRA_PID_FILTER_BANK_E;

typedef enum
{
  MXL_HYDRA_MPEG_SERIAL_MSB_1ST = 0,
  MXL_HYDRA_MPEG_SERIAL_LSB_1ST,
  
  MXL_HYDRA_MPEG_SYNC_WIDTH_BIT = 0,
  MXL_HYDRA_MPEG_SYNC_WIDTH_BYTE
} MXL_HYDRA_MPEG_DATA_FMT_E;

typedef enum
{
  MXL_HYDRA_MPEG_MODE_SERIAL_4_WIRE = 0,   // MPEG 4 Wire serial mode
  MXL_HYDRA_MPEG_MODE_SERIAL_3_WIRE,       // MPEG 3 Wire serial mode  
  MXL_HYDRA_MPEG_MODE_SERIAL_2_WIRE,       // MPEG 2 Wire serial mode
  MXL_HYDRA_MPEG_MODE_PARALLEL             // MPEG parallel mode - valid only for MxL581
} MXL_HYDRA_MPEG_MODE_E;

typedef enum
{
  MXL_HYDRA_MPEG_CLK_CONTINUOUS = 0,  // Continuous MPEG clock
  MXL_HYDRA_MPEG_CLK_GAPPED,          // Gapped (gated) MPEG clock
} MXL_HYDRA_MPEG_CLK_TYPE_E;

typedef enum
{
  MXL_HYDRA_MPEG_ACTIVE_LOW = 0,
  MXL_HYDRA_MPEG_ACTIVE_HIGH,

  MXL_HYDRA_MPEG_CLK_NEGATIVE = 0,
  MXL_HYDRA_MPEG_CLK_POSITIVE,

  MXL_HYDRA_MPEG_CLK_IN_PHASE = 0,
  MXL_HYDRA_MPEG_CLK_INVERTED,
} MXL_HYDRA_MPEG_CLK_FMT_E;

typedef enum  
{
  MXL_HYDRA_MPEG_CLK_PHASE_SHIFT_0_DEG = 0,       
  MXL_HYDRA_MPEG_CLK_PHASE_SHIFT_90_DEG,
  MXL_HYDRA_MPEG_CLK_PHASE_SHIFT_180_DEG,
  MXL_HYDRA_MPEG_CLK_PHASE_SHIFT_270_DEG
} MXL_HYDRA_MPEG_CLK_PHASE_E;

typedef enum  
{
  MXL_HYDRA_MPEG_ERR_REPLACE_SYNC = 0,       
  MXL_HYDRA_MPEG_ERR_REPLACE_VALID,       
  MXL_HYDRA_MPEG_ERR_INDICATION_DISABLED
} MXL_HYDRA_MPEG_ERR_INDICATION_E;

typedef struct
{ 
  int                        enable;               // Enable or Disable MPEG OUT
  MXL_HYDRA_MPEG_CLK_TYPE_E         mpegClkType;          // Continuous or gapped
  MXL_HYDRA_MPEG_CLK_FMT_E          mpegClkPol;           // MPEG Clk polarity
  u8                             maxMpegClkRate;       // Max MPEG Clk rate (0  104 MHz, 139 MHz) 
  MXL_HYDRA_MPEG_CLK_PHASE_E        mpegClkPhase;         // MPEG Clk phase 
  MXL_HYDRA_MPEG_DATA_FMT_E         lsbOrMsbFirst;        // LSB first or MSB first in TS transmission
  MXL_HYDRA_MPEG_DATA_FMT_E         mpegSyncPulseWidth;   // MPEG SYNC pulse width (1-bit or 1-byte)  
  MXL_HYDRA_MPEG_CLK_FMT_E          mpegValidPol;         // MPEG VALID polarity
  MXL_HYDRA_MPEG_CLK_FMT_E          mpegSyncPol;          // MPEG SYNC polarity 
  MXL_HYDRA_MPEG_MODE_E             mpegMode;             // config 4/3/2-wire serial or parallel TS out
  MXL_HYDRA_MPEG_ERR_INDICATION_E   mpegErrorIndication;  // Enable or Disable MPEG error indication
} MXL_HYDRA_MPEGOUT_PARAM_T;

typedef enum
{
  MXL_HYDRA_EXT_TS_IN_0 = 0,
  MXL_HYDRA_EXT_TS_IN_1,
  MXL_HYDRA_EXT_TS_IN_2,
  MXL_HYDRA_EXT_TS_IN_3,
  MXL_HYDRA_EXT_TS_IN_MAX

} MXL_HYDRA_EXT_TS_IN_ID_E;

typedef  enum
{
  MXL_HYDRA_TS_OUT_0 = 0,
  MXL_HYDRA_TS_OUT_1,
  MXL_HYDRA_TS_OUT_2,
  MXL_HYDRA_TS_OUT_3,
  MXL_HYDRA_TS_OUT_4,
  MXL_HYDRA_TS_OUT_5,
  MXL_HYDRA_TS_OUT_6,
  MXL_HYDRA_TS_OUT_7,
  MXL_HYDRA_TS_OUT_MAX

} MXL_HYDRA_TS_OUT_ID_E;

typedef  enum 
{
  MXL_HYDRA_TS_DRIVE_STRENGTH_1x = 0,
  MXL_HYDRA_TS_DRIVE_STRENGTH_2x,
  MXL_HYDRA_TS_DRIVE_STRENGTH_3x,
  MXL_HYDRA_TS_DRIVE_STRENGTH_4x,
  MXL_HYDRA_TS_DRIVE_STRENGTH_5x,
  MXL_HYDRA_TS_DRIVE_STRENGTH_6x,
  MXL_HYDRA_TS_DRIVE_STRENGTH_7x,
  MXL_HYDRA_TS_DRIVE_STRENGTH_8x

} MXL_HYDRA_TS_DRIVE_STRENGTH_E;

typedef enum
{
  MXL_HYDRA_DEVICE_581 = 0,
  MXL_HYDRA_DEVICE_584,
  MXL_HYDRA_DEVICE_585,
  MXL_HYDRA_DEVICE_544,
  MXL_HYDRA_DEVICE_561,
  MXL_HYDRA_DEVICE_TEST,
  MXL_HYDRA_DEVICE_582,
  MXL_HYDRA_DEVICE_541,
  MXL_HYDRA_DEVICE_568,
  MXL_HYDRA_DEVICE_542,
  MXL_HYDRA_DEVICE_541S,
  MXL_HYDRA_DEVICE_561S,
  MXL_HYDRA_DEVICE_581S,
  MXL_HYDRA_DEVICE_MAX
} MXL_HYDRA_DEVICE_E;


// Demod IQ data
typedef struct
{
  u32 demodId;       
  u32 sourceOfIQ;                  // ==0, it means I/Q comes from Formatter
                                      // ==1, Legacy FEC
                                      // ==2, Frequency Recovery
                                      // ==3, NBC
                                      // ==4, CTL
                                      // ==5, EQ
                                      // ==6, FPGA
} MXL_HYDRA_DEMOD_IQ_SRC_T;

typedef struct
{
  u32 demodId;
} MXL_HYDRA_DEMOD_ABORT_TUNE_T;

typedef struct
{
  u8 tunerId;
  u8 enable;
} MxL_HYDRA_TUNER_CMD;

// Demod Para for Channel Tune
typedef struct
{
  u32 tunerIndex;
  u32 demodIndex;
  u32 frequencyInHz;     // Frequency
  u32 standard;          // one of MXL_HYDRA_BCAST_STD_E 
  u32 spectrumInversion; // Input : Spectrum inversion.
  u32 rollOff;           /* rollOff (alpha) factor */
  u32 symbolRateInHz;    /* Symbol rate */
  u32 pilots;            /* TRUE = pilots enabled */
  u32 modulationScheme;  // Input : Modulation Scheme is one of MXL_HYDRA_MODULATION_E 
  u32 fecCodeRate;       // Input : Forward error correction rate. Is one of MXL_HYDRA_FEC_E 
  u32 maxCarrierOffsetInMHz; // Maximum carrier freq offset in MHz. Same as freqSearchRangeKHz, but in unit of MHz.
} MXL_HYDRA_DEMOD_PARAM_T;

typedef struct
{
	u32 demodIndex;
	u8 scrambleSequence[12];       // scramble sequence
	u32 scrambleCode;              // scramble gold code 
} MXL_HYDRA_DEMOD_SCRAMBLE_CODE_T;

typedef struct
{
  u32  intrType;  
  u32  intrDurationInNanoSecs;
  u32  intrMask;
} MXL_INTR_CFG_T;

typedef struct 
{
   u8 powerMode;       // enumeration values are defined in MXL_HYDRA_PWR_MODE_E (device API.h)
} MxL_HYDRA_POWER_MODE_CMD;


typedef struct
{
  u32  timeIntervalInSeconds; // in seconds
  u32  tunerIndex;
  s32  rssiThreshold;
    
} MXL_HYDRA_RF_WAKEUP_PARAM_T;

typedef struct
{
  u32  tunerCount;
  MXL_HYDRA_RF_WAKEUP_PARAM_T params;
} MXL_HYDRA_RF_WAKEUP_CFG_T;


typedef enum
{
  MXL_HYDRA_AUX_CTRL_MODE_FSK = 0,  // Select FSK controller
  MXL_HYDRA_AUX_CTRL_MODE_DISEQC,   // Select DiSEqC controller
} MXL_HYDRA_AUX_CTRL_MODE_E;


typedef enum
{ 
  MXL_HYDRA_DISEQC_ENVELOPE_MODE = 0, 
  MXL_HYDRA_DISEQC_TONE_MODE,         
} MXL_HYDRA_DISEQC_OPMODE_E;

typedef enum
{
  MXL_HYDRA_DISEQC_1_X = 0,    // Config DiSEqC 1.x mode
  MXL_HYDRA_DISEQC_2_X,        // Config DiSEqC 2.x mode                          
  MXL_HYDRA_DISEQC_DISABLE     // Disable DiSEqC 
} MXL_HYDRA_DISEQC_VER_E;

typedef enum
{
  MXL_HYDRA_DISEQC_CARRIER_FREQ_22KHZ= 0,   // DiSEqC signal frequency of 22 KHz
  MXL_HYDRA_DISEQC_CARRIER_FREQ_33KHZ,      // DiSEqC signal frequency of 33 KHz                            
  MXL_HYDRA_DISEQC_CARRIER_FREQ_44KHZ       // DiSEqC signal frequency of 44 KHz 
} MXL_HYDRA_DISEQC_CARRIER_FREQ_E;

typedef enum 
{
  MXL_HYDRA_DISEQC_ID_0 = 0,
  MXL_HYDRA_DISEQC_ID_1, 
  MXL_HYDRA_DISEQC_ID_2,
  MXL_HYDRA_DISEQC_ID_3
} MXL_HYDRA_DISEQC_ID_E;

typedef enum
{
  MXL_HYDRA_FSK_CFG_TYPE_39KPBS = 0,    // 39.0kbps  
  MXL_HYDRA_FSK_CFG_TYPE_39_017KPBS,    // 39.017kbps  
  MXL_HYDRA_FSK_CFG_TYPE_115_2KPBS      // 115.2kbps
} MXL_HYDRA_FSK_OP_MODE_E;


typedef struct
{
	u32 diseqcId;  // DSQ 0, 1, 2 or 3
	u32 opMode;   // Envelope mode (0) or internal tone mode (1)
	u32 version;   // 0: 1.0 , 1: 1.1 , 2: Disable
	u32 centerFreq; // 0: 22KHz, 1: 33KHz and 2: 44 KHz
}MXL58x_DSQ_OP_MODE_T;

typedef struct
{  
	u32 diseqcId;
	u32 contToneFlag;  // 1: Enable , 0: Disable
} MXL_HYDRA_DISEQC_CFG_CONT_TONE_T;

#define MXL_HYDRA_DISEQC_MAX_PKT_SIZE   (32)

typedef enum
{
  MXL_HYDRA_DISEQC_TONE_NONE = 0,
  MXL_HYDRA_DISEQC_TONE_SA,
  MXL_HYDRA_DISEQC_TONE_SB
} MXL_HYDRA_DISEQC_TONE_CTRL_E;

typedef struct
{
  u32 diseqcId;
  u32 nbyte;
  u8 bufMsg[MXL_HYDRA_DISEQC_MAX_PKT_SIZE];
  MXL_HYDRA_DISEQC_TONE_CTRL_E toneBurst;
} MXL_HYDRA_DISEQC_TX_MSG_T;

