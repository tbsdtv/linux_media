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

#ifndef STID135_DRV_H
#define STID135_DRV_H

#ifdef __cplusplus
    extern "C" {
#endif

/* ========================================================== */
// Include files

#include "fesat_commlla_str.h"
#include "fesat_pro_advance.h"
#include "oxford_anafe_func.h"
#include "stid135_initLLA_cut2.h"

/* ========================================================== */
// Typedefs - proprietary, non generic

enum fe_stid135_ber_status {
	ERR_MIN_THRESHOLD_REACHED,
	BER_THRESHOLD_REACHED,
	TOTAL_PACKETS_THRESHOLD_REACHED,
	NO_THRESHOLD_REACHED,
	TIMEOUT_REACHED,
	UNKNOWN_CONDITION
};

enum fe_stdi135_ber_per {  //gb from xxx_util.h, unmodified
	FE_STiD_BER     = 0,
	FE_STiD_BER_BIT7= 1,
	FE_STiD_PER     = 2,
	FE_STiD_BYTEER  = 3

};

enum fe_stid135_error_counter {  //gb! same but must be checked 
	FE_STiD_COUNTER1 = 0,
	FE_STiD_COUNTER2 = 1
};

enum fe_stid135_demod_wide_narrow {
        FE_STiD_NARROWBAND = 0,
        FE_STiD_WIDEBAND = 4
};

enum fe_stid135_stfe_mode {
	FE_STFE_BYPASS_MODE,
	FE_STFE_TAGGING_MODE,
	FE_STFE_TAGGING_MERGING_MODE
};

enum fe_stid135_stfe_output {
	FE_STFE_OUTPUT0,
	FE_STFE_OUTPUT1,
	FE_STFE_BOTH_OUTPUT
};

enum fe_stid135_stfe_input {
	FE_STFE_INPUT1 = 0x1,
	FE_STFE_INPUT2 = 0x2,
	FE_STFE_INPUT3 = 0x4,
	FE_STFE_INPUT4 = 0x8,
	FE_STFE_INPUT5 = 0x10,
	FE_STFE_INPUT6 = 0x20,
	FE_STFE_INPUT7 = 0x40,
	FE_STFE_INPUT8 = 0x80
};

/* ----------------  generic typedefs:	--------------------- */

#define fe_stid135_init_param fe_sat_init_params

/* Demod search state */

typedef internal_param_ptr			fe_stid135_handle_t;


typedef u32 u32;
typedef s32 s32;
typedef long long s64;
typedef unsigned long long u64;
typedef STCHIP_Handle_t stchip_handle_t;

struct pid_info
{
	u32	pid_number;
	u8	pid_is_output;
};

#define PATH0  0x0
#define PATH1  0x1   
#define PATH2  0x2
#define PATH3  0x3
#define PATH4  0x4
#define PATH5  0x5
#define PATH6  0x6
#define PATH7  0x7


/* maximum number of PIDs that can be output by demod at the same time
 RAM size = 192 bytes, command to output PID takes 2 byte
 so 192/2=96 PIDs */
#define MAXPIDNUMBER 96

/* RAM size for PID filtering feature from 0x10 to 0xCF = 192bytes*/
#define RAM_SIZE 192 // old value = 240

#define NB_SAT_MODCOD 83

struct pid_filtering
{
	struct	pid_info pid_table[MAXPIDNUMBER];
	u8	nb_output_pids;
	u8	is_enable_all_pid;
	u8	is_disable_all_pid;
	u8	is_numbering;
};

enum label_type {
	THREE_BYTE_LABEL,
	SIX_BYTE_LABEL
};

enum pid_command {
	NONE,
	ENABLE_PID,
	SELECT_RANGE,
	CHANGE_PID,
	ENABLE_ALL_PID
};

enum device_cut_id {
	STID135_UNKNOWN_CUT,
	STID135_CUT1_0,
	STID135_CUT1_1,
	STID135_CUT1_X,
	STID135_CUT2_0,
	STID135_CUT2_1,
	STID135_CUT2_X_UNFUSED
};

struct pid_data {
	u8 address;
	enum pid_command command;
	u32 pid_number;
};

struct ram_byte {
	BOOL first_disable_all_command;
	struct pid_data ram_table[RAM_SIZE];
};

enum gse_command {
	NO_CMD,
	ENABLE_PROTOCOL,
	ENABLE_ALL_PROTOCOL,
	DISABLE_ALL_PROTOCOL,
	ENABLE_3BYTE_LABEL,
	ENABLE_6BYTE_LABEL,
	ENABLE_ALL_3BYTE_LABEL,
	ENABLE_ALL_6BYTE_LABEL,
	DISABLE_3BYTE_LABEL,
	DISABLE_6BYTE_LABEL,
	EXPLICIT_DELETE_ALL
};

struct gse_data {
	u8 address;
	enum gse_command command;
	u16 protocol_number;
	u8 label[6];
};

struct gse_ram_byte {
	BOOL first_disable_all_protocol_command;
	BOOL first_disable_all_label_command;
	struct gse_data ram_table[RAM_SIZE];
};

struct modcod_data {
	u16 register_address[8];
	u32 mask_value;
	s32 qef; // dBx100
	BOOL forbidden[8];
};

struct mc_array_customer {
	u8 modcod_id;
	s16 snr;
};

struct fe_stid135_internal_param {
	stchip_handle_t handle_demod; /*  Handle to a demodulator */
	stchip_handle_t handle_anafe; /*  Handle to AFE */
	stchip_handle_t handle_fpga; /*  Handle to FPGA */
	stchip_handle_t handle_soc; /*  Handle to SOC */

	enum fe_sat_rolloff roll_off[8]; /* manual RollOff for DVBS1/DSS only */
	
	/* Demod */
	enum fe_sat_search_standard	demod_search_standard[8];/* Search standard:
					Auto, DVBS1/DSS only or DVBS2 only*/
	enum fe_sat_search_algo		demod_search_algo[8]; /* Algorithm for 
						search Blind, Cold or Warm*/
	enum fe_sat_search_iq_inv	demod_search_iq_inv[8]; /* I,Q  
					inversion search : auto, auto norma 
					first, normal or inverted */
	enum fe_sat_rate		demod_puncture_rate[8];
	enum fe_sat_modcode		demod_modcode[8];
	enum fe_sat_modulation		demod_modulation[8];
	struct fe_sat_search_result	demod_results[8]; /* Results of the 
					search */
	fe_lla_error_t			demod_error[8]; /* Last error 
					encountered */
	u32				demod_symbol_rate[8], /* Symbol rate 
					(Bds) */
					demod_search_range[8]; /* Search range 
					(Hz) */
	u32				quartz;/* Demod Reference frequency (Hz) */
	u8			internal_dcdc; /* DCDC supply either internal or external */
	u8			internal_ldo; /* LDO supply either internal or external */
	u8				rf_input_type; /* VGLNA input type, either single ended or differential */
	u32				master_clock, /* Master clock frequency */
					lo_frequency; /* Temporary definition 
					for LO frequency   */
	BOOL			ts_nosync;
	BOOL	 mis;
	enum fe_sat_iq_inversion 	tuner_global_iqv_inv[8]; /* Global I,Q 
					inversion I,Q conection from tuner to 
					demod */
	tuner_handle  	h_tuner; /* Handle to the tuner 1 */
   	u32				tuner_bw[8];
	s32				tuner_frequency[8], /* Current tuner frequency (Hz) */
					tuner_index_jump[8];
	struct ram_byte			pid_flt[8];
	struct gse_ram_byte		gse_flt[8];
	struct modcod_data		mc_flt[NB_SAT_MODCOD];
	BOOL 				mis_mode[8]; /* Memorisation of MIS mode */

	struct mutex *master_lock;
};


#define FE_MAX_SLICE_NUM 256
#define SQUAREWAVE_FREQUENCY PLL_FVCO_FREQUENCY*100000/13*10/2 // 238461538 if LOF=6200MHz

struct fe_stid135_slice_list {
	u16 max_index;
	struct fe_sat_slice t_slice[FE_MAX_SLICE_NUM];
};

struct status_bit_fields {
	u8 lock_definitif : 1;
	u8 pdelsync : 2;
	u8 asymctrl_on : 1;
	u8 gstat_psd_done : 1;
	u8 distxstatus_tx_end : 1;
	u8 disrxstat1_rxend : 1;
	u8 fstatus_found_signal : 1;
	u8 tsfifo_lineok : 1;
	u8 sfec_lineok : 1;
	u8 bch : 1;
	u8 pktdelin_lock : 1;
	u8 lockedsfec : 1;
	u8 lockedvit : 1;
	u8 demod_mode : 5;
	u8 agcrf_locked : 1;
	u8 pll_lock : 1;
	u8 car_lock : 1;
	u8 timing_is_locked : 1;
	u8 tsdmaerror : 1;
	u8 dest0_status_dma_overflow : 1;
	u8 dest1_status_dma_overflow : 1;
	u8 shdb_overflow : 1;
	u8 shdb_error : 1;
	u8 demod_delock : 1;
	u8 pktdelin_delock : 1;
	u16 bbfcrcko : 16;
	u16 upcrcko : 16;
	u8 tsfifo_linenok : 1;
	u8 dil_nosync : 1;
	u8 tsfifo_error : 1;
	u8 tsfifo_error_evnt : 1;
	u32 errcnt1 : 24;
	u32 errcnt2 : 24;
};

extern u32 C8CODEW_TOP_CTRL[1];
extern u32 DVBSX_AGCRF[4];
extern u32 C8CODEW_RFMUX[1];
extern u32 DVBSX_DISEQC[4];
extern u32 C8CODEW_PATH_CTRL[8];
extern u32 C8CODEW_PATH_CTRL_GEN[4];
extern u32 DVBSX_HWARE_GEN[4];
extern u32 DVBSX_DEMOD[8];
extern u32 DVBSX_VITERBI[8];
extern u32 DVBSX_SUPERFEC[8];
extern u32 DVBSX_HWARE[8];
extern u32 DVBSX_PKTDELIN[8];
extern u32 DVBSX_FECSPY[8];
extern u32 AFE_CTRL[1];
extern u32 PIOSOUTHMUX[1];
extern u32 PIONORTHMUX[1];
extern u32 C8SECTPFE_IB[8];
extern u32 C8SECTPFE_TSDMA[1];
extern u32 SYSCONFIGS[1];
extern u32 STFECONFIG[1];
extern u32 CLOCKGENNORTH[1];
extern u32 THSENSOR[1];
extern u32 PWM[1];
extern u32 C8CODEW_DVBS2FEC[1];
extern u32 SYSCONFIGN[1];
extern u32 X5BANKPIONORTH[5];
extern u32 X5BANKPIOSOUTH[5];
extern u32 DVBSX_LNBCTRL[1];

//////////////////LNA////////////////////////////////////////
/*REG0*/
#define RSTVVGLNA_REG0  0x0000
#define FSTVVGLNA_LNA_IDENT  0x00000080
#define FSTVVGLNA_CUT_IDENT  0x00000060
#define FSTVVGLNA_RELEASE_ID  0x00000010
#define FSTVVGLNA_AGCTUPD  0x00000008
#define FSTVVGLNA_AGCTLOCK  0x00000004
#define FSTVVGLNA_RFAGCHIGH  0x00000002
#define FSTVVGLNA_RFAGCLOW  0x00000001

/*REG1*/
#define RSTVVGLNA_REG1  0x0001
#define FSTVVGLNA_LNAGCPWD  0x00010080
#define FSTVVGLNA_GETOFF  0x00010040
#define FSTVVGLNA_GETAGC  0x00010020
#define FSTVVGLNA_VGO  0x0001001f

/*REG2*/
#define RSTVVGLNA_REG2  0x0002
#define FSTVVGLNA_PATH2OFF  0x00020080
#define FSTVVGLNA_RFAGCPREF  0x00020070
#define FSTVVGLNA_PATH1OFF  0x00020008
#define FSTVVGLNA_RFAGCMODE  0x00020007

/*REG3*/
#define RSTVVGLNA_REG3  0x0003
#define FSTVVGLNA_SELGAIN  0x00030080
#define FSTVVGLNA_LCAL  0x00030070
#define FSTVVGLNA_RFAGCUPDATE  0x00030008
#define FSTVVGLNA_RFAGCCALSTART  0x00030004
#define FSTVVGLNA_SWLNAGAIN  0x00030003

#define STVVGLNA_NBREGS	4
#define STVVGLNA_NBFIELDS	20	

typedef enum
{
	VGLNA_RFAGC_HIGH,
	VGLNA_RFAGC_LOW,
	VGLNA_RFAGC_NORMAL
	
} SAT_VGLNA_STATUS;

typedef struct
{
	STCHIP_Info_t	*Chip;		/* pointer to parameters to pass to the CHIP API */
	u32 	NbDefVal;		/* number of default values (must match number of STC registers) */
} 
SAT_VGLNA_InitParams_t;

typedef SAT_VGLNA_InitParams_t SAT_VGLNA_Params_t;


/* ---------------- Private functions ---------------------- */

fe_lla_error_t  FE_STiD135_CarrierGetQuality(stchip_handle_t hChip, 
	fe_lla_lookup_t *lookup, enum fe_stid135_demod Demod, s32* c_n_p);

#ifdef HOST_PC
	fe_lla_error_t FE_STiD135_GetErrors(fe_stid135_handle_t Handle, enum fe_stid135_demod Demod, 
		double *Errors, double *bits, double *Packets, double *Ber);
	fe_lla_error_t fe_stid135_start_per(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 Mode);
	
	fe_lla_error_t fe_stid135_get_per(fe_stid135_handle_t handle, 
					enum fe_stid135_demod demod, 
					double BerTh,
					unsigned int ErrTh,
					double *Ber,
					unsigned int Timeout,
					double *NbPackets,
					double *NbErrors,
					unsigned char *Status);
	
	fe_lla_error_t fe_stid135_get_fer(fe_stid135_handle_t handle, 
					enum fe_stid135_demod demod, 
					double BerTh,
					unsigned int ErrTh,
					double *Fer,
					unsigned int Timeout,
					double *NbFrames,
					double *NbErrors,
					unsigned char *Status);
	
	fe_lla_error_t BerLoop(fe_stid135_handle_t handle, 
					enum fe_stid135_demod demod,
					double BerTh,
					unsigned int ErrTh,
					double *Ber,
					unsigned int Timeout,
					double *NbPackets,
					double *NbErrors,
					unsigned char *Status,
			      	BOOL fer_dvbs2x);
#endif

fe_lla_error_t fe_stid135_get_lock_status(fe_stid135_handle_t Handle, enum fe_stid135_demod Demod, BOOL* Locked_p);

fe_lla_error_t  FE_STiD135_GetErrorCount(stchip_handle_t hChip, 
	enum fe_stid135_error_counter Counter, enum fe_stid135_demod Demod, u32* ber_p); 

fe_lla_error_t FE_STiD135_Algo(struct fe_stid135_internal_param *pParams,
	enum fe_stid135_demod Demod, BOOL satellitte_scan, enum fe_sat_signal_type *signalType_p);

fe_lla_error_t FE_STiD135_GetStandard(stchip_handle_t hChip, 
	enum fe_stid135_demod Demod, enum fe_sat_tracking_standard *foundStandard_p);

TUNER_Error_t FE_STiD135_TunerInit(struct fe_stid135_internal_param *pParams);

fe_lla_error_t FE_STiD135_SetSearchStandard(struct fe_stid135_internal_param *pParams, 
	enum fe_stid135_demod Demod);

fe_lla_error_t get_soc_block_freq(fe_stid135_handle_t Handle, u8 clkout_number, u32* clkout_p);

fe_lla_error_t  FE_STiD135_GetMclkFreq (fe_stid135_handle_t Handle, u32* MclkFreq_p);

fe_lla_error_t  FE_STiD135_GetLoFreqHz (fe_stid135_handle_t Handle, u32* LoFreq_p);

fe_lla_error_t FE_STiD135_WaitForLock(fe_stid135_handle_t Handle,enum fe_stid135_demod Demod,
			u32 DemodTimeOut,u32 FecTimeOut,BOOL satellitte_scan, s32* lock_p);


/* ---------------- Exported functions (API) ---------------------- */
fe_lla_error_t fe_stid135_get_signal_quality(fe_stid135_handle_t Handle,
					enum fe_stid135_demod demod,
					struct fe_sat_signal_info *pInfo,
					int mc_auto);

fe_lla_error_t fe_stid135_get_signal_info(fe_stid135_handle_t Handle,  
	enum fe_stid135_demod Demod, struct fe_sat_signal_info *pInfo, 
	u32 satellitte_scan);

fe_lla_error_t fe_stid135_tracking(fe_stid135_handle_t Handle, enum fe_stid135_demod Demod, 
				       struct fe_sat_tracking_info *pTrackingInfo)  ;

fe_lla_error_t FE_STiD135_Term(fe_stid135_handle_t Handle);

fe_lla_error_t	fe_stid135_search  (fe_stid135_handle_t handle, enum fe_stid135_demod demod,
	struct fe_sat_search_params *pSearch, struct fe_sat_search_result *pResult, 
	BOOL satellitte_scan);

fe_lla_error_t  fe_stid135_init    (struct fe_sat_init_params *pInit,
	fe_stid135_handle_t *Handle);

ST_Revision_t FE_STiD135_GetRevision(void);

fe_lla_error_t FE_STiD135_GetStatus(fe_stid135_handle_t Handle, enum fe_stid135_demod Demod, struct status_bit_fields* status_p);

fe_lla_error_t fe_stid135_reset_obs_registers(fe_stid135_handle_t Handle, enum fe_stid135_demod Demod);

fe_lla_error_t fe_stid135_get_matype_infos(fe_stid135_handle_t Handle,
			enum fe_stid135_demod Demod, struct fe_sat_dvbs2_matype_info_t *matype_infos);

fe_lla_error_t fe_stid135_get_slice_list(fe_stid135_handle_t Handle,
		struct fe_stid135_slice_list *SlcList, enum fe_stid135_demod Demod);

fe_lla_error_t fe_stid135_set_slice(fe_stid135_handle_t Handle,
		enum fe_stid135_demod Demod, u8 SliceID);

fe_lla_error_t fe_stid135_get_slice_info(fe_stid135_handle_t Handle,
		enum fe_stid135_demod Demod, u8 SliceId, struct fe_sat_slice *pSliceInfo);

fe_lla_error_t fe_stid135_tuner_enable(stchip_handle_t tuner_handle, FE_OXFORD_TunerPath_t tuner_nb);

fe_lla_error_t fe_stid135_set_rfmux_path(stchip_handle_t hChip,
			enum fe_stid135_demod demod, FE_OXFORD_TunerPath_t tuner);

fe_lla_error_t fe_stid135_set_ts_parallel_serial(fe_stid135_handle_t handle, enum fe_stid135_demod demod, enum fe_ts_output_mode ts_mode);

fe_lla_error_t fe_stid135_enable_stfe(fe_stid135_handle_t handle, enum fe_stid135_stfe_output stfe_output);

fe_lla_error_t fe_stid135_set_stfe(fe_stid135_handle_t handle, enum fe_stid135_stfe_mode mode, u8 stfe_input_path, 
	enum fe_stid135_stfe_output stfe_output_path, u8 tag_header);

fe_lla_error_t fe_stid135_enable_pid (fe_stid135_handle_t	handle,
     enum fe_stid135_demod	demod, u32 pid_number);

fe_lla_error_t fe_stid135_disable_pid (fe_stid135_handle_t	handle,
      enum fe_stid135_demod demod, u32 pid_number);

fe_lla_error_t fe_stid135_select_rangepid (fe_stid135_handle_t	handle,
   enum fe_stid135_demod demod,u32 pid_start_range, u32 pid_stop_range);

fe_lla_error_t fe_stid135_enable_allpid (fe_stid135_handle_t handle,
	enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_disable_allpid (fe_stid135_handle_t handle,
  enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_changepid_number (fe_stid135_handle_t handle,
	enum fe_stid135_demod demod,u32 pid_inputnumber,u32 pid_outputnumber);

fe_lla_error_t fe_stid135_disable_rangepid (fe_stid135_handle_t handle,
   enum fe_stid135_demod demod,u32 pid_start_range, u32 pid_stop_range);

fe_lla_error_t fe_stid135_enable_protocoltype(fe_stid135_handle_t handle,
enum fe_stid135_demod demod, u16 protocoltype);

fe_lla_error_t fe_stid135_disable_protocoltype(fe_stid135_handle_t handle,
 enum fe_stid135_demod demod, u16 protocoltype);

fe_lla_error_t fe_stid135_disable_allprotocoltype(fe_stid135_handle_t handle,
 enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_enable_allprotocoltype(fe_stid135_handle_t handle,
 enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_disable_allgselabel(fe_stid135_handle_t handle,
  enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_enable_allgselabel(fe_stid135_handle_t handle,
  enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_enable_gselabel(fe_stid135_handle_t handle,
    enum fe_stid135_demod demod, enum label_type gselabel_type, u8 gselabel[6]);

fe_lla_error_t fe_stid135_disable_gselabel(fe_stid135_handle_t handle,
  enum fe_stid135_demod	demod, u8 gselabel[6]);

fe_lla_error_t fe_stid135_select_ncr_source(fe_stid135_handle_t handle,
          enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_get_ncr_lock_status(fe_stid135_handle_t handle,
	  enum fe_stid135_demod demod, BOOL* ncr_lock_status_p);

fe_lla_error_t fe_stid135_set_modcodes_filter(fe_stid135_handle_t handle, 
						enum fe_stid135_demod demod,
						struct fe_sat_dvbs2_mode_t *MODCODES_MASK,
						s32 NbModes);

fe_lla_error_t fe_stid135_reset_modcodes_filter(fe_stid135_handle_t handle,
					       enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_modcodes_inventory(fe_stid135_handle_t handle,
						enum fe_stid135_demod demod,
						u8 *MODES_Inventory,
						u8 *NbModes, 
						u16 Duration);

fe_lla_error_t fe_stid135_filter_forbidden_modcodes(fe_stid135_handle_t handle,   
						enum fe_stid135_demod demod,
						s32 cnr);

fe_lla_error_t fe_stid135_get_soc_temperature(fe_stid135_handle_t handle, s16 *soc_temp);

fe_lla_error_t fe_stid135_isi_scan(fe_stid135_handle_t handle, enum fe_stid135_demod demod, struct fe_sat_isi_struct_t *p_isi_struct);

fe_lla_error_t fe_stid135_get_list_isi(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 *p_min_isi, u8 *p_max_isi);

fe_lla_error_t fe_stid135_get_isi(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 *p_isi_current);

fe_lla_error_t fe_stid135_select_isi(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 isi_wanted);

fe_lla_error_t fe_stid135_set_mis_filtering(fe_stid135_handle_t Handle, enum fe_stid135_demod demod, BOOL EnableFiltering, u8 mis_filter, u8 mis_mask);

fe_lla_error_t fe_stid135_unlock(fe_stid135_handle_t handle, enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_set_abort_flag(fe_stid135_handle_t handle, BOOL abort);

fe_lla_error_t fe_stid135_set_standby(fe_stid135_handle_t handle, u8 standby_on);

fe_lla_error_t fe_stid135_clear_filter_ram(fe_stid135_handle_t handle, enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_get_packet_error_rate(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u32 *packets_error_count, u32 *total_packets_count);

fe_lla_error_t FE_STiD135_GetRFLevel(fe_stid135_handle_t handle, 
			enum fe_stid135_demod Demod, s32 *pch_rf, s32 *pband_rf);

fe_lla_error_t fe_stid135_unselect_ncr(fe_stid135_handle_t handle,
          enum fe_stid135_demod demod);
fe_lla_error_t	fe_stid135_set_maxllr_rate( fe_stid135_handle_t handle,
		enum fe_stid135_demod demod, u32 maxllr_rate);

fe_lla_error_t FE_STiD135_TunerStandby(stchip_handle_t TunerHandle, FE_OXFORD_TunerPath_t TunerNb, u8 Enable);

fe_lla_error_t fe_stid135_get_band_power_demod_not_locked(fe_stid135_handle_t handle, 
			enum fe_stid135_demod Demod, s32 *pband_rf);

fe_lla_error_t fe_stid135_get_cut_id(fe_stid135_handle_t Handle, enum device_cut_id *cut_id);

fe_lla_error_t fe_stid135_apply_custom_qef_for_modcod_filter(fe_stid135_handle_t handle, struct mc_array_customer *mc_flt);

fe_lla_error_t fe_stid135_multi_normal_short_tuning(fe_stid135_handle_t handle);

fe_lla_error_t fe_stid135_init_before_bb_flt_calib(fe_stid135_handle_t handle,
	FE_OXFORD_TunerPath_t tuner_nb, BOOL squarewave_generation);

fe_lla_error_t fe_stid135_uninit_after_bb_flt_calib(fe_stid135_handle_t handle, FE_OXFORD_TunerPath_t tuner_nb);

fe_lla_error_t fe_stid135_measure_harmonic(fe_stid135_handle_t handle, u32 desired_frequency, u8 harmonic, u32 *val_5bin);
fe_lla_error_t fe_stid135_bb_flt_calib(fe_stid135_handle_t handle, FE_OXFORD_TunerPath_t tuner_nb);

fe_lla_error_t fe_stid135_set_gold_code(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u32 goldcode);
fe_lla_error_t fe_stid135_set_goldcold_root(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u32 goldcold_root);
fe_lla_error_t fe_stid135_disable_goldcold(fe_stid135_handle_t handle, enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_set_pls(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 pls_mode, u32 pls_code );
fe_lla_error_t fe_stid135_get_pls(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 *p_mode, u32 *p_code );

fe_lla_error_t fe_stid135_diseqc_init(fe_stid135_handle_t handle, FE_OXFORD_TunerPath_t tuner_nb, enum fe_sat_diseqc_txmode diseqc_mode);

fe_lla_error_t fe_stid135_diseqc_receive(fe_stid135_handle_t handle, u8 *data, u8 *nbdata);

fe_lla_error_t fe_stid135_diseqc_send(fe_stid135_handle_t handle, FE_OXFORD_TunerPath_t tuner_nb, u8 *data, u8 nbdata);

fe_lla_error_t fe_stid135_diseqc_reset(fe_stid135_handle_t handle, FE_OXFORD_TunerPath_t tuner_nb);

fe_lla_error_t fe_stid135_set_22khz_cont(fe_stid135_handle_t handle, FE_OXFORD_TunerPath_t tuner_nb, BOOL tone);

fe_lla_error_t fe_stid135_set_vtm(fe_stid135_handle_t handle, enum fe_stid135_demod demod,
	u32 frequency_hz, u32 symbol_rate, enum fe_sat_rolloff roll_off);

fe_lla_error_t fe_stid135_unset_vtm(fe_stid135_handle_t handle, enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_enable_constel_display(fe_stid135_handle_t handle, enum fe_stid135_demod demod,
						u8 measuring_point);

fe_lla_error_t fe_stid135_disable_constel_display(fe_stid135_handle_t handle, enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_set_carrier_frequency_init(fe_stid135_handle_t Handle,
				s32 frequency_hz, enum fe_stid135_demod demod);
fe_lla_error_t fe_stid135_set_symbol_rate(stchip_handle_t hchip, u32 master_clock,
				u32 symbol_rate, enum fe_stid135_demod demod);

fe_lla_error_t fe_stid135_manage_matype_info(fe_stid135_handle_t handle,
						enum fe_stid135_demod Demod);

STCHIP_Error_t stvvglna_init(SAT_VGLNA_Params_t *InitParams, STCHIP_Handle_t *hChipHandle);
STCHIP_Error_t stvvglna_set_standby(STCHIP_Handle_t hChip, U8 StandbyOn);
STCHIP_Error_t stvvglna_get_status(STCHIP_Handle_t hChip, U8 *Status);
STCHIP_Error_t stvvglna_get_gain(STCHIP_Handle_t hChip,S32 *Gain);
STCHIP_Error_t stvvglna_term(STCHIP_Handle_t hChip);
fe_lla_error_t get_current_llr(fe_stid135_handle_t handle,enum fe_stid135_demod demod_path,s32 *current_llr);

#ifdef __cplusplus
    }
#endif

#endif  /* ndef STID135_DRV_H */
