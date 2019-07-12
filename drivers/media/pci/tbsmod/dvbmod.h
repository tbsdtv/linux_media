/**
 *
 * dvbmod.h - DVB modulator kernel API
 *
 * Copyright (C) 2013 Dave Chapman <dave@dchapman.com>
 *
 */

#ifndef _DVBMOD_H_
#define _DVBMOD_H_

/**
 * Modulator API structs
 */

/* This is kept for legacy userspace support */

typedef enum fe_sec_voltage fe_sec_voltage_t;
typedef enum fe_caps fe_caps_t;
typedef enum fe_type fe_type_t;
typedef enum fe_sec_tone_mode fe_sec_tone_mode_t;
typedef enum fe_sec_mini_cmd fe_sec_mini_cmd_t;
typedef enum fe_status fe_status_t;
typedef enum fe_spectral_inversion fe_spectral_inversion_t;
typedef enum fe_code_rate fe_code_rate_t;
typedef enum fe_modulation fe_modulation_t;
typedef enum fe_transmit_mode fe_transmit_mode_t;
typedef enum fe_bandwidth fe_bandwidth_t;
typedef enum fe_guard_interval fe_guard_interval_t;
typedef enum fe_hierarchy fe_hierarchy_t;
typedef enum fe_pilot fe_pilot_t;
typedef enum fe_rolloff fe_rolloff_t;
typedef enum fe_delivery_system fe_delivery_system_t;


struct dvb_modulator_parameters {
	__u32			frequency_khz;   /* frequency in KHz */
	fe_transmit_mode_t	transmission_mode;
	fe_modulation_t		constellation;
	fe_guard_interval_t	guard_interval;
	fe_code_rate_t 		code_rate_HP;
	__u16			bandwidth_hz;    /* Bandwidth in Hz */
	__u16			cell_id;
};

struct dvb_modulator_gain_range {
	__u32			frequency_khz;   /* frequency in KHz */
	int			min_gain;
	int			max_gain;
};

/**
 * Modulator API commands
 */

#define DVBMOD_SET_PARAMETERS    _IOW('k', 0x40, struct dvb_modulator_parameters)
#define DVBMOD_SET_RF_GAIN       _IOWR('k', 0x41, int)
#define DVBMOD_GET_RF_GAIN       _IOR('k', 0x42, int)
#define DVBMOD_GET_RF_GAIN_RANGE _IOWR('k', 0x43, struct dvb_modulator_gain_range)

#endif
