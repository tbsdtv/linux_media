#ifndef _CXD2878_H_
#define _CXD2878_H_

 enum sony_demod_xtal_t{
    SONY_DEMOD_XTAL_16000KHz = 0,       /**< 16 MHz */
    SONY_DEMOD_XTAL_24000KHz = 1,       /**< 24 MHz */
    SONY_DEMOD_XTAL_32000KHz = 2        /**< 32 MHz */
} ;
 enum sony_ascot3_xtal_t{
    SONY_ASCOT3_XTAL_16000KHz,    /**< 16 MHz */
    SONY_ASCOT3_XTAL_20500KHz,    /**< 20.5 MHz */
    SONY_ASCOT3_XTAL_24000KHz,    /**< 24 MHz */
    SONY_ASCOT3_XTAL_41000KHz     /**< 41 MHz */
} ;
 
#define SONY_DEMOD_MAKE_IFFREQ_CONFIG(iffreq) ((u32)(((iffreq)/48.0)*16777216.0 + 0.5))
#define SONY_DEMOD_ATSC_MAKE_IFFREQ_CONFIG(iffreq) ((u32)(((iffreq)/24.0)*4294967296.0 + 0.5))

struct cxd2878_config{
	u8 addr_slvt;
	enum sony_demod_xtal_t xtal;
	u8 tuner_addr;
	enum sony_ascot3_xtal_t tuner_xtal;

	//for ts
	 //           - 0: Serial output.
     //       - 1: Parallel output (Default).
     u8 ts_mode;
	    /**
     @brief Serial output pin of TS data.

            Value:
            - 0: Output from TSDATA0
            - 1: Output from TSDATA7 (Default).
    */
    u8 ts_ser_data;
	    /**
     @brief Serial TS clock gated on valid TS data or is continuous.

            Value is stored in demodulator structure to be applied during Sleep to Active
            transition.

            Value:
            - 0: Gated
            - 1: Continuous (Default)
    */
    u8 ts_clk;
	/**
	 @brief Disable/Enable TS clock during specified TS region.
	
			bit flags: ( can be bitwise ORed )
			- 0 : Always Active
			- 1 : Disable during TS packet gap (default)
			- 2 : Disable during TS parity (default)
			- 4 : Disable during TS payload
			- 8 : Disable during TS header
			- 16: Disable during TS sync
	*/
    u8 ts_clk_mask;
		/**
		 @brief Disable/Enable TSVALID during specified TS region.
		
				bit flags: ( can be bitwise ORed )
				- 0 : Always Active
				- 1 : Disable during TS packet gap (default)
				- 2 : Disable during TS parity (default)
				- 4 : Disable during TS payload
				- 8 : Disable during TS header
				- 16: Disable during TS sync
		*/
	u8 ts_valid;

	u8 atscCoreDisable;
	
	bool lock_flag;  //for usb device 
	//for ecp3 update
	void (*write_properties) (struct i2c_adapter *i2c,u8 reg, u32 buf);
	void (*read_properties) (struct i2c_adapter *i2c,u8 reg, u32 *buf);
	// EEPROM access
	void (*write_eeprom) (struct i2c_adapter *i2c,u8 reg, u8 buf);
	void (*read_eeprom) (struct i2c_adapter *i2c,u8 reg, u8 *buf);
	
	//for 6590SE mode change(T or s);
	void (*RF_switch)(struct i2c_adapter * i2c,u8 rf_in,u8 flag);
	u8 rf_port; //for change command
};

#if IS_REACHABLE(CONFIG_DVB_CXD2878)
extern struct dvb_frontend *cxd2878_attach(
	const struct cxd2878_config *config,
	struct i2c_adapter *i2c);
#else
static inline struct dvb_frontend *cxd2878_attach(
	const struct cxd2878_config *config,
	struct i2c_adapter *i2c)
{
	dev_warn(&i2c->dev, "%s: driver disabled by Kconfig\n", __func__);
	return NULL;
}

#endif

#endif
