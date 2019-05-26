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
/*#include "gen_macros.h"   */
#include "stddefs.h"

#include "oxford_anafe_init.h"
#include "oxford_anafe_func.h"

/******************************************
FUNCTION   : Oxford_AfeInit
ACTION     : HW Init of the analog FE as described in architecture document chapt 7.1.1 and followings.
			 1.8v DCDC and/or 2.5v LDO supplies could be set INDEPENDANTLY to internal or external.
             Global SW&HW Tuner Init MUST be done inside DFE driver oxford_drv.c and MUST call the 
			 present  function.
		   
			 DEMOD validation board: LDO activated, DCDC not activated depending of HW swicth position
			 AFE RF validation board: LDO not activated, DCDC not activated depending of HW swicth position

PARAMS IN  : STCHIP_Handle_t hTuner
		 	 FE_OXFORD_XtalValue_t Fxtal
			 U8 InternalDCDC
PARAMS OUT : None
RETURN     : STCHIP_Error_t
******************************************/
 STCHIP_Error_t 	Oxford_AfeInit(	STCHIP_Handle_t hTuner, 
									U32 Fxtal_MHz, 
									U8 InternalDCDC,
									U8 InternalLDO
							   )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR; 
	/* adjust LDO_VSEL[2:0] in AFE_LDO2V5_CTRL and DCDC1V8_VREF_SEL[2:0] 
	  in AFE_DCDC1V8_CTRL  should be done here*/
	
	error|= Oxford_PowerUp(hTuner,(U32)Fxtal_MHz );
	
	error|=Oxford_PowerManagement(hTuner, InternalDCDC, InternalLDO);
	
	/*check status bits*/
	error|=Oxford_CheckPowerStatus( hTuner, InternalDCDC, InternalLDO);
	 
	error|=Oxford_ClockStartUp(hTuner,(U32)Fxtal_MHz); /*include biasing cal*/
	/* now the tuners are ready to be set individually*/
	return error;
}
/******************************************
FUNCTION   : Oxford_Term
ACTION     : Terminate the AFE task and switch off ALL tuners one by one
			 !This function is not called by GUI or ATB dll !
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : STCHIP_Error_t
******************************************/
 STCHIP_Error_t 	Oxford_AfeTerm(STCHIP_Handle_t 		hTuner)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR; 
	/* Terminate the AFE task and switch off tuners one by one*/
	
	error|=Oxford_TunerDisable(hTuner,AFE_TUNER1);
	
	error|=Oxford_TunerDisable(hTuner,AFE_TUNER2);
	
	error|=Oxford_TunerDisable(hTuner,AFE_TUNER3);
	
	error|=Oxford_TunerDisable(hTuner,AFE_TUNER4);
	
	return error;
}
/******************************************
FUNCTION   : RoundDividerX10
ACTION     : roud U32 input *10
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : Xint
******************************************/
U32 RoundU32DividerX10(U32 X)
{
	U32 Xint=0;
	
	Xint= ((U32)(X/10))*10;
	if  ((X-Xint)>5)
		Xint= (U32)(X/10)+1;
	else
		Xint=(U32)(X/10);
	
	return Xint;
	
}

/******************************************
FUNCTION   : Oxford_SetFxtalDivider
ACTION     : Set the field RDIV regarding Fxtal= 25,27,30 or 50MHz
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_XtalValue_t Fxtal
PARAMS OUT : None
RETURN     : None
******************************************/
STCHIP_Error_t Oxford_SetFxtalDivider(STCHIP_Handle_t hTuner,U32 Fxtal_MHz)
{
	if (Fxtal_MHz>30)
		return Oxford_SetPLLrefDiv(hTuner,0);   /* %2 for 50MHz*/ 
	else 
		return Oxford_SetPLLrefDiv(hTuner,1);	/* %1 for 25, 27, 30MHz */ 
 }
/******************************************
FUNCTION   : Oxford_SetClkDcdcDivider
ACTION     : Set the clk div for dcdc 1.1V and 1.8V regarding Fxtal= 25,27,30 or 50MHz
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_XtalValue_t Fxtal
PARAMS OUT : None
RETURN     : error
******************************************/
STCHIP_Error_t Oxford_SetClkDcdcDivider(STCHIP_Handle_t hTuner,U32 Fxtal_MHz)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	 switch (Fxtal_MHz) {
		case 27: /*AFE_XTAL_27MHz: */
		case 30: /*AFE_XTAL_30MHz: */
				error|= ChipSetField(hTuner,FAFE_CLK_DCDC_DIV, 1);  
		break;
		case 25: /*AFE_XTAL_25MHz:  */
		case 50:  /*AFE_XTAL_50MHz:  */
				error|= ChipSetField(hTuner,FAFE_CLK_DCDC_DIV, 0); 
		break;
		default:
			error= (STCHIP_Error_t)  CHIPERR_CONFIG_ERR;
		break;
	}
	return error;
 }
/******************************************
FUNCTION   : Oxford_AfeBiasingCal
ACTION     : AFE biasing calibration phase (chapt 7.1.3)
             MUST be done EACH TIME 1.8V supply is stopped and started
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : error
******************************************/
STCHIP_Error_t Oxford_AfeBiasingCal(STCHIP_Handle_t hTuner)
{
	return ChipSetField(hTuner,FAFE_BIAS_RCAL_START, 1);
 }
/******************************************
FUNCTION   : Oxford_PowerUp
ACTION     : Power up and xtal osc start up phase (chapt 7.1.1)
			 DCDC/LDO supply could be internal or external
PARAMS IN  : STCHIP_Handle_t hTuner
			 U8 InternalDCDC
PARAMS OUT : None
RETURN     : error
******************************************/
STCHIP_Error_t Oxford_PowerUp(STCHIP_Handle_t hTuner, U32 Fxtal_MHz)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;

	/* Set divider related to Xtal value*/
	error|= Oxford_SetFxtalDivider( hTuner, Fxtal_MHz);
	
	/*optionnal step set DCDC div clk*/
	error|=Oxford_SetClkDcdcDivider( hTuner, Fxtal_MHz);
			   
	return error;
 }

/******************************************
FUNCTION   : Oxford_PowerManagement
ACTION     : DCDC & LDO regulators start up phase (chapt7.1.2 )
			 once 3.3v is available in application,1.8v DCDC and 2.5v LDO start automatically
			 2.5v LDO enabled by default 
             NOT TO BE DONE at VALIDATION STAGE and in GUI
PARAMS IN  : STCHIP_Handle_t hTuner
			 U8				InternalDCDC,
			 U8				InternalLDO
PARAMS OUT : None
RETURN     : error
******************************************/
STCHIP_Error_t Oxford_PowerManagement(			STCHIP_Handle_t hTuner,
												U8				InternalDCDC,
												U8				InternalLDO)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	if (InternalDCDC) {
		/* enable the clock for 1.8V and 1.1V DCDC converter*/
		error|=ChipSetOneRegister(hTuner, RAFE_OSC, 0x1c);
		/*DCDC ref cllk switched from internal to divided xtal clk*/
		error|=ChipSetOneRegister(hTuner, RAFE_DCDC1V8_CTRL, 0x20);
		ChipWaitOrAbort(hTuner,2);
	}
	else {
		/* disable the clock for 1.8V and 1.1V DCDC converter (default value)*/
		error|=ChipSetOneRegister(hTuner, RAFE_OSC, 0x0c);
		/*DCDC ref cllk stay to internal (default value) */
		error|=ChipSetOneRegister(hTuner, RAFE_DCDC1V8_CTRL, 0x01); 
		ChipWaitOrAbort(hTuner,2);
	}
	
	if (InternalLDO) {
		/* enable the 2.5V LDO (default value)*/
		error|=ChipSetOneRegister(hTuner, RAFE_LDO2V5_CTRL, 0x00); 
	}
	else {
		/* disable the 2.5V LDO*/
		error|=ChipSetOneRegister(hTuner, RAFE_LDO2V5_CTRL, 0x01);
	}

	return error;
}
/******************************************
FUNCTION   : Oxford_CheckPowerStatus
ACTION     : Check 3 status bits  in case LDO and DCDC are used
             NOT TO BE DONE at VALIDATION STAGE and in GUI
PARAMS IN  : STCHIP_Handle_t hTuner
			 U8				InternalDCDC,
			 U8				InternalLDO
PARAMS OUT : None
RETURN     : error
******************************************/
STCHIP_Error_t Oxford_CheckPowerStatus(			STCHIP_Handle_t hTuner,
												U8				InternalDCDC,
												U8				InternalLDO)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	S32  LdoPor=0, DCDC_ok=0,LDO_ok=0,timeout=0, ExitCondition=0;
	
	/* check 3.3v POR bit*/
	if (InternalLDO) {
		error |= (STCHIP_Error_t)ChipGetField(hTuner, FAFE_LDO_POR_3V3, &LdoPor);
		while ((!LdoPor)&&(timeout<40)) {
			ChipWaitOrAbort(hTuner,5);
			timeout = (U8)(timeout + 5);
			error |= (STCHIP_Error_t)ChipGetField(hTuner, FAFE_LDO_POR_3V3, &LdoPor);
		}
		if (!LdoPor) {
			error|= CHIPERR_INVALID_HANDLE;
		}
	}

	if (error==CHIPERR_NO_ERROR) {
		if ( (InternalDCDC)||(InternalLDO)) {
			timeout=0;
			/* once 3.3v is available in application,1.8v DCDC and 2.5v LDO start automatically 
			to get stable clock, it is recommended to wait for 2.5ms mini */
			ChipWaitOrAbort(hTuner,3);
		
			//DCDC_ok=(U8) ChipGetField(hTuner,	FAFE_DCDC_VREG_OK);
			error |= (STCHIP_Error_t)ChipGetField(hTuner, FAFE_DCDC_VREG_OK, &DCDC_ok);
			//LDO_ok =(U8) ChipGetField(hTuner,	FAFE_LDO_VREG_OK);
			error |= (STCHIP_Error_t)ChipGetField(hTuner, FAFE_LDO_VREG_OK, &LDO_ok);
			
			ExitCondition=Oxford_LoopExitCondition(InternalDCDC, InternalLDO, (U8)DCDC_ok, (U8)LDO_ok);
			
			while ((ExitCondition==0) &&(timeout<40)) {
				ChipWaitOrAbort(hTuner,5);
				timeout = (U8)(timeout + 5);
				//DCDC_ok=(U8) ChipGetField(hTuner,	FAFE_DCDC_VREG_OK); 
				error |= (STCHIP_Error_t)ChipGetField(hTuner, FAFE_DCDC_VREG_OK, &DCDC_ok);
				//LDO_ok =(U8) ChipGetField(hTuner,	FAFE_LDO_VREG_OK);
				error |= (STCHIP_Error_t)ChipGetField(hTuner, FAFE_LDO_VREG_OK, &LDO_ok);
				ExitCondition=Oxford_LoopExitCondition(InternalDCDC, InternalLDO, (U8)DCDC_ok, (U8)LDO_ok);

			}
			if (!ExitCondition)
				error= CHIPERR_INVALID_HANDLE;
		}

 	}
	return error;
}

/******************************************
FUNCTION   : Oxford_LoopExitCondition
ACTION     :
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_XtalValue_t Fxtal_MHz 
PARAMS OUT : None
RETURN     : result
******************************************/
U8 Oxford_LoopExitCondition(U8 Internal_DCDC, U8 Internal_LDO, U8 DCDCok, U8 LDOok )
{
 	U8 result=0  ;
	if  (Internal_DCDC) {
		if  (Internal_LDO)
			//result= DCDCok & LDOok ;
			result= (U8)((!DCDCok) & LDOok) ; // reversed status!!
		else
			result= DCDCok ;
	}
	else {
		result= LDOok ;	
	}
	
	return result;
}
/******************************************
FUNCTION   : Oxford_ClockStartUp
ACTION     : clocks & chip start up phase (chapt7.1.2 to 7.1.5)
             to be executed after a HW reset 
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_XtalValue_t Fxtal_MHz
PARAMS OUT : None
RETURN     : error
******************************************/
STCHIP_Error_t Oxford_ClockStartUp(STCHIP_Handle_t hTuner,U32 Fxtal_MHz)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	/*set pll freq   */
	/* !!vco calibration  must NOT be done only until startup sequence is finished..*/
	/* ...if not VCO cal bit stays at 1  !! */
	error|=Oxford_SetFvco_MHz(hTuner,PLL_FVCO_FREQUENCY,Fxtal_MHz);
	
	/*AFE biasing cal chapt 7.1.3*/
	error|=Oxford_AfeBiasingCal(hTuner);
	ChipWaitOrAbort(hTuner,1);
	
	/* set pll wake up and vco cal (chapt 7.1.4)*/
	switch(Fxtal_MHz) {
		case 25:
		case 27:
			error|=ChipSetOneRegister(hTuner, RAFE_PLL_CTRL, 	0x93);
		break;
		case 30:
		case 50:
			error|=ChipSetOneRegister(hTuner, RAFE_PLL_CTRL, 	0x91);
		break;
	}

	ChipWaitOrAbort(hTuner,6);
	
	/*start VCO cal */
	if (!Oxford_CalVCOfilter(hTuner)) {
		/* chapt 7.1.5 start up of HF clk*/
		/*set DFE1_CLK_SEL & DFE2_CLK_SEL & DFE3_CLK_SEL to switch to funct PLL clock*/
		error|=ChipSetOneRegister(hTuner,RAFE_DFE_CLK_CTRL1,0x7f);
		
		/* optionnal event: enable the spread spectrum on DFE_CLKn */
		/*	ChipSetOneRegister(hTuner,RAFE_DFE_CLK_CTRL2,0x7); */
		
		/* now the tuners are ready to be set individually*/
	}
	else
		error= CHIPERR_CONFIG_ERR;
		
	return error;
 }
 /******************************************
FUNCTION   : Oxford_EnableLO
ACTION     : Enable the LO clk generation ch 7.1.5
 			 ADC Vreg sel also set but not used
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
PARAMS OUT : None
RETURN     : STCHIP_Error_t
******************************************/
STCHIP_Error_t Oxford_EnableLO(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb   )
{
	STCHIP_Error_t error= (STCHIP_Error_t)CHIPERR_NO_ERROR;
	
	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetOneRegister(hTuner,RAFE_RX1_CTRL,0x82);
		break;
		case AFE_TUNER2:
			error|=ChipSetOneRegister(hTuner,RAFE_RX2_CTRL,0x82);
		break;
		case AFE_TUNER3:
			error|=ChipSetOneRegister(hTuner,RAFE_RX3_CTRL,0x82);
		break;
		case AFE_TUNER4:
			error|=ChipSetOneRegister(hTuner,RAFE_RX4_CTRL,0x82);
		break;
		case AFE_TUNER_ALL:
			error|=ChipSetFieldImage(hTuner,FAFE_LO1_ENA,0x1) ;
			error|=ChipSetFieldImage(hTuner,FAFE_ADC1_VREG_SEL,0x1) ;
			error|=ChipSetFieldImage(hTuner,FAFE_LO2_ENA,0x1) ;
			error|=ChipSetFieldImage(hTuner,FAFE_ADC2_VREG_SEL,0x1) ;
			error|=ChipSetFieldImage(hTuner,FAFE_LO3_ENA,0x1) ;
			error|=ChipSetFieldImage(hTuner,FAFE_ADC3_VREG_SEL,0x1) ;
			error|=ChipSetFieldImage(hTuner,FAFE_LO4_ENA,0x1) ;
			error|=ChipSetFieldImage(hTuner,FAFE_ADC4_VREG_SEL,0x1) ;
			error|=ChipSetRegisters(hTuner,RAFE_RX1_CTRL,4);
		break;
	}
	
	return error;
}

 /******************************************
FUNCTION   : Oxford_TunerDisable
ACTION     : disable the tuner according to ch 7.1.5
 			 disable tuner stages in reverse order
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
PARAMS OUT : None
RETURN     : STCHIP_Error_t
******************************************/
STCHIP_Error_t Oxford_TunerDisable(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb   )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetOneRegister(hTuner,RAFE_RX1_CTRL,0xba);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX1_CTRL,0x9a);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX1_CTRL,0x2);
		break;
		case AFE_TUNER2:
			error|=ChipSetOneRegister(hTuner,RAFE_RX2_CTRL,0xba);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX2_CTRL,0x9a);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX2_CTRL,0x2);
		break;
		case AFE_TUNER3:
			error|=ChipSetOneRegister(hTuner,RAFE_RX3_CTRL,0xba);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX3_CTRL,0x9a);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX3_CTRL,0x2);		
		break;
		case AFE_TUNER4:
			error|=ChipSetOneRegister(hTuner,RAFE_RX4_CTRL,0xba);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX4_CTRL,0x9a);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX4_CTRL,0x2);
		break;
		case AFE_TUNER_ALL:
			error=CHIPERR_CONFIG_ERR;
		break;
	}
	
	return error;
}
/******************************************
FUNCTION   : Oxford_TunerStartUp
ACTION     : Enable the startup of a single receiver ch 7.1.6 except ADC
			 set VGLNA, mixer and BB
             SHOULD be used for VALIDATION and GUI
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
PARAMS OUT : None
RETURN     : STCHIP_Error_t
******************************************/
STCHIP_Error_t Oxford_TunerStartUp(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb   )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;

	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetOneRegister(hTuner,RAFE_RX1_CTRL,0x9a);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX1_CTRL,0xba);
			ChipWaitOrAbort(hTuner,1);
		break;
		case AFE_TUNER2:
			error|=ChipSetOneRegister(hTuner,RAFE_RX2_CTRL,0x9a);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX2_CTRL,0xba);
			ChipWaitOrAbort(hTuner,1);
		break;
		case AFE_TUNER3:
			error|=ChipSetOneRegister(hTuner,RAFE_RX3_CTRL,0x9a);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX3_CTRL,0xba);
			ChipWaitOrAbort(hTuner,1);
		break;
		case AFE_TUNER4:
			error|=ChipSetOneRegister(hTuner,RAFE_RX4_CTRL,0x9a);
			ChipWaitOrAbort(hTuner,1);
			error|=ChipSetOneRegister(hTuner,RAFE_RX4_CTRL,0xba);
			ChipWaitOrAbort(hTuner,1);
		break;
		case AFE_TUNER_ALL:
			/* not permitted to set all tuners at the same time: risk of damaging the chip!!*/
			error=CHIPERR_CONFIG_ERR;
		break;
	}
	 
	return error;
}

/******************************************
FUNCTION   : Oxford_AdcStartUp
ACTION     : Enable the startup of ADCn end of ch 7.1.6
			 MUST NOT be used for VALIDATION as baluns are used
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
PARAMS OUT : None
RETURN     : STCHIP_Error_t
******************************************/
STCHIP_Error_t Oxford_AdcStartUp(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb   )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetField(hTuner,FAFE_ADC1_ENA,0x1);
			ChipWaitOrAbort(hTuner,30);
			error|=ChipSetOneRegister(hTuner,RAFE_ADC1_CTRL1,0xfc);
		break;
		case AFE_TUNER2:
			error|=ChipSetField(hTuner,FAFE_ADC2_ENA,0x1);
			ChipWaitOrAbort(hTuner,30);
			error|=ChipSetOneRegister(hTuner,RAFE_ADC2_CTRL1,0xfc);
		break;
		case AFE_TUNER3:
			error|=ChipSetField(hTuner,FAFE_ADC3_ENA,0x1);
			ChipWaitOrAbort(hTuner,30);
			error|=ChipSetOneRegister(hTuner,RAFE_ADC3_CTRL1,0xfc);
		break;
		case AFE_TUNER4:
			error|=ChipSetField(hTuner,FAFE_ADC4_ENA,0x1);
			ChipWaitOrAbort(hTuner,30);
			error|=ChipSetOneRegister(hTuner,RAFE_ADC4_CTRL1,0xfc);
		break;
		case AFE_TUNER_ALL:
		/* not permitted to set all tuners at the same time: risk of damaging the chip!!*/
			error=CHIPERR_CONFIG_ERR;
		break; 
	}
	 
	return error;
}
/******************************************
FUNCTION   : Oxford_AdcStop
ACTION     : Disable of ADCn end of ch 7.1.6
			 
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
PARAMS OUT : None
RETURN     : STCHIP_Error_t
******************************************/
STCHIP_Error_t Oxford_AdcStop(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb   )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetOneRegister(hTuner,RAFE_ADC1_CTRL1,0xfe);
			ChipWaitOrAbort(hTuner,30);
			error|=ChipSetField(hTuner,FAFE_ADC1_ENA,0x0);
		break;
		case AFE_TUNER2:
			error|=ChipSetOneRegister(hTuner,RAFE_ADC2_CTRL1,0xfe);
			ChipWaitOrAbort(hTuner,30);
			error|=ChipSetField(hTuner,FAFE_ADC2_ENA,0x0);
		break;
		case AFE_TUNER3:
			error|=ChipSetOneRegister(hTuner,RAFE_ADC3_CTRL1,0xfe);
			ChipWaitOrAbort(hTuner,30);
			error|=ChipSetField(hTuner,FAFE_ADC3_ENA,0x0);
		break;
		case AFE_TUNER4:
			error|=ChipSetOneRegister(hTuner,RAFE_ADC4_CTRL1,0xfe);
			ChipWaitOrAbort(hTuner,30);
			error|=ChipSetField(hTuner,FAFE_ADC4_ENA,0x0);
		break;
		case AFE_TUNER_ALL:
		/* not permitted to set all tuners at the same time: risk of damaging the chip!!*/
			error=CHIPERR_CONFIG_ERR;
		break; 
	}
	 
	return error;
}
 /******************************************
FUNCTION   : Oxford_Disec_Lnb_FskStartup
ACTION     : start up DISEQ_C, LNB and FSK
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : None
******************************************/
STCHIP_Error_t Oxford_Disec_Lnb_FskStartup(STCHIP_Handle_t hTuner  )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	error|=ChipSetOneRegister(hTuner,RAFE_DISEQC,0x37);
	ChipWaitOrAbort(hTuner,1);
	error|=ChipSetOneRegister(hTuner,RAFE_LNBCTRL,0x5);
	ChipWaitOrAbort(hTuner,1);
	error|=ChipSetOneRegister(hTuner,RAFE_FSK,0x0);
	ChipWaitOrAbort(hTuner,1);
	
	return error;
}

 /******************************************
FUNCTION   : Oxford_CalVCOfilter
ACTION     : calibrate VCO filter
 			 Set bit FAFE_CAL_START to 1 and poll until it get back to 0 
 			 bit FAFE_CAL_OFF must be previously set to 0 (internal cal)
             vco cal must be done each time PLL_INT, PLL_FRAC1, PLL_FRAC2 changed
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : error
******************************************/
STCHIP_Error_t Oxford_CalVCOfilter(STCHIP_Handle_t hTuner)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	U8 timeout=0;
	S32 vco_cal=0;
	
	/*start a vco cal*/
	error |= ChipSetField(hTuner,FAFE_CAL_START,0x1);
	
	ChipWaitOrAbort(hTuner,1);
	
	error |= (STCHIP_Error_t)ChipGetField(hTuner,FAFE_CAL_START, &vco_cal);
	while (vco_cal&& (timeout<50)) {
		ChipWaitOrAbort(hTuner,5);
		//timeout+=5;
		timeout = (U8)(timeout + 5);
		error |= (STCHIP_Error_t)ChipGetField(hTuner,FAFE_CAL_START, &vco_cal);
	}
	if (vco_cal)
		error |= (STCHIP_Error_t)TUNER_CONFIG_ERR;
	
	return error;
}

 /******************************************
FUNCTION   : Oxford_CheckPllLock
ACTION     : check PLL ock bit
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : error
******************************************/
STCHIP_Error_t Oxford_CheckPllLock(STCHIP_Handle_t hTuner)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	U8 PLLok=0, timeout=0;
			    
	PLLok= (U8) Oxford_GetPLLlock(hTuner);
	while ((!PLLok)&&(timeout<20)) {
		ChipWaitOrAbort(hTuner,5);
		//timeout+=5;
		timeout = (U8)(timeout + 5);
		PLLok=(U8) Oxford_GetPLLlock(hTuner);
	}
	if (!PLLok)
		error |= (STCHIP_Error_t)TUNER_CONFIG_ERR;
	return error;
}
 /******************************************
FUNCTION   : Oxford_GetPLLlock
ACTION     : read PLL ock bit
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : U8
******************************************/
U8 Oxford_GetPLLlock(STCHIP_Handle_t hTuner)
{
	S32 value;
	
	ChipGetField(hTuner,FAFE_PLL_LOCK, &value);
	
	return((U8)value);
}

/**********************************************************************************
FUNCTION   : Oxford_GetFvco_MHz
ACTION     : calculate  Fvco in double precision for GUI and RF ATB (labview) 
			(Fvco = 4* Flo)
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : Fvco
**********************************************************************************/
U32 Oxford_GetFvco_MHz(STCHIP_Handle_t hTuner, U32 Fxtal_MHz)
{
	U32 Int=0, Frac=0, Sd=0, RefDiv=1;
	U32    Fvco_U32=0;
	
	/*read regs*/
	Sd	= 	Oxford_GetPLLsdOn( hTuner);
	Int	= 	Oxford_GetPLLinteger( hTuner);
	Frac= 	Oxford_GetPLLfrac( hTuner);
	RefDiv= Oxford_GetPLLrefDiv( hTuner);
	
	/*Fvco=((2*  Fxtal_MHz * Int + ( 2* Fxtal_MHz *Sd* Frac/(1<<15)))/RefDiv);*/
	Fvco_U32=( RoundU32DividerX10( (20* Fxtal_MHz * Int*(1<<15) +  20* Fxtal_MHz *Sd* Frac)/(1<<15))  ) /RefDiv;

	return (U32) Fvco_U32;	
}

/**********************************************************************************
FUNCTION   : Oxford_SetFvco_MHz
ACTION     : calculate Fvco and set corresponding registers in double precision
			 for GUI and RF ATB (labview)
PARAMS IN  : STCHIP_Handle_t hTuner
			 double Fvco
PARAMS OUT : None
RETURN     : STCHIP_Error_t
**********************************************************************************/
STCHIP_Error_t Oxford_SetFvco_MHz(STCHIP_Handle_t hTuner,U32 Fvco_MHz,U32 Fxtal_MHz)
{
	STCHIP_Error_t error= CHIPERR_NO_ERROR;

	U32 IntPartX10=0, RefDiv=1,FracDiv=0, FracPartX10=0;
	
	/*reset Pll before to (re)start clocks, solve  Defect RnDHV00065143*/
	error|=Oxford_ResetPll(hTuner);
	 
	RefDiv  =	 (U32)	Oxford_GetPLLrefDiv( hTuner);
	IntPartX10=  (U32) 	(((U32)Fvco_MHz* RefDiv*10)/(2*Fxtal_MHz) );   /*MHz*/
	FracPartX10= 	10*Fvco_MHz*RefDiv - IntPartX10*2*Fxtal_MHz;
	FracDiv = 			(1<<14)*Fvco_MHz*RefDiv/Fxtal_MHz - (1<<15)*(IntPartX10/10);
	
	/*write regs*/
	error|=Oxford_SetPLLfrac( hTuner,FracDiv);
	
	if (FracPartX10!=0)
		error|=Oxford_SetPLLsdOn( hTuner,1);
	else
		error|=Oxford_SetPLLsdOn( hTuner,0);

	error|=Oxford_SetPLLinteger( hTuner,(U32) (IntPartX10/10) );
	
	/*vco cal must be done each time PLL_INT, PLL_FRAC1, PLL_FRAC2 changed*/
	/*if (Oxford_CalVCOfilter(hTuner))
		error = CHIPERR_INVALID_HANDLE;
	else if (Oxford_CheckPllLock(hTuner))
		error= CHIPERR_INVALID_HANDLE; */
	
	return error;
}

/**********************************************************************************
FUNCTION   : Oxford_GetFadc_MHz
ACTION     : calculate  Fadc=Fvco/4 ie 6200/4 #1550MHz
PARAMS IN  : STCHIP_Handle_t hTuner
			 U32 Fvco_MHz
PARAMS OUT : None
RETURN     : Fadc
**********************************************************************************/
U32 Oxford_GetFadc_MHz(STCHIP_Handle_t hTuner,U32 Fvco_MHz, U32 Fxtal_MHz)
{
	return (U32)(Oxford_GetFvco_MHz(hTuner, Fxtal_MHz)/4);	
}
/**********************************************************************************
FUNCTION   : Oxford_GetPllFrac
ACTION     : get fractional value of the pll's divider
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : PllFrac
**********************************************************************************/
U32 Oxford_GetPLLfrac(STCHIP_Handle_t hTuner)
{
	S32 pllfracH, pllfracL;
	U32 pllfrac;
	
	ChipGetField(hTuner,FAFE_PLL_FRAC_H, &pllfracH);
	ChipGetField(hTuner,FAFE_PLL_FRAC_L, &pllfracL);
	
	pllfrac = (U32)(((pllfracH << 8) + pllfracL) &0x7fff);
	return(pllfrac);
}

/**********************************************************************************
FUNCTION   : Oxford_SetFrac
ACTION     : set fractional value of the pll's divider
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : f
**********************************************************************************/
STCHIP_Error_t Oxford_SetPLLfrac(STCHIP_Handle_t hTuner,U32 FracDiv)
{
	STCHIP_Error_t error= CHIPERR_NO_ERROR;
	
	error|=ChipSetField(hTuner,FAFE_PLL_FRAC_H, (FracDiv>>8) &0x7f);
	error|=ChipSetField(hTuner,FAFE_PLL_FRAC_L,  FracDiv     &0xff);

	return error;
}

/**********************************************************************************
FUNCTION   : Oxford_GetPLLinteger
ACTION     : get  integer value of the pll's divider
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : freq
**********************************************************************************/
U32 Oxford_GetPLLinteger(STCHIP_Handle_t hTuner)
{
	U32 pllint;
	
	ChipGetField(hTuner,FAFE_PLL_INT, (S32*)&pllint);
	pllint &= 0xff;
	
	return(pllint);
}

/**********************************************************************************
FUNCTION   : Oxford_SetPLLinteger
ACTION     : set integer value of the pll's divider
PARAMS IN  : STCHIP_Handle_t hTuner
			 IntDiv
PARAMS OUT : None
RETURN     : None
**********************************************************************************/
STCHIP_Error_t Oxford_SetPLLinteger(STCHIP_Handle_t hTuner,U32 IntDiv)
{
	return ChipSetField(hTuner,FAFE_PLL_INT, IntDiv &0xff);  
}
/**********************************************************************************
FUNCTION   : Oxford_SetPLLtcp
ACTION     : set test modr for PLL Charge pump
PARAMS IN  : STCHIP_Handle_t hTuner
			 PLLcp
PARAMS OUT : None
RETURN     : STCHIP_Error_t
**********************************************************************************/
STCHIP_Error_t Oxford_SetPLLtcp( STCHIP_Handle_t hTuner, U8 PLLcp)
{	
		return ChipSetField(hTuner,FAFE_TCP, PLLcp &0x03);
}
/**********************************************************************************
FUNCTION   : Oxford_GetPLLrefDiv
ACTION     : Get PLL ref divider
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : div
**********************************************************************************/
U32 Oxford_GetPLLrefDiv(STCHIP_Handle_t hTuner)
{
	U32 RefDiv=1;
		
	(STCHIP_Error_t)ChipGetField(hTuner,FAFE_PLL_REFDIV_N,(S32*)&RefDiv);
	
	if (RefDiv &0x1)
		RefDiv=1;
	else
		RefDiv=2;
		
	 return RefDiv;
}

/**********************************************************************************
FUNCTION   : Oxford_SetPllRefDiv
ACTION     : Set PLL ref divider
PARAMS IN  : STCHIP_Handle_t hTuner,
			 U32 RefDiv
PARAMS OUT : None
RETURN     : None
**********************************************************************************/
STCHIP_Error_t Oxford_SetPLLrefDiv(STCHIP_Handle_t hTuner,U32 RefDiv)
{
	return ChipSetField(hTuner,FAFE_PLL_REFDIV_N, RefDiv &0x1);  
}

/**********************************************************************************
FUNCTION   : Oxford_GetPLLsdOn
ACTION     : read sigma delta Enable/disable 
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : div
**********************************************************************************/
U32 Oxford_GetPLLsdOn(STCHIP_Handle_t hTuner)
{
	U32 sd;
		
	ChipGetField(hTuner,FAFE_PLL_SDON, (S32*)&sd);
	sd &= 0x1;
	
	return(sd);
}

/**********************************************************************************
FUNCTION   : Oxford_SetPLLsdOn
ACTION     : Enable/disable sigma delta
PARAMS IN  : STCHIP_Handle_t hTuner
			 SdOn
PARAMS OUT : None
RETURN     : None
**********************************************************************************/
STCHIP_Error_t Oxford_SetPLLsdOn(STCHIP_Handle_t hTuner,U32 SdOn)
{
	return ChipSetField(hTuner,FAFE_PLL_SDON, SdOn &0x1);  
}

/**********************************************************************************
FUNCTION   : Oxford_GetFSK
ACTION     : get fsk reg value
			 only gives access to FSK DISEQC LNBCTRL registers. 
	 		 There is absolutely no FSK, Diseq or LNBCTRL drivers  in this code
PARAMS IN  : STCHIP_Handle_t hTuner
			 
PARAMS OUT : None
RETURN     : U8
**********************************************************************************/	
U8 Oxford_GetFSK(		STCHIP_Handle_t 		hTuner)
{
	U32 fsk ;

	ChipGetOneRegister (hTuner, RAFE_FSK, &fsk);
	
	return ((U8)fsk);
}
/**********************************************************************************
FUNCTION   : Oxford_SetFSK
ACTION     : set fsk reg value
PARAMS IN  : STCHIP_Handle_t hTuner
			 U8
PARAMS OUT : None
RETURN     : None
**********************************************************************************/
STCHIP_Error_t 	Oxford_SetFSK(			STCHIP_Handle_t 		hTuner,
										U8	 					FSKctrl)
{
	return ChipSetOneRegister(hTuner,RAFE_FSK,FSKctrl); 
}
/**********************************************************************************
FUNCTION   : Oxford_GetDiseqC
ACTION     : get DiseqC reg value
			only gives access to FSK DISEQC LNBCTRL registers. 
	 		There is absolutely no FSK, Diseq or LNBCTRL drivers  in this code 
PARAMS IN  : STCHIP_Handle_t hTuner
			 
PARAMS OUT : None
RETURN     : U8
**********************************************************************************/
U8 	Oxford_GetDiseqC(		STCHIP_Handle_t 		hTuner)
{
	U32 DiseqC ;
	
	ChipGetOneRegister (hTuner, RAFE_DISEQC, &DiseqC);
	return ((U8)DiseqC);
}
/**********************************************************************************
FUNCTION   : Oxford_SetDiseqC
ACTION     : set DiseqC reg value
PARAMS IN  : STCHIP_Handle_t hTuner
			 U8	   Diseqc
PARAMS OUT : None
RETURN     : None
**********************************************************************************/
STCHIP_Error_t Oxford_SetDiseqC(		STCHIP_Handle_t 		hTuner,
										U8 						DiseqC)
{
	return ChipSetOneRegister(hTuner,RAFE_DISEQC,DiseqC); 
}
/**********************************************************************************
FUNCTION   : Oxford_GetLnbCtrl
ACTION     : get LnbCtrl reg value
			only gives access to FSK DISEQC LNBCTRL registers. 
	 		There is absolutely no FSK, Diseq or LNBCTRL drivers  in this code 
PARAMS IN  : STCHIP_Handle_t hTuner
			 
PARAMS OUT : None
RETURN     : U8 LnbCtrl                                                        
**********************************************************************************/
U8 	Oxford_GetLnbCtrl(		STCHIP_Handle_t 		hTuner)
{
	U32 LnbCtrl;
	
	ChipGetOneRegister(hTuner, RAFE_LNBCTRL, &LnbCtrl);
	
	return((U8)LnbCtrl);		
}
/**********************************************************************************
FUNCTION   : Oxford_SetLnbCtrl
ACTION     : get LnbCtrl reg value
PARAMS IN  : STCHIP_Handle_t hTuner
			 U8  LnbCtrl
PARAMS OUT : None
RETURN     : None
**********************************************************************************/
STCHIP_Error_t 	Oxford_SetLnbCtrl(		STCHIP_Handle_t 		hTuner,
										U8 						LnbCtrl)
{
	return ChipSetOneRegister(hTuner,RAFE_LNBCTRL,LnbCtrl);
}

/**********************************************************************************
FUNCTION   : Oxford_SetBBgain
ACTION     : 
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
			 U8 Value  0 to 255
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_SetBBgain(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb, U8 Value   )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetField(hTuner,FAFE_AGC1_BBPWM, Value);
			
		break;
		case AFE_TUNER2:
			error|=ChipSetField(hTuner,FAFE_AGC2_BBPWM, Value);

		break;
		case AFE_TUNER3:
			error|=ChipSetField(hTuner,FAFE_AGC3_BBPWM, Value);

		break;
		case AFE_TUNER4:
			error|=ChipSetField(hTuner,FAFE_AGC4_BBPWM, Value);

		break;
		case AFE_TUNER_ALL:
			error|=ChipSetField(hTuner,FAFE_AGC1_BBPWM, Value);
			error|=ChipSetField(hTuner,FAFE_AGC2_BBPWM, Value);
			error|=ChipSetField(hTuner,FAFE_AGC3_BBPWM, Value);
			error|=ChipSetField(hTuner,FAFE_AGC4_BBPWM, Value);
		break; 
	}
	 
	return error;
}
/**********************************************************************************
FUNCTION   : Oxford_SetBBgainMode
ACTION     : 
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
			 U8 Value
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_SetBBgainMode(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb, U8 Value   )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetField(hTuner,FAFE_AGC1_BB_CTRL, Value);
		break;
		case AFE_TUNER2:
			error|=ChipSetField(hTuner,FAFE_AGC2_BB_CTRL, Value);

		break;
		case AFE_TUNER3:
			error|=ChipSetField(hTuner,FAFE_AGC3_BB_CTRL, Value);
		break;
		case AFE_TUNER4:
			error|=ChipSetField(hTuner,FAFE_AGC4_BB_CTRL, Value);

		break;
		case AFE_TUNER_ALL:
			error|=ChipSetField(hTuner,FAFE_AGC1_BB_CTRL, Value);
			error|=ChipSetField(hTuner,FAFE_AGC2_BB_CTRL, Value);
			error|=ChipSetField(hTuner,FAFE_AGC3_BB_CTRL, Value);
			error|=ChipSetField(hTuner,FAFE_AGC4_BB_CTRL, Value);
		break; 
	}
	 
	return error;
}

/**********************************************************************************
FUNCTION   : Oxford_SetRFgain
ACTION     : 
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
			 U8 Value
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_SetRFgain(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb, U8 Value   )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetField(hTuner,FAFE_AGC1_RFPWM, Value);
		break;
		
		case AFE_TUNER2:
			error|=ChipSetField(hTuner,FAFE_AGC2_RFPWM, Value);
		break;
		
		case AFE_TUNER3:
			error|=ChipSetField(hTuner,FAFE_AGC3_RFPWM, Value);
		break;
		
		case AFE_TUNER4:
			error|=ChipSetField(hTuner,FAFE_AGC4_RFPWM, Value);
		break;
		
		case AFE_TUNER_ALL:
			error|=ChipSetField(hTuner,FAFE_AGC1_RFPWM, Value);
			error|=ChipSetField(hTuner,FAFE_AGC2_RFPWM, Value);
			error|=ChipSetField(hTuner,FAFE_AGC3_RFPWM, Value);
			error|=ChipSetField(hTuner,FAFE_AGC4_RFPWM, Value);
		break; 
	}
	 
	return error;
}
/**********************************************************************************
FUNCTION   : Oxford_SetRFgainMode
ACTION     : 
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
			 U8 Value
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_SetRFgainMode(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb, U8 Value   )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetField(hTuner,FAFE_AGC1_RF_CTRL, Value);
		break;
		
		case AFE_TUNER2:
			error|=ChipSetField(hTuner,FAFE_AGC2_RF_CTRL, Value);
		break;
		
		case AFE_TUNER3:
			error|=ChipSetField(hTuner,FAFE_AGC3_RF_CTRL, Value);
		break;
		
		case AFE_TUNER4:
			error|=ChipSetField(hTuner,FAFE_AGC4_RF_CTRL, Value);
		break;
		
		case AFE_TUNER_ALL:
			error|=ChipSetField(hTuner,FAFE_AGC1_RF_CTRL, Value);
			error|=ChipSetField(hTuner,FAFE_AGC2_RF_CTRL, Value);
			error|=ChipSetField(hTuner,FAFE_AGC3_RF_CTRL, Value);
		    error|=ChipSetField(hTuner,FAFE_AGC4_RF_CTRL, Value);
		break; 
	}
	 
	return error;
}

 
/**********************************************************************************
FUNCTION   : Oxford_SetVGLNAgainMode
ACTION     : 
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb  1, 2, 3 or 4
			 U8 Value	 0: low gain   1:high gain +6dB
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_SetVGLNAgainMode(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb, U8 Value   )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetField(hTuner,FAFE_VGLNA1_SELGAIN, Value);
		break;
		case AFE_TUNER2:
			error|=ChipSetField(hTuner,FAFE_VGLNA2_SELGAIN, Value);
		break;
		case AFE_TUNER3:
			error|=ChipSetField(hTuner,FAFE_VGLNA3_SELGAIN, Value);
		break;
		case AFE_TUNER4:
			error|=ChipSetField(hTuner,FAFE_VGLNA4_SELGAIN, Value);
		break;
		
		case AFE_TUNER_ALL:
			error|=ChipSetField(hTuner,FAFE_VGLNA1_SELGAIN, Value);
			error|=ChipSetField(hTuner,FAFE_VGLNA2_SELGAIN, Value);
			error|=ChipSetField(hTuner,FAFE_VGLNA3_SELGAIN, Value);
			error|=ChipSetField(hTuner,FAFE_VGLNA4_SELGAIN, Value);
		break;
	}
	 
	return error;
}
/**********************************************************************************
FUNCTION   : Oxford_GetVGLNAgainMode
ACTION     : 
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb  1, 2, 3 or 4
			 U8 Value	 0: low gain   1:high gain +6dB
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
U8 Oxford_GetVGLNAgainMode(STCHIP_Handle_t hTuner, FE_OXFORD_TunerPath_t 	TunerNb)
{
	
	S32 RetValue=0;
	STCHIP_Error_t error = CHIPERR_NO_ERROR;
	
	switch (TunerNb) {
		case AFE_TUNER1:
			error |= ChipGetField(hTuner,FAFE_VGLNA1_SELGAIN, &RetValue);
		break;
		case AFE_TUNER2:
			error |= ChipGetField(hTuner,FAFE_VGLNA2_SELGAIN, &RetValue);
		break;
		case AFE_TUNER3:
			error |= ChipGetField(hTuner,FAFE_VGLNA3_SELGAIN, &RetValue);
		break;
		case AFE_TUNER4:
			error |= ChipGetField(hTuner,FAFE_VGLNA4_SELGAIN, &RetValue);
		break;
		case AFE_TUNER_ALL:
			/*error*/
		break; 
	}
	 
	return (U8)RetValue;
}
/**********************************************************************************
FUNCTION   : Oxford_SetVCOcalMode
ACTION     : 
PARAMS IN  : STCHIP_Handle_t hTuner
			 U8 Value
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_SetVCOcalMode(STCHIP_Handle_t hTuner, U8 Value   )
{
	
	return 	ChipSetField(hTuner,FAFE_CAL_OFF, Value);
}
/**********************************************************************************
FUNCTION   : Oxford_SetVCOcalStart
ACTION     : set the vco calibration bit
             this bit is forced to 0 by internal logic
PARAMS IN  : STCHIP_Handle_t hTuner
			 U8 Value
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_SetVCOcalStart(STCHIP_Handle_t hTuner, U8 Value   )
{
	
	return 	ChipSetField(hTuner,FAFE_CAL_START, Value);
}
/**********************************************************************************
FUNCTION   : Oxford_SetVCOcalFreqCalCode
ACTION     : set the vco calibration code bits
PARAMS IN  : STCHIP_Handle_t hTuner
			 U8 Value
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_SetVCOfreqCalCode(STCHIP_Handle_t hTuner, U8 Value   )
{
	
	return 	ChipSetField(hTuner,FAFE_VCO_CAL, Value);
}
/**********************************************************************************
FUNCTION   : Oxford_SetVCOcalFreqCalCode
ACTION     : set the vco calibration code bits
PARAMS IN  : STCHIP_Handle_t hTuner
			 U8 Value
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
U8 Oxford_GetVCOfreqCalCode(STCHIP_Handle_t hTuner  )
{
	S32 fafe_vco_cal;
	
	ChipGetField(hTuner,FAFE_VCO_CAL, &fafe_vco_cal);
	
	return((U8)fafe_vco_cal);
}
/**********************************************************************************
FUNCTION   : Oxford_BBoutputAccess
ACTION     : enable/disable base band test access path according to VOS table 7
             for RF validation only
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
			 U8 Value
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_BBoutputAccess(STCHIP_Handle_t 					hTuner, 
									FE_OXFORD_TunerPath_t 				TunerNb )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	switch (TunerNb) {
		case AFE_TUNER1:
			 error|=ChipSetOneRegister(hTuner,RAFE_TST_CTRL6,0x03); 
		break;
		case AFE_TUNER2:
			 error|=ChipSetOneRegister(hTuner,RAFE_TST_CTRL6,0x0c); 
		break;
		case AFE_TUNER3:
			 error|=ChipSetOneRegister(hTuner,RAFE_TST_CTRL6,0x30); 
		break;
		case AFE_TUNER4:
			 error|=ChipSetOneRegister(hTuner,RAFE_TST_CTRL6,0xc0); 
		break;
		case AFE_TUNER_ALL:
		/* not possible to set test access for several tuners*/
			error=CHIPERR_INVALID_HANDLE;
		break;	
	}
	 
	return error;
}

/**********************************************************************************
FUNCTION   : Oxford_ResetPll
ACTION     : resetn signal (active low) for PLL/VCO digital part
             
PARAMS IN  : STCHIP_Handle_t hTuner
			 
PARAMS OUT : None
RETURN     : None
**********************************************************************************/
STCHIP_Error_t Oxford_ResetPll(			STCHIP_Handle_t 					hTuner )
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	
	error|=ChipSetField(hTuner,FAFE_PLL_RST_N, 0);
	ChipWaitOrAbort(hTuner, 1);
	error|=ChipSetField(hTuner,FAFE_PLL_RST_N, 1);
	 
	return error;
}

/**********************************************************************************
FUNCTION   : Oxford_SetVglnaInputs
ACTION     : Set VGNLA 4* inputs to single or diff
             keep RAFE_RF_CFG1's 4 lsb and add 4 msb from input int  IsDifferential         
PARAMS IN  : STCHIP_Handle_t hTuner
			 IsDifferential
PARAMS OUT : None
RETURN     : STCHIP_Error_t
**********************************************************************************/
STCHIP_Error_t Oxford_SetVglnaInputs(		STCHIP_Handle_t 			hTuner,
											U8							IsDifferential)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	U32 ReadenValue=0;
	
	error|=ChipGetOneRegister(hTuner, RAFE_RF_CFG1, &ReadenValue);
	error|=ChipSetOneRegister(hTuner,RAFE_RF_CFG1, (U8) ( ((IsDifferential& 0xf)<<4)|((U8)ReadenValue&0xf) ) );
	 
	return error;
}
/**********************************************************************************
FUNCTION   : Oxford_TunerState
ACTION     : Is tuner n available
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
			 
PARAMS OUT : None
RETURN     : U8 Value
**********************************************************************************/
U8	Oxford_TunerState(		STCHIP_Handle_t 		hTuner, 
							FE_OXFORD_TunerPath_t 	TunerNb )
{
	U8 TunerAvailable=0;
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	S32 val1, val2, val3, val4, val5;
					  
	switch (TunerNb) {
		case AFE_TUNER1:
			error |= ChipGetField(hTuner,FAFE_ADC1_ENA, &val1);
			error |= ChipGetField(hTuner,FAFE_LO1_ENA, &val2);
			error |= ChipGetField(hTuner,FAFE_BB1_ENA, &val3);
			error |= ChipGetField(hTuner,FAFE_MIXER1_ENA, &val4);
			error |= ChipGetField(hTuner,FAFE_VGLNA1_ENA, &val5);
			if(val1 && val2 && val3 && val4 && val5) {
				TunerAvailable=1;
			}
		break;
		case AFE_TUNER2:
			error |= ChipGetField(hTuner,FAFE_ADC2_ENA, &val1);
			error |= ChipGetField(hTuner,FAFE_LO2_ENA, &val2);
			error |= ChipGetField(hTuner,FAFE_BB2_ENA, &val3);
			error |= ChipGetField(hTuner,FAFE_MIXER2_ENA, &val4);
			error |= ChipGetField(hTuner,FAFE_VGLNA2_ENA, &val5);
			if(val1 && val2 && val3 && val4 && val5) {
				TunerAvailable=1;
			}
		break;
		case AFE_TUNER3:
			error |= ChipGetField(hTuner,FAFE_ADC3_ENA, &val1);
			error |= ChipGetField(hTuner,FAFE_LO3_ENA, &val2);
			error |= ChipGetField(hTuner,FAFE_BB3_ENA, &val3);
			error |= ChipGetField(hTuner,FAFE_MIXER3_ENA, &val4);
			error |= ChipGetField(hTuner,FAFE_VGLNA3_ENA, &val5);
			if(val1 && val2 && val3 && val4 && val5) {
				TunerAvailable=1;
			}
		break;
		case AFE_TUNER4:
			error |= ChipGetField(hTuner,FAFE_ADC4_ENA, &val1);
			error |= ChipGetField(hTuner,FAFE_LO4_ENA, &val2);
			error |= ChipGetField(hTuner,FAFE_BB4_ENA, &val3);
			error |= ChipGetField(hTuner,FAFE_MIXER4_ENA, &val4);
			error |= ChipGetField(hTuner,FAFE_VGLNA4_ENA, &val5);
			if(val1 && val2 && val3 && val4 && val5) {
				TunerAvailable=1;
			} 
		break;
		case AFE_TUNER_ALL:
		/* choice not permitted*/
			TunerAvailable=0;
		break;
		
	}
	
	if ((hTuner->Error) || (error != CHIPERR_NO_ERROR))
		TunerAvailable=0;	
	return TunerAvailable;
}

/**********************************************************************************
FUNCTION   : Oxford_StartBBcal
ACTION     :Start the BB filter calibration of the receiver n as explained inside C040_SATSAFE_25.pdf
 			rev G chapter 4.1.3.4 

			– step 1 : the receiver n is enabled by setting all required register bits RAFE_RXn_CTRL:
			VGLNAn_ENA=MIXERn_ENA=BBn_ENA=ADCn_ENA=1.
			Note : the corresponding LOn_ENA=0 => this item must be confirmed by the AFE team !
			(potential SOA issue). In case the LOn_ENA is still set at ‘1’, it is recommended to force
			the RF gain at the minimum value

			– step 2 : the division ratio of the spread-spectrum frequency divider is set to a fix value :
			DFE_CLK_SS_DIV[1:0]]=“11” => ~240MHz clock frequency with default VCO settings =>
			analyze of the signal power around the 3rd harmonics (~720MHz)

			– step 3 : set BBn_CAL_SAF_DIS=1 in RAFE_BB_CAL to enable the control of the
			calibration code by AFE_BBnI_CAL and AFE_BBnQ_CAL registers
 
			– step 4 : set BBn_CAL_START=1 in RAFE_BB_CAL to enable the calibration clock path
			and set the BBn cells in the calibration configuration.

			BBn_CAL_START does not start the cal but only set the MUX in cal path
			The FFT and data processing is performed later on in another fuction


PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
			 U8 IsCalReg
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_StartBBcal   (STCHIP_Handle_t 					hTuner, 
									FE_OXFORD_TunerPath_t 				TunerNb,
									U8 									IsFromReg)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;

	switch (TunerNb) {
		case AFE_TUNER1:
			/*LOn_ENA should be set to 0 TBC*/
			error|=ChipSetOneRegister(hTuner,RAFE_RX1_CTRL, 0x7a);
			 /* set clock freq to 240MHz*/
		 	error|=ChipSetField(hTuner,FAFE_DFE_CLK_SS_DIV, 0x3);
			 /* BB calibration code given by registers (default) or fuse */
		 	error|=ChipSetField(hTuner,FAFE_BB1_CAL_SAF_DIS, IsFromReg);
			ChipWaitOrAbort(hTuner, 1);
		 	/*set the MUX in cal path*/
		 	error|=ChipSetField(hTuner,FAFE_BB1_CAL_START, 0x1);
		break;
		case AFE_TUNER2:
			/*LOn_ENA should be set to 0 TBC*/
			error|=ChipSetOneRegister(hTuner,RAFE_RX2_CTRL, 0x7a);
			/* set clock freq to 240MHz*/
		 	error|=ChipSetField(hTuner,FAFE_DFE_CLK_SS_DIV, 0x3);
			/* BB calibration code given by registers (default) or fuse */
		 	error|=ChipSetField(hTuner,FAFE_BB2_CAL_SAF_DIS, IsFromReg);
			ChipWaitOrAbort(hTuner, 1);
			/*set the MUX in cal path*/
		 	error|=ChipSetField(hTuner,FAFE_BB2_CAL_START, 0x1);
		break;
		case AFE_TUNER3:
			/*LOn_ENA should be set to 0 TBC*/
			error|=ChipSetOneRegister(hTuner,RAFE_RX3_CTRL, 0x7a);
		 	/* set clock freq to 240MHz*/
		 	error|=ChipSetField(hTuner,FAFE_DFE_CLK_SS_DIV, 0x3);
			/* BB calibration code given by registers (default) or fuse */
		 	error|=ChipSetField(hTuner,FAFE_BB3_CAL_SAF_DIS, IsFromReg);
			ChipWaitOrAbort(hTuner, 1);
			/*set the MUX in cal path*/
		 	error|=ChipSetField(hTuner,FAFE_BB3_CAL_START, 0x1);
		break;
		case AFE_TUNER4:
			/*LOn_ENA should be set to 0 TBC*/
			error|=ChipSetOneRegister(hTuner,RAFE_RX4_CTRL, 0x7a);
			/* set clock freq to 240MHz*/
			error|=ChipSetField(hTuner,FAFE_DFE_CLK_SS_DIV, 0x3);
			/* BB calibration code given by registers (default) or fuse */
		 	error|=ChipSetField(hTuner,FAFE_BB4_CAL_SAF_DIS, IsFromReg);
			ChipWaitOrAbort(hTuner, 1);
			/*set the MUX in cal pathl*/
		 	error|=ChipSetField(hTuner,FAFE_BB4_CAL_START, 0x1);
		break;
		case AFE_TUNER_ALL:
			error=CHIPERR_CONFIG_ERR;
		break; 
	}
	 
	return error;
}
/**********************************************************************************
FUNCTION   : Oxford_StopBBcal
ACTION     : Set the BB filter out of calibration for  the receiver n in same order explained
 			inside C040_SATSAFE_25.pdf rev G chapter 4.1.3.4 

			– step 1 : the receiver n is enabled by setting all required register bits: RAFE_RXn_CTRL
 			 following ch 7.1.6 RAFE_RXn_CTRL value is set to 0x9a then 0xba

			– step 2 : the ADC n is enabled  by setting FAFE_ADC1_ENA bit  to 1
	    	  RAFE_ADC1_CTRL1 set to 0xfc to enable the digital correction of ADC n
	
			– step 3 : the division ratio of the spread-spectrum frequency divider is set 
			to default value :DFE_CLK_SS_DIV[1:0]]=“0” 

			– step 4 : set BBn_CAL_START=0 in RAFE_BB_CAL to disable the calibration clock path
			and set the BBn MUX in default path


PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_StopBBcal   (STCHIP_Handle_t 					hTuner, 
									FE_OXFORD_TunerPath_t 			TunerNb)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	

	
	/*Set tuner exept ADC*/
	error|=Oxford_TunerStartUp(hTuner, (FE_OXFORD_TunerPath_t) TunerNb);
	/* set ADC*/
	error|=Oxford_AdcStartUp(hTuner, (FE_OXFORD_TunerPath_t) TunerNb);
	/* set clock divider back to default*/
	error|=ChipSetField(hTuner,FAFE_DFE_CLK_SS_DIV, 0x0);
	
	switch (TunerNb) {
		case AFE_TUNER1:
			/*set the MUX in normal path*/
		 	error|=ChipSetField(hTuner,FAFE_BB1_CAL_START, 0x0);
		break;
		case AFE_TUNER2:
			/*set the MUX in normal path*/
		 	error|=ChipSetField(hTuner,FAFE_BB2_CAL_START, 0x0);
		break;
		case AFE_TUNER3:
			/*set the MUX in normal path*/
		 	error|=ChipSetField(hTuner,FAFE_BB3_CAL_START, 0x0);
		break;
		case AFE_TUNER4:
			/*set the MUX in normal path*/
		 	error|=ChipSetField(hTuner,FAFE_BB4_CAL_START, 0x0);
		break;
		case AFE_TUNER_ALL:
			error|=CHIPERR_INVALID_HANDLE;
		break; 
	}
	 
	return error;
}
/**********************************************************************************
FUNCTION   : Oxford_StoreBBcalCode
ACTION     : Store the BB filter calibration code into a single or all tuners
			 At first glance all BB filters are supposed to have an identical
			 frequency response
			 
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
			 U8 ICalCode 8bits
			 U8	QCalCode 2bits
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_StoreBBcalCode(STCHIP_Handle_t 					hTuner, 
									 FE_OXFORD_TunerPath_t 				TunerNb,
									 U8 								ICalCode,
									 U8									QCalCode)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;

	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetField(hTuner,FAFE_BB1_I_CAL, ICalCode);
			error|=ChipSetField(hTuner,FAFE_BB1_Q_CAL, QCalCode);
		break;
		case AFE_TUNER2:
			error|=ChipSetField(hTuner,FAFE_BB2_I_CAL, ICalCode);
			error|=ChipSetField(hTuner,FAFE_BB2_Q_CAL, QCalCode);
		break;
		case AFE_TUNER3:
			error|=ChipSetField(hTuner,FAFE_BB3_I_CAL, ICalCode);
			error|=ChipSetField(hTuner,FAFE_BB3_Q_CAL, QCalCode);
		break;
		case AFE_TUNER4:
			error|=ChipSetField(hTuner,FAFE_BB4_I_CAL, ICalCode);
			error|=ChipSetField(hTuner,FAFE_BB4_Q_CAL, QCalCode);
		break;
		case AFE_TUNER_ALL:
			/* in case a single set of BB calibration code is used  for all tuners (TBC)*/
			error|=ChipSetField(hTuner,FAFE_BB1_I_CAL, ICalCode);
			error|=ChipSetField(hTuner,FAFE_BB1_Q_CAL, QCalCode);
			error|=ChipSetField(hTuner,FAFE_BB2_I_CAL, ICalCode);
			error|=ChipSetField(hTuner,FAFE_BB2_Q_CAL, QCalCode);
			error|=ChipSetField(hTuner,FAFE_BB3_I_CAL, ICalCode);
			error|=ChipSetField(hTuner,FAFE_BB3_Q_CAL, QCalCode);
			error|=ChipSetField(hTuner,FAFE_BB4_I_CAL, ICalCode);
			error|=ChipSetField(hTuner,FAFE_BB4_Q_CAL, QCalCode);
		break;
	
	}
	return error;
}

/**********************************************************************************
FUNCTION   : Oxford_CalCodeSource
ACTION     : Selection of the calibration code source for the base-band of the
 		receiver
			 
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
			 BOOL	CalCodeSource
				TRUE => calibration code are given by AFE_BBxI_CAL
 					and AFE_BBxQ_CAL
				FALSE => calibration code are given by SAF bits
					available in RO mode in AFE_FUSEx
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_CalCodeSource(STCHIP_Handle_t	hTuner, 
				FE_OXFORD_TunerPath_t	TunerNb,
				BOOL			cal_code_source)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;

	switch (TunerNb) {
		case AFE_TUNER1:
			error|=ChipSetField(hTuner,FAFE_BB1_CAL_SAF_DIS, cal_code_source);
		break;

		case AFE_TUNER2:
			error|=ChipSetField(hTuner,FAFE_BB2_CAL_SAF_DIS, cal_code_source);
		break;
		
		case AFE_TUNER3:
			error|=ChipSetField(hTuner,FAFE_BB3_CAL_SAF_DIS, cal_code_source);
		break;
		
		case AFE_TUNER4:
			error|=ChipSetField(hTuner,FAFE_BB4_CAL_SAF_DIS, cal_code_source);
		break;
		
		case AFE_TUNER_ALL:
			error|=ChipSetField(hTuner,FAFE_BB1_CAL_SAF_DIS, cal_code_source);
			error|=ChipSetField(hTuner,FAFE_BB2_CAL_SAF_DIS, cal_code_source);
			error|=ChipSetField(hTuner,FAFE_BB3_CAL_SAF_DIS, cal_code_source);
			error|=ChipSetField(hTuner,FAFE_BB4_CAL_SAF_DIS, cal_code_source);
		break;
	}

	return error;
}

/**********************************************************************************
FUNCTION   : Oxford_GetBBcalCode
ACTION     : Get the calibration code from SOC fuse (IsFromReg=0) or from 
			 BB calibration registers (IsFromReg=1)
PARAMS IN  : STCHIP_Handle_t hTuner
			 FE_OXFORD_TunerPath_t 	TunerNb
			 U8 ICode, 8 bits
			 U8	QCode  2 bits
			 U8	IsFromFuse
PARAMS OUT : None
RETURN     : error
**********************************************************************************/
STCHIP_Error_t Oxford_GetBBcalCode(STCHIP_Handle_t 					hTuner, 
									 FE_OXFORD_TunerPath_t 			TunerNb,
									 U8 							*ICode,
									 U8								*QCode,
								     U8								IsFromReg)
{
	STCHIP_Error_t error=CHIPERR_NO_ERROR;
	S32 fld_value;

	switch (TunerNb) {
		case AFE_TUNER1:
			if (IsFromReg) {   /*read from BBcal register*/
				error |= ChipGetField(hTuner,FAFE_BB1I_CAL, &fld_value);
				*ICode = (U8)fld_value;
				error |= ChipGetField(hTuner,FAFE_BB1Q_CAL, &fld_value);
				*QCode = (U8)fld_value;
			}
			else {   /*read from fuse*/
				error |= ChipGetField(hTuner,FAFE_BB1I_CAL, &fld_value);
				*ICode = (U8)fld_value;
				error |= ChipGetField(hTuner,FAFE_BB1Q_CAL, &fld_value);
				*QCode = (U8)fld_value;
			}
		break;
		case AFE_TUNER2:
			if (IsFromReg) {   /*read from BBcal register*/
				error |= ChipGetField(hTuner,FAFE_BB2I_CAL, &fld_value);
				*ICode = (U8)fld_value;
				error |= ChipGetField(hTuner,FAFE_BB2Q_CAL, &fld_value);
				*QCode = (U8)fld_value;
			}
			else {   /*read from fuse*/
				error |= ChipGetField(hTuner,FAFE_BB2I_CAL, &fld_value);
				*ICode = (U8)fld_value;
				error |= ChipGetField(hTuner,FAFE_BB2Q_CAL, &fld_value);
				*QCode = (U8)fld_value;
			}
		break;
		case AFE_TUNER3:
			if (IsFromReg) {   /*read from BBcal register */
				error |= ChipGetField(hTuner,FAFE_BB3I_CAL, &fld_value);
				*ICode = (U8)fld_value;
				error |= ChipGetField(hTuner,FAFE_BB3Q_CAL, &fld_value);
				*QCode = (U8)fld_value;
			}
			else {   /*read from fuse*/
				error |= ChipGetField(hTuner,FAFE_BB3I_CAL, &fld_value);
				*ICode = (U8)fld_value;
				error |= ChipGetField(hTuner,FAFE_BB3Q_CAL, &fld_value);
				*QCode = (U8)fld_value;
			}
		break;
		case AFE_TUNER4:
			if (IsFromReg) {   /*read from BBcal register*/
				error |= ChipGetField(hTuner,FAFE_BB4I_CAL, &fld_value);
				*ICode = (U8)fld_value;
				error |= ChipGetField(hTuner,FAFE_BB4Q_CAL, &fld_value);
				*QCode = (U8)fld_value;
			}
			else {   /*read from fuse*/
				error |= ChipGetField(hTuner,FAFE_BB4I_CAL, &fld_value);
				*ICode = (U8)fld_value;
				error |= ChipGetField(hTuner,FAFE_BB4Q_CAL, &fld_value);
				*QCode = (U8)fld_value;
			}
		break;
		case AFE_TUNER_ALL:
			/* not permitted*/
			*ICode=0xff;
			*QCode=0xff;
			error=CHIPERR_CONFIG_ERR;
		break;
	
	}
	return error;
}

/* added, extended functionality for STiD135 GUI  */

/******************************************
FUNCTION   : Oxford_GetPllEnable
ACTION     : check if PLL is enabled
PARAMS IN  : STCHIP_Handle_t hTuner
PARAMS OUT : None
RETURN     : error
******************************************/
S32 Oxford_GetPllEnable(STCHIP_Handle_t hTuner)
{
	S32 fld_value;
	
	ChipGetField(hTuner, FAFE_PLL_ENA, &fld_value);
	
	return(fld_value);
}

/**********************************************************************************
FUNCTION   : Oxford_GetAfeId
ACTION     : Get the device ID of the AFE device
PARAMS IN  : STCHIP_Handle_t hTuner
			 
PARAMS OUT : U8 CutID, 
			 U8	FixID  
RETURN     : error
**********************************************************************************/
STCHIP_Error_t  Oxford_GetAfeId(		STCHIP_Handle_t 		hTuner, 
									 	U8 						*CutID,
									 	U8						*FixID)
{
		S32 fld_value;
		
		ChipGetField(hTuner, FAFE_CUT_ID, &fld_value);
		*CutID = (U8)fld_value;
		ChipGetField(hTuner, FAFE_FIX_ID, &fld_value);
		*FixID = (U8)fld_value;
		
		return (STCHIP_Error_t) hTuner->Error ;
}
