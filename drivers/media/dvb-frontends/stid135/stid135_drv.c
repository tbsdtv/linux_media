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

#include "stid135_drv.h"
#include "stid135_init.h"
#include "stid135_initLLA_cut2.h"
#include "c8codew_addr_map.h"
#include "stid135_addr_map.h"

#define DmdLock_TIMEOUT_LIMIT      5500  // Fixed issue BZ#86598
//#define BLIND_SEARCH_AGC2BANDWIDTH  40
#ifndef HOST_PC
	#define DEMOD_IQPOWER_THRESHOLD     10
#endif
 
#define LNF_IP3_SWITCH_LOW  0x3C00
#define LNF_IP3_SWITCH_HIGH 0x8000
#define MODE_LNF 1
#define MODE_IP3 0

#define SNR_MIN_THRESHOLD 9
#define SNR_MAX_THRESHOLD 11

// Code useful for RF level estimation
#define POWER_IREF 95 //105

static u8 mc_mask_bitfield[FE_SAT_MODCODE_MAX];
static u16 mc_reg_addr[FE_SAT_MODCODE_MAX][8];

static struct mc_array_customer st_mc_flt[FE_SAT_MODCODE_MAX] = {
	// MODCODE, SNRx100
	{FE_SATX_QPSK_11_45, -230},
	{FE_SAT_QPSK_14, -230},
	{FE_SATX_QPSK_13_45, -190},
	{FE_SATX_QPSK_4_15, -170},
	{FE_SAT_QPSK_13, -130},
	{FE_SATX_QPSK_14_45, -110},
	{FE_SAT_QPSK_25, -30},
	{FE_SATX_QPSK_9_20, 30},
	{FE_SAT_QPSK_12, 70},
	{FE_SATX_QPSK_7_15, 80},
	{FE_SATX_QPSK_11_20, 160},
	{FE_SATX_QPSK_8_15, 160},
	{FE_SAT_QPSK_35, 230},
	{FE_SAT_QPSK_23, 310},
	{FE_SATX_QPSK_32_45, 390},
	{FE_SAT_QPSK_34, 400},
	{FE_SATX_8PSK_7_15, 420},
	{FE_SAT_QPSK_45, 470},
	{FE_SATX_8PSK_8_15, 500},
	{FE_SAT_QPSK_56, 520},
	{FE_SATX_8APSK_5_9_L, 520},
	{FE_SATX_8APSK_26_45_L, 560},
	{FE_SAT_8PSK_35, 570},
	{FE_SATX_8PSK_26_45, 590},
	{FE_SATX_16APSK_1_2_L, 610},
	{FE_SAT_QPSK_89, 620},
	{FE_SATX_8PSK_23_36, 620},
	{FE_SAT_QPSK_910, 640},
	{FE_SAT_8PSK_23, 660},
	{FE_SATX_16APSK_7_15, 660},
	{FE_SATX_16APSK_8_15_L, 670},
	{FE_SATX_16APSK_5_9_L, 700},
	{FE_SATX_8PSK_25_36, 710},
	{FE_SATX_16APSK_8_15, 750},
	{FE_SATX_8PSK_13_18, 760},
	{FE_SATX_16APSK_26_45, 770},
	{FE_SATX_16APSK_3_5_L, 770},
	{FE_SAT_8PSK_34, 780},
	{FE_SATX_8PSK_32_45, 780},
	{FE_SATX_16APSK_26_45_S, 800},
	{FE_SATX_16APSK_3_5, 810},
	{FE_SATX_16APSK_28_45, 840},
	{FE_SATX_16APSK_23_36, 850},
	{FE_SATX_16APSK_3_5_S, 960},
	{FE_SATX_16APSK_2_3_L, 870},
	{FE_SAT_16APSK_23, 900},
	{FE_SAT_8PSK_56, 930},
	{FE_SATX_16APSK_25_36, 940},
	{FE_SATX_16APSK_13_18, 990},
	{FE_SATX_16APSK_32_45, 1030},
	{FE_SAT_16APSK_34, 1040},
	{FE_SAT_8PSK_89, 1050},
	{FE_SATX_16APSK_7_9, 1070},
	{FE_SAT_8PSK_910, 1080},
	{FE_SAT_16APSK_45, 1110},
	{FE_SAT_16APSK_56, 11600},
	{FE_SATX_32APSK_2_3_L, 11700},
	{FE_SATX_16APSK_77_90, 1200},
	{FE_SATX_32APSK_2_3, 1210},
	{FE_SATX_32APSK_32_45, 1250},
	{FE_SAT_16APSK_89, 1290},
	{FE_SATX_32APSK_11_15, 1290},
	{FE_SATX_32APSK_32_45_S, 1300},
	{FE_SAT_16APSK_910, 1320},
	{FE_SAT_32APSK_34, 1340},
	{FE_SATX_32APSK_7_9, 1370},
	{FE_SAT_32APSK_45, 1430},
	{FE_SAT_32APSK_56, 1490},
	{FE_SATX_64APSK_32_45_L, 1500},
	{FE_SATX_64APSK_11_15, 1600},
	{FE_SAT_32APSK_89, 1650},
	{FE_SAT_32APSK_910, 1690},
	{FE_SATX_64APSK_7_9, 1710},
	{FE_SATX_64APSK_4_5, 1740},
	{FE_SATX_64APSK_5_6, 1820},
	{FE_SATX_256APSK_29_45_L, 1890},
	{FE_SATX_128APSK_3_4, 1920},
	{FE_SATX_256APSK_32_45, 1920},
	{FE_SATX_256APSK_2_3_L, 1950},
	{FE_SATX_128APSK_7_9, 1970},
	{FE_SATX_256APSK_31_45_L, 2020},
	{FE_SATX_256APSK_11_15_L, 2030},
	{FE_SATX_256APSK_3_4, 2060}
};


static u32 LutGvanaIntegerTuner[256]={
	93487, 93305, 93201, 93274, 93202, 93316, 93319, 93252, 92752, 93298,
	93264, 93296, 93328, 93315, 93056, 93264, 93320, 93250, 93238, 92295,
	92289, 92317, 92248, 92247, 92160, 92294, 92177, 92266, 92236, 91284,
	91281, 91241, 91177, 91266, 91101, 90906, 90269, 90212, 90161, 90156,
	89737, 89249, 89187, 89141, 88726, 88180, 88153, 88077, 87403, 87179,
    87009, 86343, 86159, 86084, 85236, 85142, 84892, 84190, 84163, 83905,
    83191, 83170, 82753, 82192, 82237, 82221, 82206, 82191, 82175, 82160,
    82244, 81610, 81766, 81257, 81173, 81240, 80608, 80474, 80310, 80152,
    79763, 79315, 79216, 78844, 78596, 78246, 78041, 77663, 77503, 77188,
    76988, 76658, 76308, 76118, 75884, 75654, 75301, 75059, 74921, 74654,
    74196, 73898, 73761, 73749, 73269, 72920, 73004, 72454, 72332, 72078,
    71956, 71653, 71278, 71091, 71099, 70689, 70412, 70243, 70029, 70030,
    69584, 69207, 69175, 68916, 68920, 68416, 68209, 67959, 68076, 67758,
    67259, 67237, 67039, 67074, 66832, 66211, 66347, 65984, 65998, 65751,
    65170, 65436, 65035, 65086, 64862, 64365, 64238, 64245, 64089, 63970,
    63432, 63126, 63377, 62986, 62915, 62640, 62203, 62421, 61991, 62235,
    61703, 61332, 61175, 61178, 61029, 60691, 60597, 60271, 60118, 60234,
    59916, 59760, 59323, 59133, 59342, 59025, 58894, 58476, 58328, 57986,
    58407, 57945, 57666, 57391, 57235, 57735, 57070, 56676, 57088, 56301,
    56330, 56239, 55825, 55515, 55243, 55211, 54608, 54257, 54153, 53583,
    53286, 53372, 52810, 52243, 52259, 51731, 51267, 51354, 50613, 50294,
    50259, 49644, 49342, 49245, 48834, 48324, 48241, 47986, 47377, 47363,
    47234, 46803, 46722, 46185, 46315, 46414, 45640, 45702, 45219, 45333,
    45179, 45699, 44951, 44933, 44525, 44199, 44706, 44172, 44203, 44689,
    43869, 45183, 44692, 43704, 43194, 43548, 43181, 43179, 43177, 43198,
    43220, 43207, 43195, 43194, 43282, 43370
};

// End of code useful for RF level estimation

//==============================================================================
// Types

struct fe_sat_car_loop_vs_mode_code {
	enum fe_sat_modcode ModCode;
	u8 CarLoopPilotsOn_2;
	u8 CarLoopPilotsOff_2;
	u8 CarLoopPilotsOn_5;
	u8 CarLoopPilotsOff_5;
	u8 CarLoopPilotsOn_10;
	u8 CarLoopPilotsOff_10;
	u8 CarLoopPilotsOn_20;
	u8 CarLoopPilotsOff_20;
	u8 CarLoopPilotsOn_30;
	u8 CarLoopPilotsOff_30;
	u8 CarLoopPilotsOn_62_5;
	u8 CarLoopPilotsOff_62_5;
	u8 CarLoopPilotsOn_125;
	u8 CarLoopPilotsOff_125;
	u8 CarLoopPilotsOn_300;
	u8 CarLoopPilotsOff_300;
	u8 CarLoopPilotsOn_400;
	u8 CarLoopPilotsOff_400;
	u8 CarLoopPilotsOn_500;
	u8 CarLoopPilotsOff_500;
};	

/*****************************************************
--STRUCTURE	::	FE_STiD135_S2_CN_LookUp
--DESCRIPTION	::	DVBS2 C/N Look-Up table.
	Lookup table used to convert register
	to C/N value for DVBS2.
--***************************************************/
static fe_lla_lookup_t  FE_STiD135_S2_CN_LookUp = {
51,                                              
	{   
		/* SFE(dB), Noise DVBS2 */
 
		{-32, 13393 }, { -22, 12561 }, {-17, 12200 },
		{-12, 11767 }, {-2, 11030 }, {8, 10208 },
		{18, 9441 }, {28, 8695 }, {38, 7944 },
		{48, 7275 }, {58, 6607 }, {68, 5992 },
		{78, 5384 }, {88, 4851 }, {98, 4357 },
		{108, 3936 }, {118, 3488 }, {128, 3134 },
		{138, 2795 }, {148, 2484 }, {158, 2214 },
		{168, 1997 }, {178, 1767 }, {188, 1585 },
		{198, 1401 }, {208, 1264 }, {218, 1118 },
		{228, 996 }, {238, 896 }, {248, 798 },
		{258, 713 }, {268, 645 }, {278, 596 },
		{288, 591 }, {298, 558 }, {308, 493 },
		{318, 459 }, {328, 430 }, {338, 415 },
		{348, 400 }, {358, 385 }, {368, 382 },
		{378, 380 }, {388, 371 }, {398, 339 },
		{498, 280 }, {598, 230 }, {698, 205 },
		{798, 185 }, {898, 170 }, {998, 160 }
	}
};


/*****************************************************
--STRUCTURE	::	FE_STiD135_S1_CN_LookUp
--DESCRIPTION	::	DVBS1 C/N Look-Up table.
	Lookup table used to convert register
	to C/N value for DVBS1/DSS.
--***************************************************/
static fe_lla_lookup_t  FE_STiD135_S1_CN_LookUp = {
34,
	{
		/* SFE(dB) Noise DVBS1  */
		
		{  -2, 9200 }, {   8, 8800 }, {  18, 8350 }, {  28, 7920 },
		{  38, 7492 }, {  48, 7010 }, {  58, 6475 }, {  68, 5920 },
		{  78, 5378 }, {  88, 4848 }, {  98, 4370 }, { 108, 3909 },
		{ 118, 3500 }, { 128, 3125 }, { 138, 2788 }, { 148, 2485 },
		{ 158, 2226 }, { 168, 1975 }, { 178, 1759 }, { 188, 1573 },
		{ 198, 1400 }, { 208, 1247 }, { 218, 1112 }, { 228, 1000 },
		{ 238,  890 }, { 248,  800 }, { 258,  710 }, { 268,  636 },
		{ 278,  581 }, { 288,  524 }, { 298,  478 }, { 308,  440 },
		{ 318,  394 }, { 328,  355 }
	}
};

/*****************************************************
--STRUCTURE	::	fe_stid135_avs_look_up
--DESCRIPTION	::	AVS Look-Up table.
	Lookup table used to convert process code
	to PWM value (AVS voltage)
--***************************************************/
static fe_lla_lookup_t fe_stid135_avs_look_up = {
16,
	{
		// On Oxford valid board :
		// register = 0x00 => Vavs=1.297V
		// register = 0xFF => Vavs=0.789V
		{ 0x30, 0 }, // 1.2V
		{ 0x30, 1 }, // 1.2V
		{ 0x3a, 2 }, // 1.18V
		{ 0x44, 3 }, // 1.16V
		{ 0x4e, 4 }, // 1.14V
		{ 0x56, 5 }, // 1.125V
		{ 0x5d, 6 }, // 1.11V
		{ 0x62, 7 }, // 1.1V
		{ 0x67, 8 }, // 1.09V
		{ 0x6e, 9 }, // 1.077V
		{ 0x75, 10 }, // 1.063V
		{ 0x7b, 11 }, // 1.05V
		{ 0x83, 12 }, // 1.035V
		{ 0x8b, 13 }, // 1.02V
		{ 0x90, 14 }, // 1.01V
		{ 0x95, 15 } // 1.0V
	}
};


/*****************************************************************
Tracking carrier loop carrier QPSK 1/4   to QPSK 2/5    Normal Frame
Tracking carrier loop carrier QPSK 1/2   to 8PSK 9/10   Normal Frame   
Tracking carrier loop carrier 16APSK 2/3 to 32APSK 9/10 Normal Frame   
******************************************************************/
static struct fe_sat_car_loop_vs_mode_code FE_STiD135_S2CarLoop[NB_SAT_MODCOD] = {
/*Modcod		2MPon 	2MPoff	5MPon 	5MPoff	10MPon 	10MPoff	20MPon 	20MPoff	30MPon 	30MPoff	62.5MPon	62.5MPoff	125MPon	125MPoff	300MPon	300MPoff	400MPon	400MPoff	500MPon	500MPoff*/
/* Low CR QPSK */
	{FE_SAT_QPSK_14,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},
	{FE_SAT_QPSK_13,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},
	{FE_SAT_QPSK_25,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},
/* QSPSK */
	{FE_SAT_QPSK_12,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},
	{FE_SAT_QPSK_35,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},
	{FE_SAT_QPSK_23,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},
	{FE_SAT_QPSK_34,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SAT_QPSK_45,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SAT_QPSK_56,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SAT_QPSK_89,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SAT_QPSK_910,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
/* QPSK S2X NORMAL FRAME */
	{FE_SATX_QPSK_13_45,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},
	{FE_SATX_QPSK_9_20,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},
	{FE_SATX_QPSK_11_20,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},
/* QPSK S2X SHORT FRAME */
	{FE_SATX_QPSK_11_45,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},
	{FE_SATX_QPSK_4_15,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},
	{FE_SATX_QPSK_14_45,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},
	{FE_SATX_QPSK_7_15,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},
	{FE_SATX_QPSK_8_15,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},
	{FE_SATX_QPSK_32_45,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
/* 8SPSK */
	{FE_SAT_8PSK_35,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},
	{FE_SAT_8PSK_23,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SAT_8PSK_34,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SAT_8PSK_56,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SAT_8PSK_89,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SAT_8PSK_910,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
/* 8PSK S2X NORMAL FRAME */
	{FE_SATX_8PSK_23_36,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},
	{FE_SATX_8PSK_25_36,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SATX_8PSK_13_18,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
/* 8PSK S2X SHORT FRAME */
	{FE_SATX_8PSK_7_15,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26},
	{FE_SATX_8PSK_8_15,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26},
	{FE_SATX_8PSK_26_45,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},
	{FE_SATX_8PSK_32_45,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
/* 8PSK_L S2X NORMAL FRAME */
	{FE_SATX_8APSK_5_9_L,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26},
	{FE_SATX_8APSK_26_45_L,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},
/* 16ASPSK */
	{FE_SAT_16APSK_23,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SAT_16APSK_34,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SAT_16APSK_45,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SAT_16APSK_56,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SAT_16APSK_89,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SAT_16APSK_910,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
/* 16APSK S2X NORMAL FRAME */
	{FE_SATX_16APSK_26_45,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_3_5,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_28_45,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_23_36,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_25_36,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_13_18,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_7_9,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_77_90,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
/* 16APSK S2X SHORT FRAME */
	{FE_SATX_16APSK_7_15,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_8_15,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_26_45_S,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_3_5_S,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_32_45,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
/* 16APSK_L S2X NORMAL FRAME */
	{FE_SATX_16APSK_1_2_L,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_8_15_L,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_5_9_L, 	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_3_5_L,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SATX_16APSK_2_3_L, 	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
/* 32ASPSK */
	{FE_SAT_32APSK_34,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
	{FE_SAT_32APSK_45,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SAT_32APSK_56,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SAT_32APSK_89,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SAT_32APSK_910,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
/* 32APSK S2X NORMAL FRAME */
	{FE_SATX_32APSK_32_45,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SATX_32APSK_11_15,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SATX_32APSK_7_9,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
/* 32APSK S2X SHORT FRAME */
	{FE_SATX_32APSK_2_3,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
	{FE_SATX_32APSK_32_45_S,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},
/* 32APSK_L S2X NORMAL FRAME */
	{FE_SATX_32APSK_2_3_L,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},
/* 64APSK S2X NORMAL FRAME */
	{FE_SATX_64APSK_11_15,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SATX_64APSK_7_9,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SATX_64APSK_4_5,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SATX_64APSK_5_6,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
/* 64APSK_L S2X NORMAL FRAME */
	{FE_SATX_64APSK_32_45_L,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
/* 128APSK S2X NORMAL FRAME */
	{FE_SATX_128APSK_3_4,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SATX_128APSK_7_9,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
/* 256APSK S2X NORMAL FRAME */
	{FE_SATX_256APSK_32_45,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SATX_256APSK_3_4,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SATX_256APSK_29_45_L,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SATX_256APSK_2_3_L,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SATX_256APSK_31_45_L,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},
	{FE_SATX_256APSK_11_15_L,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09}
};

#define NB_QPSK_COEFF 20
#define NB_8PSK_COEFF 15
#define NB_16APSK_COEFF 24
#define NB_32APSK_COEFF 11
#define NB_64APSK_COEFF 5
#define NB_128APSK_COEFF 2
#define NB_256APSK_COEFF 6

static struct fe_sat_car_loop_vs_cnr fe_stid135_qpsk_car_loop[NB_QPSK_COEFF] =  										
{/* QPSK */										
	/* CNRx10	0.5Msps	10Msps	30Msps	62.5Msps	125Msps	300Msps	400Msps	500Msps */	
	{-23,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},	/* FE_SATX_QPSK_11_45 */
	{-22,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},	/* FE_SAT_QPSK_14 */
	{-18,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},	/* FE_SATX_QPSK_13_45 */
	{-16,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},	/* FE_SATX_QPSK_4_15 */
	{-12,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},	/* FE_SAT_QPSK_13 */
	{-10,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},	/* FE_SATX_QPSK_14_45 */
	{-2,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},	/* FE_SAT_QPSK_25 */
	{4,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},	/* FE_SATX_QPSK_9_20 */
	{9,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},	/* FE_SATX_QPSK_7_15 */
	{11,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},	/* FE_SAT_QPSK_12 */
	{17,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},	/* FE_SATX_QPSK_11_20 */
	{18,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},	/* FE_SATX_QPSK_8_15 */
	{24,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},	/* FE_SAT_QPSK_35 */
	{32,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},	/* FE_SAT_QPSK_23 */
	{40,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SATX_QPSK_32_45 */
	{41,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SAT_QPSK_34 */
	{48,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SAT_QPSK_45 */
	{53,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SAT_QPSK_56 */
	{63,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SAT_QPSK_89 */
	{65,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08}	/* FE_SAT_QPSK_910 */
};

static struct fe_sat_car_loop_vs_cnr fe_stid135_8psk_car_loop[NB_8PSK_COEFF] =										
{/* 8PSK */										
	/* CNRx10	0.5Msps	10Msps	30Msps	62.5Msps	125Msps	300Msps	400Msps	500Msps */	
	{43,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26},	/* FE_SATX_8PSK_7_15 */
	{51,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26},	/* FE_SATX_8PSK_8_15 */
	{53,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26,	0x26},	/* FE_SATX_8APSK_5_9_L */
	{57,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},	/* FE_SATX_8APSK_26_45_L */
	{58,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07,	0x07},	/* FE_SAT_8PSK_35 */
	{60,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},	/* FE_SATX_8PSK_26_45 */
	{63,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27,	0x27},	/* FE_SATX_8PSK_23_36 */
	{67,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SAT_8PSK_23 */
	{72,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SATX_8PSK_25_36 */
	{77,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SATX_8PSK_13_18 */
	{79,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SATX_8PSK_32_45 */
	{80,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SAT_8PSK_34 */
	{94,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SAT_8PSK_56 */
	{106,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SAT_8PSK_89 */
	{109,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08}	/* FE_SAT_8PSK_910 */
};										

static struct fe_sat_car_loop_vs_cnr fe_stid135_16apsk_car_loop[NB_16APSK_COEFF] =										
{/* 16APSK */										
	/* CNRx10	0.5Msps	10Msps	30Msps	62.5Msps	125Msps	300Msps	400Msps	500Msps */	
	{62,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_1_2_L */
	{67,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_7_15 */
	{68,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_8_15_L */
	{71,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_5_9_L */
	{76,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_8_15 */
	{78,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_3_5_L */
	{79,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_26_45 */
	{81,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_26_45_S */
	{82,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_3_5 */
	{85,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_28_45 */
	{86,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_23_36 */
	{87,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_3_5_S */
	{88,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_2_3_L */
	{91,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SAT_16APSK_23 */
	{95,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_25_36 */
	{100,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_13_18 */
	{104,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_32_45 */
	{105,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SAT_16APSK_34 */
	{108,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_7_9 */
	{112,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SAT_16APSK_45 */
	{117,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SAT_16APSK_56 */
	{121,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_16APSK_77_90 */
	{130,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SAT_16APSK_89 */
	{133,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28}	/* FE_SAT_16APSK_910 */
};										

static struct fe_sat_car_loop_vs_cnr fe_stid135_32apsk_car_loop[NB_32APSK_COEFF] =										
{/* 32APSK */										
  	/* CNRx10	0.5Msps	10Msps	30Msps	62.5Msps	125Msps	300Msps	400Msps	500Msps */	
	{118,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SATX_32APSK_2_3_L */
	{122,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SATX_32APSK_2_3 */
	{126,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SATX_32APSK_32_45 */
	{130,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08,	0x08},	/* FE_SATX_32APSK_11_15 */
	{131,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_32APSK_32_45_S */
	{135,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SAT_32APSK_34 */
	{138,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28,	0x28},	/* FE_SATX_32APSK_7_9 */
	{144,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SAT_32APSK_45 */
	{150,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SAT_32APSK_56 */
	{166,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SAT_32APSK_89 */
	{170,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09}	/* FE_SAT_32APSK_910 */
};										

static struct fe_sat_car_loop_vs_cnr fe_stid135_64apsk_car_loop[NB_64APSK_COEFF] =										
{/* 64APSK */										
	/* CNRx10	0.5Msps	10Msps	30Msps	62.5Msps	125Msps	300Msps	400Msps	500Msps */	
	{151,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SATX_64APSK_32_45_L */
	{161,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SATX_64APSK_11_15 */
	{172,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SATX_64APSK_7_9 */
	{175,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SATX_64APSK_4_5 */
	{183,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09}	/* FE_SATX_64APSK_5_6 */
};										
										
static struct fe_sat_car_loop_vs_cnr fe_stid135_128apsk_car_loop[NB_128APSK_COEFF] =										
{/* 128APSK */										
	/* CNRx10	0.5Msps	10Msps	30Msps	62.5Msps	125Msps	300Msps	400Msps	500Msps */	
	{193,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SATX_128APSK_3_4 */
	{198,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09}	/* FE_SATX_128APSK_7_9 */
};										
										
static struct fe_sat_car_loop_vs_cnr fe_stid135_256apsk_car_loop[NB_256APSK_COEFF] =										
{/* 256APSK */										
	/* CNRx10	0.5Msps	10Msps	30Msps	62.5Msps	125Msps	300Msps	400Msps	500Msps */	
	{190,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SATX_256APSK_29_45_L */
	{193,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SATX_256APSK_32_45 */
	{196,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SATX_256APSK_2_3_L */
	{203,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SATX_256APSK_31_45_L */
	{204,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09},	/* FE_SATX_256APSK_11_15_L */
	{207,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09,	0x09}	/* FE_SATX_256APSK_3_4 */
};
static  u16 dvbs2_modcode_for_llr_x100[131] = {
	0,	//FE_SAT_DUMMY_PLF,
	400,	//FE_SAT_QPSK_14,
	300,	//FE_SAT_QPSK_13,
	250,	//FE_SAT_QPSK_25,
	200,	//FE_SAT_QPSK_12,
	167,	//FE_SAT_QPSK_35,
	150,	//FE_SAT_QPSK_23,
	133,	//FE_SAT_QPSK_34,
	125,	//FE_SAT_QPSK_45,
	120,	//FE_SAT_QPSK_56,
	113,	//FE_SAT_QPSK_89,
	111,	//FE_SAT_QPSK_910,
	167,	//FE_SAT_8PSK_35,
	150,	//FE_SAT_8PSK_23,
	133,	//FE_SAT_8PSK_34,
	120,	//FE_SAT_8PSK_56,
	113,	//FE_SAT_8PSK_89,
	111,	//FE_SAT_8PSK_910,
	150,	//FE_SAT_16APSK_23,
	133,	//FE_SAT_16APSK_34,
	125,	//FE_SAT_16APSK_45,
	120,	//FE_SAT_16APSK_56,
	113,	//FE_SAT_16APSK_89,
	111,	//FE_SAT_16APSK_910,
	133,	//FE_SAT_32APSK_34,
	125,	//FE_SAT_32APSK_45,
	120,	//FE_SAT_32APSK_56,
	113,	//FE_SAT_32APSK_89,
	111,	//FE_SAT_32APSK_910,
	0,		//FE_SAT_MODCODE_UNKNOWN,
	/* below modcodes are part of DVBS2x */

	0,	//FE_SAT_MODCODE_UNKNOWN_1E = 0x1E,
	0,	//FE_SAT_MODCODE_UNKNOWN_1F  = 0x1F,
	200,	//FE_SAT_DVBS1_QPSK_12 = 0x20,
	150,	//FE_SAT_DVBS1_QPSK_23 = 0x21,
	133,	//FE_SAT_DVBS1_QPSK_34 = 0x22,
	120,	//FE_SAT_DVBS1_QPSK_56 = 0x23,
	117,	//FE_SAT_DVBS1_QPSK_67 = 0x24,
	114,	//FE_SAT_DVBS1_QPSK_78 = 0x25,
	0,	//FE_SAT_MODCODE_UNKNOWN_26 = 0x26,
	0,	//FE_SAT_MODCODE_UNKNOWN_27 = 0x27,
	0,	//FE_SAT_MODCODE_UNKNOWN_28 = 0x28,
	0,	//FE_SAT_MODCODE_UNKNOWN_29 = 0x29,
	0,	//FE_SAT_MODCODE_UNKNOWN_2A = 0x2A,
	0,	//FE_SAT_MODCODE_UNKNOWN_2B = 0x2B,
	0,	//FE_SAT_MODCODE_UNKNOWN_2C = 0x2C,
	0,	//FE_SAT_MODCODE_UNKNOWN_2D = 0x2D,
	0,	//FE_SAT_MODCODE_UNKNOWN_2E = 0x2E,
	0,	//FE_SAT_MODCODE_UNKNOWN_2F = 0x2F,
	0,	//FE_SAT_MODCODE_UNKNOWN_30 = 0x30,
	0,	//FE_SAT_MODCODE_UNKNOWN_31 = 0x31,
	0,	//FE_SAT_MODCODE_UNKNOWN_32 = 0x32,
	0,	//FE_SAT_MODCODE_UNKNOWN_33 = 0x33,
	0,	//FE_SAT_MODCODE_UNKNOWN_34 = 0x34,
	0,	//FE_SAT_MODCODE_UNKNOWN_35 = 0x35,
	0,	//FE_SAT_MODCODE_UNKNOWN_36 = 0x36,
	0,	//FE_SAT_MODCODE_UNKNOWN_37 = 0x37,
	0,	//FE_SAT_MODCODE_UNKNOWN_38 = 0x38,
	0,	//FE_SAT_MODCODE_UNKNOWN_39 = 0x39,
	0,	//FE_SAT_MODCODE_UNKNOWN_3A = 0x3A,
	0,	//FE_SAT_MODCODE_UNKNOWN_3B = 0x3B,
	0,	//FE_SAT_MODCODE_UNKNOWN_3C = 0x3C,
	0,	//FE_SAT_MODCODE_UNKNOWN_3D = 0x3D,
	0,	//FE_SAT_MODCODE_UNKNOWN_3E = 0x3E,
	0,	//FE_SAT_MODCODE_UNKNOWN_3F = 0x3F,
	0,	//FE_SATX_VLSNR1		  = 0x40,
	0,	//FE_SATX_VLSNR2		= 0x41,
	346,	//FE_SATX_QPSK_13_45	  = 0x42,
	222,	//FE_SATX_QPSK_9_20 	= 0x43,
	182,	//FE_SATX_QPSK_11_20	  = 0x44,
	180,	//FE_SATX_8APSK_5_9_L	= 0x45,
	173,	//FE_SATX_8APSK_26_45_L   = 0x46,
	157,	//FE_SATX_8PSK_23_36	= 0x47,
	144,	//FE_SATX_8PSK_25_36	  = 0x48,
	138,	//FE_SATX_8PSK_13_18	= 0x49,
	200,	//FE_SATX_16APSK_1_2_L	  = 0x4A,
	188,	//FE_SATX_16APSK_8_15_L = 0x4B,
	180,	//FE_SATX_16APSK_5_9_L	  = 0x4C,
	173,	//FE_SATX_16APSK_26_45	= 0x4D,
	167,	//FE_SATX_16APSK_3_5	  = 0x4E,
	167,	//FE_SATX_16APSK_3_5_L	= 0x4F,
	161,	//FE_SATX_16APSK_28_45	  = 0x50,
	157,	//FE_SATX_16APSK_23_36	= 0x51,
	150,	//FE_SATX_16APSK_2_3_L	  = 0x52,
	144,	//FE_SATX_16APSK_25_36	= 0x53,
	138,	//FE_SATX_16APSK_13_18	  = 0x54,
	129,	//FE_SATX_16APSK_7_9	= 0x55,
	117,	//FE_SATX_16APSK_77_90	  = 0x56,
	150,	//FE_SATX_32APSK_2_3_L	= 0x57,
	0,	//FE_SATX_32APSK_R_58	  = 0x58,
	141,	//FE_SATX_32APSK_32_45	= 0x59,
	136,	//FE_SATX_32APSK_11_15	  = 0x5A,
	129,	//FE_SATX_32APSK_7_9	= 0x5B,
	141,	//FE_SATX_64APSK_32_45_L  = 0x5C,
	136,	//FE_SATX_64APSK_11_15	= 0x5D,
	0,	//FE_SATX_64APSK_R_5E	  = 0x5E,
	129,	//FE_SATX_64APSK_7_9	= 0x5F,
	0,	//FE_SATX_64APSK_R_60	  = 0x60,
	125,	//FE_SATX_64APSK_4_5	= 0x61,
	0,	//FE_SATX_64APSK_R_62	  = 0x62,
	120,	//FE_SATX_64APSK_5_6	= 0x63,
	133,	//FE_SATX_128APSK_3_4	  = 0x64,
	129,	//FE_SATX_128APSK_7_9	= 0x65,
	155,	//FE_SATX_256APSK_29_45_L = 0x66,
	150,	//FE_SATX_256APSK_2_3_L = 0x67,
	145,	//FE_SATX_256APSK_31_45_L = 0x68,
	141,	//FE_SATX_256APSK_32_45 = 0x69,
	136,	//FE_SATX_256APSK_11_15_L = 0x6A,
	133,	//FE_SATX_256APSK_3_4	= 0x6B,
	409,	//FE_SATX_QPSK_11_45_S	  = 0x6C,
	375,	//FE_SATX_QPSK_4_15_S	= 0x6D,
	321,	//FE_SATX_QPSK_14_45_S	  = 0x6E,
	214,	//FE_SATX_QPSK_7_15_S	= 0x6F,
	188,	//FE_SATX_QPSK_8_15_S	  = 0x70,
	141,	//FE_SATX_QPSK_32_45_S	= 0x71,
	214,	//FE_SATX_8PSK_7_15_S	  = 0x72,
	188,	//FE_SATX_8PSK_8_15_S	= 0x73,
	173,	//FE_SATX_8PSK_26_45_S	  = 0x74,
	141,	//FE_SATX_8PSK_32_45_S	= 0x75,
	214,	//FE_SATX_16APSK_7_15_S   = 0x76,
	188,	//FE_SATX_16APSK_8_15_S = 0x77,
	173,	//FE_SATX_16APSK_26_45_S  = 0x78,
	167,	//FE_SATX_16APSK_3_5_S	= 0x79,
	141,	//FE_SATX_16APSK_32_45_S  = 0x7A,
	150,	//FE_SATX_32APSK_2_3_S	= 0x7B,
	141,	//FE_SATX_32APSK_32_45_S  = 0x7C,  
	0,	//FE_SATX_8PSK			= 0x7D,
	0,	//FE_SATX_32APSK		= 0x7E,
	0,	//FE_SATX_256APSK		= 0x7F,  /* POFF Modes */			
	0,	//FE_SATX_16APSK	= 0x80,
	0,	//FE_SATX_64APSK	= 0x81,
	0,	//FE_SATX_1024APSK		= 0x82,

};	/*ModCod for DVBS2*/

	

 static u8 dvbs1_modcode_for_llr_x100[8] = {
	200,	//FE_SAT_PR_1_2 =0,
	150,	//FE_SAT_PR_2_3,	
	133,	//FE_SAT_PR_3_4,
	125,	//FE_SAT_PR_4_5,	/* for turbo code only */
	120,	//FE_SAT_PR_5_6,
	117,	//FE_SAT_PR_6_7,	/* for DSS only */
	114,	//FE_SAT_PR_7_8,
	113 //FE_SAT_PR_8_9,	/* for turbo code only */
	//FE_SAT_PR_UNKNOWN
};	/*ModCod for DVBS1*/
/******************* 
Current LLA revision	
********************/
static const ST_Revision_t Revision  = "STiD135-LLA_REL_1.4.0-December_2018";

/*==============================================================================*/
/* Function Declarations  */

static fe_lla_error_t FE_STiD135_GetDemodLock    (fe_stid135_handle_t handle,
					 enum fe_stid135_demod Demod, u32 TimeOut, BOOL *Lock);
static fe_lla_error_t FE_STiD135_StartSearch     (struct fe_stid135_internal_param *pParams,
					enum fe_stid135_demod Demod); 
static fe_lla_error_t FE_STiD135_GetSignalParams(
		struct fe_stid135_internal_param *pParams, enum fe_stid135_demod Demod,
		BOOL satellitte_scan, enum fe_sat_signal_type *range_p);

static fe_lla_error_t FE_STiD135_TrackingOptimization(
		struct fe_stid135_internal_param *pParams, enum fe_stid135_demod Demod);
static fe_lla_error_t FE_STiD135_BlindSearchAlgo(struct fe_stid135_internal_param *pParams, 
		u32 demodTimeout, BOOL satellitte_scan, enum fe_stid135_demod Demod, BOOL* lock_p);
static fe_lla_error_t fe_stid135_get_agcrf_path(stchip_handle_t hChip,
			enum fe_stid135_demod demod, s32* agcrf_path_p);
static fe_lla_error_t FE_STiD135_GetFECLock (stchip_handle_t hChip, enum fe_stid135_demod Demod, 
	u32 TimeOut, BOOL* lock_bool_p);
fe_lla_error_t fe_stid135_manage_matype_info(fe_stid135_handle_t Handle,
						enum fe_stid135_demod Demod);
static fe_lla_error_t fe_stid135_manage_matype_info_raw_bbframe(fe_stid135_handle_t Handle,
						enum fe_stid135_demod Demod);
static fe_lla_error_t fe_stid135_flexclkgen_init(fe_stid135_handle_t handle);
static fe_lla_error_t fe_stid135_set_reg_init_values(fe_stid135_handle_t handle, enum fe_stid135_demod demod);
static fe_lla_error_t fe_stid135_set_reg_values_wb(fe_stid135_handle_t handle, enum fe_stid135_demod demod);
#ifdef USER2
	static fe_lla_error_t fe_stid135_manage_manual_rolloff(fe_stid135_handle_t handle, enum fe_stid135_demod demod);
#endif
static BOOL fe_stid135_check_sis_or_mis(u8 matype);
static fe_lla_error_t fe_stid135_get_mode_code(struct fe_stid135_internal_param *pParams,
					enum fe_stid135_demod demod,
					enum fe_sat_modcode *modcode, 
					enum fe_sat_frame *frame, 
					enum fe_sat_pilots *pilots);

fe_lla_error_t FE_STiD135_TunerStandby(stchip_handle_t TunerHandle,
				       FE_OXFORD_TunerPath_t TunerNb, u8 Enable);

fe_lla_error_t fe_stid135_set_vcore_supply(fe_stid135_handle_t handle);
static fe_lla_error_t fe_stid135_select_min_isi(fe_stid135_handle_t handle, enum fe_stid135_demod demod);
static void fe_stid135_modcod_flt_reg_init(void);

//==============================================================================

/*****************************************************
**FUNCTION	:: FE_STiD135_GetMclkFreq
**ACTION	:: Returns the master clock frequency
**PARAMS IN	:: Handle ==> handle to the chip
**PARAMS OUT	:: Synthesizer frequency (Hz)
**RETURN	:: error
*****************************************************/
fe_lla_error_t FE_STiD135_GetMclkFreq(fe_stid135_handle_t Handle, u32* MclkFreq_p)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	
	/*  Validation Board V1.0  */
	error |= FE_STiD135_GetLoFreqHz(Handle, MclkFreq_p);
	*MclkFreq_p =    (*MclkFreq_p * 1000000) / 12;

	return error;
}

/*****************************************************
**FUNCTION	:: FE_STiD135_GetMclkFreq
**ACTION	:: This function returns the LO frequency.
**PARAMS IN	:: Handle ==> Front End Handle
**PARAMS OUT	:: LO frequency ()
**RETURN	:: error
*****************************************************/
fe_lla_error_t FE_STiD135_GetLoFreqHz(fe_stid135_handle_t Handle, u32* LoFreq_p)
{
	struct fe_stid135_internal_param *pParams;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	
	*LoFreq_p = Oxford_GetFvco_MHz(pParams->handle_demod, pParams->quartz);
	*LoFreq_p /=4;
	
	return error;
}

/*****************************************************
--FUNCTION	::	GetSymbolRate
--ACTION	::	Get the current symbol rate
--PARAMS IN	::	hChip		->	handle to the chip
			MasterClock	->	Masterclock frequency (Hz)
			demod		->	current demod 1 .. 8
--PARAMS OUT	::	Symbol rate in Symbol/s
--RETURN	::	error
*****************************************************/
fe_lla_error_t FE_STiD135_GetSymbolRate(stchip_handle_t hChip,u32 MasterClock, 
				enum fe_stid135_demod Demod, u32* symbolRate_p)
{
	u32 sfrField3, 
	sfrField2,
	sfrField1,
	sfrField0,
	rem1,
	rem2;
	
	u32 intval1,
	intval2;
	u16 sfrReg;
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	
	sfrField3 = FLD_FC8CODEW_DVBSX_DEMOD_SFR3_SYMB_FREQ(Demod);	/*Found SR, byte 3*/
	sfrField2 = FLD_FC8CODEW_DVBSX_DEMOD_SFR2_SYMB_FREQ(Demod);	/*Found SR, byte 2*/
	sfrField1 = FLD_FC8CODEW_DVBSX_DEMOD_SFR1_SYMB_FREQ(Demod);	/*Found SR, byte 1*/
	sfrField0 = FLD_FC8CODEW_DVBSX_DEMOD_SFR0_SYMB_FREQ(Demod);	/*Found SR, byte 0*/
	sfrReg = (u16)REG_RC8CODEW_DVBSX_DEMOD_SFR3(Demod);

	
	error |= ChipGetRegisters(hChip, sfrReg, 4);
	*symbolRate_p = (u32)((ChipGetFieldImage(hChip, sfrField3) << 24)
		+ (ChipGetFieldImage(hChip, sfrField2) << 16)
		+ (ChipGetFieldImage(hChip, sfrField1) << 8)
		+ (ChipGetFieldImage(hChip, sfrField0)));
	

	MasterClock = MasterClock * 12;
		
	intval1 = MasterClock >> 16;
	intval2 = *symbolRate_p  >> 16;

	rem1 = (MasterClock) % 0x10000;
	rem2 = (*symbolRate_p) % 0x10000;

	*symbolRate_p =(intval1 * intval2) +
			((intval1 * rem2) >> 16) +
		  	((intval2 * rem1) >> 16);
	/* only for integer calculation */

	return error;
	
}


/*****************************************************
--FUNCTION	::	fe_stid135_set_symbol_rate
--ACTION	::	Set the Symbol rate
--PARAMS IN	::	hChip		->	handle to the chip
			master_clock	->	Masterclock frequency (Hz)
			symbol_rate	->	Symbol Rate (Symbol/s)
			demod		->	current demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	error
*****************************************************/
fe_lla_error_t fe_stid135_set_symbol_rate(stchip_handle_t hchip, u32 master_clock,
				u32 symbol_rate, enum fe_stid135_demod demod)
{
	u32 reg_field2, reg_field1, reg_field0;
	u32 reg32;

	fe_lla_error_t error = FE_LLA_NO_ERROR;  

	reg_field2 = FLD_FC8CODEW_DVBSX_DEMOD_SFRINIT2_SFR_INIT(demod);
	reg_field1 = FLD_FC8CODEW_DVBSX_DEMOD_SFRINIT1_SFR_INIT(demod);
	reg_field0 = FLD_FC8CODEW_DVBSX_DEMOD_SFRINIT0_SFR_INIT(demod);
	
	/* Hypothesis: master_clock=130MHz, symbol_rate=0.5MSymb/s..500MSymb/s
	FVCO/4/12=6.2GHz/4/12=130MHz*/

	reg32 = (1<<27) / (master_clock/10000);
	reg32 = reg32 * (symbol_rate/10000);
	reg32 = reg32 / (3*(1<<5));

	error |= ChipSetFieldImage(hchip, reg_field2,
			((int)reg32 >> 16) & 0xFF);
	error |= ChipSetFieldImage(hchip, reg_field1,
			((int)reg32 >> 8) & 0xFF); 
	error |= ChipSetFieldImage(hchip, reg_field0,
			((int)reg32) & 0xFF);
	
	error |= ChipSetRegisters(hchip, (u16)REG_RC8CODEW_DVBSX_DEMOD_SFRINIT2(demod), 3);


  return error;
}


/*****************************************************
--FUNCTION	::	GetCarrierFrequency
--ACTION	::	Return the carrier frequency offset
--PARAMS IN	::	hChip -> handle to the chip
			MasterClock -> Masterclock frequency (Hz)
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	Frequency offset in Hz
--RETURN	::	error
--***************************************************/
fe_lla_error_t FE_STiD135_GetCarrierFrequency(stchip_handle_t hChip,u32 MasterClock,
				enum fe_stid135_demod Demod, s32* carrierFrequency_p)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	
	u32 cfrField2,
		cfrField1,
		cfrField0,
		rem1;
	s32 derot,
		rem2,
		intval1,
		intval2;
	u16 cfrReg;
	
	BOOL sign=1;  	
	
	cfrField2 = FLD_FC8CODEW_DVBSX_DEMOD_CFR12_CAR_FREQ(Demod); /* carrier frequency Byte 2 */
	cfrField1 = FLD_FC8CODEW_DVBSX_DEMOD_CFR11_CAR_FREQ(Demod); /* carrier frequency Byte 1 */
	cfrField0 = FLD_FC8CODEW_DVBSX_DEMOD_CFR10_CAR_FREQ(Demod); /* carrier frequency Byte 0 */
	cfrReg    = (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR12(Demod);

	/*	Read the carrier frequency regs value	*/
	error |= ChipGetRegisters(hChip, cfrReg, 3);
		
	derot = (ChipGetFieldImage(hChip, cfrField2) << 16) +
	(ChipGetFieldImage(hChip, cfrField1) << 8) +
	(ChipGetFieldImage(hChip, cfrField0));
	/*	compute the signed value	*/ 
	derot = Get2Comp(derot,24);
	
	if (derot < 0) {
		sign = 0;
		derot = -derot; /* Use positive values only to avoid 
				negative value truncation */
	}
		
	/*
		Formula:  carrier_frequency = MasterClock * 12 * Reg / 2^24
	*/
	MasterClock = MasterClock * 12;
	
	intval1 = (s32)(MasterClock >> 12);
	intval2 = derot       >> 12;
    
	rem1 = MasterClock % 0x1000;
	rem2 = derot       % 0x1000;
	
	derot = (intval1 * intval2) +
		  ((intval1 * rem2) >> 12) +
		  ((intval2 * (s32)rem1) >> 12);  /*only for integer calculation */
	
	if (sign == 1) {
		*carrierFrequency_p=derot;  /* positive offset */
	} else {
		*carrierFrequency_p=-derot; /* negative offset */
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_carrier_frequency_init
--ACTION	::	Sets the CFR InitReg with the given frequency
--PARAMS IN	::	Handle		->	Front End Handle
			master_clock	->	Masterclock frequency (Hz)
			frequency_hz	->	InitFrequency (Hz)
			demod		->	current demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	error
*****************************************************/
fe_lla_error_t fe_stid135_set_carrier_frequency_init(fe_stid135_handle_t Handle,
				s32 frequency_hz, enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	s32 si_register;
	s32 freq_up, freq_low;
	s32 reg_up, reg_low;
	const u16 cfr_factor = 6711; // 6711 = 2^20/(10^6/2^6)*100
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	
	/* First, set carrier freq boundaries */
	// CFR_UP = wanted_freq - LOF + search_range/2
	// CFR_DOWN = wanted_freq - LOF - search_range/2
	freq_up = (s32)(pParams->tuner_frequency[demod-1]) + (s32)(pParams->demod_search_range[demod-1] / 2);
	reg_up = (freq_up / 1000) * (1 << 11);
	reg_up = reg_up / (((s32)pParams->master_clock / 1000) * 3);
	reg_up = reg_up * (1 << 11);
	
	freq_low = (s32)(pParams->tuner_frequency[demod-1]) - (s32)(pParams->demod_search_range[demod-1] / 2);
	reg_low = (freq_low / 1000) * (1 << 11);
	reg_low = reg_low / (((s32)pParams->master_clock / 1000) * 3);
	reg_low = reg_low * (1 << 11);
	
	/* Search range definition */
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARCFG(demod), 0x46);
	
	/*  manual cfrup/low setting, Carrier derotator on, phasedetect algo */
	error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_CFRUP2_CFR_UP(demod), 
	MMSB(reg_up));
	error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_CFRUP1_CFR_UP(demod), 
	MSB(reg_up));
	error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_CFRUP0_CFR_UP(demod), 
	LSB(reg_up));
	error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRUP2(demod),3);
	
	error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_CFRLOW2_CFR_LOW(demod),
	MMSB(reg_low));
	error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_CFRLOW1_CFR_LOW(demod),
	MSB(reg_low));
	error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_CFRLOW0_CFR_LOW(demod),
	LSB(reg_low));
	error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRLOW2(demod),3);
	
	/*
		Formula:  
		          cfr_init =  cfr_init(MHz) / ckadc  * 2^24 (signed)  
		          ckadc = 12 * Mclk(MHz)
	*/

	/* Hypothesis: master_clock=130MHz, frequency_hz=-550MHz..+650MHz
	(-550=950-1500 and 650=2150-1500)
	FVCO/4/12=6.2GHz/4/12=130MHz */
	
	si_register = ((frequency_hz/PLL_FVCO_FREQUENCY)*cfr_factor)/100;
	
	error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_CFRINIT2_CFR_INIT(demod),
	((u8)(si_register >> 16)));
	error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_CFRINIT1_CFR_INIT(demod),
	((u8)(si_register >> 8)));
	error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_CFRINIT0_CFR_INIT(demod),
	((u8)si_register));
	error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINIT2(demod),3);
	
	return error;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_TimingGetOffset
--ACTION	::	Returns the timing offset
--PARAMS IN	::	hChip -> handle to the chip
			SymbolRate -> Masterclock frequency (Hz)
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	timingoffset_p -> timing offset
--RETURN	::	error
*****************************************************/
static fe_lla_error_t FE_STiD135_TimingGetOffset(stchip_handle_t hChip, u32 SymbolRate, 
					enum fe_stid135_demod Demod, s32* timingoffset_p)
{
	u32 tmgField2,
	    tmgField1,
	    tmgField0;
	
	u16 tmgreg;
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	
	tmgreg = (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG2(Demod);	/*Found timing offset reg HSB*/
	tmgField2 = FLD_FC8CODEW_DVBSX_DEMOD_TMGREG2_TMGREG(Demod);
	tmgField1 = FLD_FC8CODEW_DVBSX_DEMOD_TMGREG1_TMGREG(Demod);
	tmgField0 = FLD_FC8CODEW_DVBSX_DEMOD_TMGREG0_TMGREG(Demod);

	/* Formula :
	 tmgreg in MHz = symb_freq in MHz * (tmgreg * 2^-(24+5)) (unsigned)
	
	 SR_Offset = TMGRREG * SR /2^29
	 TMGREG is 3 bytes registers value 
	 SR is the current symbol rate
	*/
	error |= ChipGetRegisters(hChip, tmgreg, 3);
	
	*timingoffset_p = (ChipGetFieldImage(hChip, tmgField2) << 16)+
		(ChipGetFieldImage(hChip, tmgField1) << 8)+
		(ChipGetFieldImage(hChip, tmgField0));
	
	*timingoffset_p = Get2Comp(*timingoffset_p,24);
		
	
	if (*timingoffset_p == 0) {
		*timingoffset_p = 1;
	}
	*timingoffset_p = ((s32)SymbolRate * 10) / ((s32)0x1000000 / (*timingoffset_p)); 
	*timingoffset_p = (*timingoffset_p) / 320;
	
	return error;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_GetViterbiPunctureRate
--ACTION	::	Computes the puncture rate
--PARAMS IN	::	hChip -> handle to the chip
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	punctureRate_p -> puncture rate
--RETURN	::	error
*****************************************************/
static  fe_lla_error_t FE_STiD135_GetViterbiPunctureRate(
			stchip_handle_t hChip, enum fe_stid135_demod Demod, enum fe_sat_rate *punctureRate_p)
{
	s32 rateField;
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	
	error |= ChipGetField(hChip, FLD_FC8CODEW_DVBSX_VITERBI_VITCURPUN_VIT_CURPUN(Demod), &rateField);
	
	switch(rateField) {
	case 13:			 
		*punctureRate_p = FE_SAT_PR_1_2;
	break;
	
	case 18:
		*punctureRate_p = FE_SAT_PR_2_3;
	break;
	
	case 21:
		*punctureRate_p = FE_SAT_PR_3_4;
	break;
	
	case 24:
		*punctureRate_p = FE_SAT_PR_5_6;
	break;
	
	case 25:
		*punctureRate_p = FE_SAT_PR_6_7;
	break;
	
	case 26:
		*punctureRate_p = FE_SAT_PR_7_8;
	break;
	
	default:
		*punctureRate_p = FE_SAT_PR_UNKNOWN;
	break;
	}
	
	return	error; 
}

/*****************************************************
--FUNCTION	::	FE_STiD135_GetBer
--ACTION	::	Returns the Viterbi BER if DVBS1/DSS or the PER if DVBS2
--PARAMS IN	::	hChip -> handle to the chip
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	ber_p -> BER
--RETURN	::	error
*****************************************************/
static fe_lla_error_t FE_STiD135_GetBer(stchip_handle_t hChip, enum fe_stid135_demod Demod, u32* ber_p)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	u32 ber, i;
	u32 demdStateReg,
	    prVitField,
	    pdellockField;
	s32 demodState;
	s32 fld_value;
	
	*ber_p = 10000000;
	
	demdStateReg  = FLD_FC8CODEW_DVBSX_DEMOD_DMDSTATE_HEADER_MODE(Demod);
	prVitField    = FLD_FC8CODEW_DVBSX_VITERBI_VSTATUSVIT_PRFVIT(Demod);
	pdellockField = FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_PKTDELIN_LOCK(Demod);
	
	error |= ChipGetField(hChip, demdStateReg, &demodState);

	switch(demodState) {
	case FE_SAT_SEARCH:
	case FE_SAT_PLH_DETECTED:
	default:
		*ber_p=10000000;		/*demod Not locked ber = 1*/
	break;
	
	case FE_SAT_DVBS_FOUND:

		*ber_p=0;
		/* Average 5 ber values */ 
		for (i = 0; i < 5; i++) {
			ChipWaitOrAbort(hChip, 5);
			error |= FE_STiD135_GetErrorCount(hChip, 
					FE_STiD_COUNTER1, Demod, &ber);
			*ber_p += ber; 
		}
	
		*ber_p /= 5;
	
		 /* Check for carrier */
		 error |= ChipGetField(hChip, prVitField, &fld_value);
		 if(fld_value)
		 {
			*ber_p *= 9766; 	/* ber = ber * 10^7/2^10 */
			*ber_p = *ber_p >> 13; /* theses two lines =>
					ber = ber * 10^7/2^20 */
		}
	break;
	
	case FE_SAT_DVBS2_FOUND:
	
		*ber_p = 0;
		/* Average 5 ber values */ 
		for(i = 0; i < 5; i++) {
			ChipWaitOrAbort(hChip, 5);
			error |= FE_STiD135_GetErrorCount(hChip,
					FE_STiD_COUNTER1, Demod, &ber);
			*ber_p += ber; 
		}
		*ber_p /= 5;
		
		/* Check for S2 FEC Lock */
		error |= ChipGetField(hChip, pdellockField, &fld_value) ;
		if(fld_value) {
			*ber_p *= 9766; /*	ber = ber * 10^7/2^10 */
			*ber_p = *ber_p >> 13; /*  this two lines => 
					PER = ber * 10^7/2^23 */
		}
		
	break;
	}
	
	return error;	   //ber/per scaled to 1e7 
}

/*****************************************************
--FUNCTION	::	FE_STiD135_SetViterbiStandard
--ACTION	::	Sets the standard 
--PARAMS IN	::	hChip -> handle to the chip
			Demod -> current demod 1 .. 8
			Standard -> standard
			puncture_rate -> PR
--PARAMS OUT	::	ber_p -> BER
--RETURN	::	error
*****************************************************/
static fe_lla_error_t FE_STiD135_SetViterbiStandard(stchip_handle_t hChip,
					enum fe_sat_search_standard Standard,
					enum fe_sat_rate puncture_rate,
					enum fe_stid135_demod Demod)
{
	
	u16 fecmReg,
		prvitReg;
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
		
	fecmReg  = (u16)REG_RC8CODEW_DVBSX_VITERBI_FECM(Demod);
	prvitReg = (u16)REG_RC8CODEW_DVBSX_VITERBI_PRVIT(Demod);

	switch (Standard) {
	case FE_SAT_AUTO_SEARCH:
		/* Disable DSS in auto mode search for DVBS1 and DVBS2
		only , DSS search is on demande */
		error |= ChipSetOneRegister(hChip, fecmReg, 0x00);
		/* Enable All PR exept 6/7 */
		error |= ChipSetOneRegister(hChip, prvitReg, 0x2F);
	break;
	
	case FE_SAT_SEARCH_DVBS1:
		/* Disable DSS */
		error |= ChipSetOneRegister(hChip, fecmReg, 0x00);
		switch (puncture_rate) {
		case FE_SAT_PR_UNKNOWN:
		case FE_SAT_PR_4_5:
		case FE_SAT_PR_6_7:
		case FE_SAT_PR_8_9:
			/* Enable All PR exept 6/7 */
			error |= ChipSetOneRegister(hChip, prvitReg, 0x2F);
		break;
		
		case FE_SAT_PR_1_2:
			/* Enable 1/2 PR only */
			error |= ChipSetOneRegister(hChip, prvitReg, 0x01);
		break;
		
		case FE_SAT_PR_2_3:
			/* Enable 2/3 PR only */
			error |= ChipSetOneRegister(hChip, prvitReg, 0x02);
		break;
		
		case FE_SAT_PR_3_4:
			/* Enable 3/4 PR only */
			error |= ChipSetOneRegister(hChip, prvitReg, 0x04);
		break;
		
		case FE_SAT_PR_5_6:
			/* Enable 5/6 PR only */
			error |= ChipSetOneRegister(hChip, prvitReg, 0x08);
		break;
		
		case FE_SAT_PR_7_8:
			/* Enable 7/8 PR only */
			error |= ChipSetOneRegister(hChip, prvitReg, 0x20);
		break;
		}

	break;
	
	case FE_SAT_SEARCH_DSS:
		
		error |= ChipSetOneRegister(hChip, fecmReg, 0x80);
		switch (puncture_rate) {
		case FE_SAT_PR_UNKNOWN:
		case FE_SAT_PR_3_4:
		case FE_SAT_PR_4_5:
		case FE_SAT_PR_5_6:
		case FE_SAT_PR_7_8:
		case FE_SAT_PR_8_9:
			/* Enable 1/2, 2/3 and 6/7 PR */
			error |= ChipSetOneRegister(hChip, prvitReg, 0x13);
		break;
		
		case FE_SAT_PR_1_2:
			/* Enable 1/2 PR only */
			error |= ChipSetOneRegister(hChip, prvitReg, 0x01);
		break;
		
		case FE_SAT_PR_2_3:
			/* Enable 2/3 PR only */
			error |= ChipSetOneRegister(hChip, prvitReg, 0x02);
		break;
		
		case FE_SAT_PR_6_7:
			/* Enable All 7/8 PR only */
			error |= ChipSetOneRegister(hChip, prvitReg, 0x10);
		break;
		}

	break;
	
	case FE_SAT_SEARCH_DVBS2:
	case FE_SAT_SEARCH_TURBOCODE:
	break;
	}
	
	return error;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_GetRevision
--ACTION	::	Return current LLA version
--PARAMS IN	::	NONE
--PARAMS OUT	::	NONE
--RETURN	::	Revision ==> Text string containing LLA version
--***************************************************/
ST_Revision_t FE_STiD135_GetRevision(void)
{
	return (Revision);
}

/*****************************************************
--FUNCTION	::	fe_stid135_get_cut_id
--ACTION	::	Return chip cut ID
--PARAMS IN	::	Handle	==> Front End Handle
--PARAMS OUT	::	cut_id => cut ID with major and minor ID
--RETURN	::	error
--***************************************************/
fe_lla_error_t fe_stid135_get_cut_id(fe_stid135_handle_t Handle, enum device_cut_id *cut_id)
{
	u32 reg_value;
	u8 major_cut_id, minor_cut_id;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	if (pParams != NULL) {
		error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_STATUS97, &reg_value);
		major_cut_id = (u8)((reg_value >> 28) & 0x1);
		if(major_cut_id == 0) {
			*cut_id = STID135_CUT1_X;
		} else if(major_cut_id == 1) {
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_STATUS98, &reg_value);
			minor_cut_id = (u8)reg_value;
			if(minor_cut_id == 8) {
				*cut_id = STID135_CUT2_0;
			} else if(minor_cut_id == 9) {
				*cut_id = STID135_CUT2_1;
			} else {
				*cut_id = STID135_CUT2_X_UNFUSED;
			}
		} else {
			*cut_id = STID135_UNKNOWN_CUT;
		}
	} else {
		error = FE_LLA_INVALID_HANDLE;
	}
	return(error);
}

/*****************************************************
--FUNCTION	::	FE_STiD135_GetSignalInfoLite
--ACTION	::	Return C/N only
--PARAMS IN	::	Handle	==> Front End Handle
			Demod	==> Current demod 1 or 2
--PARAMS OUT	::	pInfo	==> Informations (C/N)
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t	FE_STiD135_GetSignalInfoLite(fe_stid135_handle_t Handle,
		enum fe_stid135_demod Demod, struct fe_sat_signal_info *pInfo)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	
	if (pParams != NULL) {
		if ((pParams->handle_demod->Error) /*|| (pParams->h_tuner->Error)*/) 
			error |= FE_LLA_I2C_ERROR;
		else {
			error |= FE_STiD135_GetStandard(
					pParams->handle_demod, Demod, &(pInfo->standard)); 
			if(pInfo->standard == FE_SAT_DVBS2_STANDARD) {
				error |= FE_STiD135_CarrierGetQuality(pParams->handle_demod, NULL, Demod, &(pInfo->C_N));
			} else { /*DVBS1/DSS*/
				error |= FE_STiD135_CarrierGetQuality(pParams->handle_demod, NULL, Demod, &(pInfo->C_N));
			}
	
			if (pParams->handle_demod->Error) 
				error = FE_LLA_I2C_ERROR; 
		}
	} else
		error = FE_LLA_INVALID_HANDLE; 
		
	return error; 
}

/*****************************************************
--FUNCTION	::	fe_stid135_get_lock_status
--ACTION	::	Return locked status
--PARAMS IN	::	Handle -> Front End Handle
			Demod -> Current demod 1 .. 8
--PARAMS OUT	::	Locked_p -> Bool (locked or not)
--RETURN	::	error
--***************************************************/
fe_lla_error_t fe_stid135_get_lock_status(fe_stid135_handle_t handle, enum fe_stid135_demod Demod, BOOL* Locked_p)
{

	struct fe_stid135_internal_param *pParams;
	enum fe_sat_search_state demodState;
	fe_lla_error_t error = FE_LLA_NO_ERROR;  
	s32 fld_value[3];
	*Locked_p = FALSE;

	
	
	pParams = (struct fe_stid135_internal_param	*) handle;
	
	if (pParams != NULL) {
		error = ChipGetField(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_DEMOD_DMDSTATE_HEADER_MODE(Demod), &(fld_value[0]));
		demodState = (enum fe_sat_search_state)(fld_value[0]);
		switch (demodState) {
		case FE_SAT_SEARCH:
		case FE_SAT_PLH_DETECTED :
			*Locked_p  = FALSE;
		break;
		case FE_SAT_DVBS2_FOUND:
			error |= ChipGetField(pParams->handle_demod, 
			FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_LOCK_DEFINITIF(Demod), &(fld_value[0]));
			error |= ChipGetField(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_PKTDELIN_LOCK(Demod), &(fld_value[1]));
			error |= ChipGetField(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS_TSFIFO_LINEOK(Demod), &(fld_value[2])); 
			*Locked_p  = fld_value[0] & fld_value[1] & fld_value[2];
		break;
		
		case FE_SAT_DVBS_FOUND:
			error |= ChipGetField(pParams->handle_demod, 
			 FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_LOCK_DEFINITIF(Demod), &(fld_value[0]));
			error |= ChipGetField(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_VITERBI_VSTATUSVIT_LOCKEDVIT(Demod), &(fld_value[1]));
			error |= ChipGetField(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS_TSFIFO_LINEOK(Demod), &(fld_value[2]));
			*Locked_p  = fld_value[0] & fld_value[1] & fld_value[2];
		break;
		}
	}
	
	else *Locked_p  = FALSE;
		
	return error;
	
}

/*****************************************************
**FUNCTION	::	FE_STiD135_GetErrorCount
**ACTION	::	return the number of errors from a given counter
**PARAMS IN	:: 	hChip -> handle to the chip
			Counter -> used counter 1 or 2.
			Demod -> current demod 1 .. 2.
**PARAMS OUT	::	ber_p -> BER
**RETURN	::	error
*****************************************************/
fe_lla_error_t FE_STiD135_GetErrorCount(stchip_handle_t hChip, 
		enum fe_stid135_error_counter Counter, enum fe_stid135_demod Demod, u32* ber_p) 
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u32 lsb=0,msb=0,hsb=0;
	
	u32
		err1Field_hsb = 0,
		err1Field_msb = 0,
		err1Field_lsb = 0,
		err2Field_hsb = 0,
		err2Field_msb = 0,
		err2Field_lsb = 0;
	u16 err1Reg, err2Reg;
	
	/*Define Error fields */
	err1Field_hsb = FLD_FC8CODEW_DVBSX_HWARE_ERRCNT12_ERR_CNT1(Demod);
	err1Field_msb = FLD_FC8CODEW_DVBSX_HWARE_ERRCNT11_ERR_CNT1(Demod);
	err1Field_lsb = FLD_FC8CODEW_DVBSX_HWARE_ERRCNT10_ERR_CNT1(Demod);
	err1Reg = (u16)REG_RC8CODEW_DVBSX_HWARE_ERRCNT12(Demod);
		
	err2Field_hsb = FLD_FC8CODEW_DVBSX_HWARE_ERRCNT22_ERR_CNT2(Demod);
	err2Field_msb = FLD_FC8CODEW_DVBSX_HWARE_ERRCNT21_ERR_CNT2(Demod);
	err2Field_lsb = FLD_FC8CODEW_DVBSX_HWARE_ERRCNT20_ERR_CNT2(Demod);
	err2Reg = (u16)REG_RC8CODEW_DVBSX_HWARE_ERRCNT22(Demod);

	/*Read the Error value*/
	switch (Counter) {
	case FE_STiD_COUNTER1:
		error |= ChipGetRegisters(hChip, err1Reg, 3);
		hsb = (u32)ChipGetFieldImage(hChip, err1Field_hsb);
		msb = (u32)ChipGetFieldImage(hChip, err1Field_msb);
		lsb = (u32)ChipGetFieldImage(hChip, err1Field_lsb);
	break;
	
	case FE_STiD_COUNTER2:
		error |= ChipGetRegisters(hChip, err2Reg, 3);
		hsb = (u32)ChipGetFieldImage(hChip, err2Field_hsb);
		msb = (u32)ChipGetFieldImage(hChip, err2Field_msb);
		lsb = (u32)ChipGetFieldImage(hChip, err2Field_lsb);
	break;
	}
	
	/*Compute the Error value 3 bytes (HSB,MSB,LSB)*/
	*ber_p =(hsb<<16)+(msb<<8)+(lsb);
	
	return (error);
}


/*****************************************************
--FUNCTION	::	FE_STiD135_WaitForLock
--ACTION	::	Wait until demod + FEC locked or timout
--PARAMS IN	::	Handle -> Frontend handle
			Demod -> current demod 1 ... 8
			DemodTimeOut -> Time out in ms for demod
			FecTimeOut -> Time out in ms for FEC
			satellitte_scan -> scan or acquisition
--PARAMS OUT	::	lock_p -> Lock status true or false
--RETURN	::	error
--***************************************************/
fe_lla_error_t FE_STiD135_WaitForLock(fe_stid135_handle_t Handle,enum fe_stid135_demod Demod,
			u32 DemodTimeOut,u32 FecTimeOut,BOOL satellitte_scan, s32* lock_p)
{

	fe_lla_error_t error               = FE_LLA_NO_ERROR;
	u32 timer=0;
	u32 strMergerLockField;
	struct fe_stid135_internal_param *pParams;
	BOOL lock;
	
	pParams = (struct fe_stid135_internal_param *) Handle;

	/* Stream Merger lock status field) */
	strMergerLockField = FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS_TSFIFO_LINEOK(Demod);
	error |= FE_STiD135_GetDemodLock(Handle, Demod, DemodTimeOut, lock_p);
	
	if (*lock_p) {
		error |= FE_STiD135_GetFECLock(pParams->handle_demod, Demod, FecTimeOut, &lock);
		*lock_p = *lock_p &&  lock;
	}



	/* LINEOK check is not performed during Satellite Scan */
	if (satellitte_scan == FALSE) {
		if (*lock_p) {
			*lock_p = 0;

			while ((timer < FecTimeOut) && (*lock_p == 0))
			{
				/*Check the stream merger Lock (good packet at 
				the output)*/
				error |= ChipGetField(pParams->handle_demod, strMergerLockField, lock_p);
				ChipWaitOrAbort(pParams->handle_demod, 1);
				timer++;
			}
		}
	}
		
	if (*lock_p)
		*lock_p = TRUE;	  
	else
		*lock_p = FALSE;
	
	return error;

}

static fe_lla_error_t CarrierLoopAutoAdjust(fe_stid135_handle_t Handle,
				  enum fe_stid135_demod Demod, s32 cnr)
{
	struct fe_stid135_internal_param *pParams;
	u32 symbol_rate=0;	
	s32 offset;
	u8 aclcQPSK = 0x08, aclc8PSK = 0x08, aclc16APSK = 0x08, aclc32APSK = 0x08; /* DVBS2 */
	u8 aclc64APSK = 0x08, aclc128APSK = 0x08, aclc256APSK = 0x08; /* DVBS2X */
	u32 i=0;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
  
	pParams = (struct fe_stid135_internal_param *) Handle;
	/* Read the Symbol rate */
	error |= FE_STiD135_GetSymbolRate(pParams->handle_demod, pParams->master_clock, Demod, &symbol_rate);
	error |= FE_STiD135_TimingGetOffset(pParams->handle_demod, symbol_rate, Demod, &offset);
	if(offset < 0) {
		offset *= (-1);
		symbol_rate -= (u32)(offset);
	} else
		symbol_rate += (u32)(offset);
	
	/* QPSK */
	while((i<NB_QPSK_COEFF)&& (cnr>fe_stid135_qpsk_car_loop[i].cnrthres))i++;
	if (i!=0)
		i--;

	if(symbol_rate<=2000000)
		aclcQPSK=fe_stid135_qpsk_car_loop[i].CarLoop_2;
	else if(symbol_rate<=10000000)
		aclcQPSK=fe_stid135_qpsk_car_loop[i].CarLoop_10;
	else if(symbol_rate<=30000000)
		aclcQPSK=fe_stid135_qpsk_car_loop[i].CarLoop_30;
	else if(symbol_rate<=62500000)
		aclcQPSK=fe_stid135_qpsk_car_loop[i].CarLoop_62_5;
	else if(symbol_rate<=125000000)
	       	aclcQPSK=fe_stid135_qpsk_car_loop[i].CarLoop_125;
	else if(symbol_rate<=300000000)
	       	aclcQPSK=fe_stid135_qpsk_car_loop[i].CarLoop_300;
	else if(symbol_rate<=400000000)
	       	aclcQPSK=fe_stid135_qpsk_car_loop[i].CarLoop_400;
	else
	       	aclcQPSK=fe_stid135_qpsk_car_loop[i].CarLoop_500;
	
	
	 /* 8PSK */
	i=0;
	while((i<NB_8PSK_COEFF)&& (cnr>fe_stid135_8psk_car_loop[i].cnrthres))i++;
	if (i!=0)
		i--;

	if(symbol_rate<=2000000)
		aclc8PSK=fe_stid135_8psk_car_loop[i].CarLoop_2;
	else if(symbol_rate<=10000000)
		aclc8PSK=fe_stid135_8psk_car_loop[i].CarLoop_10;
	else if(symbol_rate<=30000000)
		aclc8PSK=fe_stid135_8psk_car_loop[i].CarLoop_30;
	else if(symbol_rate<=62500000)
		aclc8PSK=fe_stid135_8psk_car_loop[i].CarLoop_62_5;
	else if(symbol_rate<=125000000)
	       	aclc8PSK=fe_stid135_8psk_car_loop[i].CarLoop_125;
	else if(symbol_rate<=300000000)
	       	aclc8PSK=fe_stid135_8psk_car_loop[i].CarLoop_300;
	else if(symbol_rate<=400000000)
	       	aclc8PSK=fe_stid135_8psk_car_loop[i].CarLoop_400;
	else
	       	aclc8PSK=fe_stid135_8psk_car_loop[i].CarLoop_500;

	/* 16APSK */ 
	i=0; 
	while((i<NB_16APSK_COEFF)&& (cnr>fe_stid135_16apsk_car_loop[i].cnrthres))i++;
	if (i!=0)
		i--;

	if(symbol_rate<=2000000)
		aclc16APSK=fe_stid135_16apsk_car_loop[i].CarLoop_2;
	else if(symbol_rate<=10000000)
		aclc16APSK=fe_stid135_16apsk_car_loop[i].CarLoop_10;
	else if(symbol_rate<=30000000)
		aclc16APSK=fe_stid135_16apsk_car_loop[i].CarLoop_30;
	else if(symbol_rate<=62500000)
		aclc16APSK=fe_stid135_16apsk_car_loop[i].CarLoop_62_5;
	else if(symbol_rate<=125000000)
	       	aclc16APSK=fe_stid135_16apsk_car_loop[i].CarLoop_125;
	else if(symbol_rate<=300000000)
	       	aclc16APSK=fe_stid135_16apsk_car_loop[i].CarLoop_300;
	else if(symbol_rate<=400000000)
	       	aclc16APSK=fe_stid135_16apsk_car_loop[i].CarLoop_400;
	else
	       	aclc16APSK=fe_stid135_16apsk_car_loop[i].CarLoop_500;

	/* 32APSK */ 
	i=0; 
	while((i<NB_32APSK_COEFF)&& (cnr>fe_stid135_32apsk_car_loop[i].cnrthres))i++;
	if (i!=0)
		i--;

	if(symbol_rate<=2000000)
		aclc32APSK=fe_stid135_32apsk_car_loop[i].CarLoop_2;
	else if(symbol_rate<=10000000)
		aclc32APSK=fe_stid135_32apsk_car_loop[i].CarLoop_10;
	else if(symbol_rate<=30000000)
		aclc32APSK=fe_stid135_32apsk_car_loop[i].CarLoop_30;
	else if(symbol_rate<=62500000)
		aclc32APSK=fe_stid135_32apsk_car_loop[i].CarLoop_62_5;
	else if(symbol_rate<=125000000)
	       	aclc32APSK=fe_stid135_32apsk_car_loop[i].CarLoop_125;
	else if(symbol_rate<=300000000)
	       	aclc32APSK=fe_stid135_32apsk_car_loop[i].CarLoop_300;
	else if(symbol_rate<=400000000)
	       	aclc32APSK=fe_stid135_32apsk_car_loop[i].CarLoop_400;
	else
	       	aclc32APSK=fe_stid135_32apsk_car_loop[i].CarLoop_500;

	/* 64APSK */ 
	i=0; 
	while((i<NB_64APSK_COEFF)&& (cnr>fe_stid135_64apsk_car_loop[i].cnrthres))i++;
	if (i!=0)
		i--;

	if(symbol_rate<=2000000)
		aclc64APSK=fe_stid135_64apsk_car_loop[i].CarLoop_2;
	else if(symbol_rate<=10000000)
		aclc64APSK=fe_stid135_64apsk_car_loop[i].CarLoop_10;
	else if(symbol_rate<=30000000)
		aclc64APSK=fe_stid135_64apsk_car_loop[i].CarLoop_30;
	else if(symbol_rate<=62500000)
		aclc64APSK=fe_stid135_64apsk_car_loop[i].CarLoop_62_5;
	else if(symbol_rate<=125000000)
	       	aclc64APSK=fe_stid135_64apsk_car_loop[i].CarLoop_125;
	else if(symbol_rate<=300000000)
	       	aclc64APSK=fe_stid135_64apsk_car_loop[i].CarLoop_300;
	else if(symbol_rate<=400000000)
	       	aclc64APSK=fe_stid135_64apsk_car_loop[i].CarLoop_400;
	else
	       	aclc64APSK=fe_stid135_64apsk_car_loop[i].CarLoop_500;
	
	/* 128APSK */ 
	i=0; 
	while((i<NB_128APSK_COEFF)&& (cnr>fe_stid135_128apsk_car_loop[i].cnrthres))i++;
	if (i!=0)
		i--;

	if(symbol_rate<=2000000)
		aclc128APSK=fe_stid135_128apsk_car_loop[i].CarLoop_2;
	else if(symbol_rate<=10000000)
		aclc128APSK=fe_stid135_128apsk_car_loop[i].CarLoop_10;
	else if(symbol_rate<=30000000)
		aclc128APSK=fe_stid135_128apsk_car_loop[i].CarLoop_30;
	else if(symbol_rate<=62500000)
		aclc128APSK=fe_stid135_128apsk_car_loop[i].CarLoop_62_5;
	else if(symbol_rate<=125000000)
	       	aclc128APSK=fe_stid135_128apsk_car_loop[i].CarLoop_125;
	else if(symbol_rate<=300000000)
	       	aclc128APSK=fe_stid135_128apsk_car_loop[i].CarLoop_300;
	else if(symbol_rate<=400000000)
	       	aclc128APSK=fe_stid135_128apsk_car_loop[i].CarLoop_400;
	else
	       	aclc128APSK=fe_stid135_128apsk_car_loop[i].CarLoop_500;
	
	/* 256APSK */ 
	i=0; 
	while((i<NB_256APSK_COEFF)&& (cnr>fe_stid135_256apsk_car_loop[i].cnrthres))i++;
	if (i!=0)
		i--;

	if(symbol_rate<=2000000)
		aclc256APSK=fe_stid135_256apsk_car_loop[i].CarLoop_2;
	else if(symbol_rate<=10000000)
		aclc256APSK=fe_stid135_256apsk_car_loop[i].CarLoop_10;
	else if(symbol_rate<=30000000)
		aclc256APSK=fe_stid135_256apsk_car_loop[i].CarLoop_30;
	else if(symbol_rate<=62500000)
		aclc256APSK=fe_stid135_256apsk_car_loop[i].CarLoop_62_5;
	else if(symbol_rate<=125000000)
	       	aclc256APSK=fe_stid135_256apsk_car_loop[i].CarLoop_125;
	else if(symbol_rate<=300000000)
	       	aclc256APSK=fe_stid135_256apsk_car_loop[i].CarLoop_300;
	else if(symbol_rate<=400000000)
	       	aclc256APSK=fe_stid135_256apsk_car_loop[i].CarLoop_400;
	else
	       	aclc256APSK=fe_stid135_256apsk_car_loop[i].CarLoop_500;
	
	//printf( "0x%X 0x%X 0x%X 0x%X 0x%X 0x%X 0x%X\n",aclcQPSK,aclc8PSK,aclc16APSK,aclc32APSK, aclc64APSK, aclc128APSK, aclc256APSK);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), aclcQPSK);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S28(Demod), aclc8PSK);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S216A(Demod), aclc16APSK);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S232A(Demod), aclc32APSK);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S264A(Demod), aclc64APSK);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2128A(Demod), aclc128APSK);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2256A(Demod), aclc256APSK);
	
	return(error);
}

/*****************************************************
--FUNCTION	::	FE_STiD135_GetOptimCarrierLoop
--ACTION	::	Computes optimized alpha coefficient value for tracking
--PARAMS IN	::	SymbolRate -> symbol rate of RF signal
			ModCode -> mode code of RF signal
			pilots -> pilots of RF signal
--PARAMS OUT	::	NONE
--RETURN	::	alpha coefficient
--***************************************************/
u8 FE_STiD135_GetOptimCarrierLoop(u32 SymbolRate, enum fe_sat_modcode ModCode,
				s32 pilots)
{
	u8 aclcValue = 0x29;
	u32 i = 0;
  
	/* Find the index parameters for the Modulation */
	while ((i < NB_SAT_MODCOD) && (ModCode != FE_STiD135_S2CarLoop[i].ModCode))
		i++;

	if (i < NB_SAT_MODCOD) {
		if (pilots) {
			if (SymbolRate <= 3000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOn_2;
			else if (SymbolRate <= 7000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOn_5;
			else if (SymbolRate <= 15000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOn_10;
			else if (SymbolRate <= 25000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOn_20;
			else if (SymbolRate <= 46250000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOn_30;
			else if (SymbolRate <= 93750000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOn_62_5;
			else if (SymbolRate <= 212500000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOn_125;
			else if (SymbolRate <= 350000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOn_300;
			else if (SymbolRate <= 450000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOn_400;
			else
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOn_500;
		} else {
			if (SymbolRate <= 3000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOff_2;
			else if (SymbolRate <= 7000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOff_5;
			else if (SymbolRate <= 15000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOff_10;
			else if (SymbolRate <= 25000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOff_20;
			else if (SymbolRate <= 46250000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOff_30;
			else if (SymbolRate <= 93750000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOff_62_5;
			else if (SymbolRate <= 212500000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOff_125;
			else if (SymbolRate <= 350000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOff_300;
			else if (SymbolRate <= 450000000)
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOff_400;
			else
				aclcValue = 
				FE_STiD135_S2CarLoop[i].CarLoopPilotsOff_500;
		}
	} else {
    /* Modulation Unknown */
	}
  
  
	return aclcValue;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_GetStandard
--ACTION	::	Returns the current standrad (DVBS1,DSS or DVBS2
--PARAMS IN	::	hChip -> handle to the chip
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	foundStandard_p -> standard (DVBS1, DVBS2 or DSS)
--RETURN	::	error
*****************************************************/
fe_lla_error_t FE_STiD135_GetStandard(stchip_handle_t hChip,
				enum fe_stid135_demod Demod, enum fe_sat_tracking_standard *foundStandard_p)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;  
	u32 stateField, dssdvbField;
	s32 state, fld_value = 0;
	u8 i;
	
	/* state machine search status field */
	stateField  = FLD_FC8CODEW_DVBSX_DEMOD_DMDSTATE_HEADER_MODE(Demod);
	/* Viterbi standard field */
	dssdvbField = FLD_FC8CODEW_DVBSX_VITERBI_FECM_DSS_DVB(Demod);
	
	error |= ChipGetField(hChip, stateField, &state);
	
	/* Fixed NCR issue raised in BZ#98564 */
	/*  When FLYWHEEL_CPT counter becomes 0xF the demodulator is defined as locked (DVBS2 only) */
	for(i=0;i<5;i++) {
		error |= ChipGetField(hChip, FLD_FC8CODEW_DVBSX_DEMOD_DMDFLYW_FLYWHEEL_CPT(Demod), &fld_value);
		error |= ChipGetField(hChip, stateField, &state);
		if((fld_value == 0xF) && (state == 2))
			break;
	}
	if((fld_value == 0xF) && (state == 2)) {
		*foundStandard_p = FE_SAT_DVBS2_STANDARD; /* Demod found DVBS2 */
	}
			
	else if (state == 3) {			/* Demod found DVBS1/DSS */
		/* Viterbi found DSS */
		error |= ChipGetField(hChip, dssdvbField, &fld_value);
		if (fld_value == 1)
			*foundStandard_p = FE_SAT_DSS_STANDARD;
		else
			*foundStandard_p = FE_SAT_DVBS1_STANDARD;
			/* Viterbi found DVBS1 */
	} else {
		*foundStandard_p = FE_SAT_UNKNOWN_STANDARD;
		/* Demod found nothing, standard unknown */
	}
	
	return error; 
}

/*****************************************************
--FUNCTION	::	FE_STiD135_CarrierGetQuality
--ACTION	::	Returns the carrier to noise of the current carrier
--PARAMS IN	::	hChip -> handle to the chip
			lookup -> LUT for CNR level estimation.
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	c_n_p -> C/N of the carrier, 0 if no carrier  
--RETURN	::	error
--***************************************************/
fe_lla_error_t FE_STiD135_CarrierGetQuality(stchip_handle_t hChip, 
			fe_lla_lookup_t *lookup, enum fe_stid135_demod Demod, s32* c_n_p)
{
	u32 lockFlagField, noiseField1, noiseField0;
	
	s32 regval,
	Imin,
	Imax,
	i;
	u16 noiseReg;
	enum fe_sat_tracking_standard foundStandard;
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	*c_n_p = -100, 
	
	lockFlagField =	FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_LOCK_DEFINITIF(Demod);
	error |= FE_STiD135_GetStandard(hChip,Demod, &foundStandard);
	if (foundStandard == FE_SAT_DVBS2_STANDARD) {
		if (lookup == NULL)
			lookup = &FE_STiD135_S2_CN_LookUp;
		/*If DVBS2 use PLH normilized noise indicators*/
		noiseField1 = FLD_FC8CODEW_DVBSX_DEMOD_NNOSPLHT1_NOSPLHT_NORMED(Demod);
		noiseField0 = FLD_FC8CODEW_DVBSX_DEMOD_NNOSPLHT0_NOSPLHT_NORMED(Demod);
		noiseReg = (u16)REG_RC8CODEW_DVBSX_DEMOD_NNOSPLHT1(Demod);
	} else {
		if (lookup == NULL)
		{	
			lookup = &FE_STiD135_S1_CN_LookUp; 
		}
		/*if not DVBS2 use symbol normalized noise indicators*/ 
		noiseField1 = FLD_FC8CODEW_DVBSX_DEMOD_NNOSDATAT1_NOSDATAT_NORMED(Demod);
		noiseField0 = FLD_FC8CODEW_DVBSX_DEMOD_NNOSDATAT0_NOSDATAT_NORMED(Demod);
		noiseReg = (u16)REG_RC8CODEW_DVBSX_DEMOD_NNOSDATAT1(Demod);
	}
	error |= ChipGetField(hChip, lockFlagField, &regval);
	if (regval) {
		if ((lookup != NULL) && lookup->size) {
			regval = 0;
			/* ChipWaitOrAbort(hChip,5);*/
			for(i = 0; i<8; i++)
			{
				error |= ChipGetRegisters(hChip, noiseReg, 2);
				regval += MAKEWORD16(ChipGetFieldImage(hChip, noiseField1),
						     ChipGetFieldImage(hChip, noiseField0));

				ChipWaitOrAbort(hChip, 1);
			}
			regval /=8;

			Imin = 0;
			Imax = lookup->size-1;
	
			if (INRANGE(lookup->table[Imin].regval, regval, 
			lookup->table[Imax].regval))
			{
				while ((Imax - Imin) > 1) {
					i = (Imax + Imin) >> 1; 
					if (INRANGE(lookup->table[Imin].regval,
						regval,lookup->table[i].regval))
						Imax = i;
					else
						Imin = i;
				}
		
				*c_n_p = ((regval - lookup->table[Imin].regval)
					* (lookup->table[Imax].realval 
					- lookup->table[Imin].realval)
					/ (lookup->table[Imax].regval  
					- lookup->table[Imin].regval))
					+ lookup->table[Imin].realval;
			} else if (regval < lookup->table[Imin].regval)
				*c_n_p = 1000;
		}
	}
	
	return error; 
}


/*****************************************************
--FUNCTION	::	FE_STiD135_GetDemodLock
--ACTION	::	Returns the demod lock status
--PARAMS IN	::	handle -> Frontend handle
			TimeOut -> Demod timeout
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	Lock_p -> lock status, boolean
--RETURN	::	error
--***************************************************/
static fe_lla_error_t FE_STiD135_GetDemodLock    (fe_stid135_handle_t handle,
					 enum fe_stid135_demod Demod, u32 TimeOut, BOOL *Lock_p)
{
	u32 headerField, lockField, symbFreq1, symbFreq2;
	s32 lock = 0;
	u16 symbFreqRegister;
	u32 symbolRate ;
	u32 TimeOut_SymbRate, SRate_1MSymb_Sec ;
	u32 timer = 0;
	s32 fld_value, slc_min, slc_max, slc_sel;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u32 MclkFreq = 0;
	u8 timeout = 0;
	
	enum fe_sat_search_state demodState;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param*)handle;
	
	/* state machine search status field*/
	headerField = FLD_FC8CODEW_DVBSX_DEMOD_DMDSTATE_HEADER_MODE(Demod);
	/* Demod lock status field*/
	lockField   = FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_LOCK_DEFINITIF(Demod);
	
	symbFreqRegister = (u16)REG_RC8CODEW_DVBSX_DEMOD_SFR2(Demod);

	symbFreq1 = FLD_FC8CODEW_DVBSX_DEMOD_SFR1_SYMB_FREQ(Demod);
	symbFreq2 = FLD_FC8CODEW_DVBSX_DEMOD_SFR2_SYMB_FREQ(Demod);

	TimeOut_SymbRate = TimeOut;
	
	 /* SR_register = 2^16 / (12 * MCLK) */
	//SRate_1MSymb_Sec = 0x1e5;
	MclkFreq = pParams->master_clock;
	SRate_1MSymb_Sec = (1<<16) * 1 / (12*MclkFreq/1000000);
	
	while ((timer < TimeOut_SymbRate) && (lock == 0)) {
		error |= ChipGetRegisters(pParams->handle_demod, symbFreqRegister, 2);
		symbolRate = (u32)
				((ChipGetFieldImage(pParams->handle_demod, symbFreq2) << 8)+
				(ChipGetFieldImage(pParams->handle_demod, symbFreq1)));
		
		if (TimeOut < DmdLock_TIMEOUT_LIMIT) {
			TimeOut_SymbRate = TimeOut;
		} else {
			/* no division by 0 */
			if (symbolRate < SRate_1MSymb_Sec)
				symbolRate = SRate_1MSymb_Sec;
			else if (symbolRate > (5 * SRate_1MSymb_Sec))
				symbolRate = 5 * SRate_1MSymb_Sec;
			
			TimeOut_SymbRate = TimeOut / (symbolRate / SRate_1MSymb_Sec);
			
			/* no weird results */
			if (TimeOut_SymbRate < DmdLock_TIMEOUT_LIMIT)
				TimeOut_SymbRate = DmdLock_TIMEOUT_LIMIT ;
			else if (TimeOut_SymbRate > TimeOut)
				TimeOut_SymbRate = TimeOut ;

			/* The new timeout is between 200 ms and original
			TimeOut */
		}
	
		error |= ChipGetField(pParams->handle_demod, headerField, &fld_value);
		demodState = (enum fe_sat_search_state)fld_value;
		
		switch (demodState) {
		case FE_SAT_SEARCH:
		case FE_SAT_PLH_DETECTED :	/* no signal*/ 
			lock = 0;			
		break;
		
		case FE_SAT_DVBS2_FOUND: /* found a DVBS2 signal */ 
		case FE_SAT_DVBS_FOUND:
			error |= ChipGetField(pParams->handle_demod, lockField, &lock);
		break;
		}
		
		if(lock == 0) {
			mutex_unlock(pParams->master_lock);
			ChipWaitOrAbort(pParams->handle_demod, 10);	/* wait 10ms */
			mutex_lock(pParams->master_lock);
		}
		timer += 10;

	}

	if(lock == TRUE) {
		/* We have to wait for demod locked before reading ANNEXEM field (cut 1 only) */
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS6_SIGNAL_ANNEXEM(Demod), &fld_value);
		/* Dummy write to reset slicemin (if DVBS1 test followed by DVBS2 test) */
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICEMIN_DEMODFLT_SLICEMIN(Demod), 0);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICEMAX_DEMODFLT_SLICEMAX(Demod), 0);
		if((fld_value == 0) || (fld_value == 1)) {
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICESEL_DEMODFLT_SLICESEL(Demod), 0);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSDIVN_BYTE_OVERSAMPLING(Demod), 0);
		} else { /* sliced mode */
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICEMIN_DEMODFLT_SLICEMIN(Demod), &slc_min);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICEMAX_DEMODFLT_SLICEMAX(Demod), &slc_max);
			while((slc_min == 255) && (slc_max == 0) && (timeout < 40)) { // 255 is not valid value for slicemin, 0 is not valid for slicemax
				ChipWaitOrAbort(pParams->handle_demod,5);
				timeout = (u8)(timeout + 5);
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICEMIN_DEMODFLT_SLICEMIN(Demod), &slc_min);
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICEMAX_DEMODFLT_SLICEMAX(Demod), &slc_max);
			}
			if(timeout >= 40) {// we force to 1 slice number
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICESEL_DEMODFLT_SLICESEL(Demod), slc_min);
				#ifdef USER2
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICESEL_DEMODFLT_SLICESEL(Demod), 4);
				#endif
			} else {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICESEL_DEMODFLT_SLICESEL(Demod), &slc_sel);
				if((slc_sel < slc_min) || (slc_sel > slc_max)) {
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICESEL_DEMODFLT_SLICESEL(Demod), slc_min);
				}
			}
		}
	}

	*Lock_p = (BOOL) lock;
	return error;
}


/*****************************************************
--FUNCTION	::	FE_STiD135_GetFECLock
--ACTION	::	Returns the FEC lock status
--PARAMS IN	::	hChip -> handle of the chip
			TimeOut -> FEC timeout
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	lock_bool_p -> lock status, boolean
--RETURN	::	error
--***************************************************/
static fe_lla_error_t FE_STiD135_GetFECLock(stchip_handle_t hChip, enum fe_stid135_demod Demod, 
				u32 TimeOut, BOOL* lock_bool_p)
{
	u32 headerField, pktdelinField, lockVitField, timer = 0;
	s32 lock = 0;
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	s32 fld_value;
	enum fe_sat_search_state demodState;

	/* P1_DMDSTATE state machine search status field */
	headerField   = FLD_FC8CODEW_DVBSX_DEMOD_DMDSTATE_HEADER_MODE(Demod);
	/* P1_PDELSTATUS1 packet delin (DVBS 2) lock status field */
	pktdelinField = FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_PKTDELIN_LOCK(Demod);
	/* P1_LOCKEDVIT Viterbi (DVBS1/DSS) lock status field */
	lockVitField  = FLD_FC8CODEW_DVBSX_VITERBI_VSTATUSVIT_LOCKEDVIT(Demod);
		
	error |= ChipGetField(hChip, headerField, &fld_value);
	demodState = (enum fe_sat_search_state)fld_value;
	
	while ((timer < TimeOut) && (lock == 0)) {

		switch (demodState) {
		case FE_SAT_SEARCH:
		case FE_SAT_PLH_DETECTED : /* no signal*/ 
			lock = 0;
		break;
		
		case FE_SAT_DVBS2_FOUND: /* found a DVBS2 signal */ 
			error |= ChipGetField(hChip, pktdelinField, &lock);
		break;
		
		case FE_SAT_DVBS_FOUND:
			error |= ChipGetField(hChip,lockVitField, &lock);
		break;
		}
		
		if (lock == 0)
		{
			ChipWaitOrAbort(hChip, 10);
			timer += 10;
		}
	}

	*lock_bool_p = (BOOL)lock;
		
	return error;
}



/*****************************************************
--FUNCTION	::	FE_STiD135_CarrierWidth
--ACTION	::	Computes the carrier width from symbol rate 
			and roll off
--PARAMS IN	::	SymbolRate -> Symbol rate of the carrier 
			(Kbauds or Mbauds)
			roll_off -> Rolloff * 100
--PARAMS OUT	::	NONE
--RETURN	::	Width of the carrier (KHz or MHz) 
--***************************************************/
u32 FE_STiD135_CarrierWidth(u32 SymbolRate, enum fe_sat_rolloff roll_off)
{
	u32 rolloff = 0;
	
	switch (roll_off) {
	case FE_SAT_05:  rolloff = 05;  break;
	case FE_SAT_10:  rolloff = 10;  break;
	case FE_SAT_15:  rolloff = 15;  break;
	case FE_SAT_20:  rolloff = 20;  break;
	case FE_SAT_25:  rolloff = 25;  break;
	case FE_SAT_35:
			rolloff = 35;
	break;
	}
	return (SymbolRate + (SymbolRate * rolloff) / 100);
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_reg_init_values
--ACTION	::	Sets initial values of registers to be clean
			before an acquisition
--PARAMS IN	::	handle -> Frontend handle
			demod -> current demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	error
--***************************************************/
static fe_lla_error_t fe_stid135_set_reg_init_values(fe_stid135_handle_t handle, enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = NULL;
	
	if(handle != NULL) {
		pParams = (struct fe_stid135_internal_param *) handle;
	
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DEMOD(demod), 0x00);

		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(demod), 0xc8);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARFREQ(demod), 0x45); // to make demod lock in DVBS1 (cold start only)
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR1BCFG(demod), 0x67); 
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_PLSMSCRAMBB(demod), 0x70); 

		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSDLYSET2(demod), 0x31);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSDLYSET1(demod), 0x2B);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSDLYSET0(demod), 0x00);
		
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELMANT(demod), 0x78);
		
		/* New Setting by SG for NB low C/N */
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELABS(demod), 0x70);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELCOEF(demod), 0x20);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELFREQ(demod), 0x70);
		
		/* Reset matype forcing mode */
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_BBHCTRL2_FORCE_MATYPEMSB(demod), 0);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL0_HEMMODE_SELECT(demod), 0);
		
		/* Remove MPEG packetization mode */
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_EMBINDVB(demod), 0);
		
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARHDR(demod), 0x08);
		
		/* Go back to initial value (may be adapted in tracking function) */
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DFECFG(demod), 0xC1);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_XFECFG2(demod), 0x03);
		
		/* Go back to default value in NB (lot of dummy PL frames in WB) */
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR2CFR1(demod), 0x25);

		/* Go back to initial value for MIS+ISSYI use-case */
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPCRPID1_SOFFIFO_PCRADJ(demod), 0);
	} else
		error |= FE_LLA_INVALID_HANDLE;

        return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_reg_values_wb
--ACTION	::	Sets initial values of registers to be clean
			before an acquisition only in wideband usecase
--PARAMS IN	::	handle -> Frontend handle
			demod -> current demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	error
--***************************************************/
static fe_lla_error_t fe_stid135_set_reg_values_wb(fe_stid135_handle_t handle, enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = NULL;

	if(handle != NULL) {
		pParams = (struct fe_stid135_internal_param *) handle;
	
		if (pParams->demod_search_range[demod-1] > 24000000)
			pParams->demod_search_range[demod-1] = 24000000;

		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(demod), 0x80);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARFREQ(demod), 0x00);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR1BCFG(demod), 0xc5); 
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_PLSMSCRAMBB(demod), 0x40); 
		
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSDLYSET2(demod), 0xE2);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSDLYSET1(demod), 0x0A);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSDLYSET0(demod), 0x00);
	
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELMANT(demod), 0x6A);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELCOEF(demod), 0x20);
		/* Reset new Setting by SG for NB low C/N */
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELABS(demod), 0x8c);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELFREQ(demod), 0x30);
		
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARHDR(demod), 0x18);
		
		/* On a signal with lot of dummy PL frames in WB, then need to adjust CFR2CFR1 */
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR2CFR1(demod), 0x23);
	} else
		error |= FE_LLA_INVALID_HANDLE;

	return error;
}
#ifdef USER2
/*****************************************************
--FUNCTION	::	fe_stid135_manage_manual_rolloff
--ACTION	::	Manages rolloff value if user knows its value
--PARAMS IN	::	handle -> Frontend handle
			demod -> current demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	error
--***************************************************/
static fe_lla_error_t fe_stid135_manage_manual_rolloff(fe_stid135_handle_t handle, enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = NULL;
	
	if(handle != NULL) {
		pParams = (struct fe_stid135_internal_param *) handle;
	
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_MANUALS2_ROLLOFF(demod), 1);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_MANUALSX_ROLLOFF(demod), 1);
		switch(pParams->roll_off[demod-1]) {
			case FE_SAT_05:  
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(demod), 4);
			break;
			case FE_SAT_10:
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(demod), 3);
			break;
			case FE_SAT_15:
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(demod), 5);
			break;
			case FE_SAT_20:
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(demod), 2);
			break;
			case FE_SAT_25:
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(demod), 1);
			break;
			case FE_SAT_35:
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(demod), 0);
			break;
			/*TD*/
			default: /* by default automatic rolloff */ 
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_MANUALS2_ROLLOFF(demod), 0);
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_MANUALSX_ROLLOFF(demod), 0);
				
			break;
		}
	}
	else
		error |= FE_LLA_INVALID_HANDLE;
	
	return error;
}
#endif
/*****************************************************
--FUNCTION	::	fe_stid135_search  
--ACTION	::	Search for a valid transponder
--PARAMS IN	::	handle -> Front End Handle
			pSearch -> Search parameters
			pResult -> Result of the search
			demod -> current demod 1..8
			satellitte_scan ==> scan scope
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t	fe_stid135_search(fe_stid135_handle_t handle, enum fe_stid135_demod demod,
	struct fe_sat_search_params *pSearch, struct fe_sat_search_result *pResult, 
	BOOL satellitte_scan)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = NULL;
	enum fe_sat_signal_type signalType = FE_SAT_NOCARRIER;
	s32 fld_value;

	if (handle == NULL)
		return FE_LLA_INVALID_HANDLE;

	if ((!(INRANGE(100000, pSearch->symbol_rate,  520000000))) ||
		  (!(INRANGE(500000, pSearch->search_range, 70000000))))
		return FE_LLA_BAD_PARAMETER;

	pParams = (struct fe_stid135_internal_param *) handle;

	if (pParams->handle_demod->Error)
		return FE_LLA_I2C_ERROR;

	pParams->lo_frequency = pSearch->lo_frequency;

	pParams->tuner_frequency[demod-1] = (s32)(
		pSearch->frequency - pSearch->lo_frequency);

	pParams->demod_search_standard[demod-1] = pSearch->standard;
	pParams->demod_symbol_rate[demod-1] = pSearch->symbol_rate;
	pParams->demod_search_range[demod-1] = pSearch->search_range;
	pParams->demod_search_algo[demod-1] = pSearch->search_algo;
	pParams->demod_search_iq_inv[demod-1] = pSearch->iq_inversion;
	pParams->mis_mode[demod-1] = FALSE; /* Disable memorisation of MIS mode */

	/* Set default register values to start a clean search */
	error |= fe_stid135_set_reg_init_values(handle, demod);

#ifdef USER2
	if(((pSearch->search_algo == FE_SAT_COLD_START) || (pSearch->search_algo == FE_SAT_WARM_START))
		&& (pSearch->symbol_rate >= pParams->master_clock >> 1)) { /* if SR >= MST_CLK / 2 */
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_MATCST1(demod), 0x70);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICESEL_DEMODFLT_SLICESEL(demod), 4);
		/* no else part as it is done by set_reg_init_values() function */
	}
#endif
	#ifdef ATB
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(demod), 2);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_MANUALS2_ROLLOFF(demod), 1);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_MANUALSX_ROLLOFF(demod), 1);
	#endif
	#ifdef USER2
		pParams->roll_off[demod-1] = pSearch->roll_off;
		if(pSearch->man_rolloff == TRUE) {
			error |= fe_stid135_manage_manual_rolloff(handle, demod);
		}
	#endif
#if 1
	if((pSearch->symbol_rate >= pParams->master_clock) && (pParams->demod_search_algo[demod-1] == FE_SAT_BLIND_SEARCH)) /* if SR >= MST_CLK  & Blind search algo : usecase forbidden */
		return(FE_LLA_NOT_SUPPORTED);

	/* Check if user wants to lock demod on a chip where High Symbol Rate feature is forbidden on this chip */
	error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DMDSELOBS_NOSHDB_SEL(demod), &fld_value);
	if((pSearch->symbol_rate >= pParams->master_clock) && fld_value == 3)
		return(FE_LLA_NOT_SUPPORTED);

	if(pSearch->symbol_rate >= pParams->master_clock) { /* if SR >= MST_CLK */
		pParams->demod_search_algo[demod-1] = FE_SAT_WARM_START; // we force warm algo if SR > MST_CLK
		error |= fe_stid135_set_reg_values_wb(handle, demod);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELCFG(demod), 0x83);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_DEMODFLT_XXXMODE(demod), 0x15);
	} else if((pSearch->symbol_rate >= pParams->master_clock >> 1) && (pSearch->symbol_rate < pParams->master_clock)) { /* if SR >= MST_CLK / 2 */
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELCFG(demod), 0x83);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_DEMODFLT_XXXMODE(demod), 0x15);
	} else {
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CORRELCFG(demod), 0x01);
	}
#endif
	//for wideband such as 200Msymbol/s 
	if(pSearch->symbol_rate >= pParams->master_clock) { /* if SR >= MST_CLK */   
		if(demod == FE_SAT_DEMOD_1)
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_HDEBITCFG2(FE_SAT_DEMOD_2), 0xD4);
		if(demod == FE_SAT_DEMOD_3)
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_HDEBITCFG2(FE_SAT_DEMOD_4), 0xD4);
	}

	pParams->demod_puncture_rate[demod-1] = pSearch->puncture_rate;
	pParams->demod_modulation[demod-1] = pSearch->modulation;
	pParams->demod_modcode[demod-1] = pSearch->modcode;
	pParams->tuner_index_jump[demod-1] = pSearch->tuner_index_jump;

	if (error != FE_LLA_NO_ERROR)
		return FE_LLA_BAD_PARAMETER;

	if (demod == FE_SAT_DEMOD_2) {
		if(pSearch->symbol_rate > pParams->master_clock >> 1) { /* if SR >= MST_CLK / 2 */
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_MODE_HAUTDEBIT(demod), 3);
				WAIT_N_MS(10);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_PEGALCFG(demod), 0x1C);
			} else {
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_MODE_HAUTDEBIT(demod), 2);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_PEGALCFG(demod), 0x00);
			}
	}
	if (demod == FE_SAT_DEMOD_4) {
		if(pSearch->symbol_rate > pParams->master_clock >> 1) { /* if SR >= MST_CLK / 2 */
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_MODE_HAUTDEBIT(demod), 3);
				WAIT_N_MS(10);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_PEGALCFG(demod), 0x1C);
			} else {
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_MODE_HAUTDEBIT(demod), 2);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_PEGALCFG(demod), 0x00);
			}
	}

	error |= FE_STiD135_Algo(pParams, demod, satellitte_scan, &signalType);
	pSearch->tuner_index_jump = pParams->tuner_index_jump[demod-1];

	if (signalType == FE_SAT_TUNER_JUMP) {
		error = FE_LLA_TUNER_JUMP;
	} else if (signalType == FE_SAT_TUNER_NOSIGNAL) {
		/* half of the tuner bandwith jump */
		error = FE_LLA_TUNER_NOSIGNAL ;
	}
	else if (((signalType == FE_SAT_RANGEOK)
						 || ((satellitte_scan > 0)
						 && (signalType == FE_SAT_NODATA)))
						&& (pParams->handle_demod->Error == CHIPERR_NO_ERROR))
	{
		if ((satellitte_scan > 0) && (signalType == FE_SAT_NODATA)) {
			/* TPs with demod lock only are logged as well */
			error = FE_LLA_NODATA;
		} else {
			error = FE_LLA_NO_ERROR;
		}

		pResult->locked = pParams->demod_results[demod-1].locked;

		/* update results */
		pResult->standard = pParams->demod_results[demod-1].standard;
		pResult->frequency = pParams->demod_results[demod-1].frequency;
		pResult->symbol_rate = pParams->demod_results[demod-1].symbol_rate;
		pResult->puncture_rate = pParams->demod_results[demod-1].puncture_rate;
		pResult->modcode = pParams->demod_results[demod-1].modcode;
		pResult->pilots = pParams->demod_results[demod-1].pilots;
		pResult->frame_length = pParams->demod_results[demod-1].frame_length;
		pResult->spectrum = pParams->demod_results[demod-1].spectrum;
		pResult->roll_off = pParams->demod_results[demod-1].roll_off;
		pResult->modulation = pParams->demod_results[demod-1].modulation;

		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR;

		/* Optimization setting for tracking */
		error |= FE_STiD135_TrackingOptimization(pParams, demod);

		/* Reset obs registers */
		error |= fe_stid135_reset_obs_registers(handle, demod);
	} else {
		pResult->locked = FALSE;
	
		switch (pParams->demod_error[demod-1]) {
			/*I2C error*/
			case FE_LLA_I2C_ERROR:
				error = FE_LLA_I2C_ERROR;
				break;
			case FE_LLA_INVALID_HANDLE:
			case FE_LLA_ALLOCATION:
			case FE_LLA_BAD_PARAMETER:
			case FE_LLA_SEARCH_FAILED:
			case FE_LLA_TRACKING_FAILED:
			case FE_LLA_NODATA:
			case FE_LLA_TUNER_NOSIGNAL:
			case FE_LLA_TUNER_JUMP:
			case FE_LLA_TUNER_4_STEP:
			case FE_LLA_TUNER_8_STEP:
			case FE_LLA_TUNER_16_STEP:
			case FE_LLA_TERM_FAILED:
			case FE_LLA_DISEQC_FAILED:
			case FE_LLA_NOT_SUPPORTED:
				error = FE_LLA_SEARCH_FAILED;
				break;
			case FE_LLA_NO_ERROR:
				error = FE_LLA_NO_ERROR;
				break;
		}
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR;
	}

	return error;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_GetLockTimeout  
--ACTION	::	Returns the demod and fec lock timeout in function
			of the symbol rate
--PARAMS IN	::	SymbolRate -> Symbol rate
			Algo -> algorithm used
--PARAMS OUT	::	DemodTimeout -> computed timeout for demod
			FecTimeout -> computed timeout for FEC
--RETURN	::	NONE
--***************************************************/
static void FE_STiD135_GetLockTimeout(u32 *DemodTimeout,u32 *FecTimeout, 
		u32 SymbolRate, enum fe_sat_search_algo Algo)
{
	switch (Algo) {
	case FE_SAT_BLIND_SEARCH:
	
		if (SymbolRate <= 1500000) {        /*1 Msps< SR <=1.5Msps*/
			(*DemodTimeout) = 8000; // Fixed issue BZ#86598
			(*FecTimeout) = 8000;   // Fixed issue BZ#86598
		} else if (SymbolRate <= 5000000) {  /* 1.5Msps< SR <=5Msps*/
			(*DemodTimeout) = 1000;
			(*FecTimeout) = 300;
		} else if(SymbolRate <= 30000000) { /* 5 Msps< SR <=30Msps*/
			(*DemodTimeout) = 700;
			(*FecTimeout) = 300;
		} else if (SymbolRate <= 45000000) { /* 30 Msps< SR <=45Msps*/
			(*DemodTimeout) = 400;
			(*FecTimeout) = 200;
		} else  { /*SR >45Msps*/
			(*DemodTimeout) = 300;
			(*FecTimeout) = 100;
		}

	break;
	
	case FE_SAT_COLD_START:
	case FE_SAT_WARM_START:
		if (SymbolRate <= 1000000) {       /*SR <=1Msps*/
			(*DemodTimeout) = 3000;
			(*FecTimeout) = 2000;  /*1700 */  
		} else if (SymbolRate <= 2000000) { /*1Msps < SR <=2Msps*/
			(*DemodTimeout) = 2500;
			(*FecTimeout) = 1300; /*1100 */
		} else if (SymbolRate <= 5000000) { /*2Msps< SR <=5Msps*/
			(*DemodTimeout) = 1000;
			(*FecTimeout) = 650; /* 550 */
		} else if (SymbolRate <= 10000000) { /*5Msps< SR <=10Msps*/
			(*DemodTimeout) = 700;
			(*FecTimeout) = 350; /*250 */
		} else if (SymbolRate <= 20000000) { /*10Msps< SR <=20Msps*/
			(*DemodTimeout) = 400;
			(*FecTimeout) = 200; /* 130 */
		} else {  /*SR >20Msps*/
			(*DemodTimeout)=300;
			(*FecTimeout)=200; /* 150 */
		}
	break;

	}
	if (Algo == FE_SAT_WARM_START) {
		/*if warm start
		demod timeout = coldtimeout/3
		fec timeout = same as cold*/
		(*DemodTimeout) /= 2;
	}
	
}

/**********************************************************************************
FUNCTION   : Estimate_Power_Int
ACTION     : basic function to verify channel power estimation (PchRF) and 
                                     band  power estimation (Pband) in order to verify designers   
                                     formulas principle inside ATB                                                                                     
                                     Config is hardwired on TUNER1/DEMOD1                          
                                     This function handle integer values for LLA  
                                    
PARAMS IN  : Handle
                                   TunerNb[1;4]
                                   DemodNb [0;7]
                                   PowerIref should be set to 105 
PARAMS OUT : *AGCRFIN1,
                                   *AGCRFIN0,
                                   *Agc1,
                                   *AGC1POWERI,
                                   *AGC1POWERQ,
                                   *AGC1REF,
                                   *AGC2REF,
                                   *AGC2I1,
                                   *AGC2I0,
                                   *mant,
                                   *exp,
                                   *Agc2,
                                   *GvDig,
                                   *InterpolatedGvana,
                                   *PchRF,
                                   *Pband
RETURN     : error
**********************************************************************************/
static fe_lla_error_t Estimate_Power_Int(stchip_handle_t Handle,
					enum fe_stid135_demod Demod,
					u8 TunerNb,
					u8 *AGCRFIN1,
					u8 *AGCRFIN0,
					u32 *Agc1,
					u8 *AGC1POWERI,
					u8 *AGC1POWERQ,
					u8 *AGC1REF,
					u8 *AGC2REF,
					u8 *AGC2I1,
					u8 *AGC2I0,
					u16 *mant,
					u8 *exp,
					u32 *Agc2x1000,
					u32*Gvanax1000,
					s32*PchRFx1000,
					s32*Pbandx1000)
{
	s32 exp_abs_s32=0, exp_s32=0;
	u32 agc2x1000=0;
	u32 gain_analogx1000=0;
	u8 VGLNAgainMode = 0;
	u32 reg_value;
	s32 fld_value;
	u8 agcrfin1, agcrfin0, agc1poweri, agc1powerq,agc1ref, agc2ref, agc2i1, agc2i0,agciqin1, agciqin0/*, exponant=0*/;
	s8 exponant = 0; // RF level fix BZ#107344
	u16 mantisse=0;
	u8 NOSFR, DemodLock;
	u32 agc1=0;
	u32 agciqin;
	u8 agcrfpwm=0;
	s32 correction1000=0;
	u32 f;
	s32 x,y;
	u32 mult;

	struct fe_stid135_internal_param *pParams;
	fe_lla_error_t error=FE_LLA_NO_ERROR;
	pParams = (struct fe_stid135_internal_param*) Handle;
	
	/* Read all needed registers before calculation*/ 
	error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_TAGC2_AGC2EXP_NOSFR(Demod), &fld_value);
	NOSFR= (u8)fld_value; 
	error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DMDSTATE_DEMOD_LOCKED(Demod), &fld_value);
	DemodLock = (u8)fld_value; 
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2I1(Demod), &reg_value);
	agc2i1 = (u8)reg_value;
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2I0(Demod), &reg_value);
	agc2i0 = (u8)reg_value;
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFIN1(TunerNb), &reg_value);
	agcrfin1 = (u8)reg_value; 
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFIN0(TunerNb), &reg_value);
	agcrfin0 = (u8)reg_value; 
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2REF(Demod), &reg_value);
	agc2ref = (u8)reg_value; 
	ChipWaitOrAbort(pParams->handle_demod,1);
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1REF(Demod), &reg_value);
	agc1ref = (u8)reg_value; 
	ChipWaitOrAbort(pParams->handle_demod,1);
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1POWERI(Demod), &reg_value);
	agc1poweri = (u8)reg_value; 
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1POWERQ(Demod), &reg_value);
	agc1powerq = (u8)reg_value; 
	
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1IQIN1(Demod), &reg_value);
	agciqin1 = (u8)reg_value;
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1IQIN0(Demod), &reg_value);
	agciqin0 = (u8)reg_value;
	
	/* check I2c error and demod lock for data coherency                */
	/* Bit NOSFR must be =0 and POWER_IREF should not be null  */                                                                     
	if ((NOSFR==0) && (DemodLock==1) && (error==FE_LLA_NO_ERROR) && (POWER_IREF!=0) ) {
		/*************** calculate AGC2 ********************/ 
		/*  Agc2= (AGC2I1*4 +AGC2I1) *2^XtoPowerY (exp-9)  */
		/* exp min=5  max=15                               */
		/* so (exp-9) min=-4 max=6                         */
		/***************************************************/
		mantisse = (u16)((agc2i1 * 4) + ((agc2i0 >> 6) & 0x3));
		//exponant = (u8)(agc2i0 & 0x3f);
		/* Fix of BZ#107344
		AGC2 accumulator exponent is signed with a sign bit (bit#5 of AGC2I0 register) */
		if(((agc2i0 & 0x20) >> 5) == 0)
			exponant = (s8)(agc2i0 & 0x3f);
		else if(((agc2i0 & 0x20) >> 5) == 1)
			exponant = (s8)((agc2i0 & 0x1f) - 32);

		/*evaluate exp-9 */
		exp_s32 = (s32)(exponant - 9);                                                                                                                                                                                                  
		
		if (exp_s32<= -32) {
			agc2x1000 = 0;
		}else if(exp_s32<0){
			/* if exp_s32<0 divide the mantissa  by 2^abs(exp_s32)*/
			exp_abs_s32= XtoPowerY(2,(u32)(- exp_s32));
			agc2x1000 = (u32)((1000 * mantisse) / exp_abs_s32);
		} else {
			/*if exp_s32> 0 multiply the mantissa  by 2^(exp_s32)*/
			exp_abs_s32= XtoPowerY(2,(u32)(exp_s32));
			agc2x1000 = (u32)((1000 * mantisse) * exp_abs_s32);
		}
		
		/******** interpolate Gvana ************/
		/* interpolate Gvana from LUT LutGvana */
		//agc1 = (u32)((256 * agcrfin1) + agcrfin0);
		switch(TunerNb) {
			case AFE_TUNER1 :
				gain_analogx1000 = LutGvanaIntegerTuner[agcrfin1];
				error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC1_RF_PWM, &reg_value);
				agcrfpwm = (u8)reg_value;
			break;
			case AFE_TUNER2 :
				gain_analogx1000 = LutGvanaIntegerTuner[agcrfin1];
				error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC2_RF_PWM, &reg_value);
				agcrfpwm = (u8)reg_value;
			break;
			case AFE_TUNER3 :
				gain_analogx1000 = LutGvanaIntegerTuner[agcrfin1];
				error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC3_RF_PWM, &reg_value);
				agcrfpwm = (u8)reg_value;
			break;
			case AFE_TUNER4 :
			default:
				gain_analogx1000 = LutGvanaIntegerTuner[agcrfin1];
				error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC4_RF_PWM, &reg_value);
				agcrfpwm = (u8)reg_value;
			break;
		}
		/* if VGLNA is inIP3 substract  6db gain*/
		VGLNAgainMode = Oxford_GetVGLNAgainMode(pParams->handle_demod, TunerNb);
		if (VGLNAgainMode != 1){
			/* InterpolatedGvan always >0*/
			gain_analogx1000 = gain_analogx1000 - 6000; 
		}

		/************ Power Channel ************/
		/* PchAGC2 = agc2ref^2 */
		/* Pch(dBm) = 10xlog( PchAGC2 / GvDig^2) - GainAnalog */
		/* GvDig= ((agc2/165.8) * (1550/12)); for demod 1,3 */
		/* GvDig= ((agc2/268) * (1550/12));   for demod 2,4,5,6,7,8 */
		/* GvDig^2 = agc2x1000^2 * 607 for demod 1,3 */
		/* GvDig^2 = agc2x1000^2 * 232 for demod 2,4,5,6,7,8 */
		/* log(a/b) = log(a) - log(b) */
		/* 10xlog( PchAGC2 / GvDig^2) =  10xlog( PchAGC2)-10xlog(GvDig^2) */

		if ((Demod == FE_SAT_DEMOD_1) || (Demod == FE_SAT_DEMOD_3))
			mult = 607;
		else
			mult = 232;

		x = (s32)STLog10((u32)(2 * agc2ref * agc2ref));
		if (agc2x1000 > 18809) // Avoid (2 x agc2x1000^2 x 607) > Integer size 
			y = (s32)STLog10(2 * agc2x1000 * (agc2x1000/1000) * mult) - 6000;
		else if (agc2x1000 > 5947)
			y = (s32)STLog10(2 * agc2x1000 * (agc2x1000/100) * mult) - 7000;
		else if (agc2x1000 > 1880)
			y = (s32)STLog10(2 * agc2x1000 * (agc2x1000/10) * mult) - 8000;
		else
			y = (s32)STLog10(2 * agc2x1000 * agc2x1000 * mult) - 9000 ;
		
		*PchRFx1000 = (s32)(10 * (x - y) - (s32)gain_analogx1000 + 3000); // + 3000 agc2x1000
		
		/************ Power Band ***************/
		/* PBand =  10log ((AGC1REF/POWERIREF)^2 * AGC1IQIN * 3) - Gvana and log(a/b) = log(a) - log(b)*/
		/* And AGCIQIN * 3 almost = AGCPOWERI^2 + AGCPOWERQ^2 */
		agciqin = (u32)((256 * agciqin1) + agciqin0);
		*Pbandx1000 = (s32)(10 * (STLog10((u32)(3 * agciqin)) + STLog10((u32)(agc1ref * agc1ref)) -  STLog10((u32)(POWER_IREF * POWER_IREF))) - gain_analogx1000);

		/************ Correction ***************/
		agc1 = (u32)((256 * agcrfin1) + agcrfin0);
		
		f = (u32) pParams->demod_results[Demod-1].frequency;
		correction1000 = (s32)(f/1000  - 1550);
		correction1000 = (s32)(correction1000*1000/600);
		correction1000 = (s32) (correction1000 * correction1000/1000);
					
		if ((agc1 > 0) && (agcrfpwm >= 128)) {
			correction1000 += correction1000;
		}
		
		*PchRFx1000 += correction1000;
		*Pbandx1000 += correction1000;
	} else {
		error |=FE_LLA_INVALID_HANDLE;
	}

	if ( error== FE_LLA_NO_ERROR) {
		*AGCRFIN1	= agcrfin1;
		*AGCRFIN0	= agcrfin0;
		*Agc1		= agc1;
		*AGC1POWERI	= agc1poweri;
		*AGC1POWERQ	= agc1powerq;
		*AGC1REF	= agc1ref;
		*AGC2REF	= agc2ref;
		*AGC2I1		= agc2i1;
		*AGC2I0		= agc2i0;
		*mant		= mantisse;
		*exp		= (u8)exponant;
		*Agc2x1000	= agc2x1000;
		*Gvanax1000	= gain_analogx1000;
	}
	return error;
}


/*****************************************************
--FUNCTION	::	FE_STiD135_GetRFLevel  
--ACTION	::	Returns the RF level of signal
--PARAMS IN	::	handle -> Frontend handle
			Demod -> current demod 1..8
--PARAMS OUT	::	pch_rf -> computed channel power
			pband_rf -> computed band power
--RETURN	::	error
--***************************************************/
fe_lla_error_t FE_STiD135_GetRFLevel(fe_stid135_handle_t handle, 
			enum fe_stid135_demod Demod, s32 *pch_rf, s32 *pband_rf)

{
	u8 AGCRFIN1;
	u8 AGCRFIN0;
	u32 Agc1;
	u8 AGC1POWERI;
	u8 AGC1POWERQ;
	u8 AGC1REF;
	u8 AGC2REF;
	u8 AGC2I1;
	u8 AGC2I0;
	u16 mant;
	u8 exp;
	u32 Agc2x1000;
	u32 InterpolatedGvanax1000;
	s32 PchRFx1000 = 0;
	s32 Pbandx1000 = 0;
	s32 agcrf_path;
	struct fe_stid135_internal_param *pParams;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	
	pParams = (struct fe_stid135_internal_param *) handle;
	error |= fe_stid135_get_agcrf_path(pParams->handle_demod, Demod,&agcrf_path );
	
	error |= Estimate_Power_Int(handle, Demod, (u8)agcrf_path, &AGCRFIN1, &AGCRFIN0, &Agc1, &AGC1POWERI, &AGC1POWERQ, &AGC1REF, &AGC2REF, &AGC2I1, &AGC2I0, &mant, &exp, &Agc2x1000, &InterpolatedGvanax1000, &PchRFx1000, &Pbandx1000);
	*pch_rf = PchRFx1000;
	*pband_rf = Pbandx1000;
	
	return(error);
}

/**********************************************************************************
FUNCTION	::	estimate_band_power_demod_not_locked
ACTION		::	Basic function to verify band power estimation (Pband) when
			demod is not locked
PARAMS IN  	::	Handle
			Demod [0;7]
			TunerNb[1;4]
			PowerIref should be set to 105 
PARAMS OUT	::	*AGCRFIN1,
			*AGCRFIN0,
			*AGC1REF,
			*Pbandx1000
RETURN		::	error
**********************************************************************************/
static fe_lla_error_t estimate_band_power_demod_not_locked(stchip_handle_t Handle,
					enum fe_stid135_demod Demod,
					u8 TunerNb,
					u8 *AGCRFIN1,
					u8 *AGCRFIN0,
					u8 *AGC1REF,
					s32 *Pbandx1000)
{
	u32 gain_analogx1000=0;
	u8 VGLNAgainMode = 0;
	u32 reg_value;
	u8 agcrfin1, agcrfin0, agc1ref, agciqin1, agciqin0;
	u32 agciqin;
	u8 savedmd = 0;

	struct fe_stid135_internal_param *pParams;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	pParams = (struct fe_stid135_internal_param*) Handle;
	
	/* Read all needed registers before calculation*/ 
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFIN1(TunerNb), &reg_value);
	agcrfin1 = (u8)reg_value; 
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFIN0(TunerNb), &reg_value);
	agcrfin0 = (u8)reg_value; 
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1REF(Demod), &reg_value);
	agc1ref = (u8)reg_value; 
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1IQIN1(Demod), &reg_value);
	agciqin1 = (u8)reg_value;
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1IQIN0(Demod), &reg_value);
	agciqin0 = (u8)reg_value;
	
	switch(TunerNb) {
		case AFE_TUNER1 :
			gain_analogx1000 = LutGvanaIntegerTuner[agcrfin1];
		break;
		case AFE_TUNER2 :
			gain_analogx1000 = LutGvanaIntegerTuner[agcrfin1];
		break;
		case AFE_TUNER3 :
			gain_analogx1000 = LutGvanaIntegerTuner[agcrfin1];
		break;
		case AFE_TUNER4 :
		default:
			gain_analogx1000 = LutGvanaIntegerTuner[agcrfin1];
		break;
	}
	/* if VGLNA is inIP3 substract  6db gain*/
	VGLNAgainMode = Oxford_GetVGLNAgainMode(pParams->handle_demod, TunerNb);
	if (VGLNAgainMode != 1){
		/* InterpolatedGvan always >0*/
		gain_analogx1000 = gain_analogx1000 - 6000; 
	}
	

	/* Read DMDISTATE to check if demod is stopped or reset, then put demod in search state for band power accuracy */
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(Demod), &reg_value);
	savedmd = (u8)reg_value;
	if ((savedmd == 0x5C) || (savedmd == 0x1C)) {
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(Demod), 0x00); 
		WAIT_N_MS(100);
	}
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1IQIN1(Demod), &reg_value);
	agciqin1 = (u8)reg_value;
	error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1IQIN0(Demod), &reg_value);
	agciqin0 = (u8)reg_value;
	agciqin = (u32)((256 * agciqin1) + agciqin0); 
	*Pbandx1000 = (s32)(10 * (STLog10((u32)(3 * agciqin)) + STLog10((u32)(agc1ref * agc1ref)) -  STLog10((u32)(POWER_IREF * POWER_IREF))) - gain_analogx1000); 
	 
	/* Restore value of DMDISTATE */
	if (savedmd != 0)
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(Demod), savedmd);

	if ( error== FE_LLA_NO_ERROR) {
		*AGCRFIN1	= agcrfin1;
		*AGCRFIN0	= agcrfin0;
		*AGC1REF	= agc1ref;
	}
	return error;
}


/*****************************************************
--FUNCTION	::	fe_stid135_get_band_power_demod_not_locked
--ACTION	::	Returns the band pwoer when demod is not locked
--PARAMS IN	::	handle -> Frontend handle
			Demod -> current demod 1..8
--PARAMS OUT	::	pch_rf -> computed channel power
			pband_rf -> computed band power
--RETURN	::	error
--***************************************************/
fe_lla_error_t fe_stid135_get_band_power_demod_not_locked(fe_stid135_handle_t handle, 
			enum fe_stid135_demod Demod, s32 *pband_rf)

{
	u8 AGCRFIN1;
	u8 AGCRFIN0;
	u8 AGC1REF;
	s32 Pbandx1000;

	s32 agcrf_path;
	struct fe_stid135_internal_param *pParams;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	
	pParams = (struct fe_stid135_internal_param *) handle;
	error |= fe_stid135_get_agcrf_path(pParams->handle_demod, Demod, &agcrf_path);
	error |= estimate_band_power_demod_not_locked(handle, Demod, (u8)agcrf_path, &AGCRFIN1, &AGCRFIN0, &AGC1REF, &Pbandx1000);
	*pband_rf = Pbandx1000;
	
	return(error);
}


fe_lla_error_t fe_stid135_get_signal_quality(fe_stid135_handle_t Handle,
					enum fe_stid135_demod demod,
					struct fe_sat_signal_info *pInfo,
					int mc_auto)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	s32 pch_rf, pband_rf;

	pParams = (struct fe_stid135_internal_param *) Handle;

	error |= FE_STiD135_GetBer(pParams->handle_demod, demod, &(pInfo->ber));
	error |= FE_STiD135_GetRFLevel(pParams, demod, &pch_rf, &pband_rf);
	pInfo->power = pch_rf;
	
	error |= FE_STiD135_GetStandard(
			pParams->handle_demod, demod, &(pInfo->standard)); 

	if (pInfo->standard == FE_SAT_DVBS2_STANDARD) {
		error |= FE_STiD135_CarrierGetQuality(pParams->handle_demod, &FE_STiD135_S2_CN_LookUp, demod, &(pInfo->C_N));
		if (mc_auto)
			error |= fe_stid135_filter_forbidden_modcodes(pParams, demod, pInfo->C_N * 10);
	} else {
		error |= FE_STiD135_CarrierGetQuality(pParams->handle_demod, &FE_STiD135_S1_CN_LookUp, demod, &(pInfo->C_N));
	}

	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_get_signal_info
--ACTION	::	Return informations on the locked transponder
--PARAMS IN	::	Handle -> Front End Handle
			Demod -> Current demod 1 .. 8
			satellitte_scan -> scan or acquisition context
--PARAMS OUT	::	pInfo -> Informations (BER,C/N,power ...)
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_get_signal_info(fe_stid135_handle_t Handle,
					enum fe_stid135_demod Demod, 
					struct fe_sat_signal_info *pInfo, 
					u32 satellitte_scan)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	enum fe_sat_search_state demodState;
	s32 pch_rf, pband_rf;
	s32 fld_value[3];
	s32 symbolRateOffset = 0, carrier_frequency = 0;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	
	if (pParams != NULL) {		
		if ( pParams->handle_demod->Error )	
				error = FE_LLA_I2C_ERROR; 
		
		else {
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DMDSTATE_HEADER_MODE(Demod), &(fld_value[0]));
			demodState = (enum fe_sat_search_state)(fld_value[0]);
			switch(demodState) {
	
			case FE_SAT_SEARCH:
			case FE_SAT_PLH_DETECTED :
				pInfo->locked = FALSE;
				break;
			
			case FE_SAT_DVBS2_FOUND:
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_LOCK_DEFINITIF(Demod), &(fld_value[0]));
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_PKTDELIN_LOCK(Demod), &(fld_value[1]));
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS_TSFIFO_LINEOK(Demod), &(fld_value[2]));
				pInfo->locked = fld_value[0] && fld_value[1] && fld_value[2];
			break;
				
			case FE_SAT_DVBS_FOUND:
				error |= ChipGetField(pParams->handle_demod,FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_LOCK_DEFINITIF(Demod), &(fld_value[0]));
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_VITERBI_VSTATUSVIT_LOCKEDVIT(Demod), &(fld_value[1]));
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS_TSFIFO_LINEOK(Demod), &(fld_value[2]));
				
				pInfo->locked = fld_value[0] && fld_value[1] && fld_value[2];
			break;
			}
		
			/* transponder_frequency = tuner +  demod carrier
			frequency */
			pInfo->frequency = pParams->lo_frequency / 1000;
			
			/* On auxiliary demod, frequency found is not true, we have to pick it on master demod  */
			/* On auxiliary demod, SR found is not true, we have to pick it on master demod  */
			if(Demod == FE_SAT_DEMOD_2) {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_MODE_HAUTDEBIT(Demod), &(fld_value[0]));
				if(fld_value[0] == 3) {
					error |= FE_STiD135_GetCarrierFrequency(pParams->handle_demod,pParams->master_clock, FE_SAT_DEMOD_1, &carrier_frequency);
					carrier_frequency /= 1000;
					error |= FE_STiD135_GetSymbolRate(pParams->handle_demod, pParams->master_clock,FE_SAT_DEMOD_1, &(pInfo->symbol_rate));
					error |= FE_STiD135_TimingGetOffset(pParams->handle_demod,pInfo->symbol_rate, FE_SAT_DEMOD_1, &symbolRateOffset);
				}
			}
			if(Demod == FE_SAT_DEMOD_4) {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_MODE_HAUTDEBIT(Demod), &(fld_value[0]));
				if(fld_value[0] == 3) {
					error |= FE_STiD135_GetCarrierFrequency(pParams->handle_demod,pParams->master_clock, FE_SAT_DEMOD_3, &carrier_frequency);
					carrier_frequency /= 1000;
					error |= FE_STiD135_GetSymbolRate(pParams->handle_demod, pParams->master_clock,FE_SAT_DEMOD_3, &(pInfo->symbol_rate));
					error |= FE_STiD135_TimingGetOffset(pParams->handle_demod,pInfo->symbol_rate, FE_SAT_DEMOD_3, &symbolRateOffset);
				}
			}
			if(((Demod != FE_SAT_DEMOD_2) && (Demod != FE_SAT_DEMOD_4)) ||
			    ((Demod == FE_SAT_DEMOD_2) && (fld_value[0] != 3)) ||
			    ((Demod == FE_SAT_DEMOD_4) && (fld_value[0] != 3))) {
				error |= FE_STiD135_GetCarrierFrequency(pParams->handle_demod,pParams->master_clock, Demod, &carrier_frequency);
				carrier_frequency /= 1000;
				error |= FE_STiD135_GetSymbolRate(pParams->handle_demod,pParams->master_clock,Demod, &(pInfo->symbol_rate));
				error |= FE_STiD135_TimingGetOffset(pParams->handle_demod,pInfo->symbol_rate,Demod, &symbolRateOffset);
			}
			
			if(carrier_frequency < 0) {
				carrier_frequency *= (-1);
				pInfo->frequency -= (u32)carrier_frequency;
			}
			else
				pInfo->frequency += (u32)carrier_frequency;
				
			
			/* Get timing loop offset */
			if(symbolRateOffset < 0) {
				symbolRateOffset *= (-1);
				pInfo->symbol_rate -= (u32)symbolRateOffset;
			}
			else
				pInfo->symbol_rate += (u32)symbolRateOffset;
				
			error |= FE_STiD135_GetStandard(
				pParams->handle_demod, Demod, &(pInfo->standard)); 

			 error |= FE_STiD135_GetViterbiPunctureRate(
				pParams->handle_demod,Demod, &(pInfo->puncture_rate));
				
			error |= fe_stid135_get_mode_code(pParams,
						Demod,
						&pInfo->modcode, 
						&pInfo->frame_length, 
						&pInfo->pilots);
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_TMGOBS_ROLLOFF_STATUS(Demod), &(fld_value[0]));
			pInfo->roll_off = (enum fe_sat_rolloff)(fld_value[0]);
					
			if (satellitte_scan == FALSE) {
				error |= FE_STiD135_GetBer(pParams->handle_demod,Demod, &(pInfo->ber));
				error |= FE_STiD135_GetRFLevel(pParams, Demod, &pch_rf, &pband_rf);
				pInfo->power = pch_rf;
				pInfo->powerdBmx10 = pch_rf * 10;
				pInfo->band_power = pband_rf;
				if (pInfo->standard == FE_SAT_DVBS2_STANDARD) {
					error |= FE_STiD135_CarrierGetQuality(pParams->handle_demod, &FE_STiD135_S2_CN_LookUp, Demod, &(pInfo->C_N));
				} 
				else
				{
					error |= FE_STiD135_CarrierGetQuality(pParams->handle_demod, &FE_STiD135_S1_CN_LookUp, Demod, &(pInfo->C_N));
				}
			} else { /* no BER, Power and CNR measurement during scan */
				pInfo->ber = 0;
				pInfo->power = 0;
				pInfo->C_N = 100;
			}
				
			if(pInfo->standard == FE_SAT_DVBS2_STANDARD) {
				error |= ChipGetField(pParams->handle_demod,FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS6_SPECINV_DEMOD(Demod), &(fld_value[0]));
				pInfo->spectrum = (enum fe_sat_iq_inversion)(fld_value[0]);
					
				if (((pInfo->modcode >= FE_SAT_QPSK_14) && (pInfo->modcode <= FE_SAT_QPSK_910))
					|| ((pInfo->modcode >= FE_SAT_DVBS1_QPSK_12) && (pInfo->modcode <= FE_SAT_DVBS1_QPSK_78))
					|| ((pInfo->modcode >= FE_SATX_QPSK_13_45) && (pInfo->modcode <= FE_SATX_QPSK_11_20))
					|| ((pInfo->modcode >= FE_SATX_QPSK_11_45) && (pInfo->modcode <= FE_SATX_QPSK_32_45)))
					pInfo->modulation = FE_SAT_MOD_QPSK;
				
				else if (((pInfo->modcode >= FE_SAT_8PSK_35) && (pInfo->modcode <= FE_SAT_8PSK_910))
					|| ((pInfo->modcode >= FE_SATX_8PSK_23_36) && (pInfo->modcode <= FE_SATX_8PSK_13_18))
					|| ((pInfo->modcode >= FE_SATX_8PSK_7_15) && (pInfo->modcode <= FE_SATX_8PSK_32_45))
					|| (pInfo->modcode == FE_SATX_8PSK))
					pInfo->modulation=FE_SAT_MOD_8PSK;
				
				else if (((pInfo->modcode >= FE_SAT_16APSK_23) && (pInfo->modcode <= FE_SAT_16APSK_910))
					|| ((pInfo->modcode >= FE_SATX_16APSK_26_45) && (pInfo->modcode <= FE_SATX_16APSK_23_36))
					|| ((pInfo->modcode >= FE_SATX_16APSK_25_36) && (pInfo->modcode <= FE_SATX_16APSK_77_90))
					|| ((pInfo->modcode >= FE_SATX_16APSK_7_15) && (pInfo->modcode <= FE_SATX_16APSK_32_45))
					|| (pInfo->modcode == FE_SATX_16APSK))
					pInfo->modulation=FE_SAT_MOD_16APSK;
				
				else if (((pInfo->modcode >= FE_SAT_32APSK_34) && (pInfo->modcode <= FE_SAT_32APSK_910))
					|| ((pInfo->modcode >= FE_SATX_32APSK_R_58) && (pInfo->modcode <= FE_SATX_32APSK_7_9))
					|| ((pInfo->modcode >= FE_SATX_32APSK_2_3) && (pInfo->modcode <= FE_SATX_32APSK_32_45_S))
					|| (pInfo->modcode == FE_SATX_32APSK))
					pInfo->modulation = FE_SAT_MOD_32APSK;
				
				else if ((pInfo->modcode == FE_SATX_VLSNR1) || (pInfo->modcode == FE_SATX_VLSNR2))
					pInfo->modulation = FE_SAT_MOD_VLSNR;
				
				else if (((pInfo->modcode >= FE_SATX_64APSK_11_15) && (pInfo->modcode <= FE_SATX_64APSK_5_6))
					|| (pInfo->modcode == FE_SATX_64APSK))
					pInfo->modulation = FE_SAT_MOD_64APSK;
					
				else if ((pInfo->modcode == FE_SATX_128APSK_3_4) || (pInfo->modcode == FE_SATX_128APSK_7_9))
					pInfo->modulation = FE_SAT_MOD_128APSK;
					
				else if ((pInfo->modcode == FE_SATX_256APSK_32_45) || (pInfo->modcode == FE_SATX_256APSK_3_4)
					|| (pInfo->modcode == FE_SATX_256APSK))
					pInfo->modulation = FE_SAT_MOD_256APSK;
					
				else if ((pInfo->modcode == FE_SATX_8APSK_5_9_L) || (pInfo->modcode == FE_SATX_8APSK_26_45_L))
					pInfo->modulation = FE_SAT_MOD_8PSK_L;
				
				else if (((pInfo->modcode >= FE_SATX_16APSK_1_2_L) && (pInfo->modcode <= FE_SATX_16APSK_5_9_L))
					|| (pInfo->modcode == FE_SATX_16APSK_3_5_L)
					|| (pInfo->modcode == FE_SATX_16APSK_2_3_L))
					pInfo->modulation = FE_SAT_MOD_16APSK_L;
				
				else if (pInfo->modcode == FE_SATX_32APSK_2_3_L)
					pInfo->modulation = FE_SAT_MOD_32APSK_L;
				
				else if (pInfo->modcode == FE_SATX_64APSK_32_45_L)
					pInfo->modulation = FE_SAT_MOD_64APSK_L;
				
				else if (((pInfo->modcode >= FE_SATX_256APSK_29_45_L) && (pInfo->modcode <= FE_SATX_256APSK_31_45_L))
					|| (pInfo->modcode == FE_SATX_256APSK_11_15_L))
					pInfo->modulation = FE_SAT_MOD_256APSK_L;
				
				else if (pInfo->modcode == FE_SATX_1024APSK)
					pInfo->modulation = FE_SAT_MOD_1024APSK;
				
				else
					pInfo->modulation = FE_SAT_MOD_UNKNOWN;
						
				/*reset the error counter to PER*/
				error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_HWARE_ERRCTRL1(Demod), 0x67);
			} else { /*DVBS1/DSS*/
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_VITERBI_FECM_IQINV(Demod), &(fld_value[0]));
				pInfo->spectrum = (enum fe_sat_iq_inversion)(fld_value[0]);
				pInfo->modulation = FE_SAT_MOD_QPSK;
			}
				
			if (pParams->handle_demod->Error)
				error |= FE_LLA_I2C_ERROR; 

		}

	}
	else
		error = FE_LLA_INVALID_HANDLE; 
		
	return error; 
}

/*****************************************************
--FUNCTION	::	fe_stid135_tracking
--ACTION	::	Return Tracking informations : lock status, RF level, C/N and BER.
--PARAMS IN	::	Handle -> Front End Handle
			Demod -> Current demod 1 .. 8
--PARAMS OUT	::	pTrackingInfo ==> pointer to FE_STiD135_TrackingInfo_t struct.
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_tracking(fe_stid135_handle_t Handle,
				enum fe_stid135_demod Demod,
				struct fe_sat_tracking_info *pTrackingInfo)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	enum fe_sat_search_state	demodState;
	s32 pch_rf, pband_rf, fld_value[3], symbolRateOffset = 0;
	u32 symbol_rate;
	
	pParams = (struct fe_stid135_internal_param	*) Handle;
	
	if(pParams != NULL) {		
			
		if (pParams->handle_demod->Error) 
			error=FE_LLA_I2C_ERROR; 
		else {
			error = FE_STiD135_GetRFLevel(pParams, Demod, &pch_rf, &pband_rf);
			pTrackingInfo->power = pch_rf;
			pTrackingInfo->powerdBmx10=(s32)(pch_rf * 10);
			pTrackingInfo->band_power = pband_rf;
			error |= FE_STiD135_GetBer(pParams->handle_demod, Demod, &(pTrackingInfo->ber));

			error |= ChipGetField(pParams->handle_demod,FLD_FC8CODEW_DVBSX_DEMOD_DMDSTATE_HEADER_MODE(Demod), &(fld_value[0]));
			demodState = (enum fe_sat_search_state)(fld_value[0]);
			
			
			switch(demodState) {
				case FE_SAT_SEARCH:
				case FE_SAT_PLH_DETECTED :
					pTrackingInfo->locked = FALSE;
					pTrackingInfo->C_N = 0;
				break;
				case FE_SAT_DVBS2_FOUND:
					error |= ChipGetField(pParams->handle_demod,FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_LOCK_DEFINITIF(Demod), &(fld_value[0]));
					error |= ChipGetField(pParams->handle_demod,FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_PKTDELIN_LOCK(Demod), &(fld_value[1]));
					error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS_TSFIFO_LINEOK(Demod), &(fld_value[2]));
					pTrackingInfo->locked = fld_value[0] && fld_value[1] && fld_value[2];  

					error |= FE_STiD135_CarrierGetQuality(pParams->handle_demod, &FE_STiD135_S2_CN_LookUp,Demod, &(pTrackingInfo->C_N));
					/* Bug fix BZ#107382 */
					if(pTrackingInfo->C_N > SNR_MAX_THRESHOLD * 10) {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DFECFG(Demod), 0x41);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_XFECFG2(Demod), 0x00);
					} else if (pTrackingInfo->C_N < SNR_MIN_THRESHOLD * 10) {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DFECFG(Demod), 0xC1);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_XFECFG2(Demod), 0x03);
					}
					/* Performance improvement at SR <= 3MS/s */
					if(pParams->demod_results[Demod-1].symbol_rate <= 3000000)
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TCTL2(Demod), 0x04);
					else
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TCTL2(Demod), 0x00);
					/*reset The error counter to PER*/
					/* reset the error counter to  DVBS2 packet error rate */ 
					error |= ChipSetOneRegister(pParams->handle_demod,
					(u16)REG_RC8CODEW_DVBSX_HWARE_ERRCTRL1(Demod),0x67);
					/* Adjust carrier loop alpha coefficients vs CNR */
					error |= CarrierLoopAutoAdjust(pParams, Demod, pTrackingInfo->C_N);
					
					error |= FE_STiD135_GetSymbolRate(pParams->handle_demod,pParams->master_clock,Demod, &symbol_rate);
					error |= FE_STiD135_TimingGetOffset(pParams->handle_demod,symbol_rate,Demod, &symbolRateOffset);
					/* Get timing loop offset */
					if(symbolRateOffset < 0) {
						symbolRateOffset *= (-1);
						symbol_rate -= (u32)symbolRateOffset;
					} else {
						symbol_rate += (u32)symbolRateOffset;
					}
					
					/* Management of partial wideband equalizer */
					if(symbol_rate >= 250000000) { /* celerity = 200000km/s, 100m of wire => 500ns in the wire @500MS/s = 2ns/S, 500/2=250 levels */
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_WDFECFG(Demod), 0x42);
					} else if(symbol_rate >= 125000000) {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_WDFECFG(Demod), 0x4A);
					} else if(symbol_rate >=  62500000) {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_WDFECFG(Demod), 0x52);
					} else if(symbol_rate >=  31250000) {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_WDFECFG(Demod), 0x5A);
					} else {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_WDFECFG(Demod), 0x00);
					}
				break;
			
				case FE_SAT_DVBS_FOUND:
					error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_LOCK_DEFINITIF(Demod), &(fld_value[0]));
					error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_VITERBI_VSTATUSVIT_LOCKEDVIT(Demod), &(fld_value[1]));
					error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS_TSFIFO_LINEOK(Demod), &(fld_value[2]));
					
					pTrackingInfo->locked = fld_value[0] && fld_value[1] && fld_value[2];
					error |= FE_STiD135_CarrierGetQuality(pParams->handle_demod, &FE_STiD135_S1_CN_LookUp,Demod, &(pTrackingInfo->C_N)); 
  				break;
			}
			
			error |= FE_STiD135_GetLoFreqHz(pParams, (u32*)&(pTrackingInfo->frequency_if));
			pTrackingInfo->frequency_if *= 1000;
			error |= FE_STiD135_GetCarrierFrequency(pParams->handle_demod, pParams->master_clock,Demod, &(fld_value[0]));
			if(fld_value[0] < 0) {
				pTrackingInfo->frequency_if -= (-fld_value[0] / 1000);
			} else {
				pTrackingInfo->frequency_if += (fld_value[0] / 1000);
			}
			
			error = error | fe_stid135_get_mode_code(pParams,
					Demod,
					&pTrackingInfo->modcode, 
					&pTrackingInfo->frame_length, 
					&pTrackingInfo->pilots);

			if (pParams->handle_demod->Error) 
				error=FE_LLA_I2C_ERROR; 
		}
		
	}
	else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_init
--ACTION	::	Initialisation of the Demod chip
--PARAMS IN	::	pInit -> Front End Init parameters 
--PARAMS OUT	::	handle -> Handle to circuit
--RETURN	::	error
--***************************************************/
fe_lla_error_t fe_stid135_init (struct fe_sat_init_params *pInit, 
				fe_stid135_handle_t *handle)
{
	struct fe_stid135_internal_param *pParams = NULL;
	char chr_tmp[50] = "";
	u8 i, j;

	/* Demodulator chip initialisation parameters */
	Demod_InitParams_t DemodInitParams;
	
	/* SOC chip initialisation parameters */
	Demod_InitParams_t SocInitParams;
	
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	fe_lla_error_t flex_clk_gen_error = FE_LLA_NO_ERROR;
	
	STCHIP_Error_t demod_init_error = CHIPERR_NO_ERROR;
	STCHIP_Error_t SocError = CHIPERR_NO_ERROR;
	TUNER_Error_t TunerError = TUNER_NO_ERR;
	STCHIP_Info_t SocChip;
	
	/* Internal params structure allocation */
	#ifdef HOST_PC
		STCHIP_Info_t DemodChip;
		pParams = kvzalloc(sizeof(struct fe_stid135_internal_param), GFP_KERNEL);
		(*handle) = (fe_stid135_handle_t) pParams;
	#endif

	if (pParams != NULL) {
		/* Chip initialisation */
		
		/* Demodulator Init */
		#ifdef CHIP_STAPI
			DemodInitParams.Chip = (pParams->handle_demod); 
		#else
			DemodInitParams.Chip = &DemodChip;
		#endif
		
		DemodInitParams.Chip->pI2CHost = pInit->pI2CHost;
		DemodInitParams.NbDefVal = STiD135_NBREGS;
		DemodInitParams.Chip->RepeaterHost = NULL;
		DemodInitParams.Chip->RepeaterFn = NULL;
		DemodInitParams.Chip->Repeater = FALSE;
		DemodInitParams.Chip->I2cAddr = pInit->demod_i2c_adr;
		DemodInitParams.Chip->Error = CHIPERR_NO_ERROR;
		strcpy((char *)DemodInitParams.Chip->Name, 
			pInit->demod_name);

		demod_init_error = STiD135_Init(&DemodInitParams, 
					&(pParams->handle_demod));
		/* Frequency clock XTAL */
		pParams->quartz = pInit->demod_ref_clk;
		/* Board depending datas */
		pParams->internal_dcdc = pInit->internal_dcdc;
		pParams->internal_ldo = pInit->internal_ldo;
		pParams->rf_input_type = pInit->rf_input_type;

		/* Init for PID filtering feature */
		for(i=0;i<8;i++)
			pParams->pid_flt[i].first_disable_all_command = TRUE;
		/* Init for GSE filtering feature */
		for(i=0;i<8;i++) {
			pParams->gse_flt[i].first_disable_all_protocol_command = TRUE;
			pParams->gse_flt[i].first_disable_all_label_command = TRUE;
		}
		/* Init for MODCOD filtering feature */
		fe_stid135_modcod_flt_reg_init();
		for(i=0;i<NB_SAT_MODCOD;i++) {
			for(j=FE_SAT_DEMOD_1;j<=FE_SAT_DEMOD_8;j++) {
				pParams->mc_flt[i].forbidden[j-1] = FALSE;
			}
		}
		error |= fe_stid135_apply_custom_qef_for_modcod_filter(&(pParams->handle_demod), NULL);

		TunerError = FE_STiD135_TunerInit(pParams);

		SocInitParams.Chip = &SocChip;
		SocInitParams.Chip->pI2CHost = pInit->pI2CHost;
		SocInitParams.Chip->RepeaterHost = NULL;
		SocInitParams.Chip->RepeaterFn   = NULL;
		SocInitParams.Chip->Repeater     = FALSE;
		SocInitParams.Chip->I2cAddr      = pInit->demod_i2c_adr;
		strcat(chr_tmp, pInit->demod_name);
		strcat(chr_tmp, "_SOC");
		strcpy((char *)SocInitParams.Chip->Name, chr_tmp);
		SocError = STiD135_SOC_Init(&SocInitParams, &(pParams->handle_soc));
		
		/* Adjust Vcore voltage regarding process (AVS) */
		error |= fe_stid135_set_vcore_supply(pParams);
		
		/* Initialization of Flex Clock Gen SOC block */
		flex_clk_gen_error = fe_stid135_flexclkgen_init(pParams);

		if(pParams->handle_demod != NULL) {
			if((demod_init_error == CHIPERR_NO_ERROR) && (TunerError == TUNER_NO_ERR) && (SocError == CHIPERR_NO_ERROR) && (flex_clk_gen_error == FE_LLA_NO_ERROR))
			{
				for(i=FE_SAT_DEMOD_1;i<FE_SAT_DEMOD_8;i++)
					pParams->roll_off[i-1] = pInit->roll_off;

				/*Read the current Mclk*/
				error |= FE_STiD135_GetMclkFreq(pParams, &(pParams->master_clock));
				if(pParams->master_clock == 0)
					return FE_LLA_INVALID_HANDLE;

				/* BB filter calibration on all RF channels */
				for(i=AFE_TUNER1;i<=AFE_TUNER4;i++) {
					error |= fe_stid135_set_rfmux_path(pParams->handle_demod, FE_SAT_DEMOD_1, (FE_OXFORD_TunerPath_t)i);
					error |= fe_stid135_init_before_bb_flt_calib(pParams, (FE_OXFORD_TunerPath_t)i, TRUE);
					error |= fe_stid135_bb_flt_calib(pParams, (FE_OXFORD_TunerPath_t)i);
					error |= fe_stid135_uninit_after_bb_flt_calib(pParams, (FE_OXFORD_TunerPath_t)i);
					error |= Oxford_TunerDisable(pParams->handle_demod, (FE_OXFORD_TunerPath_t)i);
				}
				error |= fe_stid135_set_rfmux_path(pParams->handle_demod, FE_SAT_DEMOD_1, AFE_TUNER1);

				/* Check the error at the end of the init */
				if ((pParams->handle_demod->Error) || (pParams->handle_soc->Error))
					error = FE_LLA_I2C_ERROR;

			} else
				error = FE_LLA_I2C_ERROR;
		} else {
			error = FE_LLA_INVALID_HANDLE;
		}
	}
	
	return error;
}


/*****************************************************
--FUNCTION	::	fe_stid135_manage_LNF_IP3
--ACTION	::	Select LNF or IP3 mode
--PARAMS IN	::	demod_handle -> Frontend handle
			tuner_nb -> tuner path to configure
                	agc1Power -> Power at AGC1
--PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
static fe_lla_error_t fe_stid135_manage_LNF_IP3 (stchip_handle_t demod_handle, FE_OXFORD_TunerPath_t tuner_nb, u32 agc1Power)
{
	STCHIP_Error_t error = CHIPERR_NO_ERROR;
        u8 modeLNF=0;
                
	modeLNF = Oxford_GetVGLNAgainMode(demod_handle, tuner_nb);
    
 	if (modeLNF) {
		if (agc1Power > LNF_IP3_SWITCH_HIGH) {
			error |= Oxford_SetVGLNAgainMode(demod_handle, tuner_nb, MODE_IP3);
                }
        } else 	if (agc1Power < LNF_IP3_SWITCH_LOW) {
                error |= Oxford_SetVGLNAgainMode(demod_handle, tuner_nb, MODE_LNF);
	}
        return (fe_lla_error_t)error;
}


/*****************************************************
--FUNCTION	::	FE_STiD135_Algo
--ACTION	::	Start a search for a valid DVBS1/DVBS2 or DSS 
			transponder
--PARAMS IN	::	pParams -> Pointer to fe_stid135_internal_param structure
			Demod -> current demod 1 .. 8
			satellitte_scan -> scan scope
--PARAMS OUT	::	signalType_p -> result of algo computation
--RETURN	::	error
--***************************************************/
fe_lla_error_t FE_STiD135_Algo(struct fe_stid135_internal_param *pParams,
		enum fe_stid135_demod Demod, BOOL satellitte_scan, enum fe_sat_signal_type *signalType_p)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u32 demodTimeout = 4500;
	u32 fecTimeout = 450;
	s32	iqPower,
		agc1Power,
		i,
		fld_value;
	#ifndef HOST_PC
		s32 powerThreshold = DEMOD_IQPOWER_THRESHOLD;
	#endif
	u32 streamMergerField;
	u16 pdel_status_timeout = 0;
	s32 AgcrfPath;
	
	BOOL lock = FALSE;
	
	s32 lockstatus;
	
	*signalType_p = FE_SAT_NOCARRIER;

	/*release reset DVBS2 packet delin*/
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(Demod), 0);
	streamMergerField = FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_RST_HWARE(Demod);

	/* Stop the stream merger before stopping the demod */
	/* stream merger Stop*/
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(Demod), 0x5C);
	
	/*Get the demod and FEC timeout recommended value depending on the 
	symbol rate and the search algo*/
	FE_STiD135_GetLockTimeout(&demodTimeout, &fecTimeout, 
		pParams->demod_symbol_rate[Demod-1], pParams->demod_search_algo[Demod-1]);
#ifdef USER2
	demodTimeout = demodTimeout * 16; // Low CNR
#else
	demodTimeout = demodTimeout * 4;
#endif
	fecTimeout   = fecTimeout   * 4;
	
	error |= fe_stid135_set_symbol_rate(pParams->handle_demod,
		pParams->master_clock, pParams->demod_symbol_rate[Demod-1], Demod);
	
	error |= fe_stid135_set_carrier_frequency_init(pParams,
			pParams->tuner_frequency[Demod-1], Demod);

	/* NO signal Detection */
	/* Read PowerI and PowerQ To check the signal Presence */
	
	error |= fe_stid135_get_agcrf_path(pParams->handle_demod, Demod, &AgcrfPath);

	ChipWaitOrAbort(pParams->handle_demod, 10);
	
	error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFIN1(AgcrfPath), 2);
	
	agc1Power=MAKEWORD16(ChipGetFieldImage(pParams->handle_demod, 
		FLD_FC8CODEW_DVBSX_AGCRF_AGCRFIN1_AGCRF_VALUE(AgcrfPath)),
		ChipGetFieldImage(pParams->handle_demod, 
		FLD_FC8CODEW_DVBSX_AGCRF_AGCRFIN0_AGCRF_VALUE(AgcrfPath)));
		
	error |= fe_stid135_manage_LNF_IP3(pParams->handle_demod, AgcrfPath, (u32)agc1Power);
	
	iqPower = 0;
			
	if (agc1Power == 0) {
		/* if AGC1 integrator value is 0 then read POWERI, 
		POWERQ registers */
		/* Read the IQ power value */
		for (i = 0; i < 5; i++) {
			error |= ChipGetRegisters(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRF_POWERI(AgcrfPath), 2);
			iqPower = iqPower + (ChipGetFieldImage(
			pParams->handle_demod, FLD_FC8CODEW_DVBSX_AGCRF_AGCRF_POWERI_AGCRF_POWER_I(AgcrfPath)) 
					+  ChipGetFieldImage(
			pParams->handle_demod, FLD_FC8CODEW_DVBSX_AGCRF_AGCRF_POWERQ_AGCRF_POWER_Q(AgcrfPath))) / 2;
		}
		iqPower /= 5;
	}
			

	#ifndef HOST_PC
		// In lab conditions (1 channel), for sensitivity autotest, we have to avoid
		// this condition otherwise we are not able to lock on low RF levels
		// We keep this if statement on embedded side
		if ((agc1Power == 0) && (iqPower < powerThreshold)) {
			/*If (AGC1=0 and iqPower<IQThreshold)  then no signal  */
			pParams->demod_results[Demod-1].locked = FALSE; /*if AGC1 integrator ==0 
			and iqPower < Threshold then NO signal*/
			/* Jump of distance of the bandwith tuner */
			*signalType_p = FE_SAT_TUNER_NOSIGNAL ;
		} else
	#endif
	if ((pParams->demod_search_algo[Demod-1] == FE_SAT_BLIND_SEARCH)
			 && (satellitte_scan == TRUE)) {
		iqPower = 0;
		agc1Power = 0;
		pParams->demod_results[Demod-1].locked = FALSE; /*if AGC1 integrator ==0
		and iqPower < Threshold then NO signal*/
		/* No edge detected, jump tuner bandwidth */
		*signalType_p = FE_SAT_TUNER_NOSIGNAL;

	} else { /* falling edge detected or direct blind to be done */
		/* Set the IQ inversion search mode */

		error |= ChipSetFieldImage(pParams->handle_demod,  
		FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_SPECINV_CONTROL(Demod),
		FE_SAT_IQ_AUTO);   /* Set IQ inversion always in auto */
		error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DEMOD(Demod), 1);
		error |= FE_STiD135_SetSearchStandard(pParams, Demod);
	
		if (pParams->demod_search_algo[Demod-1] != FE_SAT_BLIND_SEARCH)
			error |= FE_STiD135_StartSearch(pParams,Demod);
	
		if (pParams->demod_search_algo[Demod-1] == FE_SAT_BLIND_SEARCH) {
			error |= FE_STiD135_BlindSearchAlgo(pParams, demodTimeout,
															satellitte_scan, Demod, &lock);
		} else {
			/* case warm or cold start wait for demod lock */
				error |= FE_STiD135_GetDemodLock(pParams,Demod,
				demodTimeout, &lock);
		}

		if (lock == TRUE) {
			/* Read signal caracteristics and check the lock 
			range */
			error |= FE_STiD135_GetSignalParams(pParams, Demod,
			satellitte_scan, signalType_p);
			/* Manage Matype Information if DVBS2 signal */
			if (pParams->demod_results[Demod-1].standard == FE_SAT_DVBS2_STANDARD) {
				/* Before reading MATYPE value, we need to wait for packet delin locked */
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_FIRST_LOCK(Demod), &fld_value);
				while ((fld_value != TRUE) && (pdel_status_timeout < 220)) {
					ChipWaitOrAbort(pParams->handle_demod, 5);
					pdel_status_timeout = (u8)(pdel_status_timeout + 5);
					error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_FIRST_LOCK(Demod), &fld_value);
				}
				if (pdel_status_timeout < 220) {
					// Either we deal with common data: TS-MPEG, GSE, and so on...
					#if 1
						error |= fe_stid135_manage_matype_info(pParams, Demod);
					// ...or we deal with raw BB frames
					#else
						error |= fe_stid135_manage_matype_info_raw_bbframe(pParams, Demod);
					#endif
				} else
					return(FE_LLA_SEARCH_FAILED);
			}
		}
	}
	
	
	if ((lock == TRUE) && (*signalType_p==FE_SAT_RANGEOK)) {
		/*The tracking optimization and the FEC lock check are 
		perfomed only if:
			demod is locked and signal type is RANGEOK i.e 
			a TP found  within the given search range 
		*/

		// - new management of NCR
		/* Release stream merger reset */
		error |= ChipSetField(pParams->handle_demod, streamMergerField, 0);
		ChipWaitOrAbort(pParams->handle_demod, 3);
		/* Stream merger reset */
		error |= ChipSetField(pParams->handle_demod, streamMergerField, 1);
		/* Release stream merger reset */
		error |= ChipSetField(pParams->handle_demod, streamMergerField, 0);
		// - end of new management of NCR
		
		error |= FE_STiD135_WaitForLock(pParams, Demod,demodTimeout, fecTimeout, satellitte_scan, &lockstatus);
		if (lockstatus == TRUE) {
			lock = TRUE;

			pParams->demod_results[Demod-1].locked = TRUE;
			
			if (pParams->demod_results[Demod-1].standard ==
			FE_SAT_DVBS2_STANDARD) {
				/*reset DVBS2 packet delinator error 
				counter */
				error |= ChipSetFieldImage(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_RESET_UPKO_COUNT(Demod), 1);
				error |= ChipSetRegisters(pParams->handle_demod,
				(u16)REG_RC8CODEW_DVBSX_PKTDELIN_PDELCTRL2(Demod), 1);
						
				/*reset DVBS2 packet delinator error 
				counter */
				error |= ChipSetFieldImage(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_RESET_UPKO_COUNT(Demod), 0);
				error |= ChipSetRegisters(pParams->handle_demod,
					(u16)REG_RC8CODEW_DVBSX_PKTDELIN_PDELCTRL2(Demod), 1);
			
				/* reset the error counter to  DVBS2
				packet error rate */
				error |= ChipSetOneRegister(pParams->handle_demod,
					(u16)REG_RC8CODEW_DVBSX_HWARE_ERRCTRL1(Demod), 0x67);
			} else {
				/* reset the viterbi bit error rate */
				error |= ChipSetOneRegister(pParams->handle_demod,
				(u16)REG_RC8CODEW_DVBSX_HWARE_ERRCTRL1(Demod), 0x75);
			}
			/*Reset the Total packet counter */
			error |= ChipSetOneRegister(pParams->handle_demod, 
			(u16)REG_RC8CODEW_DVBSX_FECSPY_FBERCPT4(Demod), 0);
			/*Reset the packet Error counter2 (and Set it to
			infinit error count mode )*/
			error |= ChipSetOneRegister(pParams->handle_demod,
			(u16)REG_RC8CODEW_DVBSX_HWARE_ERRCTRL2(Demod), 0xc1);
			
			if(pParams->demod_symbol_rate[Demod-1] >= pParams->master_clock) {
				// Need to perform a switch of latency regulation OFF/ON to make work WB NCR tests (low datarate)
				WAIT_N_MS(200);
				error |= ChipGetField(pParams->handle_demod,
					FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS3_PCRCALC_NCRREADY(Demod), &fld_value);
				if(fld_value != 0) {
					WAIT_N_MS(100);
					error |= ChipGetField(pParams->handle_demod,
						FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS3_PCRCALC_ERROR(Demod), &fld_value);
					if(fld_value == 1) {
						error |= ChipSetField(pParams->handle_demod,
						FLD_FC8CODEW_DVBSX_HWARE_TSSTATE1_TSOUT_NOSYNC(Demod), 1);
						WAIT_N_MS(10);
						error |= ChipSetField(pParams->handle_demod,
						FLD_FC8CODEW_DVBSX_HWARE_TSSTATE1_TSOUT_NOSYNC(Demod), 0);
					}
				}
			}
		} else {	
			lock = FALSE;
			/*if the demod is locked and not the FEC signal 
			type is no DATA*/
			*signalType_p = FE_SAT_NODATA;
			pParams->demod_results[Demod-1].locked = FALSE;
		}

	}
	
	return error;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_SetSearchStandard
--ACTION	::	Set the Search standard (Auto, DVBS2 only or 
			DVBS1/DSS only)
--PARAMS IN	::	pParams -> Pointer to fe_stid135_internal_param structure
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	error
--***************************************************/
fe_lla_error_t FE_STiD135_SetSearchStandard(struct fe_stid135_internal_param *pParams,
					enum fe_stid135_demod Demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR; 

	switch (pParams->demod_search_standard[Demod-1]) {
	case FE_SAT_SEARCH_DVBS1:
		error |= ChipSetFieldImage(pParams->handle_demod,
		FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS1_ENABLE(Demod), 1);
		error |= ChipSetFieldImage(pParams->handle_demod,
		FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS2_ENABLE(Demod), 0);
		error |= ChipSetRegisters(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(Demod), 1);

		error |= FE_STiD135_SetViterbiStandard(pParams->handle_demod, 
			pParams->demod_search_standard[Demod-1], 
			pParams->demod_puncture_rate[Demod-1], Demod); 
				
		error |= ChipSetOneRegister(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_HWARE_SFDLYSET2(Demod), 0); /* Enable Super FEC */	

	break;

	case FE_SAT_SEARCH_DSS: 
		/*If DVBS1/DSS only disable DVBS2 search*/
		error |= ChipSetFieldImage(pParams->handle_demod,
		FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS1_ENABLE(Demod), 1);
		error |= ChipSetFieldImage(pParams->handle_demod,
		FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS2_ENABLE(Demod), 0);
		error |= ChipSetRegisters(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(Demod), 1);

		error |= FE_STiD135_SetViterbiStandard(pParams->handle_demod,
				pParams->demod_search_standard[Demod-1],
				pParams->demod_puncture_rate[Demod-1], Demod);
				
		/* Stop Super FEC */
		 error |= ChipSetOneRegister(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_HWARE_SFDLYSET2(Demod), 2);

	break;

	case FE_SAT_SEARCH_DVBS2:
		/*If DVBS2 only activate the DVBS2 search and stop
		the VITERBI*/
		error |= ChipSetFieldImage(pParams->handle_demod,
		FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS1_ENABLE(Demod), 0);
		error |= ChipSetFieldImage(pParams->handle_demod,
		FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS2_ENABLE(Demod), 1);
		error |= ChipSetRegisters(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(Demod), 1);
	break;

	case FE_SAT_AUTO_SEARCH:
		/*If automatic enable both DVBS1/DSS and DVBS2 search*/
		error |= ChipSetFieldImage(pParams->handle_demod,
		FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS1_ENABLE(Demod), 1);
		error |= ChipSetFieldImage(pParams->handle_demod,
		FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS2_ENABLE(Demod), 1);
		error |= ChipSetRegisters(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(Demod), 1);
		
		error |= FE_STiD135_SetViterbiStandard(pParams->handle_demod,
				pParams->demod_search_standard[Demod-1],
				pParams->demod_puncture_rate[Demod-1],Demod);

		/* Enable Super FEC */
		error |= ChipSetOneRegister(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_HWARE_SFDLYSET2(Demod), 0);
	break;
	
	case FE_SAT_SEARCH_TURBOCODE:
	break;
	}
	return error;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_StartSearch
--ACTION	::	Programs the PEA to lauch a hardware search algo.
--PARAMS IN	::	pParams -> Pointer to fe_stid135_internal_param structure
			Demod -> demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	error
--***************************************************/
static fe_lla_error_t FE_STiD135_StartSearch(struct fe_stid135_internal_param *pParams,
					enum fe_stid135_demod Demod) 
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;

	/* Reset the Demod */
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(Demod), 0x1F);

	switch (pParams->demod_search_algo[Demod-1]) {
	case FE_SAT_WARM_START:
		/*The symbol rate and the exact
		carrier frequency are known */
		/*Trig an acquisition (start the search)*/
		error |= ChipSetOneRegister(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(Demod), 0x18);
	break;

	case FE_SAT_COLD_START:
		/*The symbol rate is known*/
		/*Trig an acquisition (start the search)*/
		error |= ChipSetOneRegister(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(Demod), 0x15);
	break;

	case FE_SAT_BLIND_SEARCH:
		/*Trig an acquisition (start the search)*/
		error |= ChipSetOneRegister(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(Demod), 0x00);

	break;
	}
	return error;
}


/*****************************************************
--FUNCTION	::	FE_STiD135_BlindSearchAlgo
--ACTION	::	programs the PEA to lauch a hardware search algo.
--PARAMS IN	::	pParams -> Pointer to fe_stid135_internal_param structure
			Demod -> demod 1 .. 8
			demodTimeout -> timeout of the demod part
			satellitte_scan -> scan or acquisition context
--PARAMS OUT	::	lock_p -> demod lock status
--RETURN	::	error
--***************************************************/
static fe_lla_error_t FE_STiD135_BlindSearchAlgo(struct fe_stid135_internal_param *pParams,
	u32 demodTimeout, BOOL satellitte_scan, enum fe_stid135_demod Demod, BOOL* lock_p)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	*lock_p = TRUE;

	if (satellitte_scan == FALSE) {
 	} else {
	 	pParams->demod_search_range[Demod-1] = (u32)(24000000 + 
			pParams->tuner_index_jump[Demod-1] * 1000);
		if (pParams->demod_search_range[Demod-1] > 40000000) {
			pParams->demod_search_range[Demod-1] = 40000000;
		}
	}
	error |= ChipSetOneRegister(pParams->handle_demod,
	(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(Demod), 0x5C); /* Demod Stop*/
	error |= fe_stid135_set_symbol_rate(pParams->handle_demod,pParams->master_clock,
		pParams->demod_symbol_rate[Demod-1], Demod);
	
	error |= FE_STiD135_StartSearch(pParams, Demod);
	
	error |= FE_STiD135_GetDemodLock(pParams, Demod, demodTimeout, lock_p);
	return error; 
}


/*****************************************************
--FUNCTION	::	GetSignalParams
--ACTION	::	Read signal caracteristics
--PARAMS IN	::	pParams -> Pointer to fe_stid135_internal_param structure
			Demod -> current demod 1 .. 8
			satellitte_scan -> scan scope
--PARAMS OUT	::	range_p -> RANGE Ok or not
--RETURN	::	error
--***************************************************/
static  fe_lla_error_t FE_STiD135_GetSignalParams(
	struct fe_stid135_internal_param *pParams, enum fe_stid135_demod Demod, 
	BOOL satellitte_scan, enum fe_sat_signal_type *range_p) 

{
	
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	u32 reg_value = 0;
	s32 fld_value;
	s32 offsetFreq = 0,
		i = 0,
		symbolRateOffset = 0;
	u32 lo_frequency;
	
	u8 timing;
	
	*range_p=FE_SAT_OUTOFRANGE; 
	
	ChipWaitOrAbort(pParams->handle_demod, 5);

	if(pParams->demod_search_algo[Demod-1] == FE_SAT_BLIND_SEARCH) {
		/*	if Blind search wait for symbol rate offset information
			transfer from the timing loop to the
			demodulator symbol rate
		*/
		error |= ChipGetOneRegister(pParams->handle_demod,
		(u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG2(Demod), &reg_value); 
		timing =  (u8)reg_value;
		i = 0;
		while ((i <= 50) && (timing != 0) && (timing != 0xFF)) {
			error |= ChipGetOneRegister(pParams->handle_demod,
				(u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG2(Demod), &reg_value);
			timing =  (u8)reg_value;
			ChipWaitOrAbort(pParams->handle_demod, 5);
			i += 5;
		}
	}
	error |= FE_STiD135_GetStandard(pParams->handle_demod, Demod, &(pParams->demod_results[Demod-1].standard));

	/* On auxiliary demod, frequency found is not true, we have to pick it on master demod  */
	if(Demod == FE_SAT_DEMOD_2) {
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_MODE_HAUTDEBIT(Demod), &fld_value);
		if(fld_value == 3) {
			error |= FE_STiD135_GetCarrierFrequency(pParams->handle_demod,pParams->master_clock, FE_SAT_DEMOD_1, &offsetFreq);
			error |= FE_STiD135_GetSymbolRate(pParams->handle_demod, pParams->master_clock,FE_SAT_DEMOD_1, &(pParams->demod_results[Demod-1].symbol_rate));
			error |= FE_STiD135_TimingGetOffset(pParams->handle_demod,pParams->demod_results[Demod-1].symbol_rate, FE_SAT_DEMOD_1, &symbolRateOffset);
		}
	}
	if(Demod == FE_SAT_DEMOD_4) {
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_MODE_HAUTDEBIT(Demod), &fld_value);
		if(fld_value == 3) {
			error |= FE_STiD135_GetCarrierFrequency(pParams->handle_demod,pParams->master_clock, FE_SAT_DEMOD_3, &offsetFreq);
			error |= FE_STiD135_GetSymbolRate(pParams->handle_demod, pParams->master_clock,FE_SAT_DEMOD_3, &(pParams->demod_results[Demod-1].symbol_rate));
			error |= FE_STiD135_TimingGetOffset(pParams->handle_demod,pParams->demod_results[Demod-1].symbol_rate, FE_SAT_DEMOD_3, &symbolRateOffset);
		}
	}
	if(((Demod != FE_SAT_DEMOD_2) && (Demod != FE_SAT_DEMOD_4)) ||
		((Demod == FE_SAT_DEMOD_2) && (fld_value != 3)) ||
		((Demod == FE_SAT_DEMOD_4) && (fld_value != 3))) {
		error |= FE_STiD135_GetCarrierFrequency(pParams->handle_demod,pParams->master_clock, Demod, &offsetFreq);
		error |= FE_STiD135_GetSymbolRate(pParams->handle_demod,pParams->master_clock,Demod, &(pParams->demod_results[Demod-1].symbol_rate));
		error |= FE_STiD135_TimingGetOffset(pParams->handle_demod,pParams->demod_results[Demod-1].symbol_rate,Demod, &symbolRateOffset);
	}
	/* Get timing loop offset */
	if(symbolRateOffset < 0) {
		symbolRateOffset *= (-1);
		pParams->demod_results[Demod-1].symbol_rate -= (u32)symbolRateOffset;
	} else
		pParams->demod_results[Demod-1].symbol_rate += (u32)symbolRateOffset;
	
	lo_frequency = pParams->lo_frequency / 1000;
	pParams->demod_results[Demod-1].frequency = lo_frequency;
	if(offsetFreq < 0) {
		offsetFreq *= (-1);
		pParams->demod_results[Demod-1].frequency -= (u32)offsetFreq/1000;
	} else
		pParams->demod_results[Demod-1].frequency += (u32)offsetFreq/1000;

	error |= 
		FE_STiD135_GetViterbiPunctureRate(pParams->handle_demod, Demod, &(pParams->demod_results[Demod-1].puncture_rate));
	
	error = error | fe_stid135_get_mode_code(pParams,
				Demod,
				&pParams->demod_results[Demod-1].modcode, 
				&pParams->demod_results[Demod-1].frame_length, 
				&pParams->demod_results[Demod-1].pilots);
	
	error |= ChipGetField(pParams->handle_demod, 
		FLD_FC8CODEW_DVBSX_DEMOD_TMGOBS_ROLLOFF_STATUS(Demod), &fld_value);
	pParams->demod_results[Demod-1].roll_off = (enum fe_sat_rolloff)fld_value;
			
	switch (pParams->demod_results[Demod-1].standard) {
	case FE_SAT_DVBS2_STANDARD:
		error |= ChipGetField(
		pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS6_SPECINV_DEMOD(Demod), &fld_value);
		pParams->demod_results[Demod-1].spectrum = (enum fe_sat_iq_inversion)fld_value;
					
		if (((pParams->demod_results[Demod-1].modcode >= FE_SAT_QPSK_14) && (pParams->demod_results[Demod-1].modcode <= FE_SAT_QPSK_910))
			|| ((pParams->demod_results[Demod-1].modcode >= FE_SAT_DVBS1_QPSK_12) && (pParams->demod_results[Demod-1].modcode <= FE_SAT_DVBS1_QPSK_78))
			|| ((pParams->demod_results[Demod-1].modcode >= FE_SATX_QPSK_13_45) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_QPSK_11_20))
			|| ((pParams->demod_results[Demod-1].modcode >= FE_SATX_QPSK_11_45) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_QPSK_32_45)))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_QPSK;
				
		else if (((pParams->demod_results[Demod-1].modcode >= FE_SAT_8PSK_35) && (pParams->demod_results[Demod-1].modcode <= FE_SAT_8PSK_910))
			|| ((pParams->demod_results[Demod-1].modcode >= FE_SATX_8PSK_23_36) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_8PSK_13_18))
			|| ((pParams->demod_results[Demod-1].modcode >= FE_SATX_8PSK_7_15) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_8PSK_32_45))
			|| (pParams->demod_results[Demod-1].modcode == FE_SATX_8PSK))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_8PSK;
		
		else if (((pParams->demod_results[Demod-1].modcode >= FE_SAT_16APSK_23) && (pParams->demod_results[Demod-1].modcode <= FE_SAT_16APSK_910))
			|| ((pParams->demod_results[Demod-1].modcode >= FE_SATX_16APSK_26_45) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_16APSK_23_36))
			|| ((pParams->demod_results[Demod-1].modcode >= FE_SATX_16APSK_25_36) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_16APSK_77_90))
			|| ((pParams->demod_results[Demod-1].modcode >= FE_SATX_16APSK_7_15) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_16APSK_32_45))
			|| (pParams->demod_results[Demod-1].modcode == FE_SATX_16APSK))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_16APSK;
		
		else if (((pParams->demod_results[Demod-1].modcode >= FE_SAT_32APSK_34) && (pParams->demod_results[Demod-1].modcode <= FE_SAT_32APSK_910))
			|| ((pParams->demod_results[Demod-1].modcode >= FE_SATX_32APSK_R_58) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_32APSK_7_9))
			|| ((pParams->demod_results[Demod-1].modcode >= FE_SATX_32APSK_2_3) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_32APSK_32_45_S))
			|| (pParams->demod_results[Demod-1].modcode == FE_SATX_32APSK))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_32APSK;
		
		else if ((pParams->demod_results[Demod-1].modcode == FE_SATX_VLSNR1) || (pParams->demod_results[Demod-1].modcode == FE_SATX_VLSNR2))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_VLSNR;
		
		else if (((pParams->demod_results[Demod-1].modcode >= FE_SATX_64APSK_11_15) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_64APSK_5_6))
			|| (pParams->demod_results[Demod-1].modcode == FE_SATX_64APSK))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_64APSK;
			
		else if ((pParams->demod_results[Demod-1].modcode == FE_SATX_128APSK_3_4) || (pParams->demod_results[Demod-1].modcode == FE_SATX_128APSK_7_9))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_128APSK;
			
		else if ((pParams->demod_results[Demod-1].modcode == FE_SATX_256APSK_32_45) || (pParams->demod_results[Demod-1].modcode == FE_SATX_256APSK_3_4)
			|| (pParams->demod_results[Demod-1].modcode == FE_SATX_256APSK))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_256APSK;
			
		else if ((pParams->demod_results[Demod-1].modcode == FE_SATX_8APSK_5_9_L) || (pParams->demod_results[Demod-1].modcode == FE_SATX_8APSK_26_45_L))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_8PSK_L;
		
		else if (((pParams->demod_results[Demod-1].modcode >= FE_SATX_16APSK_1_2_L) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_16APSK_5_9_L))
			|| (pParams->demod_results[Demod-1].modcode == FE_SATX_16APSK_3_5_L)
			|| (pParams->demod_results[Demod-1].modcode == FE_SATX_16APSK_2_3_L))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_16APSK_L;
		
		else if (pParams->demod_results[Demod-1].modcode == FE_SATX_32APSK_2_3_L)
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_32APSK_L;
		
		else if (pParams->demod_results[Demod-1].modcode == FE_SATX_64APSK_32_45_L)
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_64APSK_L;
		
		else if (((pParams->demod_results[Demod-1].modcode >= FE_SATX_256APSK_29_45_L) && (pParams->demod_results[Demod-1].modcode <= FE_SATX_256APSK_31_45_L))
			|| (pParams->demod_results[Demod-1].modcode == FE_SATX_256APSK_11_15_L))
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_256APSK_L;
		
		else if (pParams->demod_results[Demod-1].modcode == FE_SATX_1024APSK)
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_1024APSK;
		
		else
			pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_UNKNOWN;

	break;
				
	case FE_SAT_DVBS1_STANDARD:
	case FE_SAT_DSS_STANDARD:
		error |= ChipGetField(pParams->handle_demod, 
			FLD_FC8CODEW_DVBSX_VITERBI_FECM_IQINV(Demod), &fld_value);
		pParams->demod_results[Demod-1].spectrum = (enum fe_sat_iq_inversion)fld_value;
		pParams->demod_results[Demod-1].modulation = FE_SAT_MOD_QPSK;
	break;
				
	case FE_SAT_TURBOCODE_STANDARD:
	case FE_SAT_UNKNOWN_STANDARD:
	break;
	}
		
	offsetFreq = (s32)pParams->demod_results[Demod-1].frequency * 1000
			- (s32)lo_frequency * 1000 - pParams->tuner_frequency[Demod-1];
	
	if((pParams->demod_search_algo[Demod-1] == FE_SAT_BLIND_SEARCH)
	|| (pParams->demod_symbol_rate[Demod-1] < (u32)10000000)) {
		if ((pParams->demod_search_algo[Demod-1] == FE_SAT_BLIND_SEARCH) 
		&& (satellitte_scan == TRUE)) {	
			*range_p = FE_SAT_RANGEOK; 
		} else if ((u32)(ABS(offsetFreq)) <= ((
			pParams->demod_search_range[Demod-1] / 2)))
			*range_p = FE_SAT_RANGEOK;
		
		else if ((u32)(ABS(offsetFreq)) <= (FE_STiD135_CarrierWidth(
				pParams->demod_results[Demod-1].symbol_rate,
					pParams->demod_results[Demod-1].roll_off) / 2))
			*range_p = FE_SAT_RANGEOK;
		
		else 
			*range_p = FE_SAT_OUTOFRANGE;
	} else {
		if ((u32)(ABS(offsetFreq)) <= ((pParams->demod_search_range[Demod-1] / 2)))
			*range_p = FE_SAT_RANGEOK;
		else 
			*range_p = FE_SAT_OUTOFRANGE;
	}  

	return error;
}


/*****************************************************
--FUNCTION	::	FE_STiD135_TrackingOptimization
--ACTION	::	Set Optimized parameters for tracking
--PARAMS IN	::	pParams -> Pointer to fe_stid135_internal_param structure
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	error
--***************************************************/
static fe_lla_error_t FE_STiD135_TrackingOptimization(
	struct fe_stid135_internal_param *pParams, enum fe_stid135_demod Demod)
{
	u32 symbolRate;
	s32 pilots, timing_offset;
	u8 aclc;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	
	enum fe_sat_modcode foundModcod;
	
	
	/* Read the Symbol rate */
	error |= FE_STiD135_GetSymbolRate(pParams->handle_demod,pParams->master_clock, Demod, &symbolRate);
	error |= FE_STiD135_TimingGetOffset(pParams->handle_demod,symbolRate, Demod, &timing_offset);
	if(timing_offset < 0) {
		timing_offset *= (-1);
		symbolRate -= (u32)timing_offset;
	} else
		symbolRate += (u32)timing_offset;
			
	switch (pParams->demod_results[Demod-1].standard) {
	case FE_SAT_DVBS1_STANDARD:
		if (pParams->demod_search_standard == FE_SAT_AUTO_SEARCH) {
			error |= ChipSetFieldImage(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS1_ENABLE(Demod), 1);
			error |= ChipSetFieldImage(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS2_ENABLE(Demod), 0);
			error |= ChipSetRegisters(pParams->handle_demod, 
			(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(Demod), 1);
		}
		/*Set the rolloff to the manual value (given at the 
		initialization)*/
		error |= ChipSetFieldImage(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(Demod), pParams->roll_off[Demod-1]);
		error |= ChipSetFieldImage(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_MANUALSX_ROLLOFF(Demod), 1);
		error |= ChipSetRegisters(pParams->handle_demod,
			(u16)REG_RC8CODEW_DVBSX_DEMOD_DEMOD(Demod), 1);
				
		/* force to viterbi bit error */
		error |= ChipSetOneRegister(pParams->handle_demod,
			(u16)REG_RC8CODEW_DVBSX_HWARE_ERRCTRL1(Demod), 0x75);
	break;
			
	case FE_SAT_DSS_STANDARD:
		if( pParams->demod_search_standard == FE_SAT_AUTO_SEARCH) {
			error |= ChipSetFieldImage(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS1_ENABLE(Demod), 1);
			error |= ChipSetFieldImage(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS2_ENABLE(Demod), 0);
			error |= ChipSetRegisters(pParams->handle_demod,
				(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(Demod), 1);
		}
		/*Set the rolloff to the manual value
		(given at the initialization)*/
		error |= ChipSetFieldImage(pParams->handle_demod, 
			FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(Demod),pParams->roll_off[Demod-1]);
		error |= ChipSetFieldImage(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_MANUALSX_ROLLOFF(Demod), 1);
		error |= ChipSetRegisters(pParams->handle_demod,
			(u16)REG_RC8CODEW_DVBSX_DEMOD_DEMOD(Demod), 1);

		/* force to viterbi bit error */
		error |= ChipSetOneRegister(pParams->handle_demod, 
			(u16)REG_RC8CODEW_DVBSX_HWARE_ERRCTRL1(Demod), 0x75);
	break;

	case FE_SAT_DVBS2_STANDARD:
		error |= ChipSetFieldImage(pParams->handle_demod, 
			FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS1_ENABLE(Demod), 0);
		error |= ChipSetFieldImage(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS2_ENABLE(Demod), 1);
		error |= ChipSetRegisters(pParams->handle_demod,
			(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(Demod), 1);
		
		/* force to DVBS2 PER  */
		error |= ChipSetOneRegister(pParams->handle_demod,
			(u16)REG_RC8CODEW_DVBSX_HWARE_ERRCTRL1(Demod), 0x67);
				
		
		foundModcod = pParams->demod_results[Demod-1].modcode;
		pilots = pParams->demod_results[Demod-1].pilots;
				
		aclc = FE_STiD135_GetOptimCarrierLoop(symbolRate,
				foundModcod, pilots);
			
		if (((foundModcod >= FE_SAT_QPSK_14) && (foundModcod <= FE_SAT_QPSK_910))
			|| ((foundModcod >= FE_SAT_DVBS1_QPSK_12) && (foundModcod <= FE_SAT_DVBS1_QPSK_78))
			|| ((foundModcod >= FE_SATX_QPSK_13_45) && (foundModcod <= FE_SATX_QPSK_11_20))
			|| ((foundModcod >= FE_SATX_QPSK_11_45) && (foundModcod <= FE_SATX_QPSK_32_45))) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), aclc);
		} else if (((foundModcod >= FE_SAT_8PSK_35) && (foundModcod <= FE_SAT_8PSK_910))
			|| ((foundModcod >= FE_SATX_8PSK_23_36) && (foundModcod <= FE_SATX_8PSK_13_18))
			|| ((foundModcod >= FE_SATX_8PSK_7_15) && (foundModcod <= FE_SATX_8PSK_32_45))
			|| (foundModcod == FE_SATX_8PSK)) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S28(Demod), aclc);
		} else if (((foundModcod >= FE_SAT_16APSK_23) && (foundModcod <= FE_SAT_16APSK_910))
			|| ((foundModcod >= FE_SATX_16APSK_26_45) && (foundModcod <= FE_SATX_16APSK_23_36))
			|| ((foundModcod >= FE_SATX_16APSK_25_36) && (foundModcod <= FE_SATX_16APSK_77_90))
			|| ((foundModcod >= FE_SATX_16APSK_7_15) && (foundModcod <= FE_SATX_16APSK_32_45))
			|| (foundModcod == FE_SATX_16APSK)) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S216A(Demod), aclc);
		} else if (((foundModcod >= FE_SAT_32APSK_34) && (foundModcod <= FE_SAT_32APSK_910))
			|| ((foundModcod >= FE_SATX_32APSK_R_58) && (foundModcod <= FE_SATX_32APSK_7_9))
			|| ((foundModcod >= FE_SATX_32APSK_2_3) && (foundModcod <= FE_SATX_32APSK_32_45_S))
			|| (foundModcod == FE_SATX_32APSK)) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S232A(Demod), aclc);
		} else if ((foundModcod == FE_SATX_VLSNR1) || (foundModcod == FE_SATX_VLSNR2)) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			/*error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2(Demod), aclc);*/
		} else if (((foundModcod >= FE_SATX_64APSK_11_15) && (foundModcod <= FE_SATX_64APSK_5_6))
			|| (foundModcod == FE_SATX_64APSK)) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S264A(Demod), aclc);
		} else if ((foundModcod == FE_SATX_128APSK_3_4) || (foundModcod == FE_SATX_128APSK_7_9)) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2128A(Demod), aclc);
		} else if ((foundModcod == FE_SATX_256APSK_32_45) || (foundModcod == FE_SATX_256APSK_3_4)
			|| (foundModcod == FE_SATX_256APSK)) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2256A(Demod), aclc);
		} else if ((foundModcod == FE_SATX_8APSK_5_9_L) || (foundModcod == FE_SATX_8APSK_26_45_L)) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S28(Demod), aclc);
		} else if (((foundModcod >= FE_SATX_16APSK_1_2_L) && (foundModcod <= FE_SATX_16APSK_5_9_L))
			|| (foundModcod == FE_SATX_16APSK_3_5_L)
			|| (foundModcod == FE_SATX_16APSK_2_3_L)) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S216A(Demod), aclc);
		} else if (foundModcod == FE_SATX_32APSK_2_3_L) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S232A(Demod), aclc);
		} else if (foundModcod == FE_SATX_64APSK_32_45_L) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S264A(Demod), aclc);
		} else if (((foundModcod >= FE_SATX_256APSK_29_45_L) && (foundModcod <= FE_SATX_256APSK_31_45_L))
			|| (foundModcod == FE_SATX_256APSK_11_15_L)) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2256A(Demod), aclc);
		} else if (foundModcod == FE_SATX_1024APSK) {
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_ACLC2S2Q(Demod), 0x48);
		}

		//else
	break;

	case FE_SAT_UNKNOWN_STANDARD:
	case FE_SAT_TURBOCODE_STANDARD:
		error |= ChipSetFieldImage(pParams->handle_demod, 
			FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS1_ENABLE(Demod), 1);
		error |= ChipSetFieldImage(pParams->handle_demod,
			FLD_FC8CODEW_DVBSX_DEMOD_DMDCFGMD_DVBS2_ENABLE(Demod), 1);
		error |= ChipSetRegisters (pParams->handle_demod,
			(u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(Demod), 1);
	break;
	}
	return error;
}


/******************************************************************************/   
/* 
		WideBand Section, specific Slice functionality
		This routines assume a valid demod lock on a HBWchannel 
		and parallel symbol capability (WB Demod)
		ADC+AGC setup is not covered here
*/

/*****************************************************
--FUNCTION	::	fe_stid135_get_slice_list
--ACTION	::	Returns list of available slices
			Cardboard ram bug workaround on cut1
--PARAMS IN	::	Handle -> Front End Handle
			Demod -> current demod 1 .. 8
--PARAMS OUT	::	SlcList -> Slice list pointer
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_get_slice_list(fe_stid135_handle_t Handle,
		struct fe_stid135_slice_list *SlcList, enum fe_stid135_demod Demod) 
{
	u8 FEC_Lock_TimeOut = 100;
	u32 reg_value;
	BOOL lock = FALSE ;
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	int Demodflt_Rammode;
	u8 SliceSel, MaxSliceNumber, MinSliceNumber;
	u16 i;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	
	SlcList->max_index = 0;
	
	if(Handle != NULL) {
		/* check if the demod can handle it */
		if(Demod > FE_SAT_DEMOD_4)
			return FE_LLA_INVALID_HANDLE;
		
		/* store temporarily */
		error |= ChipGetField(pParams->handle_demod, 
		FLD_FC8CODEW_DVBSX_DEMOD_SLICECFG_DEMODFLT_RAMMODE(Demod), &Demodflt_Rammode);
		
		/* Switch off rammode */
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICECFG_DEMODFLT_RAMMODE(Demod), 0);
		/* fetch the SliceMax index */
		error |= ChipGetOneRegister(pParams->handle_demod, 
		(u16)REG_RC8CODEW_DVBSX_DEMOD_SLICEMAX(Demod), &reg_value);
		MaxSliceNumber = (u8)reg_value;
		
		/* no slice, no result */
		// Fixed issue, no slice detected on a sliced channel with only 1 slice
		if (MaxSliceNumber < 1) return error;
		
		/* fetch the SliceMin index */
		error |= ChipGetOneRegister(pParams->handle_demod, 
		(u16)REG_RC8CODEW_DVBSX_DEMOD_SLICEMIN(Demod), &reg_value);
		MinSliceNumber = (u8)reg_value; 
		error |= ChipGetOneRegister(pParams->handle_demod, 
		(u16)REG_RC8CODEW_DVBSX_DEMOD_SLICESEL(Demod), &reg_value);
		SliceSel = (u8)reg_value; 
		//rather use Getregisters,2 !
				
		for (i = MinSliceNumber; i <= MaxSliceNumber; i++) {
			/* tbd, try fetching it from SLC itself, also the anchor
			frame settings */
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_SLICESEL(Demod), i);
			
			// Delineator reset, to be sure
			error |= ChipSetField(pParams->handle_demod, 
				FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(Demod),1);
			error |= ChipSetField(pParams->handle_demod, 
				FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(Demod),0);
			
			error |= FE_STiD135_GetFECLock(pParams->handle_demod, Demod, FEC_Lock_TimeOut, &lock);
			if (lock) {
				SlcList->t_slice[SlcList->max_index].slice_id = (u8)i;
				SlcList->max_index = (u16)(SlcList->max_index + 1);
			} else {
				SlcList->t_slice[SlcList->max_index].slice_id = 0;
			}
		}
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICECFG_DEMODFLT_RAMMODE(Demod), 
					Demodflt_Rammode);
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_SLICESEL(Demod),
			SliceSel);
			
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(Demod),1);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(Demod),0);
	}
	else
		error = FE_LLA_INVALID_HANDLE; 	
	
	return error;	
}


/*****************************************************
--FUNCTION	::	fe_stid135_set_slice
--ACTION	::	Outputs desired slice
--PARAMS IN	::	Handle	==> Front End Handle
			Demod ==> current demod 1..8
			SliceID ==> slice id
--PARAMS OUT	::	None
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_slice(fe_stid135_handle_t Handle,
		enum fe_stid135_demod Demod, u8 SliceID) 
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param*)Handle;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_DEMODFLT_XXXMODE(Demod), 0x14);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICESEL_DEMODFLT_SLICESEL(Demod), 
			SliceID);
	}
	
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_get_slice_info
--ACTION	::	Returns Info on a selected slice
			Cardboard ram bug workaround on cut1
--PARAMS IN	::	Handle -> Front End Handle
			Demod -> current demod 1..8
			SliceId -> slice id
--PARAMS OUT	::	pSliceInfo -> pointer to slice data structure
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_get_slice_info(fe_stid135_handle_t Handle,
		enum fe_stid135_demod Demod, u8 SliceId, struct fe_sat_slice *pSliceInfo) 
{
	u8 FEC_Lock_TimeOut = 100;
	u32 reg_value;
	BOOL lock = FALSE;
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	u8 SliceSel, MaxSliceNumber, MinSliceNumber;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	
	if(Handle != NULL) {
		/* check if the demod can handle it */
		if(Demod > FE_SAT_DEMOD_4)
			return FE_LLA_INVALID_HANDLE;
		
		/* fetch the SliceMax index */
		error |= ChipGetOneRegister(pParams->handle_demod, 
		(u16)REG_RC8CODEW_DVBSX_DEMOD_SLICEMAX(Demod), &reg_value);
		MaxSliceNumber = (u8)reg_value; 
		/* fetch the SliceMin index */
		error |= ChipGetOneRegister(pParams->handle_demod, 
		(u16)REG_RC8CODEW_DVBSX_DEMOD_SLICEMIN(Demod), &reg_value);
		MinSliceNumber = (u8)reg_value;
		/* Save temporary */
		error |= ChipGetOneRegister(pParams->handle_demod, 
		(u16)REG_RC8CODEW_DVBSX_DEMOD_SLICESEL(Demod), &reg_value);
		SliceSel = (u8)reg_value;
		
		if((SliceId >= MinSliceNumber) && (SliceId <= MaxSliceNumber)) {
			/* tbd, try fetching it from SLC itself, also the anchor
			frame settings */
			error |= ChipSetOneRegister(pParams->handle_demod, 
				(u16)REG_RC8CODEW_DVBSX_DEMOD_SLICESEL(Demod), SliceId);
		
			// Delineator reset, to be sure
			error |= ChipSetField(pParams->handle_demod, 
				FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(Demod),1);
			error |= ChipSetField(pParams->handle_demod, 
				FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(Demod),0);
			
			error |= FE_STiD135_GetFECLock(pParams->handle_demod, Demod, FEC_Lock_TimeOut, &lock);
			if (lock) {
				// fetch the rest of the parameters
				pSliceInfo->slice_id = SliceId;
				error |= ChipGetOneRegister(pParams->handle_demod,  
						(u16)REG_RC8CODEW_DVBSX_PKTDELIN_PDELSTATUS2(Demod), &reg_value);
				pSliceInfo->modcode = ChipGetFieldImage(pParams->handle_demod, 
						FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS2_FRAME_MODCOD(Demod)); 
				pSliceInfo->frame_length = ChipGetFieldImage(pParams->handle_demod,  
						FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS2_FRAME_TYPE(Demod)) >> 1;
				pSliceInfo->pilots = ChipGetFieldImage(pParams->handle_demod,  
						FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS2_FRAME_TYPE(Demod)) & 0x01;
			} else {
				pSliceInfo->slice_id = SliceId;
				pSliceInfo->modcode = FE_SAT_MODCODE_UNKNOWN;
				pSliceInfo->frame_length = FE_SAT_UNKNOWN_FRAME;
				pSliceInfo->pilots = FE_SAT_UNKNOWN_PILOTS;
			}
		}
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_SLICESEL(Demod), SliceSel);
		
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(Demod),1);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(Demod),0);
	} else
		error = FE_LLA_INVALID_HANDLE; 	
	
	return error;	
}


/*****************************************************
--FUNCTION	::	FE_STiD135_get_mid
--ACTION	::	returns Chip ID
--PARAMS IN	::	Handle -> Front End Handle
--PARAMS OUT	::	chip ID
--RETURN	:: 	error	
--***************************************************/
fe_lla_error_t FE_STiD135_get_mid(fe_stid135_handle_t Handle, u8* mid_p)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;  
	u32 reg_value;
	pParams = (struct fe_stid135_internal_param *) Handle;
	error |= ChipGetOneRegister(pParams->handle_demod, RC8CODEW_C8CODEW_TOP_CTRL_MID, &reg_value);
	*mid_p = (u8)reg_value; 
	
	return error;
}


/*****************************************************
--FUNCTION	::	FE_STiD135_GetStatus
--ACTION	::	Get almost all status
--PARAMS IN	::	Handle -> Front End Handle
			Demod -> current demod 1..8
--PARAMS OUT	::	status_p -> bitfield structure reporting all status  
--RETURN	::	error 
--***************************************************/
fe_lla_error_t FE_STiD135_GetStatus(fe_stid135_handle_t Handle, enum fe_stid135_demod Demod, struct status_bit_fields* status_p)
{
	s32 AgcrfPath = 0;
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	struct fe_stid135_internal_param *pParams;
	s32 val1, val2, val3;
	u32 val4;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	if(pParams != NULL) {
		error |= fe_stid135_get_agcrf_path(pParams->handle_demod, Demod, &AgcrfPath);
		
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_LOCK_DEFINITIF(Demod), &val1);
		status_p->lock_definitif = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_SLICESTAT_DEMODFLT_PDELSYNC(Demod), &val1);
		status_p->pdelsync = (u8)(val1 & 0x3);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_ASYMSTATUS_ASYMCTRL_ON(Demod), &val1);
		status_p->asymctrl_on = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GSTAT_PSD_DONE(Demod), &val1);
		status_p->gstat_psd_done = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISTXSTATUS_TX_END(AgcrfPath), &val1);
		status_p->distxstatus_tx_end = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISRXSTAT1_RXEND(AgcrfPath), &val1);
		status_p->disrxstat1_rxend = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_FECSPY_FSTATUS_FOUND_SIGNAL(Demod), &val1); 
		status_p->fstatus_found_signal = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS_TSFIFO_LINEOK(Demod), &val1);
		status_p->tsfifo_lineok = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_SFSTATUS_SFEC_LINEOK(Demod), &val1);
		status_p->sfec_lineok = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_BCH_ERROR_FLAG(Demod), &val1);
		status_p->bch = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_PKTDELIN_LOCK(Demod), &val1);
		status_p->pktdelin_lock = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_SUPERFEC_SFECSTATUS_LOCKEDSFEC(Demod), &val1);
		status_p->lockedsfec = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_VITERBI_VSTATUSVIT_LOCKEDVIT(Demod), &val1);
		status_p->lockedvit = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DMDSTATE_DEMOD_MODE(Demod), &val1); 
		status_p->demod_mode = (u8)(val1 & 0x1F);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_AGCRF_AGCRFCN_AGCRF_LOCKED(AgcrfPath), &val1 );
		status_p->agcrf_locked = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FSTID135_AFE_AFE_STATUS_PLL_LOCK, &val1);
		status_p->pll_lock = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_CAR_LOCK(Demod), &val1);
		status_p->car_lock = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS_TIMING_IS_LOCKED(Demod), &val1);
		status_p->timing_is_locked = (u8)(val1 & 0x1);
		error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_SYS_C8SECTPFE_SYS_OTHER_ERR_STATUS, &val4);
		val4 = val4 >> 1;
		status_p->tsdmaerror = (u8)(val4 & 0x1);
		error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_STATUS, &val4);
		val4 = val4 >> 1;
		status_p->dest0_status_dma_overflow = (u8)(val4 & 0x1);
		error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_STATUS, &val4);
		val4 = val4 >> 1;
		status_p->dest1_status_dma_overflow = (u8)(val4 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS5_SHDB_OVERFLOW(Demod), &val1);
		status_p->shdb_overflow = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS5_SHDB_ERROR(Demod), &val1);
		status_p->shdb_error = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS2_DEMOD_DELOCK(Demod), &val1);
		status_p->demod_delock = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_PKTDELIN_DELOCK(Demod), &val1);
		status_p->pktdelin_delock = (u8)(val1 & 0x1);
		/* Freeze the BBFCRCKO and UPCRCKO counters. Allow to read them in coherency. */
		//ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_RESET_UPKO_COUNT(Demod), 1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_BBFCRCKO1_BBHCRC_KOCNT(Demod), &val1) ;
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_BBFCRCKO0_BBHCRC_KOCNT(Demod) , &val2);
		status_p->bbfcrcko = (u16)((val1 << 8)+ (val2));
		
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_UPCRCKO1_PKTCRC_KOCNT(Demod), &val1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_UPCRCKO0_PKTCRC_KOCNT(Demod), &val2);
		status_p->upcrcko = (u16)((val1<< 8) + val2);
		/* Reset and Restart BBFCRCKO and UPCRCKO counters. */
		//ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_RESET_UPKO_COUNT(Demod), 0);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS2_TSFIFO_LINENOK(Demod), &val1) ; 
		status_p->tsfifo_linenok = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS2_DIL_NOSYNC(Demod), &val1);
		status_p->dil_nosync = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS_TSFIFO_ERROR(Demod), &val1);
		status_p->tsfifo_error = (u8)(val1 & 0x1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSDEBUG0_TSFIFO_ERROR_EVNT(Demod), &val1);
		status_p->tsfifo_error_evnt = (u8)(val1 & 0x1);															  
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_ERRCNT12_ERR_CNT1(Demod), &val1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_ERRCNT11_ERR_CNT1(Demod), &val2);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_ERRCNT10_ERR_CNT1(Demod), &val3);
		status_p->errcnt1 = (u32)(((val1 << 16) + (val2 << 8) + val3) & 0xFFFFFF);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_ERRCNT22_ERR_CNT2(Demod), &val1); 
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_ERRCNT21_ERR_CNT2(Demod), &val2); 
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_ERRCNT20_ERR_CNT2(Demod), &val3); 
		status_p->errcnt2 = (u32)(((val1 << 16) + (val2 << 8) + val3) & 0xFFFFFF);
	}

	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_reset_obs_registers
--ACTION	::	Resets memorized status
--PARAMS IN	::	Handle -> Front End Handle
			Demod -> current demod 1..8
--PARAMS OUT	::	NONE
--RETURN	::	error 
--***************************************************/
fe_lla_error_t fe_stid135_reset_obs_registers(fe_stid135_handle_t Handle, enum fe_stid135_demod Demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;  
	
	struct fe_stid135_internal_param *pParams;
	s32 fld_value;
	pParams = (struct fe_stid135_internal_param *) Handle;
	if(pParams != NULL) {
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS5_SHDB_OVERFLOW(Demod), &fld_value);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS5_SHDB_ERROR(Demod), &fld_value);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS2_DEMOD_DELOCK(Demod), 0);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_PKTDELIN_DELOCK(Demod), 0);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_RESET_UPKO_COUNT(Demod), 1);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_RESET_UPKO_COUNT(Demod), 0);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS2_TSFIFO_LINENOK(Demod), 0);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS2_DIL_NOSYNC(Demod), 0);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS_TSFIFO_ERROR(Demod), &fld_value);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSDEBUG0_TSFIFO_ERROR_EVNT(Demod), 0);
		error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELSTATUS1_BCH_ERROR_FLAG(Demod), 0);
		/* Reset counter of killed packet number */
		error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_ERRCNT20(Demod), 0x00);
	}
	
	return error;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_Term
--ACTION	::	Terminates chip connection
--PARAMS IN	::	Handle -> Front End Handle
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t FE_STiD135_Term(fe_stid135_handle_t Handle)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;  
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	
	if (pParams != NULL) {
		#ifdef HOST_PC
			ChipClose(pParams->handle_demod);
			ChipClose(pParams->handle_soc);

			if(Handle)
				kvfree(pParams);
		#endif
		
	} else
		error = FE_LLA_INVALID_HANDLE; 	
	
	return error;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_ReadHWMatype
--ACTION	::	Returns the Matype, need to Read 16 bits (2x8 bits
			linked registers)
--PARAMS IN	::	hChip -> Handle to the chip
			Demod -> current demod 1..8
--PARAMS OUT	::	isi_read -> ISI read
			matype -> Matype read
--RETURN	::	error
--***************************************************/
static fe_lla_error_t fe_stid135_read_hw_matype(stchip_handle_t hChip,
	enum fe_stid135_demod Demod, u8 *matype, u8 *isi_read)
{

	fe_lla_error_t error = FE_LLA_NO_ERROR;
	
	// Read at the same time both registers (specific registers)
	error |= ChipGetRegisters(hChip, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_MATSTR1(Demod), 2);
	*matype = (u8)(ChipGetFieldImage(hChip, FLD_FC8CODEW_DVBSX_PKTDELIN_MATSTR1_MATYPE_ROLLOFF(Demod))
		| ChipGetFieldImage(hChip, FLD_FC8CODEW_DVBSX_PKTDELIN_MATSTR1_MATYPE_NPD(Demod)) << 2
		| ChipGetFieldImage(hChip, FLD_FC8CODEW_DVBSX_PKTDELIN_MATSTR1_MATYPE_ISSYI(Demod)) << 3
		| ChipGetFieldImage(hChip, FLD_FC8CODEW_DVBSX_PKTDELIN_MATSTR1_MATYPE_CCMACM(Demod)) << 4
		| ChipGetFieldImage(hChip, FLD_FC8CODEW_DVBSX_PKTDELIN_MATSTR1_MATYPE_SISMIS(Demod)) << 5
		| ChipGetFieldImage(hChip, FLD_FC8CODEW_DVBSX_PKTDELIN_MATSTR1_MATYPE_TSGS(Demod)) << 6);
	*isi_read = (u8)ChipGetFieldImage(hChip, FLD_FC8CODEW_DVBSX_PKTDELIN_MATSTR0_MATYPEISI_CURRENT(Demod));
	
	if (hChip->Error) /*Check the error at the end of the function*/ 
		error = FE_LLA_I2C_ERROR; 
	
	return error;
	
}

/*****************************************************
--FUNCTION	::	fe_stid135_manage_matype_info
--ACTION	::	Manage all action depending on Matype Information
--PARAMS IN	::	handle -> Front End Handle
			Demod -> current demod 1..8
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_manage_matype_info(fe_stid135_handle_t handle,
						enum fe_stid135_demod Demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 matype_info, isi, genuine_matype;
	s32 fld_value;
	BOOL mis = FALSE;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *) handle;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error) 
			error = FE_LLA_I2C_ERROR; 
		else {
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_TPKTDELIN_TESTBUS_SELECT(Demod), 8);
			/* Free MATYPE forced mode */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_BBHCTRL2_FORCE_MATYPEMSB(Demod), 0);
			/* Read Matype */
			error = fe_stid135_read_hw_matype(pParams->handle_demod, Demod, &matype_info, &isi);
			genuine_matype = matype_info;

			/* Chech if MIS stream (Multi Input Stream). If yes then set the MIS Filter to get the Min ISI */
 			if (!fe_stid135_check_sis_or_mis(matype_info)) {
				mis = TRUE;
				pParams->mis_mode[Demod-1] = TRUE;
 				/* Get Min ISI and activate the MIS Filter */
 				error |= fe_stid135_select_min_isi(handle, Demod);
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BITSPEED(Demod), 0);
				/* ISSYI use-case : minimize jitter below 100ns and provides a smooth TS output rate */
				if((genuine_matype >> 3) & 0x1) {
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPCRPID1_SOFFIFO_PCRADJ(Demod), 1);
				}
			}
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_TPKTDELIN_TESTBUS_SELECT(Demod), 0);

			/* If TS/GS = 11 (MPEG TS), reset matype force bit and do NOT load frames in MPEG packets */
			if(((genuine_matype>>6) & 0x3) == 0x3) {
	  			if((genuine_matype >> 3) & 0x3) {
					/* CCM or ISSYI used */
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATE1_TSOUT_NOSYNC(Demod), 0);
					//error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSYNC_TSFIFO_SYNCMODE(Demod), 0);
				} else {
					/* ACM and ISSYI not used */
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATE1_TSOUT_NOSYNC(Demod), 1);
					//error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSYNC_TSFIFO_SYNCMODE(Demod), 2);
				}
				/* Unforce HEM mode */
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL0_HEMMODE_SELECT(Demod), 0);
				/* Go back to reset value settings */
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG1_TSFIFO_MANSPEED(Demod), 0);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(Demod), 0xFF);
				/* To avoid reset of stream merger in annexM, ACM or if PID filter is enabled, set automatic computation of TS bit rate */
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DSTATUS6_SIGNAL_ANNEXEM(Demod), &fld_value);
				if((fld_value == 0) || (fld_value == 1) || (mis)) {
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BITSPEED(Demod), 0);
				} else { /* sliced mode */
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BITSPEED(Demod), 1);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSBITRATE1(Demod), 0x80);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSBITRATE0(Demod), 0x00);
				}
			}
			/* If TS/GS = 10 (GSE-HEM High Efficiency Mode) reset matype force bit, load frames in MPEG packets and disable latency regulation */
			else if(((genuine_matype>>6) & 0x3) == 0x2){
				#ifdef USER1
					/* Force HEM mode */
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL0_HEMMODE_SELECT(Demod), 3);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG1_TSFIFO_MANSPEED(Demod), 3);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_EMBINDVB(Demod), 1); // - new management of NCR
					/* Adjust TSSPEED according to channel maximum bit rate for the demodulator */
					error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG0_SDEMAP_MAXLLRRATE(Demod), &fld_value);
					if(fld_value == 0x00) {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(Demod), 0x10); // - new management of NCR
					} else {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(Demod), 0x16); // - new management of NCR
					}
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATE1_TSOUT_NOSYNC(Demod), 0);
					/* To avoid reset of stream merger in annexM, ACM or if PID filter is enabled, set pragmatic smoothing mode for computation of TS bit rate */
					matype_info &= 0x0F;
					/* Set bit 5 to ignore ISI/MIS bit because not compatible with NCR feature (latency regulation) */
					matype_info |= 0xB0;
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_MATCST1(Demod), matype_info);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_BBHCTRL2_FORCE_MATYPEMSB(Demod), 1);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BITSPEED(Demod), 1);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSBITRATE1(Demod), 0x80);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSBITRATE0(Demod), 0x00);
				#else
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_FORCE_CONTINUOUS(Demod), 1);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_FRAME_MODE(Demod), 1);
				//	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSYNC_TSFIFO_SYNCMODE(Demod), 2);

					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_EMBINDVB(Demod), 1);
					/* Go back to reset value settings */
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG1_TSFIFO_MANSPEED(Demod), 0);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(Demod), 0xFF);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATE1_TSOUT_NOSYNC(Demod), 0);
					/* Unforce HEM mode */
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL0_HEMMODE_SELECT(Demod), 0);
				#endif
			}
			/* If TS/GS = 00 (Generic packetized) or 01 (Generic continuous) force matype/tsgs = 10 and load frames in MPEG packets */
			else if((((genuine_matype>>6) & 0x3) == 0x0) || ((genuine_matype>>6) & 0x3) == 0x1) {
				#ifdef USER1
					/* Force HEM mode */
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL0_HEMMODE_SELECT(Demod), 3);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG1_TSFIFO_MANSPEED(Demod), 3);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_EMBINDVB(Demod), 1); // - new management of NCR
					/* Adjust TSSPEED according to channel maximum bit rate for the demodulator */
					error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG0_SDEMAP_MAXLLRRATE(Demod), &fld_value);
					if(fld_value == 0x00) {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(Demod), 0x10); // - new management of NCR
					} else {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(Demod), 0x16); // - new management of NCR
					}
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATE1_TSOUT_NOSYNC(Demod), 0);
					/* To avoid reset of stream merger in annexM, ACM or if PID filter is enabled, set pragmatic smoothing mode for computation of TS bit rate */
					matype_info &= 0x0F;
					/* Set bit 5 to ignore ISI/MIS bit because not compatible with NCR feature (latency regulation) */
					matype_info |= 0xB0;
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_MATCST1(Demod), matype_info);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_BBHCTRL2_FORCE_MATYPEMSB(Demod), 1);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BITSPEED(Demod), 1);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSBITRATE1(Demod), 0x80);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSBITRATE0(Demod), 0x00);
				#else

					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_FORCE_CONTINUOUS(Demod), 1);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_FRAME_MODE(Demod), 1);
					//error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSYNC_TSFIFO_SYNCMODE(Demod), 2);

					matype_info &= 0x0F;
					/* Set bit 5 to ignore ISI/MIS bit because not compatible with NCR feature (latency regulation) */
					matype_info |= 0xB0;
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_MATCST1(Demod), matype_info);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_BBHCTRL2_FORCE_MATYPEMSB(Demod), 1);
					/* Force HEM mode */
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL0_HEMMODE_SELECT(Demod), 3);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_EMBINDVB(Demod), 1);
					/* Switch to manual CLKOUT frequency processing */
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG1_TSFIFO_MANSPEED(Demod), 3);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(Demod), 0x18);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATE1_TSOUT_NOSYNC(Demod), 0);
					/* To avoid reset of stream merger in annexM, ACM or if PID filter is enabled, set pragmatic smoothing mode for computation of TS bit rate */
				#endif
			}
			/* WB, and MIS mode */
			if ((pParams->demod_symbol_rate[Demod-1] > pParams->master_clock) && mis) {
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG1_TSFIFO_MANSPEED(Demod), 3);
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG0_SDEMAP_MAXLLRRATE(Demod), &fld_value);
				if(fld_value == 0x00) {
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(Demod), 0x10); // - new management of NCR
				} else {
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(Demod), 0x16); // - new management of NCR
				}
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BITSPEED(Demod), 1);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSBITRATE1(Demod), 0x80);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSBITRATE0(Demod), 0x00);
			}
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_manage_matype_info_raw_bbframe
--ACTION	::	Manage all action depending on Matype Information
 			(raw BB frame handling)
--PARAMS IN	::	handle -> Front End Handle
			Demod -> current demod 1..8
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
static fe_lla_error_t fe_stid135_manage_matype_info_raw_bbframe(fe_stid135_handle_t handle,
						enum fe_stid135_demod Demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 matype_info, isi, genuine_matype;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *) handle;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error) 
			error = FE_LLA_I2C_ERROR; 
		else {
			/* Read Matype */
			error = fe_stid135_read_hw_matype(pParams->handle_demod, Demod, &matype_info, &isi);
			genuine_matype = matype_info;

			/* Check if MIS stream (Multi Input Stream). If yes then set the MIS Filter to get the Min ISI */
 			if (!fe_stid135_check_sis_or_mis(matype_info)) {
				pParams->mis_mode[Demod-1] = TRUE;
 				/* Get Min ISI and activate the MIS Filter */
 				error |= fe_stid135_select_min_isi(handle, Demod);
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BITSPEED(Demod), 0);
				/* ISSYI use-case : minimize jitter below 100ns and provides a smooth TS output rate */
				if((genuine_matype >> 3) & 0x1) {
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPCRPID1_SOFFIFO_PCRADJ(Demod), 1);
				}
			}

			/* If TS/GS = 01 (Generic continuous) => raw BB frame */
			if(((genuine_matype>>6) & 0x3) == 0x1) {
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_FORCE_CONTINUOUS(Demod), 1);
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL2_FRAME_MODE(Demod), 1);
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSYNC_TSFIFO_SYNCMODE(Demod), 2);

				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_EMBINDVB(Demod), 1);
				/* Switch to manual CLKOUT frequency processing */
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG1_TSFIFO_MANSPEED(Demod), 3);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(Demod), 0x18);
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATE1_TSOUT_NOSYNC(Demod), 0);
				/* To avoid reset of stream merger in annexM, ACM or if PID filter is enabled, set pragmatic smoothing mode for computation of TS bit rate */
			}
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_get_matype_infos
--ACTION	::	Returns the MATYPE (byte 1) info
--PARAMS IN	::	Handle -> Front End Handle
			Demod -> current demod 1..8
--PARAMS OUT	::	matype_infos -> pointer to MatypeInfo struct to fill
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_get_matype_infos(fe_stid135_handle_t Handle,
			enum fe_stid135_demod Demod, struct fe_sat_dvbs2_matype_info_t *matype_infos)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)Handle;

	u8 matype_val,isi;
	s32 fld_value;
	
	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
			error |= fe_stid135_read_hw_matype(pParams->handle_demod, Demod, &matype_val,
						&isi);
			/* Also available in Px_TSSTATEM:Px_TSFRAME_MODE */
			matype_infos->StreamType = (matype_val>>6)&0x3;
			matype_infos->InputStream = (matype_val>>5)&0x1;
			/* Also available in Px_TSSTATEM:Px_TSACM_MODE */
			matype_infos->CodingModulation = (matype_val>>4)&0x1;
			/* Also available in Px_TSSTATEL:Px_TSISSYI_ON */
			matype_infos->InputStreamSynchro = (matype_val>>3)&0x1;
			/* Also available in Px_TSSTATEL:Px_NPD_ON */
			matype_infos->NullPacketdeletion = (matype_val>>2)&0x1;
			/* Also available in Px_TMGOBS:Px_ROLLOFF_STATUS */
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_TMGOBS_ROLLOFF_STATUS(Demod), &fld_value);
			matype_infos->roll_off = (enum fe_sat_rolloff)(fld_value);
			
			/*Check the error at the end of the function*/
			if (pParams->handle_demod->Error )
				error = FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_TunerInit
--ACTION	::	Performs tuner init
--PARAMS IN	::	pParams -> Pointer to fe_stid135_internal_param structure
-PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
TUNER_Error_t FE_STiD135_TunerInit(struct fe_stid135_internal_param *pParams)
{
	TUNER_Error_t error = TUNER_NO_ERR;
	s32 vco_cal=0, timeout=0;
	int i;
	
	/* First, put in sleep mode all tuners if they were previously enabled 
	The aim is to lower down power consumption */
	error |= FE_STiD135_TunerStandby(pParams->handle_demod ,AFE_TUNER1, FALSE);
	error |= FE_STiD135_TunerStandby(pParams->handle_demod ,AFE_TUNER2, FALSE);
	error |= FE_STiD135_TunerStandby(pParams->handle_demod ,AFE_TUNER3, FALSE);
	error |= FE_STiD135_TunerStandby(pParams->handle_demod ,AFE_TUNER4, FALSE);
	
	error |= (TUNER_Error_t)Oxford_AfeInit(pParams->handle_demod, pParams->quartz, pParams->internal_dcdc, pParams->internal_ldo);
	if(error != TUNER_NO_ERR)
		return(error);
	WAIT_N_MS(100);
	error |= Oxford_CalVCOfilter(pParams->handle_demod);
	/* Set RF inputs either single ended or differential */
	error |= Oxford_SetVglnaInputs(pParams->handle_demod, pParams->rf_input_type);
	
	/* Select calibration code source: use AFE_BBxI_CAL and AFE_BBxQ_CAL */
	error |= Oxford_CalCodeSource(pParams->handle_demod, AFE_TUNER_ALL, TRUE);
	
	/* At startup, set NF mode of VGLNA gain */
	for(i=AFE_TUNER1;i<=AFE_TUNER4;i++) {
		error |= fe_stid135_manage_LNF_IP3(pParams->handle_demod, (FE_OXFORD_TunerPath_t)i, 0);
	}
	
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_tuner_enable
--ACTION	::	Wakes up tuner
--PARAMS IN	::	tuner_handle -> Handle to the chip
			tuner_nb -> tuner path to wake up
--PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_tuner_enable(stchip_handle_t tuner_handle, FE_OXFORD_TunerPath_t tuner_nb)
{
	STCHIP_Error_t error = CHIPERR_NO_ERROR;
	
	switch(tuner_nb) {
		case AFE_TUNER1:
			error |= Oxford_EnableLO(tuner_handle, AFE_TUNER1);
			error |= Oxford_TunerStartUp(tuner_handle, AFE_TUNER1);
			error |= (STCHIP_Error_t)Oxford_AdcStartUp(tuner_handle, AFE_TUNER1);
			error |= Oxford_SetVGLNAgainMode(tuner_handle, AFE_TUNER1, 0);
		break;
		case AFE_TUNER2:
			error |= Oxford_EnableLO(tuner_handle, AFE_TUNER2);
			error |= Oxford_TunerStartUp(tuner_handle, AFE_TUNER2);
			error |= (STCHIP_Error_t)Oxford_AdcStartUp(tuner_handle, AFE_TUNER2);
			error |= Oxford_SetVGLNAgainMode(tuner_handle, AFE_TUNER2, 0);
		break;
		case AFE_TUNER3:
			error |= Oxford_EnableLO(tuner_handle, AFE_TUNER3);
			error |= Oxford_TunerStartUp(tuner_handle, AFE_TUNER3);
			error |= (STCHIP_Error_t)Oxford_AdcStartUp(tuner_handle, AFE_TUNER3);
			error |= Oxford_SetVGLNAgainMode(tuner_handle, AFE_TUNER3, 0);
		break;
		case AFE_TUNER4:
			error |= Oxford_EnableLO(tuner_handle, AFE_TUNER4);
			error |= Oxford_TunerStartUp(tuner_handle, AFE_TUNER4);
			error |= (STCHIP_Error_t)Oxford_AdcStartUp(tuner_handle, AFE_TUNER4);
			error |= Oxford_SetVGLNAgainMode(tuner_handle, AFE_TUNER4, 0);
		break;
		case AFE_TUNER_ALL:
			error |= CHIPERR_INVALID_HANDLE;
		break;
	}
	/* Fix of BZ#116882 (FIFO reset required to make sure that read/write pointers are at a clean location */
	error |= ChipSetField(tuner_handle, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TOP_STOPCLK_STOP_CKTUNER, (0x1)<<(tuner_nb-1));
	WAIT_N_MS(10);
	error |= ChipSetField(tuner_handle, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TOP_STOPCLK_STOP_CKTUNER, (0x0)<<(tuner_nb-1));
	WAIT_N_MS(100);
	return (fe_lla_error_t)error;
}

/*****************************************************
--FUNCTION	::	FE_STiD135_TunerStandby
--ACTION	::	Puts in sleep or wake-up tuner
--PARAMS IN	::	TunerHandle -> Handle to the chip
			TunerNb -> tuner path
			Enable -> boolean variable
-PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t FE_STiD135_TunerStandby(stchip_handle_t TunerHandle, FE_OXFORD_TunerPath_t TunerNb, u8 Enable)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	
	
	if(Enable) {
		error |= (fe_lla_error_t)Oxford_EnableLO(TunerHandle, TunerNb);
		error |= (fe_lla_error_t)Oxford_TunerStartUp(TunerHandle, TunerNb);
		error |= (fe_lla_error_t)Oxford_AdcStartUp(TunerHandle, TunerNb);
	} else { /* Enable = FALSE */
		error |= (fe_lla_error_t)Oxford_TunerDisable(TunerHandle, TunerNb);
	}
	
	return (fe_lla_error_t)error;
}


/*****************************************************
--FUNCTION	::	fe_stid135_get_agcrf_path
--ACTION	::	Gets tuner path connected to current demod
--PARAMS IN	::	hChip -> Handle to the chip
			demod -> Current demod 1..8
-PARAMS OUT	::	agcrf_path_p -> tuner path number
--RETURN	::	error
--***************************************************/
static fe_lla_error_t fe_stid135_get_agcrf_path(stchip_handle_t hChip,
			enum fe_stid135_demod demod, s32* agcrf_path_p)
{

	fe_lla_error_t error = FE_LLA_NO_ERROR;
	
	switch(demod) {
		case 1:
			error |= ChipGetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX0_RFMUX_DEMOD_SEL_1, agcrf_path_p) ;
		break;
		
		case 2:
			error |= ChipGetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX1_RFMUX_DEMOD_SEL_2, agcrf_path_p) ;
		break;
		
		case 3:
			error |= ChipGetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX2_RFMUX_DEMOD_SEL_3, agcrf_path_p) ;
		break;
		
		case 4:
			error |= ChipGetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX3_RFMUX_DEMOD_SEL_4, agcrf_path_p) ;
		break;
		
		case 5:
			error |= ChipGetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX4_RFMUX_DEMOD_SEL_5, agcrf_path_p) ;
		break;
		
		case 6:
			error |= ChipGetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX5_RFMUX_DEMOD_SEL_6, agcrf_path_p) ;
		break;
		
		case 7:
			error |= ChipGetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX6_RFMUX_DEMOD_SEL_7, agcrf_path_p) ;
		break;
		
		case 8:
			error |= ChipGetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX7_RFMUX_DEMOD_SEL_8, agcrf_path_p) ;
		break;
	}
	
	*agcrf_path_p +=1;
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_rfmux_path
--ACTION	::	Sets RF mux
--PARAMS IN	::	hChip -> Handle to the chip
			demod -> Current demod 1..8
			tuner -> Current tuner 1..4
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_rfmux_path(stchip_handle_t hChip,
			enum fe_stid135_demod demod, FE_OXFORD_TunerPath_t tuner)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;

	switch(demod) {
		case 1:
			error |= ChipSetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX0_RFMUX_DEMOD_SEL_1, (s32)(tuner - 1));
		break;
		
		case 2:
			error |= ChipSetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX1_RFMUX_DEMOD_SEL_2, (s32)(tuner - 1));
		break;
		
		case 3:
			error |= ChipSetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX2_RFMUX_DEMOD_SEL_3, (s32)(tuner - 1));
		break;
		
		case 4:
			error |= ChipSetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX3_RFMUX_DEMOD_SEL_4, (s32)(tuner - 1));
		break;
		
		case 5:
			error |= ChipSetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX4_RFMUX_DEMOD_SEL_5, (s32)(tuner - 1));
		break;
		
		case 6:
			error |= ChipSetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX5_RFMUX_DEMOD_SEL_6, (s32)(tuner - 1));
		break;
		
		case 7:
			error |= ChipSetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX6_RFMUX_DEMOD_SEL_7, (s32)(tuner - 1));
		break;
		
		case 8:
			error |= ChipSetField(hChip, FLD_FC8CODEW_C8CODEW_RFMUX_RFMUX7_RFMUX_DEMOD_SEL_8, (s32)(tuner - 1));
		break;
	}
	
	if (hChip->Error) /*Check the error at the end of the function*/ 
		error = FE_LLA_I2C_ERROR;
	
	return(error);
}

/*
fe_lla_error_t fe_stid135_fskmodulatorctrl (fe_stid135_handle_t handle, 
       enum fe_stid135_demod	demod,
       bool fskmodulatorctrl)
{
}
fe_lla_error_t fe_stid135_configurefsk (fe_stid135_handle_t handle,
	enum fe_stid135_demod	demod, fe_stid135_modeparams_t fskparams)
{
}*/

/*****************************************************
--FUNCTION	::	fe_stid135_diseqc_init
--ACTION	::	Set the diseqC Tx mode 
--PARAMS IN	::	handle -> Front End Handle
		::	tuner_nb -> Current tuner 1 .. 4
		::	diseqc_mode -> continues tone, 2/3 PWM, 3/3 PWM,
			2/3 envelop or 3/3 envelop.
--PARAMS OUT	::	None
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_diseqc_init(fe_stid135_handle_t handle,
     FE_OXFORD_TunerPath_t tuner_nb, 
     enum fe_sat_diseqc_txmode diseqc_mode)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *) handle;
	s32 mode_fld, envelop_fld;
	u32 reg_value;

	if (pParams == NULL)
		return FE_LLA_INVALID_HANDLE;

	if (pParams->handle_demod->Error)
		return FE_LLA_I2C_ERROR;

	error |= Oxford_Disec_Lnb_FskStartup(pParams->handle_demod);
	
	switch(diseqc_mode) {
	case FE_SAT_22KHZ_Continues:
	case FE_SAT_DISEQC_2_3_PWM:
	case FE_SAT_DISEQC_3_3_PWM:
		mode_fld = diseqc_mode;
		envelop_fld = 0;
		break;
	case FE_SAT_22KHZ_Continues_ENVELOP:
		mode_fld = 0;
		envelop_fld = 1;
		break;
	case FE_SAT_DISEQC_2_3_ENVELOP:
		mode_fld = 2;
		envelop_fld = 1;
		break;
	case FE_SAT_DISEQC_3_3_ENVELOP:
		mode_fld = 3;
		envelop_fld = 1;
		break;
	default:
		return FE_LLA_BAD_PARAMETER;
		break;
	}
	
	/* Set alternate function #1 */
	switch(tuner_nb) {
	case AFE_TUNER2:
		error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1000, &reg_value);
		reg_value |= 0x00000001;
		error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1000, reg_value);
	break;
	case AFE_TUNER3:
		error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1000, &reg_value);
		reg_value |= 0x00000010;
		error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1000, reg_value);
	break;
	case AFE_TUNER4:
		error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1000, &reg_value);
		reg_value |= 0x00000100;
		error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1000, reg_value);
	break;
	}

	error |= ChipSetField(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_LNBCTRL_LNB_VCTRL_VLNB_ON_EN, 1);
	error |= ChipSetField(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_DISEQC_DISTXCFG_DISEQC_MODE(tuner_nb),
				mode_fld);
	error |= ChipSetField(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_DISEQC_DISTXCFG_ENVELOP(tuner_nb),
				envelop_fld);
	error |=  ChipSetField(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_DISEQC_DISRXCFG_PINSELECT(AFE_TUNER1), 6);
	error |= ChipSetField(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_DISEQC_DISRXCFG_DISRX_ON(AFE_TUNER1), 1);
	error |= ChipSetField(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_DISEQC_DISTXCFG_DISTX_RESET(tuner_nb), 1);
	error |= ChipSetField(pParams->handle_demod,
				FLD_FC8CODEW_DVBSX_DISEQC_DISTXCFG_DISTX_RESET(tuner_nb), 0);

	/* Check the error at the end of the function */
	if(pParams->handle_demod->Error)
		error = FE_LLA_I2C_ERROR;

	return error;	
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_22khz_cont
--ACTION	::	Set 22KHz continues tone.
--PARAMS IN	::	handle -> Front End Handle
::	tuner_nb -> Current tuner 1 .. 4
::	tone -> continues tone on/off
--PARAMS OUT	::	None
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_22khz_cont(fe_stid135_handle_t handle,
						FE_OXFORD_TunerPath_t tuner_nb,
						BOOL tone)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;      
	struct fe_stid135_internal_param *pParams = NULL;

	pParams = (struct fe_stid135_internal_param*) handle;
	if (pParams == NULL)
		return FE_LLA_INVALID_HANDLE;

	if (pParams->handle_demod->Error)
		return FE_LLA_I2C_ERROR;

	error |= ChipSetField(pParams->handle_demod,
		FLD_FC8CODEW_DVBSX_DISEQC_DISTXCFG_DISEQC_MODE(tuner_nb), tone ? FE_SAT_22KHZ_Continues : FE_SAT_DISEQC_2_3_PWM);

	/* Check the error at the end of the function */
	if(pParams->handle_demod->Error)
		error = FE_LLA_I2C_ERROR;

	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_diseqc_send
--ACTION	::	Send bytes to DiseqC FIFO
--PARAMS IN	::	handle -> Front End Handle
			tuner_nb -> Current tuner 1 .. 4
		::	data -> Table of bytes to send.
		::	nbdata -> Number of bytes to send.
--PARAMS OUT	::	None
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_diseqc_send(fe_stid135_handle_t handle,
        FE_OXFORD_TunerPath_t tuner_nb, u8 *data, u8 nbdata)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;      
	struct fe_stid135_internal_param *pParams = NULL;
	u32 i=0; 
	s32 fld_value;
	
	pParams = (struct fe_stid135_internal_param*) handle;
	if(pParams != NULL)
	{
		if(pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR;
		else
		{
			// We forbid receive part of tuner#1 when we send a Diseqc command (only RF#1 is diseqc-receive compliant)
			if(tuner_nb == AFE_TUNER1) {
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISRXCFG_DISRX_ON(AFE_TUNER1), 0);
			}

			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISTXCFG_DIS_PRECHARGE(tuner_nb), 1);
			while(i < nbdata) { 
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISTXSTATUS_TX_FIFO_FULL(tuner_nb), &fld_value);
				while(fld_value) {
					error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISTXSTATUS_TX_FIFO_FULL(tuner_nb), &fld_value);
				}
		
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DISEQC_DISTXFIFO(tuner_nb), data[i]);	/* send byte to FIFO :: WARNING don't use set field	!! */
				i++;
			}
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISTXCFG_DIS_PRECHARGE(tuner_nb), 0);
		
			i=0;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISTXSTATUS_TX_IDLE(tuner_nb), &fld_value);
			while((fld_value != 1) && (i < 10)) {
				/*wait until the end of diseqc send operation */
				ChipWaitOrAbort(pParams->handle_demod, 10);
				i++;
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISTXSTATUS_TX_IDLE(tuner_nb), &fld_value);
			}
			
			if(tuner_nb == AFE_TUNER1) {
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISRXCFG_DISRX_ON(AFE_TUNER1), 1);
			}

			if(pParams->handle_demod->Error) /*Check the error at the end of the function*/ 
				error = FE_LLA_I2C_ERROR;
		}
	}
	else
		error = FE_LLA_INVALID_HANDLE; 
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_diseqc_receive
--ACTION	::	Read received bytes from DiseqC FIFO
--PARAMS IN	::	handle -> Front End Handle
--PARAMS OUT	::	Data -> Table of received bytes.
		::	NbData -> Number of received bytes.
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_diseqc_receive(fe_stid135_handle_t handle,
  u8 *data, u8 *nbdata)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;      
	struct fe_stid135_internal_param *pParams = NULL;
	u32 i=0;
	u32 reg_value;
	s32 fld_value;
	
	pParams = (struct fe_stid135_internal_param*) handle;
	if(pParams != NULL)
	{
		if(pParams->handle_demod->Error) 
			error = FE_LLA_I2C_ERROR;
		else
		{
			*nbdata=0;
			// Only the DiSEqC1 block has an Rx interface allowing full DiSEqC 2.x operation on this
			// interface, the three other blocks do not have receiver interfaces implemented.
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISRXSTAT1_RXEND(AFE_TUNER1), &fld_value);
			if(fld_value) {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISRXBYTES_RXFIFO_BYTES(AFE_TUNER1), &fld_value);
				*nbdata = (u8)fld_value;
				for(i = 0;i < (*nbdata);i++)
				{
					error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DISEQC_DISRXFIFO(AFE_TUNER1), &reg_value);
					data[i] = (u8)reg_value;
				}				
			}
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/ 
				error = FE_LLA_I2C_ERROR;
		}
	}
	else
		error = FE_LLA_INVALID_HANDLE; 
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_diseqc_reset
--ACTION	::	Resets both Tx and Rx blocks
--PARAMS IN	::	handle -> Front End Handle
--PARAMS OUT	::	tuner_nb -> Current tuner 1 .. 4
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_diseqc_reset(fe_stid135_handle_t handle, FE_OXFORD_TunerPath_t tuner_nb)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;      
	struct fe_stid135_internal_param *pParams = NULL;
	
	pParams = (struct fe_stid135_internal_param*) handle;
	if(pParams != NULL)
	{
		if(pParams->handle_demod->Error) 
			error = FE_LLA_I2C_ERROR;
		else
		{
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISTXCFG_DISTX_RESET(tuner_nb), 1);
			WAIT_N_MS(100);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISTXCFG_DISTX_RESET(tuner_nb), 0);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISRXCFG_DISRX_ON(AFE_TUNER1), 0);
			WAIT_N_MS(100);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DISEQC_DISRXCFG_DISRX_ON(AFE_TUNER1), 1);
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/ 
				error = FE_LLA_I2C_ERROR;
		}
	}
	else
		error = FE_LLA_INVALID_HANDLE; 
	return error;
}


/*****************************************************
--FUNCTION	::	fe_stid135_enable_pid
--ACTION	::	Enables given PID
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
			pid_number -> PID number to enable
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_enable_pid (fe_stid135_handle_t handle,
     enum fe_stid135_demod demod, u32 pid_number)
{
	
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, ram_index = 0;
	BOOL pid_already_output = FALSE;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR;
		else {
			/* Check if pid already output */
			for(i=0;i<RAM_SIZE;i++) {
				if((pParams->pid_flt[demod-1].ram_table[i].pid_number == pid_number) && (pParams->pid_flt[demod-1].ram_table[i].command != NONE))
					pid_already_output = TRUE;
			}
			
			if(pid_already_output == FALSE) {
				/* Go to first free RAM location */
				for(i=0;i<RAM_SIZE;i++)
					if(pParams->pid_flt[demod-1].ram_table[i].command == NONE) {
						ram_index = i;
						break;
					}
				/* Check if there is enough memory space */
				if(ram_index < RAM_SIZE - 2) {
					pParams->pid_flt[demod-1].ram_table[ram_index].pid_number = pid_number;
					pParams->pid_flt[demod-1].ram_table[ram_index + 1].pid_number = pid_number;
					/* Enable PID command takes exactly 2 bytes */
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->pid_flt[demod-1].ram_table[ram_index].address);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), (pParams->pid_flt[demod-1].ram_table[ram_index].pid_number | 0x8000) >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 1));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), (pParams->pid_flt[demod-1].ram_table[ram_index].pid_number | 0x8000) & 0xFF);
					/* PID is no more dummy, but a real PID */
					pParams->pid_flt[demod-1].ram_table[ram_index].command = ENABLE_PID;
					pParams->pid_flt[demod-1].ram_table[ram_index + 1].command = ENABLE_PID;
				}
			}
				
				
			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error=FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_disable_pid
--ACTION	::	Disables given PID
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
			pid_number -> pid number to disable
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_disable_pid (fe_stid135_handle_t handle,
      enum fe_stid135_demod demod, u32 pid_number)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, ram_index = 0;
	BOOL pid_already_output = FALSE;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
			/* Check if pid already output */
			for(i=0;i<RAM_SIZE;i++) {
				if((pParams->pid_flt[demod-1].ram_table[i].pid_number == pid_number)  && (pParams->pid_flt[demod-1].ram_table[i].command != NONE))
				{
					pid_already_output = TRUE;
					ram_index = i;
					break;
				}
			}
			
			if(pid_already_output == TRUE) {
				/* Change pid already output to dummy PID */
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->pid_flt[demod-1].ram_table[ram_index].address);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x9FFF >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 1));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x9FFF & 0xFF);
				/* PID is no more a real PID, but a dummy PID */
				pParams->pid_flt[demod-1].ram_table[ram_index].command = NONE;
				pParams->pid_flt[demod-1].ram_table[ram_index].pid_number = 0;
				pParams->pid_flt[demod-1].ram_table[ram_index + 1].command = NONE;
				pParams->pid_flt[demod-1].ram_table[ram_index + 1].pid_number = 0;
			}
			
			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error=FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_disable_rangepid
--ACTION	::	Disables given range PID
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
			pid_start_range -> starting PID number to disable
			pid_stop_range -> ending PID number to disable
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_disable_rangepid (fe_stid135_handle_t handle,
   enum fe_stid135_demod demod,u32 pid_start_range, u32 pid_stop_range)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, ram_index = 0;
	BOOL range_already_output = FALSE;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
			/* Check if pid already output */
			for(i=0;i<RAM_SIZE-2;i++) {
				if((pParams->pid_flt[demod-1].ram_table[i].command == SELECT_RANGE) && (pParams->pid_flt[demod-1].ram_table[i].pid_number == pid_start_range) && (pParams->pid_flt[demod-1].ram_table[i+2].pid_number == pid_stop_range))
				{
					range_already_output = TRUE;
					ram_index = i;
					break;
				}
			}
			if(range_already_output == TRUE) {
				/* Change pid already output to dummy PID */
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->pid_flt[demod-1].ram_table[ram_index].address);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x9FFF >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 1));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x9FFF & 0xFF);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 2));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x9FFF >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 3));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x9FFF & 0xFF);
				/* PID is no more a real PID, but a dummy PID */
				pParams->pid_flt[demod-1].ram_table[ram_index].command = NONE;
				pParams->pid_flt[demod-1].ram_table[ram_index].pid_number = 0;
				pParams->pid_flt[demod-1].ram_table[ram_index + 1].command = NONE;
				pParams->pid_flt[demod-1].ram_table[ram_index + 1].pid_number = 0;
				pParams->pid_flt[demod-1].ram_table[ram_index + 2].command = NONE;
				pParams->pid_flt[demod-1].ram_table[ram_index + 2].pid_number = 0;
				pParams->pid_flt[demod-1].ram_table[ram_index + 3].command = NONE;
				pParams->pid_flt[demod-1].ram_table[ram_index + 3].pid_number = 0;
			}
			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error=FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_select_rangepid
--ACTION	::	Enables given range PID
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
			pid_start_range > starting PID number to enable
			pid_stop_range -> ending PID number to enable
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_select_rangepid (fe_stid135_handle_t	handle,
   enum fe_stid135_demod demod,u32 pid_start_range, u32 pid_stop_range)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, ram_index = 0;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
			/* Go to first free RAM location */
			for(i=0;i<RAM_SIZE;i++)
				if(pParams->pid_flt[demod-1].ram_table[i].command == NONE) {
					ram_index = i;
					break;
				}
			/* Check if there is enough memory space */
			if(ram_index < RAM_SIZE - 4) {
				pParams->pid_flt[demod-1].ram_table[ram_index].pid_number = pid_start_range;
				pParams->pid_flt[demod-1].ram_table[ram_index + 1].pid_number = pid_start_range;
				pParams->pid_flt[demod-1].ram_table[ram_index + 2].pid_number = pid_stop_range;
				pParams->pid_flt[demod-1].ram_table[ram_index + 3].pid_number = pid_stop_range;
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->pid_flt[demod-1].ram_table[ram_index].address);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), ((pid_stop_range | 0xC000) + 1) >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 1));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), ((pid_stop_range | 0xC000) + 1) & 0xFF);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 2));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), pid_start_range >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 3));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), pid_start_range & 0xFF);
				
				/* PID is no more dummy, but a real PID */
				pParams->pid_flt[demod-1].ram_table[ram_index].command = SELECT_RANGE;
				pParams->pid_flt[demod-1].ram_table[ram_index + 1].command = SELECT_RANGE;
				pParams->pid_flt[demod-1].ram_table[ram_index + 2].command = SELECT_RANGE;
				pParams->pid_flt[demod-1].ram_table[ram_index + 3].command = SELECT_RANGE;
			}
			
			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error=FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_enable_allpid
--ACTION	::	Enables all PIDs
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_enable_allpid (fe_stid135_handle_t handle,
	enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
			/* All memory cells in RAM are reset, so update of table is necessary */
			for(i=0;i<RAM_SIZE>>1;i++) {
				pParams->pid_flt[demod-1].ram_table[i].command = ENABLE_ALL_PID;
				pParams->pid_flt[demod-1].ram_table[i].pid_number = 0;
			}
			// The filter RAM is erased to load a new program. All the packets are output waiting to go to 0x01 or 0x06
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x02);
			
			/* PASSALL command */
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0xA000 >> 8);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0xA000 & 0xFF);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0000 >> 8);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0000 & 0xFF);
			
			/* Activation with DELALL by default (0x01: H/W bug, ClearQuest opened) */
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x06);
			
			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error=FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_disable_allpid
--ACTION	::	Disables all PIDs
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_disable_allpid (fe_stid135_handle_t handle,
  enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
			/* If this is the 1st time after power-up we perform this function or if a enable_all_pid has been performed, then we write into all memory cells in RAM */
			if((pParams->pid_flt[demod-1].first_disable_all_command == TRUE) || (pParams->pid_flt[demod-1].ram_table[0].command == ENABLE_ALL_PID)) {
				// The filter RAM is erased to load a new program. All the packets are output waiting to go to 0x01 or 0x06
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x03);

				for(i=0;i<RAM_SIZE;i++) {
					/* All PID are considered dummy PID */
					pParams->pid_flt[demod-1].ram_table[i].command = NONE;
					pParams->pid_flt[demod-1].ram_table[i].address = (u8)(i + 0x10);
					pParams->pid_flt[demod-1].ram_table[i].pid_number = 0;
				}
				for(i=0;i<RAM_SIZE-1;i = (u8)(i + 2)) {
					/* Change all pid to dummy PID */
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->pid_flt[demod-1].ram_table[i].address);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x9FFF >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->pid_flt[demod-1].ram_table[i+1].address);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x9FFF & 0xFF);
				}

				// Activation with DELALL by default (0x01: H/W bug, ClearQuest opened)
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x06);
				
				pParams->pid_flt[demod-1].first_disable_all_command = FALSE;
			} else {
			/* If this is NOT the 1st time we perform this function, then we write only into memory cells in RAM that do not output dummy PID */
			/* Aim is to avoid too much I2C traffic */
				for(i=0;i<RAM_SIZE - 1;i++) {
					if(pParams->pid_flt[demod-1].ram_table[i].command != NONE) {
						/* All PID are considered dummy PID */
						pParams->pid_flt[demod-1].ram_table[i].command = NONE;
						pParams->pid_flt[demod-1].ram_table[i + 1].command = NONE;
						pParams->pid_flt[demod-1].ram_table[i].pid_number = 0;
						pParams->pid_flt[demod-1].ram_table[i + 1].pid_number = 0;
						/* Change all pid to dummy PID */
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->pid_flt[demod-1].ram_table[i].address);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x9FFF >> 8);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[i].address + 1));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x9FFF & 0xFF);
						/* we have dealed with 2 memory cells, so we go further */
						i++;
					}
				}
			}

			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error=FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_changepid_number
--ACTION	::	Changes PID number from pid_inputnumber to pid_outputnumber
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
			pid_inputnumber -> PID number to modify
			pid_outputnumber -> new PID number
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_changepid_number (fe_stid135_handle_t handle,
	enum fe_stid135_demod demod,u32 pid_inputnumber,u32 pid_outputnumber)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, ram_index = 0;
	u16 pid_offset;
	BOOL pid_already_output = FALSE;

	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
			/* Check if pid already output */
			for(i=0;i<RAM_SIZE;i++) {
				if(pParams->pid_flt[demod-1].ram_table[i].pid_number == pid_inputnumber)
				{
					pid_already_output = TRUE;
					ram_index = i;
					break;
				}
			}
			if(pid_already_output == TRUE) {
				/* Compute PID offset */
				if((s32)pid_outputnumber - (s32)pid_inputnumber < 0)
					pid_offset = (pid_outputnumber - pid_inputnumber) & 0x1FFF;
				else
					pid_offset = (u16)(pid_outputnumber - pid_inputnumber);
				/* Change PID number of current PID */
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->pid_flt[demod-1].ram_table[ram_index].address);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), pid_inputnumber >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 1));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), pid_inputnumber & 0xFF);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 2));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), pid_offset >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->pid_flt[demod-1].ram_table[ram_index].address + 3));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), pid_offset & 0xFF);
				
				pParams->pid_flt[demod-1].ram_table[ram_index].command = CHANGE_PID;
			}
			
			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error=FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_enable_gselabel
--ACTION	::	Enables either 3-byte or 6-byte label
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
			gselabel_type -> 3-byte or 6-byte label
			gselabel -> value of label to enable
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_enable_gselabel(fe_stid135_handle_t handle,
    enum fe_stid135_demod demod, enum label_type gselabel_type, u8 gselabel[6])
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, j, k, ram_index;
	BOOL label_already_output = FALSE;
	BOOL ram_full;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error)  
			error = FE_LLA_I2C_ERROR; 
		else {
			/* Check if label already output */
			if(gselabel_type == THREE_BYTE_LABEL) {
				for(i=(RAM_SIZE>>2);i < (RAM_SIZE>>1);i++) {
					if((pParams->gse_flt[demod-1].ram_table[i].label[0] == gselabel[0])
					&& (pParams->gse_flt[demod-1].ram_table[i].label[1] == gselabel[1])
					&& (pParams->gse_flt[demod-1].ram_table[i].label[2] == gselabel[2]))
						label_already_output = TRUE;
				}
			}
			if(gselabel_type == SIX_BYTE_LABEL) {
				for(i=(RAM_SIZE>>1);i < RAM_SIZE;i++) {
					if((pParams->gse_flt[demod-1].ram_table[i].label[0] == gselabel[0])
					&& (pParams->gse_flt[demod-1].ram_table[i].label[1] == gselabel[1])
					&& (pParams->gse_flt[demod-1].ram_table[i].label[2] == gselabel[2])
					&& (pParams->gse_flt[demod-1].ram_table[i].label[3] == gselabel[3])
					&& (pParams->gse_flt[demod-1].ram_table[i].label[4] == gselabel[4])
					&& (pParams->gse_flt[demod-1].ram_table[i].label[5] == gselabel[5]))
						label_already_output = TRUE;
				}
			}
			/* if label not already output */
			if(label_already_output == FALSE) {
				/* Check if DISABLE_3BYTE_LABEL command is in second quarter of RAM */
				for(i=(RAM_SIZE>>2);i < (RAM_SIZE>>1);i++) {
					if(pParams->gse_flt[demod-1].ram_table[i].command == DISABLE_3BYTE_LABEL)
					{
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[i].address);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 >> 8);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 1));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 & 0xFF);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 2));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 3));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 4));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						/* Reflect GSE structure consequently - 6=number of modified bytes in RAM by this function */
						for(j=0;j<6;j++) {
							for(k=0;k<6;k++)
								pParams->gse_flt[demod-1].ram_table[i+j].label[k] = 0;
							pParams->gse_flt[demod-1].ram_table[i+j].command = NO_CMD;
						}
						/* Go to 6 address locations forward to avoid rewrite of memory cells */
						i = (u8)(i + 5); /* not 6 because of presence of i++ in loop */
					}
				}
				/* Check if DISABLE_6BYTE_LABEL command is in second half of RAM */
				for(i=(RAM_SIZE>>1);i < RAM_SIZE;i++) {
					if(pParams->gse_flt[demod-1].ram_table[i].command == DISABLE_6BYTE_LABEL) {
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[i].address);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 >> 8);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 1));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 & 0xFF);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 2));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 3));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 4));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 6));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 7));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						/* Reflect GSE structure consequently - 6=number of modified bytes in RAM by this function */
						for(j=0;j<8;j++) {
							for(k=0;k<6;k++)
								pParams->gse_flt[demod-1].ram_table[i+j].label[k] = 0;
							pParams->gse_flt[demod-1].ram_table[i+j].command = NO_CMD;
						}
						/* Go to 8 address locations forward to avoid rewrite of memory cells */
						i = (u8)(i + 7); /* not 8 because of presence of i++ in loop */
					}
				}
				if(gselabel_type == THREE_BYTE_LABEL) {
					/* Go to first free RAM location */
					ram_index = 0;
					for(i=(RAM_SIZE>>2);i <= (RAM_SIZE>>1) - 6;i++) { // check in second quarter of RAM
						if((pParams->gse_flt[demod-1].ram_table[i].command == NO_CMD) || (pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_ALL_3BYTE_LABEL)){
							ram_index = i;
							break;
						}
					}
					if((ram_index == 0) && (i == (RAM_SIZE>>1) - 6 + 1))
						ram_full = TRUE;
					else
						ram_full = FALSE;
					/* Check if there is enough memory space */
					if((ram_index <= (RAM_SIZE>>1) - 6) && (ram_full == FALSE)){ // check in second quarter of RAM & if RAM not full
						/* Enable protocol command takes exactly 6 bytes for 3-byte label */
						/* We output 3-byte label */
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[ram_index].address);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 >> 8);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 1));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 & 0xFF);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 2));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), gselabel[1]);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 3));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), gselabel[0]);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 4));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), gselabel[2]);
						// Activation with DELALL by default (0x01: H/W bug, ClearQuest opened)
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x01);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTC(demod), 0x08);
						/* Reflect GSE structure consequently */
						for(i=0;i<6;i++) {
							for(j=0;j<3;j++)
								pParams->gse_flt[demod-1].ram_table[ram_index+i].label[j] = gselabel[j];
							pParams->gse_flt[demod-1].ram_table[ram_index+i].command = ENABLE_3BYTE_LABEL;
						}
					}
				}
				
				if(gselabel_type == SIX_BYTE_LABEL) {
					/* Go to first free RAM location */
					ram_index = 0;
					for(i=(RAM_SIZE>>1);i <= RAM_SIZE - 8;i++) { // check in second half of RAM
						if((pParams->gse_flt[demod-1].ram_table[i].command == NO_CMD) || (pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_ALL_6BYTE_LABEL)){
							ram_index = i;
							break;
						}
					}
					if((ram_index == 0) && (i == RAM_SIZE - 8 + 1))
						ram_full = TRUE;
					else
						ram_full = FALSE;
					/* Check if there is enough memory space */
					if((ram_index <= RAM_SIZE - 8) && (ram_full == FALSE)){ // check in second half of RAM & if RAM not full
						/* Enable protocol command takes exactly 8 bytes for 6-byte label */
						/* We output 6-byte label */
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[ram_index].address);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 >> 8);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 1));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 & 0xFF);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 2));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), gselabel[1]);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 3));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), gselabel[0]);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 4));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), gselabel[3]);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), gselabel[2]);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 6));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), gselabel[5]);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 7));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), gselabel[4]);
						// Activation with DELALL by default (0x01: H/W bug, ClearQuest opened)
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x01);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTC(demod), 0x08);
						/* Reflect GSE structure consequently */
						for(i=0;i<8;i++) {
							for(j=0;j<6;j++)
								pParams->gse_flt[demod-1].ram_table[ram_index+i].label[j] = gselabel[j];
							pParams->gse_flt[demod-1].ram_table[ram_index+i].command = ENABLE_6BYTE_LABEL;
						}
					}
				}
			}
			//Check the error at the end of the function
			if (pParams->handle_demod->Error)
				error = FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_enable_protocoltype
--ACTION	::	Enables protocol type GSE frame
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
			protocoltype -> value of protocol to enable
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_enable_protocoltype(fe_stid135_handle_t handle,
 	enum fe_stid135_demod demod, u16 protocoltype)
{
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, j, ram_index = 0, ram_full;
	BOOL protocol_already_output = FALSE;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error = FE_LLA_I2C_ERROR;
		else {
			/* Check if protocol already output */
			for(i=0;i < (RAM_SIZE>>1);i++) {
				if((pParams->gse_flt[demod-1].ram_table[i].protocol_number == protocoltype) && (pParams->gse_flt[demod-1].ram_table[i].command != NO_CMD))
					protocol_already_output = TRUE;
			}
			/* if protocol not already output */
			if(protocol_already_output == FALSE) {
				/* Check if DISABLE_ALL_PROTOCOL command is in RAM */
				for(i=0;i < (RAM_SIZE>>2);i++) { // we check if protocol is already in first quarter of RAM
					if(pParams->gse_flt[demod-1].ram_table[i].command == DISABLE_ALL_PROTOCOL)
					{
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[i].address);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 >> 8);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 1));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 & 0xFF);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 2));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 3));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 4));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						/* Reflect GSE structure consequently - 6=number of modified bytes in RAM by this function */
						for(j=0;j<6;j++) {
							pParams->gse_flt[demod-1].ram_table[i+j].protocol_number = 0;
							pParams->gse_flt[demod-1].ram_table[i+j].command = NO_CMD;
						}
						/* Go to 6 address locations forward to avoid rewrite of memory cells */
						i = (u8)(i + 5); /* not 6 because of presence of i++ in loop */
					}
				}
				/* Go to first free RAM location */
				for(i=0;i < (RAM_SIZE>>2) - 6;i++) { // check in first quarter of RAM
					if((pParams->gse_flt[demod-1].ram_table[i].command == NO_CMD) || (pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_ALL_PROTOCOL)) {
						ram_index = i;
						break;
					}
				}
				if((ram_index == 0) && (i == (RAM_SIZE>>2) - 6))
					ram_full = TRUE;
				else
					ram_full = FALSE;
				
				/* Check if there is enough memory space */
				//if(ram_index <= (RAM_SIZE>>1) - 12) {
				if((ram_index <= (RAM_SIZE>>2) - 12) && (ram_full == FALSE)){ // check in first quarter of RAM & if RAM not full
					/* Enable protocol command takes exactly 6 bytes for 3/6-byte label protocol and 6 bytes for broadcast protocol */
					/* We output 3/6-byte label protocol */
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[ram_index].address);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 1));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 2));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), protocoltype >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 3));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), protocoltype & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 4));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 5));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					/* We output broadcast protocol */
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 6));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0540 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 7));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0540 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 8));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), protocoltype >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 9));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), protocoltype & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 10));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 11));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					// Activation with DELALL by default (0x01: H/W bug, ClearQuest opened)
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x01);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTC(demod), 0x08);
					/* Reflect GSE structure consequently */
					for(i=0;i<12;i++) {
						pParams->gse_flt[demod-1].ram_table[ram_index+i].protocol_number = protocoltype;
						pParams->gse_flt[demod-1].ram_table[ram_index+i].command = ENABLE_PROTOCOL;
					}
				}
			}
			//Check the error at the end of the function
			if (pParams->handle_demod->Error)
				error = FE_LLA_I2C_ERROR; 
		}
}
	return error;		
}

/*****************************************************
--FUNCTION	::	fe_stid135_disable_gselabel
--ACTION	::	Disables either 3-byte or 6-byte label
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
			gselabel -> value of label to enable
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_disable_gselabel(fe_stid135_handle_t handle,
  enum fe_stid135_demod	demod, u8 gselabel[6])
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, j, ram_index = 0;
	enum label_type gselabel_type = THREE_BYTE_LABEL;
	BOOL label_already_output = FALSE;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		/* Check if label already output */
		for(i=(RAM_SIZE>>2);i < (RAM_SIZE>>1);i++) {
			if((pParams->gse_flt[demod-1].ram_table[i].label[0] == gselabel[0])
			&& (pParams->gse_flt[demod-1].ram_table[i].label[1] == gselabel[1])
			&& (pParams->gse_flt[demod-1].ram_table[i].label[2] == gselabel[2])) {
				label_already_output = TRUE;
				gselabel_type = THREE_BYTE_LABEL;
				ram_index = i;
				break;
			}
		}
		for(i=(RAM_SIZE>>1);i < RAM_SIZE;i++) {
			if((pParams->gse_flt[demod-1].ram_table[i].label[0] == gselabel[0])
			&& (pParams->gse_flt[demod-1].ram_table[i].label[1] == gselabel[1])
			&& (pParams->gse_flt[demod-1].ram_table[i].label[2] == gselabel[2])
			&& (pParams->gse_flt[demod-1].ram_table[i].label[3] == gselabel[3])
			&& (pParams->gse_flt[demod-1].ram_table[i].label[4] == gselabel[4])
			&& (pParams->gse_flt[demod-1].ram_table[i].label[5] == gselabel[5])) {
				label_already_output = TRUE;
				gselabel_type = SIX_BYTE_LABEL;
				ram_index = i;
				break;
			}
		}
		/* if label already output */
		if(label_already_output == TRUE) {
			if(gselabel_type == THREE_BYTE_LABEL) {
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[ram_index].address);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 1));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 & 0xFF);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 2));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 3));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 4));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 5));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				/* Reflect GSE structure consequently */
				for(i=0;i<6;i++) {
					for(j=0;j<3;j++)
						pParams->gse_flt[demod-1].ram_table[ram_index+i].label[j] = 0;
					pParams->gse_flt[demod-1].ram_table[ram_index+i].command = NO_CMD;
				}
			}
			if(gselabel_type == SIX_BYTE_LABEL) {
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[ram_index].address);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 1));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 & 0xFF);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 2));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 3));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 4));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 5));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 6));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 7));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				/* Reflect GSE structure consequently */
				for(i=0;i<8;i++) {
					for(j=0;j<6;j++)
						pParams->gse_flt[demod-1].ram_table[ram_index+i].label[j] = 0;
					pParams->gse_flt[demod-1].ram_table[ram_index+i].command = NO_CMD;
				}
			}
			
			// Activation with DELALL by default (0x01: H/W bug, ClearQuest opened)
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x06);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTC(demod), 0x08);
			
			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error = FE_LLA_I2C_ERROR;
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_disable_protocoltype
--ACTION	::	Disables protocol type GSE frame
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
			protocoltype -> value of protocol to enable
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_disable_protocoltype(fe_stid135_handle_t handle,
 enum fe_stid135_demod demod, u16 protocoltype)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, j, ram_index = 0;
	BOOL protocol_already_output = FALSE;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error = FE_LLA_I2C_ERROR; 
		else {
			/* Check if protocol already output */
			for(i=0;i < (RAM_SIZE>>1);i++) {
				if((pParams->gse_flt[demod-1].ram_table[i].protocol_number == protocoltype) && (pParams->gse_flt[demod-1].ram_table[i].command != NO_CMD))
				{
					protocol_already_output = TRUE;
					ram_index = i;
					break;
				}
			}
			
			if(protocol_already_output == TRUE) {
				/* Check if DISABLE_ALL_PROTOCOL command is in RAM : REALLY MANDATORY ??? */
				for(i=0;i < (RAM_SIZE>>2);i++) { // check in first quarter of RAM
					if(pParams->gse_flt[demod-1].ram_table[i].command == DISABLE_ALL_PROTOCOL)
					{
						/* Change from disable all protocols to room booking */
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[i].address);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x6500 >> 8);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 1));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x6500 & 0xFF);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 2));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 3));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 4));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						/* Reflect GSE structure consequently */
						for(j=0;j<6;j++) {
							pParams->gse_flt[demod-1].ram_table[i+j].protocol_number = 0;
							pParams->gse_flt[demod-1].ram_table[i+j].command = NO_CMD;
						}
					}
				}
				/* Change protocol already output to room booking */
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[ram_index].address);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 1));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 & 0xFF);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 2));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 3));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 4));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 5));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 6));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0540 >> 8);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 7));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0540 & 0xFF);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 8));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 9));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 10));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[ram_index].address + 11));
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
				// Activation with DELALL by default (0x01: H/W bug, ClearQuest opened)
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x06);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTC(demod), 0x08);
				/* Reflect GSE structure consequently */
				for(i=0;i<12;i++) {
					pParams->gse_flt[demod-1].ram_table[ram_index+i].protocol_number = 0;
					pParams->gse_flt[demod-1].ram_table[ram_index+i].command = NO_CMD;
				}
}
			
			//Check the error at the end of the function
			if (pParams->handle_demod->Error)
				error = FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_enable_allgselabel
--ACTION	::	Enables all label GSE frame
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_enable_allgselabel(fe_stid135_handle_t handle,
        enum fe_stid135_demod	demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, j, k;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error = FE_LLA_I2C_ERROR; 
		else {
			/* Search all 3-byte label already output */
			for(i=(RAM_SIZE>>2);i < (RAM_SIZE>>1) - 6;i++) { // check in second quarter of RAM
				if(pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_3BYTE_LABEL) {
					/* Change 3-byte label already output to dummy label */
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[i].address);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 1));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 2));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 3));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 4));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 6));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 7));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 8));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 9));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 10));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 11));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					/* Reflect GSE structure consequently */
					for(j=0;j<12;j++) {
						for(k=0;k<6;k++)
							pParams->gse_flt[demod-1].ram_table[i+j].label[k] = 0;
						pParams->gse_flt[demod-1].ram_table[i+j].command = NO_CMD;
					}
					/* Go to 12 address locations forward to avoid rewrite of memory cells*/
					i = (u8)(i + 11); /* not 12 because of presence of i++ in loop */
				}
}
			/* Search all 6-byte label already output */
			for(i=(RAM_SIZE>>1);i < RAM_SIZE - 6;i++) { // check in second half of RAM
				if(pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_6BYTE_LABEL) {
					/* Change 3-byte label already output to dummy label */
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[i].address);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 1));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 2));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 3));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 4));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 6));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 7));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 8));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 9));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 10));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 11));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 12));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 13));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 14));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 15));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					/* Reflect GSE structure consequently */
					for(j=0;j<16;j++) {
						for(k=0;k<6;k++)
							pParams->gse_flt[demod-1].ram_table[i+j].label[k] = 0;
						pParams->gse_flt[demod-1].ram_table[i+j].command = NO_CMD;
					}
					/* Go to 16 address locations forward to avoid rewrite of memory cells*/
					i = (u8)(i + 15); /* not 16 because of presence of i++ in loop */
				}
			}
			/* Output labels different from zero ie output all 3-byte label */
			/* Set RAM pointer to first free RAM cell of second quarter of RAM */
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x10+(RAM_SIZE>>2));
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x1320 >> 8);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x1320 & 0xFF);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			
			/* Output labels different from zero ie output all 6-byte label */
			/* Set RAM pointer to first free RAM cell of second hald of RAM */
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x10+(RAM_SIZE>>1));
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x1720 >> 8);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x1720 & 0xFF);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			
			for(i=(RAM_SIZE>>2);i<6+(RAM_SIZE>>2);i++) {
				for(k=0;k<6;k++)
					pParams->gse_flt[demod-1].ram_table[i].label[k] = 0;
				pParams->gse_flt[demod-1].ram_table[i].command = ENABLE_ALL_3BYTE_LABEL;
			}
			for(i=(RAM_SIZE>>1);i<8+(RAM_SIZE>>1);i++) {
				for(k=0;k<6;k++)
					pParams->gse_flt[demod-1].ram_table[i].label[k] = 0;
				pParams->gse_flt[demod-1].ram_table[i].command = ENABLE_ALL_6BYTE_LABEL;
			}
			// Activation with DELALL by default (0x01: H/W bug, ClearQuest opened)
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x06);
			
			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error = FE_LLA_I2C_ERROR;
		}
	}
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_disable_allgselabel
--ACTION	::	Disables all label GSE frame
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_disable_allgselabel (fe_stid135_handle_t handle,
		enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, j, k;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error = FE_LLA_I2C_ERROR; 
		else {
			/* If this is the 1st time after power-up we perform this function, then we reset members of gse structure */
			if(pParams->gse_flt[demod-1].first_disable_all_label_command == TRUE) {
				for(i=0;i < RAM_SIZE;i++) {
					pParams->gse_flt[demod-1].ram_table[i].address = (u8)(i + 0x10);
				}
				for(i=(RAM_SIZE>>2); i <= (RAM_SIZE>>1);i++) { // fill-in second quarter of RAM
					pParams->gse_flt[demod-1].ram_table[i].command = NO_CMD;
					for(j=0;j<6;j++)
						pParams->gse_flt[demod-1].ram_table[i].label[j] = 0;
				}
				for(i=(RAM_SIZE>>1); i < RAM_SIZE;i++) { // fill-in second quarter of RAM
					pParams->gse_flt[demod-1].ram_table[i].command = NO_CMD;
					for(j=0;j<6;j++)
						pParams->gse_flt[demod-1].ram_table[i].label[j] = 0;
				}
				pParams->gse_flt[demod-1].first_disable_all_label_command = FALSE;
				/* 192bytes/4/6 because 3-byte labels are only on second quarter and command on 6 bytes */
				for(i=(RAM_SIZE>>2);i <= (RAM_SIZE>>1) - 6;i++) {
					/* Set RAM pointer to the beginning of the second quarter */
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(0x10+i));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					/* Go to 6 address locations forward to avoid rewrite of memory cells */
					i = (u8)(i + 5); /* not 6 because of presence of i++ in loop */
				}
				/* 192bytes/2/6 because 6-byte labels are only on second half and command on 8 bytes */
				for(i=(RAM_SIZE>>1);i <= (11*RAM_SIZE/12) - 8;i++) {
					/* Set RAM pointer to the beginning of the second half */
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(0x10+i));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					/* Go to 8 address locations forward to avoid rewrite of memory cells */
					i = (u8)(i + 7); /* not 8 because of presence of i++ in loop */
				}
			} else {
				/* Search all 3-byte label already output */
				for(i=(RAM_SIZE>>2);i <= (RAM_SIZE>>1) - 6;i++) { // check in second quarter of RAM
					if((pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_3BYTE_LABEL) || (pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_ALL_3BYTE_LABEL)) {
						/* Output dummy 3-byte label */
						/* Output 3-byte label 0x000000 instead */
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[i].address);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 >> 8);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 1));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0720 & 0xFF);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 2));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 3));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 4));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						/* Reflect GSE structure consequently */
						for(j=0;j<6;j++) {
							for(k=0;k<3;k++)
								pParams->gse_flt[demod-1].ram_table[i+j].label[k] = 0;
							pParams->gse_flt[demod-1].ram_table[i+j].command = NO_CMD;
						}
						/* Go to 6 address locations forward to avoid rewrite of memory cells */
						i = (u8)(i + 5); /* not 6 because of presence of i++ in loop */
					}
				}
				/* Search all 6-byte label already output */
				for(i=(RAM_SIZE>>1);i <= (11*RAM_SIZE/12) - 8;i++) { // check in second half of RAM
					if((pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_6BYTE_LABEL) || (pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_ALL_6BYTE_LABEL)) {
						/* Output dummy 6-byte label */
						/* Output 6-byte label 0x000000000000 instead */
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[i].address);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 >> 8);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 1));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0320 & 0xFF);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 2));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 3));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 4));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						/* Reflect GSE structure consequently */
						for(j=0;j<8;j++) {
							for(k=0;k<3;k++)
								pParams->gse_flt[demod-1].ram_table[i+j].label[k] = 0;
							pParams->gse_flt[demod-1].ram_table[i+j].command = NO_CMD;
						}
						/* Go to 6 address locations forward to avoid rewrite of memory cells */
						i = (u8)(i + 7); /* not 8 because of presence of i++ in loop */
					}
				}
			}
			// Activation with DELALL by default (0x01: H/W bug, ClearQuest opened)
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x06);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTC(demod), 0x08);
		}
		//Check the error at the end of the function
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR;
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_enable_allprotocoltype
--ACTION	::	Enables all protocol GSE frame
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_enable_allprotocoltype(fe_stid135_handle_t handle,
  enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, j/*, ram_index = 0*/;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error = FE_LLA_I2C_ERROR; 
		else {
			/* Search all protocol already output */
			for(i=0;i < (RAM_SIZE>>2) - 6;i++) { // check in first quarter of RAM
				if(pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_PROTOCOL) {
					/* Change protocol already output to room booking */
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[i].address);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 1));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 2));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 3));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 4));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 6));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 7));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 8));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 9));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 10));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 11));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					/* Reflect GSE structure consequently */
					for(j=0;j<12;j++) {
						pParams->gse_flt[demod-1].ram_table[i+j].protocol_number = 0;
						pParams->gse_flt[demod-1].ram_table[i+j].command = NO_CMD;
					}
					/* Go to 6 address locations forward to avoid rewrite of memory cells*/
					i = (u8)(i + 11); /* not 12 because of presence of i++ in loop */
				}
			}			
			/* Output protocols different from zero ie output all 3/6-byte label protocols */
			/* Set RAM pointer to first free RAM cell */
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x10);
			/* Output protocols different from zero ie output all 3/6-byte label protocols */
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x1520 >> 8);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x1520 & 0xFF);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			/* Output protocols different from zero ie output all broadcast protocols */
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x1540 >> 8);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x1540 & 0xFF);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			for(i=0;i<12;i++) {
				pParams->gse_flt[demod-1].ram_table[i].protocol_number = 0;
				pParams->gse_flt[demod-1].ram_table[i].command = ENABLE_ALL_PROTOCOL;
			}
			// Activation with DELALL by default (0x01: H/W bug, ClearQuest opened)
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x06);
			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error = FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_disable_allprotocoltype
--ACTION	::	Disables all protocol GSE frame
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_disable_allprotocoltype(fe_stid135_handle_t handle,
    enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, j;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error = FE_LLA_I2C_ERROR; 
		else {
			/* If this is the 1st time after power-up we perform this function, then we reset members of gse structure */
			if(pParams->gse_flt[demod-1].first_disable_all_protocol_command == TRUE) {
				for(i=0;i < (RAM_SIZE>>2);i++) { // check in first quarter of RAM
					pParams->gse_flt[demod-1].ram_table[i].command = NO_CMD;
					pParams->gse_flt[demod-1].ram_table[i].address = (u8)(i + 0x10);
					pParams->gse_flt[demod-1].ram_table[i].protocol_number = 0;
				}
				for(i=(RAM_SIZE>>2);i < RAM_SIZE;i++) {
					pParams->gse_flt[demod-1].ram_table[i].address = (u8)(i + 0x10);
				}
				pParams->gse_flt[demod-1].first_disable_all_protocol_command = FALSE;
				/* RAM start from 0x10, not from 0x00 */
				/* Set RAM pointer to the beginning */
				/* 192bytes/4/6 because protocols are only on first quarter and command on 6 bytes */
				for(i=0;i < (RAM_SIZE>>2);i++) {
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(0x10 + i));
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 >> 8);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 & 0xFF);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
					/* Go to 6 address locations forward to avoid rewrite of memory cells */
					i = (u8)(i + 5); /* not 6 because of presence of i++ in loop */
				}
			} else {
				/* Search all protocol already output */
				for(i=0;i <= (RAM_SIZE>>2) - 6;i++) { // check in first quarter of RAM
				if((pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_PROTOCOL) || (pParams->gse_flt[demod-1].ram_table[i].command == ENABLE_ALL_PROTOCOL)) {
						/* Change protocol already output to room booking */
						/* not room booking, but output protocol 0x0000 instead */
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), pParams->gse_flt[demod-1].ram_table[i].address);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 >> 8);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 1));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x0520 & 0xFF);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 2));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 3));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 4));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), (u32)(pParams->gse_flt[demod-1].ram_table[i].address + 5));
						error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
						/* Reflect GSE structure consequently */
						for(j=0;j<6;j++) {
							pParams->gse_flt[demod-1].ram_table[i+j].protocol_number = 0;
							pParams->gse_flt[demod-1].ram_table[i+j].command = NO_CMD;
						}
						/* Go to 6 address locations forward to avoid rewrite of memory cells */
						i = (u8)(i + 5); /* not 6 because of presence of i++ in loop */
					}
				}
			}
			// Activation with DELALL by default (0x01: H/W bug, ClearQuest opened)
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x06);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTC(demod), 0x08);
			
			//Check the error at the end of the function
			if (pParams->handle_demod->Error )
				error = FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_select_ncr_source
--ACTION	::	Outputs NCR on TSout0
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_select_ncr_source(fe_stid135_handle_t handle,
          enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
#ifdef USER1
			/* Select which TS has to be copied on TSout0 (TSmux) */
			error |= ChipSetField(pParams->handle_soc, FLD_FSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG160_TSMUX_SEL, (s32)(demod - 1));
			/* RCS feature association to selected demod - new management of NCR */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSRCSSEL_TSRCS_SEL, (s32)(demod - 1));
#else
			/* Set stream output frequency */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG1_TSFIFO_MANSPEED(demod), 0);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSSPEED(demod), 0x04);
			/* Make SUBNCR0 signal longer */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSRCSCFG_NCROUT_CLKLEN(demod), 2);
			/* Added a sync byte to trigg on when sniffing packets */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSINSDELH_TSINSDEL_SYNCBYTE(demod), 1);
			/* Do not embed in DVB NCR packets! */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_EMBINDVB(demod), 0);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATE1_TSOUT_NOSYNC(demod), 1);
#endif
		}
	}
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_unselect_ncr
--ACTION	::	Do not output anymore NCR on TSout0
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_unselect_ncr(fe_stid135_handle_t handle,
          enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
			/* Unselect which TS has to be copied on TSout0 (TSmux) */
			error |= ChipSetField(pParams->handle_soc, FLD_FSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG160_TSMUX_SEL, 0);
			
			/* Remove RCS feature association to demod - new management of NCR */
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_TOP_CTRL_TSRCSSEL, 0);
			
			/* Set default value for SUBNCR0 signal */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSRCSCFG_NCROUT_CLKLEN(demod), 0);
		}
	}
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_get_ncr_lock_status
--ACTION	::	Gets status of NCR
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
-PARAMS OUT	::	NCR status 
--RETURN	::	error
--***************************************************/
fe_lla_error_t fe_stid135_get_ncr_lock_status(fe_stid135_handle_t handle,
          enum fe_stid135_demod demod, BOOL* ncr_lock_status_p)
{
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	
	s32 fld_value[2];
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	*ncr_lock_status_p = FALSE; 
	
	if(pParams != NULL) {
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS3_PCRCALC_NCRREADY(demod), &(fld_value[0]));
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSSTATUS3_PCRCALC_ERROR(demod), &(fld_value[1])) ;
		if((fld_value[0] == 2) && (fld_value[1] == 0x0))
			*ncr_lock_status_p = TRUE;
		else
			*ncr_lock_status_p = FALSE;
	} else {
		*ncr_lock_status_p = FALSE;
	}
	return(error);
}

/*
fe_lla_error_t fe_stid135_enable_irq (stchip_handle_t handle,
      fe_stid135_irq_t irq_list)
{
}
fe_lla_error_t fe_stid135_disable_irq (stchip_handle_t handle,
        fe_stid135_irq_t irq_list)
{
}
*/

/*****************************************************
--FUNCTION	::	fe_stid135_set_ts_parallel_serial
--ACTION	::	Sets PIOs according to wanted TS mode
--PARAMS IN	::	handle -> Pointer to the chip structure
			demod -> Current demod 1..8
			ts_mode -> TS mode for instance serial, parallel...
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_ts_parallel_serial(fe_stid135_handle_t handle, enum fe_stid135_demod demod, enum fe_ts_output_mode ts_mode)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	u32 reg_value;
	
	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
		 	switch(ts_mode) {
				case FE_TS_SERIAL_PUNCT_CLOCK:
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_SERIAL(demod), 1); /* Serial mode */
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(demod), 0);  /* punctured clock */
					error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSCFG2(demod), 1);
					if(demod == FE_SAT_DEMOD_1) {
						// Setting alternate function 2 from PIO4_0 to PIO4_2
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1001, &reg_value);
						reg_value |= 0x00000222;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1001, reg_value);
						
						// Setting output enable from PIO4_0 to PIO4_2
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
						reg_value |= 0x00000700;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
							
						// Setting clk not data for PIO4_0
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1108, &reg_value);
						reg_value |= 0x00000004;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1108, reg_value);
					}
					else if(demod == FE_SAT_DEMOD_2) {
						// Setting alternate function 2 from PIO4_3 to PIO4_5
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1001, &reg_value);
						reg_value |= 0x00222000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1001, reg_value);
						
						// Setting output enable from PIO4_3 to PIO4_5
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
						reg_value |= 0x00003800;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
							
						// Setting clk not data for PIO4_3
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1111, &reg_value);
						reg_value |= 0x00000004;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1111, reg_value);
					}
					else if(demod == FE_SAT_DEMOD_3) {
						// Setting alternate function 2 from PIO5_0 to PIO5_2
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, &reg_value);
						reg_value |= 0x00000222;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, reg_value);
						
						// Setting output enable from PIO5_0 to PIO5_2
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
						reg_value |= 0x00070000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
							
						// Setting clk not data for PIO5_0
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1116, &reg_value);
						reg_value |= 0x00000004;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1116, reg_value);
					}
					else if(demod == FE_SAT_DEMOD_4) {
						// Setting alternate function 2 from PIO5_3 to PIO5_5
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, &reg_value);
						reg_value |= 0x00222000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, reg_value);
						
						// Setting output enable from PIO5_3 to PIO5_5
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
						reg_value |= 0x00380000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
							
						// Setting clk not data for PIO5_3
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1119, &reg_value);
						reg_value |= 0x00000004;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1119, reg_value);
					}
					else if(demod == FE_SAT_DEMOD_5) {
						// Setting alternate function 2 from PIO6_0 to PIO6_2
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, &reg_value);
						reg_value |= 0x00000222;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, reg_value);
						
						// Setting output enable from PIO6_0 to PIO6_2
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
						reg_value |= 0x07000000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
							
						// Setting clk not data for PIO6_0
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1124, &reg_value);
						reg_value |= 0x00000004;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1124, reg_value);
					}
					else if(demod == FE_SAT_DEMOD_6) {
						// Setting alternate function 2 from PIO6_3 to PIO6_5
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, &reg_value);
						reg_value |= 0x00222000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, reg_value);
						
						// Setting output enable from PIO6_3 to PIO6_5
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
						reg_value |= 0x38000000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
							
						// Setting clk not data for PIO6_3
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1127, &reg_value);
						reg_value |= 0x00000004;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1127, reg_value);
					}
					else if(demod == FE_SAT_DEMOD_7) {
						// Setting alternate function 2 from PIO7_0 to PIO7_2
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, &reg_value);
						reg_value |= 0x00000222;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, reg_value);
						
						// Setting output enable from PIO7_0 to PIO7_2
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, &reg_value);
						reg_value |= 0x07000000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, reg_value);
							
						// Setting clk not data for PIO7_0
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1124, &reg_value);
						reg_value |= 0x00000004;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1124, reg_value);
					}
					else if(demod == FE_SAT_DEMOD_8) {
						// Setting alternate function 2 from PIO7_3 to PIO7_5
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, &reg_value);
						reg_value |= 0x00222000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, reg_value);
						
						// Setting output enable from PIO7_3 to PIO7_5
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, &reg_value);
						reg_value |= 0x38000000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, reg_value);
							
						// Setting clk not data for PIO7_3
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1127, &reg_value);
						reg_value |= 0x00000004;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1127, reg_value);
					}
					// Disable leaky packet mechanism, the bandwidth is free to be as low as possible
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPIDFLTC_PIDFLT_LEAKPKT(demod), 0);
					// Remove bug fix: workaround of BZ#98230: bad sampling of data[3] of TS bus
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(demod), 0);
				break;
				
				case FE_TS_SERIAL_CONT_CLOCK:
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_SERIAL(demod), 1); /* Serial mode */
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(demod), 1);  /* continues clock */
					error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSCFG2(demod), 1);

#if 1
					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1000, &reg_value);
					reg_value |= 0x00001111;
					error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1000, reg_value);

					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1001, &reg_value);
					if(reg_value!=0x00111111){
						reg_value |= 0x00111111;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1001, reg_value);
					}

					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, &reg_value);
					if(reg_value!=0x00111111){
						reg_value |= 0x00111111;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, reg_value);
					}

					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, &reg_value);
					if(reg_value!=0x00111111){
						reg_value |= 0x00111111;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, reg_value);
					}

					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, &reg_value);
					if(reg_value!=0x00111111){
						reg_value |= 0x00111111;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, reg_value);
					}

					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
					if(reg_value!=0x3F3F3F00){
						reg_value |= 0x3F3F3F00;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
					}
					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, &reg_value);
					if(reg_value!=0x3F000000){
						reg_value |= 0x3F000000;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, reg_value);
					}

					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1050, &reg_value);
					if(reg_value!=0xFF000000){
						reg_value |= 0xFF000000;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1050, reg_value);
					}

					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1108, &reg_value);
					if(reg_value!=0x00000004){
						reg_value |= 0x00000004;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1108, reg_value);
					}

					// Setting clk not data for PIO4_3
					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1111, &reg_value);
					if(reg_value!=0x00000004){
						reg_value |= 0x00000004;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1111, reg_value);
					}
					// Setting clk not data for PIO5_0
					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1116, &reg_value);
					if(reg_value!=0x00000004){
						reg_value |= 0x00000004;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1116, reg_value);
					}
					// Setting clk not data for PIO5_3
					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1119, &reg_value);
					if(reg_value!=0x00000004){
						reg_value |= 0x00000004;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1119, reg_value);
					}
					// Setting clk not data for PIO5_3
					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1119, &reg_value);
					if(reg_value!=0x00000004){
						reg_value |= 0x00000004;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1119, reg_value);
					}
					// Setting clk not data for PIO6_0
					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1124, &reg_value);
					if(reg_value!=0x00000004){
						reg_value |= 0x00000004;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1124, reg_value);
					}
					// Setting clk not data for PIO6_3
					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1127, &reg_value);
					if(reg_value!=0x00000004){
						reg_value |= 0x00000004;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1127, reg_value);
					}
					// Setting clk not data for PIO7_0
					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1124, &reg_value);
					if(reg_value!=0x00000004){
						reg_value |= 0x00000004;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1124, reg_value);
					}
					// Setting clk not data for PIO7_3
					error = ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1127, &reg_value);
					if(reg_value!=0x00000004){
						reg_value |= 0x00000004;
						error = ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1127, reg_value);
					}
#endif
					
					// Disable leaky packet mechanism, the bandwidth is free to be as low as possible
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPIDFLTC_PIDFLT_LEAKPKT(demod), 0);
					// Remove bug fix: workaround of BZ#98230: bad sampling of data[3] of TS bus
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(demod), 0);
				break;
				
				case FE_TS_PARALLEL_PUNCT_CLOCK:		
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_SERIAL(demod), 0); /* Parallel mode */
					//error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(demod), 0);  /* punctured clock */
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(demod), 1);  /* contiunous clock */
					error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSCFG2(demod), 1);
					/* Only demod#1 and demod#3 are able to output on SOC PIOs
					It is a FPGA choice/limitation
					One option to output any demod to SOC PIOs is to use mux
					between demod and packet delineator */
					if(demod == FE_SAT_DEMOD_1) {
						// Setting alternate function 4 from PIO4_0 to PIO4_5
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1001, 0x00444444);
						// Setting alternate function 4 from PIO5_0 to PIO5_5
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, 0x00444444);
									
						// Setting output enable from PIO4_0 to PIO4_5 and from PIO5_0 to PIO5_5
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
						reg_value |= 0x003F3F00;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
							
						// Setting clk not data for PIO4_0
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1108, 0x00000004);
									
						// Setting data not clk for PIO4_3, PIO5_0 and PIO5_3
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1111, 0x00000000);
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1116, 0x00000000);
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1119, 0x00000000);
					}
					if(demod == FE_SAT_DEMOD_3) {
						// Setting alternate function 4 from PIO6_0 to PIO6_5
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, 0x00444444);
						// Setting alternate function 4 from PIO7_0 to PIO7_5
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, 0x00444444);
				
						// Setting output enable from PIO6_0 to PIO6_5
						error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
						reg_value |= 0x3F000000;
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
						// Setting output enable from PIO7_0 to PIO7_5
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, 0x3F000000);
				
						// Setting clk not data for PIO6_0 (normally 0x4, but bug, workaround = 0x6)
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1124, 0x00000006);
				
						// Setting data not clk for PIO6_3, PIO7_0 and PIO7_3
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1127, 0x00000000);
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1123, 0x00000000);
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1127, 0x00000000);
					}
					// Disable leaky packet mechanism, the bandwidth is free to be as low as possible
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPIDFLTC_PIDFLT_LEAKPKT(demod), 0);
					// Bug fix: workaround of BZ#98230: bad sampling of data[3] of TS bus
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(demod), 3);
				break;
				
				case FE_TS_DVBCI_CLOCK:
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_SERIAL(demod), 0); /* Parallel mode */
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(demod), 1);  /* continues clock */
					error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSCFG2(demod), 1);
					// Disable leaky packet mechanism, the bandwidth is free to be as low as possible
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPIDFLTC_PIDFLT_LEAKPKT(demod), 0);
					// Remove bug fix: workaround of BZ#98230: bad sampling of data[3] of TS bus
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(demod), 0);
				break;
		
				case FE_TS_PARALLEL_ON_TSOUT_0:
					// Setting alternate function 3 from PIO4_0 to PIO4_5
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1001, 0x00333333);
					// Setting alternate function 3 from PIO5_0 to PIO5_5
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, 0x00333333);
								
					// Setting output enable from PIO4_0 to PIO4_5 and from PIO5_0 to PIO5_5
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
					reg_value |= 0x003F3F00;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, /*0x003F3F00*/reg_value);
						
					// Setting clk not data for PIO4_0 and clock inversion (BZ#75008)
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1108, 0x00000205);
								
					// Setting data not clk for pio from PIO4_1 to PIO4_5 and for pio from PIO5_0 to PIO5_4, and choose STFE clock as a clock source for retime block
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1109, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1110, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1111, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1112, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1113, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1116, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1117, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1118, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1119, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1120, 0x00000401);
					
					// Enable leaky packet mechanism, the bandwidth is sustained to a minimum value
				//	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPIDFLTC_PIDFLT_LEAKPKT(demod), 1);
					// Remove bug fix: workaround of BZ#98230: bad sampling of data[3] of TS bus
				//	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(demod), 0);
				break;
				case FE_TS_PARALLEL_ON_TSOUT_1:
					// Setting alternate function 3 from PIO6_0 to PIO6_5
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, 0x00333333);
					// Setting alternate function 3 from PIO7_0 to PIO7_5
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, 0x00333333);
				        
					// Setting output enable from PIO6_0 to PIO6_5
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
					reg_value |= 0x3F000000;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
					// Setting output enable from PIO7_0 to PIO7_5
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, 0x3F000000);
				        
					// Setting clk not data for PIO6_0 and clock inversion (BZ#75008)
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1124, 0x00000205);
				        
					// Setting data not clk for pio from PIO6_0 to PIO6_5 and for pio from PIO7_0 to PIO7_4, and choose STFE clock as a clock source for retime block
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1125, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1126, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1127, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1128, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1129, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1124, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1125, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1126, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1127, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1128, 0x00000401);
					
					// Enable leaky packet mechanism, the bandwidth is sustained to a minimum value
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPIDFLTC_PIDFLT_LEAKPKT(demod), 1);
					// Remove bug fix: workaround of BZ#98230: bad sampling of data[3] of TS bus
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(demod), 0);
				break;
				
				case FE_TS_SERIAL_ON_TSOUT_0:
					// Setting alternate function 3 from PIO4_0 to PIO4_2
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1001, 0x00000333);
					
					// Setting output enable from PIO4_0 to PIO4_2
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
					reg_value |= 0x00000700;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
						
					// Setting clk not data for PIO4_0 and clock inversion (BZ#75008)
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1108, 0x00000205);
								
					// Setting data not clk for pio from PIO4_1 to PIO4_2 and choose STFE clock as a clock source for retime block
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1109, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1110, 0x00000401);
				break;
				
				case FE_TS_SERIAL_ON_TSOUT_1:
					// Setting alternate function 3 from PIO6_0 to PIO6_2
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, 0x00000333);
					
					// Setting output enable from PIO6_0 to PIO6_2
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
					reg_value |= 0x07000000;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
					
					// Setting clk not data for PIO6_0 and clock inversion (BZ#75008)
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1124, 0x00000205);
					
					// Setting data not clk for pio from PIO6_1 to PIO6_2 and choose STFE clock as a clock source for retime block
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1125, 0x00000401);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1126, 0x00000401);
				break;
				
				case FE_TS_ASI:
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_SERIAL(demod), 1); /* Serial mode */
					/* DVBCI setting: only for cut 1 */
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(demod), 1);  /* continuous clock only for BNC connector (J40) */
					error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSCFG2(demod), 1); /* reset of merger + TS_FIFO serial */
						
					// Setting alternate function 2 from PIO3_5 to PIO3_7
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1002, 0x22220000); // only for J40 connector
					
					// Setting output enable from PIO3_4 to PIO3_7
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
					reg_value |= 0x00F00000;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, reg_value);
								
					// Setting clk not data for PIO3_5
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1121, 0x00000004);
					
					// Setting clk not data for PIO3_4
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1120, 0x00000004);
					
					// Remove bug fix: workaround of BZ#98230: bad sampling of data[3] of TS bus
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(demod), 0);
				break;
				
				case FE_TS_NCR:
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_SERIAL(demod), 1); /* Serial mode */
					/* DVBCI setting: only for cut 1 */
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(demod), 1);  /*  CLKOUT pulse with each data for HE10 connector (J34) */
					error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSCFG2(demod), 1); /* reset of merger + TS_FIFO serial */
						
					// Setting alternate function 2 from PIO3_5 to PIO3_7
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1002, 0x11110000); // only for J34 connector
							
					// Setting output enable from PIO3_4 to PIO3_7
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, &reg_value);
					reg_value |= 0x00F00000;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, reg_value);
								
					// Setting clk not data for PIO3_5
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1121, 0x00000004);
					
					// Setting clk not data for PIO3_4
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1120, 0x00000004);
					
					// Remove bug fix: workaround of BZ#98230: bad sampling of data[3] of TS bus
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(demod), 0);
				break;

				case FE_TS_NCR_TEST_BUS: // new management of NCR 
					// FE_GPIO[18]=ts_extncr_out[1]=PIO1[1] (I2C repeater bus, SDA)
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_TOP_CTRL_GPIO18CFG, 0x3C);
					
					// FE_GPIO[19]=ts_extncr_out[0]=PIO1[0] (I2C repeater bus, SCL)
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_TOP_CTRL_GPIO19CFG, 0x3E);
					
					// Select AVS-PWM0, EXTNCR
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1000, &reg_value);
					reg_value |= 0x00001011;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1000, reg_value);

					// Enable alternate function #1 for PIO2[0], PIO2[1], PIO2[2], PIO2[3] and PIO2[4]
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1001, &reg_value);
					reg_value |= 0x00011111;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1001, reg_value);
					
					// Select PIO3[4] as FE-GPIO[3], PIO3[5] as FE-GPIO[2], PIO3[6] as FE-GPIO[1] and PIO3[7] as FE-GPIO[0]
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1002, &reg_value);
					reg_value |= /*0x33331111*/0x33310000; // 0x33330000 enough ??
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1002, reg_value);
					
					// Enable PIO3[5] and PIO3[7] as output, enable PIO3[4] and PIO3[6] as input
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, &reg_value);
					reg_value |= 0x3f501f1b/* Minimal value = 0x00A00000, but we set all PIOs as output */;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, reg_value);
				break;
				
				/* Careful, in mux stream mode, demod#1 and demod#2 work in pair, as in wideband mode
				If demod#1 is not locked, then it is not possible to lock demod#2 */
				case FE_TS12_MUX_STREAM_MODE:
					// Set MUX stream, not DVBCI
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_GEN_TSGENERAL(1), 0x36);
					// Punctured clock
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(1), 0);
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(2), 0);
					// Program PIO4[5:0] in alternate 4
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1001, 0x00444444);
					// Program PIO5[5:0] in alternate 4
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, 0x00444444);
					// Output enable, PIO pad enabled of PIO4[5:0] and PIO5[5:0]
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
					reg_value |= 0x003F3F00;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
					// Setting clk not data for PIO4_0
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1108, 0x00000004);
					// Setting clk not data for PIO5_5
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1121, 0x00000006);
					// Disable leaky packet mechanism, the bandwidth is free to be as low as possible
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPIDFLTC_PIDFLT_LEAKPKT(1), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPIDFLTC_PIDFLT_LEAKPKT(2), 0);
					// Remove bug fix: workaround of BZ#98230: bad sampling of data[3] of TS bus
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(1), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(2), 0);
				break;

				/* Careful, in mux stream mode, demod#3 and demod#4 work in pair, as in wideband mode
				If demod#3 is not locked, then it is not possible to lock demod#4 */
				case FE_TS34_MUX_STREAM_MODE:
					// Set MUX stream, not DVBCI
					error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_GEN_TSGENERAL(2), 0x36);
					// Punctured clock
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(3), 0);
					error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG2_TSFIFO_DVBCI(4), 0);
					// Program PIO6[5:0] in alternate 4
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, 0x00444444);
					// Program PIO7[5:0] in alternate 4
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, 0x00444444);
					// Output enable, PIO pad enabled of PIO6[5:0]
					error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
					reg_value |= 0x3F000000;
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
					// Output enable, PIO pad enabled of PIO7[5:0]
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, 0x3F000000);
	
					// Setting clk not data for PIO6_0
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1124, 0x00000006);
					// Setting clk not data for PIO7_5
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1129, 0x00000006);
					// Disable leaky packet mechanism, the bandwidth is free to be as low as possible
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPIDFLTC_PIDFLT_LEAKPKT(1), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSPIDFLTC_PIDFLT_LEAKPKT(2), 0);
					// Remove bug fix: workaround of BZ#98230: bad sampling of data[3] of TS bus
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(1), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSCFG0_TSFIFO_BCLKDEL1CK(2), 0);
				break;
				
				case FE_TS_OUTPUTMODE_DEFAULT:
				break;
			}
			// 130MHz Oxford-Mclk CK_F1
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_TOP_CTRL_GPIO14CFG, 0x7E);
			// Select Oxford-Mclk, IRQ, SGNL1[1]
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1000, 0x00011000);
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_enable_stfe
--ACTION	::	Enables STFE block (inputs and outputs)
--PARAMS IN	::	handle -> Front End Handle
			stfe_output -> either 1st output, or 2nd output or both
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_enable_stfe(fe_stid135_handle_t handle, enum fe_stid135_stfe_output stfe_output)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
			/* Enable IB0-IB7 */
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG128, 0x00000000);
			switch(stfe_output) {
			case FE_STFE_OUTPUT0:
				/* REQ = 1, enable TSout0 */
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG129, 0x00000002);
				/* REQ = 1, disable TSout1 */
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG130, 0x00000003);
			break;
			case FE_STFE_OUTPUT1:
				/* REQ = 1, disable TSout0 */
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG129, 0x00000003);
				/* REQ = 1, enable TSout1 */
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG130, 0x00000002);
			break;
			case FE_STFE_BOTH_OUTPUT:
				/* REQ = 1, enable TSout0 */
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG129, 0x00000002);
				/* REQ = 1, enable TSout1 */
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG130, 0x00000002);
			break;
			}
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_stfe
--ACTION	::	Sets PIOs according to wanted TS mode
--PARAMS IN	::	handle -> Front End Handle
			mode -> mode of STFE (bypass...)
			stfe_input_path -> see below description
			stfe_output_path -> see below description
			tag_header -> tag value in STFE tagging mode
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
/* u8 stfe_output_path : coding of output path: FE_STFE_OUTPUT0 => TSout0
					        FE_STFE_OUTPUT1 => TSout1
					        FE_STFE_BOTH_OUTPUT => TSout0 and TSout1
					       
  In the context of FE_STFE_BYPASS_MODE :
  u8 stfe_input_path : coding of input path: PATH0 => IB0
					     PATH1 => IB1
					     PATH2 => IB2
					     PATH3 => IB3
					     PATH4 => IB4
					     PATH5 => IB5
					     PATH6 => IB6
					     PATH7 => IB7
					       
  In the context of FE_STFE_TAGGING_MODE or FE_STFE_TAGGING_MERGING_MODE mode :
  u8 stfe_input_path : coding of input path: 0x1 => IB0
					     0x2 => IB1
					     0x4 => IB2
					     0x8 => IB3
					     0x10 => IB4
					     0x20 => IB5
					     0x40 => IB6
					     0x80 => IB7
					     .. but all combinations are possible, for instance :
					     0x74 => IB2 & IB4 & IB5 & IB6
					     0x94 => IB0 & IB2 & IB4 & IB7
*/
fe_lla_error_t fe_stid135_set_stfe(fe_stid135_handle_t handle, enum fe_stid135_stfe_mode mode, u8 stfe_input_path, enum fe_stid135_stfe_output stfe_output_path, u8 tag_header)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i, path[8] = {0};
	u32 reg_value;
	//u32 dest0_route_reg, dest1_route_reg;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error )  
			error=FE_LLA_I2C_ERROR; 
		else {
			switch(mode) {
			case FE_STFE_BYPASS_MODE:
				/* Enables bypass mode, performs reset and enables processing on this stream */
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_SYSTEM(stfe_input_path+1), 0x00000007);
			
				switch(stfe_output_path) {
				case FE_STFE_OUTPUT0:
					// Enables bypass mode on TSout0
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_BYPASS, 0x80000000 | stfe_input_path);
				break;
				case FE_STFE_OUTPUT1:
					// Enables bypass mode on TSout1
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_BYPASS, 0x80000000 | stfe_input_path);
				break;
				case FE_STFE_BOTH_OUTPUT:
					// Enables bypass mode on both TSout0 and TSout1
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_BYPASS, 0x80000000 | stfe_input_path);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_BYPASS, 0x80000000 | stfe_input_path);
				break;
				}
			break;

			case FE_STFE_TAGGING_MODE:
				error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_BYPASS, &reg_value);
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_BYPASS, reg_value & 0x7FFFFFFF);
				error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_BYPASS, &reg_value);
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_BYPASS, reg_value & 0x7FFFFFFF);
				for(i=0;i<8;i++)
					path[i] = (stfe_input_path>>i) & 0x1;
				if(path[0]) {
					/* Top address of stream buffer in STFE internal RAM */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM0_TOP, 0x400*(0+1)-1);
					/* Base address of stream buffer in STFE internal RAM */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM0_BASE, 0x400*(0));
					/* Transport packet size, includes tagging bytes */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM0_PKTSIZE, 0x000000C4);
					/* Source-Destination routing : choose which inputs are sent to which outputs */
				}
				if(path[1]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM1_TOP, 0x400*(1+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM1_BASE, 0x400*(1));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM1_PKTSIZE, 0x000000C4);
				}
				if(path[2]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM2_TOP, 0x400*(2+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM2_BASE, 0x400*(2));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM2_PKTSIZE, 0x000000C4);
				}
				 if(path[3]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM3_TOP, 0x400*(3+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM3_BASE, 0x400*(3));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM3_PKTSIZE, 0x000000C4);
				 }
				if(path[4]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM4_TOP, 0x400*(4+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM4_BASE, 0x400*(4));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM4_PKTSIZE, 0x000000C4);
				}
				if(path[5]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM5_TOP, 0x400*(5+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM5_BASE, 0x400*(5));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM5_PKTSIZE, 0x000000C4);
				}
				if(path[6]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM6_TOP, 0x400*(6+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM6_BASE, 0x400*(6));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM6_PKTSIZE, 0x000000C4);
				}
				if(path[7]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM7_TOP, 0x400*(7+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM7_BASE, 0x400*(7));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM7_PKTSIZE, 0x000000C4);
				}
				
				if(stfe_output_path == FE_STFE_OUTPUT0) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_ROUTE, stfe_input_path);
				} else if (stfe_output_path == FE_STFE_OUTPUT1) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_ROUTE, stfe_input_path);
				} else if(stfe_output_path == FE_STFE_BOTH_OUTPUT) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_ROUTE, stfe_input_path);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_ROUTE, (u8)(~stfe_input_path));
				}
				
				/* Output channel FIFO trigger level */
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_FIFOTRIG, 0x00000019);
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_FIFOTRIG, 0x00000019);
				
				/* Setting STFE for merging the streams */
				for(i=0;i<8;i++) {
					if(path[i] == 1) {
						/* Control tag bytes insertion */
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_TAG_BYTES(i+1), (u32)((tag_header<<24) | ((i+1)<<16) | 0x1));
						/* End address of buffer in internal RAM */
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_BUFFER_END(i+1), (u32)(0x400*(i+1)-1));
						/* Start address of buffer in internal RAM */
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_BUFFER_START(i+1), (u32)(0x400*i));
						/* Interrupt mask register */
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_MASK(i+1), 0x0000001F);
						/* Clear FIFO, buffers and enables processing on this stream */
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_SYSTEM(i+1), 0x00000003);
					}
				}
			break;

			case FE_STFE_TAGGING_MERGING_MODE:
				error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_BYPASS, &reg_value);
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_BYPASS, reg_value & 0x7FFFFFFF);
				error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_BYPASS, &reg_value);
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_BYPASS, reg_value & 0x7FFFFFFF);
				for(i=0;i<8;i++)
					path[i] = (stfe_input_path>>i) & 0x1;
				if(path[0]) {
					/* Top address of stream buffer in STFE internal RAM */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM0_TOP, 0x400*(0+1)-1);
					/* Base address of stream buffer in STFE internal RAM */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM0_BASE, 0x400*(0));
					/* Transport packet size, includes tagging bytes */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM0_PKTSIZE, 0x000000C4);
					/* Source-Destination routing : choose which inputs are sent to which outputs */
				}
				
				if(path[1]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM1_TOP, 0x400*(1+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM1_BASE, 0x400*(1));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM1_PKTSIZE, 0x000000C4);
				}
				
				if(path[2]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM2_TOP, 0x400*(2+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM2_BASE, 0x400*(2));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM2_PKTSIZE, 0x000000C4);
				}
				
				if(path[3]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM3_TOP, 0x400*(3+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM3_BASE, 0x400*(3));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM3_PKTSIZE, 0x000000C4);
				}
				
				if(path[4]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM4_TOP, 0x400*(4+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM4_BASE, 0x400*(4));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM4_PKTSIZE, 0x000000C4);
				}
				
				if(path[5]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM5_TOP, 0x400*(5+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM5_BASE, 0x400*(5));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM5_PKTSIZE, 0x000000C4);
				}
				
				if(path[6]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM6_TOP, 0x400*(6+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM6_BASE, 0x400*(6));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM6_PKTSIZE, 0x000000C4);
				}
				
				if(path[7]) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM7_TOP, 0x400*(7+1)-1);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM7_BASE, 0x400*(7));
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_STRM7_PKTSIZE, 0x000000C4);
				}
				
				/*overwritting output destination out0 register as ChipGetOneRegister is not working */
				if(stfe_output_path == FE_STFE_OUTPUT0) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_ROUTE, stfe_input_path);
				} else if (stfe_output_path == FE_STFE_OUTPUT1) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_ROUTE, stfe_input_path);
				} else if(stfe_output_path == FE_STFE_BOTH_OUTPUT) {
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_ROUTE, stfe_input_path);
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_ROUTE, (u8)~stfe_input_path);
				}
				
				/* Output channel FIFO trigger level */
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_FIFOTRIG, 0x00000019);
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_FIFOTRIG, 0x00000019);
				
				/* Setting STFE for merging the streams */
				for(i=0;i<8;i++) {
					if(path[i] == 1) {
						/* Control tag bytes insertion */
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_TAG_BYTES(i+1), (u32)((tag_header<<24) | ((i+1)<<16) | 0x1));
						/* End address of buffer in internal RAM */
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_BUFFER_END(i+1), (u32)(0x400*(i+1)-1));
						/* Start address of buffer in internal RAM */
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_BUFFER_START(i+1), (u32)(0x400*i));
						/* Interrupt mask register */
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_MASK(i+1), 0x0000001F);
						/* Clear FIFO, buffers and enables processing on this stream */
						error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_IB_C8SECTPFE_IB_SYSTEM(i+1), 0x00000003);
					}
				}
			break;
			}
		}
		error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_FORMAT, &reg_value);
		reg_value |= FSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_FORMAT_WAIT_WHOLE_PACKET__MASK;
		error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST0_FORMAT, reg_value);
		error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_FORMAT, &reg_value);
		reg_value |= FSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_FORMAT_WAIT_WHOLE_PACKET__MASK;
		error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C8SECTPFE_TSDMA_C8SECTPFE_TSDMA_DEST1_FORMAT, reg_value);
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_flexclkgen_init
--ACTION	::	Sets Flex Clock Gen block
--PARAMS IN	::	handle -> Front End Handle
-PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
static fe_lla_error_t fe_stid135_flexclkgen_init(fe_stid135_handle_t handle)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	u32 system_clock, reg_value;
	
	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error)  
			error=FE_LLA_I2C_ERROR; 
		else {
			/* if MODE_PIN0 = 1, then the system clock is equal to the crystal clock divided by 2 */
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_STATUS48, &reg_value);
			if((reg_value & 0x1) == 1)
				system_clock = pParams->quartz >> 1;
			else
				system_clock = pParams->quartz;
			
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG0, 0x10000000);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG1, 0x00030000);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG5, 0x002C25ED);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG6, 0x002C25ED);    
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG7, 0x002C25ED);    
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG8, 0x002C25ED);    
	
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG3, 0x00000000); 
	
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG89, 0x00000040);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG90, 0x00000040);          
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG91, 0x00000040);          
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG92, 0x00000040);          
	
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG98, 0x00000040);          
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG99, 0x00000040);   
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG6,  0x45454545);   
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG7,  0x45454545);  
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG8,  0x45454545);
			
			/* 0x1F0F is reset value, therefore maybe be ommited */
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG0, 0x00001F0F);
			
			switch(system_clock) {
				case 25:
					/* Control the PLL feedback divider settings */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG1, 0x00050000);
					/* Control output clock channel 0 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG5, 0x014371C7);
					/* Control output clock channel 1 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG6, 0x014371C7);
					/* Control output clock channel 2 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG7, 0x000ec4ec);
					/* Control output clock channel 3 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG8, 0x011c0000);
				break;
				case 27:
					/* Control the PLL feedback divider settings */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG1, 0x00040000);
					/* Control output clock channel 0 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG5, 0x01440000);
					/* Control output clock channel 1 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG6, 0x01440000);
					/* Control output clock channel 2 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG7, 0x000fa5fa);
					/* Control output clock channel 3 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG8, 0x011ccccc);
				break;
				case 30:
					/* Control the PLL feedback divider settings */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG1, 0x00020000);
					/* Control output clock channel 0 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG5, 0x01440000);
					/* Control output clock channel 1 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG6, 0x01440000);
					/* Control output clock channel 2 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG7, 0x000fa5fa);
					/* Control output clock channel 3 */
					error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG8, 0x011ccccc);
				break;
			}

			WAIT_N_MS(20);
			/* Power up just the PLL by clearing bit 12 */
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG0, 0x00000F0F);
			/* Wait for 20000ns to assert lock or poll bit 24 of gfgx_config0 till its 1 */
			WAIT_N_MS(10);
			/* Let the outputs come out of reset */
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG0, &reg_value);
			reg_value &= ~(u32)FSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG0_GFG0_RESET__MASK;
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG0, reg_value);
			/* Wait for a small time for the reset to come off and let the logic sort itself out. In sim doing the next bit too early
			the fast glitches still appear on the outputs */
			WAIT_N_MS(10);
			/* Power up the outputs which will go high for a while and then start generating the required clock */
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG0, &reg_value);
			reg_value &= ~(u32)FSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG0_GFG0_STANDBY__MASK;
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG0, reg_value);
			WAIT_N_MS(10);
			/* Program the required channels EN_PRG to 1 */
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG3, &reg_value);
			reg_value |= FSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG3_GFG0_STROBE__MASK;
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG3, reg_value);

			/* Define division ratio for final divider 0 - STBUS south clock */
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG89, 0x43);
			/* Define division ratio for final divider 1 - STBUS north clock */
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG90, 0x40);
			/* Define division ratio for final divider 2 - RAM clock for STFE */
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG91, 0x41);
			/* Define division ratio for final divider 3 - STFE system clock */
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG92, 0x42);
			/* Define division ratio for final divider 9 - TSOUT0 output clock : TS parallel */
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG98, 0x40);
			/* Define division ratio for final divider 10 - TSOUT1 output clock : TS parallel */
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG99, 0x40);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG6, 0x40404440);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG7, 0x42414141);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG8, 0x45434342);
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	get_clk_source
--ACTION	::	Useful function to compute clock frequency
			for each block
--PARAMS IN	::	Handle -> Front End Handle
			clkout_number -> 
-PARAMS OUT	::	crossbar_p -> 
--RETURN	::	error (if any)
--***************************************************/
static fe_lla_error_t get_clk_source(internal_param_ptr Handle, u8 clkout_number, u8* crossbar_p)
{
	struct fe_stid135_internal_param *pParams;
	fe_lla_error_t error = FE_LLA_NO_ERROR;   
	u32 reg_value;
	
	*crossbar_p = 0;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	switch(clkout_number) {
		case 0:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG6, &reg_value);
			*crossbar_p = (u8) reg_value;
			*crossbar_p = (*crossbar_p)&0x7;
		break;
		case 1:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG6, &reg_value);
			*crossbar_p = (u8)(reg_value >> 8);
			*crossbar_p = (*crossbar_p)&0x7;
		break;	
		case 2:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG6, &reg_value);  
			*crossbar_p = (u8)(reg_value >> 16); 
			*crossbar_p = (*crossbar_p)&0x7;
		break;
		case 3:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG6, &reg_value);  
			*crossbar_p = (u8)(reg_value >> 24); 
			*crossbar_p = (*crossbar_p)&0x7;
		break;
		case 4:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG7, &reg_value);  
			*crossbar_p = (u8)reg_value ; 
			*crossbar_p = (*crossbar_p)&0x7;
		break;
		case 5:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG7, &reg_value);  
			*crossbar_p = (u8)(reg_value >> 8); 
			*crossbar_p = (*crossbar_p)&0x7;
		break;
		case 6:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG7, &reg_value);  
			*crossbar_p = (u8)(reg_value >> 16); 
			*crossbar_p = (*crossbar_p)&0x7;
		break;
		case 7:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG7, &reg_value);  
			*crossbar_p = (u8)(reg_value >> 24); 
			*crossbar_p = (*crossbar_p)&0x7;
		break;
		case 8:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG8, &reg_value);  
			*crossbar_p = (u8)reg_value; 
			*crossbar_p = (*crossbar_p)&0x7;
		break;
		case 9:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG8, &reg_value);  
			*crossbar_p = (u8)(reg_value >> 8);  
			*crossbar_p = (*crossbar_p)&0x7;
		break;
		case 10:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG8, &reg_value);  
			*crossbar_p = (u8)(reg_value >> 16); 
			*crossbar_p = (*crossbar_p)&0x7;
		break;
		case 11:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG8, &reg_value);  
			*crossbar_p = (u8)(reg_value >> 24); 
			*crossbar_p = (*crossbar_p)&0x7;
		break;
	}
	return(error);
}

/*****************************************************
--FUNCTION	::	compute_final_divider
--ACTION	::	Another useful function to compute clock frequency
			for each block
--PARAMS IN	::	Handle -> Front End Handle
			clkin -> 
-PARAMS OUT	::	clkout_p -> 
--RETURN	::	error (if any)
--***************************************************/
static fe_lla_error_t compute_final_divider(internal_param_ptr Handle, u32 clkin, u8 clkout_number, u32* clkout_p)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR; 
	
	u8 crossbar = 0;
	s32 field_val;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	
	*clkout_p = pParams->quartz;
	
	error |= get_clk_source(Handle, clkout_number, &crossbar);
	switch(clkout_number) {
		case 0:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG89_FINDIV0DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 1:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG90_FINDIV1DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 2:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG91_FINDIV2DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 3:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG92_FINDIV3DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 4:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG93_FINDIV4DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 5:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG94_FINDIV5DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 6:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG95_FINDIV6DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 7:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG96_FINDIV7DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 8:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG97_FINDIV8DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 9:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG98_FINDIV9DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 10:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG99_FINDIV10DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
		case 11:
			error |= ChipGetField(pParams->handle_soc, FLD_FSTID135_OXFORD_FLEXCLKGEN_A_FCG_CONFIG100_FINDIV11DIVBY, &field_val);
			*clkout_p = clkin*100 / (u32)(field_val + 1);
		break;
	}
	return(error);
}

/*****************************************************
--FUNCTION	::	get_soc_block_freq
--ACTION	::	Compute clock frequency for each block
--PARAMS IN	::	Handle -> Front End Handle
			clkout_number -> 
-PARAMS OUT	::	clkout_p -> 
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t get_soc_block_freq(internal_param_ptr Handle, u8 clkout_number, u32* clkout_p)
{
	u8 crossbar;
	u32 clkin = 0;
	u32 Num, Den1, Den2, Den3, Den4, system_clock, reg_value;
	struct fe_stid135_internal_param *pParams;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u32 reg_val;
	
	pParams = (struct fe_stid135_internal_param *) Handle;
	
	/* if MODE_PIN0 = 1, then the system clock is equal to the crystal clock divided by 2 */
	error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_STATUS48, &reg_value);
	if((reg_value & 0x1) == 1)
		system_clock = pParams->quartz >> 1;
	else
		system_clock = pParams->quartz;
	
	*clkout_p = system_clock * 100;

	error |= get_clk_source(Handle, clkout_number, &crossbar);
	
	switch(crossbar) {
		case 0:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG1, &reg_value);
			clkin = system_clock*(((reg_value>>16) & 0x7) + 16);
			error |= compute_final_divider(Handle, clkin, clkout_number, clkout_p);
		break;
		case 1:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG1, &reg_value);
			Num = system_clock*(((reg_value>>16) & 0x7) + 16);
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG5, &Den1);
			Den1 = (Den1>>24)&0x1;
			if(Den1==0)
				Den1 = 3;
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG5, &Den2);
			Den2 = (u32)XtoPowerY(2, ((Den2>>20)&0xF));
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG5, &Den3);
			Den3 = (Den3>>15)&0x1F;
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG5, &Den4);
			Den4 = (Den4)&0x7FFF;
			*clkout_p = (Num*(1<<20))/(Den1*Den2*((1<<20)+Den3*(1<<15)+Den4));
			error |= compute_final_divider(Handle, *clkout_p, clkout_number, clkout_p);
		break;
		case 2:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG1, &Num);
			Num = system_clock*(((Num>>16) & 0x7) + 16);
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG6, &Den1);
			Den1 = (Den1>>24)&0x1;
			if(Den1==0)
				Den1 = 3;
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG6, &Den2);
			Den2 = (u32)XtoPowerY(2, ((Den2>>20)&0xF));
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG6, &Den3);
			Den3 = (Den3>>15)&0x1F;
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG6, &Den4);
			Den4 = (Den4)&0x7FFF;
			*clkout_p = (Num*(1<<20))/(Den1*Den2*((1<<20)+Den3*(1<<15)+Den4));
			error |= compute_final_divider(Handle, *clkout_p, clkout_number, clkout_p);
		break;
		case 3:
			error |=ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG1, &Num);
			Num = system_clock*(((Num>>16) & 0x7) + 16);
			error |=ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG7, &Den1);
			Den1 = (Den1>>24)&0x1;
			if(Den1==0)
				Den1 = 3;
			error |=ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG7, &Den2);
			Den2 = (u32)XtoPowerY(2, ((Den2>>20)&0xF));
			error |=ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG7, &Den3);
			Den3 = (Den3>>15)&0x1F;
			error |=ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG7, &Den4);
			Den4 = (Den4)&0x7FFF;
			*clkout_p = (Num*(1<<20))/(Den1*Den2*((1<<20)+Den3*(1<<15)+Den4));
			error |= compute_final_divider(Handle, *clkout_p, clkout_number, clkout_p);
		break;
		case 4:
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG1, &Num);
			Num = system_clock*(((Num>>16) & 0x7) + 16);
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG8, &Den1);
			Den1 = (Den1>>24)&0x1;
			if(Den1==0)
				Den1 = 3;
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG8, &Den2);
			Den2 = (u32)XtoPowerY(2, ((Den2>>20)&0xF));
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG8, &Den3);
			Den3 = (Den3>>15)&0x1F;
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_OXFORD_FLEXCLKGEN_A_GFG0_CONFIG8, &Den4);
			Den4 = (Den4)&0x7FFF;
			*clkout_p = (Num*(1<<20))/(Den1*Den2*((1<<20)+Den3*(1<<15)+Den4));
			error |= compute_final_divider(Handle, *clkout_p, clkout_number, clkout_p);
		break;
		case 5:
			*clkout_p = system_clock * 100;
		break;
	}
	return(error);
}


/*****************************************************
--FUNCTION	::	fe_stid135_get_mode_code
--ACTION	::	Gets MODCOD, frame length and pilot presence
--PARAMS IN	::	pParams -> Pointer to fe_stid135_internal_param structure
			demod -> Current demod 1..8
-PARAMS OUT	::	modcode -> MODCOD
			frame -> frame length
			pilots -> pilot presence
--RETURN	::	error (if any)
--***************************************************/
static fe_lla_error_t fe_stid135_get_mode_code(struct fe_stid135_internal_param *pParams,
					enum fe_stid135_demod demod,
					enum fe_sat_modcode *modcode, 
					enum fe_sat_frame *frame, 
					enum fe_sat_pilots *pilots) 
{
	u32 mcode = 0;
	s32 dmdmodcode = 0;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	
	if(pParams->handle_demod == NULL)
		error |= FE_LLA_INVALID_HANDLE;
	else {	
		error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDMODCOD(demod), &mcode);
		
		if(pParams->demod_results[demod-1].standard == FE_SAT_DVBS2_STANDARD) {
			
			if(((mcode >> 7) & 0x01) == 1) {
				dmdmodcode  =  (mcode >> 1) & 0x7F; // DVBS2X
			} else {
				dmdmodcode = (mcode >> 2) & 0x1F; // DVBS2 legacy
			}
			
			*pilots 	=  (enum fe_sat_pilots)(mcode & 0x01);
			*frame  	=  (enum fe_sat_frame)((mcode & 0x02) >> 1);
			
			if (dmdmodcode <= FE_SAT_MAX_LEGACY_MODCODE) { /* DVBS2 Legacy */
				*modcode    =  (enum fe_sat_modcode)dmdmodcode;
				*pilots     =  (enum fe_sat_pilots)((mcode & 0x01));
			} 
		
			if ((dmdmodcode >= 	FE_SAT_MIN_DVBS2X_MODCODE )  && /* DVBS2X */    
				(dmdmodcode <= 	FE_SAT_MAX_DVBS2X_MODCODE )) {
				*modcode  =  (enum fe_sat_modcode)(dmdmodcode);
				*frame  =  FE_SAT_NORMAL_FRAME; 
			}
			
			if ((dmdmodcode >= 	FE_SAT_MIN_SHORT_MODCODE  )  && /* DVBS2X short */         
				(dmdmodcode <= 	FE_SAT_MAX_SHORT_MODCODE )) {
				*frame  =  FE_SAT_SHORT_FRAME;
			}
			
			if ((dmdmodcode >= 	FE_SAT_MIN_POFF_MODCODE )  && /* DVBS2X ponpoff */  
				(dmdmodcode <= 	FE_SAT_MAX_POFF_MODCODE )) {                                                                              
				if (*pilots == FE_SAT_PILOTS_ON)
					dmdmodcode = dmdmodcode + (FE_SAT_MIN_PON_MODCODE - FE_SAT_MIN_POFF_MODCODE);	
				*pilots = FE_SAT_PILOTS_ON;
			}
		}
		if(pParams->demod_results[demod-1].standard == FE_SAT_DVBS1_STANDARD) {
			dmdmodcode = (mcode >> 2) & 0x3F; // DVBS1
			*pilots     =  FE_SAT_UNKNOWN_PILOTS;
			*frame      =  FE_SAT_UNKNOWN_FRAME;
			if ((dmdmodcode >= 	FE_SAT_MIN_DVBS1_MODCODE )  && /* DVBS1 */ 
				(dmdmodcode <= 	FE_SAT_MAX_DVBS1_MODCODE )) {
				*modcode    =  (enum fe_sat_modcode)(dmdmodcode);
			}
		}
	}
	
	if (pParams->handle_demod->Error )
		error = FE_LLA_I2C_ERROR; 
	
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_modcodes_filter
--ACTION	::	Set a MODCODES mask in the demodulators,
			only MODCODS of the given list are authorized at the input of the FEC 
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 .. 8
			MODCODES_MASK -> array :list of the MODCODS to be enabled
			NbModes -> Number of modes to enable (size of MODCODES_MASK table) 
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_modcodes_filter(fe_stid135_handle_t handle, 
						enum fe_stid135_demod demod,
						struct fe_sat_dvbs2_mode_t *MODCODES_MASK,
						s32 NbModes)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	s32 regflist;
	u32 modcodlst1, reg_value;
	
	u16 regIndex = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTF(demod),
		fieldIndex,
		i;
		
	u8	regMask = 0xFF,
		pilots=0,
		frameLength=0,
		frameType;
		
	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error) 
			error = FE_LLA_I2C_ERROR; 
		else {
			modcodlst1 = FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST1_SYMBRATE_FILTER(demod);
			regflist= (s32)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST2(demod);
			
			error |= ChipSetField(pParams->handle_demod, modcodlst1, 0); /* disable automatic filter vs. SR */
	
			/*First disable all modcodes */
			/* Set to 1 modcod fields of MODCODLST1 register */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST1_DIS_32PSK_9_10(demod), 0x3);
			/* Set to 1 modcod fields of MODCODLST2 to MODCODLST3 registers */
			for(i=0;i<2;i++)
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)(regflist + i), 0xFF);
			/* Set to 1 modcod fields of MODCODLST4 register */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST4_DIS_16PSK_8_9(demod), 0xF);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST4_DIS_16PSK_9_10(demod), 0x3);
			/* Set to 1 modcod fields of MODCODLST5 to MODCODLST6 registers */
			for(i=3;i<5;i++)
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)(regflist + i), 0xFF);
			/* Set to 1 modcod fields of MODCODLST7 register */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST7_DIS_8P_8_9(demod), 0xF);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST7_DIS_8PSK_9_10(demod), 0x3);
			/* Set to 1 modcod fields of MODCODLST8 to MODCODLST9 registers */
			for(i=6;i<8;i++)
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)(regflist + i), 0xFF);
			/* Set to 1 modcod fields of MODCODLSTA register */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTA_DIS_QP_8_9(demod), 0xF);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTA_DIS_QPSK_9_10(demod), 0x3);
			/* Set to 1 modcod fields of MODCODLSTB to MODCODLSTE registers */
			for(i=9;i<13;i++)
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)(regflist + i), 0xFF);
			
			/* Set to 1 modcod field of MODCODLSTF register */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTF_DIS_QPSK_1_4(demod), 0xF);
			
			/* Set to 1 modcod fields from MODCODLS10 to MODCODLS1F registers - DVBS2X */
			for(i=14;i<30;i++) {
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)(regflist + i), 0xFF);
			}
			
			for(i=0;i<NbModes;i++) {
				if(INRANGE (FE_SAT_QPSK_14, MODCODES_MASK[i].mod_code, FE_SAT_32APSK_910)) {
					regIndex = (u16)(REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTF(demod) - MODCODES_MASK[i].mod_code/2);
					fieldIndex = MODCODES_MASK[i].mod_code % 2;  
					pilots = MODCODES_MASK[i].pilots;
					frameLength = MODCODES_MASK[i].frame_length;
				
					error |= ChipGetOneRegister(pParams->handle_demod,regIndex, &reg_value);
					regMask = (u8)reg_value;
					frameType= (u8)((frameLength << 1)|(pilots));
					if(fieldIndex ==0)
						regMask = (u8)(regMask & (~(0x01 << frameType)));
					else
						regMask = (u8)(regMask & (~(0x10 << frameType)));
					error |= ChipSetOneRegister(pParams->handle_demod,regIndex,regMask);
				} else if(INRANGE (FE_SATX_QPSK_13_45, MODCODES_MASK[i].mod_code, FE_SATX_1024APSK)){
					regIndex = (u16)(REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1F(demod) - MODCODES_MASK[i].mod_code/2);
				}
				/*fieldIndex = MODCODES_MASK[i].mod_code % 2;  
				pilots = MODCODES_MASK[i].pilots;
				frameLength = MODCODES_MASK[i].frame_length;
				
				error |= ChipGetOneRegister(pParams->handle_demod,regIndex, &reg_value);
				regMask = (u8)reg_value;
				frameType= (u8)((frameLength << 1)|(pilots));
				if(fieldIndex ==0)
					regMask = (u8)(regMask & (~(0x01 << frameType)));
				else
					regMask = (u8)(regMask & (~(0x10 << frameType)));
				error |= ChipSetOneRegister(pParams->handle_demod,regIndex,regMask);   */
			}
		}

		if (pParams->handle_demod->Error ) /*Check the error at the end of the function*/ 
			error=FE_LLA_I2C_ERROR; 
	}
	return error;
}


/*****************************************************
--FUNCTION	::	fe_stid135_reset_modcodes_filter
--ACTION	::	Unset all MODCODE mask in the demodulator
--PARAMS IN	::	Handle -> Front End Handle
			demod -> Current demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_reset_modcodes_filter(fe_stid135_handle_t handle,
					       enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	u8 i, row_max;
	u32 reg_value;
		
	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if(pParams->handle_demod->Error) 
			error = FE_LLA_I2C_ERROR; 
		else {
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST0(demod), 0xFF);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST1_NRESET_MODCODLST(demod), 1);

			/*First disable all modcodes */
			row_max = sizeof(pParams->mc_flt) / sizeof(struct modcod_data) - 1;
			for(i = 0;i <= row_max;i++) {
				pParams->mc_flt[i].forbidden[demod-1] = FALSE;
				error |= ChipGetOneRegister(pParams->handle_demod, pParams->mc_flt[i].register_address[demod-1], &reg_value);
				reg_value &= ~(pParams->mc_flt[i].mask_value);
				error |= ChipSetOneRegister(pParams->handle_demod, pParams->mc_flt[i].register_address[demod-1], reg_value);
			}
			
		}
		if (pParams->handle_demod->Error ) //Check the error at the end of the function
			error = FE_LLA_I2C_ERROR; 
	}
	return error;
}

/*
Below is a list containing ALL the MODCODs implemented or reserved by the
STiD135.
Please note that MODCOD performance is a function of the channel and MODCODs
behave differently in the presence of the various degradations and will impact
the monotonicity of the list.
The implementer must conduct their own characterization to ensure the list is 
homogeneous in CNR knowing that the following factors intervene: 
o	The phase, group-delay and frequency response of the transponder
o	The back off or operating point (linearity)
o	Cumulative phase noise of the components of the system
o	Fine setting of the transmit/receive filters, roll-off, pilots, 
	adjacent channels, co-channel etc.
Furthermore the DVB-S2 spec is not coherent within itself (S2 in PER, S2X in FER).
Here below ST has provided a list as seen in the order of theoretical CNR as 
printed in the DVB-S2 specifications EN 302307 parts 1 and 2 without correction 
for PER/FER or any degradation.

The list is in order of CNR for QEF for each MODCOD starting with the lowest 
		active CNR.
It is up to the implementer to provide and maintain this list.
Forbidden MODCODs (even though viable) should simply be given a very high value 
	of CNR to ensure they are always disabled.
The MODCOD list management algorithm will first obtain lock with all MODCODs 
enabled.  Once demodulator lock has been achieved the CNR will be established 
and all the MODCODS superior to the current CNR will be disabled.
*/
/*****************************************************
--FUNCTION	::	fe_stid135_apply_custom_qef_for_modcod_filter
--ACTION	::	Fills-in modcod filtering array
--PARAMS IN	::	handle -> Front End Handle
		::	qef_table_from_customer -> pointer to a table of structure with all
			custom SNR for each MODCOD (MODCODs sorted from lowest SNR to biggest SNR)
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_apply_custom_qef_for_modcod_filter(fe_stid135_handle_t handle, struct mc_array_customer *qef_table_from_customer)
{
	u8 i, j;
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct mc_array_customer *cust_mc_flt = qef_table_from_customer;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
			
	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if(pParams->handle_demod->Error) 
			error = FE_LLA_I2C_ERROR; 
		else {
			if(cust_mc_flt == NULL) {
				for(i = 0;i < NB_SAT_MODCOD;i++) {
					for(j=FE_SAT_DEMOD_1;j<=FE_SAT_DEMOD_8;j++) {
						pParams->mc_flt[i].register_address[j-1] = mc_reg_addr[st_mc_flt[i].modcod_id][j-1];
					}
					pParams->mc_flt[i].mask_value = mc_mask_bitfield[st_mc_flt[i].modcod_id];
					pParams->mc_flt[i].qef = st_mc_flt[i].snr;
				}
			} else {
				for(i = 0;i < NB_SAT_MODCOD;i++) {
					for(j=FE_SAT_DEMOD_1;j<=FE_SAT_DEMOD_8;j++) {
						pParams->mc_flt[i].register_address[j-1] = mc_reg_addr[cust_mc_flt[i].modcod_id][j-1];
					}
					pParams->mc_flt[i].mask_value = mc_mask_bitfield[cust_mc_flt[i].modcod_id];
					pParams->mc_flt[i].qef = cust_mc_flt[i].snr;
				}
			}
		}
		if (pParams->handle_demod->Error ) //Check the error at the end of the function
			error = FE_LLA_I2C_ERROR; 
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_modcod_flt_reg_init
--ACTION	::	Fills-in modcod filtering array
--PARAMS IN	::	pParams -> Pointer to fe_stid135_internal_param structure
				demod -> Current demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
static void fe_stid135_modcod_flt_reg_init(void)
{
	u8 i;

	mc_mask_bitfield[FE_SAT_QPSK_14] = FC8CODEW_DVBSX_DEMOD_MODCODLSTF_DIS_QPSK_1_4__MASK;
	mc_mask_bitfield[FE_SAT_QPSK_13] = FC8CODEW_DVBSX_DEMOD_MODCODLSTE_DIS_QPSK_1_3__MASK;
	mc_mask_bitfield[FE_SAT_QPSK_25] = FC8CODEW_DVBSX_DEMOD_MODCODLSTE_DIS_QPSK_2_5__MASK;
	mc_mask_bitfield[FE_SAT_QPSK_12] = FC8CODEW_DVBSX_DEMOD_MODCODLSTD_DIS_QPSK_1_2__MASK;
	mc_mask_bitfield[FE_SAT_QPSK_35] = FC8CODEW_DVBSX_DEMOD_MODCODLSTD_DIS_QPSK_3_5__MASK;
	mc_mask_bitfield[FE_SAT_QPSK_23] = FC8CODEW_DVBSX_DEMOD_MODCODLSTC_DIS_QP_2_3__MASK;
	mc_mask_bitfield[FE_SAT_QPSK_34] = FC8CODEW_DVBSX_DEMOD_MODCODLSTC_DIS_QP_3_4__MASK;
	mc_mask_bitfield[FE_SAT_QPSK_45] = FC8CODEW_DVBSX_DEMOD_MODCODLSTB_DIS_QP_4_5__MASK;
	mc_mask_bitfield[FE_SAT_QPSK_56] = FC8CODEW_DVBSX_DEMOD_MODCODLSTB_DIS_QP_5_6__MASK;
	mc_mask_bitfield[FE_SAT_QPSK_89] = FC8CODEW_DVBSX_DEMOD_MODCODLSTA_DIS_QP_8_9__MASK;
	mc_mask_bitfield[FE_SAT_QPSK_910] = FC8CODEW_DVBSX_DEMOD_MODCODLSTA_DIS_QPSK_9_10__MASK;
	mc_mask_bitfield[FE_SAT_8PSK_35] = FC8CODEW_DVBSX_DEMOD_MODCODLST9_DIS_8P_3_5__MASK;
	mc_mask_bitfield[FE_SAT_8PSK_23] = FC8CODEW_DVBSX_DEMOD_MODCODLST9_DIS_8P_2_3__MASK;
	mc_mask_bitfield[FE_SAT_8PSK_34] = FC8CODEW_DVBSX_DEMOD_MODCODLST8_DIS_8P_3_4__MASK;
	mc_mask_bitfield[FE_SAT_8PSK_56] = FC8CODEW_DVBSX_DEMOD_MODCODLST8_DIS_8P_5_6__MASK;
	mc_mask_bitfield[FE_SAT_8PSK_89] = FC8CODEW_DVBSX_DEMOD_MODCODLST7_DIS_8P_8_9__MASK;
	mc_mask_bitfield[FE_SAT_8PSK_910] = FC8CODEW_DVBSX_DEMOD_MODCODLST7_DIS_8PSK_9_10__MASK;
	mc_mask_bitfield[FE_SAT_16APSK_23] = FC8CODEW_DVBSX_DEMOD_MODCODLST6_DIS_16PSK_2_3__MASK;
	mc_mask_bitfield[FE_SAT_16APSK_34] = FC8CODEW_DVBSX_DEMOD_MODCODLST6_DIS_16PSK_3_4__MASK;
	mc_mask_bitfield[FE_SAT_16APSK_45] = FC8CODEW_DVBSX_DEMOD_MODCODLST5_DIS_16PSK_4_5__MASK;
	mc_mask_bitfield[FE_SAT_16APSK_56] = FC8CODEW_DVBSX_DEMOD_MODCODLST5_DIS_16PSK_5_6__MASK;
	mc_mask_bitfield[FE_SAT_16APSK_89] = FC8CODEW_DVBSX_DEMOD_MODCODLST4_DIS_16PSK_8_9__MASK;
	mc_mask_bitfield[FE_SAT_16APSK_910] = FC8CODEW_DVBSX_DEMOD_MODCODLST4_DIS_16PSK_9_10__MASK;
	mc_mask_bitfield[FE_SAT_32APSK_34] = FC8CODEW_DVBSX_DEMOD_MODCODLST3_DIS_32PSK_3_4__MASK;
	mc_mask_bitfield[FE_SAT_32APSK_45] = FC8CODEW_DVBSX_DEMOD_MODCODLST3_DIS_32PSK_4_5__MASK;
	mc_mask_bitfield[FE_SAT_32APSK_56] = FC8CODEW_DVBSX_DEMOD_MODCODLST2_DIS_32PSK_5_6__MASK;
	mc_mask_bitfield[FE_SAT_32APSK_89] = FC8CODEW_DVBSX_DEMOD_MODCODLST2_DIS_32PSK_8_9__MASK;
	mc_mask_bitfield[FE_SAT_32APSK_910] = FC8CODEW_DVBSX_DEMOD_MODCODLST1_DIS_32PSK_9_10__MASK;
	mc_mask_bitfield[FE_SATX_QPSK_13_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS1F_DIS_QPSK_13_45_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1F_DIS_QPSK_13_45_PON__MASK;
	mc_mask_bitfield[FE_SATX_QPSK_9_20] = FC8CODEW_DVBSX_DEMOD_MODCODLS1F_DIS_QPSK_9_20_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1F_DIS_QPSK_9_20_PON__MASK;
	mc_mask_bitfield[FE_SATX_QPSK_11_20] = FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_QPSK_11_20_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_QPSK_11_20_PON__MASK;
	mc_mask_bitfield[FE_SATX_8APSK_5_9_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8APSK_5_9_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8APSK_5_9_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_8APSK_26_45_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8APSK_26_45_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8APSK_26_45_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_8PSK_23_36] = FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8PSK_23_36_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8PSK_23_36_PON__MASK;
	mc_mask_bitfield[FE_SATX_8PSK_25_36] = FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_8PSK_25_36_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_8PSK_25_36_PON__MASK;
	mc_mask_bitfield[FE_SATX_8PSK_13_18] = FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_8PSK_13_18_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_8PSK_13_18_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_1_2_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_16APSK_1_2_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_16APSK_1_2_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_8_15_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_16APSK_8_15_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_16APSK_8_15_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_5_9_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_5_9_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_5_9_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_26_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_26_45_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_26_45_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_3_5] = FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_3_5_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_3_5_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_3_5_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_3_5_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_3_5_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_28_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_28_45_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_28_45_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_23_36] = FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_23_36_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_23_36_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_2_3_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_2_3_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_2_3_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_25_36] = FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_25_36_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_25_36_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_13_18] = FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_13_18_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_13_18_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_7_9] = FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_7_9_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_7_9_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_77_90] = FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_77_90_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_77_90_PON__MASK;
	mc_mask_bitfield[FE_SATX_32APSK_2_3_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_32APSK_2_3_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_32APSK_2_3_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_32APSK_32_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_32_45_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_32_45_PON__MASK;
	mc_mask_bitfield[FE_SATX_32APSK_11_15] = FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_11_15_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_11_15_PON__MASK;
	mc_mask_bitfield[FE_SATX_32APSK_7_9] = FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_7_9_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_7_9_PON__MASK;
	mc_mask_bitfield[FE_SATX_64APSK_32_45_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_32_45_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_32_45_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_64APSK_11_15] = FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_11_15_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_11_15_PON__MASK;
	mc_mask_bitfield[FE_SATX_64APSK_7_9] = FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_7_9_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_7_9_PON__MASK;
	mc_mask_bitfield[FE_SATX_64APSK_4_5] = FC8CODEW_DVBSX_DEMOD_MODCODLS17_DIS_64APSK_4_5_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS17_DIS_64APSK_4_5_PON__MASK;
	mc_mask_bitfield[FE_SATX_64APSK_5_6] = FC8CODEW_DVBSX_DEMOD_MODCODLS17_DIS_64APSK_5_6_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS17_DIS_64APSK_5_6_PON__MASK;
	mc_mask_bitfield[FE_SATX_128APSK_3_4] = FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_128APSK_3_4_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_128APSK_3_4_PON__MASK;
	mc_mask_bitfield[FE_SATX_128APSK_7_9] = FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_128APSK_7_9_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_128APSK_7_9_PON__MASK;
	mc_mask_bitfield[FE_SATX_256APSK_29_45_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_256APSK_29_45_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_256APSK_29_45_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_256APSK_2_3_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_256APSK_2_3_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_256APSK_2_3_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_256APSK_31_45_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_31_45_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_31_45_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_256APSK_32_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_32_45_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_32_45_PON__MASK;
	mc_mask_bitfield[FE_SATX_256APSK_11_15_L] = FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_11_15_L_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_11_15_L_PON__MASK;
	mc_mask_bitfield[FE_SATX_256APSK_3_4] = FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_3_4_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_3_4_PON__MASK;
	mc_mask_bitfield[FE_SATX_QPSK_11_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_11_45_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_11_45_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_QPSK_4_15] = FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_4_15_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_4_15_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_QPSK_14_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_14_45_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_14_45_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_QPSK_7_15] = FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_7_15_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_7_15_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_QPSK_8_15] = FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_QPSK_8_15_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_QPSK_8_15_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_QPSK_32_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_QPSK_32_45_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_QPSK_32_45_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_8PSK_7_15] = FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_8PSK_7_15_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_8PSK_7_15_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_8PSK_8_15] = FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_8PSK_8_15_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_8PSK_8_15_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_8PSK_26_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_8PSK_26_45_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_8PSK_26_45_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_8PSK_32_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_8PSK_32_45_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_8PSK_32_45_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_7_15] = FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_16APSK_7_15_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_16APSK_7_15_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_8_15] = FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_16APSK_8_15_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_16APSK_8_15_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_26_45_S] = FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_26_45_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_26_45_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_3_5_S] = FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_3_5_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_3_5_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_16APSK_32_45] = FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_32_45_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_32_45_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_32APSK_2_3] = FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_32APSK_2_3_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_32APSK_2_3_SH_PON__MASK;
	mc_mask_bitfield[FE_SATX_32APSK_32_45_S] = FC8CODEW_DVBSX_DEMOD_MODCODLS10_DIS_32APSK_32_45_SH_POFF__MASK + FC8CODEW_DVBSX_DEMOD_MODCODLS10_DIS_32APSK_32_45_SH_PON__MASK;
	
	for(i=FE_SAT_DEMOD_1;i <= FE_SAT_DEMOD_8;i++) {
		mc_reg_addr[FE_SAT_QPSK_14][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTF(i);
		mc_reg_addr[FE_SAT_QPSK_13][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTE(i);
		mc_reg_addr[FE_SAT_QPSK_25][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTE(i);
		mc_reg_addr[FE_SAT_QPSK_12][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTD(i);
		mc_reg_addr[FE_SAT_QPSK_35][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTD(i);
		mc_reg_addr[FE_SAT_QPSK_23][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTC(i);
		mc_reg_addr[FE_SAT_QPSK_34][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTC(i);
		mc_reg_addr[FE_SAT_QPSK_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTB(i);
		mc_reg_addr[FE_SAT_QPSK_56][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTB(i);
		mc_reg_addr[FE_SAT_QPSK_89][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTA(i);
		mc_reg_addr[FE_SAT_QPSK_910][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTA(i);
		mc_reg_addr[FE_SAT_8PSK_35][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST9(i);
		mc_reg_addr[FE_SAT_8PSK_23][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST9(i);
		mc_reg_addr[FE_SAT_8PSK_34][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST8(i);
		mc_reg_addr[FE_SAT_8PSK_56][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST8(i);
		mc_reg_addr[FE_SAT_8PSK_89][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST7(i);
		mc_reg_addr[FE_SAT_8PSK_910][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST7(i);
		mc_reg_addr[FE_SAT_16APSK_23][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST6(i);
		mc_reg_addr[FE_SAT_16APSK_34][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST6(i);
		mc_reg_addr[FE_SAT_16APSK_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST5(i);
		mc_reg_addr[FE_SAT_16APSK_56][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST5(i);
		mc_reg_addr[FE_SAT_16APSK_89][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST4(i);
		mc_reg_addr[FE_SAT_16APSK_910][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST4(i);
		mc_reg_addr[FE_SAT_32APSK_34][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST3(i);
		mc_reg_addr[FE_SAT_32APSK_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST3(i);
		mc_reg_addr[FE_SAT_32APSK_56][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST2(i);
		mc_reg_addr[FE_SAT_32APSK_89][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST2(i);
		mc_reg_addr[FE_SAT_32APSK_910][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLST1(i);
		mc_reg_addr[FE_SATX_QPSK_13_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1F(i);
		mc_reg_addr[FE_SATX_QPSK_9_20][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1F(i);
		mc_reg_addr[FE_SATX_QPSK_11_20][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1E(i);
		mc_reg_addr[FE_SATX_8APSK_5_9_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1E(i);
		mc_reg_addr[FE_SATX_8APSK_26_45_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1E(i);
		mc_reg_addr[FE_SATX_8PSK_23_36][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1E(i);
		mc_reg_addr[FE_SATX_8PSK_25_36][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1D(i);
		mc_reg_addr[FE_SATX_8PSK_13_18][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1D(i);
		mc_reg_addr[FE_SATX_16APSK_1_2_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1D(i);
		mc_reg_addr[FE_SATX_16APSK_8_15_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1D(i);
		mc_reg_addr[FE_SATX_16APSK_5_9_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1C(i);
		mc_reg_addr[FE_SATX_16APSK_26_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1C(i);
		mc_reg_addr[FE_SATX_16APSK_3_5][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1C(i);
		mc_reg_addr[FE_SATX_16APSK_3_5_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1C(i);
		mc_reg_addr[FE_SATX_16APSK_28_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1B(i);
		mc_reg_addr[FE_SATX_16APSK_23_36][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1B(i);
		mc_reg_addr[FE_SATX_16APSK_2_3_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1B(i);
		mc_reg_addr[FE_SATX_16APSK_25_36][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1B(i);
		mc_reg_addr[FE_SATX_16APSK_13_18][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1A(i);
		mc_reg_addr[FE_SATX_16APSK_7_9][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1A(i);
		mc_reg_addr[FE_SATX_16APSK_77_90][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1A(i);
		mc_reg_addr[FE_SATX_32APSK_2_3_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS1A(i);
		mc_reg_addr[FE_SATX_32APSK_32_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS19(i);
		mc_reg_addr[FE_SATX_32APSK_11_15][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS19(i);
		mc_reg_addr[FE_SATX_32APSK_7_9][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS19(i);
		mc_reg_addr[FE_SATX_64APSK_32_45_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS18(i);
		mc_reg_addr[FE_SATX_64APSK_11_15][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS18(i);
		mc_reg_addr[FE_SATX_64APSK_7_9][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS18(i);
		mc_reg_addr[FE_SATX_64APSK_4_5][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS17(i);
		mc_reg_addr[FE_SATX_64APSK_5_6][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS17(i);
		mc_reg_addr[FE_SATX_128APSK_3_4][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS16(i);
		mc_reg_addr[FE_SATX_128APSK_7_9][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS16(i);
		mc_reg_addr[FE_SATX_256APSK_29_45_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS16(i);
		mc_reg_addr[FE_SATX_256APSK_2_3_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS16(i);
		mc_reg_addr[FE_SATX_256APSK_31_45_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS15(i);
		mc_reg_addr[FE_SATX_256APSK_32_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS15(i);
		mc_reg_addr[FE_SATX_256APSK_11_15_L][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS15(i);
		mc_reg_addr[FE_SATX_256APSK_3_4][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS15(i);
		mc_reg_addr[FE_SATX_QPSK_11_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS14(i);
		mc_reg_addr[FE_SATX_QPSK_4_15][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS14(i);
		mc_reg_addr[FE_SATX_QPSK_14_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS14(i);
		mc_reg_addr[FE_SATX_QPSK_7_15][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS14(i);
		mc_reg_addr[FE_SATX_QPSK_8_15][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS13(i);
		mc_reg_addr[FE_SATX_QPSK_32_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS13(i);
		mc_reg_addr[FE_SATX_8PSK_7_15][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS13(i);
		mc_reg_addr[FE_SATX_8PSK_8_15][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS13(i);
		mc_reg_addr[FE_SATX_8PSK_26_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS12(i);
		mc_reg_addr[FE_SATX_8PSK_32_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS12(i);
		mc_reg_addr[FE_SATX_16APSK_7_15][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS12(i);
		mc_reg_addr[FE_SATX_16APSK_8_15][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS12(i);
		mc_reg_addr[FE_SATX_16APSK_26_45_S][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS11(i);
		mc_reg_addr[FE_SATX_16APSK_3_5_S][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS11(i);
		mc_reg_addr[FE_SATX_16APSK_32_45][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS11(i);
		mc_reg_addr[FE_SATX_32APSK_2_3][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS11(i);
		mc_reg_addr[FE_SATX_32APSK_32_45_S][i-1] = (u16)REG_RC8CODEW_DVBSX_DEMOD_MODCODLS10(i);
	}
}

/*****************************************************
--FUNCTION	::	fe_stid135_filter_forbidden_modcodes
--ACTION	::	Kills MODCODS at the output of demod vs CNR
--PARAMS IN	::	handle -> Frontend handle
			demod -> Current demod 1 .. 8
			cnr -> Carrier to noise ratio
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_filter_forbidden_modcodes(fe_stid135_handle_t handle,   
						enum fe_stid135_demod demod,
						s32 cnr)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	u8 row_min, row_max, found_row, i;
	u32 reg_value;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if(pParams->handle_demod->Error) 
			error = FE_LLA_I2C_ERROR; 
		else {
			row_min = 0;
			row_max = sizeof(pParams->mc_flt) / sizeof(struct modcod_data) - 1;
			if(INRANGE(-300, cnr, 10000)) {
				while((row_max - row_min) > 1) {
					found_row = (u8)((row_max + row_min) >> 1);
					if(INRANGE(pParams->mc_flt[row_min].qef, cnr, pParams->mc_flt[found_row].qef))
						row_max = found_row;
					else
						row_min = found_row;
				}
			}
			/* Disable automatic filter vs. SR */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST1_SYMBRATE_FILTER(demod), 0);

			/* Disable all forbidden modcodes */
			row_max = sizeof(pParams->mc_flt) / sizeof(struct modcod_data) - 1;
			for(i = 0;i <= row_min;i++) {
				if(pParams->mc_flt[i].forbidden[demod-1] == TRUE) {
					pParams->mc_flt[i].forbidden[demod-1] = FALSE;
					error |= ChipGetOneRegister(pParams->handle_demod, pParams->mc_flt[i].register_address[demod-1], &reg_value);
					reg_value &= ~(pParams->mc_flt[i].mask_value);
					error |= ChipSetOneRegister(pParams->handle_demod, pParams->mc_flt[i].register_address[demod-1], reg_value);
				}
			}
			for(i = (u8)(row_min + 1);i <= row_max;i++) {
				if(pParams->mc_flt[i].forbidden[demod-1] == FALSE) {
					pParams->mc_flt[i].forbidden[demod-1] = TRUE;
					error |= ChipGetOneRegister(pParams->handle_demod, pParams->mc_flt[i].register_address[demod-1], &reg_value);
					reg_value |= pParams->mc_flt[i].mask_value;
					error |= ChipSetOneRegister(pParams->handle_demod, pParams->mc_flt[i].register_address[demod-1], reg_value);
				}
			}
		}

		if (pParams->handle_demod->Error ) //Check the error at the end of the function
			error = FE_LLA_I2C_ERROR; 
	}
	return error;
}

static u8 check_modcodes_mask_4bits(u8 *inventory, s32 fld_value, u8 modcode_offset, u8 index)
{
	switch(fld_value) {
		case 1:
			inventory[index++] = modcode_offset;
		break;
		case 2:
			inventory[index++] = (u8)(modcode_offset + 1);
		break;
		case 4:
			inventory[index++] = (u8)(modcode_offset + 2);
		break;
		case 8:
			inventory[index++] = (u8)(modcode_offset + 3);
		break;
	}
	return(index);
}

static u8 check_modcodes_mask_2bits(u8 *inventory, s32 fld_value, u8 modcode_offset, u8 index)
{
	switch(fld_value) {
		case 1:
			inventory[index++] = modcode_offset;
		break;
		case 2:
			inventory[index++] = (u8)(modcode_offset + 1);
		break;
	}
	return(index);
}

/*****************************************************
--FUNCTION	::	fe_stid135_modcodes_inventory
--ACTION	::	List during n ms MODCODS present in an ACM/VCM signal
--PARAMS IN	::	handle -> Front End handle
			demod -> Current demod 1 .. 8
			Duration -> function duration (ms) 
--PARAMS OUT	::	MODES_Inventory -> array :list of present MODCODS
			NbModes -> Number of detected mode codes
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_modcodes_inventory(fe_stid135_handle_t handle,
						enum fe_stid135_demod demod,
						u8 *MODES_Inventory,
						u8 *NbModes, 
						u16 Duration)
{			
	
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	u32 modcodlst0,modcodlst1,modcodlste,modcodlstf,nresetmodcod;
	u8 Index = 0;
	s32 fld_value;
	u32 reg_value;

	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error)
			error=FE_LLA_I2C_ERROR; 
		else {

			modcodlst0 = FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST0_NACCES_MODCODCH(demod); 
			modcodlst1 = FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST1_SYMBRATE_FILTER(demod);
			modcodlste = REG_RC8CODEW_DVBSX_DEMOD_MODCODLSTE(demod);
			modcodlstf = FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTF_MODCOD_NSTOCK(demod);
			nresetmodcod = FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST1_NRESET_MODCODLST(demod); 
			
			error |= ChipSetField(pParams->handle_demod, modcodlst1, 0); 		/* disable automatic filter vs. SR */
			error |= ChipSetField(pParams->handle_demod, nresetmodcod, 0);		/* Set all values to 0 */
			error |= ChipSetField(pParams->handle_demod, modcodlstf, 0); 		/* Set inventory mode */ 
			
			ChipWaitOrAbort(pParams->handle_demod, Duration);  		/* Wait for modecode occurence */ 
			
			// QPSK
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTF_DIS_QPSK_1_4(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x4, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTE_DIS_QPSK_1_3(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x8, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTE_DIS_QPSK_2_5(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0xc, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTD_DIS_QPSK_1_2(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x10, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTD_DIS_QPSK_3_5(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x14, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTC_DIS_QP_2_3(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x18, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTC_DIS_QP_3_4(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x1c, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTB_DIS_QP_4_5(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x20, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTB_DIS_QP_5_6(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x24, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTA_DIS_QP_8_9(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x28, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLSTA_DIS_QPSK_9_10(demod), &fld_value);
			Index = check_modcodes_mask_2bits(MODES_Inventory, fld_value, 0x2c, Index);
			// 8PSK
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST9_DIS_8P_3_5(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x30, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST9_DIS_8P_2_3(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x34, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST8_DIS_8P_3_4(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x38, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST8_DIS_8P_5_6(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x3c, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST7_DIS_8P_8_9(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x40, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST7_DIS_8PSK_9_10(demod), &fld_value);
			Index = check_modcodes_mask_2bits(MODES_Inventory, fld_value, 0x44, Index);
			// 16APSK
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST6_DIS_16PSK_2_3(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x48, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST6_DIS_16PSK_3_4(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x4c, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST5_DIS_16PSK_4_5(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x50, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST5_DIS_16PSK_5_6(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x54, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST4_DIS_16PSK_8_9(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x58, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST4_DIS_16PSK_9_10(demod), &fld_value);
			Index = check_modcodes_mask_2bits(MODES_Inventory, fld_value, 0x5c, Index);
			// 32APSK
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST3_DIS_32PSK_3_4(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x60, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST3_DIS_32PSK_4_5(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x64, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST2_DIS_32PSK_5_6(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x68, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST2_DIS_32PSK_8_9(demod), &fld_value);
			Index = check_modcodes_mask_4bits(MODES_Inventory, fld_value, 0x6c, Index);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLST1_DIS_32PSK_9_10(demod), &fld_value);
			Index = check_modcodes_mask_2bits(MODES_Inventory, fld_value, 0x70, Index);
			// QPSK NF DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1F_DIS_QPSK_13_45_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_QPSK_13_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1F_DIS_QPSK_13_45_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_QPSK_13_45 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1F_DIS_QPSK_9_20_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_QPSK_9_20 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1F_DIS_QPSK_9_20_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_QPSK_9_20 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_QPSK_11_20_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_QPSK_11_20 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_QPSK_11_20_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_QPSK_11_20 << 1) + 1;
			
			// 8PSK NF DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8APSK_5_9_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_8APSK_5_9_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8APSK_5_9_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_8APSK_5_9_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8APSK_26_45_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_8APSK_26_45_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8APSK_26_45_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_8APSK_26_45_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8PSK_23_36_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_8PSK_23_36 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1E_DIS_8PSK_23_36_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_8PSK_23_36 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_8PSK_25_36_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_8PSK_25_36 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_8PSK_25_36_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_8PSK_25_36 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_8PSK_13_18_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_8PSK_13_18 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_8PSK_13_18_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_8PSK_13_18 << 1) + 1;
			
			// 16APSK NF DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_16APSK_1_2_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_8PSK_13_18 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_16APSK_1_2_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_1_2_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_16APSK_8_15_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_8_15_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1D_DIS_16APSK_8_15_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_8_15_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_5_9_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_5_9_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_5_9_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_5_9_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_26_45_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_26_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_26_45_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_26_45 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_3_5_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_3_5 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_3_5_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_3_5 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_3_5_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_3_5_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1C_DIS_16APSK_3_5_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_3_5_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_28_45_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_28_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_28_45_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_28_45 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_23_36_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_23_36 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_23_36_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_23_36 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_2_3_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_2_3_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_2_3_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_2_3_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_25_36_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_25_36 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1B_DIS_16APSK_25_36_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_25_36 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_13_18_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_13_18 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_13_18_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_13_18 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_7_9_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_7_9 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_7_9_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_7_9 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_77_90_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_77_90 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_16APSK_77_90_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_77_90 << 1) + 1;
			
			// 32APSK NF DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_32APSK_2_3_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_32APSK_2_3_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS1A_DIS_32APSK_2_3_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_32APSK_2_3_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_32_45_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_32APSK_32_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_32_45_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_32APSK_32_45 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_11_15_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_32APSK_11_15 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_11_15_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_32APSK_11_15 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_7_9_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_32APSK_7_9 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS19_DIS_32APSK_7_9_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_32APSK_7_9 << 1) + 1;
			
			// 64APSK NF DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_32_45_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_64APSK_32_45_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_32_45_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_64APSK_32_45_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_11_15_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_64APSK_11_15 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_11_15_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_64APSK_11_15 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_7_9_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_64APSK_7_9 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS18_DIS_64APSK_7_9_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_64APSK_7_9 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS17_DIS_64APSK_4_5_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_64APSK_4_5 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS17_DIS_64APSK_4_5_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_64APSK_4_5 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS17_DIS_64APSK_5_6_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_64APSK_5_6 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS17_DIS_64APSK_5_6_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_64APSK_5_6 << 1) + 1;
			
			// 128APSK NF DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_128APSK_3_4_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_128APSK_3_4 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_128APSK_3_4_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_128APSK_3_4 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_128APSK_7_9_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_128APSK_7_9 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_128APSK_7_9_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_128APSK_7_9 << 1) + 1;
			
			// 256APSK DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_256APSK_29_45_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_256APSK_29_45_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_256APSK_29_45_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_256APSK_29_45_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_256APSK_2_3_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_256APSK_2_3_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS16_DIS_256APSK_2_3_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_256APSK_2_3_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_31_45_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_256APSK_31_45_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_31_45_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_256APSK_31_45_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_32_45_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_256APSK_32_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_32_45_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_256APSK_32_45 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_11_15_L_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_256APSK_11_15_L << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_11_15_L_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_256APSK_11_15_L << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_3_4_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_256APSK_3_4 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS15_DIS_256APSK_3_4_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_256APSK_3_4 << 1) + 1;
			
			// QPSK SF DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_11_45_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_QPSK_11_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_11_45_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_QPSK_11_45 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_4_15_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_QPSK_4_15 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_4_15_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_QPSK_4_15 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_14_45_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_QPSK_14_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_14_45_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_QPSK_14_45 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_7_15_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_QPSK_7_15 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS14_DIS_QPSK_7_15_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_QPSK_7_15 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_QPSK_8_15_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_QPSK_8_15 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_QPSK_8_15_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_QPSK_8_15 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_QPSK_32_45_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_QPSK_32_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_QPSK_32_45_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_QPSK_32_45 << 1) + 1;
			
			// 8PSK SF DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_8PSK_7_15_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_8PSK_7_15 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_8PSK_7_15_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_8PSK_7_15 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_8PSK_8_15_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_8PSK_8_15 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS13_DIS_8PSK_8_15_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_8PSK_8_15 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_8PSK_26_45_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_8PSK_26_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_8PSK_26_45_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_8PSK_26_45 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_8PSK_32_45_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_8PSK_32_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_8PSK_32_45_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_8PSK_32_45 << 1) + 1;
			
			// 16APSK SF DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_16APSK_7_15_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_7_15 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_16APSK_7_15_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_7_15 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_16APSK_8_15_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_8_15 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS12_DIS_16APSK_8_15_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_8_15 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_26_45_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_26_45_S << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_26_45_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_26_45_S << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_3_5_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_3_5_S << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_3_5_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_3_5_S << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_32_45_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_16APSK_32_45 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_16APSK_32_45_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_16APSK_32_45 << 1) + 1;
			
			// 32APSK SF DVBS2X
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_32APSK_2_3_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_32APSK_2_3 << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS11_DIS_32APSK_2_3_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_32APSK_2_3 << 1) + 1;
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS10_DIS_32APSK_32_45_SH_POFF(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = FE_SATX_32APSK_32_45_S << 1;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MODCODLS10_DIS_32APSK_32_45_SH_PON(demod), &fld_value);
			if (fld_value == 1)
				MODES_Inventory[Index++] = (FE_SATX_32APSK_32_45_S << 1) + 1;
						
			*NbModes = (u8)(Index + 1);
			
			/*set numeral mode */
			error |= ChipSetField(pParams->handle_demod,modcodlst0,0); 
			/* read mode code number sent to LDPC */ 
			error |= ChipGetOneRegister(pParams->handle_demod, (u16)modcodlste, &reg_value);
			MODES_Inventory[Index] = (u8)reg_value;
			if (MODES_Inventory[Index]==0) 
				*NbModes = (u8)(*NbModes - 1); /* Most probably the signal is not locked or not a DVB-S2 */
			
			error |= ChipSetField(pParams->handle_demod, modcodlst0, 1);	/* back to mode code mask mode */
			error |= ChipSetField(pParams->handle_demod, modcodlstf, 1); 	/* back to mode code filter mode */
			error |= ChipSetField(pParams->handle_demod, modcodlst1, 1);	/* enable automatic filter vs. SR */

			if (pParams->handle_demod->Error ) /*Check the error at the end of the function*/ 
				error = FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_get_soc_temperature
--ACTION	::	Gets SOC temperature in deg C
--PARAMS IN	::	handle -> Front End handle
--PARAMS OUT	::	soc_temp -> temperature
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_get_soc_temperature(fe_stid135_handle_t handle, s16 *soc_temp)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u32 reg_value;
	s32 soc_temperature;
	u8 dcorrect, data_ready;
	u16 timeout = 0;
	const u16 soc_temp_timeout = 500;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	
	// Reset thermal sensor block
	error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C9THS_GLUE_TOP_TSENSOR_CONFIG, 0x0);
	
	error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_STATUS126, &reg_value);
	dcorrect = reg_value & 0x1F;
	// If thermal sensor is not calibrated, program dcorrect with a default value
	if(dcorrect == 0) {
		error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C9THS_GLUE_TOP_TSENSOR_CONFIG, 0x10 << 5);
	} else {
		error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C9THS_GLUE_TOP_TSENSOR_CONFIG, (u32)(dcorrect << 5));
	}
	// Release reset and PDN at the same time
	error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C9THS_GLUE_TOP_TSENSOR_CONFIG, &reg_value);
	reg_value |= 0x410;
	error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C9THS_GLUE_TOP_TSENSOR_CONFIG, reg_value);
	reg_value = 0;
	error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C9THS_GLUE_TOP_TSENSOR_STATUS, &reg_value);
	data_ready = (reg_value>>10) & 0x1;
	while((data_ready != 1) && (timeout < soc_temp_timeout)) {
		timeout = (u16)(timeout + 5);
		error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_C9THS_GLUE_TOP_TSENSOR_STATUS, &reg_value);
		data_ready = (reg_value>>10) & 0x1;
	}
	if(timeout < soc_temp_timeout) {
		soc_temperature = (((s32)reg_value >> 11) & 0xFF) - 103;
		*soc_temp = (s8)soc_temperature;
	} else
		error = FE_LLA_NODATA;

	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_check_sis_or_mis
--ACTION	::	Return the MIS or SIS stream info
--PARAMS IN	::	matype -> MATYPE value
--PARAMS OUT	::	NONE
--RETURN	::	MIS or SIS TRUE : SIS, FALSE MIS
--***************************************************/
static BOOL fe_stid135_check_sis_or_mis(u8 matype)
{

  u8 sis_or_mis; 

  sis_or_mis = (matype >> 5) & 0x1;   

  return (BOOL)(sis_or_mis);
}

/*****************************************************
--FUNCTION	::	fe_stid135_select_min_isi
--ACTION	::	Returns the MIS or SIS stream info
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 .. 8
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
static fe_lla_error_t fe_stid135_select_min_isi(fe_stid135_handle_t handle, enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 min_isi, matype;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			/* Setup HW to store Min ISI */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL0_ISIOBS_MODE(demod), 1);
	
			/* Get Min ISI */
			ChipWaitOrAbort(pParams->handle_demod, 30);

			error |= fe_stid135_read_hw_matype(pParams->handle_demod, demod, &matype, &min_isi);
	
			/*Enable the MIS filtering*/
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_FILTER_EN(demod), 1);
	
			/*Set the MIS filter*/
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_ISIENTRY(demod), (u32)min_isi);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_ISIBITENA(demod), (u32)0xFF);
	
			/* Reset the packet delineator */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(demod), 1);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(demod), 0);
	
			/* Setup HW to store Current ISI */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL0_ISIOBS_MODE(demod), 0);
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_get_isi
--ACTION	::	Returns the ISI selected and output after filter
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demd 1 .. 8
--PARAMS OUT	::	ISI selected
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_get_isi(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 *p_isi_current)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u32 reg_value;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
		
	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error)
			error=FE_LLA_I2C_ERROR;
		else {
			error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_ISIENTRY(demod), &reg_value);
			*p_isi_current = (u8)reg_value;
		}
	}
	return error;
}
			
/*****************************************************
--FUNCTION	::	fe_stid135_isi_scan
--ACTION	::	return the number and list of ISI
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 .. 8
--PARAMS OUT	::	p_isi_struct -> Struct ISI Nb of ISI and ISI numbers
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_isi_scan(fe_stid135_handle_t handle, enum fe_stid135_demod demod, struct fe_sat_isi_struct_t *p_isi_struct)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 CurrentISI,matype;
	u8 i;
	u32 j=0, n;
	BOOL ISIAlreadyFound;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error)
			error=FE_LLA_I2C_ERROR; 
		else { 
			// Test mode to be able to read all ISIs in MATSTR0 register, 
			// otherwise only selected ISI is in MATSTR0 register
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_TPKTDELIN_TESTBUS_SELECT(demod), 8);
			/* Setup HW to store Current ISI */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL0_ISIOBS_MODE(demod), 0);
			ChipWaitOrAbort(pParams->handle_demod,100);
			/* initialise struct to FF */
			for (i=0; i < 9; i++)
				p_isi_struct->isi[i] = 0xFF;
			p_isi_struct->nb_isi = 0;
			/* Get Current ISI and store in struct */
			for (i=0; i < 40; i++) {
				ISIAlreadyFound = FALSE;
				error |= fe_stid135_read_hw_matype(pParams->handle_demod, demod, &matype, &CurrentISI);
				for (j=0; j<9; j++) {		
					if (CurrentISI == p_isi_struct->isi[j]) {
						ISIAlreadyFound = TRUE;
					}
				}
				if (! ISIAlreadyFound) {
					n = p_isi_struct->nb_isi++;
					p_isi_struct->isi[n] = CurrentISI;
				}
				ChipWaitOrAbort(pParams->handle_demod,10);
			}
			// Go back to previous value of test mode
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_TPKTDELIN_TESTBUS_SELECT(demod), 0);
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_get_list_isi
--ACTION  	::	Returns the Max and Min ISI
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 .. 8
--PARAMS OUT	::	p_min_isi -> ISI Min
			p_max_isi -> ISI Max
--RETURN 	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_get_list_isi(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 *p_min_isi, u8 *p_max_isi)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	#if 0
		u8 matype, i=0;
	#endif
	s32 fld_value;
			
	if(pParams == NULL)
		error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error) 
			error=FE_LLA_I2C_ERROR; 
		else {
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_ISIMINSTR_MATYPE_ISIMIN(demod), &fld_value);
			*p_min_isi = (u8)fld_value;
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_ISIMAXSTR_MATYPE_ISIMAX(demod), &fld_value);
			*p_max_isi = (u8)fld_value;
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_select_isi
--ACTION	::	Selects an ISI for a MIS stream
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 .. 8
			isi_wanted -> Desired ISI nb
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_select_isi(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 isi_wanted)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;      
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams == NULL)
	error=FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error)
			error=FE_LLA_I2C_ERROR;
		else {
			/* Force MIS mode if MIS signal previously detected */
			if(pParams->mis_mode[demod-1] == TRUE) {
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_MATCST1_MATYPECST_SISMIS(demod), 0);
			}
			
			/*Enable the MIS filtering*/
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_FILTER_EN(demod), 1);

			/*Set the MIS filter*/
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_ISIBITENA(demod), 0xFF);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_ISIENTRY(demod), isi_wanted);
		}
	}
	return error;
}



/*****************************************************
--FUNCTION	::	fe_stid135_set_mis_filtering
--ACTION	::	Set The multiple input stream filter and mask  
--PARAMS IN	::	Handle -> Front End Handle
			demod -> Current demod 1 .. 8
			EnableFiltering -> enable disable the MIS filter
			mis_filter  -> MIS Filter
			mis_mask -> MIS Mask
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_mis_filtering(fe_stid135_handle_t Handle, enum fe_stid135_demod demod, BOOL EnableFiltering, u8 mis_filter, u8 mis_mask)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;      
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)Handle;

	if(pParams == NULL)
		error = FE_LLA_INVALID_HANDLE;
	else {
		if (pParams->handle_demod->Error) 
			error=FE_LLA_I2C_ERROR; 
		else {
			if(EnableFiltering == TRUE) {
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_FILTER_EN(demod), 1); /*Enable the MIS filtering*/
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_ISIENTRY(demod), mis_filter);    /*Set the MIS filter*/
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_PKTDELIN_ISIBITENA(demod), mis_mask);    	/*Set the MIS Mask*/
			} else {
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_FILTER_EN(demod), 0);	/*Disable the MIS filtering*/    	
			}
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(demod), 1);	/*reset the packet delin*/
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_PKTDELIN_PDELCTRL1_ALGOSWRST(demod), 0);	/*reset the packet delin*/
						
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/ 
				error=FE_LLA_I2C_ERROR; 
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_unlock
--ACTION	::	Unlock the demodulator , set the demod to idle state  
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1..8
-PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_unlock(fe_stid135_handle_t handle, enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL) {
		error = FE_LLA_INVALID_HANDLE;
	} else {
		if(pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR;
		else {
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(demod), 0x1C); /* Demod Stop*/

			if(pParams->handle_demod->Error)  /*Check the error at the end of the function*/
				error = FE_LLA_I2C_ERROR;
		}
	}
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_abort_flag
--ACTION	::	Set Abort flag On/Off  
--PARAMS IN	::	handle -> Front End Handle
			abort -> boolean value
-PARAMS OUT	::	NONE
--RETURN	::	Error (if any)

--***************************************************/
fe_lla_error_t fe_stid135_set_abort_flag(fe_stid135_handle_t handle, BOOL abort)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;

	if(pParams == NULL) {
		error = FE_LLA_INVALID_HANDLE;
	} else {
		if(pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			ChipAbort(pParams->handle_demod, abort);
			
			if(pParams->handle_demod->Error) /*Check the error at the end of the function*/ 
			error = FE_LLA_I2C_ERROR; 
		}
	}
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_standby
--ACTION	::	Set demod STANDBY mode On/Off by accessing to the field
			STANDBY (bit[7] of the register SYNTCTRL @F1B6).
			In standby mode only the I2C clock is functional
			in order to wake-up the device
--PARAMS IN	::	handle -> Front End Handle
			standby_on -> standby ON/OFF switch
-PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_standby(fe_stid135_handle_t handle, u8 standby_on)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	enum fe_stid135_demod demod;

	if(pParams == NULL) {
		error = FE_LLA_INVALID_HANDLE;
	} else {
		if (pParams->handle_demod->Error) 
			error = FE_LLA_I2C_ERROR; 
		else {
			/* TODO : put also in standby FSK, DISEQC, AFE */
			
			/*Stop all Path Clocks*/
			for(demod = FE_SAT_DEMOD_1;demod <= FE_SAT_DEMOD_8;demod++) {
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_STOPCLK_STOP_CKDEMOD(demod), standby_on);   /*Stop Sampling clock*/ 
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_STOPCLK_STOP_CKDVBS1FEC(demod), standby_on);   /*Stop DVBS1 FEC clock*/  
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_STOPCLK_STOP_CKDVBS2FEC(demod), standby_on);   /*Stop DVBS2 FEC clock*/  
			}
			
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_SYNTCTRL_STANDBY, standby_on); /* general power ON*/
			
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/ 
				error=FE_LLA_I2C_ERROR;
		}

	}
	
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_clear_filter_ram
--ACTION	::	Clears RAM used to filter PIDs/GSE labels and protocols
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1.. 8
-PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_clear_filter_ram(fe_stid135_handle_t handle, enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	u8 i;
	struct fe_stid135_internal_param *pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams == NULL) {
		error = FE_LLA_INVALID_HANDLE;
	} else {
		if (pParams->handle_demod->Error) 
			error = FE_LLA_I2C_ERROR; 
		else {
			/* Init for PID filtering feature */
			pParams->pid_flt[demod-1].first_disable_all_command = TRUE;
			/* Init for GSE filtering feature */
			pParams->gse_flt[demod-1].first_disable_all_protocol_command = TRUE;
			pParams->gse_flt[demod-1].first_disable_all_label_command = TRUE;
			
			/* Reset shared H/W RAM */
			for(i=0;i < RAM_SIZE;i++) {
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0x10 + (u32)i);
				error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTL(demod), 0x00);
			}
			/* Disable filter so that output everything */
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_TSPIDFLTM(demod), 0);
		}
	}
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_get_packet_error_rate
--ACTION	::	Returns the number of error packet and the window packet count
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 ..8
--PARAMS OUT	::	packets_error_count -> Number of packet error, max is 2^23 packet.
		  	total_packets_count -> total window packets , max is 2^24 packet.
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_get_packet_error_rate(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u32 *packets_error_count, u32 *total_packets_count)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	u32 packets_count4 = 0,
	   packets_count3 = 0,
	   packets_count2 = 0,
	   packets_count1 = 0,
	   packets_count0 = 0;
	BOOL demod_locked = FALSE;
	
	
	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			fe_stid135_get_lock_status(handle, demod, &demod_locked);
			if(demod_locked == FALSE) { /*if Demod+FEC not locked */
				*packets_error_count = 1 << 23;		 /*Packet error count is set to the maximum value*/	
				*total_packets_count = 1 << 24;		 /*Total Packet count is set to the maximum value*/
			} else {
				/*Read the error counter 2 (23 bits) */
				error |= FE_STiD135_GetErrorCount(pParams->handle_demod, FE_STiD_COUNTER2, demod, packets_error_count);
				*packets_error_count &= 0x7FFFFF;
				
				/* Read the total packet counter 40 bits, read 5 bytes is mondatory */
				error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_FECSPY_FBERCPT4(demod), &packets_count4);    /*Read the Total packet counter byte 5*/
				error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_FECSPY_FBERCPT3(demod), &packets_count3);    /*Read the Total packet counter byte 4*/  
				error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_FECSPY_FBERCPT2(demod), &packets_count2);    /*Read the Total packet counter byte 3*/  
				error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_FECSPY_FBERCPT1(demod), &packets_count1);    /*Read the Total packet counter byte 2*/  
				error |= ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_FECSPY_FBERCPT0(demod), &packets_count0);    /*Read the Total packet counter byte 1*/

				if( (packets_count4 == 0) && (packets_count3 == 0)) { /*Use the counter for a maximum of 2^24 packets*/  
					*total_packets_count = ((packets_count2 & 0xFF) << 16) + ((packets_count1 & 0xFF) << 8) + (packets_count0 & 0xFF);
				} else {
					*total_packets_count = 1 << 24;
				}
				
				if(*total_packets_count == 0) {
					/* if the packets count doesn't start yet the packet error = 1 and total packets = 1 */
					/* if the packet counter doesn't start there is a FEC error */
					*total_packets_count = 1;
					*packets_error_count = 1;
				}
			}
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_FECSPY_FBERCPT4(demod), 0);    /*Reset the Total packet counter */ 
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_FECSPY_FECSPY_BERMETER_RESET(demod), 1);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_FECSPY_FECSPY_BERMETER_RESET(demod), 0);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_HWARE_ERRCTRL2(demod), 0xc1); /*Reset the packet Error counter2 (and Set it to infinit error count mode )*/
			
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/
				error = FE_LLA_I2C_ERROR; 
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_vcore_supply
--ACTION	::	Sets Vcore supply voltage
--PARAMS IN	::	handle -> Front End Handle
			pwm_value -> 
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_vcore_supply(fe_stid135_handle_t handle)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	u32 reg_value, pwm_value = 0x80, minor_cut;
	u8 avs_code;
	fe_lla_lookup_t *lookup = NULL;

	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			lookup = &fe_stid135_avs_look_up;
	
			if ((lookup != NULL) && (lookup->size)) {
				// read process value in SAFMEM
				error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_STATUS100, &reg_value);
				avs_code = (u8)(reg_value & 0x1F); // process_tracking
				// Check if sample is fused. If it is fused, then reject 0 and 1 process code
				error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_STATUS98, &minor_cut);
				if(minor_cut != 0) {
					if((avs_code == 0) || (avs_code == 1)) {
						return(FE_LLA_NOT_SUPPORTED);
					}
				}
				pwm_value = (u32)lookup->table[avs_code].realval; // PWM value, linear vs AVS voltage
			}
			// Program PWM_OUT
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_PWMTIMER_PWM_VAL0, pwm_value);
			// Enable PWM
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_PWMTIMER_PWM_CTRL, 0x200);
			// Vref reference: 1.02V if internal DCDC1V8, or 1.1V if external DCDC1V8
			if(pParams->internal_dcdc == 1) {
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG36, 0x4);
			} else if(pParams->internal_dcdc == 0) {
				error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG36, 0x0);
			}
			// Program PIO1[2] in alternate function 1
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1000, &reg_value);
			reg_value |= 0x00000100;
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1000, reg_value);
			// Program PIO1[2] in output
			error |= ChipGetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, &reg_value);
			reg_value |= 0x00000004;
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, reg_value);
			
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/
				error = FE_LLA_I2C_ERROR; 
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_maxllr_rate
--ACTION	::	Sets the max LLR rate 
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 .. 8
			maxllr_rate -> 90/129/180/258 MLLR/s
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t	fe_stid135_set_maxllr_rate( fe_stid135_handle_t handle,
					enum fe_stid135_demod demod, u32 maxllr_rate)
{

	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;

	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			if (maxllr_rate == 90) // 90 = 720Mcb/s / 8
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG0_SDEMAP_MAXLLRRATE(demod), 3);
			else if (maxllr_rate == 129) // 129.1667 = demod master clock
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG0_SDEMAP_MAXLLRRATE(demod), 2);
			else if (maxllr_rate == 180) // 180 = 720Mcb/s / 4
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG0_SDEMAP_MAXLLRRATE(demod), 1);
			else // 258.3333 = twice demod master clock
				error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG0_SDEMAP_MAXLLRRATE(demod), 0);

			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/
				error = FE_LLA_I2C_ERROR; 
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
	
}

/*****************************************************
--FUNCTION	::	fe_stid135_multi_normal_short_tuning
--ACTION	::	Provides an alternative set of LLR gains
 			for short frames only
--PARAMS IN	::	handle -> Front End Handle
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_multi_normal_short_tuning(fe_stid135_handle_t handle)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
		
	pParams = (struct fe_stid135_internal_param *) handle;
	
	if (pParams != NULL) {		
		if (pParams->handle_demod->Error)
				error = FE_LLA_I2C_ERROR; 

		else {
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF14, 0x28);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF15, 0x30);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF16, 0x50);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF19, 0x30);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF20, 0x40);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF21, 0x4a);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF22, 0x58);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF24, 0x80);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF25, 0x80);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF26, 0xb8);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF27, 0xe0);
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF56_1, 0x30);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF57_0, 0x14);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF58_1, 0x28);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF61_1, 0x3d);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_DVBS2FEC_GAINLLR_SF62_0, 0x58);
		}

		if (pParams->handle_demod->Error)
			error |= FE_LLA_I2C_ERROR; 

	} else
		error = FE_LLA_INVALID_HANDLE; 

	return error; 
}

/*****************************************************
--FUNCTION	::	fe_stid135_init_before_bb_flt_calib
--ACTION	::	Set chip ready for BB filter calibration
--PARAMS IN	::	Handle -> Front End Handle
			tuner_nb -> Current tuner 1 .. 4
			squarewave_generation -> boolean variable to 
			enable/disable squarewave signal generation
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any) 
--***************************************************/
fe_lla_error_t fe_stid135_init_before_bb_flt_calib(fe_stid135_handle_t handle, FE_OXFORD_TunerPath_t tuner_nb, BOOL squarewave_generation)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
		
	pParams = (struct fe_stid135_internal_param *) handle;
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGCKS(FE_SAT_DEMOD_1), 0x02);

	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_BCLCNLK(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLCNLK(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_BCLCLK(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLCLK(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARFREQ(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARHDR(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR1BCFG(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR1B2(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR1B1(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR1B0(FE_SAT_DEMOD_1), 0x00);

	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGCFG(FE_SAT_DEMOD_1), 0xc3);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_RTCNLK(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_RTCLK(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG2(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG1(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG0(FE_SAT_DEMOD_1), 0x00);

	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR2CFR1(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR22(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR21(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR20(FE_SAT_DEMOD_1), 0x00);
		
		
	
	/* ------------- ------------------- --------------------------------- */
	
	/* set bbfilt input to clock freq of (FVCO/2)/13 ~ 238.5MHz 
	  (programmable division by 13 in AFE) (for default FVCO=6200MHz !!!). */
	if(squarewave_generation == TRUE) {
		Oxford_StartBBcal(pParams->handle_demod, tuner_nb, 1);
	} else {
		Oxford_StopBBcal(pParams->handle_demod, tuner_nb);
	}

	/* Todo: Better to switch off the Tuner but leave the ADC working */
	
	/* ------------- ------------------- --------------------------------- */ 
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_FILTCFGM(FE_SAT_DEMOD_1), 0x07);    /* switch off hd filters, set manual  */
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_FILTCFGL(FE_SAT_DEMOD_1), 0x00);    /* switch off hd filters, no amplification  */ 
	
	
	/* ------------- AGC1 configuration --------------------------------- */ 
	/*  AGC1CFG: IQ mismatch control,  */ 
	
	/*  AMM_FROZEN:  compensation freeze (unsigned)
	    AMM_CORRECT: compensation authorization
	*/
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_AGC1CFG_AMM_FROZEN(FE_SAT_DEMOD_1),  1);
			
	/*	[3]  QUAD_FROZEN: compensation freeze (unsigned)
		[2]  QUAD_CORRECT: compensation authorization		  
		00:  */  
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_AGC1CFG_QUAD_FROZEN(FE_SAT_DEMOD_1),  1);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1AMM(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1QUAD(FE_SAT_DEMOD_1), 0x00);
	
	/*	AGC1CN AGC1 control
		[2:0]  AGCIQ_BETA: AGC1 loop speed: 000: stop			  */
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_AGC1CN_AGCIQ_BETA(FE_SAT_DEMOD_1), 0);


	/*	AGC1ADJ AGC1 loop set point	 ????  */
	
	/* ------------- AGC2 configuration --------------------------------- */
	
	/* AGC2O AGC2 configuration   */
	/* [2:0]  AGC2_COEF: AGC2 loop speed:  000: open loop, AGC2IM/L in manual */		
	// gAPISetField(DEMOD, pathId, FDEMOD_P1_AGC2_COEF, 0); 
	//ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_AGC2O_AGC2_COEF(FE_SAT_DEMOD_1), 0);
	
	/* AGC2IM/L						   */
	/* AGC2I1,AGC2I0 AGC2 accumulator  */
	
	/* AGC2ADJ Adjusted value of agc2_ref	  */
	/* AGC2ADJ_MANUAL: switch to manual mode 1: the automatic calculation is stopped, a value can be written in agc2ref_adjusted */	   

	
	
	/* ------------- Carrier Loop --------------------------------- */ 
	/* CARCFG Carrier 1 configuration								*/
	/* [2]  ROTAON: 1: carrier 1 derotator in action     0: carrier 1 loop open (unsigned)*/
		
	/* ------------- Timing  Loop --------------------------------- */ 
	
			 
	
	/* ------------- internal settings ---------------------------- */
	switch(tuner_nb) {
		case AFE_TUNER1:
			error |= ChipSetField(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC1_CTRL_AGC1_BB_CTRL, 3);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC1_BB_PWM, 0xCF); 	/* set AGC1 manually */
		break;
		case AFE_TUNER2:
			error |= ChipSetField(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC2_CTRL_AGC2_BB_CTRL, 3);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC2_BB_PWM, 0xCF); 	/* set AGC1 manually */
		break;
		case AFE_TUNER3:
			error |= ChipSetField(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC3_CTRL_AGC3_BB_CTRL, 3);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC3_BB_PWM, 0xCF); 	/* set AGC1 manually */
		break;
		case AFE_TUNER4:
			error |= ChipSetField(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC4_CTRL_AGC4_BB_CTRL, 3);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC4_BB_PWM, 0xCF); 	/* set AGC1 manually */
		break; 
		case AFE_TUNER_ALL:
			error |= ChipSetFieldImage(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC1_CTRL_AGC1_BB_CTRL, 3);		 /* set AGC1 manually */
			error |= ChipSetFieldImage(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC2_CTRL_AGC2_BB_CTRL, 3);		 /* set AGC1 manually */
			error |= ChipSetFieldImage(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC3_CTRL_AGC3_BB_CTRL, 3);		 /* set AGC1 manually */
			error |= ChipSetFieldImage(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC4_CTRL_AGC4_BB_CTRL, 3);		 /* set AGC1 manually */
			error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC1_CTRL, 4);
			
			error |= ChipSetFieldImage(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC1_BB_PWM_AGC1_BB_PWM, 0xCF);
			error |= ChipSetFieldImage(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC2_BB_PWM_AGC2_BB_PWM, 0xCF);
			error |= ChipSetFieldImage(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC3_BB_PWM_AGC3_BB_PWM, 0xCF);
			error |= ChipSetFieldImage(pParams->handle_demod, FLD_FSTID135_AFE_AFE_AGC4_BB_PWM_AGC4_BB_PWM, 0xCF);
			error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC1_BB_PWM, 4);
		break;
	}
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(FE_SAT_DEMOD_1), 0x40);	  //idee PG 20/04/2017
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFG4(FE_SAT_DEMOD_1), 0x80);	  //idee PG 20/04/2017
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(FE_SAT_DEMOD_1), 0x00);	  //idee PG ""
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2O(FE_SAT_DEMOD_1), 0x00);		  //idee PG ""
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2I1(FE_SAT_DEMOD_1), 0x40);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2I0(FE_SAT_DEMOD_1), 0x00); 
	
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GCTRL_LOW_RATE(FE_SAT_DEMOD_1), 0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GCTRL_INPUT_MODE(FE_SAT_DEMOD_1), 0);
	/* 0 = symbols/intersymbols */
	/* 1 = CTE */
	/* 2 = Z4 */
	/* 3 = filter calibration */
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_FFTCTRL_CTE_MODE(FE_SAT_DEMOD_1), 0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_FFTCTRL_FFT_SHIFT(FE_SAT_DEMOD_1), /*1*/0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_FFTCTRL_FFT_MODE(FE_SAT_DEMOD_1), 5);
	/* 0 = 8192 points, 1 = 4096 points */
	/* 2 = 2048 points, 3 = 1024 points */
	/* 4 = 512 points,  5 = 256 points */
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_FFTACC_NB_ACC_FFT(FE_SAT_DEMOD_1), 255);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_THRESHOLD_NO_STOP(FE_SAT_DEMOD_1), 0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEBUG1_CFO_FILT(FE_SAT_DEMOD_1), 0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEBUG1_SEL_MEM(FE_SAT_DEMOD_1), 0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_THRESHOLD_MAX_THRESHOLD(FE_SAT_DEMOD_1), 4);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GAINCONT_MODE_CONTINUOUS(FE_SAT_DEMOD_1), 0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GAINCONT_GAIN_CONTINUOUS(FE_SAT_DEMOD_1), 0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_UPDCONT_UPD_CONTINUOUS(FE_SAT_DEMOD_1), 0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEBUG1_DISABLE_RESCALE(FE_SAT_DEMOD_1), 0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEBUG1_DEBUG_INTERSYMBOL(FE_SAT_DEMOD_1), 1);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEBUG1_DISABLE_AVERAGE(FE_SAT_DEMOD_1), 1);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_FFTCTRL_MODE_INTERSYMBOL(FE_SAT_DEMOD_1), 1);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEBUG1_MODE_FULL(FE_SAT_DEMOD_1), 1);
	/* Switch off PSD (Power Spectral Density) Log format*/
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEBUG1_MODE_DB(FE_SAT_DEMOD_1), 0);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GCTRL_UFBS_ENABLE(FE_SAT_DEMOD_1), 1);
	
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_AGCRF_AGCRFCFG_AGCRF_BETA(tuner_nb), 0);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFIN1(tuner_nb), 0x40);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFIN0(tuner_nb), 0x00);
	
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG0_FIFO2_ULTRABS(FE_SAT_DEMOD_1), 1); /* Priority to UFBS scan */
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_MODE_HAUTDEBIT(FE_SAT_DEMOD_1), 1); /* Narrowband setting */
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DMDISTATE_I2C_DEMOD_MODE(FE_SAT_DEMOD_1), 2); /* set PEA to UFBS mode  */
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_TNRCFG2_TUN_IQSWAP(FE_SAT_DEMOD_1), 0); // DO NOT set to 1 !!!!
	
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_AGC1SHDB_ADCIN_IQOFF(FE_SAT_DEMOD_1), 0);	/* set I input active */

	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFREF(tuner_nb), 0x58);
	
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_uninit_after_bb_flt_calib
--ACTION	::	Unset chip from BB filter calibration mode and
			switch back to normal mode
--PARAMS IN	::	Handle -> Front End Handle
			tuner_nb -> Current tuner 1 .. 4
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any) 
--***************************************************/
fe_lla_error_t fe_stid135_uninit_after_bb_flt_calib(fe_stid135_handle_t handle, FE_OXFORD_TunerPath_t tuner_nb)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
		
	pParams = (struct fe_stid135_internal_param *) handle;

	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGCKS(FE_SAT_DEMOD_1), 0x00);

	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_BCLCNLK(FE_SAT_DEMOD_1), 0x18);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLCNLK(FE_SAT_DEMOD_1), 0x28);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_BCLCLK(FE_SAT_DEMOD_1), 0x18);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLCLK(FE_SAT_DEMOD_1), 0x28);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARFREQ(FE_SAT_DEMOD_1), 0x79);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARHDR(FE_SAT_DEMOD_1), 0x18);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR1BCFG(FE_SAT_DEMOD_1), 0x67);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGCFG(FE_SAT_DEMOD_1), 0xd3);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_RTCNLK(FE_SAT_DEMOD_1), 0x56);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_RTCLK(FE_SAT_DEMOD_1), 0x56);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG2(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG1(FE_SAT_DEMOD_1), 0x06);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG0(FE_SAT_DEMOD_1), 0xec);

	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR2CFR1(FE_SAT_DEMOD_1), 0x25);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR22(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR21(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR20(FE_SAT_DEMOD_1), 0x1c);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_FILTCFGM(FE_SAT_DEMOD_1), 0x30);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1CFG(FE_SAT_DEMOD_1),  0x54);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1AMM(FE_SAT_DEMOD_1), 0xff);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1QUAD(FE_SAT_DEMOD_1), 0xfe);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1CN(FE_SAT_DEMOD_1), 0x99);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2O(FE_SAT_DEMOD_1), 0x5b);

	switch(tuner_nb) {
		case AFE_TUNER1:
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC1_CTRL, 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC1_BB_PWM, 0x00);
		break;
		case AFE_TUNER2:
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC2_CTRL, 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC2_BB_PWM, 0x00);
		break;
		case AFE_TUNER3:
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC3_CTRL, 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC3_BB_PWM, 0x00);
		break;
		case AFE_TUNER4:
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC4_CTRL, 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RSTID135_AFE_AFE_AGC4_BB_PWM, 0x00);
		break; 
	}
	error |= Oxford_StopBBcal(pParams->handle_demod, tuner_nb);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(FE_SAT_DEMOD_1), 0xc8);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFG4(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(FE_SAT_DEMOD_1), 0x1c);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2I1(FE_SAT_DEMOD_1), 0x6c);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2I0(FE_SAT_DEMOD_1), 0x40); 
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_GCTRL(FE_SAT_DEMOD_1), 0x06);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_FFTCTRL(FE_SAT_DEMOD_1), 0xc8);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_FFTACC(FE_SAT_DEMOD_1), 0x0a);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_THRESHOLD(FE_SAT_DEMOD_1), 0x04);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DEBUG1(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_GAINCONT(FE_SAT_DEMOD_1), 0x00);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_UPDCONT(FE_SAT_DEMOD_1), 0x00);
	
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_AGCRF_AGCRFCFG_AGCRF_BETA(tuner_nb), 1);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFIN1(tuner_nb), 0xca);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFIN0(tuner_nb), 0x10);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_HDEBITCFG0(FE_SAT_DEMOD_1), 0x01);
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG2_MODE_HAUTDEBIT(FE_SAT_DEMOD_1), 2);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TNRCFG2(FE_SAT_DEMOD_1), 0x02);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC1SHDB(FE_SAT_DEMOD_1), 0x00);

	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_AGCRF_AGCRFREF(tuner_nb), 0x60);
	
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRUP2(FE_SAT_DEMOD_1), 0xCE);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRUP1(FE_SAT_DEMOD_1), 0xC9);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRUP0(FE_SAT_DEMOD_1), 0xCC);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRLOW2(FE_SAT_DEMOD_1), 0xCE);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRLOW1(FE_SAT_DEMOD_1), 0x21);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRLOW0(FE_SAT_DEMOD_1), 0x50);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINIT2(FE_SAT_DEMOD_1), 0xCE);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINIT1(FE_SAT_DEMOD_1), 0x75);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINIT0(FE_SAT_DEMOD_1), 0x8E);
	error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARCFG(FE_SAT_DEMOD_1), 0xC6);

	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_read_bin_from_psd_mem
--ACTION	::	Reads PSD memory knowing bin max
--PARAMS IN	::	Handle -> Front End Handle
			bin_max -> bin number where max
			amplitude has been found
--PARAMS OUT	::	NONE
--RETURN	::	magnitude of 5 bins
--***************************************************/
fe_lla_error_t fe_stid135_read_bin_from_psd_mem(fe_stid135_handle_t handle, u32 bin_max)
{   
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	s32 fld_value;
	u32 exp, val[5]= { 0 }, memstat, nb_samples, den;
	u32 val_max_m2, val_max_m1, val_max, val_max_p1, val_max_p2;
	struct fe_stid135_internal_param *pParams;

	// Carefull! In PSD memory, datas are 32-bits wide coded split in 2 fields:
	// (31:27); exp_max
	// (26:0): psd
	// with fft length of 256 bins, we get exp_max=0, but with higher fft lengths, exp_max is no more equal to 0
	pParams = (struct fe_stid135_internal_param *) handle;
	error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_FFTCTRL_FFT_MODE(FE_SAT_DEMOD_1), &fld_value);
	den = (u32)(XtoPowerY(2, (u32)fld_value));
	if(den != 0)
		nb_samples = (u32)(8192 / den);
	else
		return(FE_LLA_BAD_PARAMETER);
	error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEBUG1_MODE_FULL(FE_SAT_DEMOD_1), &fld_value);
	if(fld_value == 1) { // 32-bit mode
		if((bin_max%4) == 0) { // case bin_max divisable by 4 => 2 memory access needed
			if(bin_max == 0) {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), (((nb_samples-1)/4) >> 8) & 0x03);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), ((nb_samples-1)/4) & 0xFF);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			} else {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), ((bin_max/4-1) >> 8) & 0x03);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), (bin_max/4-1) & 0xFF);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
			memstat = (u32)fld_value;
			while (!memstat) {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
				memstat = (u32)fld_value;
			}
			
			/* start computing val_max_m2 */
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_EXPMAX_EXP_MAX(FE_SAT_DEMOD_1), &fld_value);
			exp = (u32)fld_value;
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA41(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA41_MEM_VAL4(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA40_MEM_VAL4(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA51_MEM_VAL5(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA50_MEM_VAL5(FE_SAT_DEMOD_1));
			val_max_m2 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_m2 */
			
			/* start computing val_max_m1 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA61(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA61_MEM_VAL6(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA60_MEM_VAL6(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA71_MEM_VAL7(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA70_MEM_VAL7(FE_SAT_DEMOD_1));
			val_max_m1 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_m1 */

			error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), ((bin_max/4) >> 8) & 0x03);
			error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), (bin_max/4) & 0xFF);
			error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
			memstat = (u32)fld_value;
			while (!memstat) {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
				memstat = (u32)fld_value;
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_EXPMAX_EXP_MAX(FE_SAT_DEMOD_1), &fld_value);
			exp = (u32)fld_value;
			/* start computing val_max */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA01(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA01_MEM_VAL0(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA00_MEM_VAL0(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA11_MEM_VAL1(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA10_MEM_VAL1(FE_SAT_DEMOD_1));
			val_max = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max */
			
			if(bin_max == nb_samples-1) {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), 0x00);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), 0x00);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
			memstat = (u32)fld_value;
			while (!memstat) {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
				memstat = (u32)fld_value;
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_EXPMAX_EXP_MAX(FE_SAT_DEMOD_1), &fld_value);
			exp = (u32)fld_value;
			
			/* start computing val_max_p1 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA21(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA21_MEM_VAL2(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA20_MEM_VAL2(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA31_MEM_VAL3(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA30_MEM_VAL3(FE_SAT_DEMOD_1));
			val_max_p1 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_p1 */
			
			/* start computing val_max_p2 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA41(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA41_MEM_VAL4(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA40_MEM_VAL4(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA51_MEM_VAL5(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA50_MEM_VAL5(FE_SAT_DEMOD_1));
			val_max_p2 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_p2 */

		} else if((bin_max%4) == 1) { // case bin_max = 4*N+1
			if(bin_max == 0) {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), (((nb_samples-1)/4) >> 8) & 0x03);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), ((nb_samples-1)/4) & 0xFF);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			} else {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), ((bin_max/4) >> 8) & 0x03);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), (bin_max/4) & 0xFF);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
			memstat = (u32)fld_value;
			while (!memstat) {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
				memstat = (u32)fld_value;
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_EXPMAX_EXP_MAX(FE_SAT_DEMOD_1), &fld_value);
			exp = (u32)fld_value;
			/* start computing val_max_m2 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA61(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA61_MEM_VAL6(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA60_MEM_VAL6(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA71_MEM_VAL7(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA70_MEM_VAL7(FE_SAT_DEMOD_1));
			val_max_m2 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_m2 */
			
			/* start computing val_max_m1 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA01(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA01_MEM_VAL0(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA00_MEM_VAL0(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA11_MEM_VAL1(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA10_MEM_VAL1(FE_SAT_DEMOD_1));
			val_max_m1 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_m1 */
			
			/* start computing val_max */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA21(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA21_MEM_VAL2(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA20_MEM_VAL2(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA31_MEM_VAL3(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA30_MEM_VAL3(FE_SAT_DEMOD_1));
			val_max = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max */
			
			if(bin_max == nb_samples-1) {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), 0x00);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), 0x00);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
				memstat = (u32)fld_value;
				while (!memstat) {
					error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
					memstat = (u32)fld_value;
				}
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_EXPMAX_EXP_MAX(FE_SAT_DEMOD_1), &fld_value);
				exp = (u32)fld_value;
			}
			/* start computing val_max_p1 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA41(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA41_MEM_VAL4(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA40_MEM_VAL4(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA51_MEM_VAL5(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA50_MEM_VAL5(FE_SAT_DEMOD_1));
			val_max_p1 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_p1 */
			
			/* start computing val_max_p2 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA61(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA61_MEM_VAL6(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA60_MEM_VAL6(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA71_MEM_VAL7(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA70_MEM_VAL7(FE_SAT_DEMOD_1));
			val_max_p2 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_p2 */

		} else if((bin_max%4) == 2) { // case bin_max = 4*N+2
			if(bin_max == 0) {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), (((nb_samples-1)/4) >> 8) & 0x03);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), ((nb_samples-1)/4) & 0xFF);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			} else {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), ((bin_max/4) >> 8) & 0x03);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), (bin_max/4) & 0xFF);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
			memstat = (u32)fld_value;
			while (!memstat) {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
				memstat = (u32)fld_value;
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_EXPMAX_EXP_MAX(FE_SAT_DEMOD_1), &fld_value);
			exp = (u32)fld_value;
			/* start computing val_max_m2 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA01(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA01_MEM_VAL0(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA00_MEM_VAL0(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA11_MEM_VAL1(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA10_MEM_VAL1(FE_SAT_DEMOD_1));
			val_max_m2 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_m2 */
			
			/* start computing val_max_m1 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA21(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA21_MEM_VAL2(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA20_MEM_VAL2(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA31_MEM_VAL3(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA30_MEM_VAL3(FE_SAT_DEMOD_1));
			val_max_m1 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_m1 */
			
			/* start computing val_max */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA41(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA41_MEM_VAL4(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA40_MEM_VAL4(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA51_MEM_VAL5(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA50_MEM_VAL5(FE_SAT_DEMOD_1));
			val_max = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max */
			
			if(bin_max == nb_samples-1) {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), 0x00);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), 0x00);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
				memstat = (u32)fld_value;
				while (!memstat) {
					error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
					memstat = (u32)fld_value;
				}
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_EXPMAX_EXP_MAX(FE_SAT_DEMOD_1), &fld_value);
				exp = (u32)fld_value;
			}
			/* start computing val_max_p1 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA61(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA61_MEM_VAL6(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA60_MEM_VAL6(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA71_MEM_VAL7(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA70_MEM_VAL7(FE_SAT_DEMOD_1));
			val_max_p1 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_p1 */
			
			/* start computing val_max_p2 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA01(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA01_MEM_VAL0(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA00_MEM_VAL0(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA11_MEM_VAL1(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA10_MEM_VAL1(FE_SAT_DEMOD_1));
			val_max_p2 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_p2 */

		} else { // case bin_max = 4*N+3 => 2 memory access needed
			if(bin_max == 0) {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), (((nb_samples-1)/4) >> 8) & 0x03);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), ((nb_samples-1)/4) & 0xFF);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			} else {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), ((bin_max/4) >> 8) & 0x03);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), (bin_max/4) & 0xFF);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
			memstat = (u32)fld_value;
			while (!memstat) {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
				memstat = (u32)fld_value;
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_EXPMAX_EXP_MAX(FE_SAT_DEMOD_1), &fld_value);
			exp = (u32)fld_value;
			/* start computing val_max_m2 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA21(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA21_MEM_VAL2(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA20_MEM_VAL2(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA31_MEM_VAL3(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA30_MEM_VAL3(FE_SAT_DEMOD_1));
			val_max_m2 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_m2 */
			
			/* start computing val_max_m1 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA41(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA41_MEM_VAL4(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA40_MEM_VAL4(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA51_MEM_VAL5(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA50_MEM_VAL5(FE_SAT_DEMOD_1));
			val_max_m1 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_m1 */
			
			/* start computing val_max */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA61(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA61_MEM_VAL6(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA60_MEM_VAL6(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA71_MEM_VAL7(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA70_MEM_VAL7(FE_SAT_DEMOD_1));
			val_max = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max */
			
			if(bin_max == nb_samples-1) {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), 0x00);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), 0x00);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			} else {
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR1_MEM_ADDR(FE_SAT_DEMOD_1), ((bin_max/4+1) >> 8) & 0x03);
				error |= ChipSetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMADDR0_MEM_ADDR(FE_SAT_DEMOD_1), (bin_max/4+1) & 0xFF);
				error |= ChipSetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMADDR1(FE_SAT_DEMOD_1), 2);
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
			memstat = (u32)fld_value;
			while (!memstat) {
				error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMSTAT_MEM_STAT(FE_SAT_DEMOD_1), &fld_value);
				memstat = (u32)fld_value;
			}
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_EXPMAX_EXP_MAX(FE_SAT_DEMOD_1), &fld_value);
			exp = (u32)fld_value;
			/* start computing val_max_p1 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA01(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA01_MEM_VAL0(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA00_MEM_VAL0(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA11_MEM_VAL1(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA10_MEM_VAL1(FE_SAT_DEMOD_1));
			val_max_p1 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_p1 */
			
			/* start computing val_max_p2 */
			error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_MEMVA21(FE_SAT_DEMOD_1), 4);
			val[3] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA21_MEM_VAL2(FE_SAT_DEMOD_1));
			val[2] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA20_MEM_VAL2(FE_SAT_DEMOD_1));
			val[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA31_MEM_VAL3(FE_SAT_DEMOD_1));
			val[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_MEMVA30_MEM_VAL3(FE_SAT_DEMOD_1));
			val_max_p2 = (((val[3] & 0x7) << 24) + (val[2] << 16) + (val[1] << 8) + val[0]) * (u32)(XtoPowerY(2, exp));
			/* end computing val_max_p2 */
		}
		return(val_max_m2+val_max_m1+val_max+val_max_p1+val_max_p2);
	} else { // to be implemented for 16-bit
	}
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_measure_harmonic
--ACTION	::	Performs a fft on a specified frequency/harmonic
--PARAMS IN	::	Handle -> Front End Handle
			desired_frequency -> frequency at which fft has to be performed (Hz)
			harmonic -> number of harmonic (usually 1 or 3)
			amplitude has been found
--PARAMS OUT	::	Magnitude based on 5 bins
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_measure_harmonic(fe_stid135_handle_t handle, u32 desired_frequency, u8 harmonic, u32 *val_5bin)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	s32 fld_value = 0, contmode;
	u32 timeout = 0;
	struct fe_stid135_internal_param *pParams;
	u32 binmax[2], peak_bin;
	
	pParams = (struct fe_stid135_internal_param *) handle;
	/* --------- measure harmonic -------------*/
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GCTRL_UFBS_RESTART(FE_SAT_DEMOD_1), 1);
	
	if(pParams->lo_frequency == 0) /* LO frequency not yet computed */
		error |= FE_STiD135_GetLoFreqHz(pParams, &(pParams->lo_frequency));
	pParams->tuner_frequency[FE_SAT_DEMOD_1-1] = (s32)(desired_frequency * harmonic - pParams->lo_frequency * 1000000 + 4000000); /* offset of 4MHz to avoid "battement" issue */
	pParams->demod_search_range[FE_SAT_DEMOD_1-1] = 30000000;
	error |= fe_stid135_set_carrier_frequency_init(pParams, pParams->tuner_frequency[FE_SAT_DEMOD_1-1], FE_SAT_DEMOD_1);
	
	pParams->demod_symbol_rate[FE_SAT_DEMOD_1-1] = 1*20*1000000;
	error |= fe_stid135_set_symbol_rate(pParams->handle_demod, pParams->master_clock, pParams->demod_symbol_rate[FE_SAT_DEMOD_1-1], FE_SAT_DEMOD_1);
	
	error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GCTRL_UFBS_RESTART(FE_SAT_DEMOD_1), 0); /* run acquisition 1h and wait until done */
	error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GAINCONT_MODE_CONTINUOUS(FE_SAT_DEMOD_1), &fld_value);
	if (!fld_value) {
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GSTAT_PSD_DONE(FE_SAT_DEMOD_1), &contmode);
		while((contmode != TRUE) && (timeout < 40)){
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GSTAT_PSD_DONE(FE_SAT_DEMOD_1), &contmode);
			timeout = (u8)(timeout + 1);
			ChipWaitOrAbort(pParams->handle_demod, 1);
		}
	}
	
	error |= ChipGetRegisters(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_BINMAX1(FE_SAT_DEMOD_1), 2);
	binmax[0] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_BINMAX0_BIN_MAX(FE_SAT_DEMOD_1));
	binmax[1] = (u32)ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_BINMAX1_BIN_MAX(FE_SAT_DEMOD_1));
	peak_bin = ((binmax[1] & 0x1F) << 8) + binmax[0];
	*val_5bin = fe_stid135_read_bin_from_psd_mem(pParams, peak_bin);
	return(error);
}

/*****************************************************
--FUNCTION	::	fe_stid135_bb_flt_calib
--ACTION	::	Calibration algorithm which should be performed
			at power-up for each RF input
--PARAMS IN	::	Handle -> Front End Handle
			tuner_nb -> Current tuner 1 .. 4
--PARAMS OUT	::	NONE
--RETURN	::	error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_bb_flt_calib(fe_stid135_handle_t handle, FE_OXFORD_TunerPath_t tuner_nb)
{
	s32 fld_value = 0;
	u32 measure_h1, measure_h3;
	u32 ratio = 0, ratio_threshold = 174; /* 174 because 10xlog(174/10)=12.4dB */
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	BOOL calib_value_found = FALSE;
	s32 epsilon = 5;
	s32 start_index = 0;
	s32 end_index;
	s32 middle_index = 0;
	struct fe_stid135_internal_param *pParams;
	s32 best_i_cal = 0x00, best_q_cal = 0x00;
	
	pParams = (struct fe_stid135_internal_param *) handle;

	error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_FFTCTRL_FFT_MODE(FE_SAT_DEMOD_1), &fld_value);
	end_index = (s32)(8192 / XtoPowerY(2, (u32)fld_value)) - 1;
	/* Search loop (dichotomy method) */
	while(!calib_value_found && ((end_index - start_index) > 1)) {
	
		middle_index = (start_index + end_index)/2;  // we set middle index for ical
		
		error |= Oxford_StoreBBcalCode(pParams->handle_demod, tuner_nb, (u8)middle_index, (u8)(middle_index>>6));
		error |= fe_stid135_measure_harmonic(handle, SQUAREWAVE_FREQUENCY, 1, &measure_h1);
		error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GSTAT_PEAK_FOUND(FE_SAT_DEMOD_1), &fld_value);
		if(fld_value == 1) {
			error |= fe_stid135_measure_harmonic(handle, SQUAREWAVE_FREQUENCY, 3, &measure_h3);
			error |= ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_GSTAT_PEAK_FOUND(FE_SAT_DEMOD_1), &fld_value);
			if(fld_value == 1) {
				ratio = (measure_h1 * 10) / measure_h3;
			}
		}

		calib_value_found = (ABS((s32)(ratio - ratio_threshold)) <= epsilon);
			
		if(ratio < ratio_threshold) end_index = middle_index;  // if value which is at ical = im is
		// greater than desired one, end index becomes middle index, therefore search range
		// is narrower on next turn
		else start_index = middle_index;  // otherwise start index becomes middle index
		//	and range is also narrower
	}
	if(ABS((s32)(ratio - ratio_threshold)) <= epsilon) { // if we find good value, we stop loop
		best_i_cal = middle_index;
		best_q_cal = middle_index >> 6;
	} else { // otherwise we set default value for ical
		best_i_cal = 0xC0;
		best_q_cal = 0x3;
	}

	Oxford_StoreBBcalCode(pParams->handle_demod, tuner_nb, (u8)best_i_cal, (u8)best_q_cal);
	return(error);
}


/*****************************************************
--FUNCTION	::	fe_stid135_set_gold_code
--ACTION	::	Management of PLS scrambling
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 ..8
			goldcode -> DVB-S2 gold code
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_gold_code(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u32 goldcode)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			/* plscramb_root is the DVBS2 gold code. The root of PRBS X is computed internally */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT2_PLSCRAMB_MODE(demod), 1);
			/* DVBS2 Gold Code */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT2_PLSCRAMB_ROOT(demod), (goldcode >> 16) & 0x3);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT1_PLSCRAMB_ROOT(demod), (goldcode >> 8) & 0xFF);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT0_PLSCRAMB_ROOT(demod), goldcode & 0xFF);
			
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/
				error = FE_LLA_I2C_ERROR; 
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_goldcold_root
--ACTION	::	Management of PLS scrambling
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 ..8
			goldcode_root -> root of goldcode
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_goldcold_root(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u32 goldcode_root)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			/* plscramb_root is the root of PRBS X */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT2_PLSCRAMB_MODE(demod), 0);
			/* Root of PRBS X */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT2_PLSCRAMB_ROOT(demod), (goldcode_root >> 16) & 0x3);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT1_PLSCRAMB_ROOT(demod), (goldcode_root >> 8) & 0xFF);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT0_PLSCRAMB_ROOT(demod), goldcode_root & 0xFF);
			
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/
				error = FE_LLA_I2C_ERROR;
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_disable_goldcold
--ACTION	::	Disable management of PLS scrambling
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 ..8
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_disable_goldcold(fe_stid135_handle_t handle, enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			/* When writing 1 in PLROOT field, we disable goldcode feature */
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT2_PLSCRAMB_MODE(demod), 0);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT2_PLSCRAMB_ROOT(demod), 0x00);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT1_PLSCRAMB_ROOT(demod), 0x00);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT0_PLSCRAMB_ROOT(demod), 0x01);
			
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/
				error = FE_LLA_I2C_ERROR;
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_pls
--ACTION	::	Management of PLS scrambling
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 ..8
			pls_mode -> scrambling mode
			pls_code -> scrambling code
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_pls(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 mode, u32 code)
{
	unsigned error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT2_PLSCRAMB_MODE(demod), (mode) & 0x3);
			ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT2_PLSCRAMB_ROOT(demod), (code >> 16) & 0x3);
			ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT1_PLSCRAMB_ROOT(demod), (code >> 8) & 0xFF);
			ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT0_PLSCRAMB_ROOT(demod), code & 0xFF);
			
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/
				error = FE_LLA_I2C_ERROR; 
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return (fe_lla_error_t)error;
}

fe_lla_error_t fe_stid135_get_pls(fe_stid135_handle_t handle, enum fe_stid135_demod demod, u8 *p_mode, u32 *p_code )
{
	unsigned error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			error = ChipGetRegisters(pParams->handle_demod, REG_RC8CODEW_DVBSX_DEMOD_PLROOT2(demod),3);
			*p_mode = ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT2_PLSCRAMB_MODE(demod));
			*p_code = (ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT2_PLSCRAMB_ROOT(demod)) << 16) |
					(ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT1_PLSCRAMB_ROOT(demod)) << 8) |
					(ChipGetFieldImage(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_PLROOT0_PLSCRAMB_ROOT(demod)));
			if (pParams->handle_demod->Error) /*Check the error at the end of the function*/
				error = FE_LLA_I2C_ERROR; 
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return (fe_lla_error_t)error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_enable_constel_display
--ACTION	::	Set constellation display
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 ..8
			measuring_point -> Selection of measuring point
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_enable_constel_display(fe_stid135_handle_t handle, enum fe_stid135_demod demod,
	u8 measuring_point)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			// Output constellation display samples at symbol rate
			// Test bus out and constellation point
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TEST_OUT, 1);
			switch(demod) {
				case FE_SAT_DEMOD_1:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(1), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 0);
				break;
				case FE_SAT_DEMOD_2:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(1), 1);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 0);
				break;
				case FE_SAT_DEMOD_3:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(2), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 1);
				break;
				case FE_SAT_DEMOD_4:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(2), 1);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 1);
				break;
				case FE_SAT_DEMOD_5:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(3), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 2);
				break;
				case FE_SAT_DEMOD_6:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(3), 1);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 2);
				break;
				case FE_SAT_DEMOD_7:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(4), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 3);
				break;
				case FE_SAT_DEMOD_8:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(4), 1);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 3);
				break;
			}
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TCTL1(demod), measuring_point);
			// MLCK on FE_GPIO14
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_TOP_CTRL_GPIO14CFG, 0x7E);
			// I/Q constellation output (Alternate 5)
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, 0x00555555);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, 0x00555555);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, 0x00555555);
			// MLCK output: SoC alternate1
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1000, 0x00001000);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1103, 0x00000004);
			// Output enable: all for test
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, 0x3FF01F1B);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, 0x3F3F3F0F);
			// Enable 270MHz clock which is mandatory in DVBS
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DMDCFG4_DIS_CLKENABLE(demod), 1);

			if (pParams->handle_demod->Error) /* Check the error at the end of the function */
				error = FE_LLA_I2C_ERROR;
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_disable_constel_display
--ACTION	::	Unset constellation display
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 ..8
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_disable_constel_display(fe_stid135_handle_t handle, enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			// Output constellation display samples at symbol rate
			// Test bus out and constellation point
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TEST_OUT, 0);
			switch(demod) {
				case FE_SAT_DEMOD_1:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(1), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 0);
				break;
				case FE_SAT_DEMOD_2:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(1), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 0);
				break;
				case FE_SAT_DEMOD_3:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(2), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 0);
				break;
				case FE_SAT_DEMOD_4:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(2), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 0);
				break;
				case FE_SAT_DEMOD_5:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(3), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 0);
				break;
				case FE_SAT_DEMOD_6:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(3), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 0);
				break;
				case FE_SAT_DEMOD_7:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(4), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 0);
				break;
				case FE_SAT_DEMOD_8:
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_PATH_CTRL_GEN_TBUSSEL_TBUS_SELECT(4), 0);
					error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_C8CODEW_TOP_CTRL_TSTOUT_TS, 0);
				break;
			}
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TCTL1(demod), 0x00);
			// MLCK on FE_GPIO14
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_C8CODEW_TOP_CTRL_GPIO14CFG, 0x82);
			// I/Q constellation output (Alternate 5)
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1002, 0x00000000);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1003, 0x00000000);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1003, 0x00000000);
			// MLCK output: SoC alternate1
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1000, 0x00000000);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1103, 0x00000000);
			// Output enable: all for test
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_NORTH_SYSTEM_CONFIG1040, 0x00000000);
			error |= ChipSetOneRegister(pParams->handle_soc, (u16)REG_RSTID135_SYSCFG_SOUTH_SYSTEM_CONFIG1040, 0x00000000);
			// Enable 270MHz clock which is mandatory in DVBS
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DMDCFG4_DIS_CLKENABLE(demod), 0);

			if (pParams->handle_demod->Error) /* Check the error at the end of the function */
				error = FE_LLA_I2C_ERROR;
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
}

/*****************************************************
--FUNCTION	::	fe_stid135_set_vtm
--ACTION	::	Management of Versatile Tuner Mode. This versatile 
tuner mode down converts the carrier from a given frequency and outputs I/Q
samples at a given sample rate and therefore bandwidth. This allows any 
frequency within the input band (950 to 2150 MHz) to be demodulated, filtered
and output as samples or symbols
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 ..8
			frequency_hz -> RF frequency (Hz)
			symbol_rate -> Symbol Rate (Symbol/s)
			roll_off -> Roll-Off
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_set_vtm(fe_stid135_handle_t handle, enum fe_stid135_demod demod,
	u32 frequency_hz, u32 symbol_rate, enum fe_sat_rolloff roll_off)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_MANUALS2_ROLLOFF(demod), 1); // manual roll-off
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(demod), roll_off); // roll-off selection
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(demod), 0x40); // DVB-S only
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFG3(demod), 0x0A);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFG4(demod), 0x04);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_HDEBITCFG2(demod), 0x54); // Simple wide band
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_HDEBITCFG0(demod), 0x08);
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2O(demod), 0x03); // AGC set-up: AGC2 remains active
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGCKS(demod), 0x02);
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARCFG(demod), 0x06); // Carrier loop frozen
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLCNLK(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_BCLCNLK(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLCLK(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_BCLCLK(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARFREQ(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARHDR(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR1BCFG(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINC2(demod), 0x80);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINC1(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINC0(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR2CFR1(demod), 0x00);
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_RTCNLK(demod), 0x00); // Timing loop frozen
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_RTCLK(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGCFG3(demod), 0x16);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG2(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG1(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG0(demod), 0x00);
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_VITERBI_VITSCALE(demod), 0x04); // Prevents Viterbi block from locking
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_VITERBI_VTH78(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_VITERBI_PRVIT(demod), 0x60);

			error |= fe_stid135_enable_constel_display(handle, demod, 5);

			// Program carrier offset
			error |= FE_STiD135_GetLoFreqHz(pParams, &(pParams->lo_frequency));
			pParams->tuner_frequency[demod-1] = (s32)(frequency_hz - pParams->lo_frequency*1000000);
			pParams->demod_search_range[demod-1] = 60000000;
			error |= fe_stid135_set_carrier_frequency_init(handle, (s32)frequency_hz, demod);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARCFG(demod), 0x06); // Carrier loop frozen, one more time because fe_stid135_set_carrier_frequency_init() function writes 0x46 in it
			// Program SR
			error |= fe_stid135_set_symbol_rate(pParams->handle_demod, pParams->master_clock, symbol_rate, demod);
			// Launch a warm start (AEP = 0x18)
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDISTATE(demod), 0x18);
			// OPTION (should be automatic): Wait 100000 symbols and copy P1_CFRINIT2/1/0 values in P1_CFR2/1/0
			/*WAIT_N_MS(100); // to be adapted
			ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINIT2(demod), &reg_value);
			ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR12(demod), reg_value);
			ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINIT1(demod), &reg_value);
			ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR11(demod), reg_value);
			ChipGetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINIT0(demod), &reg_value);
			ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR10(demod), reg_value);*/
			
			if (pParams->handle_demod->Error) /* Check the error at the end of the function */
				error = FE_LLA_I2C_ERROR;
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
}


/*****************************************************
--FUNCTION	::	fe_stid135_unset_vtm
--ACTION	::	Management of Versatile Tuner Mode. Restores the
context of demod register settings
--PARAMS IN	::	handle -> Front End Handle
			demod -> Current demod 1 ..8
--PARAMS OUT	::	NONE
--RETURN	::	Error (if any)
--***************************************************/
fe_lla_error_t fe_stid135_unset_vtm(fe_stid135_handle_t handle, enum fe_stid135_demod demod)
{
	fe_lla_error_t error = FE_LLA_NO_ERROR;
	struct fe_stid135_internal_param *pParams;
	
	pParams = (struct fe_stid135_internal_param *)handle;
	
	if(pParams != NULL) {		
		if (pParams->handle_demod->Error)
			error = FE_LLA_I2C_ERROR; 
		else {
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_MANUALS2_ROLLOFF(demod), 0);
			error |= ChipSetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_DEMOD_ROLLOFF_CONTROL(demod), 0);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFGMD(demod), 0xC8);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFG3(demod), 0x08);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_DMDCFG4(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_HDEBITCFG2(demod), 0x94);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_HDEBITCFG0(demod), 0x01);
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGC2O(demod), 0x5B);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_AGCKS(demod), 0x00);
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARCFG(demod), 0xC6);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLCNLK(demod), 0x28);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_BCLCNLK(demod), 0x18);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_ACLCLK(demod), 0x28);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_BCLCLK(demod), 0x18);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARFREQ(demod), 0x79);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CARHDR(demod), 0x18);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR1BCFG(demod), 0x67);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINC2(demod), 0x05);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINC1(demod), 0x29);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFRINC0(demod), 0x58);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_CFR2CFR1(demod), 0x25);
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_RTCNLK(demod), 0x56);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_RTCLK(demod), 0x56);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGCFG3(demod), 0x06);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG2(demod), 0x40);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG1(demod), 0x06);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_DEMOD_TMGREG0(demod), 0xEC);
			
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_VITERBI_VITSCALE(demod), 0x00);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_VITERBI_VTH78(demod), 0x28);
			error |= ChipSetOneRegister(pParams->handle_demod, (u16)REG_RC8CODEW_DVBSX_VITERBI_PRVIT(demod), 0xBF);
			
			if (pParams->handle_demod->Error) /* Check the error at the end of the function */
				error = FE_LLA_I2C_ERROR;
		}
	} else
		error = FE_LLA_INVALID_HANDLE;
		
	return error;
}

STCHIP_Error_t stvvglna_init(SAT_VGLNA_Params_t *InitParams, STCHIP_Handle_t *hChipHandle)
{
	STCHIP_Handle_t hChip = NULL;
	STCHIP_Error_t error = CHIPERR_NO_ERROR; 
	u32 reg_value;
	u8 i;
	
	STCHIP_Register_t DefSTVVGLNAVal[STVVGLNA_NBREGS]=
	{
		{ RSTVVGLNA_REG0, 0x20 },
		{ RSTVVGLNA_REG1, 0x0F },
		{ RSTVVGLNA_REG2, 0x50 },
		{ RSTVVGLNA_REG3, 0x20 }
	};


		/* fill elements of external chip data structure */
		InitParams->Chip->NbInsts  = DEMOD_NBINSTANCES;
		InitParams->Chip->NbRegs   = STVVGLNA_NBREGS;
		InitParams->Chip->NbFields = STVVGLNA_NBFIELDS;										  
		InitParams->Chip->ChipMode = STCHIP_MODE_I2C2STBUS;
		InitParams->Chip->pData = NULL;
		
		InitParams->Chip->WrStart  = RSTVVGLNA_REG0;	// Default mode for STBus interface A2D1S1 : many issues such as: bad accuracy of SR and freq, not possible to lock demods#5 to #8 if blind search and SR>20MS/s
		InitParams->Chip->WrSize  = STVVGLNA_NBREGS;
		InitParams->Chip->RdStart = RSTVVGLNA_REG0;
		InitParams->Chip->RdSize = STVVGLNA_NBREGS;	//	ChipSetMapRegisterSize(STCHIP_REGSIZE_8);
		
	
		(*hChipHandle) = ChipOpen(InitParams->Chip);
		
		hChip=(*hChipHandle);
				
		if(hChip != NULL)
		{
			/*******************************
			**   CHIP REGISTER MAP IMAGE INITIALIZATION
			**     ----------------------
			********************************/
			ChipUpdateDefaultValues(hChip,DefSTVVGLNAVal);

			for(i=0;i<STVVGLNA_NBREGS;i++)
				hChip->pRegMapImage[i].Size = STCHIP_REGSIZE_8;

			error = ChipGetOneRegister(hChip,RSTVVGLNA_REG0, &reg_value);
			hChip->ChipID = (u8)reg_value;
			printk("VGLNA Chip id =0x%x\n",hChip->ChipID );
			error = hChip->Error;
		}

	
	return error;

}


STCHIP_Error_t stvvglna_set_standby(STCHIP_Handle_t hChip, U8 StandbyOn)
{	
	STCHIP_Error_t error = CHIPERR_NO_ERROR;

	printk("stvvglan standby\n");
	if(hChip!=NULL)
	{
		if(StandbyOn)
		{
			error = ChipSetField(hChip,FSTVVGLNA_LNAGCPWD,1);
		}
		else
		{
			error = ChipSetField(hChip,FSTVVGLNA_LNAGCPWD,0);
		}
		
	}
	else
		error = CHIPERR_INVALID_HANDLE;
	
	return error;
}

STCHIP_Error_t stvvglna_get_status(STCHIP_Handle_t hChip, U8 *Status)
{
	STCHIP_Error_t error = CHIPERR_NO_ERROR;
	s32 flagAgcLow,flagAgcHigh;
	
	if(hChip!=NULL)
	{
		error = ChipGetField(hChip, FSTVVGLNA_RFAGCHIGH, &flagAgcHigh);
		error = ChipGetField(hChip,FSTVVGLNA_RFAGCLOW, &flagAgcLow);
		
		if(flagAgcHigh)
		{
			(*Status)=VGLNA_RFAGC_HIGH;
		}
		else if(flagAgcLow)
		{
			(*Status)=(U8)VGLNA_RFAGC_LOW;
		}
		else
			(*Status)=(U8)VGLNA_RFAGC_NORMAL; 
		
		error = ChipGetError(hChip);	
	}
	else
		error = CHIPERR_INVALID_HANDLE;


	return error;
}


STCHIP_Error_t stvvglna_get_gain(STCHIP_Handle_t hChip,S32 *Gain)
{

	S32 VGO, swlnaGain;
	STCHIP_Error_t error = CHIPERR_NO_ERROR;

	if(hChip != NULL)
	{
		error = ChipGetField(hChip, FSTVVGLNA_VGO, &VGO);	
		error = ChipGetError(hChip);
		
		/*Trig to read the VGO and SWLNAGAIN val*/
		error = ChipSetFieldImage(hChip,FSTVVGLNA_GETAGC,1);
		error = ChipSetRegisters(hChip,RSTVVGLNA_REG1,1);
		WAIT_N_MS(5);
		
		/*(31-VGO[4:0]) * 13/31 + (3-SWLNAGAIN[1:0])*6 */ 
		error = ChipGetField(hChip,FSTVVGLNA_VGO, &VGO);
		error = ChipGetField(hChip,FSTVVGLNA_SWLNAGAIN, &swlnaGain);
		(*Gain)=(31-VGO)*13;
		(*Gain)/=31;
		(*Gain)+=(6*(3-swlnaGain));
	}
	else
		error = CHIPERR_INVALID_HANDLE;
	
	return error;
}

STCHIP_Error_t stvvglna_term(STCHIP_Handle_t hChip)
{
	STCHIP_Error_t error = CHIPERR_NO_ERROR;
	
	if(hChip)
	{
		#ifndef ST_OSLINUX 
			if(hChip->pData)	
				free(hChip->pData);
			ChipClose(hChip);
		#endif
	}
	
	return error;
}

fe_lla_error_t get_current_llr(fe_stid135_handle_t handle,enum fe_stid135_demod demod_path,s32 *current_llr)
{
	fe_lla_error_t error=FE_LLA_NO_ERROR;
	s32 max_llr_allowed, raw_bit_rate;
	s32 fld_value[2];
	struct fe_stid135_internal_param *pParams;
	pParams = (struct fe_stid135_internal_param *) handle;
	// Bit rate = Mclk * tsfifo_bitrate / 16384

	ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSBITRATE1_TSFIFO_BITRATE(demod_path), &(fld_value[0]));
	ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_HWARE_TSBITRATE0_TSFIFO_BITRATE(demod_path), &(fld_value[1]));

	raw_bit_rate = ((fld_value[0]) << 8) + (fld_value[1]);
	FE_STiD135_GetMclkFreq(pParams, (u32*)&(fld_value[0]));
	raw_bit_rate = (s32)(((fld_value[0])/16384)) * raw_bit_rate;
	printk("\nBit rate = %d Mbits/s\n", raw_bit_rate/1000000);
	// LLR = TS bitrate * 1 / PR
	if(pParams->demod_results[demod_path-1].modcode != 0) {
		if(pParams->demod_results[demod_path-1].standard == FE_SAT_DVBS2_STANDARD) {
			if(pParams->demod_results[demod_path-1].modcode <= 131)
				*current_llr = (raw_bit_rate / 100) * dvbs2_modcode_for_llr_x100[pParams->demod_results[demod_path-1].modcode];
		}
		if(pParams->demod_results[demod_path-1].standard == FE_SAT_DVBS1_STANDARD) {
			if(pParams->demod_results[demod_path-1].puncture_rate <= 8)
				*current_llr = (raw_bit_rate / 100) * dvbs1_modcode_for_llr_x100[pParams->demod_results[demod_path-1].puncture_rate];
		}
		if(*current_llr != 0)
			printk("Current LLR  = %d MLLR/s\n", *current_llr/1000000);
		else
			printk("LLR unknown\n");
		

		if((*current_llr/1000)<80000)
			fe_stid135_set_maxllr_rate(handle,demod_path,90);
		else if(((*current_llr/1000)>80000)&&((*current_llr/1000)<113000))
		    fe_stid135_set_maxllr_rate(handle,demod_path,129);	
		else if(((*current_llr/1000)>113000)&&((*current_llr/1000)<162000))
			fe_stid135_set_maxllr_rate(handle,demod_path,180);
		else 			
			fe_stid135_set_maxllr_rate(handle,demod_path,250);

		

	} else printk("LLR cannot be computed because dummy PLF!!\n");

	ChipGetField(pParams->handle_demod, FLD_FC8CODEW_DVBSX_DEMOD_HDEBITCFG0_SDEMAP_MAXLLRRATE(demod_path), &max_llr_allowed);

	switch(max_llr_allowed) {

		case 0:
			printk("Absolute maximum rate allowed by the LLR clock\n");
		break;
		case 1:
			printk("Max LLR allowed = 180 MLLR/s\n");
			if(*current_llr > 162000000)
				printk("Careful! LLR may reach max allowed LLR!\n");
		break;
		case 2:
			FE_STiD135_GetMclkFreq(handle, (u32*)&(fld_value[0])) ;

			printk("Max LLR allowed = %d MLLR/s\n", fld_value[0]);

			FE_STiD135_GetMclkFreq(handle, (u32*)&(fld_value[0])) ;

			if(*current_llr >fld_value[0]/10*9)
				printk("Careful! LLR may reach max allowed LLR!\n");

		break;
		case 3:
			printk("Max LLR allowed = 90 MLLR/s\n");
			if(*current_llr >  81000000 )
				printk("Careful! LLR may reach max allowed LLR!\n");

		break;
		default:
			printk("Unknown max LLR\n");
		break;
	}
	return FE_LLA_NO_ERROR;

}

