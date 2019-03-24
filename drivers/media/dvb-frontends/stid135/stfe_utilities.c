/* 
* This file is part of STiD135 OXFORD LLA 
* 
* Copyright (c) <2014>-<2018>, STMicroelectronics - All Rights Reserved 
* Author(s): Laetitia Brochier (laetitia.brochier@st.com), Thierry Delahaye (thierry.delahaye@st.com) for STMicroelectronics. 
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
file stfe_utilities.c
*/
/*! \file stfe_utilities.c
    \brief This file contains some mathematical functions.
*/

/* includes ---------------------------------------------------------------- */
#include "globaldefs.h"

#define MULT32X32(a,b) (((((u32)((a)>>16))*((u32)((b)>>16)))<<1) +((((u32)((a)>>16))*((u32)(b&0x0000ffff)))>>15) + ((((u32)((b)>>16))*((u32)((a)&0x0000ffff)))>>15))


/*****************************************************
**FUNCTION	::	Get2Comp
**ACTION	::	Compute  the 2s complement 
**PARAMS IN	::	Number		-> a	 
			::	bits number	-> width	
**PARAMS OUT::	
**RETURN	::	
*****************************************************/
s32 Get2Comp(s32 a, s32 width)
{
	if(width == 32)
    	return a;
	else
		return (a >= (1<<(width-1))) ? (a - (1<<width)): a;
}

/*****************************************************
**FUNCTION	::	XtoPowerY
**ACTION	::	Compute  x^y (where x and y are integers) 
**PARAMS IN	::	Number -> x
**				Power -> y
**PARAMS OUT::	NONE
**RETURN	::	2^n
*****************************************************/
u32 XtoPowerY(s32 Number, u32 Power)
{
	u32 i;
	u32 result = 1;
	u32 oldresult = 0;

	if(Power>=32){
		printk("Potentiall unsafe call: Number = %d Power = %d  -- \n",Number,Power);
	}
	for(i=0;i<Power;i++){
		oldresult =  result;
		result *= Number;
		if(result<=oldresult)
			printk("overflow:Number=%d, Power =%d  --\n",Number,Power);
	}
	return result;
}


#define PRECISION 7                                                                                                                                                            
#define STlog10_2  301   /* log10_2 = 0.30102999566398119521373889472449 */                                                                                                        

    
static const unsigned short logtable[] =                                                                                                                                       
{                                                                                                                                                                              
	0,    6,    11,   17,                                                                                                                                                      
	22,   28,   33,   39,                                                                                                                                                      
	44,   50,   55,   61,                                                                                                                                                      
	66,   71,   77,   82,                                                                                                                                                      
	87,   93,   98,   103,                                                                                                                                                     
	109,  114,  119,  124,                                                                                                                                                     
	129,  134,  140,  145,                                                                                                                                                     
	150,  155,  160,  165,                                                                                                                                                     
	170,  175,  180,  185,                                                                                                                                                     
	190,  195,  200,  205,                                                                                                                                                     
	209,  214,  219,  224,                                                                                                                                                     
	229,  234,  238,  243,                                                                                                                                                     
	248,  253,  257,  262,                                                                                                                                                     
	267,  271,  276,  281,                                                                                                                                                     
	285,  290,  295,  299,                                                                                                                                                     
	304,  308,  313,  317,                                                                                                                                                     
	322,  326,  331,  335,                                                                                                                                                     
	340,  344,  349,  353,                                                                                                                                                     
	358,  362,  366,  371,                                                                                                                                                     
	375,  379,  384,  388,                                                                                                                                                     
	392,  397,  401,  405,                                                                                                                                                     
	409,  414,  418,  422,                                                                                                                                                     
	426,  430,  435,  439,                                                                                                                                                     
	443,  447,  451,  455,                                                                                                                                                     
	459,  464,  468,  472,                                                                                                                                                     
	476,  480,  484,  488,                                                                                                                                                     
	492,  496,  500,  504,                                                                                                                                                     
	508,  512,  516,  520,                                                                                                                                                     
	524,  527,  531,  535,                                                                                                                                                     
	539,  543,  547,  551,                                                                                                                                                     
	555,  558,  562,  566,                                                                                                                                                     
	570,  574,  577,  581,                                                                                                                                                     
	585,  589,  592,  596,                                                                                                                                                     
	600,  604,  607,  611,                                                                                                                                                     
	615,  618,  622,  626,                                                                                                                                                     
	629,  633,  637,  640,                                                                                                                                                     
	644,  647,  651,  655,                                                                                                                                                     
	658,  662,  665,  669,                                                                                                                                                     
	672,  676,  679,  683,                                                                                                                                                     
	687,  690,  693,  697,                                                                                                                                                     
	700,  704,  707,  711,                                                                                                                                                     
	714,  718,  721,  725,                                                                                                                                                     
	728,  731,  735,  738,                                                                                                                                                     
	741,  745,  748,  752,                                                                                                                                                     
	755,  758,  762,  765,                                                                                                                                                     
	768,  771,  775,  778,                                                                                                                                                     
	781,  785,  788,  791,                                                                                                                                                     
	794,  798,  801,  804,                                                                                                                                                     
	807,  811,  814,  817,                                                                                                                                                     
	820,  823,  827,  830,                                                                                                                                                     
	833,  836,  839,  842,                                                                                                                                                     
	845,  849,  852,  855,                                                                                                                                                     
	858,  861,  864,  867,                                                                                                                                                     
	870,  873,  877,  880,                                                                                                                                                     
	883,  886,  889,  892,                                                                                                                                                     
	895,  898,  901,  904,                                                                                                                                                     
	907,  910,  913,  916,                                                                                                                                                     
	919,  922,  925,  928,                                                                                                                                                     
	931,  934,  937,  940,                                                                                                                                                     
	943,  945,  948,  951,                                                                                                                                                     
	954,  957,  960,  963,                                                                                                                                                     
	966,  969,  972,  974,                                                                                                                                                     
	977,  980,  983,  986,                                                                                                                                                     
	989,  992,  994,  997                                                                                                                                                      
};                                                                                                                                                                             

static int MostSignificantBit(int x)                                                                                                                                           
{                                                                                                                                                                              
	int i=0;                                                                                                                                                                   

	if (!x)                                                                                                                                                                    
		return 0;                                                                                                                                                              
	
	while(!(x & 0x80000000))                                                                                                                                                   
	{
		x<<=1;                                                                                                                                                                 
		i++;                                                                                                                                                                   
    }
	return 31-i;                                                                                                                                                               
}

unsigned int STLog2(U32 value)                                                                                                                                                 
{

	unsigned int msb=0;                                                                                                                                                        
	unsigned int logindex=0;                                                                                                                                                   
	unsigned int result=0;                                                                                                                                                     
	unsigned int interpolation=0;                                                                                                                                              
	int inc = 1;                                                                                                                                                            
                                                                                                                                                                               
	msb =  MostSignificantBit(value);                                                                                                                                          
                                                                                                                                                                               
	if ((msb>0)  && ( msb<=PRECISION))                                                                                                                                         
	{                                                                                                                                                                          
		logindex = value <<(PRECISION - msb);                                                                                                                                  
        }
	else if (msb>0)                                                                                                                                                            
	{                                                                                                                                                                          
		logindex = value >>(msb - PRECISION);                                                                                                                                  
        }

	logindex = (logindex & 0x7F)*2;                                                                                                                                            
                                                                                                                                               
	inc = XtoPowerY(2,msb);                                                                                                                                                    
                                                                                                                                                                               
	interpolation =  ( (value*256) -(logindex + (256*inc))	) * logtable[logindex] /2;                                                                                         
	interpolation -= ( (logindex+1)+ 256*inc-(256*value)	) * logtable[logindex+1]/2;                                                                                        
 
	inc = 1000000000;                                                                                                                                                          
 
	result =  (msb*1000 + logtable[logindex]  + (interpolation/inc));                                                                                                          
 
	return   result;                                                                                                                                                           
 
}                                                                                                                                                                              
 
 
unsigned int STLog10(U32 value)                                                                         
{                                                                                                         
	return ((STLog2(value) * STlog10_2)/1000);                                                            
}

