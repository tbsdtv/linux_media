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
 @File   globaldefs.h                                                          
 @brief                                                                         
                                                                               
                                                                               
                                                                               
*/
#ifndef GLOBALDEFS
	#define GLOBALDEFS

	#ifdef HOST_PC
		#include <linux/kernel.h>
		#include <linux/delay.h>
		#include <linux/slab.h>

		#define WAIT_N_MS(X) msleep(X)
		#define calloc(n,s) kvzalloc(n*s,GFP_KERNEL)
		#define free(p) kvfree(p)
	#endif

	#include "gen_macros.h"
	#include "gen_types.h"
	#include "gen_csts.h"
	#include "gen_spcar.h"
	#include "stddefs.h"
	#include "stfe_utilities.h"
	
#endif
/* End of globaldefs.h */
	
	
