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

#include "i2c.h"
#include "chip.h"

/* ------------------------------------------------------------------------- */ 	

typedef enum
{
	PMAP_IDLE,
	PMAP_PERIPHERAL,
	PMAP_REGISTER,
	PMAP_END
}PMAP_STATE;


typedef struct node 
{
	STCHIP_Handle_t hChip;
	struct node *pNextNode;
}NODE;

/* ------------------------------------------------------------------------- */ 

static NODE *pFirstNode = NULL;
static BOOL Hierarchy_Flag = FALSE; // 4 compatibility to flat regmaps
static u8 ChipMapRegisterSize = STCHIP_REGSIZE_8;   // regsize defaults for a map

/* List routines	*/
//static u32 revInt (u32 s);

/* ------------------------------------------------------------------------- */ 

/* big endianess converter */
/*static u32 revInt (u32 s) 
{  	
	u32 i; char *p = (char *)&i; char *c = (char *)&s;
		p[0] = c[3]; p[1] = c[2]; p[2] = c[1]; p[3] = c[0]; 
	return i;
}*/

static NODE *AppendNode(STCHIP_Handle_t hChip)
{
	NODE *pNode = pFirstNode;
	
	if(pNode == NULL)
	{   /* Allocation of the first node	*/
		pNode = calloc(1,sizeof(NODE));
		pFirstNode = pNode;
	}
	else
	{   /* Allocation of a new node */
		while(pNode->pNextNode != NULL)	/* Search of the last node	*/
			pNode = pNode->pNextNode;
			
		pNode->pNextNode = calloc(1,sizeof(NODE));	/* Memory allocation */
		
		if(pNode->pNextNode != NULL)				/* Check allocation */
			pNode = pNode->pNextNode;
		else
			pNode = NULL;
	}
	
	if(pNode != NULL)	/* if allocation ok	*/
	{
		/*	Fill the node	*/
		pNode->hChip = hChip;
		pNode->pNextNode = NULL;	
	}
	
	return pNode;
}

static void DeleteNode(NODE *pNode)
{
	NODE *pPrevNode = pFirstNode;
	
	if(pNode != NULL)
	{
		if(pNode == pFirstNode) 
		{
			/* Delete the first node	*/
			pFirstNode = pNode->pNextNode;
		}
		else
		{
			/* Delete a non-first node	*/
			while(pPrevNode->pNextNode != pNode)	            /* search the node before the node to delete */
				pPrevNode = pPrevNode->pNextNode;
				
			if(pNode->pNextNode == NULL)
				pPrevNode->pNextNode = NULL;		                    /*   the node to delete is the last   */
			else	
				pPrevNode->pNextNode = pPrevNode->pNextNode->pNextNode;	/* the node to delete is not the last */
		}
		
		free(pNode);	/* memory deallocation */
	}
}


/*****************************************************
**FUNCTION	::	ChipGetFirst
**ACTION	::	Retrieve the first chip handle
**PARAMS IN	::	NONE
**PARAMS OUT::	NONE
**RETURN	::	STCHIP_Handle_t if ok, NULL otherwise
*****************************************************/
STCHIP_Handle_t	ChipGetFirst(void)
{
	if((pFirstNode != NULL) && (pFirstNode->hChip != NULL))
		return pFirstNode->hChip;	
	else
		return NULL;
}

/*****************************************************
**FUNCTION	::	ChipFindNode
**ACTION	::	Find that node that contains the chip 
**PARAMS IN	::	NONE
**PARAMS OUT::	NONE
**RETURN	::	STCHIP_Handle_t if ok, NULL otherwise
*****************************************************/
NODE *ChipFindNode(STCHIP_Handle_t hChip)
{
	NODE *pNode = pFirstNode;
	
	if(pNode != NULL)
	{
		while((pNode->hChip != hChip) && (pNode->pNextNode != NULL))
			pNode = pNode->pNextNode;
		
		if(pNode->hChip != hChip)
			pNode = NULL;	
		
	}
	
	return pNode;
}

/*****************************************************
**FUNCTION	::	ChipGetNext
**ACTION	::	Retrieve the handle of the next chip
**PARAMS IN	::	hPrevChip	==> handle of the previous chip
**PARAMS OUT::	NONE
**RETURN	::	STCHIP_Handle_t if ok, NULL otherwise
*****************************************************/
STCHIP_Handle_t	ChipGetNext(STCHIP_Handle_t hPrevChip)
{
	NODE *pNode;
	
	pNode = ChipFindNode(hPrevChip);
	if((pNode != NULL) && (pNode->pNextNode != NULL))
		return pNode->pNextNode->hChip;
	else
		return NULL; 
}

/*****************************************************
**FUNCTION	::	ChipGetHandleFromName
**ACTION	::	Retrieve the handle of chip with its name
**PARAMS IN	::	Name	==> name of the chip
**PARAMS OUT::	NONE
**RETURN	::	STCHIP_Handle_t if ok, NULL otherwise
*****************************************************/
STCHIP_Handle_t ChipGetHandleFromName(char *Name)
{
	STCHIP_Handle_t hChip;
	
	hChip = ChipGetFirst();
	while((hChip != NULL) && (strcmp(hChip->Name,Name) != 0))
	{
		hChip = ChipGetNext(hChip);
	}
	
	return hChip;
}

/*****************************************************
**FUNCTION	::	ChipOpen
**ACTION	::	Open a new chip
**PARAMS IN	::	Name	==> Name of the chip
**			I2cAddr	==> I2C address of the chip
**			NbRegs	==> number of register in the chip
**			NbFields==> number of field in the chip
**PARAMS OUT	::	NONE
**RETURN	::	Handle to the chip, NULL if an error occur
*****************************************************/
STCHIP_Handle_t ChipOpen(STCHIP_Info_t *hChipOpenParams)
{
	STCHIP_Handle_t hChip;
	s32 reg/*, field*/;
	u32 field;
	
	hChip = calloc(1,sizeof(STCHIP_Info_t));					/* Allocation of the chip structure	*/
	
	if((hChip != NULL) && (hChipOpenParams != NULL))
	{   
		if (Hierarchy_Flag)   
			hChip->pInstMap = calloc(hChipOpenParams->NbInsts,sizeof(STCHIP_Instance_t));	/* Allocation of the instances map	*/
		else
	{
			hChipOpenParams->NbInsts = 0;
			hChip->pInstMap = NULL;
		}

		hChip->pRegMapImage  = calloc((u32)hChipOpenParams->NbRegs, sizeof(STCHIP_Register_t));		/* Allocation of the register map	*/
		
		if(hChip->pRegMapImage != NULL)
		{
			//hChip->pFieldMap = calloc(hChipOpenParams->NbFields,sizeof(STCHIP_Field_t));	/* Allocation of the field map	    */
			hChip->pFieldMapImage = calloc(hChipOpenParams->NbFields,sizeof(STCHIP_Field_t));	/* Allocation of the field map	    */
			
			if(hChip->pFieldMapImage != NULL)
			{
				if(AppendNode(hChip)!=NULL) 
				{
					hChip->pI2CHost = hChipOpenParams->pI2CHost;
					hChip->I2cAddr = hChipOpenParams->I2cAddr;
					strcpy(hChip->Name,hChipOpenParams->Name);
					hChip->NbInsts      = hChipOpenParams->NbInsts;
					hChip->NbRegs       = hChipOpenParams->NbRegs;
					hChip->NbFields     = hChipOpenParams->NbFields;
					hChip->ChipMode     = hChipOpenParams->ChipMode;
					hChip->Repeater     = hChipOpenParams->Repeater;
					hChip->RepeaterHost = hChipOpenParams->RepeaterHost;
					hChip->RepeaterFn   = hChipOpenParams->RepeaterFn;
					hChip->WrStart      = hChipOpenParams->WrStart;
				    hChip->WrSize       = hChipOpenParams->WrSize;     
				    hChip->RdStart      = hChipOpenParams->RdStart;     
				    hChip->RdSize       = hChipOpenParams->RdSize;     
					hChip->Error = CHIPERR_NO_ERROR;
					hChip->pData = hChipOpenParams->pData;
					hChip->LastRegIndex = 0;
					hChip->Abort = FALSE;   
					
					for(reg=0;reg<hChip->NbRegs;reg++)
					{
						hChip->pRegMapImage[reg].Addr=0;
						hChip->pRegMapImage[reg].Value=0;
						//hChip->pRegMapImage[reg].Base=0;
					}
					
					for(field=0;field<hChip->NbFields;field++)
					{
						hChip->pFieldMapImage[field].Reg=0;
						hChip->pFieldMapImage[field].Pos=0;
						hChip->pFieldMapImage[field].Bits=0;
						hChip->pFieldMapImage[field].Mask=0;
					}
				}
				else
				{
					//free(hChip->pFieldMap);
					//free(hChip->pRegMap);
					free(hChip->pInstMap);   
					free(hChip);
					hChip = NULL;	
				}
			}
			else
			{
				//free(hChip->pRegMap);
				free(hChip);
				hChip = NULL;
			}
		}
		else
		{
			free(hChip);
			hChip = NULL;	
		}
	}
	
	return hChip;
}

/*****************************************************
**FUNCTION	::	ChipClose
**ACTION	::	Close a chip
**PARAMS IN	::	hChip	==> handle to the chip
**PARAMS OUT::	NONE
**RETURN	::	CHIPERR_NO_ERROR if ok, CHIPERR_INVALID_HANDLE otherwise
*****************************************************/
STCHIP_Error_t	ChipClose(STCHIP_Handle_t hChip)
{
	STCHIP_Error_t error = CHIPERR_NO_ERROR;
	NODE *node = NULL;
	
	if(hChip != NULL)
	{
		node = ChipFindNode(hChip);
		DeleteNode(node);
		free(hChip->pRegMapImage);
		free(hChip->pFieldMapImage);
		free(hChip);
	}
	else
		error = CHIPERR_INVALID_HANDLE;
	
	return error; 
}

/*****************************************************
**FUNCTION	::	CreateMask
**ACTION	::	Create a mask according to its number of bits and position 
**PARAMS IN	::	field	==> Id of the field
**PARAMS OUT::	NONE
**RETURN	::	mask of the field
*****************************************************/
u32 CreateMask(char NbBits, char Pos)
{
	s32 i;
	u32 mask=0;
	
	
	/*	Create mask	*/
	for (i = 0; i < NbBits; i++)
	{
		mask <<= 1 ;
		mask +=  1 ;
	}
	  
	mask = mask << Pos;
	
	return mask;
}

/*****************************************************
**FUNCTION	::	ChipAddField
**ACTION	::	Add a field to the field map 
**PARAMS IN	::	hChip	==> Handle to the chip
**				RegId	==> Id of the register which contains the field
**				FieldId	==> Id of the field
**				Name	==> Name of the field
**				Pos		==> Position (number of left shifts from LSB position) in the register 
**				NbBits	==> Size (in bits) of the field
**				Type	==> SIGNED or UNSIGNED
**PARAMS OUT::	NONE
**RETURN	::	Error
*****************************************************/
STCHIP_Error_t ChipAddField(STCHIP_Handle_t hChip,u16 RegId, u32 FieldId,char * Name, char Pos, char NbBits, STCHIP_FieldType_t Type)
{
	STCHIP_Field_t *pField; 
	
	if(hChip != NULL)
	{
		if(RegId < hChip->NbRegs)
		{
			if(FieldId < hChip->NbFields)
			{
				//pField=&hChip->pFieldMap[FieldId];
				pField=&hChip->pFieldMapImage[FieldId];
	
				strcpy(pField->Name,Name);	
				pField->Reg = RegId;
				pField->Pos = (u8)Pos;
				pField->Bits = (u8)NbBits;
				pField->Type = Type;
				if(NbBits)
					pField->Mask = CreateMask(NbBits,Pos);
				else
					hChip->Error = CHIPERR_INVALID_FIELD_SIZE;
			}
			else
				hChip->Error = CHIPERR_INVALID_FIELD_ID;
		}
		else
			hChip->Error = CHIPERR_INVALID_REG_ID;
	}
	else 
		return CHIPERR_INVALID_HANDLE;
	
	return hChip->Error;
}

/* Dichotomy-based search function  */
int dichotomy_search(STCHIP_Register_t tab[], s32 nbVal, u16 val)
{
	/* Declaration of local variables */
	BOOL found; // equals false while "val" is not yet found
	u32 start_index;  // start index
	u32 end_index;  // end index
	u32 middle_index;  // middle index
	
	/* Initialisation of these variables before search loop */
	found = FALSE;  // value is not yet found
	start_index = 0;  // search range between 0 and ...
	end_index = (u32)nbVal;  //... nbVal
	
	/* search loop */
	while(!found && ((end_index - start_index) > 1)) {
	
		middle_index = (start_index + end_index)/2;  // we set middle index
		found = (tab[middle_index].Addr == val);  // we check if searched value is located at this index
		
		if(tab[middle_index].Addr > val) end_index = middle_index;  // if value which located at im index is greater to searched value, end index becomes "ifin" middle index, therefore search range is narrower for the next loop
			else start_index = middle_index;  // otherwise start index becomes middle index and search range is also narrower
	}
	
	/* test conditionnant la valeur que la fonction va renvoyer */
	if(tab[start_index].Addr == val) return((s32)start_index);  // if we have found the good value, we return index
	else return(-1);  // other wise we return -1
}

/*****************************************************
**FUNCTION	::	ChipGetRegisterIndex
**ACTION	::	Get the index of a register from the pRegMapImage table
**PARAMS IN	::	hChip		==> Handle to the chip
**				RegId		==> Id of the register (adress)
**PARAMS OUT::	None 
**RETURN	::	Index of the register in the register map image
*****************************************************/
s32 ChipGetRegisterIndex(STCHIP_Handle_t hChip, u16 RegId)
{
	s32 regIndex=-1;
 
	if(hChip)
	{
		if(hChip->Abort==FALSE)
		{
			if(hChip->pRegMapImage[hChip->LastRegIndex].Addr ==RegId)
				regIndex = hChip->LastRegIndex;
			else
			{
				/* We assume that reg addresses in STiD135DefVal and STiD135SocDefVal are sorted in the growing order */
				regIndex = dichotomy_search(hChip->pRegMapImage, hChip->NbRegs, RegId);
				hChip->LastRegIndex = regIndex;
			}
		}
		else
		  regIndex=0;
	}
	return regIndex;
}

/*****************************************************
**FUNCTION	::	ChipGetFieldIndex
**ACTION	::	Get the index of a register from the pRegMapImage table
**PARAMS IN	::	hChip		==> Handle to the chip
**				RegId		==> Id of the fileld (address)
**PARAMS OUT::	None
**RETURN	::	Index of the register in the register map image
*****************************************************/
s32 ChipGetFieldIndex(STCHIP_Handle_t hChip, u32 FieldId)
{
	s32 regIndex=-1;
	u16 regAddress;
	
	if(hChip)
	{
		if(hChip->Abort==FALSE) 
		{
			regAddress=(u16)((FieldId >> 16)&0xFFFF);
			if(hChip->pRegMapImage[hChip->LastRegIndex].Addr ==regAddress)
				regIndex = hChip->LastRegIndex;
			else
			{
				/* We assume that reg addresses in STiD135DefVal and STiD135SocDefVal are sorted in the growing order */
				regIndex = dichotomy_search(hChip->pRegMapImage, hChip->NbRegs, regAddress);
				hChip->LastRegIndex = regIndex;
			}
		}
		else
			regIndex=0;
	}
	
	return regIndex;
}

/*****************************************************
**FUNCTION	::	ChipSetOneRegister
**ACTION	::	Set the value of one register 
**PARAMS IN	::	hChip	==> Handle to the chip
**				reg_id	==> Id of the register
**				Data	==> Data to store in the register
**PARAMS OUT::	NONE
**RETURN	::	Error
*****************************************************/
STCHIP_Error_t ChipSetOneRegister(STCHIP_Handle_t hChip,u16 RegAddr,u32 Data)   
{
	s32 regIndex;

	hChip->Error = CHIPERR_NO_ERROR;
	if(hChip) {
		if(hChip->Abort==FALSE) {
			regIndex =ChipGetRegisterIndex(hChip, RegAddr);
			if((regIndex >= 0) && (regIndex  < hChip->NbRegs)) {
				hChip->pRegMapImage[regIndex].Value=Data;
				ChipSetRegisters(hChip,RegAddr,1);
			} else
				hChip->Error = CHIPERR_INVALID_REG_ID;
		}
	} else
		return CHIPERR_INVALID_HANDLE;
	
	return hChip->Error;
}

/*****************************************************
**FUNCTION	::	ChipGetOneRegister
**ACTION	::	Get the value of one register 
**PARAMS IN	::	hChip	==> Handle to the chip
**			reg_id	==> Id of the register
**PARAMS OUT	::	Register's value
**RETURN	:: fe_lla_error_t	
*****************************************************/
STCHIP_Error_t ChipGetOneRegister(STCHIP_Handle_t hChip, u16 RegAddr, u32* data_p )
{
	s32 regIndex; 
	
	*data_p = 0xFFFFFFFF;
	hChip->Error = CHIPERR_NO_ERROR;
	if(hChip)
	{
		if(hChip->Abort==FALSE)
		{
			regIndex =ChipGetRegisterIndex(hChip, RegAddr);
		
			if((regIndex >= 0) && (regIndex  < hChip->NbRegs))
			{
				if(hChip->ChipMode != STCHIP_MODE_NOSUBADR)
				{
					if(ChipGetRegisters(hChip,RegAddr,1) == CHIPERR_NO_ERROR)
						*data_p = (u32)hChip->pRegMapImage[regIndex].Value;
				}
				else
				{
					if(ChipGetRegisters(hChip,hChip->RdStart,(s32)hChip->RdSize) == CHIPERR_NO_ERROR)  
						*data_p = (u32)hChip->pRegMapImage[regIndex].Value;
				}
			}
			else
				hChip->Error = CHIPERR_INVALID_REG_ID;
		}
	}
	else
		hChip->Error = CHIPERR_INVALID_HANDLE;
		
	return hChip->Error;
}


/*****************************************************
**FUNCTION	::	ChipSetRegisters
**ACTION	::	Set values of consecutive's registers (values are taken in RegMap)
**PARAMS IN	::	hChip		==> Handle to the chip
**				FirstReg	==> Id of the first register
**				NbRegs		==> Number of register to write		
**PARAMS OUT::	NONE
**RETURN	::	Error
*****************************************************/
STCHIP_Error_t  ChipSetRegisters(STCHIP_Handle_t hChip, u16 FirstReg, s32 NbRegs)
{
	u8 data[100],nbdata = 0;
	s32 i, j, firstRegIndex;
	//s32 j;

	if(hChip)
	{
		if(!hChip->Error)
		{
			firstRegIndex =ChipGetRegisterIndex(hChip, FirstReg);
			if((firstRegIndex >= 0) && ((firstRegIndex + NbRegs - 1) < hChip->NbRegs)) 
			{
				switch(hChip->ChipMode)
				{
					case STCHIP_MODE_I2C2STBUS:        /* fixed 2 addr + 1 data transaction mode 4 I2C to STBus bridge */
						// 16 Bit special register bug workaround RnDHV00063986 & RnDHV00062932 & BZ#69936
						if (NbRegs > 1)
							data[nbdata]  = (U8)(hChip->WrStart + STBUS_STREAM_INCR_1);    
						else data[nbdata]  = (U8)(hChip->WrStart);
						nbdata = (u8)(nbdata + 1);
					    
						//data[nbdata++]=MSB(hChip->pRegMapImage[FirstReg].Addr);	            /*   Hi sub address        */
						//data[nbdata++]=LSB(hChip->pRegMapImage[FirstReg].Addr);	            /*   Lo sub address        */
						data[nbdata++]=(u8)(MSB(hChip->pRegMapImage[firstRegIndex].Addr));	            /*   Hi sub address        */
						data[nbdata++]=(u8)(LSB(hChip->pRegMapImage[firstRegIndex].Addr));	            /*   Lo sub address        */    
						
						for(i=0;i<NbRegs;i++)								            /* register's loop */
							/* FIXME: new for 32-bit access */
							for(j=(s32)(hChip->pRegMapImage[firstRegIndex+i].Size - 1); j>=0;j--)	    /* byte's loop     */
								data[nbdata++]=0xff&(hChip->pRegMapImage[firstRegIndex+i].Value>>(8*j));	/*   fill data buffer (MSB first) */
						
					break;

					case STCHIP_MODE_SUBADR_16:
						data[nbdata++]=(u8)(MSB(hChip->pRegMapImage[firstRegIndex].Addr));	/* 16 bits sub addresses */
					case STCHIP_MODE_SUBADR_8:
					case STCHIP_MODE_NOSUBADR_RD:
						data[nbdata++]=(u8)(LSB(hChip->pRegMapImage[firstRegIndex].Addr));	/* 8 bits sub addresses */
					case STCHIP_MODE_NOSUBADR:
						for(i=0;i<NbRegs;i++)
							/* FIXME: new for 32-bit access */
							for(j=0;j<(s32)(hChip->pRegMapImage[firstRegIndex+i].Size);j++)	/* byte's loop */
								data[nbdata++]=0xff&(hChip->pRegMapImage[firstRegIndex+i].Value>>(8*j));	/*   fill data buffer (LSB first) */
					break;
				}	
				#ifndef NO_I2C
					if(hChip->Repeater && hChip->RepeaterHost && hChip->RepeaterFn)
						hChip->RepeaterFn(hChip->RepeaterHost,TRUE);	/* Set repeater ON */
						
					if(I2cReadWrite(hChip->pI2CHost,I2C_WRITE,hChip->I2cAddr,data,nbdata) != I2C_ERR_NONE)	/* write data buffer */
						hChip->Error = CHIPERR_I2C_NO_ACK;

					if(hChip->Repeater && hChip->RepeaterHost && hChip->RepeaterFn)
						hChip->RepeaterFn(hChip->RepeaterHost,FALSE);	/* Set repeater OFF */
				
				#endif
			}
			else
				hChip->Error = CHIPERR_INVALID_REG_ID;
		}
		else
			return hChip->Error;
		
	}
	else
		return CHIPERR_INVALID_HANDLE;
	
	return hChip->Error;
                       
}

/*****************************************************
**FUNCTION	::	ChipGetRegisters
**ACTION	::	Get values of consecutive's registers (values are writen in RegMap)
**PARAMS IN	::	hChip		==> Handle to the chip
**				FirstReg	==> Id of the first register
**				NbRegs		==> Number of register to read		
**PARAMS OUT::	NONE
**RETURN	::	Error
*****************************************************/
STCHIP_Error_t ChipGetRegisters(STCHIP_Handle_t hChip, u16 FirstReg, s32 NbRegs)
{
	u8 data[100] = {0},nbdata =0;
	s32 i, j, firstRegIndex;
	u8 keep_lsb=0;
	u8 lsb=0;

	if(hChip)
	{
		if(!hChip->Error)
		{
			if(hChip->Abort==FALSE)
		{
			if(NbRegs < 70)
			{
				firstRegIndex =ChipGetRegisterIndex(hChip, FirstReg);
				if((firstRegIndex >= 0) && ((firstRegIndex + NbRegs - 1) < hChip->NbRegs))
				{
					#ifndef NO_I2C
						switch(hChip->ChipMode)
						{
							case STCHIP_MODE_I2C2STBUS:	/* fixed 2 addr + 1 data transaction - 
                                                        mode for I2C to STBus bridge */
								// 16 Bit special register bug workaround RnDHV00063986 & RnDHV00062932 & BZ#69936
								if (NbRegs > 1)
									data[nbdata]  = (U8)(hChip->WrStart + STBUS_READ + STBUS_STREAM_INCR_1);
								else data[nbdata] = (U8)(hChip->WrStart + STBUS_READ);
				                                nbdata = (u8)(nbdata + 1);
							
							case STCHIP_MODE_SUBADR_16:
								data[nbdata++]=(u8)(MSB(hChip->pRegMapImage[firstRegIndex].Addr));	/* for 16 bits sub addresses */
							case STCHIP_MODE_SUBADR_8:
								data[nbdata++]=(u8)(LSB(hChip->pRegMapImage[firstRegIndex].Addr));	/* for 8 bits sub addresses	*/
								
								if(hChip->Repeater && hChip->RepeaterHost && hChip->RepeaterFn)
									hChip->RepeaterFn(hChip->RepeaterHost,TRUE);				/* Set repeater ON */
							
								if(I2cReadWrite(hChip->pI2CHost,I2C_WRITE,hChip->I2cAddr,data,nbdata) != I2C_ERR_NONE)	/* Write sub address */
									hChip->Error = CHIPERR_I2C_NO_ACK;
												
									
								if(hChip->Repeater && hChip->RepeaterHost && hChip->RepeaterFn)
									hChip->RepeaterFn(hChip->RepeaterHost,FALSE);	/* Set repeater OFF */
							
							case STCHIP_MODE_NOSUBADR:
							case STCHIP_MODE_NOSUBADR_RD:
									/* FIXME: new for 32-bit access */
									nbdata=0;
									for(i=0;i<NbRegs;i++)						/* register's loop 	*/
										nbdata=(u8)(nbdata+(hChip->pRegMapImage[firstRegIndex+i].Size));		/* sum register's size 	*/
									
									if(hChip->Repeater && hChip->RepeaterHost && hChip->RepeaterFn)
										hChip->RepeaterFn(hChip->RepeaterHost,TRUE);	/* Set repeater ON */
							
									if(I2cReadWrite(hChip->pI2CHost,I2C_READ,hChip->I2cAddr,data,nbdata) != I2C_ERR_NONE)	/* Read data buffer */ 
											hChip->Error = CHIPERR_I2C_NO_ACK;
								
									if(hChip->Repeater && hChip->RepeaterHost && hChip->RepeaterFn)
										hChip->RepeaterFn(hChip->RepeaterHost,FALSE);	/* Set repeater OFF */
									
									/* FIXME: new for 32-bit access */		
									// TAB data consistency
									if (keep_lsb)
										data[0] = lsb;
							break;
						}
					
						/*	Update RegMap structure	*/
						/*for(i=0;i<NbRegs;i++)
							if(!hChip->Error)
								hChip->pRegMapImage[firstRegIndex+i].Value = data[i];
							else
								hChip->pRegMapImage[firstRegIndex+i].Value = 0xFF; */
						/* FIXME: new for 32-bit access */
						if(hChip->Error)
							memset (data, 0xFF, nbdata);
						if ((hChip->pRegMapImage[firstRegIndex].Size) == 0) hChip->pRegMapImage[firstRegIndex].Size = 1;  /* also throw a message here */
						for(i=0;i<NbRegs; i++)	        /* FIXME: trial, do not forget it ! register's loop */
						{
							hChip->pRegMapImage[firstRegIndex+i].Value=0x00000000;				/* reset register's value */
						
							for(j=0;j<(s32)(hChip->pRegMapImage[firstRegIndex+i].Size);j++)				/* byte's loop */
								if (hChip->ChipMode == STCHIP_MODE_I2C2STBUS)                   /* gb hware can also be little endian */
									 hChip->pRegMapImage[firstRegIndex+i].Value = (hChip->pRegMapImage[firstRegIndex+i].Value << 8) + (data[i+j]); /* fill register value, big endian, new */
								else hChip->pRegMapImage[firstRegIndex+i].Value = hChip->pRegMapImage[firstRegIndex+i].Value + (u32)(data[i+j]<<(8*j)); /* fill register value, little endian, classic */
						}
					#endif
				}
				else
					hChip->Error = CHIPERR_INVALID_REG_ID;
				  
			}
			else 
				hChip->Error = CHIPERR_I2C_BURST;
			}
		}
	}
	else
		return CHIPERR_INVALID_HANDLE;
	
	return hChip->Error;
}

/*****************************************************
**FUNCTION	::	ChipUpdateDefaultValues
**ACTION	::	update the default values of the RegMap chip
**PARAMS IN	::	hChip	==> handle to the chip
			::	pRegMap	==> pointer to 
**PARAMS OUT::	NONE
**RETURN	::	CHIPERR_NO_ERROR if ok, CHIPERR_INVALID_HANDLE otherwise
*****************************************************/
STCHIP_Error_t  ChipUpdateDefaultValues(STCHIP_Handle_t hChip,STCHIP_Register_t  *pRegMap)
{
	STCHIP_Error_t error = CHIPERR_NO_ERROR;
	s32 reg;
	
	if(hChip != NULL)
	{
		for(reg=0;reg<hChip->NbRegs;reg++)
		{
			hChip->pRegMapImage[reg].Addr=pRegMap[reg].Addr;
			hChip->pRegMapImage[reg].Value=pRegMap[reg].Value;
		}
	}
	else
		error = CHIPERR_INVALID_HANDLE;
	
	return error;
}

/*****************************************************
**FUNCTION	::	ChipApplyDefaultValues
**ACTION	::	Write default values in all the registers
**PARAMS IN	::	hChip	==> Handle of the chip	
**PARAMS OUT::	NONE
**RETURN	::	Error
*****************************************************/
STCHIP_Error_t ChipApplyDefaultValues(STCHIP_Handle_t hChip, u16 RegAddr, u8 RegsVal)
{
	if(hChip != NULL) 
	{
		if(hChip->ChipMode != STCHIP_MODE_NOSUBADR)   
		{
			if((!hChip->Error))
			{
				ChipSetOneRegister(hChip,RegAddr,RegsVal);     
			}
		}
		 
	}
	else
		return CHIPERR_INVALID_HANDLE;
		
	return hChip->Error;
}


/*****************************************************
**FUNCTION	::	ChipGetError
**ACTION	::	Return the current error of the chip
**PARAMS IN	::	hChip	==> Handle of the chip
**PARAMS OUT::	NONE
**RETURN	::	Current error, CHIPERR_INVALID_HANDLE otherwise
*****************************************************/
STCHIP_Error_t ChipGetError(STCHIP_Handle_t hChip)
{
	if(hChip != NULL)     
		return hChip->Error;
	else
		return CHIPERR_INVALID_HANDLE;
}

/*****************************************************
**FUNCTION	::	ChipResetError
**ACTION	::	Reset the error of the chip
**PARAMS IN	::	hChip	==> Handle of the chip
**PARAMS OUT::	NONE
**RETURN	::	Error
*****************************************************/
STCHIP_Error_t ChipResetError(STCHIP_Handle_t hChip)    
{
	if(hChip != NULL) 
		hChip->Error = CHIPERR_NO_ERROR;
	else
		return CHIPERR_INVALID_HANDLE;
		
	return hChip->Error;
}

/*****************************************************
**FUNCTION	::	ChipGetFieldMask
**ACTION	::	get the mask of a field in the chip
**PARAMS IN	::	
**PARAMS OUT::	mask
**RETURN	::	mask
*****************************************************/
s32 ChipGetFieldMask(u32 FieldId)
{
	s32 mask;
	mask = FieldId & 0xFF; /*FieldId is [reg address][reg address][sign][mask] --- 4 bytes */ 
	
	return mask;
}

/*****************************************************
**FUNCTION	::	ChipGetFieldSign
**ACTION	::	get the sign of a field in the chip
**PARAMS IN	::	
**PARAMS OUT::	sign
**RETURN	::	sign
*****************************************************/
s32 ChipGetFieldSign(u32 FieldId)
{
	s32 sign;
	sign = (FieldId>>8) & 0x01; /*FieldId is [reg address][reg address][sign][mask] --- 4 bytes */ 
	
	return sign;
}

/*****************************************************
**FUNCTION	::	ChipGetFieldPosition
**ACTION	::	get the position of a field in the chip
**PARAMS IN	::	
**PARAMS OUT::	position
**RETURN	::	position
*****************************************************/
s32 ChipGetFieldPosition(u8 Mask)
{
	s32 position=0, i=0;

	while((position == 0)&&(i < 8))
	{
		position = (Mask >> i) & 0x01;
		i++;
	}
  
	return (i-1);
}

/*****************************************************
**FUNCTION	::	ChipGetFieldBits
**ACTION	::	get the number of bits of a field in the chip
**PARAMS IN	::	
**PARAMS OUT::	number of bits
**RETURN	::	number of bits
*****************************************************/
s32 ChipGetFieldBits(s32 mask, s32 Position)
{
 s32 bits,bit;
 s32 i =0;
 
 bits = mask >> Position;
 bit = bits ;
 while ((bit > 0)&&(i<8))
 {
 	i++;
 	bit = bits >> i;
 	
 }
 return i;
}

/*****************************************************
**FUNCTION	::	ChipSetFieldImage
**ACTION	::	Set value of a field in RegMap
**PARAMS IN	::	hChip	==> Handle to the chip
**				FieldId	==> Id of the field
**				Value	==> Value of the field
**PARAMS OUT::	NONE
**RETURN	::	Error
*****************************************************/
STCHIP_Error_t ChipSetFieldImage(STCHIP_Handle_t hChip,u32 FieldId, s32 Value)
{
	s32 regIndex,
		mask,
		sign,
		bits,
		pos;
	
	if(hChip != NULL)
	{
		if(!hChip->Error)
		{
			if(hChip->Abort==FALSE)
		{
			regIndex=ChipGetFieldIndex(hChip,FieldId);						/*	Just for code simplification	*/
			
			if((regIndex >= 0) && (regIndex  < hChip->NbRegs))
			{

				sign = ChipGetFieldSign(FieldId);
				mask = ChipGetFieldMask(FieldId);
				pos = ChipGetFieldPosition((u8)mask);
				bits = ChipGetFieldBits(mask,pos);
			
				if(sign == CHIP_SIGNED)
					Value = (Value > 0 ) ? Value : Value + (1<<bits);	/*	compute signed fieldval	*/

				Value = mask & (Value << pos);	/*	Shift and mask value	*/
				hChip->pRegMapImage[regIndex].Value = (u32)((hChip->pRegMapImage[regIndex].Value & (u32)(~mask)) + (u32)Value);	/*	Concat register value and fieldval	*/
			}
			else
				hChip->Error = CHIPERR_INVALID_FIELD_ID;
		}
	}
	}
	else
		return CHIPERR_INVALID_HANDLE;
	
	return hChip->Error;
}

/*****************************************************
**FUNCTION	::	ChipSetField
**ACTION	::	Set value of a field in the chip
 			(8-bit registers only)
			Do not use it to access fields of
 			32-bit registers (see BZ#76053)
**PARAMS IN	::	hChip	==> Handle to the chip
**				FieldId	==> Id of the field
**				Value	==> Value to write
**PARAMS OUT::	NONE
**RETURN	::	Error
*****************************************************/
STCHIP_Error_t ChipSetField(STCHIP_Handle_t hChip,u32 FieldId,s32 Value)
{
	s32 regValue,
		mask,
		sign,
		bits,
		pos;
	
	if(hChip)
	{
		if(!hChip->Error)
		{

			if(hChip->Abort==FALSE)
			{
			hChip->Error=ChipGetOneRegister(hChip,(u16)((FieldId >> 16)&0xFFFF), (u32*) &regValue);		/*	Read the register	*/
			sign = ChipGetFieldSign(FieldId);
			mask = ChipGetFieldMask(FieldId);
			pos = ChipGetFieldPosition((u8)mask);
			bits = ChipGetFieldBits(mask,pos);
			
			if(sign == CHIP_SIGNED)
				Value = (Value > 0 ) ? Value : Value + (bits);	/*	compute signed fieldval	*/

			Value = mask & (Value << pos);						/*	Shift and mask value	*/

			regValue=(regValue & (~mask)) + Value;		/*	Concat register value and fieldval	*/
			hChip->Error |= ChipSetOneRegister(hChip,(u16)((FieldId >> 16)&0xFFFF),(u8)regValue);		/*	Write the register */
			}

		}
		else
			hChip->Error = CHIPERR_INVALID_FIELD_ID;
	}
	else
		return CHIPERR_INVALID_HANDLE;
		
	return hChip->Error;
}

/*****************************************************
**FUNCTION	::	ChipGetFieldImage
**ACTION	::	get the value of a field from RegMap
**PARAMS IN	::	hChip	==>	Handle of the chip
**				FieldId	==> Id of the field
**PARAMS OUT::	NONE
**RETURN	::	field's value
*****************************************************/
s32 ChipGetFieldImage(STCHIP_Handle_t hChip,u32 FieldId)
{
	s32 value = 0xFF;
	s32 regIndex,
		mask,
		sign,
		bits,
		pos;
		
	if(hChip)
	{
		if(hChip->Abort==FALSE) 
		{
		regIndex=ChipGetFieldIndex(hChip,FieldId);						/*	Just for code simplification	*/
			
		if((regIndex >= 0) && (regIndex  < hChip->NbRegs))
		{
			sign = ChipGetFieldSign(FieldId);
			mask = ChipGetFieldMask(FieldId);
			pos = ChipGetFieldPosition((u8)mask);
			bits = ChipGetFieldBits(mask,pos);					

			if(!hChip->Error)
				value = (s32)hChip->pRegMapImage[regIndex].Value;

			value=(value & mask) >> pos;	/*	Extract field	*/

			if((sign == CHIP_SIGNED)&&(value & (1<<(bits-1))))
				value = value - (1<<bits);			/*	Compute signed value	*/
		}
		else
			hChip->Error = CHIPERR_INVALID_FIELD_ID;
		}
	}
	
	return value;
}

#ifdef HOST_PC
/*****************************************************
**FUNCTION	::	ChipGetField
**ACTION	::	get the value of a field from the chip
 			(8-bit registers only)
			Do not use it to access fields of 32-bit
			registers (see BZ#76053)
**PARAMS IN	::	hChip	==>	Handle of the chip
**				FieldId	==> Id of the field
**PARAMS OUT	::	NONE
**RETURN	::	error
*****************************************************/
STCHIP_Error_t ChipGetField(STCHIP_Handle_t hChip,u32 FieldId, s32* value_p )
{
	
	s32 sign, mask, pos, bits;
	STCHIP_Error_t error = CHIPERR_NO_ERROR; 
	
	*value_p = 0xFF;
	
	if(hChip != NULL)
	{
		if(!hChip->Error)
		{
			if(hChip->Abort==FALSE)
		{
			/* I2C Read : register address set-up */
			sign = ChipGetFieldSign(FieldId);
			mask = ChipGetFieldMask(FieldId);
			pos = ChipGetFieldPosition((u8)mask);
			bits = ChipGetFieldBits(mask,pos);					
			
			error=ChipGetOneRegister(hChip,(u16)(FieldId >> 16), (u32*)value_p);		/*	Read the register	*/     
			*value_p=(*value_p & mask) >> pos;	/*	Extract field	*/

			if((sign == CHIP_SIGNED)&&(*value_p & (1<<(bits-1))))
				*value_p = *value_p - (1<<bits);			/*	Compute signed value	*/
		}
	}
	}
	
	return error;
}

/*****************************************************
**FUNCTION	::	ChipCheckAck
**ACTION	::	Test if the chip acknowledge at its supposed address
**PARAMS IN	::	ChipId	==> Id of the chip
**PARAMS OUT::	NONE
**RETURN	::	ACK if acknowledge is OK, NOACK otherwise
*****************************************************/
int ChipCheckAck(STCHIP_Handle_t hChip)
{
	I2C_RESULT status = I2C_ERR_ACK;
	u8 data = 0;
	
	if(hChip)  
	{
		hChip->Error = CHIPERR_NO_ERROR;

		#ifndef NO_I2C
				if(hChip->Repeater && hChip->RepeaterHost && hChip->RepeaterFn)
						hChip->RepeaterFn(hChip->RepeaterHost,TRUE);	/* Set repeater ON */ 

					// PJ 07/2012 change polling access to WRITE, since a READ could clear flags on target device
					//status = I2cReadWrite(hChip->pI2CHost,I2C_READ,hChip->I2cAddr,&data,1);
					status = I2cReadWrite(hChip->pI2CHost,I2C_WRITE,hChip->I2cAddr,&data,0);
		
					if(hChip->Repeater && hChip->RepeaterHost && hChip->RepeaterFn)
						hChip->RepeaterFn(hChip->RepeaterHost,FALSE);	/* Set repeater OFF */ 
			
		#else
			status = I2C_ERR_NONE;
		#endif
	
		if(status != I2C_ERR_NONE)
			hChip->Error = CHIPERR_I2C_NO_ACK;
	}
	return status;  
}
#endif

/*****************************************************
**FUNCTION	::	ChipWait_Or_Abort
**ACTION	::	wait for n ms or abort if requested 
**PARAMS IN	::	
**PARAMS OUT::	NONE
**RETURN	::	NONE 
*****************************************************/
void ChipWaitOrAbort(STCHIP_Handle_t hChip,u32 delay_ms)
{
 	u32 i=0;
 	while((hChip->Abort==FALSE)&&(i++<(delay_ms/10))) WAIT_N_MS(10);
 	i=0;
 	while((hChip->Abort==FALSE)&&(i++<(delay_ms%10))) WAIT_N_MS(1);
}
#ifdef HOST_PC
void ChipAbort(STCHIP_Handle_t hChip, BOOL Abort)
{
    hChip->Abort = Abort;
}
#endif
/*****************************************************
**FUNCTION	::	Chip_368dvbt2_WaitMailboxComplete
*****************************************************/

/* --------------------------------------------------------------------------*/ 
/* WBDemod Instance Map generation					     */

void ChipSetHierarchyMap (BOOL Flag)
 { 
	Hierarchy_Flag = Flag;     
	return;
 } 

 void ChipSetMapRegisterSize(STCHIP_RegSize_t RegSize)       
{ 
     ChipMapRegisterSize = RegSize;      /* helper, sets global regsize default for a map */
}

