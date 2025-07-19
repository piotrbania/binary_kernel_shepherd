
#include "danalyze.h"
#include "dintegrate.h"


/*
* Function instruments instruction + resizes jumps.
* For optimizations make sure you execute this function
* only with last instruction in the basic block.
*
* Resize JCC to full length; cover LOOPs
* Instrument:
* CALL REl32	-> only if function is PAX compatibile
* JMP INDIRECT
* CALL INDIRECT
* RET			-> also needs to know if it is PAX compatibile
*
*
* After the instrumentation we need to know which offsets
* for callbacks needs to be changed. Also the relocation
* information must be filled. However the relocation data
* may be only filled after/or In stage1.
*
*
*/

int DIntegrate::instrument_instr(_instr_iext *iext, _bb_iext *bbi, BOOL usePAX)
{

	type_flags	*flags	=	this->DA->BinData.flags;
	_dinstr		*di		=	iext->di_org;
	assert(di);
	ulong32		irva	=	di->rva_addr;
	type_flags	iflags	=	flags[irva];



	if (daIS_F_INSTR_JCC(iflags))
	{
		// extend  JCC / LOOP 
		assert((di->emul_int != LOOPNE_0) && (di->emul_int != LOOPE_0));

		daSET_F_BB_EXT_REQUIRES_JMPJCCFIX(&bbi->flags);
		
		//if (di->len == 2)
		// in some weird cases jumps may use prefixes 
		// so dont assume size = 2
		if ((di->emul_int == JCC_0) || (di->emul_int == LOOP_0) || (di->emul_int == JECXZ_0))
		{
			// now extend it
			daSET_F_BB_EXT_EXTENDED_JCC(&bbi->flags);
			if (di->emul_int == JECXZ_0)
				this->extend_JECXZ(iext);
			else
				this->extend_JCC(iext);
		}
		else
		{
			// already extended, so just copy the data
			this->copy_original_instruction(iext);
		}
	}

	// for now instrument only: RET/RET XX
	//else if (daIS_F_INSTR_RETURN(iflags))
	else if ((di->emul_int == RET_0) || (di->emul_int == RET_1))
	{

		// instrument ret
		daSET_F_BB_EXT_INSTRUMENT_RET(&bbi->flags);
#if ((DI_INSTRUMENT == 1) && (DI_INSTRUMENT_RET == 1))
		this->instrument_RET(iext, usePAX);
#endif
	}
	else if (di->emul_int == JMP_SHORT_0)
	{
		// firstly check if this jump is not redundant
		if (!this->link_JMP(iext, bbi))
		{
			daSET_F_BB_EXT_REQUIRES_JMPJCCFIX(&bbi->flags);
		// short jump
			daSET_F_BB_EXT_EXTENDED_JMP(&bbi->flags);
			this->extend_JMP(iext);
		}
		
	}
	else if (di->emul_int == JMP_0)
	{

		// firstly check if this jump is not redundant
		if (!this->link_JMP(iext, bbi))
		{
			daSET_F_BB_EXT_REQUIRES_JMPJCCFIX(&bbi->flags);
			// already extended, so just copy the data
			this->copy_original_instruction(iext);
		}
	}

	else if (di->emul_int	== CALL_0)
	{

		this->copy_original_instruction(iext);

		// this is a call rel so add this bbi to list
		CallRelList.push_back(bbi);

		// we need to check first if the destination procedure
		// is pax suitable
		BOOL usePAX_c		=	!daIS_REFERENCED(flags[di->linked_instr_rva]);
		if (usePAX_c)
		{
		// instrument CALL rel32 / if usePAX=TRUE
#if ((DI_INSTRUMENT == 1) && (DI_INSTRUMENT_CALLREL == 1))
			daSET_F_BB_EXT_INSTRUMENT_CALLREL(&bbi->flags);
			this->instrument_CALLREL(iext);
#endif
		}
	}

	else if ((di->emul_int == CALL_2) || (di->emul_int == CALL_1))
	{
		// call indirect ([mem]/reg)
		// dont instrument api calls (if possible)
		
#if ((DI_INSTRUMENT == 1) && (DI_INSTRUMENT_CALLI == 1))
		if (!daIS_F_INSTR_USES_IMPORTED_API(flags[irva]))
		{
			daSET_F_BB_EXT_INSTRUMENT_CALLI(&bbi->flags);
			this->instrument_CALLI(iext);
		}
#endif
	}
	else if ((di->emul_int == JMP_2) || (di->emul_int == JMP_1))
	{
		// jmp indirect ([mem]/reg)
		// dont instrument api calls (if possible)
#if ((DI_INSTRUMENT == 1) && (DI_INSTRUMENT_JMPI == 1))
		if (!daIS_F_INSTR_USES_IMPORTED_API(flags[irva]))
		{
			daSET_F_BB_EXT_INSTRUMENT_JMPI(&bbi->flags);
			instrument_JMPI(iext);
		}
#endif
	}



	

	// if block is interrupted
	if (daIS_F_BB_INTERRUPTED(flags[irva]))
	{
		daSET_F_BB_EXT_INTERRUPTED(&bbi->flags);
		this->repair_interrupted_block(bbi, iext);
		return D_OK;
	}


	// check if next-block fixing is required
	if (bbi->bbi_next)
	{
		this->fix_nextlink(iext, bbi);
	}


	return D_OK;
}


/*
* Instrument all functions
*/

int	DIntegrate::instrument(void)
{

	type_flags	*flags		=	this->DA->BinData.flags;

	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	=	this->DA->FunctionList[i];
		BOOL usePAX			=	!daIS_REFERENCED(flags[func->bb_start->rva_start]);

#if DEBUG_INSTRUMENTATION == 1
		this->debug_instrument_function(func);
#endif

		for (int j = 0; j < func->BBIList->size(); j++)
		{
			_bb_iext	 *bbi	= (*func->BBIList)[j];
			assert(bbi);
			_dbasicblock *bb	= (_dbasicblock*)bbi->bb_org;


//bp(bb->rva_start, 0x000011E7);


			// get last instruction
			assert(bbi->InstrIExtList && bbi->InstrIExtList->size());
			_instr_iext *iext		= (*bbi->InstrIExtList)[bbi->InstrIExtList->size()-1];

			this->instrument_instr(iext, bbi, usePAX);

		}
	}



	return D_OK;
}


/*
* Function repairs interrupted block in this way that:
* for example "int 3" is a block interruptor but sometimes
* instructions after "int 3" are used. (ntoskrnl debug services).
* Two ways available here:
* 1st way:
* <org_interruptor_instr>
* push after_org_interruptor_loc
* ret
*
* 2nd way:
* push org_interruptor_loc
* ret
*
* 2nd way should be used when only possible, however
* please remember we are patching basic blocks
* with JMPREL at entry. So we need to make sure
* the interruptor instruciton will be not overwritten.
* So when the basic block size is too low we 
* use the 2nd way.
*/

inline	void DIntegrate::repair_interrupted_block(_bb_iext		*bbi, _instr_iext *iext)
{
	_dinstr		*di			=	iext->di_org;
	uchar		*old_data	=	iext->data;
	int			org_len		=	0;

	// get the correct way
	_dbasicblock	*bb		=	(_dbasicblock*)bbi->bb_org;
	ulong32	bb_total_size	=	(bb->rva_end - bb->rva_start) + di->len;

	if ((bb_total_size >= PATCH_SIZE) && 
		((bb_total_size - di->len) < PATCH_SIZE))
		org_len	=	di->len;


#if DI_DEBUG_IT == 1
	flog("%s: Picking %s way !\n",
		__FUNCTION__,
		(org_len == 0? "NORMAL1ST":"2NDAFTER"));
#endif

	org_len= di->len;
	int size_needed =	org_len + I_PUSH_VALUE_LEN + I_RET_LEN;
	//size_needed++;	// debug only
	new_iext_data(iext, size_needed);

	// copy original data

	memcpy((void*)iext->data, old_data, org_len);

	// write the push 
	ulong32 push_val	=	di->rva_addr	+ org_len + this->DA->o_imagebase;
	sp_asmINSTR_PUSH_VALUE(iext->data + org_len, push_val);


	// debug only
	//*(uchar*)(iext->data + org_len + I_PUSH_VALUE_LEN) = 0xCC;
	//org_len++;
	//end debugonly

	sp_asmINSTR_RET(iext->data + org_len + I_PUSH_VALUE_LEN);
	iext->data_size		=	size_needed;



#if DI_DEBUG_IT == 1
	flog("%s: instrumentation for %08x\n", __FUNCTION__, di->rva_addr);
	this->dump_instrumentation(iext);
#endif
}

/*
* Instruments CALL INDIRECT / JUMP INDIRECT
*
*	push [dest]/reg
*   call callback_JMPI/CALLI
*
* last two instructions will be overwritten by the loader to
* call filter_CALLI/JMPI. So dont worry about them now.
*/

inline	void DIntegrate::instrument_CALLI(_instr_iext *iext)
{

	// firstly calculate the needed size&alloc
	_dinstr		*di	=	iext->di_org;
	int size_needed =	di->len + PATCH_SIZE + di->len;
	new_iext_data(iext, size_needed);

	
	// see if this is call reg/jmp reg version
	if ((di->emul_int == CALL_1) || (di->emul_int == JMP_1))
	{
		assert(di->len == 2);
		uchar reg = sp_asmGET_REG(di->data[1]);

		// assemble push reg
		sp_asmINSTR_PUSH_REG(iext->data, reg);

		// assemble call callback_CALL
		sp_asmINSTR_CALL(iext->data + I_PUSH_REG_LEN);	
		iext->data_size		=	I_PUSH_REG_LEN + PATCH_SIZE;
	}
	else
	{
		// must be call/jmp [mem]
		// assemble push [mem]; will have the same size as org instruction
		sp_asmINSTR_PUSH_MEM(iext->data,  &di->data[1], di->len - 1);

		// assemble call callback
		sp_asmINSTR_CALL(iext->data + di->len);	
		iext->data_size		=	di->len + PATCH_SIZE;
	}


	// add original instruction at the end
	memcpy(&iext->data[iext->data_size], di->data, di->len);
	iext->data_size += di->len;

#if DI_DEBUG_IT == 1
	this->dump_instrumentation(iext);
#endif

}

/*
* Instruments JMPI
*/
inline	void DIntegrate::instrument_JMPI(_instr_iext *iext)
{
	// firstly calculate the needed size&alloc
	_dinstr		*di	=	iext->di_org;
	int size_needed =	di->len + PATCH_SIZE;
	new_iext_data(iext, size_needed);

	
	// see if this is call reg/jmp reg version
	if (di->emul_int == JMP_1)
	{
		assert(di->len == 2);
		uchar reg = sp_asmGET_REG(di->data[1]);

		// assemble push reg
		sp_asmINSTR_PUSH_REG(iext->data, reg);

		// assemble call callback_CALL
		sp_asmINSTR_CALL(iext->data + I_PUSH_REG_LEN);	
		iext->data_size		=	I_PUSH_REG_LEN + PATCH_SIZE;
	}
	else
	{
		// must be call/jmp [mem]
		// assemble push [mem]; will have the same size as org instruction
		sp_asmINSTR_PUSH_MEM(iext->data,  &di->data[1], di->len - 1);

		// assemble call callback
		sp_asmINSTR_CALL(iext->data + di->len);	
		iext->data_size		=	di->len + PATCH_SIZE;
	}



#if DI_DEBUG_IT == 1
	this->dump_instrumentation(iext);
#endif

}


/*
* Instrument call relative for PAX like method
* Just emit test eax, KEY after each call
*
* we cant use test eax,KEY because it influences the 
* EFLAGS and things like win32k.sys will produce
* unstable results :(
* use jmp $+4; dd key instead
*/

inline	void  DIntegrate::instrument_CALLREL(_instr_iext *iext)
{
	// firstly calculate the needed size&alloc
	_dinstr		*di	=	iext->di_org;
	int size_needed =	di->len + I_SHORT_JMP_LEN + sizeof(ulong32);
	new_iext_data(iext, size_needed);

	// now copy original instruction there
	memcpy((void*)iext->data, di->data, di->len);

	// now place jmp $+4
	sp_asmINSTR_SHORT_JMP(&iext->data[di->len]);
	iext->data[di->len + 1] = 0x04;

	// now place KEY there
	*(ulong32*)&iext->data[di->len + I_SHORT_JMP_LEN] = this->magic_key;
	iext->data_size	=	size_needed;


#if DI_DEBUG_IT == 1
	this->dump_instrumentation(iext);
#endif

}


/*
* Instrumentation for RET
*
* push	usePAX {0/1}
* push	retIMM	{0-if none)
* call	callback_RET
* original_instruction
* 
* last two instructions will be overwritten by the loader to
* filter_RET so dont worry about them now
* 
* #if DI_USE_PAX == 0 -> 
* call	callback_RET
*/

inline	void DIntegrate::instrument_RET(_instr_iext *iext, BOOL usePAX)
{

	_dinstr		*di	=	iext->di_org;
#if DI_USE_PAX == 1
	// firstly calculate the needed size&alloc
	int size_needed =	PATCH_SIZE + (I_PUSH_VALUE_LEN * 2) + di->len;
	new_iext_data(iext, size_needed);


	// write push usePAX
	sp_asmINSTR_PUSH_VALUE(iext->data, (usePAX == FALSE? 0:1));
	
	// write push retIMM
	ulong32 ret_imm	=	0;
	if (di->len > 1) ret_imm	=	*(uword*)&di->data[1];
	sp_asmINSTR_PUSH_VALUE(iext->data + I_PUSH_VALUE_LEN, ret_imm);


	// write call callback
	sp_asmINSTR_CALL(iext->data + (I_PUSH_VALUE_LEN*2));	
	iext->data_size	=	size_needed;

	// write original command
	memcpy(iext->data + size_needed - di->len, di->data, di->len);
#else
	int size_needed =	PATCH_SIZE + di->len;
	new_iext_data(iext, size_needed);

	// write call callback
	sp_asmINSTR_CALL(iext->data);	
	iext->data_size	=	size_needed;

	// write original command
	memcpy(iext->data + size_needed - di->len, di->data, di->len);
#endif


#if DI_DEBUG_IT == 1
	this->dump_instrumentation(iext);
#endif


}


/*
* Function extends short JMPS (2bytes) to long form 5 bytes
*/

inline	void DIntegrate::extend_JMP(_instr_iext *iext)
{
	_dinstr		*di	=	iext->di_org;	
	int size_needed =	PATCH_SIZE;

	new_iext_data(iext, size_needed);

	sp_asmINSTR_LONG_JMP(iext->data);
	iext->data_size	=	PATCH_SIZE;


#if DI_DEBUG_IT == 1
	this->dump_instrumentation(iext);
#endif

}


/*
* Function extends JECXZ.
* Since this instruction doesnt have a longer form
* we need to change it to two new instructions:
* or ecx,ecx
* jz long
*
* JECXZ are pretty rarely used but still they may happen
* just like in win32k.sys...
*/

inline	void DIntegrate::extend_JECXZ(_instr_iext *iext)
{
	_dinstr		*di	=	iext->di_org;
	
	int size_needed =	I_LONG_JCC_LEN + I_OR_REGREG_LEN;
	new_iext_data(iext, size_needed);

	sp_asmINSTR_OR_ECXECX(iext->data);
	sp_asmINSTR_LONG_JCC(iext->data + I_OR_REGREG_LEN , D_TTTN_JE);
	iext->data_size	=	I_LONG_JCC_LEN + I_OR_REGREG_LEN;


#if DI_DEBUG_IT == 1
	this->dump_instrumentation(iext);
#endif
}

/*
* Function extends JCCs (and LOOPs)
* change LOOP => dec ecx,jnz long
* change JCC to longer forms
*/

inline	void DIntegrate::extend_JCC(_instr_iext *iext)
{
	_dinstr		*di	=	iext->di_org;
	
	int size_needed =	I_LONG_JCC_LEN;
	if (di->emul_int == LOOP_0)
		size_needed		+=	I_DEC_LEN;


	new_iext_data(iext, size_needed);

	if (di->emul_int == LOOP_0)
	{
		sp_asmINSTR_DEC_ECX(iext->data);
		sp_asmINSTR_LONG_JCC(iext->data + I_DEC_LEN, D_TTTN_JNE);
		iext->data_size	=	I_LONG_JCC_LEN + I_DEC_LEN;
	}
	else
	{
		// normal short jcc here so extend it to longer form
		int tttn		=   sp_asmGET_TTTN(di->data[0]);
		sp_asmINSTR_LONG_JCC(iext->data, tttn);
		iext->data_size	=	I_LONG_JCC_LEN;
	}



#if DI_DEBUG_IT == 1
	this->dump_instrumentation(iext);
#endif

}

/*
* Function shows created instrumentation.
*/

void	DIntegrate::dump_instrumentation(_instr_iext *iext)
{

	return;

	flog("%s: instrumenting instr at %08x (ORG/INSTRUMENTED)\n", __FUNCTION__, iext->di_org->rva_addr);
	this->DA->debug_show_instruction(iext->di_org->rva_addr);

	for (int i = 0; i < iext->data_size; i++)
	{
		int len = this->DA->debug_show_instruction_from_data(iext->data+i);
		i += len - 1;
	}
}

/*
* Allocates new data for iext
*/

inline	uchar* DIntegrate::new_iext_data(_instr_iext *iext, int size)
{
	iext->data		=	new uchar[size];
	assert(iext->data);
	memset((void*)iext->data, 0, size);
	return iext->data;
}



/*
* Function fixes the fallthrough connection between two nodes.
* We are using jump patch here.
*/

inline  void DIntegrate::fix_nextlink(_instr_iext *iext, _bb_iext *bbi)
{
	uchar	*org_data	=	iext->data;
	assert(org_data);
	BOOL	free_it		=	this->was_iext_data_allocated(iext);

	new_iext_data(iext, iext->data_size + PATCH_SIZE);

	// copy the original data
	memcpy((void*)iext->data, org_data, iext->data_size);

	sp_asmINSTR_LONG_JMP(&iext->data[iext->data_size]);
	iext->data_size		=	iext->data_size + PATCH_SIZE;

	if (free_it)
		delete []org_data;
}

/*
* Functions allocates data, and copies original instructions there.
* This is a must since the offsets will be overwritten in the stage2.
*/

inline	void DIntegrate::copy_original_instruction(_instr_iext *iext)
{
	uchar	*org_data	=	iext->data;

	new_iext_data(iext, iext->data_size);

	// copy the original data
	memcpy((void*)iext->data, org_data, iext->data_size);
}


/*
* When basicblock has JMP to another block.
* And this another block is located just after it
* we don't have to emit the jump!
*/

inline	BOOL DIntegrate::link_JMP(_instr_iext *iext, _bb_iext *bbi)
{
	if (!bbi->bbi_linked)
		return FALSE;

	// is it located just after parent block?
	if (bbi->bbi_linked->DFSInTime == (bbi->DFSInTime + 1))
	{

#if DI_DEBUG_IT == 1
		flog("%s: redundant jump connecting bb=%08x and bb=%08x\n",
			__FUNCTION__,
			static_cast<_dbasicblock*>(bbi->bb_org)->rva_start,
			static_cast<_dbasicblock*>(bbi->bbi_linked->bb_org)->rva_start);

#endif
		// yep we can skip the jump
		daSET_F_BB_EXT_REDUNDANT_JMP(&bbi->flags);
		iext->data_size	=	0;
		return TRUE;
	}

	return FALSE;
}