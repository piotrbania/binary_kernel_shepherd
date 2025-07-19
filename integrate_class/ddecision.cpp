
#include "danalyze.h"
#include "dintegrate.h"

/*
* Function determines is function is hookable. Sets all necessary flags
*/

BOOL		DIntegrate::determine_hook_ability(_dfunction *func)
{
	_bb_iext *bbi	=	func->BBIList->front();


	if (is_func_hookable(func))
	{
		daSET_F_BB_EXT_HOOKABLE(&bbi->flags);
		return TRUE;
	}

	assert(!daIS_F_BB_EXT_HOOKABLE(bbi->flags));
	daSET_F_BB_EXT_NOTHOOKABLE(&bbi->flags);
	return FALSE;
}


/*
* Function decides if destination function is hookable.
*
*/

int debug_ile = 0;

BOOL	DIntegrate::is_func_hookable(_dfunction *func)
{
	type_flags	*flags	=	this->DA->BinData.flags;
	_dbasicblock *bb	= func->bb_start;

	
#if SKIP_INIT_SECTION == 1
	if (this->is_rva_in_INIT_section(bb->rva_start))
	{
#if DI_DEBUG_IT == 1
		flog("%s: RVA=%08x in INIT section (not hooking!)\n",
			__FUNCTION__,
			bb->rva_start);
#endif
		return FALSE;
	}
#endif

	// calculate basicblock size
	_dinstr	*di		=	this->DA->get_dinstr_from_rva(bb->rva_end);
	assert(di);
	ulong32 bb_size = (bb->rva_end - bb->rva_start) + di->len;

	// is there enough size?
	if (bb_size < PATCH_SIZE)
	{
			// first basicblock is too short (dont patch!)
#if DI_DEBUG_IT == 1
		flog("%s: !!! basicblock too short for patching RVA=%08x SIZE=%d\n",
			__FUNCTION__,
			bb->rva_start,
			bb_size);
#endif
		return FALSE;
	}

	// check if it was accessed as data
	if (daIS_F_ACCESSED_AS_DATA(flags[bb->rva_start]))
	{
#if DI_DEBUG_IT == 1
		flog("%s: function = %08x accessed as data! NOTHOOKABLE!\n",
			__FUNCTION__,
			bb->rva_start);
#endif
		return FALSE;
	}


	//debug


	/*
	type_flags	f = flags[bb->rva_start];
	if (daIS_F_RELOC_XREF(f) || daIS_F_FUNC_EXPORTED(f))
	{
			flog("%s: debug-only found bad func=%08x here, so skipping!\n",
				__FUNCTION__,bb->rva_start);
			return FALSE;
	}
	*/

	/*
	for (int j = 0; j < PATCH_SIZE+1; j++)
	{
		type_flags	f = flags[bb->rva_start+j];
		if (daIS_F_RELOC_DATA(f) ||
			daIS_F_INSTR_SYMBOL_IN_MEMIMM(f) ||
			daIS_F_INSTR_SYMBOL_IN_IMM(f))
		{
			flog("%s: debug-only found relocation func=%08x here, so skipping!\n",
				__FUNCTION__,bb->rva_start);
			return FALSE;
		}
	}
	*/
	//enddebug


	// check if function is forbidden to hook
	if (this->is_forbidden_function(func))
		return FALSE;


	// if this is not a prospect function say it is hookable
	if (!daIS_F_PROSPECT(flags[bb->rva_start]))
	{
		debug_ile++;
		return TRUE;
	}

	// debug
	//if (daIS_F_PROSPECT(flags[bb->rva_start]))
	//	return FALSE; 
	//end debug

	// ok this is a prospect we need to be careful here
	// it is better to hook less than overwrite the data
	
	// we have a prologue so this is a function for sure
	if (this->DA->is_prologue(bb->rva_start, 1))
		return TRUE;

	// check if this basicblock consists only
	// of ascii/unicode characters
	if (this->is_bb_asciiunicode(bb))
	{
#if DI_DEBUG_IT == 1
		flog("%s: entire basicblock %08x is ascii/unicode!  NOTHOOKABLE\n",
			__FUNCTION__, bb->rva_start);
#endif
		return FALSE;
	}


	// switch places with the above condition to gain speed (this is debug version)
	// if prospect consist only of one basicblock we consider this as not odd
	// and not hookable
	int		num_of_bb	=	func->BBIList->size();
	if (num_of_bb < 2)
	{
#if DI_DEBUG_IT == 1
		flog("%s: function %08x consist of %d basicblocks NOTHOOKABLE!\n",
			__FUNCTION__, bb->rva_start, num_of_bb);
#endif
		return FALSE;
	}
	

	// if it consists only of < 2 instructions skip it
	_bb_iext	*bbi		=	func->BBIList->front();
	int		num_of_instrs	=	bbi->InstrIExtList->size();

	if (num_of_instrs < 2)
	{
#if DI_DEBUG_IT == 1
		flog("%s: function 1stbasicblock %08x consist of %d instructions NOTHOOKABLE!\n",
			__FUNCTION__, bb->rva_start, num_of_bb);
#endif
		return FALSE;
	}


	// add some heuristisc here and check if the prospect was
	// referenced by a basicblock that uses API functions like
	// DebugPrint, sprintf, printf, DisplayString etc.
	

#if DI_DEBUG_IT == 1
		flog("%s: function %08x consist is HOOKABLE!\n",
			__FUNCTION__, bb->rva_start, num_of_bb);
#endif

	return TRUE;
}


/*
* Function checks if basicblock data is ascii/unicode
*/

BOOL DIntegrate::is_bb_asciiunicode(_dbasicblock *bb)
{
	
	ulong32			rva_start		=	bb->rva_start;
	ulong32			rva_end			=	bb->rva_end;

	_dinstr	*di		=	this->DA->get_dinstr_from_rva(rva_start);
	_dinstr	*die	=	this->DA->get_dinstr_from_rva(rva_end);
	assert(die && di);

	rva_end			+=		di->len;

	uchar	*data		=	this->DA->BinData.data;
	int		ascii_chars	=	0;

	ulong32	rva;
	for (rva = rva_start; rva < rva_end; rva++)
	{
		if ((data[rva] != 0) && (!is_ascii_char(data[rva])))
			break;
		ascii_chars++;
	}


	// entire basicblock was ascii
	if (rva == rva_end)
		return TRUE;

	// more than 5 ascii bytes
	if (ascii_chars > 5)
		return TRUE;

	return FALSE;
}


/*
* Function test is char is ascii.
*/

BOOL DIntegrate::is_ascii_char(uchar p)
{
/*	if (!(p >= 'a' && p <= 'z') && 
		!(p >= 'A' && p <= 'Z') &&
		!(p >= '0' && p <= '9') && 
		!(p == '_') &&
		!(p == '@') && 
		!(p == '.'))
		return FALSE;
*/

	// new line, creturn
	//if ((p == 13) || (p == 10))
	if ((p >= 9) && (p <= 10))
		return TRUE;

	// from space to 'z'
	if ((p >= 32) && (p <= 122))
		return TRUE;
		
	return FALSE;
}



/*
* Some functions cannot be hooked this way we do it.
* (see ntkrnlpa KeInitializeInterrupt for details)
*/

int DIntegrate::setup_invalid_addrs(void)
{

	this->BlackListLoc.clear();
	this->rva_KiInterruptTemplate			=	0;
	this->rva_KiUnlockDispatcherDatabase	=	0;
	this->is_ntkrnlpa						=	FALSE;

	ulong32	rva_KeInitializeInterrupt		=	NULL;

	char	*name							=   this->DA->o_filename;
	name	=	strrchr(name, '\\');

	if (!name)
		return D_FAILED;

	// check if this is ntoskrnl or ntkrnlpa
	name++;

#define NTOS1 "ntoskrnl"
#define NTOS2 "ntkrnl"

	if ((strncmp(name, NTOS1, sizeof(NTOS1)-1) != 0) &&
		(strncmp(name, NTOS2, sizeof(NTOS2)-1) != 0))
	{
#if DI_DEBUG_IT == 1
		flog("%s: this is not kernel!\n", __FUNCTION__);
#endif
		return D_FAILED;
	}


#if DI_DEBUG_IT == 1
		flog("%s: we are instrumenting kernel!\n", __FUNCTION__);
#endif

	this->is_ntkrnlpa						=	TRUE;


#define adler32_KiInterruptTemplate				0x4bef07beh
#define adler32_KiUnlockDispatcherDatabase      0x89000a3dh

#define bad_func1		"KiInterruptTemplate"
#define bad_func2		"KiUnlockDispatcherDatabase"
#define bad_func3		"Ki386"
#define bad_func4		"KeInitializeInterrupt"		
#define bad_func5		"KeFlushCurrentTb"


	// function that use KeFlushCurrentTb sequence: mov eax,cr3; mov cr3,eax
	// this function is modified by the kernel here (Ki386EnableGlobalPage):
	//	_PAGELK:0011D01D                 mov     edi, offset _KeFlushCurrentTb@0 ; KeFlushCurrentTb()
	//	_PAGELK:0011D022                 mov     esi, offset loc_68097
	//	_PAGELK:0011D027                 mov     ecx, 19h
	//	_PAGELK:0011D02C                 rep movsb
	// 
	// We must restore the calls to Ki386EnableGlobalPage. And also we must not hook the
	// "loc_68097". In order to do so scan for ret opcode just afte the end of
	// KeFlushCurrentTb. Place everything in this range as not hookable.




	assert(!this->DA->Symbols->SymbolVector.empty());
	for (int i = 0; i < this->DA->Symbols->SymbolVector.size(); i++)
	{
		_sinfo			*SymbolInfo	=	this->DA->Symbols->SymbolVector[i];
		if (SymbolInfo->name[0] == 0)
			continue;
		
		// todo: change to adler later
		// for now leave the string comparisions
			
		char	*sname	=	(char*)&SymbolInfo->name;
		if ((sname[0] == '_') || (sname[0] == '@'))
			sname++;
		ulong32	rva		=	SymbolInfo->addrRVA;

		// if we are in init section right now
		// and the symbol name is Ki386######
		// mark it as not hookable
		// or for now block all the Kis


		int	is_KeFlush	=	strncmp(sname, bad_func5, sizeof(bad_func5)-1);
	
		if ((strncmp(sname, bad_func3, sizeof(bad_func3)-1) == 0) ||
			(is_KeFlush == 0))
		{

#if DI_DEBUG_IT == 1
			flog("%s: found blacklisted function %08x (%s)\n",
				__FUNCTION__, rva, sname);
#endif
			this->BlackListLoc.push_back(rva);


			// update: 16.04.2011
			// add flags for the function
			_dfunction	*func = this->DA->find_function_by_rva(rva);
			if (!func) continue;
			daSET_F_FUNC_EXT_FORBIDDEN(&func->flags);

			// strcmp, 0 = KeFlush found, those function are special
			if ((is_KeFlush == 0))
			{
				daSET_F_FUNC_EXT_RESTORECALL(&func->flags);
				this->resolve_KeFlushCurrentTb_issue(rva);
			}
			continue;
		}


		if (strncmp(sname, bad_func1, sizeof(bad_func1)-1) == 0)
			this->rva_KiInterruptTemplate			=	rva;
		else if (strncmp(sname, bad_func2, sizeof(bad_func2)-1) == 0)
			this->rva_KiUnlockDispatcherDatabase	=	rva;
		else if (strncmp(sname, bad_func4, sizeof(bad_func4)-1) == 0)
			rva_KeInitializeInterrupt				=   rva;
	}


#if DI_DEBUG_IT == 1
	flog("%s: rva_KiInterruptTemplate = %08x, rva_KiUnlockDispatcherDatabase = %08x rva_KeInitializeInterrupt = %08x\n",
		__FUNCTION__,
		this->rva_KiInterruptTemplate,
		this->rva_KiUnlockDispatcherDatabase,
		rva_KeInitializeInterrupt);
#endif


	// on vista there is none KiUnlockDispatcherDatabase, so lets make it differently
	// go into KeInitializeInterrupt and scan for 
	// xp version:
	// .text:00022177                 add     edx, 4
	// .text:0002217A                 cmp     edi, (offset loc_6A801+1)
	// .text:00022180                 jl      short loc_22170
	//
	// vista version:
	// .text:00008D1D                 add     esi, 4
	// .text:00008D20                 cmp     edi, (offset loc_488E4+3)
	// .text:00008D26                 jl      short loc_8D16
	// 
	// we need to get the offset for cmp edi!!!
	// sig: 04 81 FF
	// 0x50 -> i just a safe range

	if (!this->rva_KiUnlockDispatcherDatabase)
	{
		uchar	*p	=	&this->DA->BinData.data[rva_KeInitializeInterrupt+0x50];
#define MAX_SEARCH 0x200
		for (int i = 0; i < MAX_SEARCH; i++)
		{
			if ((p[i] == 0x04) && (p[i+1] == 0x81) && (p[i+2] == 0xFF))
			{

				// get the offset cmp edi, OFFSET
				this->rva_KiUnlockDispatcherDatabase	=	*(ulong32*)&p[i+3] - this->DA->o_imagebase;
				assert((this->rva_KiUnlockDispatcherDatabase > 0));

#if DI_DEBUG_IT == 1
				flog("%s: found the pattern, end offset is %08x\n",
					__FUNCTION__, this->rva_KiUnlockDispatcherDatabase);
#endif
			}
		}
	}


	// those locations must be found otherwise something is fucxked up
	assert(this->rva_KiInterruptTemplate && this->rva_KiUnlockDispatcherDatabase);
	assert(this->rva_KiInterruptTemplate < this->rva_KiUnlockDispatcherDatabase);

	return D_OK;
}


/*
* Functions checks if selected function is forbidden to hook.
* speed this up later by using flags!!!
*/

inline BOOL	DIntegrate::is_forbidden_function(_dfunction *func)
{
	// only for ntoskrnl
	if (!this->is_ntkrnlpa)
		return FALSE;

	ulong32 func_rva	=	func->bb_start->rva_start;


	/*
	
	// check the blacklist
	for (int i = 0; i < this->BlackListLoc.size(); i++)
	{
		if (this->BlackListLoc[i] == func_rva)
		{
#if DI_DEBUG_IT == 1
			flog("%s: function at %08x is blacklisted to hook!\n",
				__FUNCTION__, func_rva);
#endif
			return TRUE;
		}
	}
	*/


	if (daIS_F_FUNC_EXT_FORBIDDEN(func->flags))
	{
#if DI_DEBUG_IT == 1
		flog("%s: function at %08x is blacklisted to hook!\n",
			__FUNCTION__, func_rva);
#endif
		return TRUE;
	}


	// check the ranges
	if ((func_rva >= this->rva_KiInterruptTemplate) && (func_rva <= this->rva_KiUnlockDispatcherDatabase))
	{
#if DI_DEBUG_IT == 1
		flog("%s: function at %08x is forbidden to hook!\n",
			__FUNCTION__, func_rva);
#endif

		return TRUE;
	}

	return FALSE;
}




/*
* Function checks if this rva is located in INIT section
*/
inline BOOL DIntegrate::is_rva_in_INIT_section(ulong32 rva)
{
	if (!this->init_section_rva_end)
		return FALSE;
	if ((rva >= this->init_section_rva_start) && (rva <= this->init_section_rva_end))
		return TRUE;
	return FALSE;

}



/*
* Function restores CALL mirrored_procedure to CALL original procedure
* Only needed with ntoskrnl (KeFlush case etc.)
*/

BOOL	DIntegrate::restore_call(_dfunction *func, _bb_iext *bbi, _instr_iext *iext, ulong32 iRVA)
{

#define di iext->di_org
	assert(di->emul_int == CALL_0);
	assert(iext->data[0] == 0xE8);


	ulong32		f_addr = func->bb_start->rva_start;
	_dfunction *f_dest = this->DA->find_function_by_rva(iext->di_org->linked_instr_rva);
	assert(f_dest);
	ulong32		f_dest_rva = f_dest->bb_start->rva_start;

#if DI_DEBUG_IT == 1
	flog("%s: [%d] FUNC=%08x repairing instruction %08x (newRVA=%08x) -> callTO: %08x\n", 
		__FUNCTION__, debug_repair_count, f_addr, di->rva_addr, iRVA, f_dest_rva);
#endif

	// now fix the call
	*(ulong32*)&iext->data[1]	= f_dest_rva - iRVA - 5;	
	debug_repair_count++;


#undef di
	return TRUE;
}


/*
* Function resolves the issue with self-modifying code of KeFlushCurrentTb.
* Everything was explained in the upper lines.
*/ 

BOOL	DIntegrate::resolve_KeFlushCurrentTb_issue(ulong32 rva_KeFlushCurrentTb)
{

	// get the data

	type_flags		*flags		=	this->DA->BinData.flags;
	uchar			*p			=	&this->DA->BinData.data[rva_KeFlushCurrentTb];
	uchar			*p_org		=	p;

	// scan until we find the ret value (0xC3)
	// 3 times to make the safe range
	int	found_times = 0;
	while (1)
	{
		if (p[0] == 0xC3)
		{
			if (found_times < 3)
			{
				found_times++;
				p++;
				continue;
			}
			else
				break;
		}
		p++;
	}


#define MAX_RANGE (0x000680B4 - 0x00068090)
	ulong32 range = (ulong32)(p - p_org);
	if (range > MAX_RANGE)
		range = MAX_RANGE;

#if DI_DEBUG_IT == 1
	flog("%s: Range is %08x - %08x\n", 
		__FUNCTION__, rva_KeFlushCurrentTb, rva_KeFlushCurrentTb + range);
#endif

	// now find every function in that range and mark it as not hookable
	for (ulong32 a = rva_KeFlushCurrentTb; a < (rva_KeFlushCurrentTb + range); a++)
	{
		if (daIS_F_FUNCTION_START(flags[a]))
		{
			_dfunction *func = this->DA->find_function_by_rva(a);
			if (!func) continue;

			// mark it as not hookable
			daSET_F_FUNC_EXT_FORBIDDEN(&func->flags);

#if DI_DEBUG_IT == 1
			flog("%s: Function %08x is forbidden to hook!\n",
				__FUNCTION__, func->bb_start->rva_start);
#endif

		}

	}

	return TRUE;
}