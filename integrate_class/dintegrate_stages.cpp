

#include "danalyze.h"
#include "dintegrate.h"

//#include "Imagehlp.h"

// imagehlp.h conflicts with the symbol headers :(
#define CHECKSUM_SUCCESS 0
/*

#define IMAGEAPI DECLSPEC_IMPORT __stdcall
extern DWORD IMAGEAPI
MapFileAndCheckSumA (
    LPSTR Filename,
    LPDWORD HeaderSum,
    LPDWORD CheckSum
    );
#define MapFileAndCheckSum  MapFileAndCheckSumA
*/



/*
* Function calculates new size for every basicblock.
*/

int	DIntegrate::calculate_new_bb_size(void)
{
	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	= this->DA->FunctionList[i];

		for (int j = 0; j < func->BBIList->size(); j++)
		{
			_bb_iext	 *bbi	= (*func->BBIList)[j];
			assert(bbi);
			_dbasicblock *bb	= (_dbasicblock*)bbi->bb_org;
			

			// for every instruction
			assert(bbi->InstrIExtList);

			bbi->size			=	0;
			for (int k = 0; k < bbi->InstrIExtList->size(); k++)
			{
				_instr_iext *iext		= (*bbi->InstrIExtList)[k];
				bbi->size				+= iext->data_size;	
			}
		}
	}




	return D_OK;
}



/*
* STAGE1, CALCULATE ALL OFFSET (RVA_NEW)
* FOR ALL BASICBLOCKS (AND FUNCTIONS)
* MUST BE CALLED AFTER INSTRUMENTATION
*/

int	DIntegrate::integrate_stage1(void)
{
	ulong32		rva_start	=	NULL;

	// firstly calculate the size
	this->calculate_new_bb_size();
	this->total_align_size	=		0;

	this->find_INIT_section();
	this->generate_callbacks();

	rva_start	=	this->callback_mem_size;

	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	= this->DA->FunctionList[i];
		
		rva_start = this->integrate_stage1_func(func, rva_start);
	}



	return D_OK;
}




/*
* STAGE2 - REPAIR ALL RELATIVE OFFSETS FOR JMPS/CALLS
* MUST BE CALLED AFTER STAGE1
*/

int	DIntegrate::integrate_stage2(void)
{

	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	= this->DA->FunctionList[i];
		this->integrate_stage2_func(func);
	}


	return D_OK;
}



/*
* Function repairs the offsets
*/

int	DIntegrate::integrate_stage2_func(_dfunction *func)
{

	int list_size = func->BBIList->size();
	for (int i = 0; i < list_size; i++)
	{
		_bb_iext		*bbi	=	(*func->BBIList)[i];
		_dbasicblock	*bb		=	(_dbasicblock*)bbi->bb_org;


		_instr_iext	*iext = bbi->InstrIExtList->back();
		type_flags	iflags = this->DA->BinData.flags[iext->di_org->rva_addr];


		// interrupted blocks are already fixed
		int		fix_set			=	0;
		if (daIS_F_BB_EXT_INTERRUPTED(bbi->flags))
			fix_set		+=	I_PUSH_VALUE_LEN + I_RET_LEN;	//continue;

		
		if (daIS_F_BB_EXT_REQUIRES_NFIX(bbi->flags))
			fix_set				+=	PATCH_SIZE;


		// check if it was instrumented if so repair the callbacks
		// CALII requires fix set
#if (DI_INSTRUMENT_CALLI == 1)
		//bp(iext->di_org->rva_addr, 0x000290A1);
		if (daIS_F_BB_EXT_INSTRUMENT_CALLI(bbi->flags))
		{
			// remember after the call callback there is original instruction CALLI
			_dinstr *di = iext->di_org;
			*(ulong32*)&iext->data[iext->data_size - sizeof(ulong32) - di->len - fix_set] =
				this->rva_callback_CALLI - (bbi->rva_new + bbi->size - di->len) + fix_set;	
			goto try_bbi_next_fix;
		}
#endif
#if (DI_INSTRUMENT_JMPI == 1)
		if (daIS_F_BB_EXT_INSTRUMENT_JMPI(bbi->flags))
		{
			*(ulong32*)&iext->data[iext->data_size - sizeof(ulong32)] =
				this->rva_callback_JMPI - (bbi->rva_new + bbi->size);	
			continue;
		}
#endif
#if (DI_INSTRUMENT_RET == 1)
		else if (daIS_F_BB_EXT_INSTRUMENT_RET(bbi->flags))
		{
			// remeber after call there is also original ret
			_dinstr *di = iext->di_org;
			*(ulong32*)&iext->data[iext->data_size - sizeof(ulong32) - di->len] =
				this->rva_callback_RET - (bbi->rva_new + bbi->size - di->len);	
			continue;
		}
#endif


	
		// if linked one is != 0; we have a jump/jcc link
		// we must be sure it is not a call also
		if (bbi->bbi_linked && daIS_F_BB_EXT_REQUIRES_JMPJCCFIX(bbi->flags))
		{

			// debug ony
			_dbasicblock *bb_linked = (_dbasicblock*)bbi->bbi_linked->bb_org;

			// so lets link them
			// get the last instruction
			//_instr_iext	*iext = (*bbi->InstrIExtList)[bbi->InstrIExtList->size()-1];
			
			assert(iext->data_size > ( sizeof(ulong32) + fix_set));
			*(ulong32*)&iext->data[iext->data_size - sizeof(ulong32) - fix_set] =
				bbi->bbi_linked->rva_new - (bbi->rva_new + bbi->size) + fix_set;	

			/*
			ulong32 debug_offset = bbi->bbi_linked->rva_new - (bbi->rva_new + bbi->size) + fix_set;	
			flog("linking bbRVA=%08x bbENDRVA=%08x with RVA=%08x jmpIMM=%08x\n",
				bbi->rva_new,
				bbi->rva_new + bbi->size,
				bbi->bbi_linked->rva_new,
				debug_offset);
				*/

//			bp(iext->di_org->rva_addr, 0x1863);
		}
		else
		{
			// time to repair call rel
			// firstly check if this instruction is a instrumented CALLI/JMPI
			// if so skip it
			if (daIS_F_BB_EXT_INSTRUMENT_CALLI(bbi->flags) || daIS_F_BB_EXT_INSTRUMENT_JMPI(bbi->flags))
				goto try_bbi_next_fix;

	
			// and now check if this is a call rel, if not skip it also		
			if (!daIS_F_INSTR_CALL(iflags))
				goto try_bbi_next_fix;
			
			if (iext->di_org->len != 5)
				goto try_bbi_next_fix;	//continue;

			// call destination must be a function at this point!
			_dfunction *f_dest = this->DA->find_function_by_rva(iext->di_org->linked_instr_rva);
			assert(f_dest);

			// check for special case (KeFlush)
			// (this call must be restored later to the original function)
			if (daIS_F_FUNC_EXT_RESTORECALL(f_dest->flags))
				daSET_F_BB_EXT_RESTORECALL(&bbi->flags);

			// we are fixing a call, so the offset starts at 1
			_bb_iext		*bbi_first = f_dest->BBIList->front();
			*(ulong32*)&iext->data[1] =
				bbi_first->rva_new - (bbi->rva_new + bbi->size) + (iext->data_size - iext->di_org->len);

		}


try_bbi_next_fix:;
		// make the next link fix
		if (bbi->bbi_next && !daIS_F_BB_EXT_INTERRUPTED(bbi->flags))
		{
			*(ulong32*)&iext->data[iext->data_size - sizeof(ulong32)] =
				bbi->bbi_next->rva_new - (bbi->rva_new + bbi->size);	
		}

	}



	// debug only


	/*
#if DEBUG_INSTRUMENTATION == 1
	for (int i = 0; i < list_size; i++)
	{
		_bb_iext		*bbi	=	(*func->BBIList)[i];
		_dbasicblock	*bb		=	(_dbasicblock*)bbi->bb_org;


		_instr_iext	*iext = bbi->InstrIExtList->front();
		type_flags	iflags = this->DA->BinData.flags[iext->di_org->rva_addr];

		if (daIS_F_BB_EXT_DEBUG_FIX(bbi->flags))
		{
			// fix the call to DebugPrint
			// call offset is located 5 bytes from the end
			//DBG_PRINT_RVA

		//	uchar *p = (uchar*)&iext->data[iext->data_size - sizeof(ulong32) - I_POPAD_LEN - 1];


#define DBG_PRINT_RVA 0x1000
			*(ulong32*)&iext->data[iext->data_size - sizeof(ulong32) - I_POPAD_LEN] =
				DBG_PRINT_RVA - (bbi->rva_new + bbi->size);



			continue;
		}
	}
#endif
*/

	return D_OK;
}


/*
* Calculates new RVA for every BB in function.
* and returns the last RVA used. It also check is function is hookable.
*/

ulong32 DIntegrate::integrate_stage1_func(_dfunction *func, ulong32 start_rva)
{


	// check if function is hookable
	this->determine_hook_ability(func);

	// keep each function aligned
	ulong32 rva					= align(start_rva,  FUNC_ALIGN);
	this->total_align_size		+= rva - start_rva;

	int list_size = func->BBIList->size();
	for (int i = 0; i < list_size; i++)
	{
		_bb_iext		*bbi	=	(*func->BBIList)[i];
		_dbasicblock	*bb		=	(_dbasicblock*)bbi->bb_org;

		// the list was sorted by DFS so just increase the RVAs
		bbi->rva_new			=	rva;
		ulong32 i_rva			=	rva;
		rva						+=	bbi->size;

		// get the relocations
		int	instr_num			=	bbi->InstrIExtList->size();
		
		for (int j = 0; j <  instr_num; j++)
		{
			_instr_iext	*iext	=	(*bbi->InstrIExtList)[j];

			this->write_relocation_entry(bbi,	iext, i_rva);

			// if this is the last one fill the callbacks informations
			if (j == (instr_num-1))
			{

				this->write_relocation_entry_for_instrumented_CALLi(bbi, iext, i_rva);
				this->write_relocation_entry_for_interrupted_bb(bbi, iext, i_rva);
				//this->write_callback_entry(bbi, iext, i_rva);
			}

			i_rva				+=	iext->data_size;
		}
	}

	// debug
	/*
	for (int i = 0; i < list_size; i++)
	{
		_bb_iext		*bbi	=	(*func->BBIList)[i];
		if (bbi->bbi_next) __asm int 3;
	}
	*/

	return rva;
}

/*
* Function checks if instruction is a instrumented CALLI.
* Adds relocation entry to original instruction if required.
* Execute it only with last instruction.
*/

int	DIntegrate::write_relocation_entry_for_instrumented_CALLi(_bb_iext		*bbi, _instr_iext *iext, ulong32 i_new_rva)
{

#if (DI_INSTRUMENT_CALLI == 0)
	return D_FAILED;
#endif


	//bp(iext->di_org->rva_addr, 0x000290A1);

	if (!daIS_F_BB_EXT_INSTRUMENT_CALLI(bbi->flags))
		return D_FAILED;

	// now check if this instruction has relocable data in MEMIMM
	_dinstr		*di			=	iext->di_org;
	type_flags	iflags		=	this->DA->BinData.flags[di->rva_addr];

	if (!daIS_F_INSTR_RELOCABLE_DATA_IN_MEMIMM(iflags))
		return D_FAILED;


	// at the end of the block we have the original instruction
	// with mem_imm, so get back to it
	// update: we also require FIX SETs here!!!
	int fix_set	=	0;
	if (daIS_F_BB_EXT_INTERRUPTED(bbi->flags))
		fix_set		+=	I_PUSH_VALUE_LEN + I_RET_LEN;	//continue;
	if (daIS_F_BB_EXT_REQUIRES_NFIX(bbi->flags))
		fix_set				+=	PATCH_SIZE;

	ulong32 new_relocation = i_new_rva + iext->data_size - sizeof(ulong32) - fix_set;
	this->RelocsList.push_back(new_relocation);

#if DI_DEBUG_IT == 1
	
	flog("%s: relocs in instrumented CALLI orgINSTR: %08x newINSTR=%08x\n",
		__FUNCTION__,
		di->rva_addr,
		i_new_rva);
#endif

	return D_OK;
}


/*
* Function checks if block was interrupted and then writes the additional
* relocation entry. This must be only executed for last instruction
* in a block.
*/

int	DIntegrate::write_relocation_entry_for_interrupted_bb(_bb_iext		*bbi, _instr_iext *iext, ulong32 i_new_rva)
{
	if (!daIS_F_BB_EXT_INTERRUPTED(bbi->flags))
		return D_FAILED;

	_dinstr		*di			=	iext->di_org;
	

	assert(iext->data_size	> I_PUSH_VALUE_LEN);
	//ulong32 new_relocation = i_new_rva + di->len + 1;
	//ulong32 new_relocation = i_new_rva + 1;

	ulong32 new_relocation = i_new_rva + iext->data_size - sizeof(ulong32) - I_RET_LEN;
//	new_relocation--;	// debug only
	this->RelocsList.push_back(new_relocation);

#if DI_DEBUG_IT == 1
	flog("%s: relocs in PUSH_INTERRUPTED orgINSTR: %08x newINSTR=%08x\n",
		__FUNCTION__,
		di->rva_addr,
		i_new_rva);
#endif

	return D_OK;
}


/*
* Function checks selected instruction and writes
* relocation information if needed.
*/

int	DIntegrate::write_relocation_entry(_bb_iext		*bbi, _instr_iext *iext, ulong32 i_new_rva)
{
	_dinstr		*di			=	iext->di_org;
	type_flags	iflags		=	this->DA->BinData.flags[di->rva_addr];

	//bp(di->rva_addr, 0x1003);
	int			imm_size	=	disit_getDF_size_IMM(di->disit_flags);

	if (daIS_F_INSTR_RELOCABLE_DATA_IN_IMM(iflags))
	{
		// data in imm (always 32 bit)
		//imm_size			=	disit_getDF_size_IMM(di->disit_flags);

		//imm_size			=	sizeof(ulong32);
		this->RelocsList.push_back((ulong32)(i_new_rva	+ di->len - sizeof(ulong32)));

#if DI_DEBUG_IT == 1
		flog("%s: relocs in IMM orgINSTR: %08x orgOFF: %08x newINSTR: %08x\n",
			__FUNCTION__,
			di->rva_addr,
			di->len - sizeof(ulong32),
			i_new_rva);
#endif

	}

	if (daIS_F_INSTR_RELOCABLE_DATA_IN_MEMIMM(iflags))
	{


		// remember even if this is the intrumented call [mem]/jmp [mem]
		// the relocable offset stays at the same locations (as it is in original instruction)

		// data in memimm (always 32bit)
		this->RelocsList.push_back((ulong32)(i_new_rva	+ di->len - sizeof(ulong32) - imm_size));


#if DI_DEBUG_IT == 1
		flog("%s: relocs in MEMIMM orgINSTR: %08x orgOFF: %08x newINSTR=%08x\n",
			__FUNCTION__,
			di->rva_addr,
			di->len - sizeof(ulong32) - imm_size,
			i_new_rva);
#endif

	}




	return D_OK;
}


/*
* When we instrument RET/CALLI/JMPI last 5 bytes are left for 
* "call callback"
*/

int		DIntegrate::write_callback_entry(_bb_iext *bbi, _instr_iext *iext, ulong32 i_new_rva)
{
	if (daIS_F_BB_EXT_REQUIRE_CALLBACK_FIX(bbi->flags))
	{
		_callback_location	*cb_loc	=	new _callback_location;
		assert(cb_loc);

		int		fix_set			=	0;
		if (daIS_F_BB_EXT_REQUIRES_NFIX(bbi->flags))
			fix_set				=	PATCH_SIZE;

		// compute the rva for callback
		cb_loc->rva_addr			=	i_new_rva + iext->data_size	- PATCH_SIZE - fix_set;



		if (daIS_F_BB_EXT_INSTRUMENT_RET(bbi->flags))
			cb_loc->type	=	CALLBACK_TYPE_RET;
		else if (daIS_F_BB_EXT_INSTRUMENT_CALLI(bbi->flags))
			cb_loc->type	=	CALLBACK_TYPE_CALLI;
		else if (daIS_F_BB_EXT_INSTRUMENT_JMPI(bbi->flags))
			cb_loc->type	=	CALLBACK_TYPE_JMPI;

		this->CallbacksList.push_back(cb_loc);



#if DI_DEBUG_IT == 1
		flog("%s: callback RVA=%08x\n",
			__FUNCTION__,
			cb_loc->rva_addr);
#endif

	}

	return D_OK;
}



/*
* Modifies PE file. And puts the integrated data to the last section.
*/

void DIntegrate::dump_integrate_file(char *file)
{

	BOOL							st;
	HANDLE							hFile;
	type_flags						*flags;
	ulong32							correct_size;
	ulong32							FileSize, BytesRead;
	uchar							*temp_data, *mem;
	PIMAGE_SECTION_HEADER			pSHc;

	PIMAGE_DOS_HEADER				pMZ;
	PIMAGE_NT_HEADERS				pPE;
	PIMAGE_SECTION_HEADER			pSH;


	
	hFile		=	CreateFile(	file,
								GENERIC_READ|GENERIC_WRITE, 
								FILE_SHARE_READ, 
								NULL, 
								OPEN_EXISTING, 
								FILE_ATTRIBUTE_NORMAL, 
								NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		flog("%s: unable to open file, error = %d\n", __FUNCTION__, GetLastError());

	}

	assert(hFile != INVALID_HANDLE_VALUE);

	// get the file size now
	FileSize	=	GetFileSize(hFile, NULL);
	assert(FileSize);
	

	// alloc some mem and load the file contents

#define MAX_MEM	(FileSize*5)
	temp_data	=	new uchar[MAX_MEM];
	assert(temp_data);
	memset((void*)temp_data, 0, MAX_MEM);
	st			=	ReadFile(hFile, temp_data, FileSize, (LPDWORD)&BytesRead, NULL);
	assert(st == TRUE);
#undef MAX_MEM


	// now align everything just like it should be in the memory (PE loader style)
	pMZ				=	(PIMAGE_DOS_HEADER)temp_data;
	pPE				=	(PIMAGE_NT_HEADERS) ((ulong32)temp_data + pMZ->e_lfanew);
	pSH				=	(PIMAGE_SECTION_HEADER)((ulong32)temp_data + pMZ->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	

	// get to the last section
	pSHc			=	&pSH[pPE->FileHeader.NumberOfSections-1];
	//pSHc->Characteristics	|= IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE;
	//pSHc->Characteristics	&= ~IMAGE_SCN_MEM_DISCARDABLE;

	pSHc->Characteristics	=	0x68000020;

	// check if this is the section with relocs
	ulong32			reloc_sec_rva	=	pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	assert(pSHc->VirtualAddress == reloc_sec_rva);

	if (pSHc->VirtualAddress != reloc_sec_rva)
	{
		flog("%s: error: lastSectionRVA=%08x != relocSectionVA=%08x\n",
			__FUNCTION__,
			pSHc->VirtualAddress,
			reloc_sec_rva);

		delete []temp_data;
		CloseHandle(hFile);
		return;
	}

	uchar	*p		=	temp_data;
	

	generate_org_relocs(reloc_sec_rva);		// changed
	ulong32			org_relocs_size	=	this->computed_org_relocs_size;	//this->get_org_relocs_size(reloc_sec_rva);
	pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size	= org_relocs_size;
	memcpy((void*)&p[pSHc->PointerToRawData], this->computed_org_relocs, this->computed_org_relocs_size);
	delete []this->computed_org_relocs;


#if DI_DEBUG_IT == 1
	flog("%s: Reloc start = %08x LastRelocRAW = %08x\n", 
		__FUNCTION__,
		pSHc->VirtualAddress, 
		org_relocs_size + pSHc->PointerToRawData);
#endif



	// time to write our relocs
	ulong32 new_relocRVA	=	pSHc->VirtualAddress + org_relocs_size;
	this->generate_relocs(new_relocRVA);
	pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size += 
		(this->computed_relocs_size - this->computed_relocs_align_size);

#if DI_DEBUG_IT == 1
	flog("%s: Writting relocs size=%d bytes to RAWOFFSET=%08x, endRelocRVA=%08x (align=%d)\n",
		__FUNCTION__,
		this->computed_relocs_size,
		pSHc->PointerToRawData + org_relocs_size,
		pSHc->VirtualAddress + pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size,
		this->computed_relocs_align_size);
#endif


	// now write the data
	memcpy((void*)&p[pSHc->PointerToRawData + org_relocs_size], this->computed_relocs, this->computed_relocs_size);
	delete []this->computed_relocs;

	// now write the callbacks
	ulong32			written_size		=	this->computed_relocs_size;
	ulong32			start_raw			=	pSHc->PointerToRawData + org_relocs_size + written_size;

	memcpy((void*)&p[start_raw], this->callback_mem, this->callback_mem_size);
	delete []this->callback_mem;
	written_size	+=	this->callback_mem_size;
	//start_raw		+=	this->callback_mem_size;

	ulong32			new_org_filesize	=	pSHc->PointerToRawData + org_relocs_size;
	ulong32			new_code_baseRVA	=	pSHc->VirtualAddress + org_relocs_size + written_size - this->callback_mem_size;


#if DI_DEBUG_IT == 1
	flog("%s: CALLBACKs END_FULLRVA	=	%08x\n",
		__FUNCTION__, new_code_baseRVA);
	memset((void*)&p[start_raw+this->callback_mem_size], 0xCC, 10);
	uchar *kapa = &p[start_raw+this->callback_mem_size] + 2;
#endif

	ulong32			last_func_rva		=	0;
	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	= this->DA->FunctionList[i];


//		written_size		= func->BBIList->front()->rva_new - last_func_rva;
		last_func_rva		= func->BBIList->front()->rva_new;

		int list_size = func->BBIList->size();
		for (int i = 0; i < list_size; i++)
		{
			
			_bb_iext		*bbi		=	(*func->BBIList)[i];
			_dbasicblock	*bb			=	(_dbasicblock*)bbi->bb_org;

	
#if DEBUG_INSTRUMENTATION == 1
			if (daIS_F_BB_EXT_DEBUG_FIX(bbi->flags))
			{
				_instr_iext *iext	= bbi->InstrIExtList->front();
//#define DBG_PRINT_RVA 0x1000
				*(ulong32*)&iext->data[iext->data_size - sizeof(ulong32) - I_POPAD_LEN - 2] =
					DBG_PRINT_RVA - ((bbi->rva_new + new_code_baseRVA) + (iext->data_size - I_POPAD_LEN - 2));

			}
#endif


			ulong32			ioff				=	0;
			int				instr_list_size		=	bbi->InstrIExtList->size();
			_instr_iext		*iext_last			=	bbi->InstrIExtList->back();

			for (int k = 0; k < instr_list_size; k++)
			{
				_instr_iext *iext	= (*bbi->InstrIExtList)[k];
//				bp(iext->di_org->rva_addr, 0x00001392);



#if DEBUG_FIX == 1
				//ulong32 iRVA	=	new_code_baseRVA + bbi->rva_new+ioff;
				//this->debug_fix_func(func, bbi, iext, iRVA);
#endif

#if DI_DEBUG_IT == 1
				
			//	flog("%s: Emitting oldInstruction=%08x to %08x RAW=%08x\n",
			//		__FUNCTION__,
			//		iext->di_org->rva_addr,
			//		new_code_baseRVA + bbi->rva_new+ioff,
			//		start_raw+bbi->rva_new+ioff
			//		);
					
#endif

				// added: 16.04.2011
				if ((iext == iext_last) && daIS_F_BB_EXT_RESTORECALL(bbi->flags))
					this->restore_call(func, bbi, iext, new_code_baseRVA + bbi->rva_new+ioff);

				memcpy((void*)&p[start_raw+bbi->rva_new+ioff], iext->data, iext->data_size);
				written_size		+= iext->data_size;
				ioff				+= iext->data_size;
			}
		}
	}


	written_size			+=	this->total_align_size;

	// update the reloc section header

	int virtual_sec_size	=	org_relocs_size	+ written_size;
	virtual_sec_size		=	align(virtual_sec_size, pPE->OptionalHeader.SectionAlignment);
	int raw_sec_size		=	org_relocs_size	+ written_size;
	raw_sec_size			=	align(raw_sec_size, pPE->OptionalHeader.FileAlignment);

	pSHc->SizeOfRawData		=	raw_sec_size;
	pSHc->Misc.VirtualSize	=	virtual_sec_size;

	pPE->OptionalHeader.SizeOfImage = align(pSHc->VirtualAddress + pSHc->Misc.VirtualSize, 
		pPE->OptionalHeader.SectionAlignment);

	ulong32 debug_size		=	new_org_filesize + written_size;
	new_org_filesize		=	align(new_org_filesize + written_size, pPE->OptionalHeader.FileAlignment);

#if DI_DEBUG_IT == 1
	flog("%s: dumping %d bytes, added bytes %d \n", __FUNCTION__, new_org_filesize, written_size);
	flog("%s: new code dumped at RVA=%08x VA=%08x\n", 
		__FUNCTION__,
		pSHc->VirtualAddress + org_relocs_size + this->computed_relocs_size,
		this->DA->orva2va(pSHc->VirtualAddress + org_relocs_size + this->computed_relocs_size));
	flog("%s: size=%d bytes (before align=%d bytes)\n",
		__FUNCTION__,
		new_org_filesize,
		debug_size);


#endif


	// time to hook (redirect) original functions & calls
	// order is important here: first hook_calls then hook_functions
	// (only if hardcore hook function mode is enabled)


#if DI_HOOK_ALL	== 1
	//this->hook_calls(temp_data, new_code_baseRVA);
	this->hook_functions(temp_data, new_code_baseRVA);
#endif

	pPE->OptionalHeader.CheckSum	=	NULL;



	// write to the file
	_llseek((HFILE)hFile, 0, SEEK_SET);
	SetEndOfFile(hFile);
	_lwrite((HFILE)hFile, (LPCCH)temp_data, new_org_filesize);
	CloseHandle(hFile);


	// now compute the checksum (this is a bit overkill)
	pPE->OptionalHeader.CheckSum	=	this->compute_checksum(file);
	
	HFILE hF	=	_lopen(file, OF_READWRITE);
	assert(hF != HFILE_ERROR);
	ulong32 peh_offset = (ulong32)pPE - (ulong32)pMZ;
	_llseek(hF, peh_offset, SEEK_SET);
	_lwrite(hF, (LPCCH)pPE, sizeof(IMAGE_NT_HEADERS));
	_lclose(hF);




	delete []temp_data;
	
}

/*
* Function computes checksum
*/

ulong32		DIntegrate::compute_checksum(char *file_name)
{
	ulong32 checksum = get_pe_checksum(file_name);

	if (checksum == NULL)
	{
#if DI_DEBUG_IT == 1
		flog("%s: error unable to compute checksum!\n", __FUNCTION__);
#endif
		return 0;
	}

#if DI_DEBUG_IT == 1
		flog("%s: new PE checksum = %08x!\n", __FUNCTION__, checksum);
#endif

	return checksum;
}


/*
* Function allocates buffer for additional relocs, and write
* them to this memory (PE loader style)
*/

uchar		*DIntegrate::generate_relocs(ulong32 new_relocRVA)
{

	if (this->RelocsList.size() == NULL)
	{
#if DI_DEBUG_IT == 1
		flog("%s: nothing in relocs!\n", __FUNCTION__);
#endif

		this->computed_relocs_size	=	NULL;
		this->computed_relocs		=	NULL;
		return 0;
	}

	// calculate the size for max relocs (should be never bigger)
	ulong32 max_r_size		=	this->RelocsList.size() * sizeof(ulong32) + 16;

	this->computed_relocs	=	new uchar[max_r_size];
	assert(computed_relocs);
	memset((void*)this->computed_relocs, 0, max_r_size);


	// ok we are ready to go
	sort(this->RelocsList.begin(), this->RelocsList.end());


	int						num_of_blocks	=	0;
	ulong32					base_rva		=	this->RelocsList.front() & 0xFFFFFFF0;
	PIMAGE_BASE_RELOCATION	reloc_header	=	(PIMAGE_BASE_RELOCATION)this->computed_relocs;
	reloc_header->VirtualAddress			=	base_rva;
	reloc_header->SizeOfBlock				=	0;	
	uword *entry					=	(uword*)(this->computed_relocs + sizeof(IMAGE_BASE_RELOCATION));

#define I_RELOC_MAX_ENTRIES			((0xFFFF - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD))

	for (int i = 0; i < this->RelocsList.size(); i++)
	{
		ulong32		entry_rva	=	this->RelocsList[i];
		uword		write_entry	=	0;

		// we need to put another entry
		if (((entry_rva - base_rva) > 0xFFF) || (num_of_blocks > I_RELOC_MAX_ENTRIES))
		{
			// block exceeded need to add new one
#define ABSOLUTE_LOC 0
			*entry				=	ABSOLUTE_LOC;
			entry++;

			base_rva			=	entry_rva & 0xFFFFF000;
			reloc_header->SizeOfBlock		= (ulong32)entry - (ulong32)reloc_header;
			reloc_header		=	(PIMAGE_BASE_RELOCATION)entry;
			reloc_header->VirtualAddress	= base_rva;
			num_of_blocks		=	0;
			entry				=	(uword*)((ulong32)reloc_header + sizeof(IMAGE_BASE_RELOCATION));
		}

#define IMAGE_REL_BASED_HIGHLOWX	0x3000
		/* wpisz dany adres, IMAGE_REL_BASED_HIGHLOW */
		entry[0]					=	(uword)(entry_rva - base_rva) | IMAGE_REL_BASED_HIGHLOWX;
		entry++;
		num_of_blocks++;	
	}


	entry[0]						=	ABSOLUTE_LOC;
	entry++;
	reloc_header->SizeOfBlock		=	(ulong32)entry - (ulong32)reloc_header;
	this->computed_relocs_size		=	(ulong32)entry	- (ulong32)this->computed_relocs;// + sizeof(IMAGE_BASE_RELOCATION);
	this->computed_relocs_align_size = align(this->computed_relocs_size + sizeof(IMAGE_BASE_RELOCATION), FUNC_ALIGN) - this->computed_relocs_size ;
	this->computed_relocs_size		+= 	this->computed_relocs_align_size;
	

	// now we need to repair the base addresses
	// we are assuming the code will be emitted directly after the relocs
	ulong32	new_code_baseRVA		=	new_relocRVA + this->computed_relocs_size;
	reloc_header					=	(PIMAGE_BASE_RELOCATION)this->computed_relocs;
	while (reloc_header->SizeOfBlock != 0)
	{
	
		reloc_header->VirtualAddress	+=	new_code_baseRVA;
		reloc_header = (PIMAGE_BASE_RELOCATION)((DWORD)reloc_header + (DWORD)reloc_header->SizeOfBlock);
		
	}



	return this->computed_relocs;
}



/*
* Function gets original relocs size.
*/

ulong32		DIntegrate::get_org_relocs_size(ulong32 reloc_section_rva)
{

	PIMAGE_BASE_RELOCATION	reloc_header = (PIMAGE_BASE_RELOCATION)this->DA->lrva2va(reloc_section_rva);
	PIMAGE_BASE_RELOCATION	pRE = reloc_header;

	// travel though original relocs
	while (pRE->SizeOfBlock != 0)
		pRE = (PIMAGE_BASE_RELOCATION)((DWORD)pRE + (DWORD)pRE->SizeOfBlock);

	return (ulong32)pRE - (ulong32)reloc_header;
}


/*
* Function filters and write down to allocated memory original relocs.
* The filtering procedure is a must if we want to store the file.
* So we must be sure that func_start bytes {0-5} are free of relocations. 
* Because they will corrupt our jmp patch.
*/

uchar		*DIntegrate::generate_org_relocs(ulong32 reloc_section_rva)
{
	type_RelocsList			OrgRelocsList;
	ulong32 org_relocs_size	=	this->get_org_relocs_size(reloc_section_rva);

	// allocate some memory
	this->computed_org_relocs	=	new uchar[org_relocs_size*2];
	assert(computed_org_relocs);
	memset((void*)this->computed_org_relocs, 0, org_relocs_size);


	OrgRelocsList.clear();
	
	// now parse the relocs and write them down
	PIMAGE_BASE_RELOCATION	pRE = (PIMAGE_BASE_RELOCATION)this->DA->lrva2va(reloc_section_rva);
	#define reloc_members_num(x)		((x - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD))


	int		collisions = 0;
	while (pRE->SizeOfBlock != 0)
	{
		WORD			relocType;
		PWORD			pEntry;
		int				entries		= reloc_members_num(pRE->SizeOfBlock);
		
		pEntry = (PWORD)((DWORD)pRE + (DWORD)sizeof(IMAGE_BASE_RELOCATION));

		for (int i=0; i < entries; i++ )
		{
			ulong32		addr = (DWORD)((*pEntry & 0x0FFF) + pRE->VirtualAddress);
			relocType		 = (*pEntry & 0xF000) >> 12;		// najwyzsze 4 bity to typ

			
			
			if (relocType == IMAGE_REL_BASED_HIGHLOW)
			{
				// add it only if it isnt colliding

				
#if DI_HOOK_ALL	== 1

				if (!this->is_bad_reloc_addr(addr))
				{
					OrgRelocsList.push_back(addr);
				}
				else
					collisions++;
#else
				OrgRelocsList.push_back(addr);
#endif
			}
			pEntry++;
		}
		
		pRE = (PIMAGE_BASE_RELOCATION)((DWORD)pRE + (DWORD)pRE->SizeOfBlock);
	}

#if DI_DEBUG_IT == 1
	flog("%s: found %d original relocs! (collisions=%d)\n",
		__FUNCTION__, 
		OrgRelocsList.size(),
		collisions);
#endif


	// ok now lets write them down
	sort(OrgRelocsList.begin(), OrgRelocsList.end());


	int						num_of_blocks	=	0;
	ulong32					base_rva		=	OrgRelocsList.front() & 0xFFFFFFF0;
	PIMAGE_BASE_RELOCATION	reloc_header	=	(PIMAGE_BASE_RELOCATION)this->computed_org_relocs;
	reloc_header->VirtualAddress			=	base_rva;
	reloc_header->SizeOfBlock				=	0;	
	uword *entry							=	(uword*)(this->computed_org_relocs + sizeof(IMAGE_BASE_RELOCATION));


	for (int i = 0; i < OrgRelocsList.size(); i++)
	{
		ulong32		entry_rva	=	OrgRelocsList[i];
		uword		write_entry	=	0;

		// we need to put another entry
		if (((entry_rva - base_rva) > 0xFFF) || (num_of_blocks > I_RELOC_MAX_ENTRIES))
		{
			// block exceeded need to add new one
#define ABSOLUTE_LOC 0
			*entry				=	ABSOLUTE_LOC;
			entry++;

			base_rva			=	entry_rva & 0xFFFFF000;
			reloc_header->SizeOfBlock		= (ulong32)entry - (ulong32)reloc_header;
			reloc_header		=	(PIMAGE_BASE_RELOCATION)entry;
			reloc_header->VirtualAddress	= base_rva;
			num_of_blocks		=	0;
			entry				=	(uword*)((ulong32)reloc_header + sizeof(IMAGE_BASE_RELOCATION));
		}

#define IMAGE_REL_BASED_HIGHLOWX	0x3000
		/* wpisz dany adres, IMAGE_REL_BASED_HIGHLOW */
		entry[0]					=	(uword)(entry_rva - base_rva) | IMAGE_REL_BASED_HIGHLOWX;
		entry++;
		num_of_blocks++;	
	}


	entry[0]						=	ABSOLUTE_LOC;
	entry++;
	reloc_header->SizeOfBlock		=	(ulong32)entry - (ulong32)reloc_header;
	this->computed_org_relocs_size		=	(ulong32)entry	- (ulong32)this->computed_org_relocs; // + sizeof(IMAGE_BASE_RELOCATION);
	
	OrgRelocsList.clear();
	return this->computed_org_relocs;

}


/*
* Function checks if the reloc rva is located somewhere between 
* first 5 bytes of a function.
*/

BOOL DIntegrate::is_bad_reloc_addr(ulong32 reloc_rva)
{
	type_flags	*flags	=	this->DA->BinData.flags;

	
	

	for (ulong32 rva = (reloc_rva - PATCH_SIZE); rva != reloc_rva; rva++)
	{

#define is_func(f)	(f & (DA_FLAG_FUNCTION_START|DA_FLAG_ANALYZED|DA_FLAG_INSTR))


		if (is_func(flags[rva]))
		{

			// firstly check if this function was hooked
			_dfunction	*func	=	this->DA->find_function_by_rva(rva);
			if (!func)
				continue;

			_bb_iext	*bbi	=	func->BBIList->front();
			if (!daIS_F_BB_EXT_HOOKABLE(bbi->flags))
			{
#if DI_DEBUG_IT == 1
				flog("found function at %08x but it was not hooked! continuing!\n",
					rva);
#endif
				continue;
			}


			// ok now get the function first basicblock 
			_dinstr		 *di	=	this->DA->get_dinstr_from_rva(rva);
			_dbasicblock *bb	=	this->DA->find_basicblock(rva);
			if (!di || !bb)
				continue;


			// function will be patched by jump, so now make sure
			// the reloc will not overwrite the jump offset

			if ((bb->rva_start <= reloc_rva) && ((bb->rva_start + PATCH_SIZE) > reloc_rva))
			{
#if DI_DEBUG_IT == 1
				flog("%s: reloc_rva = %08x collides with function hook %08x\n",
					__FUNCTION__,
					reloc_rva,
					rva);
#endif
				return TRUE;
			}
		}

	}	

	return FALSE;
}


/*
* Functions hooks all original functions and point them to the relocated ones
*/

int	DIntegrate::hook_functions(uchar *file_data, ulong32 new_code_baseRVA)
{

	type_flags	*flags	=	this->DA->BinData.flags;

#if DI_DEBUG_IT == 1
	int	not_hookable = 0;
	int	hookable = 0;
#endif

	// hook every function
	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	= this->DA->FunctionList[i];
		_dbasicblock *bb	= func->bb_start;
		_bb_iext	*bbi	=	func->BBIList->front();

		// get the raw offset
		ulong32 bb_raw		= this->DA->orva2raw(bb->rva_start);


		flog("%s: processing function %08x \n", __FUNCTION__, bb->rva_start);
//		bp(bb->rva_start, 0x003F2910);
		
		if (!daIS_F_BB_EXT_HOOKABLE(bbi->flags))
		{
#if DI_DEBUG_IT == 1
			flog("%s: function=%08x is not hookable!\n", __FUNCTION__, bb->rva_start);
			not_hookable++;
#endif
			continue;
		}


		if (bb_raw == -1)
		{
			// wtf ? 
			flog("%s: unable to find raw offset for %08x\n",
				__FUNCTION__,
				bb->rva_start);
			assert(0);	

			continue;
		}



		// calculate basicblock size
		_dinstr	*di		=	this->DA->get_dinstr_from_rva(bb->rva_end);
		assert(di);
		ulong32 bb_size = (bb->rva_end - bb->rva_start) + di->len;

	
		// get the destination rva
		ulong32 dest_rva	=	bbi->rva_new +  new_code_baseRVA;
		int		prospect	=	(daIS_F_PROSPECT(flags[bb->rva_start]) == 0? 0:1);
		int		num_of_bb	=	func->BBIList->size();

#if DI_ANTIROP == 1
		// debug only 02.11.2011 -> for antirop
		this->EraseFunction(file_data, func);
		// end debug
#endif


#if DI_DEBUG_IT == 1
		flog("%s: redirtecting RVA=%08x (RAW=%08x) to %08x (numOfBB=%d PROSPECT=%d)\n",
			__FUNCTION__,
			bb->rva_start,
			bb_raw,
			dest_rva,
			num_of_bb,
			prospect);
		
		hookable++;
#endif

		// ok we have the raw offset so lets patch it
		sp_asmINSTR_LONG_JMP(&file_data[bb_raw]);
		*(ulong32*)&file_data[bb_raw+1]	=	dest_rva - bb->rva_start - PATCH_SIZE;
	}


#if DI_DEBUG_IT == 1
	flog("%s: FUNCTIONS HOOKED=%d NOTHOOKED=%d\n",
		__FUNCTION__, hookable, not_hookable);
#endif

	return D_OK;
}





/*
*
* Function hooks all valid call rel (len=5). Where dest is a function
* that was mirrored. Those call are changed to jmp rel (len=5) to 
* mirror location.
*/

int			DIntegrate::hook_calls(uchar *file_data, ulong32 new_code_baseRVA)
{

	type_DICollisions		CallRelCollisionsList;	// calls patched multiple times
	CallRelCollisionsList.clear();
	


	for (int i = 0; i < CallRelList.size(); i++)
	{
		// CallRelList is filled while the instrumentation is done
		// each entry is a bbi which ends with call
		_bb_iext		*bbi	=	CallRelList[i];
		_instr_iext		*iext	=	bbi->InstrIExtList->back();


		ulong32			dest_rva	=	bbi->rva_new +  new_code_baseRVA + bbi->size - iext->data_size;
		ulong32			i_org_rva	=	iext->di_org->rva_addr;
		ulong32			i_org_raw	=	this->DA->orva2raw(i_org_rva);
//		assert(file_data[i_org_raw] == 0xE8);	// make sure it was not patched already

		if (file_data[i_org_raw] == 0xE9)
		{
#if DI_DEBUG_IT == 1
			ulong32 dest_offset = *(ulong32*)&file_data[i_org_raw+1] + i_org_rva + PATCH_SIZE;
			flog("%s: instrRVA=%08x already hooked to %08x (now wanted=%08x)\n",
				__FUNCTION__,
				i_org_rva,
				dest_offset,
				dest_rva);
#endif

			CallRelCollisionsList.push_back(iext->di_org);
			continue;
		}

		sp_asmINSTR_LONG_JMP(&file_data[i_org_raw]);
		*(ulong32*)&file_data[i_org_raw+1]	=	dest_rva - i_org_rva - PATCH_SIZE;
	
	}


	

	// we cant allow multiple hooks (so restore all multiple ones)
	for (int i = 0; i < CallRelCollisionsList.size(); i++)
	{
		_dinstr			*di			=	CallRelCollisionsList[i];
		ulong32			i_org_raw	=	this->DA->orva2raw(di->rva_addr);
		memcpy((void*)&file_data[i_org_raw], (void*)di->data, di->len);

#if DI_DEBUG_IT == 1
		flog("%s: restoring hooks at orgRVA=%08x\n",
			__FUNCTION__,
			di->rva_addr);
#endif
	}


	return D_OK;


	/*
	type_flags	*flags	=	this->DA->BinData.flags;
	// scan all the memory
	for (ulong32 rva = NULL; rva < this->DA->BinData.data_size; rva++)
	{
		// check if this is a call 
		if (daIS_F_HEAD(flags[rva]) && daIS_F_INSTR_CALL(flags[rva]))
		{
			_dinstr	*di	=	this->DA->get_dinstr_from_rva(rva);
			assert(di);

			// not a call REL5
			if (di->emul_int != CALL_0)
				continue;

			// get the raw offset
			ulong32 di_raw		= this->DA->orva2raw(rva);
		
			// ok we have the raw offset so lets patch it
			sp_asmINSTR_LONG_JMP(&file_data[di_raw]);
			*(ulong32*)&file_data[di_raw+1]	=	dest_rva - rva - PATCH_SIZE;
		}

	}
*/

	return D_OK;
}

/*
* Function checks if function is suitable for hardcore patching.
* At this point first basicblock of the function is too short 
* for patching. So we will check if there is enough place
* at the rest of the function.
*
* UPDATE: dont use it - not safet
*/

BOOL	DIntegrate::is_hardcore_hook_suitable(ulong32 func_rva)
{
	type_flags	*flags	=	this->DA->BinData.flags;

	for (ulong32 rva = func_rva; rva < (func_rva + PATCH_SIZE); rva++)
	{

		if (daIS_F_RELOC_XREF(flags[rva]) || daIS_F_FUNCTION_START(flags[rva]) || 
			daIS_F_IMPORT_DATA(flags[rva]))
		{
#if DI_DEBUG_IT == 1
			flog("%s: function at %08x (byteRVA: %08x) not suitable for hardcore patch!\n",
				__FUNCTION__,
				func_rva,
				rva);
#endif
			return FALSE;
		}


		if (daIS_F_RELOC_DATA(flags[rva]))
		{
#if DI_DEBUG_IT == 1
			flog("%s: function at %08x (byteRVA: %08x) not suitable for hardcore patch (relocs)!\n",
				__FUNCTION__,
				func_rva,
				rva);
#endif
			return FALSE;
		}

	}


	return TRUE;
}


/*
* To avoid potential BSODs skip the init section protection.
* (function located there will be not hooked)
*/

	
void DIntegrate::find_INIT_section(void)
{
	this->init_section_rva_start	=	0;
	this->init_section_rva_end		=	0;


	PIMAGE_SECTION_HEADER			pSHs;

	pSHs = this->DA->pSH; 
	for (int i = 0; i < this->DA->pPE->FileHeader.NumberOfSections; i++)
	{
		if (strcmpi((char*)&pSHs[i].Name, "INIT") == 0)
		{

#if DI_DEBUG_IT == 1
			flog("%s: INIT SECTION FOUND -> START=%08x END=%08x\n",
				__FUNCTION__,
				pSHs[i].VirtualAddress,
				pSHs[i].VirtualAddress + pSHs[i].SizeOfRawData);
#endif

			this->init_section_rva_start	=	pSHs[i].VirtualAddress;
			this->init_section_rva_end		=	pSHs[i].VirtualAddress + pSHs[i].SizeOfRawData;

			break;
		}

	}


}

