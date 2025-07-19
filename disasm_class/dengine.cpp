#include "danalyze.h"

// debugonly
int DAnalyze::debug_find_future_addr(ulong32 rva_addr)
{
	for (type_FutureAddrList::iterator it = FutureAddrList.begin();
		it != FutureAddrList.end(); it++)
	{
		ulong32 rva = *it;
		if (rva_addr == rva)
			return 1;
	}

	return 0;
}

// debug only
void DAnalyze::debug_show_flags_for_rva(ulong32 rva_addr)
{
	type_flags flags;
	flags = this->BinData.flags[rva_addr];

	flog("FLAGS for: %08x (%08x) -> ", rva_addr, orva2va(rva_addr));
#define q(x,y) { if (flags & x) flog(y"|"); }
	q(DA_FLAG_INSTR, "DA_FLAG_INSTR");
	q(DA_FLAG_HEAD, "DA_FLAG_HEAD");
	q(DA_FLAG_TAIL, "DA_FLAG_TAIL");
	q(DA_FLAG_BB_END, "DA_FLAG_BB_END");
	q(DA_FLAG_LABEL, "DA_FLAG_LABEL");
	flog("\r\n");
}



// debug only (libdasm)
#if DA_USE_SQL == 1
int DAnalyze::get_instruction_text(ulong32 rva_addr, char *instr_string)
{
	INSTRUCTION inst;
	ulong32 addr = lrva2va(rva_addr);

	int st = get_instruction(&inst, (unsigned char*)addr, MODE_32);
	if (st)
	{
		get_instruction_string(&inst, FORMAT_INTEL, 0, instr_string, 256);
		return D_OK;
	}
	else
	{
		flog("Unable to disassemble %08x\r\n",
			rva_addr);
		return D_FAILED;

	}
}
#endif


int DAnalyze::debug_show_instruction(ulong32 rva_addr)
{
	char		instr_string[256];
	INSTRUCTION inst;
	ulong32 addr = lrva2va(rva_addr);

	int st = get_instruction(&inst, (unsigned char*)addr, MODE_32);
	if (st)
	{
		get_instruction_string(&inst, FORMAT_INTEL, 0, instr_string, sizeof(instr_string));
		flog("%08x %s\r\n",
			rva_addr,
			instr_string);
	}
	else
	{
		flog("Unable to disassemble %08x\r\n",
			rva_addr);

	}

	return inst.length;
}



int DAnalyze::debug_show_instruction_from_data(uchar *data)
{
	char		instr_string[256];
	INSTRUCTION inst;
	
	int st = get_instruction(&inst, (unsigned char*)data, MODE_32);
	if (st)
	{
		get_instruction_string(&inst, FORMAT_INTEL, 0, instr_string, sizeof(instr_string));
		flog("%08x %s\r\n",
			data,
			instr_string);
	}
	else
	{
		flog("Unable to disassemble %08x\r\n",
			data);

	}

	return inst.length;
}



/*
* Function analyzes mem operand of instruction
* If the MEM_IMM is out of range:
* - MEM_IMM > (imagebase+imagesize)
* - MEM_IMM < (imagebase) && MEM_IMM > (imagesize)
* - 
* -> This technique generates large number of false
* postives since following instructions are found
* in the valid code, for example:
* win32k: 001125d3 (bf9125d3) test byte [07ffe02d0h],010h
* win32k: 000de1fc (bf8de1fc) lea eax,[ecx-01000001h]
*
* So lets try something different:
* If there is a reloc flag at the end of instruction
* and the instruction itself is not using MEM_IMM or IMM32 data
* then something is wrong.
*/

inline BOOL	DAnalyze::is_mem_operand_in_range(ulong32 rva, _dis_data *dd)
{
	type_flags		*flags = this->BinData.flags;

	if (daIS_F_RELOC_DATA(flags[rva+dd->len]))
	{
		if (dd->mem_imm || dd->imm_data)
		{
			return TRUE;
		}
		else
		{

				// seems like invalid instruction (data covered as code) so stop the stream
#if DA_DEBUG_IT == 1
					flog("*** is_mem_operand_in_range(): %08x (%08x) -> invalid MEM_IMM operand\r\n",
						rva,
						orva2va(rva));
#endif
			return FALSE;
		}
	}

	
	return TRUE;

	/*
	if (dd->mem_imm)
	{
		// negative one
		if ((int)(dd->mem_imm) < 0)
		{
			if (~dd->mem_imm < this->o_imagesize)
				return TRUE;
		}


		if ((dd->mem_imm > (this->o_imagebase + this->o_imagesize)))
			return FALSE;

		// nobody uses structs bigger than imagesize right ? 
		if ((dd->mem_imm < this->o_imagebase) && (dd->mem_imm > this->o_imagesize))
			return FALSE;
	}
	*/

	return TRUE;
}


/*
* Function is executed when disassembler finds out it started
* disassembling DATA instead of CODE. So in order to make things more
* clean we need to delete all the instructions that are not instruction (data).
* And also update the region flags. 
* Algo:
* Travel backwards and find the F_LABEL flag. Assume everything
* is data between the LABEL and the RVA. Update the InstrList.
* + update just delete all instructions fro the InstrBlock
*/

int	DAnalyze::remove_bad_area(type_InstrList	*InstrBlock)
{
	_dinstr			*di;
	type_flags		*flags = this->BinData.flags;



#if DA_DEBUG_IT == 1
	flog("*** remove_bad_area(): removing %d instructions!\n",
		InstrBlock->size());
#endif

	for (int i = 0; i < InstrBlock->size(); i++)
	{
		di = (*InstrBlock)[i];


#if DA_DEBUG_IT == 1
		flog("*** remove_bad_area(): removing %d instruction at %08x!\n",
			i,
			di->rva_addr);
#endif


		this->BinData.fast_instrs[di->rva_addr] = 0;
		flags[di->rva_addr]		=	(flags[di->rva_addr] & ~(DA_FLAG_INSTR|DA_FLAG_ANALYZED|DA_FLAG_HEAD|DA_FLAG_TAIL));
		delete di;
	}

	InstrBlock->clear();
	return D_OK;



/*
	ulong32			rva_end = rva;	

	// travel backwards
	rva++;
	do 
	{		
		// check if this is an API like KeBugCheckEx or it is a valid call (like in ntoskrnl)
		// if so dont delete it
		// INIT:001F4D94                 call    _KeBugCheck@4   ; KeBugCheck(x)
		// INIT:001F4D99                 int     3               ; Trap to Debugger
		// INIT:001F4D99 ; ---------------------------------------------------------------------------
		// INIT:001F4D9A ; char asc_1F4D9A

		if (daIS_F_INSTR_USES_IMPORTED_API(flags[rva-1]) ||
			daIS_F_INSTR_CALL(flags[rva-1]))

		{

#if DA_DEBUG_IT == 1
			flog("*** remove_bad_area(): instr at: %08x (%08x) uses importedAPI/procedure so stopping here!\n",
				rva-1,
				orva2va(rva-1));
#endif
			di	=	this->get_dinstr_from_rva(rva-1);
			assert(di);
			rva	=	rva + di->len;
			break;
		}

		rva--;
		// update the flags
		daSET_F_DATA(&flags[rva]);
	} while (!daIS_F_LABEL(flags[rva]));
	


#if DA_DEBUG_IT == 1
		flog("*** remove_bad_area(): removing instruction at: from %08x (%08x) to %08x (%08x)\r\n",
			rva,
			orva2va(rva),
			rva_end,
			orva2va(rva_end));
#endif

	// if start == end then do nothing
	if (rva == rva_end)
		return D_OK;


	// debug
	return D_OK;
	//debug

	// delete from the instruction list
	while (1)
	{
		if (this->InstrList.empty())
			break;

		di = this->InstrList.back();
		this->InstrList.pop_back();

#if DA_DEBUG_IT == 1
		flog("*** remove_bad_area(): removing instruction at: %08x (%08x)\r\n",
			di->rva_addr,
			orva2va(di->rva_addr));
#endif

		//bp(rva,0x000025AF);
		if (di->rva_addr == rva)
		{
			delete []di;
			break;
		}

		if (di->rva_addr < rva)
			break;


		// free memory
		delete []di;

	};
*/

	return D_OK;
}

/*
* This function is only executed when jmp [mem] or call [mem] is found!
* Also it must be executed after check_operands_and_set_flags function.
* Functions checks if the [mem] is filled with RELOCABLE_OFFSETs (VTABLE)
* If VTABLE is found the instruction linked_instr changes to rva of the vtable
*/


BOOL DAnalyze::add_vtable_entries(ulong32 mem_rva, BOOL strict_mode)
{
	int				entries = 0;
	type_flags		*flags	= this->BinData.flags;
	uchar			*data	= this->BinData.data;



	if (!daIS_F_RELOC_DATA(flags[mem_rva]))
		return FALSE;

	// now check if next field +4/-4 contains relocable offset
	if ((daIS_F_RELOC_DATA(flags[mem_rva+sizeof(ulong32)]) ||		\
		daIS_F_RELOC_DATA(flags[mem_rva-sizeof(ulong32)])))
	{

			// scan entire VTABLE and mark all the suitable locations
			// as code! (to disassemble)

			ulong32 vtable_entry_rva = mem_rva;
			while (1)
			{
				// no more entries
				if (!daIS_F_RELOC_DATA(flags[vtable_entry_rva]))// || !daIS_F_HEAD(flags[vtable_entry_rva]))
					break;

				ulong32 entry_dest_rva	=	ova2rva(*(ulong32*)&data[vtable_entry_rva]);
				if (this->is_addr_in_range(entry_dest_rva))
				{
					if (strict_mode)
					{
						if (!this->is_prologue(entry_dest_rva, FALSE))
						{
							vtable_entry_rva += sizeof(ulong32);
							continue;
						}

						this->set_future_addr(entry_dest_rva);
						daSET_F_LABEL(&flags[entry_dest_rva]);
						entries++;
					}
					else
					{
						// not strict mode so add as a prospect
						this->set_future_addr_prospect(entry_dest_rva);
						entries++;
					}



#if DA_DEBUG_IT == 1
					flog("VTABLE ENTRY at %08x -> %08x\n",
						vtable_entry_rva,
						entry_dest_rva);
#endif
				}
				vtable_entry_rva += sizeof(ulong32);
			};

			
			return entries;
	}


	return FALSE;
}


void DAnalyze::check_for_vtable(_dinstr *di, _dis_data *dd)
{
	ulong32			irva = di->rva_addr;
	type_flags		*flags	= this->BinData.flags;
	uchar			*data	= this->BinData.data;

//	bp(di->rva_addr, 0x00001004);


	// no memory registers no vtable!
	if (!dd->sib_mul_reg)
		return;

	// also check if there is correct offset in the mem_imm
	if (!daIS_F_INSTR_RELOCABLE_DATA_IN_MEMIMM(flags[irva]))
		return;


	ulong32 mem_rva = ova2rva(dd->mem_imm);
	if (this->add_vtable_entries(mem_rva))
	{
		// if so this is a vtable
		daSET_F_INSTR_USES_VTABLE(&flags[irva]);

		// point the objMEMIMM to the vtable
		di->objMEMIMM_rva	=	mem_rva;

#if DA_DEBUG_IT == 1
			flog("*** Instruction at: %08x (%08x) uses VTABLE=%08x\r\n",
					di->rva_addr,
					orva2va(di->rva_addr),
					orva2va(mem_rva));
#endif
	}
}

/*
* Function checks if instructions is a semantic nop:
* nop, mov edi,edi etc. and writes the flag if necessary
*/

void DAnalyze::check_semantic_nops(_dinstr *di, _dis_data *dd)
{
	// first of all check if we have flags in destination
	// if so this is not a semantic NOP

	if (D_SHOW_FLAGS(dd->obj_dest))
		return;


	// now if the destination == src we have a semantic nop
	// (just limit this one to general registers)
	// if it uses mem it is not SNOP
	// if it uses imm it is not SNOP
	if (((ulong32)dd->i_obj_dest != (ulong32)dd->i_obj_src) ||
		disit_is_DF_USE_MEM(dd->dflags) ||
		disit_isDF_IMM(dd->dflags))
		return;

	// ok this is a semantic nop
	type_flags		*flags = this->BinData.flags;
	daSET_F_INSTR_SEMANTIC_NOP(&flags[di->rva_addr]);


#if DA_DEBUG_IT == 1
			flog("*** Instruction at: %08x (%08x) is a SEMANTICNOP\r\n",
					di->rva_addr,
					orva2va(di->rva_addr));
#endif

}


/*
* Function analyzes operands of instruction, if:
* instr [op],xxx   <-- op is marked as data
* instr xxx,[op]   <-- op is marked as data
*
* Additional checks:
* MEM_IMM	-> is a symbol?
* IMM		-> is a symbol?
* MEM_IMM	-> is a imported api? (USES IMPORTED API)
* MEM_IMM	-> contains relocable data?
* IMM		-> contains relocable data? 
*/

void DAnalyze::check_operands_and_set_flags(_dinstr *di, _dis_data *dd)
{
	int				data_size;
	_sinfo			*SymbolInfo;
	ulong32			irva = di->rva_addr;

	type_flags		*flags = this->BinData.flags;
	

	//bp(irva,0x000BFCC4);




	// lets check the memory operand first
//	if (dd->mem_imm && (disit_getDF_size_MEM_IMM(dd->dflags) == D_SIZE32))
	if ((disit_getDF_size_MEM_IMM(dd->dflags) == D_SIZE32))
	{
		ulong32 mem_rva = ova2rva(dd->mem_imm);
		if (this->is_addr_in_range(mem_rva))
		{
			// mark this field as data to prevent further misunderstandings
			// only if this was WRITE access

			data_size				=	disit_getDF_size_MEM_REQ(dd->dflags);
			di->objMEMIMM_rva		=	mem_rva;
			daSET_F_LABEL(&flags[mem_rva]);

			//added 30.03.2011
			daSET_ACCESSED_AS_DATA_ON_LEN(flags, mem_rva, data_size);

			if (disit_is_DF_MEM_ACTDEST(dd->dflags))
				daSET_DATA_ON_LEN(flags, mem_rva, data_size);

			// now lets check if it contains a symbol
			// flag the symbol if there is any
			SymbolInfo		=	this->Symbols->get_symbol_info(mem_rva);
			if (SymbolInfo)
			{			
				daSET_F_INSTR_SYMBOL_IN_MEMIMM(&flags[irva]);
			

#if DA_DEBUG_IT == 1
			flog("*** Instruction at: %08x (%08x) uses symbol in mem_imm=%08x\r\n",
					di->rva_addr,
					orva2va(di->rva_addr),
					orva2va(mem_rva));
#endif
			}


			// does it contain relocable data?
			ulong32 mem_imm_offset_rva = (ulong32)((ulong32)di->rva_addr + dd->len - disit_getDF_size_IMM(dd->dflags) - sizeof(ulong32));

			// check if at this RVA we have RELOC flags
			if (daIS_F_RELOC_DATA(flags[mem_imm_offset_rva]))
			{
				daSET_F_INSTR_RELOCABLE_DATA_IN_MEMIMM(&flags[irva]);



#if DA_DEBUG_IT == 1
			flog("*** Instruction at: %08x (%08x) has relocable entry in mem_imm=%08x\r\n",
					di->rva_addr,
					orva2va(di->rva_addr),
					orva2va(mem_rva));
#endif

			}

			// lets check if it points to imports
			if (daIS_F_IMPORT_DATA(flags[mem_rva]))
			{
				daSET_F_INSTR_USES_IMPORTED_API(&flags[irva]);

#if DA_DEBUG_IT == 1
			flog("*** Instruction at: %08x (%08x) uses imported api in mem_imm=%08x\r\n",
					di->rva_addr,
					orva2va(di->rva_addr),
					orva2va(mem_rva));
#endif
			}
	

		}	// if is in range
	} // if mem_imm


	// now similiar check for imm
	//if (dd->imm_data && (disit_getDF_size_IMM(dd->dflags) == D_SIZE32))
	if ((disit_getDF_size_IMM(dd->dflags) == D_SIZE32))
	{
		ulong32 imm_rva = ova2rva(dd->imm_data);

		// firstly make sure if there is reloc entry for it 
		// if not dont even try to scan for symbols

		ulong32 imm_offset_rva = (ulong32)((ulong32)di->rva_addr + dd->len - sizeof(ulong32));
		// check if at this RVA we have RELOC flags
		if (daIS_F_RELOC_DATA(flags[imm_offset_rva]))
		{
			daSET_F_INSTR_RELOCABLE_DATA_IN_IMM(&flags[irva]);
			
			// set LABEL flag on the *imm location
			// at this point it is hard to decide if this is data or code
			// so lets stick to the basic assumptions
			daSET_F_LABEL(&flags[imm_rva]);
			di->objIMM_rva	=	imm_rva;


//#ifdef  _EXTRA_OPERAND_CHECK
			// if this imm is used by instruction that is not MOV/PUSH IMM
			// mark this as not hookable
			// added 30.03.2011
			if ((di->emul_int != MOV_4) && (di->emul_int != MOV_5) 
				&& (di->emul_int != MOV_6) && (di->emul_int != MOV_7) &&
				(di->emul_int != PUSH_3) && (di->emul_int != CMP_4) && (di->emul_int != CMP_5))
			{
				daSET_ACCESSED_AS_DATA_ON_LEN(flags, imm_rva, sizeof(uchar));

				/*
				flog("KAPENCJA: DIrva=%08x OBJECTRVA=%08x\n",
					di->rva_addr,
					imm_rva);
					*/
			}

//#endif

			// if imm points to not executable area this is data for sure
			// just its size if unknown (so assume 1 byte for now)
			if (!daIS_F_EXECUTABLE_AREA(flags[imm_rva]))
			{
				daSET_DATA_ON_LEN(flags, imm_rva, sizeof(uchar));
#if DA_DEBUG_IT == 1
			flog("*** Using imm=%08x -> marked as data (stored in no-exec area)\r\n",
					orva2va(imm_rva));
#endif			


			}

#if DA_DEBUG_IT == 1
			flog("*** Instruction at: %08x (%08x) has relocable entry in imm=%08x\r\n",
					di->rva_addr,
					orva2va(di->rva_addr),
					orva2va(imm_rva));
#endif


			// now check for symbols (since we have relocs)
			SymbolInfo		=	this->Symbols->get_symbol_info(imm_rva);
			if (SymbolInfo)
			{			
				daSET_F_INSTR_SYMBOL_IN_IMM(&flags[irva]);
			
#if DA_DEBUG_IT == 1
			flog("*** Instruction at: %08x (%08x) uses symbol in imm=%08x\r\n",
					di->rva_addr,
					orva2va(di->rva_addr),
					orva2va(imm_rva));
#endif
			}

		}

	}
}


/*
* Function gets dinstr ptr from rva
*/

/*
_dinstr* DAnalyze::get_dinstr_from_rva(ulong32 rva_addr)
{
	return this->BinData.fast_instrs[rva_addr];
}
*/

/*
* Function creates and fills new dinstr structure
* It also sets specified flags. It also adds it to InstrList
* Additionally the offset is written to dinstr_ptrs.
*/

_dinstr* DAnalyze::new_dinstr(ulong32 rva_addr, uchar *data_ptr, int8 len, int emul_int)
{
	type_flags		*flags = this->BinData.flags;

	_dinstr *di = new _dinstr;
	assert(di);
	memset((void*)di,0,sizeof(_dinstr));


	di->data		=	data_ptr;
	di->rva_addr	=	rva_addr;
	di->len			=	len;
	di->emul_int	=	emul_int;
	this->InstrList.push_back(di);

	daSET_INSTR_ON_LEN(flags, rva_addr, len);


	// and write the offset to the resolve table
	this->BinData.fast_instrs[rva_addr] = di;

	return di;
}



/*
* Function adds following rva to future addr list 
* and marks it as FUNCTION_START + LABEL flag
*/

void DAnalyze::set_future_addr_function(ulong32 rva_addr, bool validate)
{
	type_flags	*flags;

	if (validate)
		if (!this->is_addr_in_range(rva_addr))
			return;

#if DA_DEBUG_IT == 1
			flog("*** New Function at: %08x (%08x)\r\n",
					rva_addr,
					orva2va(rva_addr));
#endif


	flags		=	this->BinData.flags;
	this->set_future_addr(rva_addr);
	daSET_F_FUNCTION_START(&flags[rva_addr]);
	daSET_F_LABEL(&flags[rva_addr]);

}

/*
* Function performs the entire disassembly
*/

int DAnalyze::engine_run(void)
{
	int			st;
	_dis_data	dd;
	uchar		*mem, *p;
	type_flags	*flags;
	type_addr	ret_addr;
	ulong32		rva_addr, temp;
	_dinstr		*di, *di_temp;
	

	BOOL		used_prospect = FALSE;

	type_InstrList	InstrBlock;		// for delation purposes

	mem			=	this->BinData.data;
	flags		=	this->BinData.flags;
	assert(mem && flags);

	p			=	mem;

	
	
#define D_CHECK_DEST(rva)	{		ret_addr	=	this->is_future_addr_correct(rva,false);	\
									switch(ret_addr)											\
									{															\
										case TADDR_GOOD:										\
											goto d_continue;									\
										case TADDR_ANALYZED:									\
											continue;											\
										case TADDR_INVALID:										\
											if (di)	di->next_instr_rva = NULL;					\
											continue;											\
									}															\
									}
//if (di) { di->next_instr_rva = NULL;	}			\

	// debug test
	//this->FutureAddrList.clear();
	//this->set_future_addr(0x0006a2a3);

//	int res = this->debug_find_future_addr(0x12050);
//	__asm int 3;

#ifdef TIME_TEST == 1
	char *name = strrchr(this->o_filename,'\\');
	div_t result = div(this->o_filesize, 1000000);
	flog("Disassembling: %s\r\n", name);
	
	
	double mb = ((double)this->o_filesize / 1024 /1024 );

	flog("FileSize: %f MB\r\n", mb);
	Czasomierz.reset();
#endif



main_loop:;
	for (;;)
	{
		
		// get rva addr for analysis
		rva_addr	=	this->get_future_addr();

		// are we done?
		if (rva_addr == 0)
			break;

d_continue:;
		rva_addr				=	this->process_instruction(rva_addr, &di);
		if ((rva_addr == DSTATUS_GETNEW) || (rva_addr == DSTATUS_INVALID))
		{
			continue;
		}
		D_CHECK_DEST(rva_addr);
	}


	this->engine_process_prospects();


	// ok all done now use the entires from the prospect list
	
#if DA_DEBUG_IT == 1
			flog("*** making basicblocks!\r\n");
#endif



#ifdef TIME_TEST == 1
	double seconds = Czasomierz.seconds();
	flog("STAGE 1 DISASSEMBLY DONE, %f seconds elapsed\r\n", seconds); 
	flog("STAGE 1 NumOfInstructions = %d\r\n", this->InstrList.size());
	Czasomierz.reset();
	this->seconds_elapsed_disassembly	=	seconds;
#endif



	this->make_basicblocks();



#ifdef TIME_TEST == 1
	double seconds2 = Czasomierz.seconds();
	flog("STAGE 2 BASICBLOCKS DONE, %f seconds elapsed\r\n",seconds2); 
	flog("STAGE 2 NumOfBasicBlocks = %d\r\n", this->BasicBlockList.size());
	Czasomierz.reset();
	this->seconds_elapsed_basicblocks = seconds2;
#endif


#if DA_DEBUG_IT == 1
	this->debug_dump_basicblocks();
	//this->debug_compare_ida();
#endif

	
	
	
	

	return D_OK;
}


/*
* Function disassembles single instruction at rva_addr, and return di_out
* and corresponding status 
* #define DSTATUS_GETNEW	0	// disassembly ok, now take new future addr
* #define DSTATUS_INVALID	-1	// invalid addr or disassembler error
* or next rva_addr
*/

ulong32	DAnalyze::process_instruction(ulong32 rva_addr, _dinstr **di_out)
{
	int			st;
	_dis_data	dd;
	uchar		*mem, *p;
	type_flags	*flags;
	ulong32		temp;
	_dinstr		*di, *di_temp;

	*di_out		=	NULL;
	mem			=	this->BinData.data;
	flags		=	this->BinData.flags;
	assert(mem && flags);

	p			=	mem;
	//rva			=	rva_addr;



	//bp(rva_addr, 0x000022A8);

#define RETURN_ERROR	return DSTATUS_INVALID;
#define RETURN_BREAK	return DSTATUS_GETNEW;
#define RETURN_ADDR		return (rva_addr+dd.len);

	// no need to pick up the addr (continue the stream)
	p			=	(uchar*)lrva2va(rva_addr);

	//000528e8 (004528e8) add [eax],al
	//assume: 00 00 -> is always bad // or DWORD FF FF
	if ((*(uword*)p == 0x0000) || (*(uword*)p == 0xFFFF))
	{
#if DA_DEBUG_IT == 1
		flog("*** process_instruction(): Unable to disassemble (NULLBYTES/FFFF): %08x (%08x)\r\n",
			rva_addr,
			orva2va(rva_addr));
#endif
		RETURN_ERROR;
	}


	// end added 30.03.2011

	//memset((void*)&dd,0,sizeof(_dis_data));
	
	
	st			=	_disasm(p,&dd);
	if (!st)
	{
#if DA_DEBUG_IT == 1
		flog("*** process_instruction(): Unable to disassemble: %08x (%08x)\r\n",
			rva_addr,
			orva2va(rva_addr));
#endif
		RETURN_ERROR;
	}


	// check for overlap
	for (int i = 1; i < dd.len; i++)
	{
		if (daIS_F_INSTR(flags[rva_addr+i]))
		{
#if DA_DEBUG_IT == 1
		flog("*** process_instruction(): %08x overlaps with %08x\r\n",
			rva_addr,
			rva_addr+i);
#endif
			RETURN_ERROR;
		}
	}


#if DA_DEBUG_IT == 1
		// debug only
	this->debug_show_instruction(rva_addr);
#endif

	// allocate the structure for new instruction
	di					=	this->new_dinstr(rva_addr, p, dd.len, dd.emul_int);
	di->disit_flags		=	dd.dflags;
	*di_out				=	di;

	

	switch(dd.emul_int)
	{

		// -----------------------------------------
		// NORMAL INSTRUCTION
		// -----------------------------------------
		// + additional flags depending on the operands
		default:
			di->next_instr		=	(_dinstr*)(rva_addr + dd.len);		// just rva for now
			this->check_operands_and_set_flags(di,&dd);
			this->check_semantic_nops(di,&dd);

			// before we will proceed make sure this instruction is "valid"
			// most of the mismatched data->code has some strange MEM_IMM operands
			// so we will scan for this

			if (!is_mem_operand_in_range(rva_addr,&dd))
			{
				// ups, data as code? remove it!
				//this->remove_bad_area(&InstrList);
				//continue;

				RETURN_ERROR;

			}
			RETURN_ADDR;

		// -----------------------------------------
		// CALL reg
		// -----------------------------------------
		case CALL_1:
			di->next_instr		=	(_dinstr*)(rva_addr + dd.len);		// just rva for now
			//daSET_F_BB_END(&flags[rva_addr]);	// dodane 09.03.2011 (call tez konczy basicblock)

//			RETURN_ADDR;
			daSET_F_BB_END(&flags[rva_addr]);	// dodane 09.03.2011 (call tez konczy basicblock)
			this->set_future_addr((ulong32)di->next_instr);	// dodane 09.03.2011
			daSET_F_DONT_MERGE(&flags[di->next_instr_rva]); // dodane 09.03.2011
			RETURN_BREAK;



		// -----------------------------------------
		// JMP UNCONDITIONAL 
		// -----------------------------------------
		case JMP_SHORT_0:
		case JMP_0:
			daSET_F_INSTR_JMP(&flags[rva_addr]);
			di->linked_instr	=	(_dinstr*)(rva_addr + dd.len + dd.imm_data);
			this->set_future_addr((ulong32)di->linked_instr);
			daSET_F_BB_END(&flags[rva_addr]);
			RETURN_BREAK;

		// -----------------------------------------
		// CONDITIONAL JMPS (JCCS) and LOOPS and normal CALL 
		// -----------------------------------------
		case LOOPNE_0:
		case LOOPE_0:
		case JCC_0:
		case JCC_1:
		case JECXZ_0:
		case LOOP_0:
			daSET_F_INSTR_JCC(&flags[rva_addr]);
			daSET_F_BB_END(&flags[rva_addr]);
			di->linked_instr	=	(_dinstr*)(rva_addr + dd.len + dd.imm_data);
			di->next_instr		=	(_dinstr*)(rva_addr + dd.len);	
			this->set_future_addr((ulong32)di->linked_instr);
			this->set_future_addr((ulong32)di->next_instr);
			RETURN_BREAK;
		
		// same as upper one, just with one change dest is marked as function
		// dont mark next instruction as label
		case CALL_0:

		//	bp(rva_addr,0x00011A3F   );

			di->linked_instr	=	(_dinstr*)(rva_addr + dd.len + dd.imm_data);
			di->next_instr		=	(_dinstr*)(rva_addr + dd.len);	


			if (this->is_addr_in_range(di->linked_instr_rva))
			{
				daSET_F_INSTR_CALL(&flags[rva_addr]);
				this->set_future_addr_function((ulong32)di->linked_instr_rva,true);

				//  correct range, so now check if it points to DEADEND api
				//  like this one in ntoskrnl:
				//  call    _KeBugCheckEx@20 ; KeBugCheckEx(x,x,x,x,x)
				//  nop			<--- stop disassembly here
				if (daIS_F_FUNC_DEADEND(flags[di->linked_instr_rva]))
				{
#if DA_DEBUG_IT == 1
					flog("*** DEADEND FUNCTION CALL AT : %08x (%08x) - BREAKING\r\n",
						rva_addr,
						orva2va(rva_addr));
#endif
					daSET_F_BB_INTERRUPTED(&flags[rva_addr]);	// dodano 30.03.2011
					di->next_instr_rva	=	NULL;

					
					daSET_F_BB_END(&flags[rva_addr]);
					RETURN_BREAK;
				}
			}
			else
				di->linked_instr_rva	=	NULL;

			//RETURN_ADDR;

			daSET_F_BB_END(&flags[rva_addr]);	// dodane 09.03.2011 (call tez konczy basicblock)
			this->set_future_addr((ulong32)di->next_instr);	// dodane 09.03.2011
			daSET_F_DONT_MERGE(&flags[di->next_instr_rva]);
			RETURN_BREAK;



		// -----------------------------------------
		// RETURNS AND RETURN ALIKE INSTURCTIONS
		// -----------------------------------------
		case RET_0:
		case RET_1:
		case RET_FAR_0:
		case RET_FAR_1:
		case IRET_IRETD_0:
			daSET_F_INSTR_RETURN(&flags[rva_addr]);
			daSET_F_BB_END(&flags[rva_addr]);
			RETURN_BREAK;
		
		
			// same us upper; + mark block as interrupted
		case JMP_1:
		case JMP_3:
		case JMP_4:
			daSET_F_BB_END(&flags[rva_addr]);
			RETURN_BREAK;

		case INT_0x3_0:
		case HLT_0:
			daSET_F_BB_END(&flags[rva_addr]);
			daSET_F_BB_INTERRUPTED(&flags[rva_addr]);	// dodano 30.03.2011
			RETURN_BREAK;





		// -----------------------------------------
		// CALL [MEM] | JMP [MEM]
		// -----------------------------------------
		// + additionally scan for switch tables
		// dont mark next instr as label
		// + TODO: if this is not a [eax+rel], the mem_imm must be relocable!!
		// so dont add if it is not
		// set the flag only if the offset is valid
		case CALL_2:
			di->next_instr		=	(_dinstr*)(rva_addr + dd.len);	
			//this->set_future_addr((ulong32)di->next_instr);
			this->check_operands_and_set_flags(di,&dd);
			temp	=	ova2rva(dd.mem_imm);
			

			if (!daIS_F_INSTR_USES_IMPORTED_API(flags[rva_addr]))
			{
				if (this->is_addr_in_range(temp))
				{
					temp				=	*(ulong32*)lrva2va(temp);
					temp				=	ova2rva(temp);
					if (this->is_addr_in_range(temp))
					{
						di->linked_instr	=	(_dinstr*)temp;
						this->set_future_addr_function((ulong32)di->linked_instr, true);
					}
					daSET_F_INSTR_CALL(&flags[rva_addr]);
					this->check_for_vtable(di,&dd);
				}
			}
			else
			{
				// check if it uses dead-end api if so break
				if (daIS_F_IMPORT_DATA_DEADEND(flags[di->objMEMIMM_rva]))
				{
#if DA_DEBUG_IT == 1
					flog("*** DEADEND API CALL AT : %08x (%08x)\r\n",
						rva_addr,
						orva2va(rva_addr));
#endif

					di->next_instr		=	NULL;
					daSET_F_BB_INTERRUPTED(&flags[rva_addr]);	// dodano 30.03.2011
					daSET_F_BB_END(&flags[rva_addr]);
					RETURN_BREAK;
				}
			}

			

//			RETURN_ADDR;
			daSET_F_BB_END(&flags[rva_addr]);	// dodane 09.03.2011 (call tez konczy basicblock)
			this->set_future_addr((ulong32)di->next_instr);	// dodane 09.03.2011
			daSET_F_DONT_MERGE(&flags[di->next_instr_rva]);
			RETURN_BREAK;



		case JMP_2:
			// firstly read the memory
			this->check_operands_and_set_flags(di,&dd);
			temp	=	ova2rva(dd.mem_imm);
			if (!daIS_F_INSTR_USES_IMPORTED_API(flags[rva_addr]) && this->is_addr_in_range(temp))
			{
				temp				=	*(ulong32*)lrva2va(temp);
				temp				=	ova2rva(temp);
				if (this->is_addr_in_range(temp))
				{
					di->linked_instr	=	(_dinstr*)temp;
					this->set_future_addr((ulong32)di->linked_instr);
				}
				daSET_F_INSTR_JMP(&flags[rva_addr]);
				this->check_for_vtable(di,&dd);
			}
			daSET_F_BB_END(&flags[rva_addr]);
			RETURN_BREAK;


	}




}


/*
* After initial disassembly is done (most of the code coverage)
* try to process some not-reliable areas (like areas pointed by
* reloc information or jump/call tables
*/

int	 DAnalyze::engine_process_prospects(void)
{
	ulong32			rva_addr;
	_dinstr			*di, *di_temp;
	type_flags		*flags		= this->BinData.flags;
	uchar			*p			=	this->BinData.data;


#if DA_DEBUG_IT == 1
			flog("*** now using prospect list!\r\n");
#endif

	

	this->FutureAddrList.clear();
	//this->FutureAddrList.assign(this->ProspectAddrList.begin(), this->ProspectAddrList.end());



#define CHECK_DINSTR_FIELD(field)	{	if (di && field)		{																\
											if (this->is_prospect_rva_good(field, NULL) == TADDR_INVALID)	\
												goto addr_is_invalid;															\
						 } }

	while (!this->ProspectAddrList.empty())
	{

		di						=	NULL;
		BOOL	addr_invalid	=	FALSE;
		// give one element
		ulong32	rva_prospect	=	this->ProspectAddrList.back();
		this->ProspectAddrList.pop_back();

		// set actual pointer for InstrList state
		int	dinstr_index	=	InstrList.size();
		this->FutureAddrList.push_back(rva_prospect);

#if DA_DEBUG_IT == 1
		flog("*** engine_process_prospects(): using %08x as prospect start point!\r\n",
			rva_prospect);
#endif

//		bp(rva_prospect,0x0002a436);

		for (;;)
		{

			BOOL	addr_from_list = TRUE;
			CHECK_DINSTR_FIELD(di->linked_instr_rva);
	
			// disassemble until no future addrs
			if (this->FutureAddrList.empty())
				break;
			rva_addr	=	this->FutureAddrList.back();
			this->FutureAddrList.pop_back();


			

		

			// check if it is unicode or ascii
			if ((this->can_be_ascii(&p[rva_addr]) >= MAX_ASCII_CHARS) || 
			(this->can_be_unicode(&p[rva_addr]) >= MAX_UNICODE_CHARS))
			{

#if DA_DEBUG_IT == 1
				flog("*** engine_process_prospects() -> unicode/ascii at %08x, skipping!!\r\n", rva_addr);
#endif

				goto addr_is_invalid;
			}


continue_prospect_disasm:;
			CHECK_DINSTR_FIELD(di->linked_instr_rva);
	

			// test the addr
			switch(this->is_prospect_rva_good(rva_addr, NULL))
			{
				default:
				case TADDR_INVALID:
					addr_invalid = TRUE;
					break;

				case TADDR_ANALYZED:
					if (addr_from_list)
						daSET_F_LABEL(&flags[rva_addr]);
					continue;

				case TADDR_GOOD:
					if (addr_from_list)
						daSET_F_LABEL(&flags[rva_addr]);
					break;
			}

			// break the loop if addr is invalid
			// and clean up the dinstr
			if (addr_invalid)
			{
addr_is_invalid:;
				for (int i = dinstr_index; i < InstrList.size(); i++)
				{
					di_temp	=	InstrList[i];

#if DA_DEBUG_IT == 1
					flog("*** engine_run() prospect -> delating instruction at %08x!\r\n",
						di_temp->rva_addr);
#endif

					flags[di_temp->rva_addr]	&=	~(DA_FLAG_FUNCTION_START|DA_FLAG_INSTR|DA_FLAG_HEAD|DA_FLAG_TAIL);
					delete di_temp;
				}

				InstrList.erase(InstrList.begin()+dinstr_index, InstrList.end());
				di		=	NULL;
				
				
				this->FutureAddrList.clear();
				break;
				//continue;
			}

			ulong32 last_rva_addr = rva_addr;
			rva_addr	=	this->process_instruction(rva_addr, &di);
			if (rva_addr == DSTATUS_GETNEW)
				continue;
			else if (rva_addr == DSTATUS_INVALID)
			{
				// overlapping or invalid instruction
				// added: 30.03.2011 
				flags[last_rva_addr]	&=	~(DA_FLAG_FUNCTION_START|DA_FLAG_INSTR|DA_FLAG_HEAD|DA_FLAG_TAIL);

				goto addr_is_invalid;
			}


			addr_from_list	=	FALSE;
			goto continue_prospect_disasm;

		}
	}

	return D_OK;
}


// debug only (compare with ida file)
void DAnalyze::debug_compare_ida()
{
	DWORD fs;
	ulong32	*mem;

#define EXPORT_NAME "J:\\projekty\\symbol_test\\lab\\export.dat"
	HFILE in = _lopen(EXPORT_NAME,OF_READ);
	assert(in != HFILE_ERROR);

	fs = GetFileSize((HANDLE)in,NULL);
	assert(fs);

	type_flags *flags = this->BinData.flags;;



	mem	=	(ulong32*)new uchar[fs+4];
	assert(mem);
	memset((void*)mem,0xCC,fs+4);

	// read all 
	_lread(in,mem,fs);


	for (int i = 0; mem[i] != 0xCCCCCCCC; i++)
	{
		ulong32 f = flags[mem[i]];
		if (!daIS_F_HEAD(f) || !daIS_F_INSTR(f))
		{
			flog("NotAnalyzed: IDA: %08x -> OUR: %08x\r\n",
				mem[i],
				mem[i]);

		}
	}




	delete []mem;
	_lclose(in);

}




void DAnalyze::debug_compare_ida_data()
{
	DWORD fs;
	ulong32	*mem;

#define EXPORT_NAME_DATA "J:\\projekty\\binary_shepherding\\data_locations.txt"
	HFILE in = _lopen(EXPORT_NAME_DATA,OF_READ);
	assert(in != HFILE_ERROR);

	fs = GetFileSize((HANDLE)in,NULL);
	assert(fs);

	type_flags *flags = this->BinData.flags;;



	mem	=	(ulong32*)new uchar[fs+4];
	assert(mem);
	memset((void*)mem,0xCC,fs+4);

	// read all 
	_lread(in,mem,fs);

int bad = 0;
	for (int i = 0; mem[i] != 0xCCCCCCCC; i++)
	{
		ulong32 f = flags[mem[i]];
		ulong32 rva = mem[i];


		
		if (daIS_F_INSTR(f))
		{
			BOOL enough_size = TRUE;
			if (daIS_F_FUNCTION_START(f))
			{
				// count the bytes
				for (int j = mem[i]; j < (mem[i]+PATCH_SIZE); j++)
					if (daIS_F_BB_END(flags[j]))
						enough_size = FALSE;
			}

			if (daIS_F_ACCESSED_AS_DATA(f))
				flog("[%08d] DATA: IDA: %08x -> OUR CODE: %08x AND NOTHOOKED!\r\n",
					bad,
					mem[i],
					mem[i]);
			else if (daIS_F_FUNCTION_START(f) && enough_size)
				flog("[%08d] DATA: IDA: %08x -> OUR CODE: %08x AND HOOKED!\r\n",
					bad,
					mem[i],
					mem[i]);

			bad++;
		}
		
	}




	delete []mem;
	_lclose(in);

}



