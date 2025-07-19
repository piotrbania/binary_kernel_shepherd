#include "danalyze.h"



// debug only
void DAnalyze::debug_dump_basicblocks(void)
{
	int i;
	ulong32 temp;
	_dbasicblock *bb_temp;


	if (this->BasicBlockList.empty())
		return;

	flog("DUMPING BASICBLOCKS\r\n");


	for (i = 0; i < this->BasicBlockList.size();
		i++)
	{
		_dbasicblock *db = this->BasicBlockList[i];
		flog("------------------------------------\r\n");
		flog("BasicBlock start = %08x (%08x)\r\n",db->rva_start, orva2va(db->rva_start));
	//	flog("BasicBlock end = %08x (%08x)\r\n",db->rva_end, orva2va(db->rva_end));
		if (daIS_F_BB_MERGED(db->flags)) flog("BasicBlock was merged!\r\n");
		flog("BasicBlock FullCRC = %08x %08x\r\n",db->crc.crc_elements.first_32bit, db->crc.crc_elements.desc_crc);

#if DA_DIFF_USE_WEAKCRCMAP == 1
		flog("BasicBlockCRC = BYTES: %08x ADLER: %08x WEAK: %08x\r\n",db->crc.crc_elements.byte_crc,
			db->crc.crc_adler,
			db->crc.crc_weak);
#else
		flog("BasicBlockCRC = BYTES: %08x ADLER: %08x WEAK: %08x\r\n",db->crc.crc_elements.byte_crc,
			db->crc.crc_adler,
			0xDEADBEEF);
#endif

		flog("CRC ilen=%d Childs=%d Parents=%d ChildFuncs=%d\r\n",
			db->crc.crc_elements.instr_num,
			db->crc.crc_elements.childs_num,
			db->crc.crc_elements.parents_num,
			db->crc.crc_elements.child_func_num);

		flog("ChildFuncsDump: \r\n");
		if (db->ChildFunctionsList)
		{
			for (int j = 0; j < db->ChildFunctionsList->size(); j++)
			{
				bb_temp = (*db->ChildFunctionsList)[j];
				if (this->is_addr_in_range((ulong32)bb_temp) || IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_temp))
					flog("%d -> %08x (%08x) -> NOT RESOLVED\r\n", j, bb_temp, orva2va((ulong32)bb_temp));
				else
					flog("%d -> %08x (%08x)\r\n", j, bb_temp->rva_start, orva2va(bb_temp->rva_start));			}
		}

		flog("ChildsDump: \r\n");
		if (db->ChildsList)
		{
			for (int j = 0; j < db->ChildsList->size(); j++)
			{
				
				bb_temp = (*db->ChildsList)[j];
				if (this->is_addr_in_range((ulong32)bb_temp) || IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_temp))
					flog("%d -> %08x (%08x) -> NOT RESOLVED\r\n", j, bb_temp, orva2va((ulong32)bb_temp));
				else
					flog("%d -> %08x (%08x)\r\n", j, bb_temp->rva_start, orva2va(bb_temp->rva_start));
			}
		}

		flog("ParentsDump: \r\n");
		if (db->ParentsList)
		{
			for (int j = 0; j < db->ParentsList->size(); j++)
			{
				bb_temp = (*db->ParentsList)[j];
				if (this->is_addr_in_range((ulong32)bb_temp) || IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_temp))
					flog("%d -> %08x (%08x) -> NOT RESOLVED\r\n", j, bb_temp, orva2va((ulong32)bb_temp));
				else
					flog("%d -> %08x (%08x)\r\n", j, bb_temp->rva_start, orva2va(bb_temp->rva_start));
			}
		}


		flog("Instructions dump\r\n");
		
		type_flags	*flags = this->BinData.flags;

		//for (int j = db->rva_start; j < db->rva_end+1; j++)
		for (int j = db->rva_start; ; j++)
		{	
			_dinstr	*di = this->get_dinstr_from_rva(j);
			assert(di);
			this->debug_show_instruction(j);
			j	+= di->len - 1;

			if (daIS_F_BB_END(flags[di->rva_addr]))
				break;

		}

		flog("------------------------------------\r\n");


		if (daIS_F_BB_MERGED(db->flags) && db->MergedList)
		{
			// list all merged areas
			flog("Merged basicblocks: %d\r\n",db->MergedList->size());
			for (int j = 0; j < db->MergedList->size(); j++)
			{
				_dbasicblock *bb_m = (*db->MergedList)[j];
				//flog("* Merged basicblock %08x(%08x) - %08x (%08x)\r\n",
				flog("* Merged basicblock %08x(%08x)\r\n",
					bb_m->rva_start,
					orva2va(bb_m->rva_start)
					);//bb_m->rva_end,
					//orva2va(bb_m->rva_end));

				flog("Merged child instructions\r\n");

				//for (int j = bb_m->rva_start; j < bb_m->rva_end+1; j++)
				for (int j = bb_m->rva_start; ; j++)
				{	
					_dinstr	*di = this->get_dinstr_from_rva(j);
					assert(di);
					this->debug_show_instruction(j);
					j	+= di->len - 1;

					if (daIS_F_BB_END(flags[di->rva_addr]))
						break;
				}

				flog("------------------------------------\r\n");
			}
		}

	}




	flog("END OF BASICBLOCK DUMP (found = %d bblocks)\r\n",i);



}

/*
* Function get instruction bytes and supply them for computing the checksum.
* Bytes does not include:
* -> operands that contains relocable addresses (MEM_IMM/IMM)
* -> no jump/call/jcc offsets (just opcodes)
* -> if instr is NOP it is not included
*/


int DAnalyze::set_bytes_for_checksum(_dbasicblock *bb, _dinstr *di, type_flags iflags)
{
	_sinfo *sym;


	BOOL		eip_changer			=	FALSE;
	BOOL		imm_data_reloc		=	FALSE;
	BOOL		memimm_data_reloc	=	FALSE;

	ulong32		mem_imm_rva			=	0;
	ulong32		ad_flags			=	0;				// additional flags
	ulong32		byte_rva_start		=	di->rva_addr;
	ulong32		byte_rva_end		=	di->rva_addr + di->len;

	//ulong32		crc_weak			=	0;
	ulong32		byte_rva_weak_end	=	0;
	int			imm_size			=	0;
	int			mem_imm_size		=	0;


	uchar		*data				= this->BinData.data;

	// check for nop element
	if (daIS_F_INSTR_SEMANTIC_NOP(iflags))
		return D_OK;


	// if this is a SHORT_JMP (unconditional) 
	// add just the opcode of longer jump to the checksum 
	if (di->emul_int == JMP_SHORT_0)
	{
		this->Checksum->add_byte_clean(JMP_OPCODE);
		this->Checksum->add_byte_adler(JMP_OPCODE);
		return D_OK;

	}


		

	// check for relocable elements
	// imm_data always at the end
	// mem_imm always before the imm_data
	if (daIS_F_INSTR_RELOCABLE_DATA_IN_IMM(iflags))
	{
		byte_rva_end	-=	sizeof(ulong32);
		imm_data_reloc	=	TRUE;
		reference_add(di->objIMM_rva, bb, di);
	}
	


	if (daIS_F_INSTR_RELOCABLE_DATA_IN_MEMIMM(iflags))
	{
		// there is a MEM imm but what if is there is also an imm constant
		// which was not relocable???
		if (!daIS_F_INSTR_RELOCABLE_DATA_IN_IMM(iflags))
		{
			type_flags *flags = this->BinData.flags;
			ulong32 last =  di->rva_addr + di->len;
			while (!daIS_F_RELOC_DATA(flags[last-1]))
			{
				last--;
				this->Checksum->add_byte_clean(data[last]);
			}
			byte_rva_end	=	last;
		}

		// add the references
		reference_add(di->objMEMIMM_rva, bb, di);

		byte_rva_end						-= sizeof(ulong32);
		memimm_data_reloc					= TRUE;
		this->Checksum->crc.crc_elements.uses_memimm_relocable	=	1;
	}

	assert(byte_rva_end > byte_rva_start);




	// if this is a JCC/JMP/CALL
	if (daIS_F_INSTR_CALL(iflags)	||
		daIS_F_INSTR_JMP(iflags)	||
		daIS_F_INSTR_JCC(iflags))
	{
		eip_changer		=	TRUE;
		byte_rva_end	=	byte_rva_start	+ 1;	// at least one byte for opcode
		if (di->len > 5)	// bigger than the standard length (so opcode is two bytes now)
			byte_rva_end++;
	}
	
	// to avoid collisions add additional flags
	// if this is a JCC, just fill the tttn field
	// and go home
	if (daIS_F_INSTR_JCC(iflags))				
	{	
		//this->Checksum->crc.crc_elements.uses_jcc	=	1;
		int8 tttn	=	data[byte_rva_start] & 0x0F;
		if (di->len > 2)
			tttn	=	data[byte_rva_start+1] & 0x0F;

		this->Checksum->crc.crc_elements.tttn = tttn;

		// add the tttn to adler checksum also
		this->Checksum->add_byte_adler(tttn);


#if DA_DIFF_USE_WEAKCRCMAP == 1
		this->Checksum->add_byte_adler_weak(tttn);
#endif

		return D_OK;
	}
		
	if (disit_is_DF_USE_MEM(di->disit_flags))
	{
		this->Checksum->crc.crc_elements.uses_mem		=	1;
		if (disit_is_DF_MEM_ACTSRC(di->disit_flags))	
			this->Checksum->crc.crc_elements.mem_act	=	1;


	}


	mem_imm_rva			=	byte_rva_end;
	byte_rva_weak_end	=	byte_rva_end;

	if (disit_isDF_IMM(di->disit_flags) && !eip_changer)	
	{
		imm_size	=	disit_getDF_size_IMM(di->disit_flags);
		mem_imm_rva		-=	imm_size;

		this->Checksum->crc.crc_elements.uses_imm		=	1;

		if (!imm_data_reloc)
		{
			for (int j = 0; j < imm_size; j++)
				ad_flags	+=	(data[byte_rva_end - j - 1] << (j+1));
			
			if (di->emul_int == PUSH_3)
				byte_rva_weak_end	-=	imm_size;	
		}
	}


	if (disit_isDF_MEM_IMM(di->disit_flags))	
	{
		mem_imm_size	=	disit_getDF_size_MEM_IMM(di->disit_flags);
		this->Checksum->crc.crc_elements.uses_memimm	=	1;

		if (!memimm_data_reloc)
		{
			for (int j = 0; j < mem_imm_size; j++)
			{
				// add the bytes in special fashion too
				ad_flags	+=	(data[mem_imm_rva - j - 1] << (j+3));
				//crc_weak	+=	(data[mem_imm_rva - j - 1] << (j+3));
			}
			//byte_rva_end	-=	mem_imm_size;
		}


		// if there is a sib multipler add it too
		if (disit_is_DF_USE_SIB(di->disit_flags))
		{
			int sib_mul = disit_getDF_size_SIBMUL(di->disit_flags);
			this->Checksum->add_byte_clean(sib_mul);
			this->Checksum->add_byte_adler(sib_mul);
		}

	}


	this->Checksum->crc.crc_elements.byte_crc	+=	ad_flags;
	//this->Checksum->crc.crc_weak				+=	crc_weak;


	// submit the bytes to the checksum procedure
	for (ulong32 rva = byte_rva_start; rva < byte_rva_end; rva++)
	{
		this->Checksum->add_byte_clean(data[rva]);
		this->Checksum->add_byte_adler(data[rva]);
	}


	// now same for weak crc
	// if instruction uses SIB and SIBMUL=0 (2^0=1)
	// then ignore last byte

#if DA_DIFF_USE_WEAKCRCMAP == 1
	int skip_index = 0;	
	int	pass = 1;
	if (disit_is_DF_USE_SIB(di->disit_flags) && (disit_getDF_size_SIBMUL(di->disit_flags) == 0))
	{
		//skip_index	=	di->len - imm_size - mem_imm_size;
	}

	for (ulong32 rva = byte_rva_start; rva < byte_rva_weak_end; rva++, pass++)
	{
		if (skip_index && (skip_index == pass))
			continue;
		//this->Checksum->crc.crc_weak	+=	data[rva];
		this->Checksum->add_byte_adler_weak(data[rva]);
	}
#endif


#if DA_DIFF_USE_WEAKCRCMAP == 1
#define store_sym_crc(sym_addr)		{								\
	_sinfo *sym = this->Symbols->get_symbol_info(sym_addr);			\
	if (sym)	{													\
		uchar*	api_name = (uchar*)&sym->adler32_name;						\
		this->Checksum->crc.crc_elements.byte_crc	+=	sym->adler32_name;	\
		this->Checksum->add_byte_adler(api_name[0]);				\
		this->Checksum->add_byte_adler(api_name[1]);				\
		this->Checksum->add_byte_adler(api_name[2]);				\
		this->Checksum->add_byte_adler(api_name[3]);				\
		this->Checksum->add_byte_adler_weak(api_name[0]);				\
		this->Checksum->add_byte_adler_weak(api_name[1]);				\
		this->Checksum->add_byte_adler_weak(api_name[2]);				\
		this->Checksum->add_byte_adler_weak(api_name[3]);				\
	}}
#else
#define store_sym_crc(sym_addr)		{								\
	_sinfo *sym = this->Symbols->get_symbol_info(sym_addr);			\
	if (sym)	{													\
		uchar*	api_name = (uchar*)&sym->adler32_name;						\
		this->Checksum->crc.crc_elements.byte_crc	+=	sym->adler32_name;	\
		this->Checksum->add_byte_adler(api_name[0]);				\
		this->Checksum->add_byte_adler(api_name[1]);				\
		this->Checksum->add_byte_adler(api_name[2]);				\
		this->Checksum->add_byte_adler(api_name[3]);				\
	}}

#endif


	// im not sure if we should use it here
	// todo: mark
#if DA_STORE_SYM_CRC == 1
	if (daIS_F_INSTR_SYMBOL_IN_MEMIMM(iflags))
		store_sym_crc(di->objMEMIMM_rva);
	if (daIS_F_INSTR_SYMBOL_IN_IMM(iflags))
		store_sym_crc(di->objIMM_rva);
	if (daIS_F_INSTR_CALL(iflags))
	{
		type_flags	*flags = this->BinData.flags;
		if (daIS_F_HAS_SYMBOL(flags[di->linked_instr_rva]))
		{
			store_sym_crc(di->linked_instr_rva);
		}
	}
#endif

	// check if the instruction is using ImportAPI
	if (daIS_F_INSTR_USES_IMPORTED_API(iflags))
	{
		// if so add the adler32 of the name to the checksum bytes 
		store_sym_crc(di->objMEMIMM_rva);
	}


	return D_OK;
}

/*
* Function allocates and initializes new basicblock
*/

_dbasicblock	*DAnalyze::new_basicblock(ulong32 start_rva)
{
	_dbasicblock *bb = new _dbasicblock;
	assert(bb);

	memset((void*)bb, 0, sizeof(_dbasicblock));
	bb->rva_start	=	start_rva;

	this->BasicBlockList.push_back(bb);
	this->BasicBlockMap.insert(make_pair<ulong32,_dbasicblock*>(start_rva,bb));


#if DA_DEBUG_IT == 1
			flog("*** new_basicblock() at %08x (%08x)\r\n",
					start_rva,
					orva2va(start_rva));
#endif

	return bb;
}



/*
* Function generates basicblocks for executable data.
* It also initializes FunctionList with new functions
* if selected basicblock starts a function.
*/

int DAnalyze::make_basicblocks()
{
	ulong32			rva = 0;
	type_flags		*flags;
	type_flags		iflags;
	_dbasicblock	*bb;
	_dinstr			*di;


	flags		= this->BinData.flags;
	

	this->bb_not_resolved = 0;
	this->BasicBlockList.clear();
	this->BasicBlockMap.clear();



	int instr_index			=	0;
	int	instr_list_size		=	this->InstrList.size();

	while(1)
	{
		if (instr_index >= instr_list_size)
			break;


		// get one instruction from the list
		// it is always a HEAD
		di			=	this->InstrList[instr_index];
		rva			=	di->rva_addr;
		iflags		=	flags[rva];

		
		// if this is a label (it is time to build a basicblock)
		if (daIS_F_LABEL(iflags))
		{

			// make new basicblock
			this->Checksum->reset_checksum();

		
		//	flog("crc is now: %08x\n",this->Checksum->crc.crc_elements.first_32bit);
			bb									=	this->new_basicblock(rva);
			instr_index							+=	this->fill_and_close_basicblock(bb);
			
			
			bb->crc								=	this->Checksum->compute_checksum_full(
															get_list_size(bb->ChildsList),
															NULL,
															get_list_size(bb->ChildFunctionsList));

		//	
			if (daIS_F_FUNCTION_START(iflags))
				daSET_F_BB_FUNCTION_START(&bb->flags);


			continue;
		}

		// not code so increase the rva and continue
		instr_index++;

	}


	//this->debug_dump_basicblocks();
	this->resolve_basicblock_informations();
	

#if DA_DEBUG_IT == 1	
	flog("*** Found %d notresolved basicblocks!\r\n",this->bb_not_resolved);
#endif

	return D_OK;
}


/*
* Function fills the basicblock with informations. Also it
* setups the end of it. And returns the next available area
* after this block.
*/


int	DAnalyze::fill_and_close_basicblock(_dbasicblock *bb)
{
	ulong32			rva;
	ulong32			end_rva;
	type_flags		*flags;
	type_flags		iflags;
	_dinstr			*di;
	int				i_num = 0;

	rva			=	bb->rva_start;
	flags		=	this->BinData.flags;
	iflags		=	flags[rva];

	

	di			=	this->get_dinstr_from_rva(rva);
	assert(di);
	assert(rva == di->rva_addr);




	// firstly check if this instruction 
	// has BB_END flag, if so this basicblock consists of 
	// single instruction only
	if (daIS_F_BB_END(iflags))
	{
		//bb->rva_end		= rva;

#ifdef _BINSHEP
		bb->rva_end		= rva;
#endif

		this->fill_basicblock_lists(bb, di, iflags);

#ifndef _BINSHEP
		this->set_bytes_for_checksum(bb, di, iflags);
		this->Checksum->set_instruction_counter(1);
#endif

	//	if (daIS_USING_SYMBOLS(iflags))
	//		this->Checksum->inc_symbols_counter();
		return 1;
	}


	// now cover entire basicblock till we find the end of it
	// ALGO is:
	// 1) get actual instruction data
	// 2) check next instruction and see if it is a LABEL
	// 3) if it is a label set BB_END on the actual one
	// 4) if current instruction has BB_END close the loop
	

	//bp(bb->rva_start,0x000251c1);

	ulong32	last_good_rva	=	rva;
	while (1)
	{

		// this is the actual instruction
		iflags		=	flags[rva];
		di			=	this->get_dinstr_from_rva(rva);
		if (!di)
		{

#if DA_DEBUG_IT == 1
			flog("*** fill_and_close_basicblock() -> XXX-BROKEN_BASICBLOCK=%08x LAST=%08x \r\n",
					bb->rva_start,
					rva);
#endif

			this->Checksum->set_instruction_counter(i_num);

			// todo: fix here bb->rva_end = last-good-rva ??
 			daSET_F_BB_END(&flags[last_good_rva]);
//			bb->rva_end	= last_good_rva;


#ifdef _BINSHEP
			bb->rva_end	= last_good_rva;
#endif

			return i_num;
		}


//		this->debug_show_instruction(rva+di->len);
//		this->debug_show_flags_for_rva(rva+di->len);

		// now check the next one 
		ulong32 rva_next	=  di->next_instr_rva;
		if (daIS_F_LABEL(flags[rva_next]))
		{
			// set the BB_END on the current one
			daSET_F_BB_END(&flags[rva]);
			iflags = flags[rva];


#if DA_DEBUG_IT == 1
			flog("*** fill_and_close_basicblock() -> NEW_BB_END for BB=%08x (%08x) NEW_BB_END=%08x (%08x)\r\n",
					bb->rva_start,
					orva2va(bb->rva_start),
					rva,
					orva2va((ulong32)rva));
			flog("**** requested by %08x (%08x)\r\n",
				rva_next,
				orva2va(rva_next));
#endif

		}

		// if instruction uses symbol
		/*
		if (daIS_USING_SYMBOLS(iflags))
		{
			this->Checksum->inc_symbols_counter();
		}
		*/

		this->fill_basicblock_lists(bb, di, iflags);

#ifndef _BINSHEP
		this->set_bytes_for_checksum(bb, di, iflags);
#endif

		i_num++;
	
		// now check if this is the end of the block
		if (daIS_F_BB_END(iflags))
			break;

		last_good_rva	=	rva;
		rva				=	di->next_instr_rva;
	}



#ifdef _BINSHEP
		bb->rva_end	= rva;
#endif

	//bb->rva_end	= rva;

#if DA_DEBUG_IT == 1
	/*
	flog("*** fill_and_close_basicblock() at %08x (%08x) end at: %08x (%08x)\r\n",
					bb->rva_start,
					orva2va(bb->rva_start),
					bb->rva_end,
					orva2va(bb->rva_end));
					*/

	flog("*** fill_and_close_basicblock() at %08x (%08x) end at: %08x (%08x)\r\n",
					bb->rva_start,
					orva2va(bb->rva_start));

#endif

	// set the instruction counter
	this->Checksum->set_instruction_counter(i_num);
	return i_num;
}


/*
* Function fills the lists (child, parents etc) for selected basicblock
* depending on the instruction
*/

int	DAnalyze::fill_basicblock_lists(_dbasicblock *bb, _dinstr *di, type_flags iflags)
{

	// if this is a call, we need to fill the ChildFuncs table
	if (daIS_F_INSTR_CALL(iflags))
	{

#if DA_DEBUG_IT == 1
		flog("*** fill_basicblock_lists() instr is a CALL at: %08x (%08x)\r\n",
				di->rva_addr,
				orva2va(di->rva_addr));
#endif

		if (daIS_F_BB_END(iflags))
		{
			if (di->next_instr_rva)
			{
				bb->ChildsList	=	new type_BBChilds;
				bb->ChildsList->push_back((_dbasicblock*)di->next_instr_rva);
			}
		}



		// make sure the list was not allocated already
		if (!bb->ChildFunctionsList)
		{
			bb->ChildFunctionsList	=	new type_BBChildFunctions;
			bb->ChildFunctionsList->clear();
		}

		// now it is important to distinguish between normal
		// single dest call and a call using VTABLE
		// since VTABLE generates more ChildFunctionsist

		if (daIS_F_INSTR_USES_VTABLE(iflags))
		{
			// write all the locations to the list
			this->write_vtable_to_basicblock_list(di->linked_instr_rva, bb->ChildFunctionsList);

		}
		else
		{


			// make sure the destination is valid
			if (!daIS_F_INSTR_USES_IMPORTED_API(iflags) && 
				this->is_addr_in_range(di->linked_instr_rva))
			{

				// write just this single destination (RVA for now)
				// make sure it is not zero
				if (di->linked_instr_rva)
				{
					bb->ChildFunctionsList->push_back((_dbasicblock*)di->linked_instr_rva);

#if DA_DEBUG_IT == 1
				flog("*** fill_basicblock_lists() instr is a CALL at: %08x (%08x) -> NO VTABLE found, adding %08x (%08x) to list\r\n",
						di->rva_addr,
						orva2va(di->rva_addr),
						di->linked_instr_rva,
						orva2va((ulong32)di->linked_instr_rva));
#endif			
				
				}
			}
		}

		return D_OK;
	} // if CALL

	// if this is not a CALL and not a BB ender it means we have nothing
	// to do here.
	if (!daIS_F_BB_END(iflags))
		return D_OK;

	// if this is a return, there is no next
	if (daIS_F_INSTR_RETURN(iflags))
		return D_OK;



	// allocate the ChildList if needed because it will be used
	// in every possible situation
	// todo: just allocate without the IF?
	if (!bb->ChildsList)
	{
		bb->ChildsList	=	new type_BBChilds;
		bb->ChildsList->clear();
	}


	// if this is an uncodintional jump write the child to the list
	if (daIS_F_INSTR_JMP(iflags))
	{
#if DA_DEBUG_IT == 1
			flog("*** fill_basicblock_lists() instr is a JMP at: %08x (%08x) (BB_END)\r\n",
					di->rva_addr,
					orva2va(di->rva_addr));
#endif



		// again check for vtable
		if (daIS_F_INSTR_USES_VTABLE(iflags))
		{
			// write all the locations to the list
			this->write_vtable_to_basicblock_list(di->linked_instr_rva, bb->ChildsList);

		}
		else
		{


			// todo: remake the imported apis (cover them)?
			// make sure it is valid
			if (!daIS_F_INSTR_USES_IMPORTED_API(iflags) && 
				this->is_addr_in_range(di->linked_instr_rva))
			{

			// write just this single destination (RVA for now)
				if (di->linked_instr_rva)
				{
#if DA_DEBUG_IT == 1
				flog("*** fill_basicblock_lists() instr is a JMP at: %08x (%08x) -> NO VTABLE found, adding %08x (%08x) to list\r\n",
						di->rva_addr,
						orva2va(di->rva_addr),
						di->linked_instr_rva,
						orva2va((ulong32)di->linked_instr_rva));
#endif

					bb->ChildsList->push_back((_dbasicblock*)di->linked_instr_rva);

				}
			}
		}

		return D_OK;
	} // if JMP


	// if this is a conditional jump then add two locations
	if (daIS_F_INSTR_JCC(iflags))
	{
#if DA_DEBUG_IT == 1
			flog("*** fill_basicblock_lists() instr is a JCC at: %08x (%08x) (BB_END)\r\n",
					di->rva_addr,
					orva2va(di->rva_addr));
			flog("*** adding two locations to ChildsList %08x (%08x) and %08x (%08x)\r\n",
				di->linked_instr_rva,
				orva2va(di->linked_instr_rva),
				di->next_instr_rva,
				orva2va(di->next_instr_rva));
#endif

			// and add both locations
			bb->ChildsList->push_back((_dbasicblock*)di->linked_instr_rva);
			bb->ChildsList->push_back((_dbasicblock*)di->next_instr_rva);

			return D_OK;
	} // JCC



	// now if the basicblock was split, normal instruction may end the basicblock
	// so we just need to add next instr as child (since it probably has the LABEL flag)
	if (di->next_instr_rva)
		bb->ChildsList->push_back((_dbasicblock*)di->next_instr_rva);

	return D_OK;
}


/*
* Function writes all relocable offsets from vtable_rva to supplied list.
*/

int	DAnalyze::write_vtable_to_basicblock_list(ulong32 vtable_rva, type_BBChildFunctions *list)
{

	uchar			*data	= this->BinData.data;	
	type_flags		*flags	= this->BinData.flags;


	// make the same thing just go backwards too?
	while(daIS_F_RELOC_DATA(flags[vtable_rva]))
	{
		ulong32		dest_rva	=	*(ulong32*)&data[vtable_rva];
		dest_rva				=	ova2rva(dest_rva);

		if (this->is_addr_in_range(dest_rva))
		{
			if (daIS_F_EXECUTABLE_AREA(flags[dest_rva]) && 
				daIS_F_INSTR(flags[dest_rva]) &&
				daIS_F_HEAD(flags[dest_rva]))
			{
				// this is a correct destination
				list->push_back((_dbasicblock*)dest_rva);

#if DA_DEBUG_IT == 1
			flog("*** write_vtable_to_basicblock_list: Adding %08x (%08x) to the list %08x (vtable at %08x (%08x))\r\n",
					dest_rva,
					orva2va(dest_rva),
					list,
					vtable_rva,
					orva2va(vtable_rva));
#endif

			}
		}
		vtable_rva		+= sizeof(ulong32);
	}

	return D_OK;
}




/*
* Function finds basicblock by rva addr
*/

_dbasicblock *DAnalyze::find_basicblock(ulong32 rva_addr)
{

	if (this->BasicBlockMap.empty())
		return 0;

	type_BBMap::iterator it = this->BasicBlockMap.find(rva_addr);
	if (it != this->BasicBlockMap.end())
		return it->second;


#if DA_DEBUG_IT == 1
			flog("*** find_basicblock for rva=%08x (%08x) failed!\r\n",
				rva_addr,
				orva2va(rva_addr));
#endif	

	this->bb_not_resolved++;
	return 0;
}



/*
* Function resolves the addrs from the basicblock lists.
* Additionally it also creates ParentsList for selected basicblock
* And generates final checksum
*/

int DAnalyze::resolve_basicblock_informations(void)
{
	if (this->BasicBlockList.empty())
		return D_FAILED;


	// loop through every basicblock
	for (int i = 0; i < this->BasicBlockList.size(); i++)
	{
		_dbasicblock *bb = this->BasicBlockList[i];

		// now important thing if ChidList and ChildFunctionsList
		// is allocaed but it does not contains any elements FREE IT
#define safe_check_list(list)	{		if (list)		{					\
											if (list->size() == 0)	{		\
												delete list;				\
												list	=	NULL;			\
											} } }


		safe_check_list(bb->ChildsList);
		safe_check_list(bb->ChildFunctionsList);

		this->resolve_basicblock_list(bb->ChildFunctionsList);
		this->resolve_basicblock_list(bb->ChildsList);


		// try to merge basicblock if possible
		this->add_parents_to_basicblock(bb);
	}

	this->try_to_merge_basicblocks();
	return D_OK;
}



/*
* Function tries to merge two basicblocks (recursive!)
*/

BOOL	DAnalyze::merge_with_parent(_dbasicblock *bb)
{
	_dcrc			crc;
	_dinstr			*instr;
	_dbasicblock	*bb_child, *bb_temp;
	type_flags		*flags = this->BinData.flags;
	BOOL			jmp_merge_mode	=	FALSE;

	// if the parent was already merged good bye
	if (daIS_F_BB_MERGED(bb->flags))
		return FALSE;


try_again:;
	if (bb->ChildsList)
	{
		if (bb->ChildsList->size() != 1)
			return FALSE;

		// we have one child only, now we need to check the child
		bb_child = (*bb->ChildsList)[0];

		// we can't marge the same block with the same block man
		// see ntdll
		/*
			.text:000279AE                 and     [ebp+var_8], 0
			.text:000279B2                 lea     eax, [ebp+var_8]
			.text:000279B5                 push    eax
			.text:000279B6                 push    1
			.text:000279B8                 mov     [ebp+var_4], 80000000h
			.text:000279BF                 call    _ZwDelayExecution@8 ; ZwDelayExecution(x,x)
			.text:000279C4                 jmp     short loc_279AE
		*/

		if ((ulong32)bb_child == (ulong32)bb)
			return FALSE;


		if (IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_child))
			return FALSE;

		// if the child was referenced by relocs we cant merge it
		if (daIS_F_RELOC_XREF(flags[bb_child->rva_start]))
			return FALSE;


		if (bb_child->ParentsList->size() != 1)
		{
			if (!daIS_F_INSTR_JMP(flags[bb->rva_start]))
				return FALSE;

			return this->merge_with_parent_jmp(bb, bb_child);

			//jmp_merge_mode	=	TRUE;
		}

#if DA_DEBUG_IT == 1
		flog("*** try_to_merge_basicblocks() merging parent %08x (%08x) with %08x (%08x)!\r\n",
				bb->rva_start,
				orva2va(bb->rva_start),
				bb_child->rva_start,
				orva2va(bb_child->rva_start));
		flog("*** recursive scanning!\r\n");
#endif	


		// but firstly we need to take the recursive guess
		// fixed: make sure the child structure was not changed
		if (this->merge_with_parent(bb_child))
			goto try_again;


		// ok we can merge it
		// parent->child = child->child (if any)
		// set new basicblock flags
		daSET_F_BB_MERGED(&bb->flags);

		// check if the child was a function
		// because if it was (the parent is now a function)
		if (daIS_F_BB_FUNCTION_START(bb_child->flags))
		{
			daSET_F_BB_FUNCTION_START(&bb->flags);
		

#if DA_DEBUG_IT == 1
		flog("*** try_to_merge_basicblocks() NOWFUNCTION parent %08x (%08x) from %08x (%08x)!\r\n",
				bb->rva_start,
				orva2va(bb->rva_start),
				bb_child->rva_start,
				orva2va(bb_child->rva_start));
		flog("*** recursive scanning!\r\n");
#endif			
		}


		daSET_F_BB_TODELETE(&bb_child->flags);
		bb->ChildsList->clear();
		delete bb->ChildsList;
		bb->ChildsList	=	0;
	

		// if parent was just a unconditional jump
		// we need to process ParentsList also
		if (jmp_merge_mode)
		{
			if (bb_child->ParentsList)
			{
				if (!bb->ParentsList)
					bb->ParentsList = new type_BBParents;


				for (int k = 0; k < bb_child->ParentsList->size(); k++)
				{
					_dbasicblock	*bb_temp	=	(*bb_child->ParentsList)[k];
					
					// skip the currently processed one
					if ((ulong32)bb_temp == (ulong32)bb)
						continue;

					// add the found parent to bb as a parent also
					bb->ParentsList->push_back(bb_temp);

					// fix the child addr in the bb_temp
					// point it child to bb
					for (int kk = 0; kk < bb_temp->ChildsList->size(); kk++)
					{
						if ((*bb_temp->ChildsList)[kk] == bb_child)
						{
#if DA_DEBUG_IT == 1
							flog("*** merge_with_parent()	exchanging childs bb=%08x childOfChild=%08x\r\n",
								bb->rva_start,
								bb_temp->rva_start);
#endif

							(*bb_temp->ChildsList)[kk]	=	bb;
						}
					}


				// same thing for bb_temp->ChildFuncsList
				if (bb_temp->ChildFunctionsList)
				{
					for (int kk = 0; kk < bb_temp->ChildFunctionsList->size(); kk++)
					{
						if ((*bb_temp->ChildFunctionsList)[kk] == bb_child)
						{
#if DA_DEBUG_IT == 1
							flog("*** merge_with_parent()	exchanging ChildFunctions bb=%08x childOfChild=%08x\r\n",
								bb->rva_start,
								bb_temp->rva_start);
#endif

							(*bb_temp->ChildFunctionsList)[kk]	=	bb;
						}
					}
				}

				}  // for all bb_child parents

				delete bb_child->ParentsList;
			} // if bb_child has parents
		} // if jmp merge


		if (bb_child->ChildsList)
		{
			bb->ChildsList			=	bb_child->ChildsList;
			
			// if we have a child list (in bb_child)
			// we need to update exchange-parents of the bb_child->Childs
			// to point to the merged block
			for (int k = 0; k < bb_child->ChildsList->size(); k++)
			{
				_dbasicblock	*bb_temp	=	(*bb_child->ChildsList)[k];
				if (IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_temp))
					continue;

				// there must be at least one parent pointing to bb_child
				for (int kk = 0; kk < bb_temp->ParentsList->size(); kk++)
					if ((*bb_temp->ParentsList)[kk] == bb_child)
					{


#if DA_DEBUG_IT == 1
						flog("*** merge_with_parent()	exchanging parents bb=%08x childOfChild=%08x\r\n",
							bb->rva_start,
							bb_temp->rva_start);
#endif

						(*bb_temp->ParentsList)[kk]	=	bb;
					}
			}

			bb_child->ChildsList	=	NULL;
		}

		// but now we need to append the ChildFunctionList from child to the parent
		if (bb_child->ChildFunctionsList)
		{
			if (!bb->ChildFunctionsList)
				bb->ChildFunctionsList	=	new 	type_BBChildFunctions;
				// now append all of the elements
			for (int j = 0; j < bb_child->ChildFunctionsList->size(); j++)
			{
				bb->ChildFunctionsList->push_back((*bb_child->ChildFunctionsList)[j]);
			}
			delete bb_child->ChildFunctionsList;
			bb_child->ChildFunctionsList	=	NULL;
		}

		// now we need to update the checksum
		// take the checksum from the child
		// and add it to the parent checksum but remove the linking instruction (jmp)
		// from the parent checksum before
		// so in other words checksum everything except the last instruction
		this->Checksum->reset_checksum();
		ulong32 arva = bb->rva_start;
		//while (arva < bb->rva_end)
		while (1)
		{
			type_flags	iflags2	=	flags[arva];
			if (daIS_F_BB_END(iflags2))
				break;

			instr = this->get_dinstr_from_rva(arva);
			assert(instr);

#ifndef _BINSHEP
			this->set_bytes_for_checksum(bb, instr, iflags2);
			this->Checksum->inc_instruction_counter();
#endif

			arva += instr->len;
		}

#ifndef _BINSHEP
			// now write the checksum
		crc	=	this->Checksum->compute_checksum_full(  get_list_size(bb->ChildsList),
													get_list_size(bb->ParentsList),
													get_list_size(bb->ChildFunctionsList));
		// now update the rest of the checksum
		//crc.crc_elements.symbols_num	=	bb->crc.crc_elements.symbols_num	+ bb_child->crc.crc_elements.symbols_num;
		crc.crc_elements.instr_num		+=	bb_child->crc.crc_elements.instr_num;
		crc.crc_elements.byte_crc		+=	bb_child->crc.crc_elements.byte_crc;
		crc.crc_adler					+=	bb_child->crc.crc_adler;
		
		crc.crc_elements.mem_act		|=	bb_child->crc.crc_elements.mem_act;
		crc.crc_elements.uses_imm		|=	bb_child->crc.crc_elements.uses_imm;
		crc.crc_elements.uses_memimm	|=	bb_child->crc.crc_elements.uses_memimm;	
		crc.crc_elements.uses_memimm_relocable	|=	bb_child->crc.crc_elements.uses_memimm_relocable;
		crc.crc_elements.uses_mem		|=	bb_child->crc.crc_elements.uses_mem;		
		crc.crc_elements.tttn			|=	bb_child->crc.crc_elements.tttn;

		bb->crc							=	crc;
#endif
			
		// now its important to see if we have merged a block
		// that was merged before
		// first of all add this block to the merged list
		bb->MergedList		=	new type_BBMerged;
		assert(bb->MergedList);
		bb->MergedList->push_back(bb_child);
			// change the child destination on the map
		type_BBMap::iterator	it_map	=	this->BasicBlockMap.find(bb_child->rva_start);
		assert(it_map != this->BasicBlockMap.end());
		it_map->second					=	bb;
		//this->BasicBlockMap.erase(it_map);

		// now check if the child was also merged if so
		// add its merged list to the current one
		//bp(bb_child->rva_start,0x0001108c);
		if (bb_child->MergedList)
		{
			// also change the map entry
			for (int j = 0; j < bb_child->MergedList->size(); j++)
			{
				bb_temp = (*bb_child->MergedList)[j];
				bb->MergedList->push_back(bb_temp);
				this->BasicBlockMap.find(bb_temp->rva_start);
				assert(it_map != this->BasicBlockMap.end());
				it_map->second					=	bb;
			}
				// now we can release the child merged list since it was copied
			delete bb_child->MergedList;
			bb_child->MergedList	=	NULL;
		}	
		return TRUE;
	}
	return FALSE;
}


/*
* Function tries to merge parent (which only contains of one JMP instruction)
* with child
* Algo:
* + add bb (parent) parents to the child (vise versa)
*   mark the parent (bb) as not suitable for fingerprint 
*/

BOOL DAnalyze::merge_with_parent_jmp(_dbasicblock *bb, _dbasicblock *bb_child)
{


#if DA_DEBUG_IT == 1
	flog("%s: jmp=%08x -> child: %08x\r\n",
		__FUNCTION__,
		bb->rva_start,
		bb_child->rva_start);
#endif

	daSET_F_BB_MERGED(&bb->flags);
	
	// but firstly we need to take the recursive guess
	this->merge_with_parent(bb_child);

	// check if the child was a function
	// because if it was (the parent is now a function)
	if (daIS_F_BB_FUNCTION_START(bb_child->flags))
	{
		daSET_F_BB_FUNCTION_START(&bb->flags);
	}

	daSET_F_BB_TODELETE(&bb->flags);


	// travel through the parent parents
	// and update the childlists 
	if (bb->ParentsList)
	{
		for (int i = 0; i < bb->ParentsList->size(); i++)
		{
			_dbasicblock *bb_temp	=	(*bb->ParentsList)[i];
			for (int kk = 0; kk < bb_temp->ChildsList->size(); kk++)
			{
				if ((*bb_temp->ChildsList)[kk] == bb)
					(*bb_temp->ChildsList)[kk] = bb_child;
			}
		}
	}

	// erase the parent from child
	if (bb_child->ParentsList)
	{
		for (int i = 0; i < bb_child->ParentsList->size(); i++)
		{
			_dbasicblock *bb_temp	=	(* bb_child->ParentsList)[i];
			if ((ulong32)bb_temp	==	(ulong32)bb)
				bb_child->ParentsList->erase(bb_child->ParentsList->begin()+i);
		}
	}
	// append parent parents to child
	// and delete parent lists


	if (bb->ParentsList)
	{
		if (!bb_child->ParentsList)
		{
			bb_child->ParentsList = new type_BBParents;
			assert(bb_child->ParentsList);
		}

		bb_child->ParentsList->insert(bb_child->ParentsList->begin(), bb->ParentsList->begin(), bb->ParentsList->end());
	}

	// delete
	delete bb->ParentsList;
	delete bb->ChildsList;
	bb->ParentsList	=	NULL;
	bb->ChildsList	=	NULL;

	return TRUE;
}


/*
* Function tries to merge two basicblocks
*/

BOOL	DAnalyze::try_to_merge_basicblocks(void)
{
	_dcrc			crc;
	_dinstr			*instr;
	_dbasicblock	*bb, *bb_child, *bb_temp;
	type_flags		*flags = this->BinData.flags;


	
#ifndef _BINSHEP



	// we need to travel through all the basicblocks :(
	for (int i = 0; i < this->BasicBlockList.size(); i++)
	{
		// if the basicblock bb has one child and this one child
		// has one parent we are ready for merging
		bb	=	this->BasicBlockList[i];

		this->merge_with_parent(bb);

	}


#endif

	// todo: optimize this shit
	// travel again and make the fingerprints
	// and make function structures
	for (int i = 0; i < this->BasicBlockList.size(); i++)
	{
		bb	=	this->BasicBlockList[i];
	
#ifndef _BINSHEP
		// if this block should be deleted then
		if (daIS_F_BB_TODELETE(bb->flags))
		{
//			this->BasicBlockList.erase(this->BasicBlockList.begin()+i);
//			i--;
			continue;
		}	
	

		this->Diff->make_basicblock_fingerprint(bb);
#endif

		
		if (daIS_F_BB_FUNCTION_START(bb->flags))
			this->new_function(bb);


	}


	return FALSE;
}


/*
* Function resolves the rva_addrs from the list, and changes them to the
* factual basicblock location
*/

void	DAnalyze::resolve_basicblock_list(type_BBChildFunctions *list)
{

	if ((ulong32)list == NULL)
		return;

	for (int i = 0; i < list->size(); i++)
	{
		ulong32 bb_rva		=	(ulong32)(*list)[i];
		_dbasicblock *bb		=	this->find_basicblock(bb_rva);
		if (bb)
			(*list)[i]		=	bb;
		else	// if the basicblock was not found report it
			(*list)[i]		=	(_dbasicblock*)SET_BASICBLOCK_NOTRESOLVED(bb_rva);
	}
}


/*
* Function writes the current basicblock as a parent for all the
* basicblock mentioned in clist. This must be called after
* clist is resolved by "resolve_bb_list"
*/

void	DAnalyze::add_parents_to_basicblock(_dbasicblock *bb)
{
	type_BBChilds *clist	=	bb->ChildsList;

	if (clist == NULL)
		return;

	for (int i = 0; i < clist->size(); i++)
	{
		_dbasicblock *bb_child = (*clist)[i];

		if (IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_child))
		{


//#if DA_DEBUG_IT == 1
			flog("*** add_parents_to_basicblock request_from=%08x (%08x) to add %08x failed!\r\n",
				bb->rva_start,
				orva2va(bb->rva_start),
				bb_child);
//#endif	

			//__asm int 3;
			debug_break;
			continue;
		}


		if (!bb_child->ParentsList)
			bb_child->ParentsList	=	new type_BBParents;

		// now add the current bb to destination
		bb_child->ParentsList->push_back(bb);

		// each time we add the parent we need to update the checksum
		bb_child->crc.crc_elements.parents_num += 1;
	

	}
}