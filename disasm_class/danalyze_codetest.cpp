#include "danalyze.h"


/*
* Function tries to guess if following RVA 
* can be treated as CODE. Some sample heuristic
* method is used. It also marks bad locations as data.
*/

BOOL DAnalyze::can_be_code_using_disasm(ulong32 rva)
{
	BOOL		all_done;
	int			st;
	uchar		*p;
	ulong32		current_rva, temp_addr;
	_dis_data	dd;
	ulong64		defined_objs;
	type_flags	*flags;


#define MARK_AS_DATA(crva)	{	daSET_F_HEAD(&flags[crva]); daSET_F_DATA(&flags[crva]); }


	// first of all if this is a prologue or a function
	// matched by symbols report a valid one
	if (this->can_be_code_strict(rva))
		return TRUE;



	// if not we need to start disassembling	
	defined_objs	=	0;
	all_done		=	FALSE;
	current_rva		=	rva;

	flags			=	this->BinData.flags;
	

	for (int i = 0; i < MAX_HEURISTISC_INSTR; i++)
	{
		if (!this->is_addr_in_range(current_rva) || 
			!this->can_be_code_weak(current_rva))
			return FALSE;

		// disassembly failed? -> so go home
		p			=	(uchar*)lrva2va(current_rva);

		if (*(uword*)p == 0x0000)
		{
#if DA_DEBUG_IT == 1
				flog("***Warning: CanBeCodeDisasm start: %08x (%08x) NULLBYTES found! \r\n",
						rva,
						orva2va(rva));
#endif
			MARK_AS_DATA(rva);
			return FALSE;
		}

		st			=	_disasm(p, &dd);
		if	(!st) 
		{
#if DA_DEBUG_IT == 1
				flog("***Warning: CanBeCodeDisasm start: %08x (%08x) unable to disasm! \r\n",
						rva,
						orva2va(rva));
#endif

			MARK_AS_DATA(rva);
			return FALSE;
		}


		//this->debug_show_instruction(current_rva);

		// check if on its range there was no symbol defined
		for (int j = 0; j < dd.len; j++)
		{

			// also check if there is reloc information inside of the function bytes
			// and it overlaps with the next one
			if ((dd.len <= sizeof(ulong32)) || ((dd.len - j) < sizeof(ulong32)))
			{
				if (daIS_F_HEAD(flags[current_rva+j]) && daIS_F_RELOC_DATA(flags[current_rva+j]))
				{
#if DA_DEBUG_IT == 1
					flog("***Warning: CanBeCodeDisasm start: %08x (%08x) found relocdata at %08x (%08x) (this is not code) \r\n",
						rva,
						orva2va(rva),
						current_rva+j,
						orva2va(current_rva+j));
#endif

					MARK_AS_DATA(rva);

#if DA_DEBUG_IT == 1
					this->debug_show_instruction(current_rva);
#endif
					return FALSE;
				}
			}


			_sinfo *sInfo = this->Symbols->get_symbol_info(rva+j);
			if (sInfo)
			{
				if (sInfo->type == SYMBOL_DATA)
				{
#if DA_DEBUG_IT == 1
					flog("***Warning: CanBeCodeDisasm start: %08x (%08x) found data symbol at %08x (%08x) (this is not code) \r\n",
						rva,
						orva2va(rva),
						current_rva+j,
						orva2va(current_rva+j));
#endif
					MARK_AS_DATA(rva);

#if DA_DEBUG_IT == 1
					this->debug_show_instruction(current_rva);
#endif

					return FALSE;
				}
				else
				{
					// symbol is a function or data
					// check somewhere in the middle of instruction if so it is bad
					if (j > 1)
					{
#if DA_DEBUG_IT == 1
						flog("***Warning: CanBeCodeDisasm start: %08x (%08x) found unknown symbol at %08x (%08x) (this is not code) \r\n",
							rva,
							orva2va(rva),
							current_rva+j,
							orva2va(current_rva+j));
#endif
						MARK_AS_DATA(rva);

#if DA_DEBUG_IT == 1
						this->debug_show_instruction(current_rva);
#endif

						return FALSE;
					}
				}
			} // symbol if found
		} // for dd.len


		// if something uses mem_imm and it is a NULL, mark this as bad also
		//00003d54 (00403d54) lea eax,[ecx*4+00h]
		// except LEA sponsored by NTOSKRNL
		if (((dd.emul_int != LEA_0)) && (disit_isDF_MEM_IMM(dd.dflags) && (dd.mem_imm == 0)))
		{
			// no segment registers before
			// push dword ptr fs:[0] is valid

			if (!disit_isDF_PrefixSEG(dd.dflags))
			{
#if DA_DEBUG_IT == 1
				flog("***Warning: CanBeCodeDisasm start: %08x (%08x) instr at: %08x (%08x) using mem_imm=NULL \r\n",
						rva,
						orva2va(rva),
						current_rva,
						orva2va(current_rva));
#endif
				MARK_AS_DATA(rva);	// ->> ??

#if DA_DEBUG_IT == 1
				this->debug_show_instruction(current_rva);
#endif
			}

			return FALSE;

		}

		// first of all check if the (mem_regs|sib_mul_reg) are also 
		// located in the i_obj_src (this should never happen in real code)
		// limits this to 32bit registers
		// (except LEA)
		//  mov     eax, [eax] <-- good
		//  mov		[eax],eax  <-- bad?

		//bp(current_rva,0x0005649b);
		ulong32 res = ((ulong32)dd.mem_regs | (ulong32)dd.sib_mul_reg) & (ulong32)dd.i_obj_src;
		if ((dd.emul_int != LEA_0) && (res) && (disit_is_DF_MEM_ACTDEST(dd.dflags)))
		{
			// if mem regs are not esp or ebp
			if ((dd.mem_regs) & ~(R_ESP|R_EBP))
			{
#if DA_DEBUG_IT == 1
				flog("***Warning: CanBeCodeDisasm start: %08x (%08x) instr at: %08x (%08x) using mem_obj with srcdest_obj \r\n",
						rva,
						orva2va(rva),
						current_rva,
						orva2va(current_rva));
#endif
			MARK_AS_DATA(rva);

#if DA_DEBUG_IT == 1
				this->debug_show_instruction(current_rva);
#endif

				return FALSE;
			}
		}


		switch(dd.emul_int)
		{
			// normal instruction
			default:
				break;
 			
			case RET_0:
			case RET_1:
			case RET_FAR_0:
			case RET_FAR_1:
			case IRET_IRETD_0:
			case INT_0x3_0:
			case HLT_0:
				all_done = TRUE;
				break;

			case JMP_3:
			case JMP_4:
				break;

				// jmp reg (reg must be initialized first)
			case JMP_1:
				if (!(defined_objs & dd.obj_src))
				{
#if DA_DEBUG_IT == 1
					flog("***Warning: CanBeCodeDisasm start: %08x (%08x) instr at: %08x (%08x) using reg which was not initialized \r\n",
						rva,
						orva2va(rva),
						current_rva,
						orva2va(current_rva));
					this->debug_show_instruction(current_rva);
#endif

					
					return FALSE;
				}

				all_done = TRUE;
				break;

				// call reg (reg must be initialized first)
			case CALL_1:
				if (!(defined_objs & dd.obj_src))
				{
#if DA_DEBUG_IT == 1
					flog("***Warning: CanBeCodeDisasm start: %08x (%08x) instr at: %08x (%08x) using reg which was not initialized \r\n",
						rva,
						orva2va(rva),
						current_rva,
						orva2va(current_rva));
					this->debug_show_instruction(current_rva);
#endif

					return FALSE;
				}
				break;


				// conditional stuff
				// just test if the flags were defined before
				case LOOPNE_0:
				case LOOPE_0:
				case JCC_0:
				case JCC_1:
				case JECXZ_0:
				case LOOP_0:
					if (!(D_SHOW_FLAGS(defined_objs) & dd.obj_src))
					{

#if DA_DEBUG_IT == 1
						flog("***Warning: CanBeCodeDisasm start: %08x (%08x) instr at: %08x (%08x) using flags which were not initialized \r\n",
							rva,
							orva2va(rva),
							current_rva,
							orva2va(current_rva));
						this->debug_show_instruction(current_rva);
#endif

						MARK_AS_DATA(rva);
						return FALSE;
					}
					break;


					// jmp REL
					// we dont follow calls, we just test the destination
					case JMP_SHORT_0:
					case JMP_0:
						all_done = TRUE;
					// call REL
					case CALL_0:
						temp_addr = (current_rva + dd.len + dd.imm_data);

						// if temp_addr is invalid this is a bad region
						if (!this->is_addr_in_range(temp_addr)	||
							!this->can_be_code_weak(temp_addr))
						{

#if DA_DEBUG_IT == 1
							flog("***Warning: CanBeCodeDisasm start: %08x (%08x) instr at: %08x (%08x) -> invalid DEST operand \r\n",
								rva,
								orva2va(rva),
								current_rva,
								orva2va(current_rva));
							this->debug_show_instruction(current_rva);
#endif
							MARK_AS_DATA(rva);
							return FALSE;
						}
						break;

						// JMP [MEM] / CALL[MEM]
						case JMP_2:
							all_done = TRUE;
						case CALL_2:
							break;
		} // switch dd.emul_int


		// if ret was found or something, break the loop
		if (all_done)
			break;

		defined_objs	|=	dd.obj_dest;

		// next instruction
		current_rva	+=	dd.len;
	} // for XX instructions



	// ret/jmp/call was found so mark this as a good location
	if (all_done)
	{
#if DA_DEBUG_IT == 1
			flog("***Warning: CanBeCodeDisasm start: %08x (%08x) -> SEEMS TO BE CORRECT \r\n",
						rva,
						orva2va(rva));
#endif
			return TRUE;
	}

	return FALSE;// test

	// check if this is ascii
	if (this->can_be_ascii((uchar*)lrva2va(rva)) >= MAX_ASCII_CHARS)
	{

#if DA_DEBUG_IT == 1
			flog("***Warning: CanBeCodeDisasm start: %08x (%08x) found more than %d ascii chars \r\n",
						rva,
						orva2va(rva),
						MAX_ASCII_CHARS);
#endif

		return FALSE;
	}



	return TRUE;
}



/*
* Function adds new location to ProspectFutureAddr list
*/

void DAnalyze::set_future_addr_prospect(ulong32 rva_addr)
{
	type_flags *flags = this->BinData.flags;
	daSET_F_LABEL(&flags[rva_addr]);
	daSET_F_PROSPECT(&flags[rva_addr]);

	this->ProspectAddrList.push_back(rva_addr);

#if DA_DEBUG_IT == 1
			flog("*** set_future_addr_prospect() adding %08x to prospect list\n",
				rva_addr);
#endif
}



/*
* Function checks rva and the instruction at rva
* (if it overlaps with another instruction)
*/

type_addr DAnalyze::is_prospect_rva_good(ulong32 rva, _dinstr *di)
{
	
	type_flags	*flags		=	this->BinData.flags;

	// check this addr, maybe it was analyzed before
	// or it is not correct
	if (!this->is_addr_in_range(rva))
	{

#if DA_DEBUG_IT == 1
					flog("*** is_prospect_rva_good() -> RVA %08x not in range!\r\n",
							rva);
#endif

		return TADDR_INVALID;
	}


	// check if this is a executable area
	// so not reloc data, not data, not import data
	if (!this->can_be_code_weak(rva))
	{

#if DA_DEBUG_IT == 1
		flog("*** is_prospect_rva_good() -> RVA %08x is invalid!! (canbecode() - failed)\r\n", rva);
#endif
		return TADDR_INVALID;
	}




	// it is in range, so now check if it points to something
	// that was analyzed before
	if (daIS_F_ANALYZED(flags[rva]))
	{
		// if it was analyzed it must be the head
		// or something is wrong
		if (daIS_F_HEAD(flags[rva]))
		{

#if DA_DEBUG_IT == 1
			flog("*** is_prospect_rva_good() -> RVA %08x already analyzed!\r\n", rva);
#endif

			return TADDR_ANALYZED;
		}


#if DA_DEBUG_IT == 1
		flog("*** is_prospect_rva_good() -> RVA %08x is a tail!!\r\n", rva);
#endif

		// if not report a bad area
		return TADDR_INVALID;
	}



	return TADDR_GOOD;
}