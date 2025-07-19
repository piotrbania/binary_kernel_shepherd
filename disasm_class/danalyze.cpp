#include "danalyze.h"


/* 
* Class Constructor 
*/

DAnalyze::DAnalyze()
{

	this->ready		=	FALSE;
	this->Symbols	=	NULL;

	memset((void*)&this->BinData,0,sizeof(_bin_data));

	this->ProspectAddrList.clear();
	this->FutureAddrList.clear();
	this->InstrList.clear();
	this->BasicBlockList.clear();
	this->BasicBlockMap.clear();
	this->ReferenceMap.clear();

	this->Checksum		=	new DChecksum();
	this->Diff			=	new DDiff();

}


/*
* Class Destructor
*/

DAnalyze::~DAnalyze()
{

	// free all memory
	SAFE_DELETE(this->BinData.data);
	SAFE_DELETE(this->BinData.flags);
	SAFE_DELETE(this->BinData.fast_instrs);
	SAFE_DELETE_C(this->Symbols);
	SAFE_DELETE_C(this->Checksum);
	SAFE_DELETE_C(this->Diff);

	// delete all instructions and basicblocks
	for (int i = 0; i < this->BasicBlockList.size(); i++)
	{

#define SAFE_LIST_DELETE(x)	{ if (x) { x->clear(); delete x; } }

		_dbasicblock *bb	=	this->BasicBlockList[i];
		SAFE_LIST_DELETE(bb->ChildsList);
		SAFE_LIST_DELETE(bb->ParentsList);
		SAFE_LIST_DELETE(bb->ChildFunctionsList);
		SAFE_LIST_DELETE(bb->MergedList);
	
		SAFE_DELETE(this->BasicBlockList[i]);
	}


	for (int i = 0; i < this->FunctionList.size(); i++)
		SAFE_DELETE(this->FunctionList[i]);


	for (type_InstrList::iterator it = this->InstrList.begin(); 
		it != this->InstrList.end(); it++)
	{
		//_dinstr *di = *it;
		//SAFE_DELETE(di);
		SAFE_DELETE(*it);
	}


//	ReferenceMap
	for (type_ReferenceMap::iterator it = this->ReferenceMap.begin();
		it != this->ReferenceMap.end(); it++)
	{
		//_reference_entry	*r_entry = it->second;
		//delete r_entry;
		SAFE_DELETE(it->second);
	}


	this->ProspectAddrList.clear();
	this->FutureAddrList.clear();
	this->InstrList.clear();
	this->BasicBlockList.clear();
	this->BasicBlockMap.clear();
	this->ReferenceMap.clear();

}

/*
* Function checks if current_rva is located at the execuable area. If it is correct
* nothing is done. Othwerise function scans entire region for next executable area
* updating offset per PAGE_SIZE each time.
*/

ulong32 DAnalyze::get_next_executable_rva(type_flags *flags, ulong32 current_rva)
{
	ulong32 rva = current_rva;

	// is this one correct?
	if (daIS_F_EXECUTABLE_AREA(flags[rva]))
		return rva;

	// get next executable section
	PIMAGE_SECTION_HEADER pSHc = this->pSH;
	for (int i = 0; i < this->pPE->FileHeader.NumberOfSections; i++)
	{
		if (pSHc[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			if (current_rva < pSHc[i].VirtualAddress)
				return pSHc[i].VirtualAddress;
		}
	}

	return D_NOMEM;	// nothing found


	/*
	// if not let the party started
	rva = rva & (this->sec_align - 1);	// section align
	do
	{
		rva	+=	this->sec_align;
		if (rva >= this->BinData.data_size)
			return D_NOMEM;
		
	} while (!daIS_F_EXECUTABLE_AREA(flags[rva]));
	*/

	return rva;
}


/*
* Function checks if api function (api name) is not comming
* back 
* Basic check for now KeBugCheckEx/ExitProcess/ExitThread
* later add some table with checksums
* this is only executed onces (while parsing the import section)
*/
BOOL DAnalyze::is_deadend_import_api(char	*api_name)
{
#define is_bad_name(name) if (strncmp(api_name, name, sizeof(name)-1) == 0) return TRUE;
#define is_bad_name_equal(name) if (strcmp(api_name, name) == 0) return TRUE;


	

	if (!api_name)
		return FALSE;

	while ((*api_name == '_') || (*api_name == '?')) 
		api_name++;

/*
	_KeBugCheckEx@20
	_KeBugCheck@4
	_KeBugCheck2@24

	- some valid functions with KeBugCheck string exist so
	we cant make it short
	
	*/

	
	is_bad_name_equal("KeBugCheckEx");
	is_bad_name_equal("KeBugCheck");

	is_bad_name("KeBugCheckEx@20");
	is_bad_name("KeBugCheck@4");
	is_bad_name("KeBugCheck2@24");
	is_bad_name("ExitProcess");
	is_bad_name("ExitThread");
	is_bad_name("FreeLibraryAndExitThread");

	is_bad_name("PoShutdownBugCheck");
	is_bad_name("MiIssueNoPtesBugcheck");
	is_bad_name("PopInternalError");
	is_bad_name("RtlExitUserThread");
	is_bad_name("ZwRaiseException");
	is_bad_name("ExRaiseStatus");

	is_bad_name("RpcRaiseException");
	is_bad_name("RaiseException");
	is_bad_name("NdrpRaisePipeException");

	is_bad_name("CxxThrowException");
	is_bad_name("PspUnhandledExceptionInSystemThread");

	is_bad_name("NtBuildGUID");
	is_bad_name("NtBuildLab");
	is_bad_name("NtBuildNumber");
	is_bad_name("FsRtlLegalAnsiCharacterArray");

	return FALSE;
}



/*
* Function counts ascii chars at p 
*/

int	DAnalyze::can_be_ascii(uchar *p)
{
	int len = 0;

	//while (isascii(*p++))
	//	len++;

	while(1)
	{
		if (!(*p >= 'a' && *p <= 'z') && 
			!(*p >= 'A' && *p <= 'Z') &&
			!(*p >= '0' && *p <= '9') && 
			!(*p == '_') &&
			!(*p == '@') && 
			!(*p == '.'))
		   break;
		len++;
		p++;
	}



	return len;
}

/*
* Function counts number of unicode characters
* XX00XX00...
*/

int	DAnalyze::can_be_unicode(uchar *p)
{
	int len = 0;

	while ((p[len] != 0) && (p[len+1] == 0))
		len += 2; 

	return len;
}


/*
* Function tries to guess if following RVA 
* can be treated as CODE. This is weak.
* This is the more strict version.
*/

BOOL DAnalyze::can_be_code_strict(ulong32 rva)
{
	_sinfo							*sInfo;
	type_flags						flags = this->BinData.flags[rva];

	// firslty check if rva is in executable range
	if (!daIS_F_EXECUTABLE_AREA(flags))
		return FALSE;

	// secondly check if it is not reloc data or import data
	if (daIS_F_RELOC_DATA(flags) || daIS_F_IMPORT_DATA(flags))
		return FALSE;

	// if this is tail we have a problem
	if (daIS_F_TAIL(flags))
	{
#if DA_DEBUG_IT == 1
		flog("***Warning: CanBeCode at %08x (tail) -> head %08x. \r\n",
			orva2va(rva),
			orva2va(daFIND_HEAD(this->BinData.flags, rva)));
#endif

		return FALSE;
	}

	// try to get the symbol type
	sInfo = this->Symbols->get_symbol_info(rva);
	if (sInfo)
	{
		if (sInfo->type == SYMBOL_FUNCTION)
			return TRUE;
	}


	// now do the signature matching
	// scan for push ebp, mov ebp,esp
	return this->is_prologue(rva);
}


/*
* Function scans rva location for prologue signature
*/


struct _sigs
{
	ulong32		sig_bytes;
	ulong32		sig_mask;
};

_sigs prologue_sigs[]	=	{
	{0x8B55FF8B, 0xFFFFFFFF},
	{0x00EC8B55, 0x00FFFFFF}
	//0xFF8B,		// 8B  FF	-> mov edi,edi, 
	//0x8B55		// 55  8B EC  -> push ebp, part mov
};
#define prologue_sigs_size ((sizeof(prologue_sigs)/sizeof(_sigs)))

BOOL DAnalyze::is_prologue(ulong32 rva, BOOL strict_mode)
{
	for (int i = 0; i < prologue_sigs_size; i++)
	{

		if ((*(ulong32*)lrva2va(rva) & prologue_sigs[i].sig_mask) ==
			prologue_sigs[i].sig_bytes)
			return TRUE;


		/*
		if (*(uword*)lrva2va(rva) == prologue_sigs[i])
		{
			if (strict_mode && (i == 0))
			{
				// mov edi,edi must be followed by push ebp mov
				if (*(uword*)lrva2va(rva+sizeof(uword)) == prologue_sigs[i+1])
					return TRUE;
			}
			else
			{
				return TRUE;
			}
		}
		*/
	}

	// additional test for:
	// 0x6A XX			push    10h
	// 0x68 XX XX XX XX push    offset stru_199730
	// 0xE8				call    __SEH_prolog
	uchar	*p = (uchar*)lrva2va(rva);

	if ((p[0] == 0x6A) &&
		(p[2] == 0x68) &&
		(p[7] == 0xE8))
		return TRUE;


	return FALSE;
}

/*
* Function tries to guess if following RVA 
* can be treated as CODE. This is less strict
* (especially for EXPORTED data). We assume
* everything that is exported, located in the
* code section is a function :( Not really good
*/


BOOL DAnalyze::can_be_code_weak(ulong32 rva)
{
	_sinfo							*sInfo;
	type_flags						flags = this->BinData.flags[rva];

	// check if rva is in executable range
	// and this is not import or reloc data
	if (!daIS_F_EXECUTABLE_AREA(flags) || 
		daIS_F_RELOC_DATA(flags) || 
		daIS_F_IMPORT_DATA(flags) ||
		daIS_F_DATA(flags))
		return FALSE;

	return TRUE;
}

/*
* Function adds all found by the symbols functions
* to FutureAddrList.
* Also it sets FUNC_DEAD on the found-bad-functions.
*/

int	DAnalyze::add_functions_symbols(void)
{
	ulong32		rva;
	type_flags	*flags = this->BinData.flags;

	// enumerate all symbol and find the function ones
	for (int i = 0;
		i < this->Symbols->SymbolVector.size();
		i++)
	{
		_sinfo *pSym = this->Symbols->SymbolVector[i];
		rva = pSym->addrRVA;

		daSET_F_HAS_SYMBOL(&flags[rva]);

		// is this is a bad api
		if (this->is_deadend_import_api(pSym->name))
		{

#if DA_DEBUG_IT == 1
				flog("*** DEADEND function from symbols: %08x (%08x) %s\r\n",
					pSym->addrRVA,
					lrva2va(pSym->addrRVA),
					pSym->name);
#endif
				// set the flags
				
				daSET_F_FUNC_DEADEND(&flags[pSym->addrRVA]);
		}


		if (pSym->type == SYMBOL_UNKNOWN)
		{
			this->add_vtable_entries(rva, TRUE);
		}
		else if (pSym->type == SYMBOL_FUNCTION)
		{
			
			// do the basic check
			if (this->can_be_code_weak(rva))
			{
				// add it to the list
				this->set_future_addr_function(rva,false);

#if DA_DEBUG_IT == 1
				flog("*** Function from symbols: %08x (%08x)\r\n",
					rva,
					lrva2va(rva));
#endif

			}
		}
		else if (pSym->type	== SYMBOL_DATA)
		{
			daSET_F_DATA(&flags[rva]);


#if DA_DEBUG_IT == 1
				flog("*** Data from symbols: %08x (%08x)\r\n",
					rva,
					lrva2va(rva));
#endif

		}
	}


	
	return D_OK;
}


/*
* Function adds all exported functions to FutureAddrList
* Notice: export section may include exported data
* so we need to apply some weak heuristisc here and
* assume every exported functions is stdcall (so it 
* should start with a standard prologue)
* Additionally test if it is located at the 
* executable area. 
*/

int	DAnalyze::add_functions_exports(void)
{

	uword*									ordinals;
	ulong32*								functions;       
	ulong32*								names;
	ulong32									f_addr;
	char*									c_name;
	BOOL									is_code;

	uchar		*p		=	this->BinData.data;
	type_flags	*flags	=	this->BinData.flags;

  
	ulong32 rva		=	this->pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;


	if ((this->pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size <= 0) ||
		(this->pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress <= 0))
	{

#if DA_DEBUG_IT == 1
		flog("*** No export data was found. \r\n");
#endif
		return D_FAILED;
	}


	pEXP		= (PIMAGE_EXPORT_DIRECTORY)((ulong32)rva + this->m_imagebase);

	functions	= (ulong32*)lrva2va(pEXP->AddressOfFunctions);
	ordinals	= (uword*)lrva2va(pEXP->AddressOfNameOrdinals);
	names		= (ulong32*)lrva2va(pEXP->AddressOfNames);

	for (int i = 0; i < pEXP->NumberOfNames; i++) 
	{
		// export by name
		f_addr		= (ulong32)functions[ordinals[i]];

		// see if it can be treated as code
		is_code			= this->can_be_code_weak(f_addr);

		int is_ascii	= this->can_be_ascii(&p[f_addr]);

		if (is_ascii >= MAX_ASCII_CHARS)
		{
#if DA_DEBUG_IT == 1
			flog("*** add_functions_exports(): exported symbol is a string!\r\n");
#endif

			is_code	=	0;
		}




		if (names[i])
		{
			c_name	= (char*)((ulong32)lrva2va(names[i]));
			

			// firstly check if it is not forbidden
			// added: 08.04.2011
			if (this->is_deadend_import_api(c_name))
			{
				is_code = 0;
			}


#if DA_DEBUG_IT == 1
			flog("*** Exported function: %s (%08x, %08x) isPotentialCode: %d \r\n",
				c_name,
				f_addr, 
				lrva2va(f_addr),
				is_code);
#endif

		}
		else
		{
	
#if DA_DEBUG_IT == 1
			flog("*** Exported ordinal: %d (%08x, %08x) isPotentialCode: %d\r\n",
				ordinals[i], 
				f_addr, 
				lrva2va(f_addr),
				is_code);
#endif
		}

		// add this RVA to FutureAddrList
		if (is_code)
		{
			this->set_future_addr_function(f_addr,false);
			daSET_F_FUNC_EXPORTED(&flags[f_addr]);
		}
	}



	return D_OK;
}


/*
* Function scans entire memory for reloc data and sees if it
* is suitable location for function code. If so it add it
* to the FutureAddrList
*/

int	DAnalyze::add_functions_relocs(void)
{

	ulong32		rva_start;
	uchar		*mem				=	this->BinData.data;
	type_flags	*flags				=	this->BinData.flags;


	for (rva_start = 0; rva_start < this->BinData.data_size; rva_start++)
	{
		// is this reloc data?
		if (daIS_F_RELOC_DATA(flags[rva_start]) && daIS_F_HEAD(flags[rva_start]))
		{
			// read the dword and conver it to RVA
			ulong32 dest_addr = ova2rva(*(ulong32*)&mem[rva_start]);

			// add more strict checking here?
			//if (this->is_addr_in_range(dest_addr) && this->can_be_code_weak(dest_addr))
			if (this->is_addr_in_range(dest_addr) && this->can_be_code_weak(dest_addr))
			{
				daSET_F_RELOC_XREF(&flags[dest_addr]);
				daSET_F_FUNCTION_START(&flags[dest_addr]);
				this->set_future_addr_prospect(dest_addr);
			}

			/*
			if (this->can_be_code_using_disasm(dest_addr))
			{
#if DA_DEBUG_IT == 1
				flog("*** FunctionFromReloc found at %08x (%08x) -? func: %08x (%08x)\r\n",
						rva_start,
						orva2va(rva_start),
						dest_addr,
						orva2va(dest_addr));
#endif

				// it seems to be ok, add it to the list
				this->set_future_addr(dest_addr);
			}
			*/

			rva_start += 3;	// each entry (4bytes)
		}

	}
	
//	__asm int 3;


	return D_OK;
}

/*
* Function adds all found functions by the heuristisc scan.
* Well it is hard to name it as heuristisc since it is
* only a signature scan so far.
*/

int	DAnalyze::add_functions_heuristics(void)
{
	PIMAGE_SECTION_HEADER			pSHc;


	// limit the scan to executable sections
	pSHc	=	this->pSH;
	for (int i = 0;
		i < this->pPE->FileHeader.NumberOfSections;
		i++, pSHc++)
	{
		if (pSHc->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			// scan entire section (slowwwwwwwww)
			ulong32 start_rva = pSHc->VirtualAddress;
			for (int j = 0; j < pSHc->SizeOfRawData; j++)
			{
				if (this->is_prologue(start_rva+j) && this->can_be_code_weak(start_rva+j))
				{
					//this->set_future_addr(start_rva+j);

					this->set_future_addr_function(start_rva+j,false);
#if DA_DEBUG_IT == 1
					flog("*** Heuristis Function found at %08x (%08x)\r\n",
						start_rva+j,
						orva2va(start_rva+j));
#endif

					// no prolog after a prolog right
					j	+= sizeof(ulong32);
				}

			}

		}
	}
	
	

	return D_OK;
}

/*
* Function adds all possible functions to FutureAddrList
*/

int	DAnalyze::add_functions_ep(void)
{
	ulong32	ep;
	type_flags	*flags = this->BinData.flags;

	// make sure we start with the not-reliable-ones

	this->add_functions_relocs();

	this->add_functions_heuristics();
	this->add_functions_exports();
	this->add_functions_symbols();
	
	ep = this->pPE->OptionalHeader.AddressOfEntryPoint;
	//this->set_future_addr(ep);
	this->set_future_addr_function(ep,false);
	daSET_F_FUNC_EXPORTED(&flags[ep]);
	return D_OK;
}


/*
* Function marks all import entries as daSET_F_IMPORT_DATA
*/
int DAnalyze::flag_imports(void)
{
	int								b;
	type_flags						*flags;
	ulong32							i_addr, first;
	PIMAGE_THUNK_DATA				thunk;
	PIMAGE_IMPORT_BY_NAME			iname;


	flags				=	this->BinData.flags;

	i_addr				= this->pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if ((i_addr <= 0) || (this->pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size <= 0))
		return D_FAILED;

	this->pIMP			=	(PIMAGE_IMPORT_DESCRIPTOR)lrva2va(i_addr);

	while ((pIMP->OriginalFirstThunk != 0) || (pIMP->FirstThunk != 0))
	{
		char	*dll_name = (char*)((ulong32)lrva2va(pIMP->Name));

		first = (pIMP->OriginalFirstThunk == 0 ? pIMP->FirstThunk:pIMP->OriginalFirstThunk);
		thunk = (PIMAGE_THUNK_DATA)(first + (ulong32)this->m_imagebase);


#if DA_DEBUG_IT == 1
		flog("***Imports from %s\r\n",dll_name);
#endif

		b		=	0;
		while ((DWORD)thunk->u1.Function != 0)
		{
			ulong32	api_addr	=	(ulong32)(pIMP->FirstThunk + b);// + this->m_imagebase);
			if (((DWORD)thunk->u1.Function & IMAGE_ORDINAL_FLAG32) == IMAGE_ORDINAL_FLAG32)
			{
				// import by ordinal 
#if DA_DEBUG_IT == 1
				flog("*** Import ordinal %d\r\n",thunk->u1.Ordinal);
#endif
				
			}
			else
			{
				/* import by name */
				iname = (PIMAGE_IMPORT_BY_NAME)((ulong32)thunk->u1.ForwarderString + this->m_imagebase);
				

#if DA_DEBUG_IT == 1
				flog("*** Import name %s (%08x, with base %08x)\r\n",iname->Name,
					api_addr,
					api_addr + this->m_imagebase);
#endif
				

				// check if the name is a dead-end api (not comming back)
				if (this->is_deadend_import_api((char*)iname->Name))
				{
#if DA_DEBUG_IT == 1
					flog("*** DEADEND API DETECTED!\r\n");
#endif

					// mark it as dead end
					daSET_F_IMPORT_DATA_DEADEND(&flags[api_addr]);
				}


			}

			// put the flag on entire dword
			daSET_F_HEAD(&flags[api_addr]);
			daSET_F_IMPORT_DATA(&flags[api_addr]);
			daSET_F_IMPORT_DATA(&flags[api_addr+1]);
			daSET_F_IMPORT_DATA(&flags[api_addr+2]);
			daSET_F_IMPORT_DATA(&flags[api_addr+3]);

			b += sizeof(DWORD);
			thunk++;
		}


		pIMP++;
	} //while pIMP

	
	return D_OK;
}

/*
* Function marks all relocs entries as daSET_F_RELOC_DATA
*/
int DAnalyze::flag_relocs(void)
{
	type_flags						*flags;
	PIMAGE_BASE_RELOCATION			pRE;
	int								entries;
	ulong32							addr;

#define reloc_members_num(x)		((x - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD))

	flags	=	this->BinData.flags;
	pRE		=	(PIMAGE_BASE_RELOCATION)((ulong32)this->m_imagebase + 
		(ulong32)this->pPE->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if ((ulong32)pRE == (ulong32)this->pMZ)
	{
		// no relocs
#if DA_DEBUG_IT == 1
		flog("*** No relocs found\r\n");
#endif
		return D_FAILED;
	}

#if DA_DEBUG_IT == 1
	flog("*** Relocs at %08x\r\n",(ulong32)pRE);
#endif

	while (pRE->SizeOfBlock != 0)
	{
		WORD			relocType;
		PWORD			pEntry;
		entries			= reloc_members_num(pRE->SizeOfBlock);
		
		pEntry			= (PWORD)((DWORD)pRE + (DWORD)sizeof(IMAGE_BASE_RELOCATION));

		for (int i=0; i < entries; i++ )
		{
			addr		= (DWORD)((*pEntry & 0x0FFF) + pRE->VirtualAddress);
			relocType	= (*pEntry & 0xF000) >> 12;		// najwyzsze 4 bity to typ

			if (relocType == IMAGE_REL_BASED_HIGHLOW)
			{
	
#if DA_DEBUG_IT == 1
				flog("*** Relocs entry at %08x\r\n",(ulong32)addr);
#endif
				// put the flag on entire dwrd
				daSET_F_HEAD(&flags[addr]);
				daSET_F_RELOC_DATA(&flags[addr]);
				daSET_F_RELOC_DATA(&flags[addr+1]);
				daSET_F_RELOC_DATA(&flags[addr+2]);
				daSET_F_RELOC_DATA(&flags[addr+3]);

			}
			pEntry++;
		}
		
		pRE = (PIMAGE_BASE_RELOCATION)((DWORD)pRE + (DWORD)pRE->SizeOfBlock);
	}

	return D_OK;
}

/*
* Function tests if the supplied rva is suitable for analysis:
* - contains code, was not analyzed before, is not tail etc.
*/

type_addr DAnalyze::is_future_addr_correct(ulong32 rva, bool remove)
{
	type_flags	*flags		=	this->BinData.flags;

	// make sure the location is in range and it is executable
	if (!this->is_addr_in_range(rva) || !this->can_be_code_weak(rva))
	{
#if DA_DEBUG_IT == 1
		flog("*** is_future_addr_correct() warning: rva=%08x (%08x) is not executable addr\r\n",
				rva,
				orva2va(rva));
#endif	

		return TADDR_INVALID;
	}

	// check if this is tail (this means something is wrong, like self-modifying code
	// was used

	if (daIS_F_TAIL(flags[rva]))
	{

#if DA_DEBUG_IT == 1
		flog("*** get_future_addr() warning: rva=%08x (%08x) is a tail of %08x (head)\r\n",
			rva,
			orva2va(rva),
			daFIND_HEAD(flags,rva));
#endif	
		return TADDR_INVALID;
	}


	// check if it was already analyzed
	if (daIS_F_ANALYZED(flags[rva]))
	{
		// even if it was analyzed set the LABEL flag
		daSET_F_LABEL(&flags[rva]);

#if DA_DEBUG_IT == 1
		flog("*** get_future_addr() warning: rva=%08x (%08x) already analyzed\r\n",
			rva,
			orva2va(rva));
#endif	
		return TADDR_ANALYZED;
	}

	return TADDR_GOOD;
}

/*
* Function adds rva to FutureAddrList
*/

void DAnalyze::set_future_addr(ulong32 rva_addr)
{

	this->FutureAddrList.push_back(rva_addr);

	//if (this->is_addr_in_range(rva_addr))
	//	daSET_F_LABEL(&this->BinData.flags[rva_addr]);
}

/*
* Function returns last addr in the FutureAddrList.
* Before it does that it makes sure the address
* is located in the executable area, is valid
* and doesnt point to the middle of "other" instructions

*/

ulong32 DAnalyze::get_future_addr(void)
{
	ulong32			rva_addr;
	type_flags		*flags;
	type_addr		ret_addr;



	// repeat until we will find something suitable
	flags		=	this->BinData.flags;
	for (;;)	
	{
		if (this->FutureAddrList.empty())
			return 0;

		rva_addr	=	this->FutureAddrList.back();
		FutureAddrList.pop_back();


//		bp(rva_addr,0x12050);

		// until good addrs is found
		if (this->is_future_addr_correct(rva_addr) != TADDR_GOOD)
			continue;
		else
		{
				// at this point make sure it is marked as an label 
			daSET_F_LABEL(&flags[rva_addr]);
			return rva_addr;
		}
	}
}


/*
* Function loads PE file in memory, including pre-allocating
* memory for flags and other structs.
*/

int DAnalyze::LoadPeFile(char *name)
{
	BOOL							st;
	HANDLE							hFile;
	type_flags						*flags;
	ulong32							correct_size;
	ulong32							FileSize, BytesRead;
	uchar							*temp_data, *mem;
	PIMAGE_SECTION_HEADER			pSHc;


	hFile		=	CreateFile(	name,
								GENERIC_READ, 
								FILE_SHARE_READ, 
								NULL, 
								OPEN_EXISTING, 
								FILE_ATTRIBUTE_NORMAL, 
								NULL);
	assert(hFile != INVALID_HANDLE_VALUE);

	// get the file size now
	FileSize	=	GetFileSize(hFile, NULL);
	assert(FileSize);
	this->o_filesize	=	FileSize;
	strncpy((char*)&this->o_filename, (char*)name, sizeof(this->o_filename)-1);


	// alloc some mem and load the file contents
	temp_data	=	new uchar[FileSize+1];
	assert(temp_data);
	memset((void*)temp_data, 0, FileSize);
	st			=	ReadFile(hFile, temp_data, FileSize, (LPDWORD)&BytesRead, NULL);
	assert(st == TRUE);
	CloseHandle(hFile);


	// now align everything just like it should be in the memory (PE loader style)
	this->pMZ				=	(PIMAGE_DOS_HEADER)temp_data;
	this->pPE				=	(PIMAGE_NT_HEADERS) ((ulong32)temp_data + pMZ->e_lfanew);
	this->pSH				=	(PIMAGE_SECTION_HEADER)((ulong32)temp_data + pMZ->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	pSHc					=	this->pSH;


	// check the signatures & test the PE (is it valid?) -> later
	assert((pPE->Signature == IMAGE_NT_SIGNATURE) || (pPE->FileHeader.NumberOfSections != NULL)); 

	if (!(pPE->FileHeader.Characteristics & IMAGE_FILE_MACHINE_I386))
	{
		flog("%s: invalid architecture - not i386!\n", __FUNCTION__);
		delete []temp_data;
		return D_FAILED;

	}


	// calculate the correct size in memory
	correct_size	=	pSHc->VirtualAddress;
	for (int i = 0; i < pPE->FileHeader.NumberOfSections; i++, pSHc++)
	{
		if (pSHc->Misc.VirtualSize > pSHc->SizeOfRawData)
			correct_size	+=	align(pSHc->Misc.VirtualSize,pPE->OptionalHeader.SectionAlignment);
		else
			correct_size	+=	align(pSHc->SizeOfRawData,pPE->OptionalHeader.SectionAlignment);
	}


#if DA_DEBUG_IT == 1
	flog("*** LoadPeFile(%s), file size = %d bytes\r\n",name,FileSize);
	flog("*** Size in memory = %d (%x) bytes\r\n",correct_size, correct_size);
#endif	

	// allocate space for the PE file in memory
	this->BinData.data_size			=	 correct_size;
	mem		=	this->BinData.data	=	 new uchar[correct_size];
	assert(mem);
	memset((void*)mem,0,correct_size);


	// allocate memory for flags
	flags	=	this->BinData.flags	=	 new type_flags[correct_size];
	assert(flags);
	memset((void*)flags, 0, sizeof(type_flags)*correct_size);


	// alloctae memory for instruction pointers
	this->BinData.fast_instrs	=	(_dinstr**)new ulong32[correct_size];
	assert(this->BinData.fast_instrs);
	memset((void*)this->BinData.fast_instrs, 0, sizeof(type_flags)*correct_size);


#if DA_DEBUG_IT == 1
	flog("*** Mem at %08x, FlagsMem at %08x\r\n",mem,this->BinData.flags);
#endif


	// write the header
	memcpy((void*)mem, temp_data, this->pSH->VirtualAddress);

	// now write the sections there (as they appear in memory, preserve align etc.)
	pSHc	= this->pSH;
	for (int i = 0; i < pPE->FileHeader.NumberOfSections; i++, pSHc++)
	{
#if DA_DEBUG_IT == 1
		flog("*** Section %s at %08x\r\n",pSHc->Name,pSHc->VirtualAddress);
#endif

		memcpy((void*)&mem[pSHc->VirtualAddress],
			&temp_data[pSHc->PointerToRawData], 
			pSHc->SizeOfRawData);

		// set the executable flag if required
		if (pSHc->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
#if DA_DEBUG_IT == 1
			flog("*** ExecutableSection %s at %08x\r\n",pSHc->Name,pSHc->VirtualAddress);
#endif
			for (int i = 0; i < pSHc->SizeOfRawData; i++)
			{
				daSET_F_EXECUTABLE_AREA(&flags[pSHc->VirtualAddress+i]);
			}

		}

	}

	this->m_imagebase		=	(ulong32)mem;
	this->pMZ				=	(PIMAGE_DOS_HEADER)mem;
	this->pPE				=	(PIMAGE_NT_HEADERS) ((ulong32)mem + pMZ->e_lfanew);
	this->pSH				=	(PIMAGE_SECTION_HEADER)((ulong32)mem + pMZ->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	this->o_imagebase		=	(ulong32)pPE->OptionalHeader.ImageBase;
	this->o_imagesize		=	(ulong32)pPE->OptionalHeader.SizeOfImage;
	this->sec_align			=	(ulong32)pPE->OptionalHeader.SectionAlignment;
	// try to load symbols
	this->Symbols			=	new SymbolClass;
	this->Symbols->load_symbol(name, NULL);


	this->flag_relocs();
	this->flag_imports();
	this->add_functions_ep();

	this->ready				= TRUE;
	delete []temp_data;
	return D_OK;
}



/*
* dump all functions
*/

void DAnalyze::dump_functions(void)
{
	type_flags		*flags;

	flags		=	this->BinData.flags;
	for (ulong32 i = 0; i < this->BinData.data_size; i++)
	{
		if (daIS_F_FUNCTION_START(flags[i]))
		{
			BOOL	pax_suitable = !daIS_REFERENCED(flags[i]);
			flog("%s: function at %08x (pax_suitable = %s)\n", 
				__FUNCTION__,
				i,
				(pax_suitable == 0? "NO":"YES"));
		}
	}

}

/*
* Function converts RVA to RAW.
* Returns -1 if failed
*/

ulong32 DAnalyze::orva2raw(ulong32 rva)
{
	PIMAGE_SECTION_HEADER			pSHX	=	this->pSH;

	for (int i = 0; i < this->pPE->FileHeader.NumberOfSections; i++, pSHX++)
	{
		if ((rva >= pSHX->VirtualAddress) && (rva <= (pSHX->VirtualAddress + pSHX->SizeOfRawData)))
		{
			ulong32 raw_offset	=	(rva - pSHX->VirtualAddress) + pSHX->PointerToRawData;
			return raw_offset;
		}
	}

	return -1;
}