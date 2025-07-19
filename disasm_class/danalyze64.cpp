#include "danalyze.h"


/*
* Function loads PE file in memory, including pre-allocating
* memory for flags and other structs.
*/

int DAnalyze::LoadPeFile64(char *name)
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
	this->pPE64				=	(PIMAGE_NT_HEADERS64) ((ulong32)temp_data + pMZ->e_lfanew);
	this->pSH				=	(PIMAGE_SECTION_HEADER)((ulong32)temp_data + pMZ->e_lfanew + sizeof(IMAGE_NT_HEADERS64));
	pSHc					=	this->pSH;


	// check the signatures & test the PE (is it valid?) -> later
	assert((pPE64->Signature == IMAGE_NT_SIGNATURE) || (pPE64->FileHeader.NumberOfSections != NULL)); 

	if (!(pPE64->FileHeader.Characteristics & IMAGE_FILE_MACHINE_AMD64))
	{
		flog("%s: invalid architecture - not amd64!\n", __FUNCTION__);
		delete []temp_data;
		return D_FAILED;

	}


	// calculate the correct size in memory
	correct_size	=	pSHc->VirtualAddress;
	for (int i = 0; i < pPE64->FileHeader.NumberOfSections; i++, pSHc++)
	{
		if (pSHc->Misc.VirtualSize > pSHc->SizeOfRawData)
			correct_size	+=	align(pSHc->Misc.VirtualSize,pPE64->OptionalHeader.SectionAlignment);
		else
			correct_size	+=	align(pSHc->SizeOfRawData,pPE64->OptionalHeader.SectionAlignment);
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
	for (int i = 0; i < pPE64->FileHeader.NumberOfSections; i++, pSHc++)
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

	this->m_imagebase64		=	(ulong64)mem;
	this->pMZ				=	(PIMAGE_DOS_HEADER)mem;
	this->pPE64				=	(PIMAGE_NT_HEADERS64) ((ulong32)mem + pMZ->e_lfanew);
	this->pSH				=	(PIMAGE_SECTION_HEADER)((ulong32)mem + pMZ->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	this->o_imagebase64		=	(ulong64)pPE64->OptionalHeader.ImageBase;
	this->o_imagesize		=	(ulong32)pPE64->OptionalHeader.SizeOfImage;
	this->sec_align			=	(ulong32)pPE64->OptionalHeader.SectionAlignment;
	// try to load symbols
	//this->Symbols			=	new SymbolClass;
	//this->Symbols->load_symbol(name, NULL);


	this->flag_relocs64();



	this->flag_imports64();
	//this->add_functions_ep();

	this->ready				= TRUE;
	delete []temp_data;
	return D_OK;
}



/*
* Function marks all relocs entries as daSET_F_RELOC_DATA
*/
int DAnalyze::flag_relocs64(void)
{
	type_flags						*flags;
	PIMAGE_BASE_RELOCATION			pRE;
	int								entries;
	ulong32							addr;

#define reloc_members_num(x)		((x - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD))

	flags	=	this->BinData.flags;
	pRE		=	(PIMAGE_BASE_RELOCATION)((ulong64)this->m_imagebase64 + 
		(ulong32)this->pPE64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if ((ulong32)pRE == (ulong32)this->pMZ)
	{
		// no relocs
#if DA_DEBUG_IT == 1
		flog("*** No relocs found\r\n");
#endif
		return D_FAILED;
	}

#if DA_DEBUG_IT == 1
	flog("*** Relocs at %llx\r\n",(ulong32)pRE);
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

			if (relocType == IMAGE_REL_BASED_DIR64)
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
		
		pRE = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)pRE + pRE->SizeOfBlock);
	}

	return D_OK;
}



/*
* Function marks all import entries as daSET_F_IMPORT_DATA
*/
int DAnalyze::flag_imports64(void)
{
	int								b;
	type_flags						*flags;
	ulong32							i_addr, first;
	PIMAGE_THUNK_DATA64				thunk;
	PIMAGE_IMPORT_BY_NAME			iname;


	flags				=	this->BinData.flags;

	i_addr				= this->pPE64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

	if ((i_addr <= 0) || (this->pPE64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size <= 0))
		return D_FAILED;


	// just same gay test for now
	this->pIMP			=	(PIMAGE_IMPORT_DESCRIPTOR)lrva2va64(i_addr);
	if ((sizeof(DWORD_PTR) == sizeof(ulong32)))
		this->pIMP			=	(PIMAGE_IMPORT_DESCRIPTOR)(i_addr + (ulong32)this->m_imagebase64);

	while ((pIMP->OriginalFirstThunk != 0) || (pIMP->FirstThunk != 0))
	{
		char	*dll_name = (char*)((ulong32)lrva2va64(pIMP->Name));

		first = (pIMP->OriginalFirstThunk == 0 ? pIMP->FirstThunk:pIMP->OriginalFirstThunk);
		thunk = (PIMAGE_THUNK_DATA64)(first + this->m_imagebase64);


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
