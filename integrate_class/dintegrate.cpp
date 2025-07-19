
#include "danalyze.h"
#include "dintegrate.h"



/*
* Constructor
*/

DIntegrate::DIntegrate()
{
	

}


/*
* Destructor
*/

DIntegrate::~DIntegrate()
{
	this->terminate();
}


/*
* Sets the source object
*/

void	 DIntegrate::set_object(DAnalyze *DA)
{
	this->DA = DA;

}



/*
* Clean the flags for all basicblock in the function BB list.
*/

void DIntegrate::DFS_clear(_dfunction *func)
{
	int list_size = func->BBIList->size();

	assert(list_size);

	for (int i = 0; i < list_size; i++)
	{
		_bb_iext *bbi	=	(*func->BBIList)[i];
		daSET_F_BB_EXT_NOTVISITED(&bbi->flags);
		static_cast<_dbasicblock*>(bbi->bb_org)->bb_iext	=	NULL;
	}
}



/*
* Start traveling the basicblocks using DepthFirstSearch. 
* Additionally fill the node list of the procedure.
*/

int	DIntegrate::DFS_start(_dfunction *func, _dbasicblock *bb_start)
{
	
	func->BBIList->clear();


	// make sure all flags are cleared at this point 
	this->DFSInTime =	0;
	this->DFS_go(func, bb_start);


	// clean the visited flags now
	this->DFS_clear(func);

	return D_OK;
}


/*
* Performs DFS algo on func. Also allocates EXT data for BB.
*/

inline _bb_iext* DIntegrate::new_bb_iext(void)
{
	_bb_iext*	nb = new _bb_iext;
	assert(nb);
	memset((void*)nb, 0, sizeof(_bb_iext));
	return nb;

}



int	DIntegrate::DFS_go(_dfunction *func, _dbasicblock *bb)
{
	_dbasicblock *bbc;

	
	// allocate some memory
	if (!bb->bb_iext)
		bb->bb_iext		=	new_bb_iext();

	daSET_F_BB_EXT_VISITED(&bb->bb_iext->flags);
	//bb->shared_times++;

	// add instructions
	this->fill_instructions(bb);

	// add this node to the node list
	bb->bb_iext->bb_org			=	bb;
	bb->bb_iext->DFSInTime		=	this->DFSInTime;
	this->DFSInTime++;
	func->BBIList->push_back(bb->bb_iext);

	// for all basic block edges
	if (!bb->ChildsList)
		return D_FAILED;

	assert(bb->ChildsList->size());
	for (int i = bb->ChildsList->size(); i > 0; i--)
	{
		bbc = (*bb->ChildsList)[i-1];

		// allocate the strucutre
		if (!bbc->bb_iext)
			bbc->bb_iext		=	new_bb_iext();

		// first one is a dest link, but it must not be a call
		if (i == 1)
		{
			// make a link for integration
			bb->bb_iext->bbi_linked	=	bbc->bb_iext;
		}


		if (!daIS_F_BB_EXT_VISITED(bbc->bb_iext->flags))
		{
#if DIX_DEBUG_IT == 1
			flog("DFS_go bb=%08x found new edge = %08x\n",
				bb->rva_start,
				bbc->rva_start);

#endif
			DFS_go(func, bbc);
		}
		else
		{
			// already visited so this is a potential backedge
			// potential backedges will be tested later (with dominators and shit)
			//daSET_F_BB_EXT_LOOPHEADER(&bb_i->ext->flags);
		}
	}


	// fill the next links if there are any
	// get the last instruction
	_dinstr	*di	=	this->DA->get_dinstr_from_rva(bb->rva_end);
	assert(di);
	type_flags	iflags = this->DA->BinData.flags[di->rva_addr];

	// no next
	if (daIS_F_INSTR_JMP(iflags) || daIS_F_INSTR_RETURN(iflags))
		return D_OK;


	// CALL/JCC here; so the last child is the next node
	// we fill this information only if the child was already
	// processed

	assert(bb->ChildsList);
	bbc = bb->ChildsList->back();
	
	// yes it was processed already, will require fix
	// BBCDfsTime < BBDfsTime
	if ((bbc->bb_iext) && (bbc->bb_iext->DFSInTime < bb->bb_iext->DFSInTime))
	{
		daSET_F_BB_EXT_REQUIRES_NFIX(&bb->bb_iext->flags);
		bb->bb_iext->bbi_next	=	bbc->bb_iext;

#if DIX_DEBUG_IT == 1
		flog("%s: bb=%08x (inTime=%d) REQUIRES JMP PATCH to bbc=%08x (inTime=%d)\n",
			__FUNCTION__,
			bb->rva_start,
			bb->bb_iext->DFSInTime,
			bbc->rva_start,
			bbc->bb_iext->DFSInTime);
#endif

	}



	return D_OK;
}


void DIntegrate::terminate(void)
{
	// travel through all functions
	// and delete bb_iext

	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func = this->DA->FunctionList[i];
		if (!func->BBIList)
			continue;

		for (int j = 0; j < func->BBIList->size(); j++)
		{
			_bb_iext	 *bbi = (*func->BBIList)[j];
			assert(bbi);
			_dbasicblock *bb = (_dbasicblock*)bbi->bb_org;

			if (bbi->InstrIExtList)
			{
				for (int k = 0; k < bbi->InstrIExtList->size(); k++)
				{
					_instr_iext *iext = (*bbi->InstrIExtList)[k];

					// do we need to free the data
					if (this->was_iext_data_allocated(iext))
						SAFE_DELETE(iext->data);


					SAFE_DELETE_C(iext);
				}

				SAFE_DELETE_C(bbi->InstrIExtList);
			}

			
			SAFE_DELETE_C(bbi);
			bb->bb_iext = NULL;
		}

		SAFE_DELETE_C(func->BBIList);
	}


	// now deallocate all callbacks
	for (int i = 0; i < this->CallbacksList.size(); i++)
	{
		delete this->CallbacksList[i];
	}


	CallRelList.clear();

}



/*
* Function process all found functions
*/

int	DIntegrate::process_functions(void)
{

	this->debug_repair_count	=	0;
	RelocsList.clear();
	CallbacksList.clear();
	CallRelList.clear();


	this->setup_invalid_addrs();
	this->magic_key			=		0xAAAAAAAA;	//GetTickCount();


	Czasomierz.reset();

	// first of all build a function list
	// since this was not done before

	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	= this->DA->FunctionList[i];
		func->BBIList		= new type_BBIExtList;
		assert(func->BBIList);

		this->DFS_start(func, func->bb_start);
	}

#if DI_ANTIROP == 1
	// debug only 02.11.2011 anti rop
	this->MarkSharedBasicBlocks();
	// end debug only
#endif


	this->instrument();
	this->integrate_stage1();
	this->integrate_stage2();

	// dump only
#if DI_DEBUG_IT == 1
	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	= this->DA->FunctionList[i];
		this->dump_function(func);
	}
#endif


	double elapsed_time = Czasomierz.seconds();
	flog("%s: IntegrationTime = %f seconds\n", __FUNCTION__, elapsed_time);


	return D_OK;
}


/*
* Dumps function info.
*/
void DIntegrate::dump_function(_dfunction *func)
{

	flog("\n%s: --------- FUNCTION DUMP %08x ----------\n",
		__FUNCTION__,
		func->bb_start->rva_start);

	for (int j = 0; j < func->BBIList->size(); j++)
	{
		_bb_iext	 *bbi = (*func->BBIList)[j];
		_dbasicblock *bb = (_dbasicblock*)bbi->bb_org;

		char instrument_type[255];

		instrument_type[0] = NULL;
		if (daIS_F_BB_EXT_INSTRUMENT_RET(bbi->flags))
			_snprintf(instrument_type, sizeof(instrument_type)-1, "%s|INSTRUMENT_RET", instrument_type);
		if (daIS_F_BB_EXT_INSTRUMENT_CALLI(bbi->flags))
			_snprintf(instrument_type, sizeof(instrument_type)-1, "%s|INSTRUMENT_CALLI", instrument_type);
		if (daIS_F_BB_EXT_INSTRUMENT_CALLREL(bbi->flags))
			_snprintf(instrument_type, sizeof(instrument_type)-1, "%s|INSTRUMENT_CALLREL", instrument_type);
		if (daIS_F_BB_EXT_INSTRUMENT_JMPI(bbi->flags))
			_snprintf(instrument_type, sizeof(instrument_type)-1, "%s|INSTRUMENT_JMPI", instrument_type);
		if (daIS_F_BB_EXT_EXTENDED_JCC(bbi->flags))
			_snprintf(instrument_type, sizeof(instrument_type)-1, "%s|INSTRUMENT_EXTJCC", instrument_type);
		if (daIS_F_BB_EXT_EXTENDED_JMP(bbi->flags))
			_snprintf(instrument_type, sizeof(instrument_type)-1, "%s|INSTRUMENT_EXTJMP", instrument_type);





		ulong32 link_rva = 0;
		if (bbi->bbi_linked)
			link_rva = bbi->bbi_linked->rva_new;

		flog("%s: [%04d] DFSInTime=%d bb_start = %08x bb_end = %08x inum=%04d newRVA=%08x newSIZE=%08x link=%08x Instrument:%s\n",
			__FUNCTION__,
			j,
			bbi->DFSInTime,
			bb->rva_start,
			bb->rva_end,
			bbi->InstrIExtList->size(),
			bbi->rva_new,
			bbi->size,
			link_rva,
			instrument_type);
	}

}


/*
* Function allocates InstrExtList in the basicblock.
* And fills it with instructions.
*/

int	DIntegrate::fill_instructions(_dbasicblock *bb)
{

	_bb_iext *bb_iext = bb->bb_iext;
	assert(bb_iext);

	// create the instruction list
	bb_iext->InstrIExtList	=	new type_InstrIExtList;
	assert(bb_iext->InstrIExtList);
	bb_iext->InstrIExtList->clear();


	// now fill it with instructions
	for (ulong32 i = bb->rva_start; i < (bb->rva_end+1); i++)
	{
		_dinstr *di = this->DA->get_dinstr_from_rva(i);
		assert(di);

		// create new struct for extended instruction
		_instr_iext *iext = new_instr_iext(di, di->data, di->len);
		bb_iext->InstrIExtList->push_back(iext);

		i += di->len - 1;
	}



	return D_OK;
}

/*
* Function creates and fills new _instr_iext structure.
*/

inline _instr_iext*	DIntegrate::new_instr_iext(_dinstr	*di_org, uchar *data_ptr, uint8 data_size)
{
	_instr_iext *iext = new _instr_iext;
	assert(iext);

	iext->di_org	=	di_org;
	iext->data		=	data_ptr;
	iext->data_size	=	data_size;
	return iext;
}


/*
* Function test if new data was allocated for selected instruction.
* Ie. happens when instr was instrumented
*/

inline  BOOL	DIntegrate::was_iext_data_allocated(_instr_iext *iext)
{

	if (iext->data == iext->di_org->data)
		return FALSE;

	return TRUE;
}



/*
* Compare data locations with IDA
*/

void DIntegrate::compare_IDA_data(void)
{
		DWORD fs;
	ulong32	*mem;



	// dump all hooked functions
	int fd = 0;
	flog("--------- dumping hooked functions --------------- \n");
	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *funcx	= this->DA->FunctionList[i];
		_bb_iext	*bbix		=	funcx->BBIList->front();
		BOOL		  hookedx	=	daIS_F_BB_EXT_HOOKABLE(bbix->flags);	

		if (hookedx)
		{

			char			f_name[255];
			strcpy((char*)&f_name, "NO_NAME");
			ulong32			f_addr		=	funcx->bb_start->rva_start;
			_sinfo			*SymbolInfo	=	this->DA->Symbols->get_symbol_info(f_addr);
			if (SymbolInfo) 
				_snprintf(f_name, sizeof(f_name), "%s", SymbolInfo->name);

			flog("%08d: function hooked: %08x (%s)\n",
				fd, f_addr, f_name);
			fd++;

		}

	}

	flog("--------- end of hooked functions dump ----------- \n");



#define EXPORT_NAME_DATA "J:\\projekty\\binary_shepherding\\data_locations.txt"
	HFILE in = _lopen(EXPORT_NAME_DATA,OF_READ);
	assert(in != HFILE_ERROR);

	fs = GetFileSize((HANDLE)in,NULL);
	assert(fs);

	type_flags *flags = this->DA->BinData.flags;;



	mem	=	(ulong32*)new uchar[fs+4];
	assert(mem);
	memset((void*)mem,0xCC,fs+4);

	// read all 
	_lread(in,mem,fs);

int bad = 0;
	for (int i = 0; mem[i] != 0xCCCCCCCC; i++)
	{

		ulong32 rva = mem[i];

		if (!this->DA->is_addr_in_range(rva))
			continue;

		ulong32 f = flags[mem[i]];
		

		_dfunction *func = this->DA->find_function_by_rva(rva);
		if (!func)
			continue;

		if (!func->BBIList)
		{
			flog("%s: function %08x taken as data but BBIList not filled!\n",
				__FUNCTION__, rva);
			continue;
		}


		_bb_iext	*bbi		=	func->BBIList->front();
		_dbasicblock *bb		=	(_dbasicblock*)bbi->bb_org;
		_dinstr		*di			=	this->DA->get_dinstr_from_rva(bb->rva_end);
		assert(di);
		int			  bb_size	=	bb->rva_end - bb->rva_start + di->len;
		int			  num_of_bb	=	func->BBIList->size();	

		BOOL		  hooked	=	daIS_F_BB_EXT_HOOKABLE(bbi->flags);		//this->is_func_hookable(func);


		int	prospect	=	(daIS_F_PROSPECT(flags[bb->rva_start]) == 0? 0:1);
		//if ((bb_size >= PATCH_SIZE) && (!daIS_F_ACCESSED_AS_DATA(f)))
		if (hooked)
		{
			flog("%s: [%08d] !!!!!! data marked as code at %08x (numOfBB=%d PROSPECT=%d) and HOOKED\n",
				__FUNCTION__, bad, rva, num_of_bb, prospect);
			bad++;
		}
		else
		{
			flog("%s: [%08d] !!!!!!! data marked as code at %08x (numOfBB=%d PROSPECT=%d) and NOTHOOKED\n",
				__FUNCTION__, bad, rva, num_of_bb, prospect);
			bad++;
		}
		
	}


	delete []mem;
	_lclose(in);



}