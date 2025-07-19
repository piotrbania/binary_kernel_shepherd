#include "danalyze.h"

/*
* Function tries to match an object (variable used by instruction)
* in the second (mirrored/changed) file.
* This is achieved by symbol lookup, references and some 
* hardcore magic and still can fail :(
*/ 


#if DDIFF_SHOW_OUTPUT == 1
int debug_all_objs	=	0;
int debug_notmatched_objs = 0;



vector<ulong32>	debug_UnmatchedObjs;
vector<debug_obj_match*> debug_MatchedObjs;


void debug_add_obj_match(ulong32 obj, ulong32 obj_match)
{
	debug_obj_match	*dom = new debug_obj_match;
	assert(dom);
	dom->obj			=	obj;
	dom->obj_match		=	obj_match;

	debug_MatchedObjs.push_back(dom);
	
}

#endif

ulong32	DDiff::match_object(ulong32 obj_rva)
{

	ulong32		obj_rva_m;



#if DDIFF_SHOW_OUTPUT == 1
	debug_all_objs++;
#endif

	// try to find by symbols
	obj_rva_m	=	match_object_by_symbol(obj_rva);
	if (obj_rva_m)
	{
#if DDIFF_SHOW_OUTPUT == 1
		debug_add_obj_match(obj_rva, obj_rva_m);	
#endif
		return obj_rva_m;
	}

	// now try to find the addr by references
	obj_rva_m	=	match_object_by_references(obj_rva);
	if (obj_rva_m)
	{
#if DDIFF_SHOW_OUTPUT == 1
		debug_add_obj_match(obj_rva, obj_rva_m);	
#endif


		return obj_rva_m;
	}

	// try the hardcore method
	obj_rva_m	=	match_object_by_heuristisc(obj_rva);
	if (obj_rva_m)
	{
#if DDIFF_SHOW_OUTPUT == 1
		debug_add_obj_match(obj_rva, obj_rva_m);	
#endif
		return obj_rva_m;
	}


#if DDIFF_SHOW_OUTPUT == 1
	debug_notmatched_objs++;
	this->debug_not_matched_objects = debug_notmatched_objs;
	debug_UnmatchedObjs.push_back(obj_rva);
#endif


	return 0;
}



/*
* Function tries to match a two symbols 
* and calculate the rva between them and
* the wanted obj
*/

ulong32 DDiff::match_object_by_heuristisc_get_rva(
	ulong32 obj_rva,
	ulong32 symbol_rva,
	ulong32 *symbol_rva_out)
{
	_sinfo		*sym;
	ulong32		obj_m_rva;
	ulong32		symbol_m_rva;

	*symbol_rva_out	=	0;


	sym		=	this->Analyze1->Symbols->get_symbol_info(symbol_rva);	

	if (!sym)
	{
#if DDIFF_SHOW_OUTPUT == 1
		flog("match_object_by_heuristisc_get_rva: objectRVA=%08x -> unable to find symbol near\r\n",
			obj_rva);
#endif
		return 0;
	}



#if DDIFF_SHOW_OUTPUT == 1
	flog("match_object_by_heuristisc_get_rva: objectRVA=%08x -> nearest symbol rva = %08x (%s)\r\n",
		obj_rva,
		sym->addrRVA,
		sym->name);
#endif


	// now try to find same symbol in the second file
	symbol_m_rva	=	match_object_by_symbol(sym->addrRVA);
	if (!symbol_m_rva)
		return 0;


	*symbol_rva_out	=	symbol_m_rva;

	// calculate the difference
	ulong32		diff_rva	=	obj_rva	-	sym->addrRVA;
	

	return diff_rva;
}


/*
* Function tries to match object my heuristisc method
* This is used when everything else failed.
* Algo:
* * Find a symbol near the object rva (in both files).
* * Calculate the rva (from the symbol to the object)
* * Try to compare the referencing functions
*/

ulong32 DDiff::match_object_by_heuristisc(ulong32 obj_rva)
{
	ulong32		diff_rva = 0, diff_rva_down = 0;
	ulong32		symbol_rva = 0, obj_m_rva = 0;
	ulong32		symbol_m_rva = 0, symbol_m_rva_down = 0;
	type_ReferenceMap::iterator	it, it_m;

	_sinfo *sym = 0;
	type_flags	*flags = this->Analyze1->BinData.flags;


	// firstly locate the symbol near
	for (symbol_rva = obj_rva; symbol_rva > 0; symbol_rva--)
	{
		if (daIS_F_HAS_SYMBOL(flags[symbol_rva]))
		{
			diff_rva	=	this->match_object_by_heuristisc_get_rva(obj_rva, symbol_rva, &symbol_m_rva );
			break;
		}
	}

	// something went wrong
	if (!diff_rva)
		return 0;

#if DDIFF_SHOW_OUTPUT == 1
	flog("match_object_by_heuristisc: locating symbol below!\r\n");
#endif

	// now try to locate next symbol but located after the obj_rva
	ulong32 max_space = this->Analyze1->BinData.data_size - obj_rva - 4;
	if (max_space <= 0)
		return 0;

	for (symbol_rva = obj_rva+4; symbol_rva < max_space; symbol_rva++)
	{
		if (daIS_F_HAS_SYMBOL(flags[symbol_rva]))
		{
			diff_rva_down	=	this->match_object_by_heuristisc_get_rva(obj_rva, symbol_rva, &symbol_m_rva_down);
			break;
		}
	}


	// now diff_rva_down + diff_rva must be equal to zero
	// or something is wrong
	if ((diff_rva + symbol_m_rva) !=  (diff_rva_down + symbol_m_rva_down))
	{

#if DDIFF_SHOW_OUTPUT == 1
	flog("match_object_by_heuristisc: invalid RVAS %08x -> %08x!\r\n",
		diff_rva,
		diff_rva_down);
#endif
		return 0;

	}


	obj_m_rva	=	symbol_m_rva + diff_rva;
	assert(diff_rva > 0);


	// ok now it is time to compare references
	type_ReferencePair f_pair		=	this->Analyze1->ReferenceMap.equal_range(obj_rva);
	type_ReferencePair f_pair_m		=	this->Analyze2->ReferenceMap.equal_range(obj_m_rva);


	if ((f_pair.first	== f_pair.second) ||
		(f_pair_m.first == f_pair_m.second))
	{
#if DDIFF_SHOW_OUTPUT == 1
		flog("match_object_by_heuristisc: objectRVA=%08x objectRVA_M=%08x -> bad references!\r\n",
			obj_rva,
			obj_m_rva);
#endif
		return 0;

	}



	// ok now do some comparisions
	
	_dinstr	*di, *di_m;
	for (it = f_pair.first; it != f_pair.second; it++)
	{
		di = it->second->instr;
		for (it_m = f_pair_m.first; it_m != f_pair_m.second; it_m++)
		{
			di_m = it_m->second->instr;

			// if we have at least one match
			// we have found the object
			// warning:	verify this with more tests
			if ((di->len			== di_m->len) &&
				(di->disit_flags	== di_m->disit_flags)	&&
				(di->emul_int		== di_m->emul_int))
			{

#if DDIFF_SHOW_OUTPUT == 1
				flog("match_object_by_heuristisc: HMATCH objectRVA=%08x found objectRVA_M=%08x !\r\n",
					obj_rva,
					obj_m_rva);
#endif

				return obj_m_rva;
			}
		}
	}

	return 0;
}

/*
* Function tries to match object by symbols
*/

ulong32 DDiff::match_object_by_symbol(ulong32 obj_rva)
{
	
	_sinfo *sym, *sym_m;
	type_flags	*flags = this->Analyze1->BinData.flags;

	// ok firstly lets check if it is a symbol
	if (daIS_F_HAS_SYMBOL(flags[obj_rva]))
	{

#if DDIFF_SHOW_OUTPUT == 1
		flog("match_object_by_symbol: objectRVA=%08x has symbol\r\n",
			obj_rva);
#endif

		sym	=	 this->Analyze1->Symbols->get_symbol_info(obj_rva);	
		if (!sym || (!sym->adler32_name))
		{

#if DDIFF_SHOW_OUTPUT == 1
			flog("match_object_by_symbol: objectRVA=%08x has symbol -> but no symbol found WTF\r\n",
				obj_rva);
#endif
			return 0;
		}

		// ok we have found the symbol, now we can try to locate the same symbol
		// in the second file
		sym_m	=	 this->Analyze2->Symbols->get_symbol_info_by_adler(sym->adler32_name);

		if (sym_m)
		{

#if DDIFF_SHOW_OUTPUT == 1
			flog("match_object_by_symbol: objectRVA=%08x name:%s located, mirrorRVA=%08x\r\n",
				obj_rva,
				sym_m->name,
				sym_m->addrRVA);
#endif
			return sym_m->addrRVA;
		}
	}

	return 0;
}


/*
* Function tries to locate an object from first file in the second file.
* This is done by using the references information. 
* -> it should be verified when dealing with multiple matches
*    and short-basicblocks. 
*/

ulong32 DDiff::match_object_by_references(ulong32 obj_rva)
{
	_dinstr							*di, *di_matched;
	_dbasicblock					*bb, *bb_matched;
	
	type_ReferenceMap::iterator	it;
	type_reference ref_type	=	REF_IMM;

	
	
	// firstly try to find any basicblock that
	// also uses the same object (same file)


	type_ReferencePair f_pair	=	this->Analyze1->ReferenceMap.equal_range(obj_rva);
	for (it = f_pair.first; it != f_pair.second; it++)
	{

		bb	=	it->second->bb;

#if DDIFF_SHOW_OUTPUT == 1
		flog("match_object_by_references objectRVA=%08x used in BB=%08x\r\n",
			obj_rva,
			bb->rva_start);
#endif

		// it must be matched otherwise no use for us
		if (!daIS_F_BB_MATCHED(bb->flags) && !daIS_F_BB_MULTIPLEMATCH(bb->flags))
		{

#if DDIFF_SHOW_OUTPUT == 1
			flog("match_object_by_references objectRVA=%08x used in BB=%08x -> BB not matched, skipping\r\n",
				obj_rva,
				bb->rva_start);
#endif
			continue;
		}

		// wtf here
		if (!bb->bb_matched)
		{
#if DDIFF_SHOW_OUTPUT == 1
			flog("match_object_by_references objectRVA=%08x used in BB=%08x -> BB not matched WTFFLAGS, skipping\r\n",
				obj_rva,
				bb->rva_start);
#endif
			continue;
		}


		// ok this one should give us the info we need
		// first of all remember at this point those basicblocks
		// were matched (100% match). So it means they are identical.
		bb_matched	=	bb->bb_matched;



#if DDIFF_SHOW_OUTPUT == 1
		flog("match_object_by_references objectRVA=%08x used in BB=%08x matched-> BB=%08x\r\n",
			obj_rva,
			bb->rva_start,
			bb_matched->rva_start);
#endif

		// this is the instruction that causes the reference (original file/first tile)
		di	=	it->second->instr;

		// guess where the symbol was (mem_imm or imm(default))
		if (di->objMEMIMM_rva	==	obj_rva)
			ref_type	=	REF_MEMIMM;
		else
		{
			assert(di->objIMM_rva	== obj_rva);
		}


		// ok the instruction was found in the original file
		// now locate the same instruction in the second file
		// since both blocks are matched, we can assume 
		// same instruction is located on the same RVA from the basicblock start
		ulong32 i_rva	=	(di->rva_addr - bb->rva_start) + bb_matched->rva_start;
		di_matched		=	this->Analyze2->get_dinstr_from_rva(i_rva);
		if (!di_matched)
			continue;	
		//assert(di_matched);


		// alright now get mirrored object rva 
#define return_mirrored_object(mobj_rva)	{ assert(mobj_rva); return mobj_rva; }
		if (ref_type == REF_MEMIMM)
		{
			return_mirrored_object(di_matched->objMEMIMM_rva);
		}
	
		return_mirrored_object(di_matched->objIMM_rva);
	}

	return 0;
}

