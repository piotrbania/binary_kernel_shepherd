#include "danalyze.h"


DDiff::DDiff()
{
	this->PrimaryFingerPrintMap.clear();
	this->SecondaryFingerPrintMap.clear();
	this->AdlerFingerPrintMap.clear();
	this->BytesFingerPrintMap.clear();

	


#if DDIFF_SHOW_OUTPUT == 1

	extern int debug_all_objs;
	extern int debug_notmatched_objs;
	debug_all_objs			=	0;
	debug_notmatched_objs	= 0;

	extern vector<ulong32>				debug_UnmatchedObjs;
	extern vector<debug_obj_match*>		debug_MatchedObjs;

	debug_UnmatchedObjs.clear();
	debug_MatchedObjs.clear();


#endif


}


DDiff::~DDiff()
{

	this->PrimaryFingerPrintMap.clear();
	this->SecondaryFingerPrintMap.clear();
	this->AdlerFingerPrintMap.clear();
	this->BytesFingerPrintMap.clear();

	// delete the best matches

	for (int i = 0; i < this->NotMatchedBasicBlocks.size(); i++)
	{
		_dbbmatch	*bm	=	this->NotMatchedBasicBlocks[i];
		for (int j = 0; j < bm->BestMatches.size(); j++)
		{
			delete bm->BestMatches[j];
		}
		delete bm;
	}

}


void DDiff::set_src_dest_objects(class DAnalyze *A1, class DAnalyze *A2)
{
	this->Analyze1		=	A1;
	this->Analyze2		=	A2;

	this->PMap1			=	&A1->Diff->PrimaryFingerPrintMap;
	this->PMap2			=	&A2->Diff->PrimaryFingerPrintMap;
	this->SMap1			=	&A1->Diff->SecondaryFingerPrintMap;
	this->SMap2			=	&A2->Diff->SecondaryFingerPrintMap;
	this->AMap1			=	&A1->Diff->AdlerFingerPrintMap;
	this->AMap2			=	&A2->Diff->AdlerFingerPrintMap;
	this->BMap1			=	&A1->Diff->BytesFingerPrintMap;
	this->BMap2			=	&A2->Diff->BytesFingerPrintMap;
	this->WMap1			=	&A1->Diff->WeakFingerPrintMap;
	this->WMap2			=	&A2->Diff->WeakFingerPrintMap;



	this->BBList1		=	&A1->BasicBlockList;
	this->BBList2		=	&A2->BasicBlockList;
}

/*
* Function adds fingerprints to the hash_multimaps
* (duplicates may happen)
*/

int DDiff::make_basicblock_fingerprint(_dbasicblock *bb)
{

#ifdef _BINSHEP
		return D_OK;
#endif

	_dcrc crc;


	// add the perfect adler map  (just some hack)
	crc.crc_elements.first_32bit		=	bb->crc.crc_adler;
	crc.crc_elements.desc_crc			=	bb->crc.crc_elements.desc_crc;
	this->AdlerFingerPrintMap.insert(make_pair<ulong64,_dbasicblock*>(
		crc.crc,
		bb));


	// add the primary fingerprint
	this->PrimaryFingerPrintMap.insert(make_pair<ulong64,_dbasicblock*>(
		bb->crc.crc,
		bb));
	

	// add the secondary fingerprint
	this->SecondaryFingerPrintMap.insert(make_pair<ulong32,_dbasicblock*>(
		bb->crc.crc_elements.desc_crc,
		bb));
	

	// add the additional fingerprint map with adler32 from f.bytes a key
	this->BytesFingerPrintMap.insert(make_pair<ulong32,_dbasicblock*>(
		bb->crc.crc_adler,
		bb));


#if DA_DIFF_USE_WEAKCRCMAP == 1
	this->WeakFingerPrintMap.insert(make_pair<ulong32,_dbasicblock*>(
		bb->crc.crc_weak,
		bb));
#endif



	return D_OK;
}

int DDiff::match_process_pair(_dbasicblock	*bb1, int count, type_AdlerPrintPair *pair, BOOL report_unmatched)
{
	type_PrimaryFingerPrintMap::iterator	it1, it2;
	_dbbmatch								*dmatch;

	if (count == 0)
	{
			// none matched 
#if DDIFF_SHOW_OUTPUT == 1
			flog("Unmatched block: %08x \r\n", bb1->rva_start);
#endif
			debug_none_num++;

			// just set an empty struct for it
			if (report_unmatched)
			{
				dmatch			=	new _dbbmatch;
				assert(dmatch);
				dmatch->bb		=	bb1;
				dmatch->BestMatches.clear();
				NotMatchedBasicBlocks.push_back(dmatch);
			}
			return D_FAILED;
	}


#if DA_DIFFDEBUG_IT == 1
	flog("*** compare_basicblocks() there are %d basicblocks with primary checksum=%llx (bb_addr=%08x)\r\n",
				count,
				bb1->crc.crc,
				bb1->rva_start);
#endif


	
	if (count > 1)
	{
			dmatch			=	new _dbbmatch;
			assert(dmatch);
			dmatch->bb		=	bb1;
			dmatch->BestMatches.clear();
			NotMatchedBasicBlocks.push_back(dmatch);
			daSET_F_BB_MULTIPLEMATCH(&bb1->flags);
			debug_multiple_num++;
	}


	for (it2 = pair->first; it2 != pair->second; it2++)
	{
		// at least one match was found
		//bb1	=	(*it1).second;
		_dbasicblock	*bb2 =   (*it2).second;

		if (count > 1)
		{
			// multiple matches use our wicked procedure
			daSET_F_BB_MULTIPLEMATCH(&bb2->flags);
			_dbbestmatches*	bestmatch		= this->match_by_level(bb1,bb2);
			dmatch->BestMatches.push_back(bestmatch);

#if DA_DIFFDEBUG_IT == 1
			int max_match =	get_list_size(bb1->ChildsList) + get_list_size(bb1->ParentsList);

			flog("*** compare_basicblocks() bestmatch for bb1=%08x(%08x) -> bb2=%08x(%08x) (match rate=%d/%d)\r\n",
				bb1->rva_start,
				bb1->rva_start,
				bb2->rva_start,
				bb2->rva_start,
				bestmatch->match_level,
				max_match);
#endif
		
			continue;
		}


		// debug
		debug_single_num++;

		// we have a match
		daSET_F_BB_MATCHED(&bb1->flags);
		daSET_F_BB_MATCHED(&bb2->flags);
		bb1->bb_matched	=	bb2;
		bb2->bb_matched	=	bb1;
			// debug
		//	bp(bb1->rva_start, 0x0000bf72);
		//	bp(bb2->rva_start, 0x0000bf72);


#if DA_DIFFDEBUG_IT == 1
		flog("*** compare_basicblocks() perfect match bb1=%08x(%08x) bb2=%08x(%08x)\r\n",
			bb1->rva_start,
			(bb1->rva_start),
			bb2->rva_start,
			(bb2->rva_start));
#endif
			
		}

	return D_OK;
}


/*
* Function compares basicblocks 
* 1) testing for entire checksum (64bit) match if there is only one the basicblock is matched
* 2) for the rest we use another function
*/

int	DDiff::compare_basicblocks(void)
{

	int		count;
	type_FingerPrintPair					pair;
	type_PrimaryFingerPrintMap::iterator	it1, it2;

	_dbasicblock							*bb1, *bb2;
	_dbbmatch								*dmatch;


	debug_single_num		=	0;
	debug_multiple_num		=	0;
	debug_none_num			=	0;


	NotMatchedBasicBlocks.clear();


#ifdef TIME_TEST == 1
	this->Analyze1->Czasomierz.reset();
#endif

	// for every basicblock's checksum try to find a matching one
	for (it1 = AMap1->begin(); it1 != AMap1->end(); it1++)
	{
		bb1					=	(*it1).second;
		ulong64 crc			=	bb1->crc.crc;
		ulong64 crc_adler	=	(*it1).first;

		if (daIS_F_BB_MATCHED(bb1->flags))
			continue;



#if DA_DIFFDEBUG_IT == 1
		flog("*** compare_basicblocks() (ADLERPASS) trying find match for %08x (%llx)\r\n",
					bb1->rva_start,
					crc_adler);
#endif

		// try to match by adler
		// if we have a match continue
		pair		=	AMap2->equal_range(crc_adler);
		count		=	AMap2->count(crc_adler);
		int	st		=	this->match_process_pair(bb1, count, &pair, FALSE);
		if (st == D_OK)
			continue;


#if DA_DIFFDEBUG_IT == 1
		flog("*** compare_basicblocks() (PMAP) trying find match for %08x (%llx)\r\n",
					bb1->rva_start,
					crc);
#endif

		// the search by entire checksum (64bit)
		// if there more than 1 matches we need to do some graph checking
		pair		=	PMap2->equal_range(crc);
		count		=	PMap2->count(crc);

		this->match_process_pair(bb1, count, &pair, TRUE);

	}


	flog("* Diff stats: SingleMatches: %d MultipleMatches: %d UnmatchedBeforeHMatching: %d\r\n",
		debug_single_num,
		debug_multiple_num,
		debug_none_num);

	// now try to match the unmatched ones
	this->match_unmatched_basicblock();


#ifdef TIME_TEST == 1
	double seconds2 = this->Analyze1->Czasomierz.seconds();
	flog("STAGE 3 COMPARING BASICBLOCKS DONE, %f seconds elapsed\r\n",seconds2); 
	this->Analyze1->Czasomierz.reset();
	this->seconds_elapsed_diff	=	seconds2;
#endif


	return D_OK;
}



/*
* Function tries to match blocks that were not matched
* or had multiple matches.
*/

int	DDiff::match_unmatched_basicblock(void)
{
	_dbbmatch		*dbm;
	_dbasicblock	*bb1, *bb2;


	int				debug_unmatched		=0;


	// firstly try to match by name
	for (int i = 0; i < NotMatchedBasicBlocks.size(); i++)
	{
		bb1 = NotMatchedBasicBlocks[i]->bb;
		if (daIS_F_BB_MULTIPLEMATCH(bb1->flags))
		{
			this->match_by_name(bb1);
		}
	}


	for (int i = 0; i < NotMatchedBasicBlocks.size(); i++)
	{
		dbm		=	NotMatchedBasicBlocks[i];
		bb1		=	dbm->bb;

//		bp(bb1->rva_start,0x00011140);
	
		if (daIS_F_BB_MULTIPLEMATCH(bb1->flags) && !bb1->bb_matched)
		{
			// multiple matches we need to pick one
			// perhaps it has a name?
			//if (!this->match_by_name(bb1))
			//{
				this->pick_best_match(dbm);
			//}
			continue;
		}
		
		// block was already matched so go home
		if (daIS_F_BB_MATCHED(bb1->flags))
			continue;


		// completely unmatched one try the scan
		if (!da_WAS_MATCHED(bb1->flags))
		{

#if DDIFF_SHOW_OUTPUT == 1
			flog("%s: trying to match unmatched-block: %08x \r\n", __FUNCTION__, bb1->rva_start);
#endif
			if (!this->match_by_name(bb1))
			{
				this->hardcore_matching(BBList1, BBList2, dbm);
				debug_unmatched++;


#if DDIFF_SHOW_OUTPUT == 1
				flog("%s: not matched-block: %08x \r\n", __FUNCTION__, bb1->rva_start);
#endif
			}
#if DDIFF_SHOW_OUTPUT == 1
			else
			{
				flog("%s: matched by name %08x \r\n", __FUNCTION__, bb1->rva_start);
			}
#endif

			type_FunctionList OutFuncList;
			this->Analyze1->get_functions_for_basicblock(bb1, &OutFuncList);

			for (int i = 0; i < OutFuncList.size(); i++)
			{
				_dfunction *dfound = OutFuncList[i];


				//flog("BB: %08x Adding function %08x\r\n", bb1->rva_start, dfound->bb_start->rva_start);

				type_FunctionMap::iterator it = UmatchedFunctionsMap.find(dfound->bb_start->rva_start);
				if (it ==  UmatchedFunctionsMap.end())
				{
					UmatchedFunctionsMap.insert(make_pair<ulong32, _dfunction*>(dfound->bb_start->rva_start, dfound));
				}

			}

//			__asm int 3;

			
		}
	
	}


	flog("*** Unmatched %d basicblocks!\r\n",debug_unmatched);
	this->debug_none_num = debug_unmatched;


#if DDIFF_SHOW_OUTPUT == 1
	int kkk = 0;
	type_FunctionMap::iterator it = UmatchedFunctionsMap.begin();
	for (it; it != UmatchedFunctionsMap.end(); it++)
	{
		_dfunction *df = (*it).second;
		flog("[%d] sub:  \t %08x\r\n", kkk++, df->bb_start->rva_start);

		this->debug_list_function_basicblocks(df);

	}
#endif


	// debug only
#define TEST_OBJ_RVA	0x101c
	//ulong32 mirror_obj = this->match_object_by_references(TEST_OBJ_RVA);
	//flog("mirrored obj %08x -> %08x\r\n", TEST_OBJ_RVA, mirror_obj);



#if DDIFF_SHOW_OUTPUT == 1
	extern int debug_notmatched_objs;
	extern int debug_all_objs;

	extern vector<ulong32> debug_UnmatchedObjs;
	extern vector<debug_obj_match*> debug_MatchedObjs;

	flog("Unmatched OBJECTS = %d MATCHED OBJECTS: %d \r\n", 
		 debug_notmatched_objs,
		 (debug_all_objs - debug_notmatched_objs));

	flog("* Listing matched objects!\r\n");
	vector<debug_obj_match*>::iterator itd2;

	this->debug_matched_objects	=	debug_MatchedObjs.size();

	int k = 0;
	for (k = 0, itd2 = debug_MatchedObjs.begin(); itd2 != debug_MatchedObjs.end(); itd2++, k++)
	{
		debug_obj_match *dom = *itd2;


		flog("[%d] ObjMatch %08x -> %08x\r\n",
			k,
			dom->obj,
			dom->obj_match);

		delete dom;
	}
	



	flog("\r\n* Listing UNmatched objects!\r\n");
	
	vector<ulong32>::iterator itd;
	
	for (k = 0, itd = debug_UnmatchedObjs.begin(); itd != debug_UnmatchedObjs.end(); itd++, k++)
	{
		flog("[%d] Unmatched OBJECT -> %08x\r\n",
			k,
			*itd);
	}

#endif



	return D_OK;
}


/*
* Function tries to match the basicblock by name
*/

BOOL DDiff::match_by_name_do(_dbasicblock *bb1)
{
	_sinfo			*sym1, *sym2;
	_dbasicblock	*bb2, *bb_m;

	// try to match by name
	sym1	=	this->Analyze1->Symbols->get_symbol_info(bb1->rva_start);
	if (sym1 && sym1->adler32_name)
	{

#if DA_DIFFDEBUG_IT == 1
		flog("*** match_by_name() trying to match by name bb1=%08x(%08x) adler32=%08x\r\n",
			bb1->rva_start,
			this->Analyze1->orva2va(bb1->rva_start),
			sym1->adler32_name);
#endif
		

		sym2	=	this->Analyze2->Symbols->get_symbol_info_by_adler(sym1->adler32_name);
		if (sym2)
		{
			// we have a match
			bb2	=	this->Analyze2->find_basicblock(sym2->addrRVA);
			assert(bb2);

			// already matched? skip it
			if (bb2->bb_matched)
				return FALSE;

			
			// debug
			//bp(bb1->rva_start, 0x0000bf72);
			//bp(bb2->rva_start, 0x0000bf72);


			// set the match
			bb1->bb_matched		=	bb2;
			bb2->bb_matched		=	bb1;
			daSET_F_BB_HARDMATCH(&bb1->flags);
			daSET_F_BB_HARDMATCH(&bb2->flags);


#if DA_DIFFDEBUG_IT == 1
			flog("*** match_by_name() MATCHEDbyNAME bb1=%08x(%08x) (crc=%llx, inum=%d) with bb2=%08x(%08x) (crc=%llx, inum=%d)\r\n",
				bb1->rva_start,
				bb1->rva_start,
				bb1->crc.crc,
				bb1->crc.crc_elements.instr_num,
				bb2->rva_start,
				bb2->rva_start,
				bb2->crc.crc,
				bb2->crc.crc_elements.instr_num);
#endif

			return TRUE;
		}
	}

	return FALSE;

}

BOOL DDiff::match_by_name(_dbasicblock *bb1)
{
	_dbasicblock	*bb_m;

	// this is only useful when the basicblock is a function
	if (!daIS_F_BB_FUNCTION_START(bb1->flags))
		return FALSE;
	

	// if the block was merged we need to scan entire MergedBlocks table for symbols
	// luckily for us typically it doesnt contain more than 2 entires
	if (daIS_F_BB_MERGED(bb1->flags))
	{
		for (int i = 0; i < bb1->MergedList->size(); i++)
		{
			bb_m	=	(*bb1->MergedList)[i];
			if (this->match_by_name_do(bb_m))
			{
				bb1->bb_matched		=	bb_m->bb_matched;
				daSET_F_BB_HARDMATCH(&bb1->flags);
				return TRUE;
			}
		}
	}
	
	return this->match_by_name_do(bb1);
}

/*
* Function picks the match for the bb with multiple matches.
*/

// this is not multithread safe
int max_val = 0;
bool sort_cmp_function(_dbbestmatches *m1,_dbbestmatches *m2)
{
	int distance_1	=	max_val	-	m1->match_level;
	int distance_2	=	max_val	-	m2->match_level;
	
	return (distance_1 < distance_2);
}

int		DDiff::pick_best_match(_dbbmatch *dbm)
{
	BOOL			is_perfect_match = FALSE;

	int				max_match_val;
	_dbasicblock	*bb1, *bb2;


	bb1				=	dbm->bb;

	

	/*
	// before we will start lets try to match it by name!
	if (this->match_by_name(bb1))
	{
#if DA_DIFFDEBUG_IT == 1
			flog("*** pick_best_match() picked by name for %08x (matched=%08x)\r\n",
				bb1->rva_start,
				bb1->bb_matched->rva_start);
#endif
			bp(bb1->rva_start, 0x0000bf72);
			bp(bb1->bb_matched->rva_start, 0x0000bf72);
			return D_OK;
	}

*/

	max_match_val	=	get_list_size(bb1->ChildsList) + get_list_size(bb1->ParentsList);
	max_val			=	max_match_val;

	// firstly sort the BestMatches list (toplevel is ~max_match_val)
	sort(dbm->BestMatches.begin(),dbm->BestMatches.end(),sort_cmp_function);

#if DA_DIFFDEBUG_IT == 1
			flog("*** pick_best_match() picking for %08x\r\n",
				bb1->rva_start);
#endif


	// sometimes same procedures may have same addresses so if
	// such location is found assume we have a match
	for (int i = 0; i < dbm->BestMatches.size(); i++)
	{
		if (dbm->BestMatches[i]->match->rva_start	==
			bb1->rva_start)
		{
			// we have a match by addr
			bb2				=	dbm->BestMatches[i]->match;
			bb1->bb_matched	=	bb2;
			bb2->bb_matched	=	bb1;
			

#if DA_DIFFDEBUG_IT == 1
			flog("*** pick_best_match() pickedBYaddr bb1=%08x -> bb2=%08x\r\n",
				bb1->rva_start,
				bb2->rva_start);
#endif
			return D_OK;
		}
	}



	// now we need to check if we have a perfect match max_match_val reached
	// and there is only one 
	// so check the first one
	if (dbm->BestMatches[0]->match_level == max_match_val)
	{
		is_perfect_match	=	TRUE;
		// we have a best match now just check if it is unique
		if (dbm->BestMatches[1]->match_level != max_match_val)
		{
			// we have a perfect match
			bb2				=	dbm->BestMatches[0]->match;

			// check if the block wasnt already matched
			if (bb2->bb_matched)
			{
#if DA_DIFFDEBUG_IT == 1
			flog("*** pick_best_match() perfect match bb1=%08x(%08x) bb2=%08x(%08x) (%d/%d) BUT BB2 IS ALREADY MATCHED to %08x\r\n",
				bb1->rva_start,
				bb1->rva_start,
				bb2->rva_start,
				bb2->rva_start,
				dbm->BestMatches[0]->match_level,
				max_match_val,
				bb2->bb_matched->rva_start);
#endif
			
				goto try_different_match1;
			}
		


	
			bb1->bb_matched	=	bb2;
			bb2->bb_matched	=	bb1;


#if DA_DIFFDEBUG_IT == 1
			flog("*** pick_best_match() perfect match bb1=%08x(%08x) bb2=%08x(%08x) (%d/%d)\r\n",
				bb1->rva_start,
				bb1->rva_start,
				bb2->rva_start,
				bb2->rva_start,
				dbm->BestMatches[0]->match_level,
				max_match_val);
#endif

			return D_OK;
		}
	}


	// ok we dont have the perfect match or 
	// we have more than one perfect matches
	// try to match by partial signature
	// if this fails pick the first match

try_different_match1:;
	//int		match_num	=	0;
	// now if there was a perfect match and was not resolved so far
	// it means that at least first two BestMatches have equal match_level
	// so pick the one which is located more close to our bb
	

	// todo: sometimes we have more than two matches with the same level
	// so in this case we will pick the one located most near the original one
	if (dbm->BestMatches.size() > 2)
	{
		int		rel_index		=	0;
		ulong32 rel_addr		=	abs((int)(dbm->BestMatches[0]->match->rva_start - dbm->bb->rva_start));
		int		wanted_level	=	dbm->BestMatches[0]->match_level;

		if (dbm->BestMatches[0]->match_level == 
			dbm->BestMatches[2]->match_level)
		{

			for (int i = 0; i < dbm->BestMatches.size(); i++)
			{

				if (dbm->BestMatches[i]->match_level < wanted_level)
					continue;

				// pick by the nearest addr
#define new_rel_addr abs((int)(dbm->BestMatches[i]->match->rva_start - dbm->bb->rva_start))

//				flog("ABS: %08x - %08x = %08x (%d)\n", 
//					dbm->BestMatches[i]->match->rva_start,
//					dbm->bb->rva_start,
//					new_rel_addr,
//					new_rel_addr);

				if (new_rel_addr < rel_addr)
				{
					rel_index	=	i;
					rel_addr	=	new_rel_addr;

					// additional thing
					BOOL	pick_it	=	this->compare_cfg(bb1, dbm->BestMatches[rel_index]->match, true)	&
						this->compare_cfg(bb1, dbm->BestMatches[rel_index]->match, false);

					// if pickit is ok we have a good match
					if (pick_it)
					{

#if DA_DIFFDEBUG_IT == 1
						flog("pick_it_bitch: %08x -> %08x\r\n", 
							bb1->rva_start, dbm->BestMatches[rel_index]->match->rva_start);
#endif

						break;
					}
				

				}
			}


			// ok so pick the match now
			// write the match
			bb2				=	dbm->BestMatches[rel_index]->match;
			bb1->bb_matched	=	bb2;
			bb2->bb_matched	=	bb1;


			// debug
			//bp(bb1->rva_start, 0x0000bf72);
			//bp(bb2->rva_start, 0x0000bf72);

#if DA_DIFFDEBUG_IT == 1
			flog("*** pick_best_match() nearest match bb1=%08x(%08x) bb2=%08x(%08x) (%d/%d)\r\n",
				bb1->rva_start,
				bb1->rva_start,
				bb2->rva_start,
				bb2->rva_start,
				dbm->BestMatches[rel_index]->match_level,
				max_match_val);
#endif

			return D_OK;
		}
	}


	// pick the possible match
	for (int i = 0; i < dbm->BestMatches.size(); i++)
	{
		if (dbm->BestMatches[i]->match->bb_matched)
		{

#if DA_DIFFDEBUG_IT == 1
			bb2				=	dbm->BestMatches[i]->match;
			flog("*** pick_best_match() pickingloop bb2=%08x was already matched to bb1=%08x\r\n",
				bb2->rva_start,
				bb2->bb_matched->rva_start);
#endif
			continue;
		}

		//bp(dbm->bb->rva_start,0x000251c1);
		// check if we have an equal match level with this element and the next one if there is any
		if ((i+1) < dbm->BestMatches.size())
		{
			if (dbm->BestMatches[i]->match_level	==	dbm->BestMatches[i+1]->match_level)
			{
				// same matching level so, try to guess which one fits better
				// by comparing the cfg
				BOOL	pick_first	=	this->compare_cfg(bb1, dbm->BestMatches[i]->match, true)	|
					this->compare_cfg(bb1, dbm->BestMatches[i]->match, false);
				BOOL	pick_second	=	this->compare_cfg(bb1, dbm->BestMatches[i+1]->match, true)	|
					this->compare_cfg(bb1, dbm->BestMatches[i+1]->match, false);

				// if second one is correct pick it instead of the first one
				if (pick_second && !pick_first)
				{
					i++;

#if DA_DIFFDEBUG_IT == 1
					flog("*** pick_best_match() -> picking second one!\r\n");
#endif
				}

#if DA_DIFFDEBUG_IT == 1
				if (pick_first && pick_second)
				{
					flog("*** pick_best_match() -> wtf is happening here CFGpick_first(%08x) = CFGpick_second(%08x)?\r\n",
						dbm->BestMatches[i]->match,
						dbm->BestMatches[i+1]->match
						);
				}
#endif
			}

		}


		// write the match
		bb2				=	dbm->BestMatches[i]->match;
		bb1->bb_matched	=	bb2;
		bb2->bb_matched	=	bb1;

#if DA_DIFFDEBUG_IT == 1
			flog("*** pick_best_match() first/last match bb1=%08x(%08x) bb2=%08x(%08x) (%d/%d)\r\n",
				bb1->rva_start,
				bb1->rva_start,
				bb2->rva_start,
				bb2->rva_start,
				dbm->BestMatches[i]->match_level,
				max_match_val);
#endif

			return D_OK;
	}

#if DA_DIFFDEBUG_IT == 1
	flog("*** pick_best_match() NOTHING PICKED FOR %08x \r\n",
		dbm->bb->rva_start);
#endif


	return D_OK;
}



/*
* Function tries to match the unmatched (0similar block found by checksum) 
* block by comparing the adler32 from f. bytes and also ignoring the number of
* parents elements

*/


BOOL DDiff::match_by_bytes(_dbasicblock *bb1)
{
	type_ByteFingerPrintMap::iterator	it;
	_dbasicblock *bb2;

	_dcrc	crc1, crc2;
	
	type_ByteFingerPrintPair f_pair =	this->BMap2->equal_range(bb1->crc.crc_adler);
	crc1							=	bb1->crc;
	crc1.crc_elements.parents_num	=	0;	// ignore parents num


	for (it = f_pair.first; it != f_pair.second; it++)
	{

		bb2				=	it->second;
		// check if it wasnt matched already
		if (bb2->bb_matched)
			continue;

		crc2							=	bb2->crc;
		crc2.crc_elements.parents_num	=	0;	// ignore parents num

		// check if both blocks are equal (besides the parents num field)
		// if so we have a match
		if (crc1.crc_elements.desc_crc	==	crc2.crc_elements.desc_crc)
		{


#if DA_DIFFDEBUG_IT == 1
			flog("*** match_by_bytes() matched bb1=%08x with bb2=%08x by adlerBYTES&cfg\r\n",
				bb1->rva_start,
				bb2->rva_start);
#endif

			daSET_F_BB_HARDMATCH(&bb1->flags);
			daSET_F_BB_HARDMATCH(&bb2->flags);
			bb1->bb_matched		=	bb2;
			bb2->bb_matched		=	bb1;
			return TRUE;
		}

	}

	return FALSE;
}



/*
* Function tries to match the unmatched (0similar block found by checksum) 
* block by comparing the byte checksum (without imm operands) and thecfg
*/

#if DA_DIFF_USE_WEAKCRCMAP == 1
BOOL DDiff::match_by_weak_bytes(_dbasicblock *bb1)
{
	type_WeakFingerPrintMap::iterator	it;
	_dbasicblock *bb2;

	_dcrc	crc1, crc2;
	
	if (!bb1->crc.crc_weak)
		return FALSE;


	type_WeakFingerPrintPair f_pair =	this->WMap2->equal_range(bb1->crc.crc_weak);
	crc1							=	bb1->crc;
	crc1.crc_elements.parents_num	=	0;	// ignore parents num



	for (it = f_pair.first; it != f_pair.second; it++)
	{

		bb2				=	it->second;
		// check if it wasnt matched already
		if (bb2->bb_matched)
			continue;

		crc2							=	bb2->crc;
		crc2.crc_elements.parents_num	=	0;	// ignore parents num

		// check if both blocks are equal (besides the parents num field)
		// if so we have a match
		if (crc1.crc_elements.desc_crc	==	crc2.crc_elements.desc_crc)
		{


#if DA_DIFFDEBUG_IT == 1
			flog("*** match_by_weak_bytes() matched bb1=%08x with bb2=%08x by weakBYTES&cfg\r\n",
				bb1->rva_start,
				bb2->rva_start);
#endif

			daSET_F_BB_HARDMATCH_WEAKB(&bb1->flags);
			daSET_F_BB_HARDMATCH_WEAKB(&bb2->flags);
			bb1->bb_matched		=	bb2;
			bb2->bb_matched		=	bb1;
			return TRUE;
		}

	}

	return FALSE;
}
#endif



/*
* Function tries to match the unmatched (0similar block found by checksum) to 
* anther block from list_b2 *superslow*
*/

int	DDiff::hardcore_matching(type_BBList *list_b1, type_BBList *list_b2, _dbbmatch *dbm)
{
	
	type_SecondaryFingerPrintMap::iterator	it;
	_dbasicblock *bb1, *bb2;
	bb1		=	dbm->bb;



	// try to match by second checksum
	type_SecFingerPrintPair f_pair	=	this->SMap2->equal_range(bb1->crc.crc_elements.desc_crc);
	for (it = f_pair.first; it != f_pair.second; it++)
	{
		
		bb2				=	it->second;
		// check if it wasnt matched already
		if (bb2->bb_matched)
			continue;

		// both conditions must be TRUE
		BOOL cfg_match	=	this->compare_cfg(bb1, bb2, true)	& this->compare_cfg(bb1, bb2, false);
		if (cfg_match)
		{

#if DA_DIFFDEBUG_IT == 1
			flog("*** hardcore_matching() matched bb1=%08x with bb2=%08x by crc&cfg\r\n",
				bb1->rva_start,
				bb2->rva_start);
#endif

			daSET_F_BB_HARDMATCH(&bb1->flags);
			daSET_F_BB_HARDMATCH(&bb2->flags);
			bb1->bb_matched		=	bb2;
			bb2->bb_matched		=	bb1;
			return D_OK;
		}

	}




	for (int i = 0; i < list_b2->size(); i++)
	{
		bb2		=	(*list_b2)[i];

		// we want to have unmatched ones only
		if (da_WAS_MATCHED(bb2->flags))
			continue;

		// try to match by cfg
		// both conditions must be TRUE
		BOOL cfg_match	=	this->compare_cfg(bb1, bb2, true)	& this->compare_cfg(bb1, bb2, false);
		if (cfg_match)
		{

#if DA_DIFFDEBUG_IT == 1
			flog("*** hardcore_matching() matched bb1=%08x with bb2=%08x by cfg only\r\n",
				bb1->rva_start,
				bb2->rva_start);
#endif

			daSET_F_BB_HARDMATCH(&bb1->flags);
			daSET_F_BB_HARDMATCH(&bb2->flags);
			bb1->bb_matched		=	bb2;
			bb2->bb_matched		=	bb1;
			return D_OK;
		}
		else
		{
			// still no match so try to match by adlerBYTEchecksum and part CFG
			if (match_by_bytes(bb1))
				return D_OK;

#if DA_DIFF_USE_WEAKCRCMAP == 1
			if (match_by_weak_bytes(bb1))
				return D_OK;
#endif
		}

	}


	// ok 



#if DA_DIFFDEBUG_IT == 1
			flog("*** hardcore_matching() -> bb1=%08x STILL-NOT-MATCHED!!!\r\n",
				bb1->rva_start);
#endif

	return D_FAILED;
}

/*
* Function calculates the match level between bb and bb_similar
*/

_dbbestmatches	*DDiff::match_by_level(_dbasicblock *bb, _dbasicblock *bb_similar)
{
	_dbbestmatches	*new_best	=	new _dbbestmatches;
	assert(new_best);

	new_best->match			=	bb_similar;
	new_best->match_level	=	this->calc_match_level(bb->ChildsList, bb_similar->ChildsList);
	new_best->match_level	+=	this->calc_match_level(bb->ParentsList, bb_similar->ParentsList);
	return new_best;
}

int	DDiff::calc_match_level(type_BBList *list_b1, type_BBList *list_b2)
{
	int match_level	=	0;
	

	// now calculate the match level
	if (list_b1	&& list_b2)
	{
		// base the match_level value on different characteristisc
		match_level =	list_b1->size() - list_b2->size();
		for (int i = 0; i < list_b1->size(); i++)
		{
			_dbasicblock	*b1	=	(*list_b1)[i];
			BOOL	block_found = FALSE;

			for (int j = 0; j < list_b2->size(); j++)
			{
				// check if the checksum matches
				_dbasicblock	*b2	=	(*list_b2)[j];
				
				if (IS_BASICBLOCK_NOTRESOLVED((ulong32)b2))
					continue;

				if (b1->crc.crc	==	b2->crc.crc)
				{
					block_found = TRUE;
					match_level++;
					break;
				}
			}

			// if the block was not found decrease the match_level
			if (!block_found)
				match_level--;


		}
	}

	return match_level;
}



/*
* Function compares two blocks by CFG (parents or childs)
* The only condition for this to work is one of the parents/childs
* must be already matched
*/

BOOL 	DDiff::compare_cfg(_dbasicblock *bb1, _dbasicblock *bb2, BOOL parents)
{
	_dbasicblock	*parent, *child, *b_match;

	// match by parents
	if (parents)
	{
		// nothing to compare with
		if (!bb1->ParentsList)
			return FALSE;

		parent	=	(*bb1->ParentsList)[0];

		if (IS_BASICBLOCK_NOTRESOLVED((ulong32)parent))
			return FALSE;
		
		// nothing matched so we cant compare
		if (!parent->bb_matched)
			return FALSE;

		b_match	=	parent->bb_matched;

		if (!b_match->ChildsList)
			return FALSE;

		// ok mirror parent is there, so now check if bb2 is one
		// of its child
		for (int i = 0; i < b_match->ChildsList->size(); i++)
		{
			if ((*b_match->ChildsList)[i] == bb2)
			{

#if DA_DIFFDEBUG_IT == 1
			flog("compare_cfg bb1=%08x bb2=%08x are the same! (parent check)\r\n",
				bb1->rva_start,
				bb2->rva_start);
#endif
				return TRUE;
			}

		}
	} // parents scan
	else
	{
		// scan childs
		// nothing to compare with
		if (!bb1->ChildsList)
			return FALSE;

		child	=	(*bb1->ChildsList)[0];


		if (IS_BASICBLOCK_NOTRESOLVED((ulong32)child))
			return FALSE;

		// nothing matched so we cant compare
		if (!child->bb_matched)
			return FALSE;

		b_match	=	child->bb_matched;


	if (!b_match->ParentsList)
			return FALSE;

		// ok mirror child is there, so now check if bb2 is one
		// of its parents
		for (int i = 0; i < b_match->ParentsList->size(); i++)
		{
			if ((*b_match->ParentsList)[i] == bb2)
			{

#if DA_DIFFDEBUG_IT == 1
			flog("compare_cfg bb1=%08x bb2=%08x are the same! (child check)\r\n",
				bb1->rva_start,
				bb2->rva_start);
#endif
				return TRUE;
			}

		}
	} // childs


	return FALSE;
}




void DDiff::debug_list_function_basicblocks(_dfunction *df)
{
	_dbasicblock		*bb, *bb_temp;

	type_BBList				FutureBBs;
	type_BBMap				VisitedBBs;
	type_BBMap::iterator	it;

	VisitedBBs.clear();
	FutureBBs.clear();

	FutureBBs.push_back(df->bb_start);

	int counter = 0;

	for (;;)
	{
		if (FutureBBs.empty())
			break;

		bb	=	FutureBBs.back();
		FutureBBs.pop_back();

		// check if it was already processed
		it	=	VisitedBBs.find(bb->rva_start);
		if(it != VisitedBBs.end())
			continue;


		
		// not processed so add it to the map
		VisitedBBs.insert(make_pair<ulong32,_dbasicblock*>(bb->rva_start,bb));

		// if it has childs add them to the future list
		if (bb->ChildsList)
		{
			for (int i = 0; i < bb->ChildsList->size(); i++)
			{
				bb_temp = (*bb->ChildsList)[i];
				if (!IS_BASICBLOCK_NOTRESOLVED((ulong32)bb_temp))
				{
					FutureBBs.push_back(bb_temp);
				}
				else
				{
					flog("Basicblock %08x was not resolved (referenced by %08x)\r\n",
						bb->rva_start,
						bb_temp);
				}

			}
		}


		char debug_flags[255];
		debug_flags[0] = 0;
		if (daIS_F_BB_MULTIPLEMATCH(bb->flags)) _snprintf(debug_flags,255, "MULTIPLEMATCH");
		if (daIS_F_BB_HARDMATCH(bb->flags)) _snprintf(debug_flags,255, "HARDMATCH");
		if (daIS_F_BB_HARDMATCH_WEAKB(bb->flags)) _snprintf(debug_flags,255, "HARDMATCH_WEAKB");

		// ok now display the information about found bb 
		if (bb->bb_matched)
			flog("[%d] BBlock: %08x (crc: b:%08x r:%08x tttn:%d) -> \
				 %08x (crc: b:%08x r:%08x tttn:%d) %s\r\n",
				counter,
				bb->rva_start,
				bb->crc.crc_elements.first_32bit,
				bb->crc.crc_elements.desc_crc,
				bb->crc.crc_elements.tttn,
				bb->bb_matched->rva_start,
				bb->bb_matched->crc.crc_elements.first_32bit,
				bb->bb_matched->crc.crc_elements.desc_crc,
				bb->bb_matched->crc.crc_elements.tttn,
				debug_flags);
		else
			flog("[%d] BBlock: %08x (org) -> NOT MATCHED\r\n",
				counter,
				bb->rva_start);


		if ((!daIS_F_BB_MATCHED(bb->flags) && !daIS_F_BB_MULTIPLEMATCH(bb->flags)))
		{
			debug_find_obj_instrs_in_bb(bb);

		}


		counter++;
	} // for(;;)

	flog("----------- FUNCTION DUMP DONE ---------- \r\n\r\n");
}



/*
* Function lists all instructions in basicblock which use memory operands.
* (which are not apis)
* this should be used with unmatched basicblocks 
*/

void DDiff::debug_find_obj_instrs_in_bb(_dbasicblock *bb)
{

	_dinstr		*di;
	ulong32		i_rva	=	bb->rva_start;
	type_flags  iflags = 0;

	
	do
	{

		di	=	this->Analyze1->get_dinstr_from_rva(i_rva);
		if (!di) break;

		iflags = this->Analyze1->BinData.flags[i_rva];

		// test the instruction now
		// operands

//		bp(di->rva_addr, 0x1014);
		if (daIS_F_INSTR_RELOCABLE_DATA_IN_MEMIMM(iflags))
		{
			if (!daIS_F_INSTR_USES_IMPORTED_API(iflags))
			{

				flog("debug_find_obj_instrs_in_bb: instruction from BB=%08x at %08x uses memimm_rva=%08x (SYMBOLNAME=%s)\r\n",
					bb->rva_start,
					di->rva_addr,
					di->objMEMIMM_rva,
					(daIS_F_INSTR_SYMBOL_IN_MEMIMM(iflags)? "true":"no"));
			
				ulong32 temp = this->match_object(di->objMEMIMM_rva);
				flog("trying to matched the obj=%08x -> matchobj=%08x\r\n",
					di->objMEMIMM_rva,
					temp);
			}
		}


		if (daIS_F_INSTR_RELOCABLE_DATA_IN_IMM(iflags))
		{
			flog("debug_find_obj_instrs_in_bb: instruction from BB=%08x at %08x uses imm_rva=%08x (SYMBOLNAME=%s)\r\n",
				bb->rva_start,
				di->rva_addr,
				di->objIMM_rva,
				(daIS_F_INSTR_SYMBOL_IN_IMM(iflags)? "true":"no"));

				ulong32 temp = match_object(di->objIMM_rva);
				flog("trying to match the obj=%08x -> matchobj=%08x\r\n",
					di->objIMM_rva,
					temp);
		}


		if (daIS_F_BB_END(iflags))
			break;


		// next one
		i_rva	=	i_rva + di->len;
	} while (di);


	// make the same for merged block
	if (bb->MergedList)
	{
		for (int i = 0; i < bb->MergedList->size(); i++)
		{
			_dbasicblock *mb	=	(*bb->MergedList)[i];

			flog("debug_find_obj_instrs_in_bb: merged from bb=%08x, using bb=%08x\r\n",
				bb->rva_start,
				mb->rva_start);

			debug_find_obj_instrs_in_bb(mb);
		}

	}
	



}