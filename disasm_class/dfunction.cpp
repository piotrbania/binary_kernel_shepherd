#include "danalyze.h"



/*
* Function returns the function list which includes basicblock in its body
*/

void DAnalyze::get_functions_for_basicblock_recursive(_dbasicblock		*bb, 
											type_FunctionList	*OutFuncList,
											type_BBMap			*BBVisitedMap)
{


	// check if the bb wasnt processed already
	type_BBMap::iterator	it	=	BBVisitedMap->find(bb->rva_start);
	if (it != BBVisitedMap->end())
		return;

	// add this basicblock to visited regions
	BBVisitedMap->insert(make_pair<ulong32,_dbasicblock*>(bb->rva_start,bb));

	// check if the bb itself is a function
	// if so add it
	if (daIS_F_BB_FUNCTION_START(bb->flags))
	{
		type_FunctionMap::iterator	it	=	this->FunctionMap.find(bb->rva_start);
		if (it != this->FunctionMap.end())
		{
			OutFuncList->push_back(it->second);
			return;
		}
		else
		{
			// should never happen
#if DA_DEBUG_IT == 1
			flog("*** get_functions_for_basicblock_r() fatal: cant locate function for %08x (%08x)\r\n",
					bb->rva_start,
					orva2va(bb->rva_start));
#endif
			return;
		}

	}


	// now make the same thing for all the other parents
	if (bb->ParentsList)
	{
		for (int i = 0; i < bb->ParentsList->size(); i++)
		{
			this->get_functions_for_basicblock_recursive(
				(*bb->ParentsList)[i],
				OutFuncList,
				BBVisitedMap);
		}
	}

}


int	DAnalyze::get_functions_for_basicblock(_dbasicblock *bb, type_FunctionList *OutFuncList)
{

	type_BBMap		BBVisitedMap;
	BBVisitedMap.clear();
	OutFuncList->clear();

	this->get_functions_for_basicblock_recursive(bb, OutFuncList, &BBVisitedMap);
	

#if DA_DEBUG_IT == 1
	int	count =	OutFuncList->size();
	flog("*** get_functions_for_basicblock() found %d functions for %08x (%08x)\r\n",
				count,
				bb->rva_start,
				orva2va(bb->rva_start));
	for (int i = 0; i < count; i++)
	{
		flog("F%d	->	%08x(%08x)\r\n",
			i,
			(*OutFuncList)[i]->bb_start->rva_start,
			orva2va((*OutFuncList)[i]->bb_start->rva_start));
	}
	flog("--- func dump done ---\r\n");
#endif


	BBVisitedMap.clear();
	return OutFuncList->size();
}



/*
* Function finds function by rva
*/
_dfunction			*DAnalyze::find_function_by_rva(ulong32 rva)
{
	if (this->FunctionMap.empty())
		return 0;

	type_FunctionMap::iterator it = this->FunctionMap.find(rva);
	if (it == this->FunctionMap.end())
		return 0;

	return it->second;
}


/*
* Function allocates and initializes new basicblock
*/

_dfunction	*DAnalyze::new_function(_dbasicblock *bb_start)
{
	_dfunction *df = new _dfunction;
	assert(df);

	memset((void*)df, 0, sizeof(_dfunction));
	df->bb_start	=	bb_start;

	this->FunctionList.push_back(df);
	this->FunctionMap.insert(make_pair<ulong32,_dfunction*>(bb_start->rva_start,df));


#if DA_DEBUG_IT == 1
			flog("*** new_function() at %08x (%08x)\r\n",
					bb_start->rva_start,
					orva2va(bb_start->rva_start));
#endif

	return df;
}



/*
* Function fills all informations (checksum, symbols etc) for
* every function in the list
*/


int DAnalyze::make_functions(void)
{
	_dfunction	*df;
	

	if (this->FunctionList.empty())
		return D_FAILED;

	for (int i = 0; i < this->FunctionList.size(); i++)
	{
		df = this->FunctionList[i];
		

		// no we need to walk through all the basic blocks

	}






	return D_OK;
}


/*
* Function walks through the function basicblocks.
* It writes all the necessary data to dfunction structure.
*/

int	DAnalyze::walk_function_basicblocks(_dfunction *df)
{
	_dbasicblock	*bb;
	type_BBChilds	FutureBBList;
	type_BBMap		AnalyzedBBList;


	FutureBBList.clear();
	AnalyzedBBList.clear();

	while (1)
	{
		// all done?
		if (FutureBBList.empty())
			break;

		bb			=	FutureBBList.back();
		FutureBBList.pop_back();

		// check if it was already analyzed
		if (this->was_bb_analyzed(bb, &AnalyzedBBList))
			continue;

		// add this to analyzed list 
		AnalyzedBBList.insert(make_pair<ulong32,_dbasicblock*>((ulong32)bb,bb));

		// now add all childs to the Future list
		// if there is no childs this is the return

	}



	return D_OK;
}

/*
* Function checks if the basic block was already analyzed
*/

BOOL DAnalyze::was_bb_analyzed(_dbasicblock *bb, type_BBMap *AnalyzedBBList)
{
	if (AnalyzedBBList->empty())
		return FALSE;

	type_BBMap::iterator	it = AnalyzedBBList->find((ulong32)bb);
	if (it != AnalyzedBBList->end())
		return TRUE;

	return FALSE;
}