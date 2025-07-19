
#include "danalyze.h"
#include "dintegrate.h"



/*
* Test function - erases functions
* Executed before function hook is placed.
*/

int			DIntegrate::EraseFunction(uchar *file_data, _dfunction *func)
{
	BOOL	first = FALSE;

	for (int j = 0; j < func->BBIList->size(); j++)
	{
		_bb_iext	 *bbi = (*func->BBIList)[j];
		_dbasicblock *bb = (_dbasicblock*)bbi->bb_org;

		ulong32 bb_raw		= this->DA->orva2raw(bb->rva_start);
		int size = bb->rva_end - bb->rva_start;

		if (!first && !daIS_F_BB_EXT_HOOKABLE(bbi->flags))
		{
			flog("%s: skipping because function=%08x bb=%08x-%08x -> not hookable\n",
				__FUNCTION__, func->bb_start->rva_start, bb->rva_start, bb->rva_end);

			
			return 1;
		}
		first = TRUE;


		if (IsSharedBasicBlock(bb->rva_start))
		{
			flog("%s: not destroying function=%08x bb=%08x-%08x -> SHARED\n",
				__FUNCTION__, func->bb_start->rva_start, bb->rva_start, bb->rva_end);

			//continue;
			return 1;
		}

		flog("%s: destroying function=%08x bb=%08x-%08x\n",
			__FUNCTION__, func->bb_start->rva_start, bb->rva_start, bb->rva_end);

		memset((void*)&file_data[bb_raw], 0xCC, size);
	}

	return 1;
}


/*
* Marks shared basicblocks across functions -> do not use in the product (performance overkill)
* debug only
*/

int			DIntegrate::MarkSharedBasicBlocks(void)
{
	 SharedBBList.clear();
	 VisitedBBList.clear();


	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	= this->DA->FunctionList[i];
		// clean the visited flags now
		this->DFS_clear(func);
	}

	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	= this->DA->FunctionList[i];

		for (int j = 0; j < func->BBIList->size(); j++)
		{
			_bb_iext	 *bbi = (*func->BBIList)[j];
			_dbasicblock *bb = (_dbasicblock*)bbi->bb_org;

			if (IsVisitedBasicBlock(bb->rva_start))
			{
				//daSET_F_BB_EXT_SHARED(&bbi->flags);

				SharedBBList.insert(make_pair(bb->rva_start, bb));
				flog("%s: function=%08x basicblock=%08x is shared!\n",
					__FUNCTION__, func->bb_start->rva_start, bb->rva_start);

			}
			else
				VisitedBBList.insert(make_pair(bb->rva_start, bb));
			//daSET_F_BB_EXT_VISITED(&bbi->flags);
		}
	}

	for (int i = 0; i < this->DA->FunctionList.size(); i++)
	{
		_dfunction *func	= this->DA->FunctionList[i];
		// clean the visited flags now
		this->DFS_clear(func);
	}

	return 1;
}


ulong32		DIntegrate::IsSharedBasicBlock(ulong32 rva_addr)
{
	type_SharedBB::iterator it = SharedBBList.find(rva_addr);

	if (it != SharedBBList.end())
		return (ulong32)it->second;
	return 0;
}


ulong32		DIntegrate::IsVisitedBasicBlock(ulong32 rva_addr)
{
	type_SharedBB::iterator it = VisitedBBList.find(rva_addr);

	if (it != VisitedBBList.end())
		return (ulong32)it->second;
	return 0;
}