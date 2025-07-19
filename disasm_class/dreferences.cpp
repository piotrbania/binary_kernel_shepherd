#include "danalyze.h"


/*
* Function adds reference (xref) information to specified object
* represented by RVA.
* For example: mov dword ptr [object],eax
* means that object RVA will be placed in the ReferenceMap, and the instruction
* which caused the reference will be put there also as a pair. 
*/

_reference_entry	*DAnalyze::reference_add(ulong32 obj_rva, _dbasicblock *bb, _dinstr *instr)
{
	_reference_entry	*r_entry;

	r_entry			=	new _reference_entry;
	assert(r_entry);

	r_entry->instr	=	instr;
	r_entry->bb		=	bb;
	ReferenceMap.insert(make_pair<ulong32, _reference_entry*>(obj_rva, r_entry));

	return r_entry;
}

